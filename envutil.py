"""環境変数を安全に読むための共通ヘルパ。

このモジュールは**依存を持たない**（標準ライブラリのみ）。bot / webapp /
webapp_admin のどのプロセスからでも、副作用なしにインポートできることを
意図している。`config.py` は ffmpeg の解決をインポート時に行うため、
そちらを共通の置き場にはできない。

## なぜ必要か

以前はリポジトリ全体で `int(os.environ.get("X", "600"))` の形が使われていた。
この形には2つの問題がある:

1. `X=` （空文字）が設定されていると `ValueError` でインポート時に落ちる。
   docker-compose や .env で「変数は宣言したが値は空」は普通に起きるため、
   起動そのものが失敗する。
2. `X=abc` のような壊れた値も同じくインポート時に落ちる。どの環境変数が
   原因かはスタックトレースを読まないと分からない。

ここの関数はいずれも**例外を投げない**。読めない値は理由をログに残した上で
既定値へフォールバックする（＝安全側に倒す）。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def env_raw(key: str) -> Optional[str]:
    """環境変数を取得する。未設定・空文字・空白のみ の場合は None。"""
    value = os.environ.get(key)
    if value is None:
        return None
    value = value.strip()
    return value or None


def env_str(key: str, default: Optional[str] = None) -> Optional[str]:
    """文字列として読む。空文字は「未設定」として扱う。"""
    value = env_raw(key)
    return default if value is None else value


def env_bool(key: str, default: bool) -> bool:
    """真偽値として読む。解釈できない値は既定値へ倒し、理由を残す。"""
    raw = env_raw(key)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    logger.warning(
        "環境変数 %s の値 %r を真偽値として解釈できません。既定値 %r を使います。",
        key,
        raw,
        default,
    )
    return default


def env_int(
    key: str,
    default: int,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    """整数として読む。

    未設定・空文字・数値でない値のいずれでも例外は投げず、既定値へ倒す。
    `minimum` / `maximum` を渡すと範囲へクランプし、クランプしたことを
    ログに残す（黙って値が変わらないようにするため）。
    """
    raw = env_raw(key)
    if raw is None:
        return _clamp_int(key, default, minimum, maximum, from_default=True)
    try:
        value = int(raw, 10)
    except ValueError:
        logger.warning(
            "環境変数 %s の値 %r を整数として解釈できません。既定値 %r を使います。",
            key,
            raw,
            default,
        )
        return _clamp_int(key, default, minimum, maximum, from_default=True)
    return _clamp_int(key, value, minimum, maximum, from_default=False)


def env_float(
    key: str,
    default: float,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    """小数として読む。挙動は :func:`env_int` と同じ。"""
    raw = env_raw(key)
    if raw is None:
        return _clamp_float(key, default, minimum, maximum, from_default=True)
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "環境変数 %s の値 %r を数値として解釈できません。既定値 %r を使います。",
            key,
            raw,
            default,
        )
        return _clamp_float(key, default, minimum, maximum, from_default=True)
    if value != value or value in (float("inf"), float("-inf")):
        # NaN / inf は範囲チェックをすり抜けて後段を壊すため、ここで弾く
        logger.warning(
            "環境変数 %s の値 %r は有限の数値ではありません。既定値 %r を使います。",
            key,
            raw,
            default,
        )
        return _clamp_float(key, default, minimum, maximum, from_default=True)
    return _clamp_float(key, value, minimum, maximum, from_default=False)


def env_path(key: str, default: Path) -> Path:
    """パスとして読む。空文字はカレントディレクトリではなく既定値へ倒す。

    `Path("")` は `Path(".")` になり、キャッシュ等がリポジトリ直下へ
    書き出される事故になるため、空文字を明示的に既定値へ倒している。
    """
    raw = env_raw(key)
    if raw is None:
        return default
    return Path(raw)


def _clamp_int(key: str, value: int, minimum: Optional[int], maximum: Optional[int], *, from_default: bool) -> int:
    """範囲へ丸める。丸めたときは理由をログへ残す。

    黙って丸めると「設定した値と実際に効いている値が違う」状態が、どこにも
    現れないまま続く。丸めたこと自体より、気づけないことのほうが問題になる。
    """
    clamped = value
    if minimum is not None and clamped < minimum:
        clamped = minimum
    if maximum is not None and clamped > maximum:
        clamped = maximum
    if clamped != value:
        _log_clamp(key, value, clamped, minimum, maximum, from_default=from_default)
    return clamped


def _clamp_float(
    key: str, value: float, minimum: Optional[float], maximum: Optional[float], *, from_default: bool
) -> float:
    """範囲へ丸める。丸めたときは理由をログへ残す（_clamp_int の float 版）。"""
    clamped = value
    if minimum is not None and clamped < minimum:
        clamped = minimum
    if maximum is not None and clamped > maximum:
        clamped = maximum
    if clamped != value:
        _log_clamp(key, value, clamped, minimum, maximum, from_default=from_default)
    return clamped


def _log_clamp(key, value, clamped, minimum, maximum, *, from_default: bool) -> None:
    """丸めた事実を、環境変数由来かコード上の既定値由来かを分けて記録する。

    後者（from_default）は「コードに書いた既定値が、他の設定に連動した
    上下限に阻まれて効いていない」という分かりにくい状態なので、文面を
    分けて警告にしてある。詳しくは分岐の中のコメント。
    """
    lo = "-" if minimum is None else minimum
    hi = "-" if maximum is None else maximum
    if from_default:
        # env var 自体は未設定で、コード上のリテラル既定値 value を使うはずだった。
        # それでも許容範囲(minimum/maximum)を外れてクランプされるのは、
        # minimum/maximum に他の環境変数由来の値（式）が渡されていて、その値が
        # 実行時に既定値を上回った／下回ったケース。ここを無音にすると、
        # 「コード上は20.0と書いてあるのに実際は25.0で動いている」という
        # 事故に気づく手段が無くなる（黙って何もしない分岐を作らない）。
        logger.warning(
            "環境変数 %s は未設定のため既定値 %r を使う想定でしたが、"
            "許容範囲(%s〜%s、他の設定値に連動している場合あり)に収まらないため "
            "%r に丸めました。",
            key,
            value,
            lo,
            hi,
            clamped,
        )
    else:
        logger.warning(
            "環境変数 %s の値 %r は許容範囲外です。%r に丸めました（許容: %s〜%s）。",
            key,
            value,
            clamped,
            lo,
            hi,
        )
