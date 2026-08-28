"""Bot と管理画面のあいだで受け渡す「シグナル」。

管理画面は Bot とは別プロセスなので、Bot にしかできない操作（VC への接続、
録音の開始・停止、Discord への送信）を直接は呼べない。共有ディレクトリへ
ファイルを1つ置き、Bot が定期的に拾って実行する。

置き場所は settings.json と同じ SETTINGS_DIR の下。書く側（管理画面）と
読む側（Bot）で解決の仕方が違うと、書いた場所と読む場所がずれて何も起きなく
なるため、両方がこのモジュールを通す。

ファイル名の付け方:

    <用途>.signal              何度実行しても結果が同じもの（ニュース取得など）。
                               溜めておく意味が無いので上書きでよい。

    <用途>.<一意>.signal       対象が payload の中にしかないもの（guild_id 付き）。
                               上書きすると別のサーバー宛の指示が消える。

後者を用途名だけで書いていたため、2つのサーバーの管理者が Bot の巡回間隔
（30秒）より短い間に操作すると、先の1件が黙って消えていた。押した側には
「キューに追加しました」と出たままで、ログにも何も残らなかった。

Bot 側は「最初の '.' まで」を用途名として読むので、どちらの形も同じ分岐へ
落ちる（点を含む用途名は作らないこと）。
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from envutil import env_path

logger = logging.getLogger(__name__)

_DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data"

SUFFIX = ".signal"


def signal_dir() -> Path:
    """シグナルの置き場。

    素の os.getenv("SETTINGS_DIR", 既定値) は、変数が空文字で宣言だけされて
    いるときに既定値へ倒れず Path("") = カレントディレクトリになる。Bot と
    管理画面はカレントディレクトリが違いうるので、そうなると書いた場所と
    読む場所がずれる。env_path は空文字を「未設定」として扱う。
    """
    return env_path("SETTINGS_DIR", _DEFAULT_DIR) / "_dev_signals"


def task_name_of(path: Path) -> str:
    """ファイル名から用途名を取り出す。

    "recording_start.signal"           -> "recording_start"
    "recording_start.19f3a2c1de.signal" -> "recording_start"
    """
    return path.name.split(".", 1)[0]


def write(name: str, payload: Any, *, per_guild: bool = False) -> Path:
    """シグナルを1つ置く。

    per_guild=True は「対象が payload の中にしかない」指示に付ける。用途名
    だけのファイル名にすると、Bot が拾う前に別の対象宛で上書きされて消える。
    """
    directory = signal_dir()
    directory.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    # 時刻を先頭に置いて、同じ用途が複数あるときに置いた順で並ぶようにする。
    unique = f".{time.time_ns():x}{uuid.uuid4().hex[:6]}" if per_guild else ""
    path = directory / f"{name}{unique}{SUFFIX}"
    path.write_text(text, encoding="utf-8")
    return path


def pending() -> list[str]:
    """未処理のシグナルの用途名。開発者パネルの表示用。"""
    return sorted(task_name_of(path) for path in collect())


def collect() -> list[Path]:
    """未処理のシグナルを、置かれた順に返す。

    同じ用途が複数溜まっていることがある（録音の開始と停止など）。glob の
    順序は環境依存なので、更新時刻とファイル名で並べ直してから渡す。
    """
    try:
        paths = list(signal_dir().glob(f"*{SUFFIX}"))
    except OSError as e:
        logger.warning("[signal] 置き場を読めませんでした: %s", e)
        return []

    def order(path: Path) -> tuple[float, str]:
        try:
            return (path.stat().st_mtime, path.name)
        except OSError:
            # 拾っているあいだに消えた（Bot が処理した）。最後に回す。
            return (float("inf"), path.name)

    return sorted(paths, key=order)


def latest(name: str) -> Path | None:
    """その用途で最後に置かれたシグナル。無ければ None。

    検証と、開発者パネルから中身を確認するためのもの。
    """
    matched = [path for path in collect() if task_name_of(path) == name]
    return matched[-1] if matched else None
