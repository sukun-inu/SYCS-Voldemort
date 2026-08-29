"""events/ 以下の各モジュールが共通で使う小さな道具。

setup_events() を分割する前は bot_setup.py 直下に _safe() があり、全ハンドラが
それを直接呼んでいた。分割後も同じ形で使えるよう、bot_setup.py に依存しない
（＝どのモジュールから import しても循環しない）ここへそのまま移した。
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def _safe(coro, name: str) -> None:
    """付随処理の失敗で本筋を止めないためのラッパー。

    イベントハンドラごとに try/except/logger.exception を書き下すと、
    定型が積み上がって本来の分岐が埋もれる（実際 setup_events が1,200行に
    膨れた一因はこれだった）ので1箇所にまとめる。
    """
    try:
        await coro
    except Exception as e:
        logger.exception("[BOT_SETUP] %s error: %s", name, e)
