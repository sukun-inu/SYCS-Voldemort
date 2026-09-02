"""on_ready。

再接続のたびに何度でも発火するイベントなので、背景タスク・常駐タスクの
多重起動防止（is_running() / state の *_started フラグ）が主眼。
setup_events(bot) の巨大クロージャからそのまま切り出した。
"""

from __future__ import annotations

import asyncio
import logging

from discord.ext.commands import Bot
from envutil import env_bool
from services.djaudio_cache import cache_cleanup_loop as djaudio_cache_cleanup
from services.earthquake_service import run_earthquake_ws

from events.background_tasks import BackgroundLoops
from events.state import EventState
from events.user_state_sync import (
    _USER_STATE_AUTO_REPAIR_ENABLED,
    _USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS,
    _USER_STATE_SYNC_DELAY_SECONDS,
    _USER_STATE_SYNC_ON_READY,
    _sync_user_state_on_ready,
    _user_state_auto_repair_loop,
)

logger = logging.getLogger(__name__)

_BOT_BACKGROUND_WORKER = env_bool("BOT_BACKGROUND_WORKER", True)


def register(bot: Bot, state: EventState, loops: BackgroundLoops) -> None:
    """常駐処理（ステータス更新・開発シグナル監視・ニュース/スティッキー・
    地震WS監視・djaudioキャッシュ掃除・ユーザー状態同期/自動修復）の起動を
    on_ready の中に配線する。on_ready は再接続のたびに何度でも発火する
    ため、二重起動を防ぐ判定（is_running()やstate側の*_startedフラグ）が
    このモジュールの主眼（モジュール docstring 参照）。
    """

    @bot.event
    async def on_ready():
        """再接続のたびに呼ばれる。bot.tree.sync()は呼ぶたびにDiscord側と
        コマンド定義を全同期するだけなので毎回呼んでも実害は無いが、下の
        各常駐タスクの起動は多重に走ると同じ処理が並行実行されてしまうため、
        is_running()/state.*_started で毎回ガードしてからstart()する。
        BOT_BACKGROUND_WORKER=false のときはニュース・スティッキー・地震
        監視・djaudioキャッシュ掃除だけを止める（ステータス更新と
        dev_signal_taskは常時起動）。
        """
        logger.info("[BOT] Logged in as %s", bot.user)
        await bot.tree.sync()
        if not loops.update_status.is_running():
            loops.update_status.start()
        if not loops.dev_signal_task.is_running():
            loops.dev_signal_task.start()
        if _BOT_BACKGROUND_WORKER:
            if not loops.news_feed_task.is_running():
                loops.news_feed_task.start()
            if not loops.pending_sticky_task.is_running():
                loops.pending_sticky_task.start()
            if state.ws_task is None or state.ws_task.done():
                state.ws_task = asyncio.create_task(run_earthquake_ws(bot))
            # on_ready は再接続のたびに何度でも発火する。他のタスクと同じく
            # 多重起動を防ぎ、参照も保持する（保持しないと実行中に GC で
            # タスクごと消えることがある）。
            if state.djaudio_cleanup_task is None or state.djaudio_cleanup_task.done():
                state.djaudio_cleanup_task = asyncio.create_task(djaudio_cache_cleanup(bot=bot, interval=60))
            logger.info("[BOT] background worker enabled: periodic jobs are active")
        else:
            logger.info("[BOT] BOT_BACKGROUND_WORKER=false: periodic background jobs are disabled")

        if _USER_STATE_SYNC_ON_READY and not state.user_state_sync_started:
            state.user_state_sync_started = True
            state.user_state_sync_task = asyncio.create_task(_sync_user_state_on_ready(bot, state.user_state_sync_lock))
            logger.info(
                "[BOT] USER_STATE_SYNC_ON_READY=true: background sync task started (delay=%ss)",
                _USER_STATE_SYNC_DELAY_SECONDS,
            )

        if _USER_STATE_AUTO_REPAIR_ENABLED and not state.user_state_repair_started:
            state.user_state_repair_started = True
            state.user_state_repair_task = asyncio.create_task(
                _user_state_auto_repair_loop(bot, state.user_state_sync_lock)
            )
            logger.info(
                "[BOT] USER_STATE_AUTO_REPAIR_ENABLED=true: periodic repair started (interval=%ss)",
                _USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS,
            )
