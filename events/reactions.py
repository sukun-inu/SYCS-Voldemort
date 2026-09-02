"""on_raw_reaction_add / on_raw_reaction_remove（リアクションロール）。

setup_events(bot) の巨大クロージャからそのまま切り出した。実体は
services/reaction_role_service.py に委譲するだけの薄いハンドラ。
"""

from __future__ import annotations

import discord
from discord.ext.commands import Bot
from services.reaction_role_service import handle_reaction_add, handle_reaction_remove

from events._util import _safe


def register(bot: Bot) -> None:
    """raw版のイベントを使う理由: on_reaction_add/removeはメッセージが
    discord.pyのメッセージキャッシュに乗っていないと発火しない。リアクション
    ロールはボット再起動より前に貼られた古いメッセージにも反応する必要が
    あるため、キャッシュに依存しないraw版を使う。実処理は
    services.reaction_role_service に委譲する薄い配線。
    """

    @bot.event
    async def on_raw_reaction_add(payload: discord.RawReactionActionEvent):
        """rawイベントを使う理由はregister()のdocstring参照。実処理は
        handle_reaction_addへ委譲。
        """
        await _safe(handle_reaction_add(bot, payload), "on_raw_reaction_add")

    @bot.event
    async def on_raw_reaction_remove(payload: discord.RawReactionActionEvent):
        """on_raw_reaction_addと対になるロール解除側。実処理は
        handle_reaction_removeへ委譲（rawの理由はregister()参照）。
        """
        await _safe(handle_reaction_remove(bot, payload), "on_raw_reaction_remove")
