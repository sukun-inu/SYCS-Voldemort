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
    @bot.event
    async def on_raw_reaction_add(payload: discord.RawReactionActionEvent):
        await _safe(handle_reaction_add(bot, payload), "on_raw_reaction_add")

    @bot.event
    async def on_raw_reaction_remove(payload: discord.RawReactionActionEvent):
        await _safe(handle_reaction_remove(bot, payload), "on_raw_reaction_remove")
