import asyncio
import logging
from typing import Dict

import discord

from services.settings_store import (
    get_sticky_messages,
    update_sticky_message_id,
)

logger = logging.getLogger(__name__)

# チャンネルIDごとのロック（同時スティッキー投稿を防止）
_locks: Dict[int, asyncio.Lock] = {}


def _get_lock(channel_id: int) -> asyncio.Lock:
    if channel_id not in _locks:
        _locks[channel_id] = asyncio.Lock()
    return _locks[channel_id]


async def handle_sticky(message: discord.Message) -> None:
    if message.guild is None or message.author.bot:
        return

    channel_id = message.channel.id
    guild_id = message.guild.id

    stickies = get_sticky_messages(guild_id)
    entry = stickies.get(str(channel_id))
    if not entry:
        return

    content: str = entry.get("content", "")
    old_message_id: int | None = entry.get("message_id")

    lock = _get_lock(channel_id)
    if lock.locked():
        return

    async with lock:
        # 古いスティッキーメッセージを削除
        if old_message_id:
            try:
                old_msg = await message.channel.fetch_message(old_message_id)
                await old_msg.delete()
            except (discord.NotFound, discord.HTTPException):
                pass

        # 新しいスティッキーメッセージを投稿
        try:
            new_msg = await message.channel.send(f"📌 {content}")
            update_sticky_message_id(guild_id, channel_id, new_msg.id)
        except Exception as e:
            logger.exception("[sticky_service] send error ch=%s: %s", channel_id, e)
