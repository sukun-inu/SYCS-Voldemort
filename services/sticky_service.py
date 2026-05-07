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
# ロック保持中にメッセージが来たことを記録（解放後に再処理）
_pending: Dict[int, bool] = {}


def _get_lock(channel_id: int) -> asyncio.Lock:
    if channel_id not in _locks:
        _locks[channel_id] = asyncio.Lock()
    return _locks[channel_id]


async def _post_once(channel: discord.TextChannel, guild_id: int, content: str, old_message_id: int | None) -> None:
    """古いスティッキーを削除して新しいものを投稿する（ロック保持済み前提で呼ぶ）。"""
    if old_message_id:
        try:
            old_msg = await channel.fetch_message(old_message_id)
            await old_msg.delete()
        except (discord.NotFound, discord.HTTPException):
            pass

    try:
        new_msg = await channel.send(f"📌 {content}")
        update_sticky_message_id(guild_id, channel.id, new_msg.id)
    except Exception as e:
        logger.exception("[sticky_service] send error ch=%s: %s", channel.id, e)


async def post_sticky(channel: discord.TextChannel, guild_id: int) -> None:
    """スティッキーメッセージを即時投稿する（コマンド実行時など）。"""
    channel_id = channel.id
    stickies = get_sticky_messages(guild_id)
    entry = stickies.get(str(channel_id))
    if not entry:
        return

    content: str = entry.get("content", "")
    old_message_id: int | None = entry.get("message_id")

    lock = _get_lock(channel_id)
    async with lock:
        _pending[channel_id] = False
        await _post_once(channel, guild_id, content, old_message_id)


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
    lock = _get_lock(channel_id)

    if lock.locked():
        # 処理中は pending フラグを立てるだけ（終了後に再処理される）
        _pending[channel_id] = True
        return

    async with lock:
        _pending[channel_id] = False
        old_message_id: int | None = entry.get("message_id")
        await _post_once(message.channel, guild_id, content, old_message_id)

    # ロック解放後に pending が立っていたら再度投稿（その間に来たメッセージを反映）
    if _pending.get(channel_id):
        _pending[channel_id] = False
        stickies = get_sticky_messages(guild_id)
        entry = stickies.get(str(channel_id))
        if entry:
            content = entry.get("content", "")
            old_message_id = entry.get("message_id")
            async with lock:
                await _post_once(message.channel, guild_id, content, old_message_id)
