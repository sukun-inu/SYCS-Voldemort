import asyncio
import logging
from typing import Dict

import discord

from services.settings_store import (
    get_sticky_messages,
    remove_sticky_message,
    update_sticky_message_id,
)

logger = logging.getLogger(__name__)

_locks: Dict[int, asyncio.Lock] = {}
# ロック保持中にメッセージが届いたことを記録し、解放後に再投稿するためのフラグ
_pending: Dict[int, bool] = {}


def _get_lock(channel_id: int) -> asyncio.Lock:
    if channel_id not in _locks:
        _locks[channel_id] = asyncio.Lock()
    return _locks[channel_id]


async def _post_once(channel: discord.TextChannel, guild_id: int, content: str, old_message_id: int | None) -> None:
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


async def _post_latest(channel: discord.TextChannel, guild_id: int) -> None:
    """最新の設定を読み込んでスティッキーを投稿する（ロック保持済み前提）。"""
    entry = get_sticky_messages(guild_id).get(str(channel.id))
    if not entry:
        return
    await _post_once(channel, guild_id, entry.get("content", ""), entry.get("message_id"))


async def post_sticky(channel: discord.TextChannel, guild_id: int) -> None:
    """スティッキーメッセージを即時投稿する（コマンド実行時など）。"""
    lock = _get_lock(channel.id)
    async with lock:
        _pending[channel.id] = False
        await _post_latest(channel, guild_id)


async def delete_sticky(channel: discord.TextChannel, guild_id: int) -> None:
    """Discordのメッセージを削除し、設定からスティッキーを除去する。"""
    entry = get_sticky_messages(guild_id).get(str(channel.id))
    if entry and entry.get("message_id"):
        try:
            old_msg = await channel.fetch_message(entry["message_id"])
            await old_msg.delete()
        except (discord.NotFound, discord.HTTPException):
            pass
    remove_sticky_message(guild_id, channel.id)


async def handle_sticky(message: discord.Message) -> None:
    if message.guild is None or message.author.bot:
        return

    channel_id = message.channel.id
    guild_id = message.guild.id

    entry = get_sticky_messages(guild_id).get(str(channel_id))
    if not entry:
        return

    lock = _get_lock(channel_id)
    if lock.locked():
        _pending[channel_id] = True
        return

    async with lock:
        _pending[channel_id] = False
        await _post_once(message.channel, guild_id, entry.get("content", ""), entry.get("message_id"))

    if _pending.get(channel_id):
        _pending[channel_id] = False
        async with lock:
            await _post_latest(message.channel, guild_id)
