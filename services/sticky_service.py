import asyncio
import logging

import discord

from services.settings_store import (
    awrite,
    get_all_guild_ids,
    get_sticky_messages,
    remove_sticky_message,
    update_sticky_message_id,
)

logger = logging.getLogger(__name__)

_locks: dict[int, asyncio.Lock] = {}
_pending: dict[int, bool] = {}


def _get_lock(channel_id: int) -> asyncio.Lock:
    """チャンネルごとの投稿ロックを使い回す。スティッキーの再投稿は
    「削除してから送り直す」の2段階なので、同じチャンネルで複数の
    トリガー（メッセージ発言・WebUI操作）が重なると、削除と送信の
    順序が入れ替わって二重投稿や削除漏れになる。それを防ぐための鍵。
    """
    if channel_id not in _locks:
        _locks[channel_id] = asyncio.Lock()
    return _locks[channel_id]


async def _post_once(channel: discord.TextChannel, guild_id: int, content: str, old_message_id: int | None) -> None:
    """古いスティッキーを削除してから新しく送り直し、新メッセージIDを
    保存する。呼び出し元でロックを取っている前提（この関数自体は
    排他しない）。古いメッセージが既に無くても（手動削除等）
    NotFound/HTTPException は無視して投稿を続ける。
    """
    if old_message_id:
        try:
            old_msg = await channel.fetch_message(old_message_id)
            await old_msg.delete()
        except (discord.NotFound, discord.HTTPException):
            pass

    try:
        new_msg = await channel.send(f"📌 {content}")
        await awrite(update_sticky_message_id, guild_id, channel.id, new_msg.id)
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
    await awrite(remove_sticky_message, guild_id, channel.id)


async def handle_sticky(message: discord.Message) -> None:
    """発言のたびにスティッキーを一番下へ送り直す（on_message から呼ぶ）。

    連投で呼び出しが重なったときは、ロックを持っている投稿が終わるまで
    _pending フラグだけ立てて自分は投稿しない。ロック解放後にもう一度
    だけ投稿し直すことで、連投1回ごとに削除→送信を繰り返して
    レートリミットを消費するのを避けつつ、最終的には最新の内容で
    再投稿される。
    """
    if message.guild is None or message.author.bot:
        return

    channel_id = message.channel.id
    guild_id = message.guild.id

    entry = get_sticky_messages(guild_id).get(str(channel_id))
    if not entry or entry.get("pending") == "delete":
        return

    lock = _get_lock(channel_id)
    if lock.locked():
        _pending[channel_id] = True
        return

    async with lock:
        _pending[channel_id] = False
        # message.channel は複数チャンネル型の Union だが、スティッキー機能は
        # テキストチャンネル運用前提。他の型で到達した場合の型不一致は
        # 実害の検証が別途必要なため、ここでは黙らせるだけに留める。
        await _post_latest(message.channel, guild_id)  # type: ignore[arg-type]

    if _pending.get(channel_id):
        _pending[channel_id] = False
        async with lock:
            await _post_latest(message.channel, guild_id)  # type: ignore[arg-type]


async def process_pending_stickies(bot: discord.Client) -> None:
    """WebUIからのpending操作（post/delete）を処理する。定期タスクから呼ぶ。"""
    for guild_id in get_all_guild_ids():
        stickies = get_sticky_messages(guild_id)
        for ch_id_str, entry in list(stickies.items()):
            pending = entry.get("pending")
            if not pending:
                continue

            channel_id = int(ch_id_str)
            guild = bot.get_guild(guild_id)
            if guild is None:
                continue
            channel = guild.get_channel(channel_id)
            if not isinstance(channel, discord.TextChannel):
                continue

            lock = _get_lock(channel_id)
            if pending == "post":
                async with lock:
                    _pending[channel_id] = False
                    # ロック待ち中に handle_sticky が処理済みの場合は二重投稿を避ける
                    fresh = get_sticky_messages(guild_id).get(ch_id_str, {})
                    if fresh.get("pending") == "post":
                        await _post_latest(channel, guild_id)
            elif pending == "delete":
                async with lock:
                    _pending[channel_id] = False
                    message_id = entry.get("message_id")
                    if message_id:
                        try:
                            old_msg = await channel.fetch_message(message_id)
                            await old_msg.delete()
                        except (discord.NotFound, discord.HTTPException):
                            pass
                    await awrite(remove_sticky_message, guild_id, channel_id)
