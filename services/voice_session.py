"""VC接続を管理する層。

Discord の bot は1ギルドにつき音声接続を1本しか持てない。接続の所有を
このモジュールに集約し、読み上げ（TTS）はここ経由で接続を取りにくる。
"""

from __future__ import annotations

import asyncio
import logging
from typing import cast

import discord

logger = logging.getLogger(__name__)

# guild_id -> VoiceClient
_clients: dict[int, discord.VoiceClient] = {}
_locks: dict[int, asyncio.Lock] = {}


async def acquire(
    guild: discord.Guild,
    vc_channel_id: int,
) -> discord.VoiceClient | None:
    """VCに接続する。既に別チャンネルに繋がっていれば移動する。"""
    lock = _locks.setdefault(guild.id, asyncio.Lock())
    async with lock:
        existing = _clients.get(guild.id)

        if existing is not None and existing.is_connected():
            if existing.channel and existing.channel.id == vc_channel_id:
                return existing
            channel = guild.get_channel(vc_channel_id)
            if isinstance(channel, discord.VoiceChannel):
                try:
                    await existing.move_to(channel)
                    return existing
                except Exception as e:
                    logger.warning("[voice] move_to 失敗 guild=%s: %s", guild.id, e)
            await _force_disconnect(guild.id, existing)

        elif existing is not None:
            # ハンドシェイク切断などで失われた古い接続を捨ててから繋ぎ直す
            logger.info("[voice] 切れている接続を破棄して再接続します guild=%s", guild.id)
            await _force_disconnect(guild.id, existing)

        channel = guild.get_channel(vc_channel_id)
        if not isinstance(channel, discord.VoiceChannel):
            logger.warning("[voice] vc_channel_id=%s が見つからないか VC ではありません", vc_channel_id)
            return None

        # discord.py 側に既に接続済みの client があれば拾い直す
        # 型の上では VoiceProtocol だが、接続は discord.VoiceClient
        # でしか行わないので実体は必ず VoiceClient。
        current = cast("discord.VoiceClient | None", guild.voice_client)
        if current is not None and current.is_connected():
            if current.channel and current.channel.id == vc_channel_id:
                _clients[guild.id] = current
                return current
            await _force_disconnect(guild.id, current)

        try:
            client = await channel.connect(cls=discord.VoiceClient)
        except discord.ClientException as e:
            if "Already connected" in str(e):
                current = cast("discord.VoiceClient | None", guild.voice_client)
                if current is not None and current.is_connected():
                    _clients[guild.id] = current
                    return current
            logger.exception("[voice] 接続エラー guild=%s: %s", guild.id, e)
            return None
        except Exception as e:
            logger.exception("[voice] 接続エラー guild=%s: %s", guild.id, e)
            return None

        _clients[guild.id] = client
        return client


async def _force_disconnect(guild_id: int, client: discord.VoiceClient) -> None:
    """古い/移動できない接続を切ってから _clients から取り除く。切断が
    discord.py 側で失敗しても _clients からは必ず外す（呼び出し元は
    このあと新しい接続を張りに行くため、管理表だけは新しい接続に
    差し替えられるようにしておく必要がある）。
    """
    try:
        await client.disconnect(force=True)
    except Exception as e:
        # 失敗しても呼び出し元は新しい接続を張りに行くので処理は止めないが、
        # 古い接続が discord.py 側には生きたまま残っている可能性があるので
        # 理由は残す（黙って握りつぶすと、居座りに気づく手がかりが無くなる）。
        logger.warning("[voice] guild=%s 古い接続の強制切断に失敗しました: %s", guild_id, e)
    if _clients.get(guild_id) is client:
        _clients.pop(guild_id, None)


async def release(guild_id: int) -> bool:
    """接続を切る。戻り値は実際に切断したかどうか。"""
    # _locks はここでは消さない。acquire() は "async with lock" の間だけ
    # _locks[guild_id] を見ており、ここで pop すると、その最中に別の
    # acquire() 呼び出しが setdefault() で新しい（ロックされていない）Lock を
    # 作ってしまい、進行中の acquire() と排他が効かないまま両方が同時に
    # channel.connect() へ進んでしまう。ギルド数は有限なので Lock を
    # 残しておいても増え続ける心配はない。
    client = _clients.pop(guild_id, None)
    if client is None:
        return False
    try:
        await client.disconnect(force=True)
    except Exception as e:
        # _clients からは既に pop 済みなので、ここで諦めると実際の接続が
        # 生きたまま管理外になる（bot が VC に居座り続ける、次の acquire() が
        # 拾い直すまで誰も気づけない）。黙って握りつぶさず理由を残す。
        logger.warning(
            "[voice] guild=%s 切断に失敗しました（管理外の接続が残っている可能性）: %s",
            guild_id,
            e,
        )
    return True
