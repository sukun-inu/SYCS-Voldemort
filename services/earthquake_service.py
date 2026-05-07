import asyncio
import json
import logging

import aiohttp
import discord
from discord.ext.commands import Bot

from services.settings_store import (
    get_all_guild_ids,
    get_earthquake_settings,
)

logger = logging.getLogger(__name__)

_WS_URL = "wss://api.p2pquake.net/v2/ws"

_SCALE_MAP = {
    10: "1",
    20: "2",
    30: "3",
    40: "4",
    45: "4強",
    50: "5弱",
    55: "5強",
    60: "6弱",
    65: "6強",
    70: "7",
}

_SCALE_COLORS = {
    10: discord.Color.green(),
    20: discord.Color.green(),
    30: discord.Color.yellow(),
    40: discord.Color.orange(),
    45: discord.Color.orange(),
    50: discord.Color.red(),
    55: discord.Color.red(),
    60: discord.Color.dark_red(),
    65: discord.Color.dark_red(),
    70: discord.Color.dark_red(),
}


def _scale_label(scale: int) -> str:
    return _SCALE_MAP.get(scale, f"不明({scale})")


def _max_scale(quake: dict) -> int:
    points = quake.get("points", [])
    if not points:
        return quake.get("earthquake", {}).get("maxScale", -1)
    return max((p.get("scale", -1) for p in points), default=-1)


async def _notify_all_guilds(bot: Bot, event: dict) -> None:
    max_scale = _max_scale(event)
    eq = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    name = hypo.get("name", "不明")
    magnitude = hypo.get("magnitude", "?")
    depth = hypo.get("depth", "?")
    origin_time = eq.get("time", "不明")

    color = _SCALE_COLORS.get(max_scale, discord.Color.red())
    embed = discord.Embed(
        title=f"🔔 地震情報 — 最大震度 {_scale_label(max_scale)}",
        color=color,
    )
    embed.add_field(name="震源地", value=name, inline=True)
    embed.add_field(name="マグニチュード", value=str(magnitude), inline=True)
    embed.add_field(name="深さ", value=f"{depth} km", inline=True)
    embed.add_field(name="発生時刻", value=origin_time, inline=False)
    embed.set_footer(text="情報提供: P2PQuake")

    for guild_id in get_all_guild_ids():
        s = get_earthquake_settings(guild_id)
        channel_id = s.get("channel_id")
        if not channel_id:
            continue
        min_scale = int(s.get("min_scale", 30))
        if max_scale < min_scale:
            continue

        guild = bot.get_guild(guild_id)
        if guild is None:
            continue
        channel = guild.get_channel(int(channel_id))
        if not isinstance(channel, discord.TextChannel):
            continue

        try:
            await channel.send(embed=embed)
        except Exception as e:
            logger.exception("[earthquake] send error guild=%s: %s", guild_id, e)


async def run_earthquake_ws(bot: Bot) -> None:
    """P2PQuake WebSocket に常時接続し、地震情報をリアルタイムで受信・通知する。切断時は自動再接続。"""
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(_WS_URL, heartbeat=30) as ws:
                    logger.info("[earthquake] WebSocket接続確立")
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                            except json.JSONDecodeError:
                                continue
                            if data.get("code") == 551:
                                await _notify_all_guilds(bot, data)
                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            logger.warning("[earthquake] WebSocket切断: type=%s", msg.type)
                            break
        except Exception as e:
            logger.exception("[earthquake] WebSocket接続エラー: %s", e)

        logger.info("[earthquake] 10秒後に再接続します")
        await asyncio.sleep(10)
