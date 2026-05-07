import logging

import aiohttp
import discord
from discord.ext.commands import Bot

from services.settings_store import (
    get_all_guild_ids,
    get_earthquake_settings,
    set_earthquake_last_event_id,
)

logger = logging.getLogger(__name__)

_API_URL = "https://api.p2pquake.net/v2/history?codes=551&limit=10"

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


async def run_earthquake_check(bot: Bot) -> None:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(_API_URL, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    logger.warning("[earthquake] API status=%s", resp.status)
                    return
                events: list[dict] = await resp.json()
    except Exception as e:
        logger.exception("[earthquake] API error: %s", e)
        return

    if not events:
        return

    latest_id: str = str(events[0].get("id", ""))

    for guild_id in get_all_guild_ids():
        s = get_earthquake_settings(guild_id)
        channel_id = s.get("channel_id")
        if not channel_id:
            continue
        min_scale: int = int(s.get("min_scale", 30))
        last_event_id: str = str(s.get("last_event_id", ""))

        # 初回起動: 最新IDだけ記録してポストしない
        if not last_event_id:
            set_earthquake_last_event_id(guild_id, latest_id)
            continue

        guild = bot.get_guild(guild_id)
        if guild is None:
            continue
        channel = guild.get_channel(int(channel_id))
        if not isinstance(channel, discord.TextChannel):
            continue

        new_events = []
        for ev in events:
            ev_id = str(ev.get("id", ""))
            if ev_id == last_event_id:
                break
            new_events.append(ev)

        if not new_events:
            continue

        # 最新IDを更新
        set_earthquake_last_event_id(guild_id, latest_id)

        # 古い順に投稿（最大5件）
        for ev in reversed(new_events[:5]):
            max_scale = _max_scale(ev)
            if max_scale < min_scale:
                continue

            eq = ev.get("earthquake", {})
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

            try:
                await channel.send(embed=embed)
            except Exception as e:
                logger.exception("[earthquake] send error guild=%s: %s", guild_id, e)
