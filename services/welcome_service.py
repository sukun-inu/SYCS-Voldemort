import logging

import discord

from services.settings_store import get_goodbye_settings, get_welcome_settings

logger = logging.getLogger(__name__)

_DEFAULT_WELCOME = "{user} がサーバーに参加しました！ ようこそ **{server}** へ！ （現在 {count} 名）"
_DEFAULT_GOODBYE = "{username} がサーバーから退出しました。"


def _render(template: str, member: discord.Member) -> str:
    return (
        template
        .replace("{user}", member.mention)
        .replace("{username}", str(member))
        .replace("{server}", member.guild.name)
        .replace("{count}", str(member.guild.member_count))
    )


async def send_welcome(member: discord.Member) -> None:
    s = get_welcome_settings(member.guild.id)
    channel_id = s.get("channel_id")
    if not channel_id:
        return
    channel = member.guild.get_channel(int(channel_id))
    if channel is None or not isinstance(channel, discord.TextChannel):
        return
    message = s.get("message") or _DEFAULT_WELCOME
    try:
        await channel.send(_render(message, member))
    except Exception as e:
        logger.exception("[welcome_service] send_welcome error: %s", e)


async def send_goodbye(member: discord.Member) -> None:
    s = get_goodbye_settings(member.guild.id)
    channel_id = s.get("channel_id")
    if not channel_id:
        return
    channel = member.guild.get_channel(int(channel_id))
    if channel is None or not isinstance(channel, discord.TextChannel):
        return
    message = s.get("message") or _DEFAULT_GOODBYE
    try:
        await channel.send(_render(message, member))
    except Exception as e:
        logger.exception("[welcome_service] send_goodbye error: %s", e)
