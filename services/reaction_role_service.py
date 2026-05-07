import logging

import discord
from discord.ext.commands import Bot

from services.settings_store import get_reaction_roles

logger = logging.getLogger(__name__)


def _emoji_key(emoji: discord.PartialEmoji | str) -> str:
    if isinstance(emoji, str):
        return emoji
    return str(emoji) if emoji.id is None else str(emoji.id)


async def handle_reaction_add(bot: Bot, payload: discord.RawReactionActionEvent) -> None:
    if payload.guild_id is None or payload.member is None or payload.member.bot:
        return

    guild = bot.get_guild(payload.guild_id)
    if guild is None:
        return

    rr = get_reaction_roles(payload.guild_id)
    mapping = rr.get(str(payload.message_id))
    if not mapping:
        return

    key = _emoji_key(payload.emoji)
    role_id = mapping.get(key)
    if role_id is None:
        return

    role = guild.get_role(int(role_id))
    if role is None:
        return

    try:
        await payload.member.add_roles(role, reason="リアクションロール")
        logger.info("[reaction_role] add role=%s user=%s", role.name, payload.member)
    except discord.HTTPException as e:
        logger.exception("[reaction_role] add_roles error: %s", e)


async def handle_reaction_remove(bot: Bot, payload: discord.RawReactionActionEvent) -> None:
    if payload.guild_id is None:
        return

    guild = bot.get_guild(payload.guild_id)
    if guild is None:
        return

    member = guild.get_member(payload.user_id)
    if member is None or member.bot:
        return

    rr = get_reaction_roles(payload.guild_id)
    mapping = rr.get(str(payload.message_id))
    if not mapping:
        return

    key = _emoji_key(payload.emoji)
    role_id = mapping.get(key)
    if role_id is None:
        return

    role = guild.get_role(int(role_id))
    if role is None:
        return

    try:
        await member.remove_roles(role, reason="リアクションロール解除")
        logger.info("[reaction_role] remove role=%s user=%s", role.name, member)
    except discord.HTTPException as e:
        logger.exception("[reaction_role] remove_roles error: %s", e)
