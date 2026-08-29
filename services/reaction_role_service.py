import logging
import re

import discord
from discord.ext.commands import Bot

from services.settings_store import get_reaction_roles

logger = logging.getLogger(__name__)


# カスタム絵文字の書き方（設定に入りうる形）。
#   <:name:123>  <a:name:123>  name:123  123
# Discord のピッカーから貼ると <:name:123> の完全形になり、ID だけを打つ人も
# いる。どれも同じ絵文字なので、比べる前に ID へ寄せる。
_CUSTOM_EMOJI = re.compile(r"^<a?:[^:]+:(\d+)>$|^[^:]+:(\d+)$|^(\d+)$")


def emoji_key(emoji) -> str:
    """絵文字を、保存と照合で共通に使える1つの文字列にする。

    カスタム絵文字は ID（数字）に寄せ、ユニコード絵文字はそのまま使う。

    ここを共通にしていなかったころは、保存側（管理画面・スラッシュコマンド）が
    入力された文字列をそのままキーにして `<:name:123>` を書き込み、照合側は
    `str(emoji.id)` すなわち `123` を作って引いていた。キーが一致しないので
    mapping.get() は必ず None になり、カスタム絵文字のリアクションロールは
    ログも残さず一切動かなかった。ユニコード絵文字は両者が同じ文字列になるため
    偶然動いていて、気付きにくい状態だった。

    discord に依存しないでおく（設定を読み書きする側からも呼べるように）。
    PartialEmoji でも文字列でも受け取れる。
    """
    identifier = getattr(emoji, "id", None)
    if identifier is not None:
        return str(identifier)

    text = str(emoji).strip()
    matched = _CUSTOM_EMOJI.match(text)
    if matched:
        return next(group for group in matched.groups() if group)
    return text


def _emoji_key(emoji: discord.PartialEmoji | str) -> str:
    return emoji_key(emoji)


def _role_id_for(mapping: dict, emoji) -> str | int | None:
    """このリアクションに割り当てられたロール。

    保存済みのキーも同じ規則に通してから比べる。過去に `<:name:123>` の形で
    保存された設定を、入れ直してもらわずにそのまま動かすため。
    """
    key = emoji_key(emoji)
    if key in mapping:
        return mapping[key]
    for stored, role_id in mapping.items():
        if emoji_key(stored) == key:
            return role_id
    return None


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

    role_id = _role_id_for(mapping, payload.emoji)
    if role_id is None:
        logger.debug(
            "[reaction_role] 割り当ての無い絵文字 message=%s key=%s 登録=%s",
            payload.message_id, emoji_key(payload.emoji), list(mapping))
        return

    role = guild.get_role(int(role_id))
    if role is None:
        logger.warning(
            "[reaction_role] 設定されたロールが見つかりません guild=%s role_id=%s",
            payload.guild_id, role_id)
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

    role_id = _role_id_for(mapping, payload.emoji)
    if role_id is None:
        logger.debug(
            "[reaction_role] 割り当ての無い絵文字 message=%s key=%s 登録=%s",
            payload.message_id, emoji_key(payload.emoji), list(mapping))
        return

    role = guild.get_role(int(role_id))
    if role is None:
        logger.warning(
            "[reaction_role] 設定されたロールが見つかりません guild=%s role_id=%s",
            payload.guild_id, role_id)
        return

    try:
        await member.remove_roles(role, reason="リアクションロール解除")
        logger.info("[reaction_role] remove role=%s user=%s", role.name, member)
    except discord.HTTPException as e:
        logger.exception("[reaction_role] remove_roles error: %s", e)
