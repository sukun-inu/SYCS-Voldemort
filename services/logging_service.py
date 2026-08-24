import logging
from datetime import datetime
from io import BytesIO
from typing import Dict, Mapping, Optional

import aiohttp
import discord

try:
    from colorthief import ColorThief  # type: ignore[import]
except ImportError:  # ライブラリ未導入時は色抽出をスキップ
    ColorThief = None  # type: ignore[assignment]

from config import JST as _JST
from services.settings_store import get_guild_settings, update_guild_settings

logger = logging.getLogger(__name__)

_LEVEL_PRIORITY = {
    "NONE": 0,
    "ERROR": 1,
    "INFO": 2,
    "DEBUG": 3,
}

# ユーザーごとの代表色キャッシュ {user_id: 0xRRGGBB}（最大1024件でLRU）
_USER_COLOR_CACHE: Dict[int, int] = {}
_USER_COLOR_CACHE_MAX = 1024


def _get_default_settings() -> Dict[str, Optional[int | str]]:
    return {"channel_id": None, "level": "INFO"}


def get_log_settings(guild_id: int) -> Dict[str, Optional[int | str]]:
    raw = get_guild_settings(guild_id)
    level = str(raw.get("log_level", "INFO")).upper()
    channel_id = raw.get("log_channel_id")
    settings = _get_default_settings()
    settings["level"] = level
    settings["channel_id"] = channel_id
    return settings


def set_log_channel(guild_id: int, channel_id: int | None) -> None:
    update_guild_settings(guild_id, {"log_channel_id": channel_id})


def set_log_level(guild_id: int, level: str) -> None:
    upper = level.upper()
    if upper not in _LEVEL_PRIORITY:
        raise ValueError(f"不正なログレベル: {level}. 使用可能: NONE, ERROR, INFO, DEBUG")
    update_guild_settings(guild_id, {"log_level": upper})


def _should_log(guild_id: int, level: str) -> bool:
    settings = get_log_settings(guild_id)
    current_level = str(settings.get("level", "INFO") or "INFO").upper()
    return _LEVEL_PRIORITY.get(level, 0) <= _LEVEL_PRIORITY.get(current_level, 2)


def _level_color(level: str) -> discord.Color:
    if level == "ERROR":
        return discord.Color.red()
    if level == "INFO":
        return discord.Color.blue()
    if level == "DEBUG":
        return discord.Color.dark_gray()
    return discord.Color.light_grey()


async def _user_avatar_color(user: Optional[discord.abc.User]) -> Optional[discord.Color]:
    """ユーザーのアバター画像から代表色を抽出して返す。

    - colorthief が利用可能な場合のみ動作
    - ユーザーごとに結果をキャッシュ
    """
    if user is None or ColorThief is None:
        return None

    user_id = getattr(user, "id", None)
    if isinstance(user_id, int) and user_id in _USER_COLOR_CACHE:
        rgb = _USER_COLOR_CACHE[user_id]
        r = (rgb >> 16) & 0xFF
        g = (rgb >> 8) & 0xFF
        b = rgb & 0xFF
        return discord.Color.from_rgb(r, g, b)

    # アバターURLから画像を取得して色抽出
    try:
        avatar_url = user.display_avatar.url  # type: ignore[attr-defined]
    except Exception:
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(str(avatar_url)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.read()
    except Exception:
        return None

    try:
        thief = ColorThief(BytesIO(data))  # type: ignore[operator]
        r, g, b = thief.get_color(quality=10)
    except Exception:
        return None

    if isinstance(user_id, int):
        if len(_USER_COLOR_CACHE) >= _USER_COLOR_CACHE_MAX:
            _USER_COLOR_CACHE.pop(next(iter(_USER_COLOR_CACHE)))
        _USER_COLOR_CACHE[user_id] = (r << 16) + (g << 8) + b

    return discord.Color.from_rgb(r, g, b)


def _get_log_channel(bot: discord.Client, guild_id: int) -> Optional[discord.TextChannel]:
    """設定からログチャンネルを取得。未設定や型不一致の場合はNone。"""
    settings = get_log_settings(guild_id)
    channel_id = settings.get("channel_id")
    if not channel_id:
        logger.debug("ログチャンネル未設定 guild_id=%s", guild_id)
        return None

    channel = bot.get_channel(int(channel_id))
    if not isinstance(channel, discord.TextChannel):
        logger.debug("ログチャンネルがTextChannelでない guild_id=%s channel_id=%s", guild_id, channel_id)
        return None
    return channel


async def log_action(
    bot: discord.Client,
    guild_id: int,
    level: str,
    message: str,
    *,
    user: Optional[discord.abc.User] = None,
    fields: Optional[Mapping[str, str]] = None,
    embed_color: Optional[discord.Color] = None,
) -> None:
    """指定されたギルドのログチャンネルにEmbedでメッセージを送信

    - すべてのログはRich Embed形式
    - ユーザー関連のログでは、ユーザーのアイコンをAuthorに表示
    - フッターに日本時間(JST)での実行時刻を記載
    """
    level = level.upper()
    if level not in _LEVEL_PRIORITY:
        # 想定外のレベルは無視
        return

    if not _should_log(guild_id, level):
        return

    channel = _get_log_channel(bot, guild_id)
    if channel is None:
        return

    embed = await build_log_embed(
        level, message, user=user, fields=fields, embed_color=embed_color,
    )
    await channel.send(embed=embed)


async def build_log_embed(
    level: str,
    message: str,
    *,
    user: Optional[discord.abc.User] = None,
    fields: Optional[Mapping[str, str]] = None,
    embed_color: Optional[discord.Color] = None,
) -> discord.Embed:
    """ログ用の Embed を組み立てる。

    開発者パネルの「ログ出力テスト」もこれを使う。テスト側が独自に Embed を
    組むと、本番で実際に出るものとずれていくため。
    """
    level = level.upper()
    jst_now = datetime.now(_JST)

    user_color = None
    if embed_color is None:
        user_color = await _user_avatar_color(user)
    base_color = embed_color or user_color or _level_color(level)

    # Discord API の Embed 制限値
    # タイトル: 256文字、説明: 4096文字、著者名: 256文字、フッター: 2048文字
    title = f"[{level}] ボットログ"
    if len(title) > 256:
        title = title[:256]
    
    description = message
    if len(description) > 4096:
        description = description[:4093] + "..."
    
    embed = discord.Embed(
        title=title,
        description=description,
        color=base_color,
    )

    if user is not None:
        try:
            avatar_url = str(user.display_avatar.url)  # type: ignore[attr-defined]
            author_name = str(user)
            if len(author_name) > 256:
                author_name = author_name[:253] + "..."
            embed.set_author(name=author_name, icon_url=avatar_url)
        except Exception:
            author_name = str(user)
            if len(author_name) > 256:
                author_name = author_name[:253] + "..."
            embed.set_author(name=author_name)

    if fields:
        for name, value in fields.items():
            # Discord API の制限: embed フィールドは 1024 文字以下
            truncated_value = str(value)[:1024]
            if len(str(value)) > 1024:
                truncated_value += "... (省略)"
            embed.add_field(name=name, value=truncated_value, inline=False)

    # フッターも 2048 文字制限を適用
    footer_text = f"時刻 (JST): {jst_now.strftime('%Y-%m-%d %H:%M:%S')}"
    if len(footer_text) > 2048:
        footer_text = footer_text[:2045] + "..."
    embed.set_footer(text=footer_text)
    return embed


async def send_log_embed(
    bot: discord.Client,
    guild_id: int,
    level: str,
    embed: discord.Embed,
) -> Optional[discord.Message]:
    """ログチャンネルにEmbedを送信し、メッセージを返す（進捗更新用）

    - ログレベル設定に従って送信する
    - ログチャンネル未設定などの場合は None を返す
    """
    level = level.upper()
    if level not in _LEVEL_PRIORITY:
        return None

    if not _should_log(guild_id, level):
        return None

    channel = _get_log_channel(bot, guild_id)
    if channel is None:
        return None

    try:
        return await channel.send(embed=embed)
    except Exception:
        logger.debug("send_log_embed failed", exc_info=True)
        return None
