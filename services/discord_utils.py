import discord
from datetime import datetime
from typing import Mapping, Sequence


def _resolve_color(color: str | int | discord.Color) -> discord.Color:
    """色指定をdiscord.Colorに変換する"""
    if isinstance(color, discord.Color):
        return color
    if isinstance(color, int):
        return discord.Color(color)
    try:
        return getattr(discord.Color, color)()
    except AttributeError:
        return discord.Color.blurple()


def create_embed(title: str, description: str, data: Mapping[str, str], color: str | int | discord.Color) -> discord.Embed:
    """Discord Embedを作成"""
    embed = discord.Embed(title=title, description=description, color=_resolve_color(color))

    for name, value in data.items():
        embed.add_field(name=name, value=value, inline=True)

    embed.set_footer(
        text=f"タイムスタンプ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Powered by MetalpriceAPI Free"
    )
    return embed


async def send_large_message(channel: discord.TextChannel, text: str) -> None:
    """大きなメッセージをDiscordの制限(2000文字)に収まるよう分割して送信"""
    remaining = text
    while remaining:
        chunk = remaining[:2000]
        if len(remaining) > 2000:
            # 改行位置でできるだけ綺麗に区切る
            split_at = chunk.rfind("\n")
            if split_at > 1000:
                chunk = chunk[:split_at]
        remaining = remaining[len(chunk):].lstrip()
        await channel.send(chunk)
