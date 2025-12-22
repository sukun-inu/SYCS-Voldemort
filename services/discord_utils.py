import json
import discord
from datetime import datetime


def create_embed(title: str, description: str, data: dict, color: str | int) -> discord.Embed:
    """Discord Embedを作成"""
    if isinstance(color, str):
        color = getattr(discord.Color, color)()
    
    embed = discord.Embed(title=title, description=description, color=color)
    
    for name, value in data.items():
        embed.add_field(name=name, value=value, inline=True)
    
    embed.set_footer(
        text=f"タイムスタンプ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Powered by MetalpriceAPI Free"
    )
    return embed


async def send_large_message(channel: discord.TextChannel, text: str) -> None:
    """大きなメッセージを2000文字ずつ分割して送信"""
    while text:
        part, text = text[:2000], text[2000:]
        print("DEBUG: Sending message part: " + part)
        await channel.send(part)
