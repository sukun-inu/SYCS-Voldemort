"""サーバー情報 / ユーザー情報を表示するコマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

from typing import Optional

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.interaction_utils import admin_site_view
from config import JST as _JST


def register(bot: Bot) -> None:
    info_group = app_commands.Group(name="info", description="サーバーとユーザーの情報", guild_only=True)

    @info_group.command(name="server", description="サーバー情報を表示します")
    async def serverinfo_cmd(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        g = interaction.guild
        created = g.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M")
        owner = g.owner.mention if g.owner else "不明"

        roles_count = len(g.roles) - 1  # @everyone 除く
        text_ch = sum(1 for c in g.channels if isinstance(c, discord.TextChannel))
        voice_ch = sum(1 for c in g.channels if isinstance(c, discord.VoiceChannel))

        embed = discord.Embed(title=g.name, color=discord.Color.blurple())
        if g.icon:
            embed.set_thumbnail(url=g.icon.url)
        embed.add_field(name="サーバーID", value=str(g.id), inline=True)
        embed.add_field(name="オーナー", value=owner, inline=True)
        embed.add_field(name="メンバー数", value=str(g.member_count), inline=True)
        embed.add_field(name="テキストチャンネル", value=str(text_ch), inline=True)
        embed.add_field(name="ボイスチャンネル", value=str(voice_ch), inline=True)
        embed.add_field(name="ロール数", value=str(roles_count), inline=True)
        embed.add_field(name="作成日", value=created, inline=True)
        embed.add_field(name="ブーストレベル", value=str(g.premium_tier), inline=True)
        embed.add_field(name="ブースト数", value=str(g.premium_subscription_count or 0), inline=True)
        await interaction.response.send_message(embed=embed, view=admin_site_view())

    @info_group.command(name="user", description="ユーザー情報を表示します")
    @app_commands.describe(member="情報を表示するメンバー（省略時は自分）")
    async def userinfo_cmd(
        interaction: discord.Interaction,
        member: Optional[discord.Member] = None,
    ):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        target = member or interaction.user
        if not isinstance(target, discord.Member):
            await interaction.response.send_message("そのメンバーの情報を取得できなかった。", ephemeral=True)
            return

        joined = target.joined_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if target.joined_at else "不明"
        created = target.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if target.created_at else "不明"
        roles = [r.mention for r in target.roles if not r.is_default()]

        embed = discord.Embed(title=str(target), color=target.color)
        embed.set_thumbnail(url=target.display_avatar.url)
        embed.add_field(name="ユーザーID", value=str(target.id), inline=True)
        embed.add_field(name="ニックネーム", value=target.nick or "(なし)", inline=True)
        embed.add_field(name="アカウント作成日", value=created, inline=True)
        embed.add_field(name="サーバー参加日", value=joined, inline=True)
        embed.add_field(name="BOT", value="はい" if target.bot else "いいえ", inline=True)
        embed.add_field(
            name=f"ロール（{len(roles)}個）",
            value=" ".join(roles[:15]) or "なし",
            inline=False,
        )
        await interaction.response.send_message(embed=embed)

    bot.tree.add_command(info_group)
