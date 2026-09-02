"""ウェルカム / グッバイ（入退室のあいさつ）コマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import admin_site_view
from services.settings_store import (
    awrite,
    get_goodbye_settings,
    get_welcome_settings,
    set_goodbye_channel,
    set_goodbye_message,
    set_welcome_channel,
    set_welcome_message,
)


def register(bot: Bot) -> None:
    """/greeting welcome/goodbye の channel・message と /greeting status を登録する。"""
    # 入退室のあいさつは welcome と goodbye で対になっており、状況表示は
    # 両方をまとめて出す。別々のグループにすると status の置き場所が無くなる
    # ので、greeting の下に welcome / goodbye を置く二段構えにする。
    greeting_group = app_commands.Group(
        name="greeting", description="入退室のあいさつ（ウェルカム / グッバイ）", guild_only=True
    )
    welcome_group = app_commands.Group(name="welcome", description="入室時のあいさつ", parent=greeting_group)
    goodbye_group = app_commands.Group(name="goodbye", description="退室時のあいさつ", parent=greeting_group)

    @welcome_group.command(name="channel", description="【管理者】ウェルカム送信チャンネルを設定します")
    @app_commands.describe(channel="ウェルカムメッセージを送るチャンネル")
    async def set_welcome_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        """set_goodbye_ch と対になる、welcome 側のチャンネル設定。"""
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_welcome_channel, guild.id, channel.id)
        await interaction.response.send_message(f"{channel.mention} をウェルカムチャンネルと定めた。", ephemeral=True)

    @welcome_group.command(name="message", description="【管理者】ウェルカムメッセージを設定します")
    @app_commands.describe(message="テンプレート: {user} {username} {server} {count} が使用可能")
    async def set_welcome_msg(interaction: discord.Interaction, message: str):
        """テンプレート文字列はここでは検証しない。

        実際の展開(services/welcome_service.py)が str.format ではなく
        .replace() の連鎖なので、{typo} のような存在しないプレースホルダを
        書いても例外にはならず、そのまま文字通り出力されるだけ。だから
        ここで許可された名前かを事前チェックする必要が無い。
        """
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_welcome_message, guild.id, message)
        await interaction.response.send_message(f"ウェルカムメッセージを定めた。\n> {message}", ephemeral=True)

    @goodbye_group.command(name="channel", description="【管理者】グッバイ送信チャンネルを設定します")
    @app_commands.describe(channel="グッバイメッセージを送るチャンネル")
    async def set_goodbye_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        """set_welcome_ch と対になる、goodbye 側のチャンネル設定。"""
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_goodbye_channel, guild.id, channel.id)
        await interaction.response.send_message(f"{channel.mention} をグッバイチャンネルと定めた。", ephemeral=True)

    @goodbye_group.command(name="message", description="【管理者】グッバイメッセージを設定します")
    @app_commands.describe(message="テンプレート: {user} {username} {server} {count} が使用可能")
    async def set_goodbye_msg(interaction: discord.Interaction, message: str):
        """テンプレート未検証の理由は set_welcome_msg と同じ（.replace() 連鎖で例外にならない）。"""
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_goodbye_message, guild.id, message)
        await interaction.response.send_message(f"グッバイメッセージを定めた。\n> {message}", ephemeral=True)

    @greeting_group.command(name="status", description="ウェルカム/グッバイ設定を表示します")
    async def welcome_settings_cmd(interaction: discord.Interaction):
        """channel/message の4コマンドと違い ensure_admin なし。閲覧は全員に開放している。"""
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        ws = get_welcome_settings(interaction.guild.id)
        gs = get_goodbye_settings(interaction.guild.id)
        w_ch = f"<#{ws.get('channel_id')}>" if ws.get("channel_id") else "未設定"
        g_ch = f"<#{gs.get('channel_id')}>" if gs.get("channel_id") else "未設定"
        embed = discord.Embed(title="ウェルカム/グッバイ設定", color=discord.Color.green())
        embed.add_field(name="ウェルカムチャンネル", value=w_ch, inline=True)
        embed.add_field(name="ウェルカムメッセージ", value=ws.get("message") or "(デフォルト)", inline=False)
        embed.add_field(name="グッバイチャンネル", value=g_ch, inline=True)
        embed.add_field(name="グッバイメッセージ", value=gs.get("message") or "(デフォルト)", inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    bot.tree.add_command(greeting_group)
