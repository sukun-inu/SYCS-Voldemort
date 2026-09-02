"""VC入退室通知チャンネルの設定コマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from services.settings_store import awrite, set_vc_notify_channel_id


def register(bot: Bot) -> None:
    """/vcnotify set・clear を登録する。"""
    vcnotify_group = app_commands.Group(name="vcnotify", description="VC の入退室通知", guild_only=True)

    @vcnotify_group.command(name="set", description="【管理者】VC通知チャンネルを設定します")
    @app_commands.describe(channel="VC通知を送るテキストチャンネル")
    async def set_vc_notify_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        """clear_vc_notify_ch と同じ set_vc_notify_channel_id を使い、値が None かで
        設定/解除を切り替える（解除専用の別関数を持たない）。"""
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_vc_notify_channel_id, guild.id, channel.id)
        await interaction.response.send_message(f"{channel.mention} をVC通知チャンネルと定めた。", ephemeral=True)

    @vcnotify_group.command(name="clear", description="【管理者】VC通知チャンネル設定を解除します")
    async def clear_vc_notify_ch(interaction: discord.Interaction):
        """set_vc_notify_ch と同じ setter に None を渡すことで解除を表す。"""
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_vc_notify_channel_id, guild.id, None)
        await interaction.response.send_message("VC通知チャンネルを解除した。", ephemeral=True)

    bot.tree.add_command(vcnotify_group)
