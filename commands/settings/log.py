"""ログの送信先とレベルの設定コマンド（/log）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

from typing import cast

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from services.logging_service import get_log_settings, set_log_channel, set_log_level


def register(log_group: app_commands.Group) -> None:
    @log_group.command(name="channel", description="【管理者】ログ送信チャンネルを設定します")
    @app_commands.describe(channel="ログを投稿するテキストチャンネル")
    async def set_log_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        set_log_channel(guild.id, channel.id)
        settings = get_log_settings(guild.id)
        await interaction.response.send_message(
            f"{channel.mention} を余のログチャンネルと定めた。ログレベル: {settings.get('level', 'INFO')}",
            ephemeral=True,
        )

    @log_group.command(name="level", description="【管理者】ログレベルを設定します")
    @app_commands.describe(level="記録するログの詳細さ")
    @app_commands.choices(
        level=[
            app_commands.Choice(name="NONE（ログを記録しない）", value="NONE"),
            app_commands.Choice(name="ERROR（エラーのみ）", value="ERROR"),
            app_commands.Choice(name="INFO（通常運用向け・推奨）", value="INFO"),
            app_commands.Choice(name="DEBUG（詳細・調査向け）", value="DEBUG"),
        ]
    )
    async def set_log_level_cmd(interaction: discord.Interaction, level: str):
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        try:
            set_log_level(guild.id, level)
        except ValueError as e:
            await interaction.response.send_message(str(e), ephemeral=True)
            return

        settings = get_log_settings(guild.id)
        channel_id = settings.get("channel_id")
        ch_text = f"<#{channel_id}>" if channel_id else "未設定"
        await interaction.response.send_message(
            f"ログレベルを {settings.get('level')} に定めた。ログチャンネル: {ch_text}",
            ephemeral=True,
        )
