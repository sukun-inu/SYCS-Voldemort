"""AI応答チャンネルの設定コマンド（/chat）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from services.settings_store import awrite, set_response_channel_id


def register(chat_group: app_commands.Group) -> None:
    @chat_group.command(name="set", description="【管理者】AI応答チャンネルを設定します")
    @app_commands.describe(channel="ChatGPTが応答するテキストチャンネル")
    async def set_response_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        await awrite(set_response_channel_id, interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"{channel.mention} を余への語りかけチャンネルと定めた。",
            ephemeral=True,
        )

    @chat_group.command(name="clear", description="【管理者】AI応答チャンネル設定を解除します")
    async def clear_response_channel_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        await awrite(set_response_channel_id, interaction.guild.id, None)
        await interaction.response.send_message(
            "余への語りかけチャンネルを解除した。再設定されるまで余は応答しない。",
            ephemeral=True,
        )
