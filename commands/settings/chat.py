"""AI応答チャンネルの設定コマンド（/chat）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

from typing import cast

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from services.settings_store import awrite, set_response_channel_id


def register(chat_group: app_commands.Group) -> None:
    """/chat set・clear を登録する。"""

    @chat_group.command(name="set", description="【管理者】AI応答チャンネルを設定します")
    @app_commands.describe(channel="ChatGPTが応答するテキストチャンネル")
    async def set_response_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        """clear_response_channel_cmd と対になる設定側。書き込みを awrite
        経由にする理由（同期呼び出しのままだとイベントループが止まる）は
        awrite の docstring 参照。
        """
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_response_channel_id, guild.id, channel.id)
        await interaction.response.send_message(
            f"{channel.mention} を余への語りかけチャンネルと定めた。",
            ephemeral=True,
        )

    @chat_group.command(name="clear", description="【管理者】AI応答チャンネル設定を解除します")
    async def clear_response_channel_cmd(interaction: discord.Interaction):
        """None を書き込んで解除する。get_response_channel_id は未設定/None を
        0 として返す（services/settings_store.py参照）ため、この 0 が
        handle_chatgpt_message 側で「未設定」を表す番兵として扱われる経路に
        そのまま乗る。
        """
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_response_channel_id, guild.id, None)
        await interaction.response.send_message(
            "余への語りかけチャンネルを解除した。再設定されるまで余は応答しない。",
            ephemeral=True,
        )
