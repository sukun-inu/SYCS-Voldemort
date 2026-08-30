"""チャンネル最下部に貼り付けるスティッキーメッセージのコマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from services.settings_store import awrite, get_sticky_messages, set_sticky_message
from services.sticky_service import delete_sticky, post_sticky


def register(bot: Bot) -> None:
    sticky_group = app_commands.Group(
        name="sticky", description="チャンネル最下部に貼り付けるメッセージ", guild_only=True
    )

    @sticky_group.command(name="set", description="【管理者】このチャンネルにスティッキーを設定します")
    @app_commands.describe(content="スティッキーとして固定するメッセージ内容")
    async def sticky_cmd(interaction: discord.Interaction, content: str):
        if not await _ensure_admin(interaction):
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message("テキストチャンネルでのみ使えるぞ。", ephemeral=True)
            return
        await awrite(set_sticky_message, interaction.guild.id, interaction.channel.id, content.replace("\\n", "\n"))
        await interaction.response.send_message("スティッキーメッセージを刻んだ。", ephemeral=True)
        await post_sticky(interaction.channel, interaction.guild.id)

    @sticky_group.command(name="clear", description="【管理者】このチャンネルのスティッキーを解除します")
    async def unsticky_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message("テキストチャンネルでのみ使えるぞ。", ephemeral=True)
            return
        await interaction.response.send_message("スティッキーメッセージを取り除いた。", ephemeral=True)
        await delete_sticky(interaction.channel, interaction.guild.id)

    @sticky_group.command(name="list", description="スティッキー設定一覧を表示します")
    async def list_stickies_cmd(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        stickies = get_sticky_messages(interaction.guild.id)
        if not stickies:
            await interaction.response.send_message("スティッキーメッセージは設定されておらぬ。", ephemeral=True)
            return
        lines = [f"<#{ch_id}>: {v.get('content', '')[:50]}" for ch_id, v in stickies.items()]
        # チャンネル数に上限が無いため、件数が多いとDiscordのメッセージ上限(2000文字)を超えうる。
        header = "**スティッキー一覧**\n"
        body = cap_list_for_message(lines, budget=MESSAGE_BUDGET, header=header, limit=25, omitted_unit="件")
        await interaction.response.send_message(header + body, ephemeral=True)

    bot.tree.add_command(sticky_group)
