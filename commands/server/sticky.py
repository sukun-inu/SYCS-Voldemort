"""チャンネル最下部に貼り付けるスティッキーメッセージのコマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from services.settings_store import awrite, get_sticky_messages, set_sticky_message
from services.sticky_service import delete_sticky, post_sticky


def register(bot: Bot) -> None:
    """/sticky set・clear・list を登録する。"""
    sticky_group = app_commands.Group(
        name="sticky", description="チャンネル最下部に貼り付けるメッセージ", guild_only=True
    )

    @sticky_group.command(name="set", description="【管理者】このチャンネルにスティッキーを設定します")
    @app_commands.describe(content="スティッキーとして固定するメッセージ内容")
    async def sticky_cmd(interaction: discord.Interaction, content: str):
        """content.replace("\\n", "\n") は、ユーザーが改行のつもりで打った
        リテラルな "\\n" を実際の改行に戻す。スラッシュコマンドの文字列入力
        は実改行を打ちにくい環境があるための救済。

        確認の ephemeral 応答を先に返し、実際のチャンネル投稿(post_sticky)は
        その後に行う。post_sticky 側が遅くても、3秒の応答期限には影響しない
        順序にしている。
        """
        if not await _ensure_admin(interaction):
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message("テキストチャンネルでのみ使えるぞ。", ephemeral=True)
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(set_sticky_message, guild.id, interaction.channel.id, content.replace("\\n", "\n"))
        await interaction.response.send_message("スティッキーメッセージを刻んだ。", ephemeral=True)
        await post_sticky(interaction.channel, guild.id)

    @sticky_group.command(name="clear", description="【管理者】このチャンネルのスティッキーを解除します")
    async def unsticky_cmd(interaction: discord.Interaction):
        """sticky_cmd と同じ理由で、応答を返してから delete_sticky を呼ぶ順序にしている。"""
        if not await _ensure_admin(interaction):
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message("テキストチャンネルでのみ使えるぞ。", ephemeral=True)
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await interaction.response.send_message("スティッキーメッセージを取り除いた。", ephemeral=True)
        await delete_sticky(interaction.channel, guild.id)

    @sticky_group.command(name="list", description="スティッキー設定一覧を表示します")
    async def list_stickies_cmd(interaction: discord.Interaction):
        """set/clear と違い ensure_admin なし。閲覧は全員に開放している。"""
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
