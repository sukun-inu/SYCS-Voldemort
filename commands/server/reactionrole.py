"""リアクションロールの追加・削除・一覧コマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from services.settings_store import add_reaction_role, awrite, get_reaction_roles, remove_reaction_role


def register(bot: Bot) -> None:
    reactionrole_group = app_commands.Group(
        name="reactionrole", description="リアクションでロールを付与する設定", guild_only=True
    )

    @reactionrole_group.command(name="add", description="【管理者】リアクションロールを追加します")
    @app_commands.describe(
        message_id="対象メッセージのID",
        emoji="リアクションで使う絵文字",
        role="付与するロール",
    )
    async def add_rr_cmd(
        interaction: discord.Interaction,
        message_id: str,
        emoji: str,
        role: discord.Role,
    ):
        if not await _ensure_admin(interaction):
            return
        try:
            mid = int(message_id)
        except ValueError:
            await interaction.response.send_message("メッセージIDは数値で指定するがよい。", ephemeral=True)
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        await awrite(add_reaction_role, guild.id, mid, emoji.strip(), role.id)
        await interaction.response.send_message(
            f"メッセージ `{mid}` に {emoji} → {role.mention} のリアクションロールを追加した。",
            ephemeral=True,
        )

    @reactionrole_group.command(name="remove", description="【管理者】リアクションロールを削除します")
    @app_commands.describe(
        message_id="対象メッセージのID（候補から選択できる）",
        emoji="削除するリアクション絵文字（候補から選択できる）",
    )
    async def remove_rr_cmd(
        interaction: discord.Interaction,
        message_id: str,
        emoji: str,
    ):
        if not await _ensure_admin(interaction):
            return
        try:
            mid = int(message_id)
        except ValueError:
            await interaction.response.send_message("メッセージIDは数値で指定するがよい。", ephemeral=True)
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        removed = await awrite(remove_reaction_role, guild.id, mid, emoji.strip())
        if removed:
            await interaction.response.send_message(f"リアクションロール ({emoji}) を取り除いた。", ephemeral=True)
        else:
            await interaction.response.send_message("そのようなリアクションロールは見つからなかった。", ephemeral=True)

    @remove_rr_cmd.autocomplete("message_id")
    async def _remove_rr_message_id_autocomplete(
        interaction: discord.Interaction, current: str
    ) -> list[app_commands.Choice[str]]:
        if interaction.guild is None:
            return []
        rr = get_reaction_roles(interaction.guild.id)
        choices = []
        for mid, mapping in rr.items():
            if current and current not in str(mid):
                continue
            choices.append(app_commands.Choice(name=f"{mid}（{len(mapping)}件のロール）"[:100], value=str(mid)))
        return choices[:25]

    @remove_rr_cmd.autocomplete("emoji")
    async def _remove_rr_emoji_autocomplete(
        interaction: discord.Interaction, current: str
    ) -> list[app_commands.Choice[str]]:
        if interaction.guild is None:
            return []
        rr = get_reaction_roles(interaction.guild.id)
        selected_mid = str(getattr(interaction.namespace, "message_id", "") or "")
        mapping = rr.get(selected_mid, {}) if selected_mid else {}
        # message_id未選択時は全メッセージ分の絵文字から候補を出す
        source = (
            mapping.items() if mapping else ((emoji, role_id) for mp in rr.values() for emoji, role_id in mp.items())
        )
        choices = []
        for emoji, role_id in source:
            if current and current.lower() not in emoji.lower():
                continue
            role = interaction.guild.get_role(role_id)
            label = f"{emoji} → {role.name if role else role_id}"
            choices.append(app_commands.Choice(name=label[:100], value=emoji))
            if len(choices) >= 25:
                break
        return choices

    @reactionrole_group.command(name="list", description="リアクションロール一覧を表示します")
    async def list_rr_cmd(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        rr = get_reaction_roles(interaction.guild.id)
        if not rr:
            await interaction.response.send_message("リアクションロールは設定されておらぬ。", ephemeral=True)
            return
        lines = []
        for msg_id, mapping in rr.items():
            for emoji, role_id in mapping.items():
                lines.append(f"メッセージ `{msg_id}` | {emoji} → <@&{role_id}>")
        # 件数が多いとDiscordのメッセージ上限(2000文字)を超えるため打ち切るが、
        # 何件省いたかは隠さない。
        header = "**リアクションロール一覧**\n"
        body = cap_list_for_message(lines, budget=MESSAGE_BUDGET, header=header, limit=20, omitted_unit="件")
        await interaction.response.send_message(header + body, ephemeral=True)

    bot.tree.add_command(reactionrole_group)
