"""バイパスロール（検出の対象外）の設定コマンド（/bypass）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

from typing import List

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from commands.settings.picker import EntityPickerView
from services.settings_store import add_bypass_roles, get_bypass_role_ids, remove_bypass_roles


def register(bypass_group: app_commands.Group) -> None:
    @bypass_group.command(name="add", description="【管理者】バイパスロールを追加します（複数選択可）")
    async def add_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.RoleSelect(
            placeholder="追加するロールを選択（複数選択可・最大25個）", min_values=1, max_values=25
        )
        view = EntityPickerView(
            interaction.user.id, select, add_bypass_roles, "バイパスロールに加えた", "バイパスロール数"
        )
        await interaction.response.send_message(
            "バイパスロールに追加するロールを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @bypass_group.command(name="remove", description="【管理者】バイパスロールを削除します（複数選択可）")
    async def remove_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.RoleSelect(
            placeholder="削除するロールを選択（複数選択可・最大25個）", min_values=1, max_values=25
        )
        view = EntityPickerView(
            interaction.user.id, select, remove_bypass_roles, "バイパスロールから除いた", "バイパスロール数"
        )
        await interaction.response.send_message(
            "バイパスロールから削除するロールを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @bypass_group.command(name="list", description="【管理者】バイパスロール一覧を表示します")
    async def list_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        ids = get_bypass_role_ids(interaction.guild.id)
        if not ids:
            await interaction.response.send_message("バイパスロールはまだ設定されていない。", ephemeral=True)
            return

        role_mentions: List[str] = []
        for rid in ids:
            r = interaction.guild.get_role(rid)
            role_mentions.append(r.mention if r else f"<@&{rid}>")

        # 件数が多いとDiscordのメッセージ上限(2000文字)を超えて送信自体が失敗する。
        header = "バイパスロール一覧:\n"
        body = cap_list_for_message(role_mentions, budget=MESSAGE_BUDGET, header=header, limit=60, omitted_unit="個")
        await interaction.response.send_message(
            header + body,
            ephemeral=True,
        )
