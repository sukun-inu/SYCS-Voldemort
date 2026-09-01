"""信頼済みユーザー（検出の対象外）の設定コマンド（/trusted）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

from typing import List

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from commands.settings.picker import EntityPickerView
from services.settings_store import add_trusted_users, get_trusted_user_ids, remove_trusted_users


def register(trusted_group: app_commands.Group) -> None:
    @trusted_group.command(name="add", description="【管理者】信頼済みユーザーを追加します（複数選択可）")
    async def add_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.UserSelect(
            placeholder="追加するユーザーを選択（複数選択可・最大25人）", min_values=1, max_values=25
        )
        view = EntityPickerView(
            interaction.user.id, select, add_trusted_users, "余の信頼を与えた", "信頼済みユーザー数"
        )
        await interaction.response.send_message(
            "信頼済みに追加するユーザーを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @trusted_group.command(name="remove", description="【管理者】信頼済みユーザーを削除します（複数選択可）")
    async def remove_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.UserSelect(
            placeholder="削除するユーザーを選択（複数選択可・最大25人）", min_values=1, max_values=25
        )
        view = EntityPickerView(
            interaction.user.id, select, remove_trusted_users, "余の信頼を取り消した", "信頼済みユーザー数"
        )
        await interaction.response.send_message(
            "信頼済みから削除するユーザーを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @trusted_group.command(name="list", description="【管理者】信頼済みユーザー一覧を表示します")
    async def list_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        ids = get_trusted_user_ids(interaction.guild.id)
        if not ids:
            await interaction.response.send_message("まだ誰も余の信頼を勝ち取っていない。", ephemeral=True)
            return

        members: List[str] = []
        for uid in ids:
            m = interaction.guild.get_member(uid)
            members.append(m.mention if m else f"<@{uid}>")

        # 件数が多いとDiscordのメッセージ上限(2000文字)を超えて送信自体が失敗する。
        header = "余が認めた者の一覧だ:\n"
        body = cap_list_for_message(members, budget=MESSAGE_BUDGET, header=header, limit=60, omitted_unit="名")
        await interaction.response.send_message(
            header + body,
            ephemeral=True,
        )
