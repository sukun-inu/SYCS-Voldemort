"""信頼済みユーザー（検出の対象外）の設定コマンド（/trusted）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

from typing import Any, List, cast

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from commands.settings.picker import EntityPickerView
from services.settings_store import add_trusted_users, get_trusted_user_ids, remove_trusted_users


def register(trusted_group: app_commands.Group) -> None:
    """/trusted add・remove・list を登録する。"""

    @trusted_group.command(name="add", description="【管理者】信頼済みユーザーを追加します（複数選択可）")
    async def add_trusted_members_cmd(interaction: discord.Interaction):
        """スラッシュコマンドの引数は固定個数しか取れないため、複数選択は
        EntityPickerView（UserSelect）に委ねる。ここでは選択UIを出すだけで、
        実際の保存(add_trusted_users)は選択確定後にビュー側が呼ぶ
        （commands/settings/bypass.py の add_bypass_roles_cmd と同じ形）。
        """
        if not await _ensure_admin_in_guild(interaction):
            return
        select: discord.ui.UserSelect[Any] = discord.ui.UserSelect(
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
        """add_trusted_members_cmd と同じ流れ。渡す関数が remove_trusted_users
        に変わるだけ。
        """
        if not await _ensure_admin_in_guild(interaction):
            return
        select: discord.ui.UserSelect[Any] = discord.ui.UserSelect(
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
        """guild.get_member が None を返すのは、ID だけ設定に残ったまま
        メンバーがサーバーを抜けた（キャッシュから落ちた）場合。mention は
        解決できないので `<@id>` の生メンションで代替する。
        """
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        ids = get_trusted_user_ids(guild.id)
        if not ids:
            await interaction.response.send_message("まだ誰も余の信頼を勝ち取っていない。", ephemeral=True)
            return

        members: List[str] = []
        for uid in ids:
            m = guild.get_member(uid)
            members.append(m.mention if m else f"<@{uid}>")

        # 件数が多いとDiscordのメッセージ上限(2000文字)を超えて送信自体が失敗する。
        header = "余が認めた者の一覧だ:\n"
        body = cap_list_for_message(members, budget=MESSAGE_BUDGET, header=header, limit=60, omitted_unit="名")
        await interaction.response.send_message(
            header + body,
            ephemeral=True,
        )
