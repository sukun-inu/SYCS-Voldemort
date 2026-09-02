"""バイパスロール（検出の対象外）の設定コマンド（/bypass）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
"""

from typing import Any, List, cast

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from commands.settings.picker import EntityPickerView
from services.settings_store import add_bypass_roles, get_bypass_role_ids, remove_bypass_roles


def register(bypass_group: app_commands.Group) -> None:
    """/bypass add・remove・list を登録する。"""

    @bypass_group.command(name="add", description="【管理者】バイパスロールを追加します（複数選択可）")
    async def add_bypass_roles_cmd(interaction: discord.Interaction):
        """スラッシュコマンドの引数は固定個数しか取れないため、複数選択は
        EntityPickerView（RoleSelect）に委ねる。ここでは選択UIを出すだけで、
        実際の保存(add_bypass_roles)は選択確定後にビュー側が呼ぶ。
        """
        if not await _ensure_admin_in_guild(interaction):
            return
        select: discord.ui.RoleSelect[Any] = discord.ui.RoleSelect(
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
        """add_bypass_roles_cmd と同じ流れ（複数選択を EntityPickerView に委ねる
        理由もそちら参照）。渡す関数が remove_bypass_roles に変わるだけ。
        """
        if not await _ensure_admin_in_guild(interaction):
            return
        select: discord.ui.RoleSelect[Any] = discord.ui.RoleSelect(
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
        """guild.get_role が None を返すのは、ID だけ設定に残ったままロールが
        削除された場合。mention は解決できないので `<@&id>` の生メンションで
        代替し、それだけを理由に一覧表示自体を落とさない。
        """
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)
        ids = get_bypass_role_ids(guild.id)
        if not ids:
            await interaction.response.send_message("バイパスロールはまだ設定されていない。", ephemeral=True)
            return

        role_mentions: List[str] = []
        for rid in ids:
            r = guild.get_role(rid)
            role_mentions.append(r.mention if r else f"<@&{rid}>")

        # 件数が多いとDiscordのメッセージ上限(2000文字)を超えて送信自体が失敗する。
        header = "バイパスロール一覧:\n"
        body = cap_list_for_message(role_mentions, budget=MESSAGE_BUDGET, header=header, limit=60, omitted_unit="個")
        await interaction.response.send_message(
            header + body,
            ephemeral=True,
        )
