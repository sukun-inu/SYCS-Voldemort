"""リアクションロールの追加・削除・一覧コマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。

register() は登録だけを担い、コマンドと autocomplete の中身はモジュール
直下の関数に置いてある。入れ子のままだと候補の絞り込みも一覧の組み立ても
`register()` を通してしか呼べず、単体で確かめられない（CONTRIBUTING 5.）。
"""

from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from services.settings_store import add_reaction_role, awrite, get_reaction_roles, remove_reaction_role


async def _parse_message_id(interaction: discord.Interaction, message_id: str) -> int | None:
    """message_id を int にする。数値でなければ断って None を返す。

    メッセージID(snowflake)は64bitあり、Discordのスラッシュコマンド int
    オプションが素直に扱える範囲を超えて桁落ちしうる。str で受けて
    Python の任意精度 int に変換することで、そのリスクを避けている。
    """
    try:
        return int(message_id)
    except ValueError:
        await interaction.response.send_message("メッセージIDは数値で指定するがよい。", ephemeral=True)
        return None


async def _apply_add(
    interaction: discord.Interaction,
    message_id: str,
    emoji: str,
    role: discord.Role,
) -> None:
    """/reactionrole add の中身。"""
    if not await _ensure_admin(interaction):
        return
    mid = await _parse_message_id(interaction, message_id)
    if mid is None:
        return
    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild = cast(discord.Guild, interaction.guild)
    await awrite(add_reaction_role, guild.id, mid, emoji.strip(), role.id)
    await interaction.response.send_message(
        f"メッセージ `{mid}` に {emoji} → {role.mention} のリアクションロールを追加した。",
        ephemeral=True,
    )


async def _apply_remove(interaction: discord.Interaction, message_id: str, emoji: str) -> None:
    """/reactionrole remove の中身。message_id を str で受ける理由は add と同じ。"""
    if not await _ensure_admin(interaction):
        return
    mid = await _parse_message_id(interaction, message_id)
    if mid is None:
        return
    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild = cast(discord.Guild, interaction.guild)
    removed = await awrite(remove_reaction_role, guild.id, mid, emoji.strip())
    if removed:
        await interaction.response.send_message(f"リアクションロール ({emoji}) を取り除いた。", ephemeral=True)
    else:
        await interaction.response.send_message("そのようなリアクションロールは見つからなかった。", ephemeral=True)


async def _message_id_choices(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    """message_id の候補。value は str のまま返す。

    remove 側が受け取るのも str なので、ここで int に変換し直す必要はない。
    """
    if interaction.guild is None:
        return []
    rr = get_reaction_roles(interaction.guild.id)
    choices = []
    for mid, mapping in rr.items():
        if current and current not in str(mid):
            continue
        choices.append(app_commands.Choice(name=f"{mid}（{len(mapping)}件のロール）"[:100], value=str(mid)))
    return choices[:25]


async def _emoji_choices(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    """emoji の候補。同じコマンド内で先に入力済みの message_id で絞り込む。

    Discord の autocomplete は全パラメータをまとめて送るのではなく、
    入力中の1つずつ問い合わせてくるが、その時点で確定している他の
    パラメータ値は namespace 経由で見える。それを使って候補を
    選択済みメッセージの絵文字だけに絞り込む（未選択なら全件から）。
    件数上限は最後に slice する _message_id_choices と違い、
    ここは role 解決のループ中に25件で break して以降の処理を省く。
    """
    if interaction.guild is None:
        return []
    rr = get_reaction_roles(interaction.guild.id)
    selected_mid = str(getattr(interaction.namespace, "message_id", "") or "")
    mapping = rr.get(selected_mid, {}) if selected_mid else {}
    # message_id未選択時は全メッセージ分の絵文字から候補を出す
    source = mapping.items() if mapping else ((emoji, role_id) for mp in rr.values() for emoji, role_id in mp.items())
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


async def _apply_list(interaction: discord.Interaction) -> None:
    """/reactionrole list の中身。add/remove と違い ensure_admin なし。閲覧は全員に開放している。"""
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


def register(bot: Bot) -> None:
    """/reactionrole add・remove・list（リアクションロールの設定）を登録する。"""
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
        """リアクションロールを足す（本体は _apply_add）。"""
        await _apply_add(interaction, message_id, emoji, role)

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
        """リアクションロールを外す（本体は _apply_remove）。"""
        await _apply_remove(interaction, message_id, emoji)

    @remove_rr_cmd.autocomplete("message_id")
    async def _remove_rr_message_id_autocomplete(
        interaction: discord.Interaction, current: str
    ) -> list[app_commands.Choice[str]]:
        """message_id の候補（本体は _message_id_choices）。"""
        return await _message_id_choices(interaction, current)

    @remove_rr_cmd.autocomplete("emoji")
    async def _remove_rr_emoji_autocomplete(
        interaction: discord.Interaction, current: str
    ) -> list[app_commands.Choice[str]]:
        """emoji の候補（本体は _emoji_choices）。"""
        return await _emoji_choices(interaction, current)

    @reactionrole_group.command(name="list", description="リアクションロール一覧を表示します")
    async def list_rr_cmd(interaction: discord.Interaction):
        """リアクションロールの一覧を出す（本体は _apply_list）。"""
        await _apply_list(interaction)

    bot.tree.add_command(reactionrole_group)
