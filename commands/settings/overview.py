"""Bot の設定一覧とコマンドヘルプ（/bot）。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
help コマンドが bot.tree を走査するため、ここだけ bot を受け取る。
"""

from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import EMBED_FIELD_BUDGET, admin_site_view, cap_list_for_message
from services.logging_service import get_log_settings
from services.settings_store import get_bypass_role_ids, get_response_channel_id, get_trusted_user_ids


# /bot help を1枚の embed へ詰める件数。embed の description は4096文字まで
# なので、コマンドが増えるといつか超える。超えた日に /bot help が丸ごと失敗
# するので、件数で先に切る。
HELP_CHUNK_SIZE = 20
# 一覧に並べる信頼済みユーザー／バイパスロールの件数。embed の1フィールドは
# 1024文字までで、多いギルドだと収まらない。
OVERVIEW_LIST_LIMIT = 15


def _mention_list(ids: list, template: str, unit: str) -> str:
    """ID の並びを、embed の1フィールドに収まる長さの列挙にする。

    信頼済みユーザーとバイパスロールで同じ丸め方をすること。片方だけ丸めても、
    もう片方が多いギルドでは**そのフィールドだけ落ちて表示が壊れる。**
    """
    if not ids:
        return "なし"
    # embedのfield value（メッセージ本文ではない）なので上限は1024文字。
    return cap_list_for_message(
        [template.format(id=value) for value in ids],
        budget=EMBED_FIELD_BUDGET,
        limit=OVERVIEW_LIST_LIMIT,
        omitted_unit=unit,
        joiner=", ",
    )


def _settings_embed(guild_id: int) -> discord.Embed:
    """いまの Bot 設定を1枚の Embed にする。"""
    log_settings = get_log_settings(guild_id)
    log_ch_id = log_settings.get("channel_id")
    resp_ch_id = get_response_channel_id(guild_id)
    trusted_ids = get_trusted_user_ids(guild_id)
    bypass_ids = get_bypass_role_ids(guild_id)

    embed = discord.Embed(
        title="余の現在の設定だ",
        description=f"サーバーID: `{guild_id}`",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="ログチャンネル", value=f"<#{log_ch_id}>" if log_ch_id else "未設定", inline=True)
    embed.add_field(name="ログレベル", value=log_settings.get("level", "INFO"), inline=True)
    embed.add_field(
        name="AI応答チャンネル",
        value=f"<#{resp_ch_id}>" if resp_ch_id else "未設定（無効）",
        inline=True,
    )
    embed.add_field(
        name=f"信頼済みユーザー（{len(trusted_ids)}名）",
        value=_mention_list(trusted_ids, "<@{id}>", "名"),
        inline=False,
    )
    embed.add_field(
        name=f"バイパスロール（{len(bypass_ids)}個）",
        value=_mention_list(bypass_ids, "<@&{id}>", "個"),
        inline=False,
    )
    return embed


def _command_lines(bot: Bot) -> list[str]:
    """打てるコマンドを1行ずつ並べる。

    walk_commands() はグループ自身も返し、cmd.name は葉の名前しか持たない。
    素直に name で集めると /log channel と /quake channel が衝突して片方が
    消える。**実際に打てる形（qualified_name）**で並べる。

    ここに出るのは Discord へ sync 済みのコマンドとは限らない。このプロセスの
    bot.tree に register() 済みのものを見ているだけなので、sync 前でも並ぶし、
    他プロセスの状態は反映されない。
    """
    all_commands: dict[str, str] = {}
    for cmd in bot.tree.walk_commands():
        if isinstance(cmd, app_commands.Group):
            continue
        all_commands[cmd.qualified_name] = cmd.description or "(説明なし)"

    return [f"`/{name}` — {desc}" for name, desc in sorted(all_commands.items(), key=lambda x: x[0])]


def _help_embeds(lines: list[str]) -> list[discord.Embed]:
    """コマンド一覧を、見出し付きの1枚目とそれ以降に分ける。

    見出しを全ページに付けると同じ題が何度も並ぶので、最初の1枚だけに付ける。
    """
    embeds: list[discord.Embed] = []
    for i in range(0, len(lines), HELP_CHUNK_SIZE):
        chunk = lines[i : i + HELP_CHUNK_SIZE]
        is_first = i == 0
        embeds.append(
            discord.Embed(
                title="余が授けたコマンドの一覧" if is_first else None,
                description=(
                    "余の力を借りられるコマンドだ。使いこなすがよい。\n\n" + "\n".join(chunk)
                    if is_first
                    else "\n".join(chunk)
                ),
                color=discord.Color.blurple(),
            )
        )
    return embeds


def register(bot: Bot, bot_group: app_commands.Group) -> None:
    """/bot settings（設定一覧）と /bot help（コマンド一覧）を登録する。"""

    @bot_group.command(name="settings", description="【管理者】Bot設定を一覧表示します")
    async def settings_cmd(interaction: discord.Interaction):
        """設定の一覧（本体は _settings_embed）。"""
        if not await _ensure_admin_in_guild(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild_id = cast(discord.Guild, interaction.guild).id
        embed = _settings_embed(guild_id)
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    @bot_group.command(name="help", description="利用可能なスラッシュコマンド一覧を表示します")
    async def help_cmd(interaction: discord.Interaction):
        """コマンドの一覧（本体は _command_lines / _help_embeds）。"""
        embeds = _help_embeds(_command_lines(bot))
        await interaction.response.send_message(embeds=embeds, ephemeral=True, view=admin_site_view())
