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


def register(bot: Bot, bot_group: app_commands.Group) -> None:
    @bot_group.command(name="settings", description="【管理者】Bot設定を一覧表示します")
    async def settings_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild_id = cast(discord.Guild, interaction.guild).id

        log_settings = get_log_settings(guild_id)
        log_ch_id = log_settings.get("channel_id")
        log_level = log_settings.get("level", "INFO")
        log_ch_text = f"<#{log_ch_id}>" if log_ch_id else "未設定"

        resp_ch_id = get_response_channel_id(guild_id)
        resp_ch_text = f"<#{resp_ch_id}>" if resp_ch_id else "未設定（無効）"

        trusted_ids = get_trusted_user_ids(guild_id)
        if not trusted_ids:
            trusted_text = "なし"
        else:
            mentions = [f"<@{uid}>" for uid in trusted_ids]
            # embedのfield value（メッセージ本文ではない）なので上限は1024文字。
            trusted_text = cap_list_for_message(
                mentions,
                budget=EMBED_FIELD_BUDGET,
                limit=15,
                omitted_unit="名",
                joiner=", ",
            )

        bypass_ids = get_bypass_role_ids(guild_id)
        if not bypass_ids:
            bypass_text = "なし"
        else:
            mentions = [f"<@&{rid}>" for rid in bypass_ids]
            bypass_text = cap_list_for_message(
                mentions,
                budget=EMBED_FIELD_BUDGET,
                limit=15,
                omitted_unit="個",
                joiner=", ",
            )

        embed = discord.Embed(
            title="余の現在の設定だ",
            description=f"サーバーID: `{guild_id}`",
            color=discord.Color.blurple(),
        )
        embed.add_field(name="ログチャンネル", value=log_ch_text, inline=True)
        embed.add_field(name="ログレベル", value=log_level, inline=True)
        embed.add_field(name="AI応答チャンネル", value=resp_ch_text, inline=True)
        embed.add_field(
            name=f"信頼済みユーザー（{len(trusted_ids)}名）",
            value=trusted_text,
            inline=False,
        )
        embed.add_field(
            name=f"バイパスロール（{len(bypass_ids)}個）",
            value=bypass_text,
            inline=False,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    @bot_group.command(name="help", description="利用可能なスラッシュコマンド一覧を表示します")
    async def help_cmd(interaction: discord.Interaction):
        # walk_commands() はグループ自身も返し、cmd.name は葉の名前しか持たない。
        # 素直に name で集めると /log channel と /quake channel が衝突して
        # 片方が消える。実際に打てる形（qualified_name）で並べる。
        all_commands: dict[str, str] = {}
        for cmd in bot.tree.walk_commands():
            if isinstance(cmd, app_commands.Group):
                continue
            all_commands[cmd.qualified_name] = cmd.description or "(説明なし)"

        items = sorted(all_commands.items(), key=lambda x: x[0])
        lines = [f"`/{name}` — {desc}" for name, desc in items]

        chunk_size = 20
        embeds: list[discord.Embed] = []
        for i in range(0, len(lines), chunk_size):
            chunk = lines[i : i + chunk_size]
            is_first = i == 0
            embed = discord.Embed(
                title="余が授けたコマンドの一覧" if is_first else None,
                description=(
                    "余の力を借りられるコマンドだ。使いこなすがよい。\n\n" + "\n".join(chunk)
                    if is_first
                    else "\n".join(chunk)
                ),
                color=discord.Color.blurple(),
            )
            embeds.append(embed)

        await interaction.response.send_message(embeds=embeds, ephemeral=True, view=admin_site_view())
