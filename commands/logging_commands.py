from typing import Callable, List, Optional

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import admin_site_view
from services.logging_service import get_log_settings, set_log_channel, set_log_level
from services.settings_store import (
    add_bypass_roles,
    add_trusted_users,
    get_bypass_role_ids,
    get_response_channel_id,
    get_trusted_user_ids,
    remove_bypass_roles,
    remove_trusted_users,
    set_response_channel_id,
)


async def _update_entity_list(
    interaction: discord.Interaction,
    entities: list,
    update_fn: Callable,
    action_text: str,
    count_label: str,
) -> None:
    ids = [e.id for e in entities]
    updated = update_fn(interaction.guild.id, ids)
    mentions = ", ".join(e.mention for e in entities)
    await interaction.response.send_message(
        f"{action_text}: {mentions}\n（{count_label}: {len(updated)}）",
        ephemeral=True,
    )


def register_logging_commands(bot: Bot) -> None:

    @bot.tree.command(name="log_channel_set", description="【管理者】ログ送信チャンネルを設定します")
    @app_commands.describe(channel="ログを投稿するテキストチャンネル")
    async def set_log_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_log_channel(interaction.guild.id, channel.id)
        settings = get_log_settings(interaction.guild.id)
        await interaction.response.send_message(
            f"{channel.mention} を余のログチャンネルと定めた。ログレベル: {settings.get('level', 'INFO')}",
            ephemeral=True,
        )

    @bot.tree.command(name="log_level_set", description="【管理者】ログレベルを設定します")
    @app_commands.describe(level="NONE / ERROR / INFO / DEBUG のいずれか")
    async def set_log_level_cmd(interaction: discord.Interaction, level: str):
        if not await _ensure_admin_in_guild(interaction):
            return

        try:
            set_log_level(interaction.guild.id, level)
        except ValueError as e:
            await interaction.response.send_message(str(e), ephemeral=True)
            return

        settings = get_log_settings(interaction.guild.id)
        channel_id = settings.get("channel_id")
        ch_text = f"<#{channel_id}>" if channel_id else "未設定"
        await interaction.response.send_message(
            f"ログレベルを {settings.get('level')} に定めた。ログチャンネル: {ch_text}",
            ephemeral=True,
        )

    @bot.tree.command(name="chat_channel_set", description="【管理者】AI応答チャンネルを設定します")
    @app_commands.describe(channel="ChatGPTが応答するテキストチャンネル")
    async def set_response_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_response_channel_id(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"{channel.mention} を余への語りかけチャンネルと定めた。",
            ephemeral=True,
        )

    @bot.tree.command(name="chat_channel_clear", description="【管理者】AI応答チャンネル設定を解除します")
    async def clear_response_channel_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_response_channel_id(interaction.guild.id, None)
        await interaction.response.send_message(
            "余への語りかけチャンネルを解除した。どこからでも語りかけるがよい。",
            ephemeral=True,
        )

    @bot.tree.command(name="trusted_member_add", description="【管理者】信頼済みユーザーを追加します")
    @app_commands.describe(
        member1="信頼済みに追加するメンバー1",
        member2="信頼済みに追加するメンバー2 (任意)",
        member3="信頼済みに追加するメンバー3 (任意)",
        member4="信頼済みに追加するメンバー4 (任意)",
        member5="信頼済みに追加するメンバー5 (任意)",
    )
    async def add_trusted_members_cmd(
        interaction: discord.Interaction,
        member1: discord.Member,
        member2: Optional[discord.Member] = None,
        member3: Optional[discord.Member] = None,
        member4: Optional[discord.Member] = None,
        member5: Optional[discord.Member] = None,
    ):
        if not await _ensure_admin_in_guild(interaction):
            return

        members = [m for m in [member1, member2, member3, member4, member5] if m is not None]
        await _update_entity_list(interaction, members, add_trusted_users, "余の信頼を与えた", "信頼済みユーザー数")

    @bot.tree.command(name="trusted_member_remove", description="【管理者】信頼済みユーザーを削除します")
    @app_commands.describe(
        member1="削除するメンバー1",
        member2="削除するメンバー2 (任意)",
        member3="削除するメンバー3 (任意)",
        member4="削除するメンバー4 (任意)",
        member5="削除するメンバー5 (任意)",
    )
    async def remove_trusted_members_cmd(
        interaction: discord.Interaction,
        member1: discord.Member,
        member2: Optional[discord.Member] = None,
        member3: Optional[discord.Member] = None,
        member4: Optional[discord.Member] = None,
        member5: Optional[discord.Member] = None,
    ):
        if not await _ensure_admin_in_guild(interaction):
            return

        members = [m for m in [member1, member2, member3, member4, member5] if m is not None]
        await _update_entity_list(interaction, members, remove_trusted_users, "余の信頼を取り消した", "信頼済みユーザー数")

    @bot.tree.command(name="trusted_member_list", description="【管理者】信頼済みユーザー一覧を表示します")
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

        await interaction.response.send_message(
            "余が認めた者の一覧だ:\n" + "\n".join(members),
            ephemeral=True,
        )

    @bot.tree.command(name="bypass_role_add", description="【管理者】バイパスロールを追加します")
    @app_commands.describe(
        role1="追加するロール1",
        role2="追加するロール2 (任意)",
        role3="追加するロール3 (任意)",
    )
    async def add_bypass_roles_cmd(
        interaction: discord.Interaction,
        role1: discord.Role,
        role2: Optional[discord.Role] = None,
        role3: Optional[discord.Role] = None,
    ):
        if not await _ensure_admin_in_guild(interaction):
            return

        roles = [r for r in [role1, role2, role3] if r is not None]
        await _update_entity_list(interaction, roles, add_bypass_roles, "バイパスロールに加えた", "バイパスロール数")

    @bot.tree.command(name="bypass_role_remove", description="【管理者】バイパスロールを削除します")
    @app_commands.describe(
        role1="削除するロール1",
        role2="削除するロール2 (任意)",
        role3="削除するロール3 (任意)",
    )
    async def remove_bypass_roles_cmd(
        interaction: discord.Interaction,
        role1: discord.Role,
        role2: Optional[discord.Role] = None,
        role3: Optional[discord.Role] = None,
    ):
        if not await _ensure_admin_in_guild(interaction):
            return

        roles = [r for r in [role1, role2, role3] if r is not None]
        await _update_entity_list(interaction, roles, remove_bypass_roles, "バイパスロールから除いた", "バイパスロール数")

    @bot.tree.command(name="bypass_role_list", description="【管理者】バイパスロール一覧を表示します")
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

        await interaction.response.send_message(
            "バイパスロール一覧:\n" + "\n".join(role_mentions),
            ephemeral=True,
        )

    @bot.tree.command(name="bot_settings", description="【管理者】Bot設定を一覧表示します")
    async def settings_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        guild_id = interaction.guild.id

        log_settings = get_log_settings(guild_id)
        log_ch_id = log_settings.get("channel_id")
        log_level = log_settings.get("level", "INFO")
        log_ch_text = f"<#{log_ch_id}>" if log_ch_id else "未設定"

        resp_ch_id = get_response_channel_id(guild_id)
        resp_ch_text = f"<#{resp_ch_id}>" if resp_ch_id else "未設定"

        trusted_ids = get_trusted_user_ids(guild_id)
        if not trusted_ids:
            trusted_text = "なし"
        else:
            mentions = [f"<@{uid}>" for uid in trusted_ids[:15]]
            trusted_text = ", ".join(mentions)
            if len(trusted_ids) > 15:
                trusted_text += f" …他{len(trusted_ids) - 15}名"

        bypass_ids = get_bypass_role_ids(guild_id)
        if not bypass_ids:
            bypass_text = "なし"
        else:
            mentions = [f"<@&{rid}>" for rid in bypass_ids[:15]]
            bypass_text = ", ".join(mentions)
            if len(bypass_ids) > 15:
                bypass_text += f" …他{len(bypass_ids) - 15}個"

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

    @bot.tree.command(name="bot_help", description="利用可能なスラッシュコマンド一覧を表示します")
    async def help_cmd(interaction: discord.Interaction):
        commands = {}
        for cmd in bot.tree.walk_commands():
            commands[cmd.name] = cmd.description or "(説明なし)"

        items = sorted(commands.items(), key=lambda x: x[0])

        embed = discord.Embed(
            title="余が授けたコマンドの一覧",
            description="余の力を借りられるコマンドだ。使いこなすがよい。",
            color=discord.Color.blurple(),
        )

        for name, desc in items:
            embed.add_field(name=f"/{name}", value=desc or "(説明なし)", inline=False)

        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())
