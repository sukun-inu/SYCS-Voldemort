import discord
from discord import app_commands
from discord.ext.commands import Bot
from typing import Optional

from services.logging_service import set_log_channel, set_log_level, get_log_settings
from services.settings_store import (
    set_response_channel_id,
    get_response_channel_id,
    add_trusted_users,
    remove_trusted_users,
    get_trusted_user_ids,
    add_bypass_roles,
    remove_bypass_roles,
    get_bypass_role_ids,
)


async def _ensure_admin_in_guild(interaction: discord.Interaction) -> bool:
    """ギルド内かつ管理者であることを確認"""
    if interaction.guild is None:
        await interaction.response.send_message("ギルド内でのみ使用可能だ。", ephemeral=True)
        return False

    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("このコマンドは管理者のみが実行できる。", ephemeral=True)
        return False

    return True


def register_logging_commands(bot: Bot) -> None:
    """ログ/設定関連のスラッシュコマンドを登録"""

    @bot.tree.command(name="set_log_channel", description="ボットの動作ログを送信するチャンネルを設定（管理者専用）")
    @app_commands.describe(channel="ログを投稿するテキストチャンネル")
    async def set_log_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_log_channel(interaction.guild.id, channel.id)
        settings = get_log_settings(interaction.guild.id)
        await interaction.response.send_message(
            f"ログチャンネルを {channel.mention} に設定した。現在のログレベル: {settings.get('level', 'INFO')}",
            ephemeral=True,
        )

    @bot.tree.command(name="set_log_level", description="ボットの動作ログレベルを設定（管理者専用）")
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
            f"ログレベルを {settings.get('level')} に設定した。現在のログチャンネル: {ch_text}",
            ephemeral=True,
        )

    @bot.tree.command(name="set_response_channel", description="ChatGPT応答チャンネルを設定（管理者専用）")
    @app_commands.describe(channel="ChatGPTが応答するテキストチャンネル")
    async def set_response_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_response_channel_id(interaction.guild.id, channel.id)
        current = get_response_channel_id(interaction.guild.id)
        await interaction.response.send_message(
            f"ChatGPT応答チャンネルを {channel.mention} に設定した。（現在のID: {current}）",
            ephemeral=True,
        )

    @bot.tree.command(name="clear_response_channel", description="ChatGPT応答チャンネル設定を解除（管理者専用）")
    async def clear_response_channel_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_response_channel_id(interaction.guild.id, None)
        await interaction.response.send_message(
            "ChatGPT応答チャンネル設定を解除しました。",
            ephemeral=True,
        )

    @bot.tree.command(name="add_trusted_members", description="信頼済みユーザーとして追加（セキュリティチェック対象外・管理者専用）")
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
        ids = [m.id for m in members]
        updated = add_trusted_users(interaction.guild.id, ids)
        mentions = ", ".join(m.mention for m in members)
        await interaction.response.send_message(
            f"信頼済みユーザーに追加: {mentions}\n現在の信頼済みユーザー数: {len(updated)}",
            ephemeral=True,
        )

    @bot.tree.command(name="remove_trusted_members", description="信頼済みユーザーから削除（管理者専用）")
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
        ids = [m.id for m in members]
        updated = remove_trusted_users(interaction.guild.id, ids)
        mentions = ", ".join(m.mention for m in members)
        await interaction.response.send_message(
            f"信頼済みユーザーから削除: {mentions}\n現在の信頼済みユーザー数: {len(updated)}",
            ephemeral=True,
        )

    @bot.tree.command(name="list_trusted_members", description="信頼済みユーザー一覧を表示（管理者専用）")
    async def list_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        ids = get_trusted_user_ids(interaction.guild.id)
        if not ids:
            await interaction.response.send_message("信頼済みユーザーは登録されていない。", ephemeral=True)
            return

        # 実在するメンバーだけ mention する
        members: list[str] = []
        for uid in ids:
            m = interaction.guild.get_member(uid)
            members.append(m.mention if m else f"<@{uid}>")

        await interaction.response.send_message(
            "信頼済みユーザー一覧:\n" + "\n".join(members),
            ephemeral=True,
        )

    @bot.tree.command(name="add_bypass_roles", description="セキュリティチェックをバイパスするロールを追加（管理者専用）")
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
        ids = [r.id for r in roles]
        updated = add_bypass_roles(interaction.guild.id, ids)
        names = ", ".join(r.mention for r in roles)
        await interaction.response.send_message(
            f"バイパスロールに追加: {names}\n現在のバイパスロール数: {len(updated)}",
            ephemeral=True,
        )

    @bot.tree.command(name="remove_bypass_roles", description="バイパスロールから削除（管理者専用）")
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
        ids = [r.id for r in roles]
        updated = remove_bypass_roles(interaction.guild.id, ids)
        names = ", ".join(r.mention for r in roles)
        await interaction.response.send_message(
            f"バイパスロールから削除: {names}\n現在のバイパスロール数: {len(updated)}",
            ephemeral=True,
        )

    @bot.tree.command(name="list_bypass_roles", description="バイパスロール一覧を表示（管理者専用）")
    async def list_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        ids = get_bypass_role_ids(interaction.guild.id)
        if not ids:
            await interaction.response.send_message("バイパスロールは登録されていない。", ephemeral=True)
            return

        role_mentions: list[str] = []
        for rid in ids:
            r = interaction.guild.get_role(rid)
            role_mentions.append(r.mention if r else f"<@&{rid}>")

        await interaction.response.send_message(
            "バイパスロール一覧:\n" + "\n".join(role_mentions),
            ephemeral=True,
        )

    @bot.tree.command(name="help", description="このボットで利用可能なスラッシュコマンド一覧を表示")
    async def help_cmd(interaction: discord.Interaction):
        """/help で全スラッシュコマンドと説明を一覧表示"""
        # bot.tree からスラッシュコマンドを列挙
        commands = {}
        for cmd in bot.tree.walk_commands():
            # 同名コマンドは上書き（最後の定義を優先）
            commands[cmd.name] = cmd.description or "(説明なし)"

        # 名前順にソート
        items = sorted(commands.items(), key=lambda x: x[0])

        embed = discord.Embed(
            title="利用可能なスラッシュコマンド一覧",
            description="/help 以外にも以下のコマンドが利用可能だ。",
            color=discord.Color.blurple(),
        )

        for name, desc in items:
            embed.add_field(name=f"/{name}", value=desc or "(説明なし)", inline=False)

        await interaction.response.send_message(embed=embed, ephemeral=True)
