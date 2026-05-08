import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import bind_permission_error_handler
from config import DJAUDIO_BASE_URL
from services.settings_store import get_djaudio_runtime_settings, set_djaudio_watch_channel


def register_djaudio_commands(bot: Bot) -> None:

    @bot.tree.command(
        name="djaudio_channel_set",
        description="【管理者】DJAudio の監視チャンネルを設定します",
    )
    @app_commands.describe(channel="監視するチャンネル（未指定で解除）")
    @app_commands.checks.has_permissions(manage_channels=True)
    async def djaudio_channel_set(
        interaction: discord.Interaction,
        channel: discord.TextChannel | None = None,
    ):
        if not await _ensure_admin(interaction):
            return
        runtime = get_djaudio_runtime_settings(interaction.guild_id)

        if channel is None:
            set_djaudio_watch_channel(interaction.guild_id, None)
            embed = discord.Embed(
                title="✅ DJAudio 監視チャンネル解除",
                description="URL の自動 MP3 変換を無効にしました。",
                color=discord.Color.red(),
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        set_djaudio_watch_channel(interaction.guild_id, channel.id)
        embed = discord.Embed(title="✅ DJAudio チャンネル設定完了", color=discord.Color.green())
        embed.description = (
            f"{channel.mention} を監視チャンネルに設定しました。\n"
            "このチャンネルに URL を投稿すると自動で MP3 リンクを返信します。\n\n"
            f"🔗 配信 URL ベース: `{DJAUDIO_BASE_URL}`\n"
            f"⏱️ キャッシュ有効期間: `{runtime.cache_ttl // 60}分`\n"
            f"⏳ クールダウン: `{runtime.cooldown}秒` / 最大URL: `{runtime.max_urls}`"
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    bind_permission_error_handler(
        djaudio_channel_set,
        missing_permissions_message="❌ チャンネル管理権限が必要です。",
    )

    @bot.tree.command(
        name="djaudio_status",
        description="【管理者】DJAudio の現在設定を表示します",
    )
    @app_commands.checks.has_permissions(manage_channels=True)
    async def djaudio_status(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        runtime = get_djaudio_runtime_settings(interaction.guild_id)

        watch_ch_id = runtime.watch_channel_id
        if watch_ch_id:
            ch = interaction.guild.get_channel(watch_ch_id)
            ch_text = ch.mention if ch else f"ID: {watch_ch_id}（チャンネル未検出）"
        else:
            ch_text = "未設定"

        embed = discord.Embed(title="🎵 DJAudio 設定", color=discord.Color.blurple())
        embed.add_field(name="監視チャンネル", value=ch_text, inline=False)
        embed.add_field(name="配信 URL ベース", value=f"`{DJAUDIO_BASE_URL}`", inline=False)
        embed.add_field(name="キャッシュ有効期間", value=f"{runtime.cache_ttl // 60}分", inline=True)
        embed.add_field(name="クールダウン", value=f"{runtime.cooldown}秒", inline=True)
        embed.add_field(name="最大URL / メッセージ", value=str(runtime.max_urls), inline=True)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    bind_permission_error_handler(
        djaudio_status,
        missing_permissions_message="❌ チャンネル管理権限が必要です。",
    )
