import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import admin_site_view, bind_permission_error_handler
from config import DJAUDIO_BASE_URL
from services.settings_store import (
    awrite,
    get_djaudio_runtime_settings,
    set_djaudio_output_channel,
    set_djaudio_watch_channel,
)


def _base_url_is_local() -> bool:
    return "localhost" in DJAUDIO_BASE_URL or "127.0.0.1" in DJAUDIO_BASE_URL


def register_djaudio_commands(bot: Bot) -> None:
    group = app_commands.Group(
        name="djaudio",
        description="DJAudio（URL の自動MP3変換）の設定",
        guild_only=True,
    )

    @group.command(
        name="channel",
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
            await awrite(set_djaudio_watch_channel, interaction.guild_id, None)
            embed = discord.Embed(
                title="✅ DJAudio 監視チャンネル解除",
                description="URL の自動 MP3 変換を無効にした。",
                color=discord.Color.red(),
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        await awrite(set_djaudio_watch_channel, interaction.guild_id, channel.id)
        embed = discord.Embed(title="✅ DJAudio チャンネル設定完了", color=discord.Color.green())
        embed.description = (
            f"{channel.mention} を監視チャンネルと定めた。\n"
            "このチャンネルに URL を投稿すれば、自動で MP3 リンクを返してやろう。\n\n"
            f"🔗 配信 URL ベース: `{DJAUDIO_BASE_URL}`\n"
            f"⏱️ キャッシュ有効期間: `{runtime.cache_ttl // 60}分`\n"
            f"⏳ クールダウン: `{runtime.cooldown}秒` / 最大URL: `{runtime.max_urls}`"
        )
        if _base_url_is_local():
            embed.add_field(
                name="⚠️ 注意",
                value="配信 URL ベースが `localhost` のままだ。このままではサーバー外の者はリンクを開けぬ。"
                "管理者は `DJAUDIO_BASE_URL` 環境変数を外部から到達可能な URL に設定せよ。",
                inline=False,
            )
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    bind_permission_error_handler(
        djaudio_channel_set,
        missing_permissions_message="❌ チャンネル管理の権限がなければ使えぬ。",
    )

    @group.command(
        name="output",
        description="【管理者】DJAudio の結果送信チャンネルを設定します（未指定で監視チャンネルに返信）",
    )
    @app_commands.describe(channel="結果を送信するチャンネル（未指定で解除→監視チャンネルに返信）")
    @app_commands.checks.has_permissions(manage_channels=True)
    async def djaudio_output_set(
        interaction: discord.Interaction,
        channel: discord.TextChannel | None = None,
    ):
        if not await _ensure_admin(interaction):
            return

        if channel is None:
            await awrite(set_djaudio_output_channel, interaction.guild_id, None)
            embed = discord.Embed(
                title="✅ DJAudio 出力チャンネル解除",
                description="結果は監視チャンネルへの返信で送られるようになった。",
                color=discord.Color.red(),
            )
        else:
            await awrite(set_djaudio_output_channel, interaction.guild_id, channel.id)
            embed = discord.Embed(
                title="✅ DJAudio 出力チャンネル設定完了",
                description=f"{channel.mention} に MP3 リンクを送信するよう定めた。",
                color=discord.Color.green(),
            )
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    bind_permission_error_handler(
        djaudio_output_set,
        missing_permissions_message="❌ チャンネル管理の権限がなければ使えぬ。",
    )

    @group.command(
        name="status",
        description="DJAudio の現在設定を表示します",
    )
    async def djaudio_status(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        runtime = get_djaudio_runtime_settings(interaction.guild_id)

        def _ch_text(ch_id: int | None) -> str:
            if not ch_id:
                return "未設定"
            ch = interaction.guild.get_channel(ch_id)
            return ch.mention if ch else f"ID: {ch_id}（チャンネル未検出）"

        embed = discord.Embed(title="🎵 DJAudio 設定", color=discord.Color.blurple())
        embed.add_field(name="監視チャンネル", value=_ch_text(runtime.watch_channel_id), inline=True)
        embed.add_field(
            name="出力チャンネル",
            value=_ch_text(runtime.output_channel_id)
            + ("" if runtime.output_channel_id else "（監視チャンネルに返信）"),
            inline=True,
        )
        embed.add_field(name="配信 URL ベース", value=f"`{DJAUDIO_BASE_URL}`", inline=False)
        embed.add_field(name="キャッシュ有効期間", value=f"{runtime.cache_ttl // 60}分", inline=True)
        embed.add_field(name="クールダウン", value=f"{runtime.cooldown}秒", inline=True)
        embed.add_field(name="最大URL / メッセージ", value=str(runtime.max_urls), inline=True)
        if _base_url_is_local():
            embed.add_field(
                name="⚠️ 配信 URL が localhost のまま",
                value="サーバー外からリンクを開けない状態だ。`DJAUDIO_BASE_URL` を外部到達可能な URL に設定せよ。",
                inline=False,
            )
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    bot.tree.add_command(group)
