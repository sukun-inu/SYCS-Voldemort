from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import admin_site_view, bind_permission_error_handler
from config import DJAUDIO_BASE_URL
from services.settings_store import (
    DJAudioRuntimeSettings,
    awrite,
    get_djaudio_runtime_settings,
    set_djaudio_output_channel,
    set_djaudio_watch_channel,
)


def _base_url_is_local() -> bool:
    """厳密な到達性判定はしない。開発時によくある2値だけを見た簡易チェック。"""
    return "localhost" in DJAUDIO_BASE_URL or "127.0.0.1" in DJAUDIO_BASE_URL


async def _apply_watch_channel(interaction: discord.Interaction, channel: discord.TextChannel | None) -> None:
    """監視チャンネルを設定・解除する。

    `has_permissions(manage_channels=True)` だけでは admin 限定にならない。
    Manage Channels 権限だけ持つ非管理者も decorator は通してしまうため、
    説明文の「【管理者】」を実際に守るには `_ensure_admin` の追加チェックが
    要る。decorator 側は主にDiscordの権限エラー表示のためだけに残している。
    """
    if not await _ensure_admin(interaction):
        return
    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild_id = cast(int, interaction.guild_id)
    runtime = get_djaudio_runtime_settings(guild_id)

    if channel is None:
        await awrite(set_djaudio_watch_channel, guild_id, None)
        embed = discord.Embed(
            title="✅ DJAudio 監視チャンネル解除",
            description="URL の自動 MP3 変換を無効にした。",
            color=discord.Color.red(),
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    await awrite(set_djaudio_watch_channel, guild_id, channel.id)
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


async def _apply_output_channel(interaction: discord.Interaction, channel: discord.TextChannel | None) -> None:
    """結果の送信先を設定・解除する。

    `_ensure_admin` が要る理由は _apply_watch_channel と同じ
    （manage_channels decorator だけでは非管理者を弾けない）。
    """
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


def _channel_text(guild: discord.Guild, channel_id: int | None) -> str:
    """設定後にチャンネルが削除されていても落ちないよう、IDのみで表示する。"""
    if not channel_id:
        return "未設定"
    channel = guild.get_channel(channel_id)
    return channel.mention if channel else f"ID: {channel_id}（チャンネル未検出）"


def _status_embed(runtime: DJAudioRuntimeSettings, guild: discord.Guild) -> discord.Embed:
    """現在の設定を1つの埋め込みにまとめる。"""
    embed = discord.Embed(title="🎵 DJAudio 設定", color=discord.Color.blurple())
    embed.add_field(name="監視チャンネル", value=_channel_text(guild, runtime.watch_channel_id), inline=True)
    embed.add_field(
        name="出力チャンネル",
        value=_channel_text(guild, runtime.output_channel_id)
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
    return embed


async def _show_status(interaction: discord.Interaction) -> None:
    """設定を変えない読み取り専用なので、他の2つと違い admin ガードは無い。"""
    if interaction.guild is None:
        await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
        return
    # guild_id は guild とは別属性で、上のチェックでは絞り込みが効かない。
    # guild が非 None である以上、guild_id も必ず非 None。
    guild_id = cast(int, interaction.guild_id)
    runtime = get_djaudio_runtime_settings(guild_id)
    embed = _status_embed(runtime, interaction.guild)
    await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())


def register_djaudio_commands(bot: Bot) -> None:
    """DJAudio（URL自動MP3変換）の /djaudio channel/output/status を登録する。

    ここに残すのは「何を、どの名前で、どの権限で登録するか」だけで、中身は
    module 直下の関数にある。登録の姿（グループ名・3つの並び・ツリーへの
    追加）は tests の DjaudioRegistrationShapeTests が固定している
    —— `bot.tree.add_command` が抜けると**コマンドは1つも Discord に出ない
    のに、例外も出ず単体テストも通る**ため。
    """
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
        """監視チャンネルの設定（中身は _apply_watch_channel）。"""
        await _apply_watch_channel(interaction, channel)

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
        """出力チャンネルの設定（中身は _apply_output_channel）。"""
        await _apply_output_channel(interaction, channel)

    bind_permission_error_handler(
        djaudio_output_set,
        missing_permissions_message="❌ チャンネル管理の権限がなければ使えぬ。",
    )

    @group.command(
        name="status",
        description="DJAudio の現在設定を表示します",
    )
    async def djaudio_status(interaction: discord.Interaction):
        """現在設定の表示（中身は _show_status）。"""
        await _show_status(interaction)

    bot.tree.add_command(group)
