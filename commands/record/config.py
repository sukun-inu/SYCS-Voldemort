"""録音の設定（/record auto, config）。

register_recording_commands() 分割前の commands/recording_commands.py から
そのまま切り出した（経緯は commands/record/__init__.py を参照）。

register() は登録だけを担い、コマンドの中身はモジュール直下の関数に置いて
ある。入れ子のままだと、設定の組み立てと Embed の組み立てをそれぞれ単体で
呼べず、`register()` を通してしか触れない（CONTRIBUTING 5.）。
"""

from typing import cast

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import EMBED_FIELD_BUDGET, cap_list_for_message, send_ephemeral
from services import recording_service as recording
from services.settings_store import awrite, get_recording_settings, set_recording_settings


def _auto_start_note(guild_id: int, settings: dict) -> str:
    """自動録音を入れたときに、実際どう動くのかを一言で返す。

    オンにしても対象VCが定まっていなければ何も起きない。そのまま静かに
    空振りさせず「channel を指定するか読み上げの対象VCを設定せよ」と伝える。
    黙って有効化だけ返すと、動いていないのに設定した気になってしまう。
    """
    if not settings.get("enabled", True):
        return "ただし録音そのものが無効なので、まず有効にせよ。"
    target_id = recording.auto_start_channel_id(guild_id)
    if target_id:
        return f"対象は <#{target_id}> だ。人が入った時点で録り始める。"
    return "ただし対象のVCが定まっておらぬ。" "channel を指定するか、読み上げの対象VCを設定せよ。"


async def _apply_auto(
    interaction: discord.Interaction,
    enabled: bool,
    channel: discord.VoiceChannel | None,
) -> None:
    """/record auto の中身。自動録音の可否と対象VCを書き込んで結果を返す。"""
    if not await _ensure_admin(interaction):
        return

    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild_id = cast(int, interaction.guild_id)
    patch: dict = {"auto_start": enabled}
    if channel is not None:
        patch["vc_channel_id"] = channel.id
    await awrite(set_recording_settings, guild_id, patch)

    settings = get_recording_settings(guild_id)
    if not enabled:
        await send_ephemeral(interaction, "自動録音を切った。手動の `/record start` は使える。")
        return

    await send_ephemeral(interaction, f"自動録音を入れた。{_auto_start_note(guild_id, settings)}")


def _config_patch(
    enabled: bool | None,
    limit_minutes: int | None,
    retention_days: int | None,
    announce_channel: discord.TextChannel | None,
) -> tuple[dict, str | None]:
    """渡された引数から書き込む差分を組み立てる。範囲外なら (空, 理由) を返す。

    引数を1つも渡さなかった場合、差分は空のままになる。設定を変えていない
    のに毎回書き込むと、ただの照会でも永続化が走ってしまう（設定ファイル/DB
    への不要な書き込みと、更新時刻等の副作用）ため、呼び出し側はここが空
    なら書かない。
    """
    patch: dict = {}
    if enabled is not None:
        patch["enabled"] = enabled
    if limit_minutes is not None:
        if not (0 <= limit_minutes <= recording.MAX_MINUTES_LIMIT):
            return {}, f"自動停止までの分数は 0〜{recording.MAX_MINUTES_LIMIT} で指定せよ（0 で無制限）。"
        patch["max_minutes"] = limit_minutes
    if retention_days is not None:
        if not (recording.RETENTION_DAYS_MIN <= retention_days <= recording.RETENTION_DAYS_MAX):
            return {}, f"保存日数は {recording.RETENTION_DAYS_MIN}〜{recording.RETENTION_DAYS_MAX} で指定せよ。"
        patch["retention_days"] = retention_days
    if announce_channel is not None:
        patch["announce_channel_id"] = announce_channel.id
    return patch, None


def _config_embed(settings: dict, target_id: int | None, updated: bool) -> discord.Embed:
    """いまの録音設定を1枚の Embed にする。

    フッターの警告（無効なのに自動録音オン）は、設定の組み合わせ自体は
    許しつつ、動かない状態であることに気づかせるためのもの。
    """
    embed = discord.Embed(
        title="🎙️ 録音の設定" + ("（更新した）" if updated else ""),
        color=discord.Color.blurple(),
    )
    embed.add_field(name="録音機能", value="✅ 有効" if settings["enabled"] else "❌ 無効", inline=True)
    embed.add_field(name="自動録音", value="✅ オン" if settings["auto_start"] else "❌ オフ", inline=True)
    embed.add_field(
        name="対象VC",
        value=f"<#{target_id}>" if target_id else "未設定",
        inline=True,
    )
    embed.add_field(
        name="自動停止",
        value=(
            "全員が退出したとき"
            if settings["max_minutes"] == recording.UNLIMITED
            else f"{settings['max_minutes']} 分後"
        ),
        inline=True,
    )
    embed.add_field(name="保存期間", value=f"{settings['retention_days']} 日", inline=True)
    announce_id = settings.get("announce_channel_id")
    embed.add_field(
        name="通知先",
        value=f"<#{announce_id}>" if announce_id else "VCのチャット欄",
        inline=True,
    )
    excluded = settings.get("excluded_user_ids") or []
    excluded_text = (
        cap_list_for_message(
            [f"<@{u}>" for u in excluded],
            budget=EMBED_FIELD_BUDGET,
            limit=20,
            omitted_unit="人",
            joiner="、",
        )
        if excluded
        else "なし"
    )
    embed.add_field(name="録音しない人", value=excluded_text, inline=False)
    if not settings["enabled"] and settings["auto_start"]:
        embed.set_footer(text="録音機能が無効なので、自動録音はオンでも動かぬ。")
    return embed


async def _apply_config(
    interaction: discord.Interaction,
    enabled: bool | None,
    limit_minutes: int | None,
    retention_days: int | None,
    announce_channel: discord.TextChannel | None,
) -> None:
    """/record config の中身。変更があれば書き込み、いまの設定を返す。"""
    if not await _ensure_admin(interaction):
        return

    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild_id = cast(int, interaction.guild_id)
    patch, rejected = _config_patch(enabled, limit_minutes, retention_days, announce_channel)
    if rejected:
        await send_ephemeral(interaction, rejected)
        return

    if patch:
        await awrite(set_recording_settings, guild_id, patch)

    settings = get_recording_settings(guild_id)
    embed = _config_embed(settings, recording.preferred_vc_channel_id(guild_id), bool(patch))
    await interaction.response.send_message(embed=embed, ephemeral=True)


def register(group: app_commands.Group) -> None:
    """/record auto と /record config（録音の設定まわり）を登録する。"""

    @group.command(name="auto", description="【管理者】自動録音のオン／オフを切り替えます")
    @app_commands.describe(
        enabled="オンにすると、対象VCに人が入った時点で録音を始めます",
        channel="自動録音するVC（未指定なら読み上げと同じVC）",
    )
    async def record_auto(
        interaction: discord.Interaction,
        enabled: bool,
        channel: discord.VoiceChannel | None = None,
    ):
        """自動録音のオン／オフ（本体は _apply_auto）。"""
        await _apply_auto(interaction, enabled, channel)

    @group.command(
        name="config",
        description="【管理者】録音の設定を表示・変更します（引数なしで現在の設定を表示）",
    )
    @app_commands.describe(
        enabled="録音機能そのもののオン／オフ",
        limit_minutes=f"自動停止までの分数（0 で無制限・最大 {recording.MAX_MINUTES_LIMIT}）",
        retention_days=f"ダウンロードリンクの保存日数"
        f"（{recording.RETENTION_DAYS_MIN}〜{recording.RETENTION_DAYS_MAX}）",
        announce_channel="開始・完了の通知先（未指定ならVCのチャット欄）",
    )
    async def record_config(
        interaction: discord.Interaction,
        enabled: bool | None = None,
        limit_minutes: int | None = None,
        retention_days: int | None = None,
        announce_channel: discord.TextChannel | None = None,
    ):
        """録音設定の表示・変更（本体は _apply_config）。"""
        await _apply_config(interaction, enabled, limit_minutes, retention_days, announce_channel)
