"""録音の設定（/record auto, config）。

register_recording_commands() 分割前の commands/recording_commands.py から
そのまま切り出した（経緯は commands/record/__init__.py を参照）。
"""

import discord
from discord import app_commands

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import EMBED_FIELD_BUDGET, cap_list_for_message, send_ephemeral
from services import recording_service as recording
from services.settings_store import awrite, get_recording_settings, set_recording_settings


def register(group: app_commands.Group) -> None:
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
        if not await _ensure_admin(interaction):
            return

        patch: dict = {"auto_start": enabled}
        if channel is not None:
            patch["vc_channel_id"] = channel.id
        await awrite(set_recording_settings, interaction.guild_id, patch)

        settings = get_recording_settings(interaction.guild_id)
        if not enabled:
            await send_ephemeral(interaction, "自動録音を切った。手動の `/record start` は使える。")
            return

        target_id = recording.auto_start_channel_id(interaction.guild_id)
        if not settings.get("enabled", True):
            where = "ただし録音そのものが無効なので、まず有効にせよ。"
        elif target_id:
            where = f"対象は <#{target_id}> だ。人が入った時点で録り始める。"
        else:
            where = "ただし対象のVCが定まっておらぬ。" "channel を指定するか、読み上げの対象VCを設定せよ。"
        await send_ephemeral(interaction, f"自動録音を入れた。{where}")

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
        if not await _ensure_admin(interaction):
            return

        patch: dict = {}
        if enabled is not None:
            patch["enabled"] = enabled
        if limit_minutes is not None:
            if not (0 <= limit_minutes <= recording.MAX_MINUTES_LIMIT):
                await send_ephemeral(
                    interaction,
                    f"自動停止までの分数は 0〜{recording.MAX_MINUTES_LIMIT} で指定せよ（0 で無制限）。",
                )
                return
            patch["max_minutes"] = limit_minutes
        if retention_days is not None:
            if not (recording.RETENTION_DAYS_MIN <= retention_days <= recording.RETENTION_DAYS_MAX):
                await send_ephemeral(
                    interaction,
                    f"保存日数は {recording.RETENTION_DAYS_MIN}〜{recording.RETENTION_DAYS_MAX} で指定せよ。",
                )
                return
            patch["retention_days"] = retention_days
        if announce_channel is not None:
            patch["announce_channel_id"] = announce_channel.id

        if patch:
            await awrite(set_recording_settings, interaction.guild_id, patch)

        settings = get_recording_settings(interaction.guild_id)
        target_id = recording.preferred_vc_channel_id(interaction.guild_id)

        embed = discord.Embed(
            title="🎙️ 録音の設定" + ("（更新した）" if patch else ""),
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
        await interaction.response.send_message(embed=embed, ephemeral=True)
