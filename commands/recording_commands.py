"""VC録音のスラッシュコマンド（管理者専用）。

/record start  … 今いる VC（または指定した VC）の録音を開始
/record stop   … 停止して ZIP のリンクを返す
/record status … 録音中かどうか、経過時間、参加者
/record exclude … 自分を録音対象から外す／戻す（本人が使う）
"""

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import EMBED_FIELD_BUDGET, cap_list_for_message, send_ephemeral
from services import recording_service as recording
from services.settings_store import (
    get_recording_settings,
    set_recording_excluded_users,
    set_recording_settings,
)


def _duration(seconds: int) -> str:
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}時間{minutes}分{secs}秒" if hours else f"{minutes}分{secs}秒"


def register_recording_commands(bot: Bot) -> None:

    group = app_commands.Group(
        name="record",
        description="【管理者】ボイスチャンネルを録音します",
        guild_only=True,
    )

    @group.command(name="start", description="【管理者】VCの録音を開始します（参加者に通知されます）")
    @app_commands.describe(channel="録音するVC（未指定なら自分が今いるVC）")
    async def record_start(
        interaction: discord.Interaction,
        channel: discord.VoiceChannel | None = None,
    ):
        if not await _ensure_admin(interaction):
            return

        target = channel
        if target is None:
            voice_state = getattr(interaction.user, "voice", None)
            target = voice_state.channel if voice_state else None
        if not isinstance(target, discord.VoiceChannel):
            await send_ephemeral(
                interaction,
                "録音するVCが分からぬ。VCに入ってから実行するか、channel を指定せよ。",
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            session = await recording.start_recording(
                bot, interaction.guild, target,
                started_by=interaction.user,
                announce_to=interaction.channel,
            )
        except recording.RecordingError as e:
            await interaction.followup.send(str(e), ephemeral=True)
            return

        stops = ("VC から全員が退出したときに止まる。"
                 if session.is_unlimited
                 else f"{session.max_seconds // 60} 分で自動的に止まる。")
        await interaction.followup.send(
            f"🔴 **{target.name}** の録音を始めた。{stops}"
            "止めるときは `/record stop` を使え。",
            ephemeral=True,
        )

    @group.command(name="stop", description="【管理者】録音を停止して、ダウンロードリンクを出します")
    async def record_stop(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        if not recording.is_recording(interaction.guild_id):
            await send_ephemeral(interaction, "このサーバーでは録音しておらぬ。")
            return

        await interaction.response.defer(thinking=True)
        try:
            result = await recording.stop_recording(bot, interaction.guild_id)
        except recording.RecordingError as e:
            await interaction.followup.send(str(e))
            return

        embed = recording.build_result_embed(interaction.guild_id, result)
        await interaction.followup.send(embed=embed)

    @group.command(name="status", description="録音の状況を表示します")
    async def record_status(interaction: discord.Interaction):
        # 誰が録音されていて、どれだけ喋ったかを出す。個人に紐づく情報なので、
        # ドキュメントどおり管理者に限る（自分が対象かどうかは開始時の通知と
        # /record exclude で分かる）。
        if not await _ensure_admin(interaction):
            return
        session = recording.get_session(interaction.guild_id)
        if session is None:
            await send_ephemeral(interaction, "今は録音しておらぬ。")
            return

        status = session.status()
        embed = discord.Embed(
            title="🔴 録音中",
            description=f"**{status['channel_name']}** / 経過 {_duration(status['elapsed_seconds'])}",
            color=discord.Color.red(),
        )
        embed.add_field(name="開始した人", value=status["started_by"], inline=True)
        if status.get("unlimited"):
            embed.add_field(name="停止条件", value="全員が退出したとき", inline=True)
        else:
            embed.add_field(
                name="自動停止まで",
                value=_duration(max(0, status["max_seconds"] - status["elapsed_seconds"])),
                inline=True,
            )
        if status["speakers"]:
            speaker_lines = [
                f"・{s['name']}（発話 {_duration(s['voiced_seconds'])}）"
                for s in status["speakers"]
            ]
            # 大人数のVCでは全員分を出すとembedのfield上限を超えうる。表示名は
            # 最大32文字あるため件数だけでは守れない。件数だけ隠れて減って
            # 見えないよう、省いた分は明示する。
            embed.add_field(
                name="録音中の参加者",
                value=cap_list_for_message(
                    speaker_lines, budget=EMBED_FIELD_BUDGET, limit=20, omitted_unit="人",
                ),
                inline=False,
            )
        else:
            embed.add_field(name="録音中の参加者", value="まだ誰も喋っておらぬ。", inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

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
        set_recording_settings(interaction.guild_id, patch)

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
            where = (
                "ただし対象のVCが定まっておらぬ。"
                "channel を指定するか、読み上げの対象VCを設定せよ。"
            )
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
            set_recording_settings(interaction.guild_id, patch)

        settings = get_recording_settings(interaction.guild_id)
        target_id = recording.preferred_vc_channel_id(interaction.guild_id)

        embed = discord.Embed(
            title="🎙️ 録音の設定" + ("（更新した）" if patch else ""),
            color=discord.Color.blurple(),
        )
        embed.add_field(name="録音機能",
                        value="✅ 有効" if settings["enabled"] else "❌ 無効", inline=True)
        embed.add_field(name="自動録音",
                        value="✅ オン" if settings["auto_start"] else "❌ オフ", inline=True)
        embed.add_field(
            name="対象VC",
            value=f"<#{target_id}>" if target_id else "未設定",
            inline=True,
        )
        embed.add_field(
            name="自動停止",
            value=("全員が退出したとき" if settings["max_minutes"] == recording.UNLIMITED
                   else f"{settings['max_minutes']} 分後"),
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
                budget=EMBED_FIELD_BUDGET, limit=20, omitted_unit="人", joiner="、",
            )
            if excluded else "なし"
        )
        embed.add_field(name="録音しない人", value=excluded_text, inline=False)
        if not settings["enabled"] and settings["auto_start"]:
            embed.set_footer(text="録音機能が無効なので、自動録音はオンでも動かぬ。")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @group.command(name="exclude", description="自分を録音の対象から外す／戻します")
    @app_commands.describe(exclude="True で除外、False で解除")
    async def record_exclude(interaction: discord.Interaction, exclude: bool = True):
        if interaction.guild is None:
            await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
            return

        settings = get_recording_settings(interaction.guild_id)
        excluded = set(settings.get("excluded_user_ids", []))
        user_id = interaction.user.id

        if exclude:
            excluded.add(user_id)
            message = (
                "以後、このサーバーの録音では貴様の声は記録されぬ。"
                "\n※ 進行中の録音にも即時反映される。"
            )
        else:
            excluded.discard(user_id)
            message = "除外を解除した。以後の録音では貴様の声も記録される。"

        set_recording_excluded_users(interaction.guild_id, sorted(excluded))

        # 進行中のセッションにも反映する（設定だけ変えて今の録音に効かないと紛らわしい）
        session = recording.get_session(interaction.guild_id)
        if session is not None:
            session.excluded_user_ids = set(excluded)

        await send_ephemeral(interaction, message)

    bot.tree.add_command(group)
