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
from commands.interaction_utils import send_ephemeral
from services import recording_service as recording
from services.settings_store import get_recording_settings, set_recording_excluded_users


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

        await interaction.followup.send(
            f"🔴 **{target.name}** の録音を始めた。"
            f"{session.max_seconds // 60} 分で自動的に止まる。"
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
        embed.add_field(
            name="自動停止まで",
            value=_duration(max(0, status["max_seconds"] - status["elapsed_seconds"])),
            inline=True,
        )
        if status["speakers"]:
            embed.add_field(
                name="録音中の参加者",
                value="\n".join(
                    f"・{s['name']}（発話 {_duration(s['voiced_seconds'])}）"
                    for s in status["speakers"][:20]
                ),
                inline=False,
            )
        else:
            embed.add_field(name="録音中の参加者", value="まだ誰も喋っておらぬ。", inline=False)
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
