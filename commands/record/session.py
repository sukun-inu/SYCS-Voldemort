"""録音そのものの操作（/record start, stop, status）。

register_recording_commands() 分割前の commands/recording_commands.py から
そのまま切り出した（経緯は commands/record/__init__.py を参照）。
"""

from typing import Optional, cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import EMBED_FIELD_BUDGET, cap_list_for_message, send_ephemeral
from services import recording_service as recording


def _duration(seconds: int) -> str:
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}時間{minutes}分{secs}秒" if hours else f"{minutes}分{secs}秒"


def register(bot: Bot, group: app_commands.Group) -> None:
    @group.command(name="start", description="【管理者】VCの録音を開始します（参加者に通知されます）")
    @app_commands.describe(channel="録音するVC（未指定なら自分が今いるVC）")
    async def record_start(
        interaction: discord.Interaction,
        channel: discord.VoiceChannel | None = None,
    ):
        if not await _ensure_admin(interaction):
            return

        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild = cast(discord.Guild, interaction.guild)

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
                bot,
                guild,
                target,
                started_by=interaction.user,
                # ForumChannel/CategoryChannel は Messageable ではないが、スラッシュ
                # コマンドの発生元チャンネルとしては実質的に来ない。
                announce_to=cast(Optional[discord.abc.Messageable], interaction.channel),
            )
        except recording.RecordingError as e:
            await interaction.followup.send(str(e), ephemeral=True)
            return

        stops = (
            "VC から全員が退出したときに止まる。"
            if session.is_unlimited
            else f"{session.max_seconds // 60} 分で自動的に止まる。"
        )
        await interaction.followup.send(
            f"🔴 **{target.name}** の録音を始めた。{stops}" "止めるときは `/record stop` を使え。",
            ephemeral=True,
        )

    @group.command(name="stop", description="【管理者】録音を停止して、ダウンロードリンクを出します")
    async def record_stop(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild_id = cast(int, interaction.guild_id)
        if not recording.is_recording(guild_id):
            await send_ephemeral(interaction, "このサーバーでは録音しておらぬ。")
            return

        await interaction.response.defer(thinking=True)
        try:
            result = await recording.stop_recording(bot, guild_id)
        except recording.RecordingError as e:
            await interaction.followup.send(str(e))
            return

        embed = recording.build_result_embed(guild_id, result)
        await interaction.followup.send(embed=embed)

    @group.command(name="status", description="録音の状況を表示します")
    async def record_status(interaction: discord.Interaction):
        # 誰が録音されていて、どれだけ喋ったかを出す。個人に紐づく情報なので、
        # ドキュメントどおり管理者に限る（自分が対象かどうかは開始時の通知と
        # /record exclude で分かる）。
        if not await _ensure_admin(interaction):
            return
        # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
        guild_id = cast(int, interaction.guild_id)
        session = recording.get_session(guild_id)
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
            speaker_lines = [f"・{s['name']}（発話 {_duration(s['voiced_seconds'])}）" for s in status["speakers"]]
            # 大人数のVCでは全員分を出すとembedのfield上限を超えうる。表示名は
            # 最大32文字あるため件数だけでは守れない。件数だけ隠れて減って
            # 見えないよう、省いた分は明示する。
            embed.add_field(
                name="録音中の参加者",
                value=cap_list_for_message(
                    speaker_lines,
                    budget=EMBED_FIELD_BUDGET,
                    limit=20,
                    omitted_unit="人",
                ),
                inline=False,
            )
        else:
            embed.add_field(name="録音中の参加者", value="まだ誰も喋っておらぬ。", inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)
