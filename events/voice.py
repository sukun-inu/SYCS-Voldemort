"""on_voice_state_update とその内側のヘルパー。

setup_events(bot) の巨大クロージャの中でも単独最大（約270行）だった
on_voice_state_update を、判定・ログ・永続化・通知・TTS/録音連携ごとの
ヘルパーへ割った。ハンドラ本体はそれらを順番に呼ぶだけにしてある。
ロジックは元のまま移しただけで、判定条件やログ文言は変えていない。
"""

from __future__ import annotations

import logging
import time
from datetime import datetime

import discord
from discord.ext.commands import Bot
from services.logging_service import log_action
from services.security_service import handle_security_for_voice_join
from services.settings_store import get_vc_notify_channel_id, get_vc_notify_filter_role_id, get_vc_notify_role_id
from services.user_state_service import record_user_state_event
from config import JST as _JST

from events._util import _safe

logger = logging.getLogger(__name__)

_WDAYS = ["月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日", "日曜日"]

# VC入室時刻を覚えておく上限時間。退出イベントを取り逃した分（Bot 停止中に
# 退出された等）が永久に残らないよう、これを過ぎた記録は捨てる。
_VC_JOIN_TTL_SECONDS = 24 * 3600


def _tts_vc_became_empty(guild_id: int, channel) -> bool:
    """監視中の VC から人間が居なくなったか。

    切断判定は以前 on_voice_state_update の冒頭（退出のみ）と末尾（退出と移動）に
    少しずつ違う条件で書かれていて、どちらが効いているのか読まないと分からなかった。
    条件はここ1つに持たせ、呼び出し側は文脈だけを持つ。
    """
    if channel is None:
        return False
    from services.tts_service import get_effective_vc_watch as _get_vc_watch
    from services.tts_store import get_tts_settings as _get_tts_settings
    watched_id, _ = _get_vc_watch(guild_id, _get_tts_settings(guild_id))
    if not watched_id or int(watched_id) != channel.id:
        return False
    return not any(m for m in channel.members if not m.bot)


def _compute_vc_transition(
    key: tuple[int, int],
    now_ts: float,
    before_ch,
    after_ch,
    vc_join_times: dict[tuple[int, int], float],
) -> tuple[bool, bool, bool, int | None, str]:
    """参加/退出/移動の判定と、退出時の滞在時間を1箇所にまとめる。

    vc_join_times は on_voice_state_update の呼び出しをまたいで register()
    側が持ち続ける辞書で、ここで直接書き換える（呼び出し側で再代入はしない
    ので nonlocal は要らない）。
    """
    is_join = before_ch is None and after_ch is not None
    is_leave = before_ch is not None and after_ch is None
    is_move = before_ch is not None and after_ch is not None and before_ch.id != after_ch.id

    if is_join:
        vc_join_times[key] = now_ts
        # 退出イベントを取り逃した分（Bot 停止中に退出された等）は pop されず
        # 永久に残る。入室のたびに期限切れを間引いて、じわじわ増えるのを止める。
        if len(vc_join_times) > 256:
            cutoff = now_ts - _VC_JOIN_TTL_SECONDS
            for stale in [k for k, ts in vc_join_times.items() if ts < cutoff]:
                vc_join_times.pop(stale, None)

    duration_str = ""
    duration_seconds: int | None = None
    if is_leave:
        join_ts = vc_join_times.pop(key, None)
        if join_ts is not None:
            duration_seconds = int(now_ts - join_ts)
            h, r = divmod(duration_seconds, 3600)
            m, s = divmod(r, 60)
            duration_str = f"{h:02d}:{m:02d}:{s:02d}"

    return is_join, is_leave, is_move, duration_seconds, duration_str


async def _tts_vc_announce(bot: Bot, member: discord.Member, before, after) -> None:
    """TTS の VC参加・退出アナウンス。

    bot含む全メンバーが対象のため、呼び出し側は bot自身/guild無しの
    early return より前にこれを呼ぶ（early return 後に置くと Bot 自身の
    参加・退出でアナウンスが動かない）。
    """
    try:
        _bch = before.channel
        _ach = after.channel
        _ev = (
            "join"  if _bch is None and _ach is not None else
            "leave" if _bch is not None and _ach is None else
            None
        )
        if _ev:
            from services.tts_service import enqueue_vc_event as _tts_vc_event, get_effective_vc_watch as _get_vc_watch, disconnect as _tts_disconnect
            from services.tts_store import get_tts_settings as _get_tts_settings
            _cfg = _get_tts_settings(member.guild.id)
            _vid, _ = _get_vc_watch(member.guild.id, _cfg)
            # 全員退出: 監視VCがBot以外0人になったらTTSを切断（再接続防止）。
            # 判定は _tts_vc_became_empty に集約している。
            if _ev == "leave" and _tts_vc_became_empty(member.guild.id, _bch):
                await _tts_disconnect(member.guild.id)
            elif not member.bot and _cfg.get("enabled") and _cfg.get("vc_notify") and _vid:
                _tch = _ach if _ev == "join" else _bch
                if _tch and _vid == _tch.id:
                    await _tts_vc_event(bot, member.guild, member, _ev)
    except Exception as e:
        logger.exception("[BOT_SETUP] TTS vc_notify error: %s", e)


async def _log_vc_transition(
    bot: Bot, member: discord.Member, is_join: bool, is_leave: bool, is_move: bool, before_ch, after_ch,
) -> None:
    """VC 参加 / 退出 / 移動 をログチャンネルへ。"""
    try:
        if is_join:
            await log_action(
                bot, member.guild.id, "INFO",
                f"{member.mention} が VC に参加しました。",
                user=member,
                fields={"チャンネル": after_ch.mention},
            )
        elif is_leave:
            await log_action(
                bot, member.guild.id, "INFO",
                f"{member.mention} が VC から退出しました。",
                user=member,
                fields={"チャンネル": before_ch.mention},
            )
        elif is_move:
            await log_action(
                bot, member.guild.id, "INFO",
                f"{member.mention} が VC を移動しました。",
                user=member,
                fields={
                    "移動前": before_ch.mention,
                    "移動後": after_ch.mention,
                },
            )
    except Exception as e:
        logger.exception("[BOT_SETUP] VC log_action error: %s", e)


async def _persist_vc_transition(
    member: discord.Member,
    is_join: bool,
    is_leave: bool,
    is_move: bool,
    before_ch,
    after_ch,
    duration_seconds: int | None,
    duration_str: str,
) -> None:
    """VC 参加 / 退出 / 移動 を永続化。"""
    try:
        if is_join:
            await record_user_state_event(
                guild_id=member.guild.id,
                user_id=member.id,
                event_type="voice_join",
                status_after="active",
                user=member,
                in_guild=True,
                is_banned=False,
                timed_out_until=member.timed_out_until,
                payload={
                    "channel_before_id": None,
                    "channel_before_name": None,
                    "channel_after_id": int(after_ch.id) if after_ch else None,
                    "channel_after_name": str(after_ch.name) if after_ch else None,
                    "duration_seconds": None,
                },
            )
        elif is_leave:
            await record_user_state_event(
                guild_id=member.guild.id,
                user_id=member.id,
                event_type="voice_leave",
                status_after="active",
                user=member,
                in_guild=True,
                is_banned=False,
                timed_out_until=member.timed_out_until,
                payload={
                    "channel_before_id": int(before_ch.id) if before_ch else None,
                    "channel_before_name": str(before_ch.name) if before_ch else None,
                    "channel_after_id": None,
                    "channel_after_name": None,
                    "duration_seconds": duration_seconds,
                    "duration_hms": duration_str or None,
                },
            )
        elif is_move:
            await record_user_state_event(
                guild_id=member.guild.id,
                user_id=member.id,
                event_type="voice_move",
                status_after="active",
                user=member,
                in_guild=True,
                is_banned=False,
                timed_out_until=member.timed_out_until,
                payload={
                    "channel_before_id": int(before_ch.id) if before_ch else None,
                    "channel_before_name": str(before_ch.name) if before_ch else None,
                    "channel_after_id": int(after_ch.id) if after_ch else None,
                    "channel_after_name": str(after_ch.name) if after_ch else None,
                },
            )
    except Exception as e:
        logger.exception("[BOT_SETUP] VC user_state persist error: %s", e)


async def _vc_notify_handler(
    member: discord.Member,
    is_join: bool,
    is_leave: bool,
    is_move: bool,
    before_ch,
    after_ch,
    now_ts: float,
    duration_str: str,
    vc_last_mention: dict[int, float],
) -> None:
    """VC 通知チャンネルへ（リッチエンベッド）。"""
    if not (is_join or is_leave or is_move):
        return
    vc_notify_id = get_vc_notify_channel_id(member.guild.id)
    if not vc_notify_id:
        return
    notify_ch = member.guild.get_channel(vc_notify_id)
    if not isinstance(notify_ch, discord.TextChannel):
        return

    # フィルターロールが設定されている場合、そのロールが view_channel を持つ VC のみ通知
    filter_role_id = get_vc_notify_filter_role_id(member.guild.id)
    if filter_role_id:
        filter_role = member.guild.get_role(filter_role_id)
        if filter_role:
            # 移動は移動元と移動先の両方が関係する。以前は is_join 以外を
            # すべて before_ch で判定していたため、そのロールに見えない VC へ
            # 移動しても、移動元さえ見えていれば通知が飛んでいた。
            # 関係するチャンネルのうち1つでも見えるなら通知する。
            related = [c for c in (before_ch, after_ch) if c is not None] if is_move \
                else [after_ch if is_join else before_ch]
            visible = [
                c for c in related
                if c is not None and c.permissions_for(filter_role).view_channel
            ]
            if not visible:
                return

    if is_join:
        eff_action = "join"
    elif is_leave:
        eff_action = "leave"
    else:
        eff_action = "move"

    now_jst  = datetime.fromtimestamp(now_ts, tz=_JST)
    time_str = (
        f"{now_jst.year}年{now_jst.month}月{now_jst.day}日 "
        f"{_WDAYS[now_jst.weekday()]} "
        f"{now_jst.hour}:{now_jst.minute:02d}"
    )

    if eff_action == "join":
        title       = "VCに参加しました"
        description = f"🔊 **{after_ch.name}** に参加しました\n\n{time_str}"
        color       = discord.Color.green()
    elif eff_action == "leave":
        title       = "VCから切断しました"
        desc_parts  = [f"🔊 **{before_ch.name}** から退出しました", "", time_str]
        if duration_str:
            desc_parts.append(f"通話時間: {duration_str}")
        description = "\n".join(desc_parts)
        color       = discord.Color.red()
    else:
        title       = "VCを移動しました"
        description = f"🔊 **{before_ch.name}** → **{after_ch.name}**\n\n{time_str}"
        color       = discord.Color.blurple()

    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    embed.set_author(name=member.display_name, icon_url=member.display_avatar.url)
    embed.set_thumbnail(url=member.display_avatar.url)

    # ロールメンション: 退出時は通知しない（参加・移動時のみ）。
    # 同ギルドで直近 10 分以内に送信済みならスキップ。
    content = None
    role_id = get_vc_notify_role_id(member.guild.id)
    if role_id and eff_action != "leave":
        gid = member.guild.id
        if now_ts - vc_last_mention.get(gid, 0.0) >= 600:
            content = f"<@&{role_id}>"
            vc_last_mention[gid] = now_ts

    await notify_ch.send(content=content, embed=embed)


async def _stop_recording_if_vc_empty(bot: Bot, guild: discord.Guild, channel) -> None:
    """録音中のVCから人間が居なくなったら、そこで区切って書き出す。

    放っておくと上限（既定6時間）まで無音を録り続けることになる。
    """
    from services import recording_service as recording

    session = recording.get_session(guild.id)
    if session is None or channel is None or channel.id != session.channel_id:
        return
    if any(m for m in channel.members if not m.bot):
        return

    result = await recording.stop_recording(bot, guild.id, reason="VC が空になりました")
    embed = recording.build_result_embed(guild.id, result)
    # 設定した通知先 → 開始告知を出した場所 → VC のチャット欄 の順に試す
    configured = recording.resolve_announce_channel(guild)
    announced = session.announce_message.channel if session.announce_message else None
    for target in (configured, announced, channel):
        if target is None:
            continue
        try:
            await target.send(embed=embed)
            return
        except Exception as e:
            logger.debug("[BOT_SETUP] 録音結果を送れませんでした: %s", e)
    logger.warning("[BOT_SETUP] guild=%s 録音結果の通知先がありませんでした（token=%s）",
                   guild.id, result["token"])


def register(bot: Bot) -> None:
    # (guild_id, user_id) → 入室時刻。VC の在室時間を数えるためだけの状態で、
    # 他のモジュールとは共有しないので EventState には含めていない。
    _vc_join_times: dict[tuple[int, int], float] = {}
    # guild_id → 最後にロールメンションを送った時刻。同上。
    _vc_last_mention: dict[int, float] = {}

    @bot.event
    async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        # TTS VC参加・退出アナウンス（bot含む全メンバー対象のため早期returnの前に実行）
        if member.guild is not None:
            await _tts_vc_announce(bot, member, before, after)

        if member.guild is None or member.bot:
            return

        await _safe(handle_security_for_voice_join(bot, member, before, after), "VC security")

        # チャンネル参照を一度だけ取得（プロパティ再ルックアップによる None 化を防ぐ）
        before_ch = before.channel
        after_ch  = after.channel

        key = (member.guild.id, member.id)
        now_ts = time.time()
        is_join, is_leave, is_move, duration_seconds, duration_str = _compute_vc_transition(
            key, now_ts, before_ch, after_ch, _vc_join_times,
        )

        await _log_vc_transition(bot, member, is_join, is_leave, is_move, before_ch, after_ch)
        await _persist_vc_transition(
            member, is_join, is_leave, is_move, before_ch, after_ch, duration_seconds, duration_str,
        )
        await _safe(
            _vc_notify_handler(
                member, is_join, is_leave, is_move, before_ch, after_ch, now_ts, duration_str, _vc_last_mention,
            ),
            "VC notify",
        )

        # 自動録音: 設定済みVCに人が入ったら録り始める。読み上げとは独立した
        # スイッチで、両方オンなら同じ接続で両方動く。
        if is_join and after_ch is not None:
            from services import recording_service as recording
            await _safe(
                recording.maybe_auto_start(bot, member, after_ch),
                "録音の自動開始",
            )

        # TTS 自動参加: 設定済みVCに誰か入ったらBotも入る（temp override 中はスキップ）
        try:
            if is_join and after_ch is not None:
                from services.tts_service import auto_join as _tts_auto_join, has_temp_override as _has_temp
                from services.tts_store import get_tts_settings as _get_tts_settings
                _tts_cfg = _get_tts_settings(member.guild.id)
                _tts_vc_id = _tts_cfg.get("vc_channel_id")
                if _tts_cfg.get("enabled") and _tts_vc_id and int(_tts_vc_id) == after_ch.id:
                    if not _has_temp(member.guild.id):
                        await _tts_auto_join(member.guild, int(_tts_vc_id))
                        # 読み上げが入った VC でも録音の条件を見る（入室側の
                        # 判定と入口が違うだけで、狙いは同じ）
                        from services import recording_service as _recording
                        await _recording.maybe_start_for_channel(
                            bot, member.guild, after_ch, trigger="TTS参加",
                        )
        except Exception as e:
            logger.exception("[BOT_SETUP] TTS auto_join error: %s", e)

        # 録音中のVCが空になったら、無音を録り続けないよう自動で止めて書き出す。
        # TTS の切断より先に処理する（切断されると録音が途中で終わるため）。
        await _safe(_stop_recording_if_vc_empty(bot, member.guild, before_ch), "録音の自動停止")

        # TTS 自動退出: VCに人間が誰もいなくなったらBotも退出（temp override も解除）。
        # 退出だけでなく移動も対象になるのがここ。判定そのものは冒頭と共通。
        try:
            if (is_leave or is_move) and _tts_vc_became_empty(member.guild.id, before_ch):
                from services.tts_service import disconnect as _tts_disconnect
                await _tts_disconnect(member.guild.id)
        except Exception as e:
            logger.exception("[BOT_SETUP] TTS auto_leave error: %s", e)
