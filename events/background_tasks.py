"""@tasks.loop で回している4本の背景タスク。

update_status（ステータス更新）/ news_feed_task（ニュースフィード）/
pending_sticky_task（スティッキー pending 処理）/ dev_signal_task（開発者
シグナル監視）。setup_events(bot) の巨大クロージャからそのまま切り出した。

register(bot, state) はこれらを定義するだけで start() はしない（実際に
動かし始めるのは events.ready.on_ready の仕事）。呼び出し側が .is_running() /
.start() を呼べるよう、定義したループを BackgroundLoops として返す。
"""

from __future__ import annotations

import asyncio
import json
import logging
import math

import discord
import psutil
from discord.ext import tasks
from discord.ext.commands import Bot
from envutil import env_int
from services import dev_signals
from services.earthquake_service import run_earthquake_ws
from services.news_service import run_news_feeds
from services.sticky_service import process_pending_stickies

from events._util import _safe
from events.state import EventState
from events.user_state_sync import _USER_STATE_AUTO_REPAIR_WRITE_EVENTS, _sync_user_state_all_guilds

logger = logging.getLogger(__name__)

# ステータス更新の間隔（秒）。Discord のプレゼンス更新は 20秒あたり5回まで。
_STATUS_INTERVAL_SECONDS = env_int("BOT_STATUS_INTERVAL_SECONDS", 20, minimum=5)


def _format_status_text(cpu: float, mem: float, latency_raw) -> str:
    """update_status が組み立てる表示文字列。

    bot.latency は接続状況によって inf/NaN になり得る（実際に heartbeat が
    届く前は inf）。そのまま f-string に渡すと "infms" のような表示になるため、
    有限値のときだけ ms 表記にし、それ以外は N/A にする。
    """
    if isinstance(latency_raw, (int, float)) and math.isfinite(latency_raw):
        latency_display = f"{round(latency_raw * 1000)}ms"
    else:
        latency_display = "N/A"
    return f"Ping: {latency_display} | CPU: {cpu}% | MEM: {mem}%"


class BackgroundLoops:
    """register() が定義した4本の tasks.Loop をまとめて返すための入れ物。

    ready.py が on_ready の中で .is_running() / .start() を呼べるようにする
    以外の役割は無い（namedtuple でも良いが、フィールド名で読めるようこの形）。
    """

    def __init__(self, update_status, news_feed_task, pending_sticky_task, dev_signal_task):
        self.update_status = update_status
        self.news_feed_task = news_feed_task
        self.pending_sticky_task = pending_sticky_task
        self.dev_signal_task = dev_signal_task


def register(bot: Bot, state: EventState) -> BackgroundLoops:
    # --------------------------
    # ステータス更新
    # --------------------------
    # Discord のプレゼンス更新には 20秒あたり5回という制限がある。5秒間隔だと
    # 20秒あたり4回で、超えてはいないが余裕がほぼ無い（1日 17,280 回）。
    # 内容は CPU/MEM/Ping の数％の揺れなので、間隔を空けたうえで
    # 表示が実際に変わったときだけ送る。
    @tasks.loop(seconds=_STATUS_INTERVAL_SECONDS)
    async def update_status():
        if not bot.is_ready() or bot.is_closed():
            return
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            text = _format_status_text(cpu, mem, bot.latency)
            if text == state.last_status_text:
                return
            await bot.change_presence(activity=discord.Game(name=text))
            state.last_status_text = text
        except Exception as e:
            if "Cannot write to closing transport" in str(e) or "ClientConnectionResetError" in type(e).__name__:
                return
            logger.exception("ステータス更新エラー: %s", e)

    # --------------------------
    # ニュースフィード（5分ごと）
    # --------------------------
    @tasks.loop(minutes=5)
    async def news_feed_task():
        await _safe(run_news_feeds(bot), "news_feed_task")

    # --------------------------
    # スティッキー pending 処理（30秒ごと）
    # --------------------------
    @tasks.loop(seconds=30)
    async def pending_sticky_task():
        await _safe(process_pending_stickies(bot), "pending_sticky_task")

    # --------------------------
    # 開発者シグナルファイル監視（30秒ごと）
    # --------------------------
    @tasks.loop(seconds=30)
    async def dev_signal_task():
        # 置かれた順に処理する。同じ用途が複数溜まっていることがあり
        # （録音の開始と停止など）、順序が入れ替わると噛み合わない。
        for sig_file in dev_signals.collect():
            task_name = dev_signals.task_name_of(sig_file)
            try:
                try:
                    sig_content = sig_file.read_text(encoding="utf-8")
                except OSError:
                    continue
                sig_file.unlink(missing_ok=True)
                logger.info("[DEV] シグナル受信: %s", task_name)
                if task_name == "news_feeds":
                    await run_news_feeds(bot)
                elif task_name == "sticky":
                    await process_pending_stickies(bot)
                elif task_name == "djaudio_cache":
                    from services.djaudio_cache import _cleanup_expired

                    await _cleanup_expired(bot=bot)
                elif task_name == "earthquake_reconnect":
                    if state.ws_task and not state.ws_task.done():
                        state.ws_task.cancel()
                    state.ws_task = asyncio.create_task(run_earthquake_ws(bot))
                elif task_name == "user_state_repair":
                    await _sync_user_state_all_guilds(
                        bot,
                        source="manual_signal",
                        write_events_on_sync=_USER_STATE_AUTO_REPAIR_WRITE_EVENTS,
                        run_integrity_repair=True,
                        lock=state.user_state_sync_lock,
                    )
                elif task_name == "eq_replay":
                    from services.earthquake_service import _notify_all_guilds

                    payload = json.loads(sig_content)
                    # 新形式は {"event": ..., "guild_id": ...|None, "channel_id": ...|None}。
                    # ロールアウト中に旧形式（イベント本体を直接書いた文字列）が
                    # 来ても動くよう、"event" キーが無ければ payload 全体を
                    # イベントとして扱う（channel_id は旧形式には無い＝None）。
                    if isinstance(payload, dict) and "event" in payload:
                        event = payload.get("event") or {}
                        only_guild_id = payload.get("guild_id")
                        override_channel_id = payload.get("channel_id")
                    else:
                        event = payload
                        only_guild_id = None
                        override_channel_id = None
                    sent = await _notify_all_guilds(
                        bot,
                        event,
                        only_guild_id=only_guild_id,
                        override_channel_id=override_channel_id,
                    )
                    # 0 件のときの理由は _notify_all_guilds 側が warning ログを出す。
                    # ここでは「シグナル完了」ログだけでは何が起きたか分からない、
                    # という状態を無くすために件数を残す。
                    logger.info("[DEV] eq_replay: %d 件へ送信", sent)
                elif task_name in ("recording_start", "recording_stop"):
                    # 管理画面は別プロセスなので、録音の開始・停止はここで受ける。
                    from services import recording_service as recording

                    payload = json.loads(sig_content)
                    guild_id = int(payload.get("guild_id", 0))
                    guild = bot.get_guild(guild_id)
                    if guild is None:
                        logger.warning(
                            "[DEV] %s: guild_id=%s が見つかりません" "（bot が未参加、またはキャッシュ未反映）",
                            task_name,
                            guild_id,
                        )
                    elif task_name == "recording_start":
                        channel = guild.get_channel(int(payload.get("channel_id", 0)))
                        if not isinstance(channel, discord.VoiceChannel):
                            logger.warning(
                                "[DEV] recording_start: channel_id=%s が見つからないか VC ではありません",
                                payload.get("channel_id"),
                            )
                        else:
                            starter = guild.me or bot.user
                            try:
                                await recording.start_recording(
                                    bot,
                                    guild,
                                    channel,
                                    started_by=starter,
                                )
                                logger.info("[DEV] recording_start: guild=%s ch=%s", guild_id, channel.id)
                            except recording.RecordingError as e:
                                logger.warning("[DEV] recording_start 失敗 guild=%s: %s", guild_id, e)
                    else:
                        try:
                            result = await recording.stop_recording(bot, guild_id, reason="管理画面から停止")
                            embed = recording.build_result_embed(guild_id, result)
                            target = recording.resolve_announce_channel(
                                guild,
                                fallback=guild.get_channel(result["channel_id"]),
                            )
                            if isinstance(target, discord.abc.Messageable):
                                await target.send(embed=embed)
                            else:
                                logger.warning(
                                    "[DEV] recording_stop: guild=%s 結果の送信先がありません（token=%s）",
                                    guild_id,
                                    result["token"],
                                )
                            logger.info("[DEV] recording_stop: guild=%s token=%s", guild_id, result["token"])
                        except recording.RecordingError as e:
                            logger.warning("[DEV] recording_stop 失敗 guild=%s: %s", guild_id, e)
                elif task_name.startswith("test_"):
                    # 通知テストの中身は services/dev_test_notify.py が持つ。
                    # 「本番と同じ関数を使う」「channel_id 指定なら本番の
                    # チャンネル設定を見ずに直接送る」をそちらで一括して守る。
                    from services.dev_test_notify import KINDS, run_test

                    kind = task_name[len("test_") :]
                    if kind not in KINDS:
                        logger.warning("[DEV] 未知の通知テストです: %s", kind)
                    else:
                        payload = json.loads(sig_content)
                        await run_test(
                            bot,
                            kind,
                            int(payload.get("guild_id", 0)),
                            payload.get("channel_id"),
                        )
                else:
                    # どの分岐にも当たらないと、ファイルだけ消えて「受信」「完了」の
                    # ログが残り、何も実行されないまま成功に見える。名前の打ち間違いや
                    # 実装漏れが静かに埋もれるので、必ず声を上げる。
                    logger.warning(
                        "[DEV] 未知のシグナルなので何もしませんでした: %s",
                        task_name,
                    )
                    continue
                logger.info("[DEV] シグナル完了: %s", task_name)
            except Exception as e:
                logger.exception("[DEV] シグナル実行エラー %s: %s", task_name, e)

    return BackgroundLoops(
        update_status=update_status,
        news_feed_task=news_feed_task,
        pending_sticky_task=pending_sticky_task,
        dev_signal_task=dev_signal_task,
    )
