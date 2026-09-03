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
from typing import cast

import discord
import psutil
from discord.ext import tasks
from discord.ext.commands import Bot
from envutil import env_int
from services import dev_signals
from services.metrics_reporter import report_once
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
    """register() が定義した5本の tasks.Loop をまとめて返すための入れ物。

    ready.py が on_ready の中で .is_running() / .start() を呼べるようにする
    以外の役割は無い（namedtuple でも良いが、フィールド名で読めるようこの形）。
    """

    def __init__(self, update_status, news_feed_task, pending_sticky_task, dev_signal_task, metrics_task):
        """受け取った5本の tasks.Loop をそのまま同名フィールドへ保持するだけ。"""
        self.update_status = update_status
        self.news_feed_task = news_feed_task
        self.pending_sticky_task = pending_sticky_task
        self.dev_signal_task = dev_signal_task
        self.metrics_task = metrics_task


async def _update_status(bot: Bot, state: EventState) -> None:
    """change_presence は表示文字列が前回から変わったときだけ送る。

    CPU/MEM は常に数%揺れるため、愚直に毎回送るとプレゼンス更新のレート
    制限（20秒あたり5回）にすぐ達する。"Cannot write to closing
    transport"・ClientConnectionResetError は接続が閉じかけている間に
    飛んでくる例外で、is_ready()/is_closed() のチェックを入れてもなお
    発生するため、ログを埋めないよう個別に握りつぶす。
    """
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


async def _signal_earthquake_reconnect(bot: Bot, state: EventState) -> None:
    """地震WSを張り直す。走っている接続があれば先に畳む。"""
    if state.ws_task and not state.ws_task.done():
        state.ws_task.cancel()
    state.ws_task = asyncio.create_task(run_earthquake_ws(bot))


async def _signal_user_state_repair(bot: Bot, state: EventState) -> None:
    """全ギルドのユーザー状態を突き合わせ直し、食い違いがあれば直す。"""
    await _sync_user_state_all_guilds(
        bot,
        source="manual_signal",
        write_events_on_sync=_USER_STATE_AUTO_REPAIR_WRITE_EVENTS,
        run_integrity_repair=True,
        lock=state.user_state_sync_lock,
    )


async def _signal_eq_replay(bot: Bot, sig_content: str) -> None:
    """記録済みの地震イベントを、本番と同じ経路で流し直す。"""
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


async def _recording_start(bot: Bot, guild, guild_id: int, payload: dict) -> None:
    """管理画面から指定された VC で録音を始める。

    `guild_id` を別に受けるのは、ログへ出すのが**要求された guild_id**だから。
    `guild.id` で代用すると、取り違えたときに「要求した ID」ではなく
    「見つかった ID」が出て、食い違いそのものが見えなくなる。
    """
    from services import recording_service as recording

    channel = guild.get_channel(int(payload.get("channel_id", 0)))
    if not isinstance(channel, discord.VoiceChannel):
        logger.warning(
            "[DEV] recording_start: channel_id=%s が見つからないか VC ではありません",
            payload.get("channel_id"),
        )
        return
    # guild.me は接続直後だと None のことがあり、そのときは bot.user（起動時に
    # 必ず入る）で代用する。どちらも実体は「録音を始めた人」として扱える
    # ユーザーだが、型としては Member | ClientUser | None なので cast で通す。
    # 分割前はこの行が注釈の無いクロージャの中にあり、型検査の対象外だった。
    starter = cast(discord.abc.User, guild.me or bot.user)
    try:
        await recording.start_recording(bot, guild, channel, started_by=starter)
        logger.info("[DEV] recording_start: guild=%s ch=%s", guild_id, channel.id)
    except recording.RecordingError as e:
        logger.warning("[DEV] recording_start 失敗 guild=%s: %s", guild_id, e)


async def _recording_stop(bot: Bot, guild, guild_id: int) -> None:
    """録音を止め、結果を告知先へ送る。

    停止先は `guild.id` ではなく、要求された `guild_id` で指す（理由は
    _recording_start と同じ）。
    """
    from services import recording_service as recording

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


async def _signal_recording(bot: Bot, task_name: str, sig_content: str) -> None:
    """録音の開始・停止。管理画面は別プロセスなので、ここで受ける。"""
    payload = json.loads(sig_content)
    guild_id = int(payload.get("guild_id", 0))
    guild = bot.get_guild(guild_id)
    if guild is None:
        logger.warning(
            "[DEV] %s: guild_id=%s が見つかりません" "（bot が未参加、またはキャッシュ未反映）",
            task_name,
            guild_id,
        )
        return
    if task_name == "recording_start":
        await _recording_start(bot, guild, guild_id, payload)
    else:
        await _recording_stop(bot, guild, guild_id)


async def _signal_test_notify(bot: Bot, task_name: str, sig_content: str) -> None:
    """通知テスト。中身は services/dev_test_notify.py が持つ。

    「本番と同じ関数を使う」「channel_id 指定なら本番のチャンネル設定を
    見ずに直接送る」をそちらで一括して守る。
    """
    from services.dev_test_notify import KINDS, run_test

    kind = task_name[len("test_") :]
    if kind not in KINDS:
        logger.warning("[DEV] 未知の通知テストです: %s", kind)
        return
    payload = json.loads(sig_content)
    await run_test(bot, kind, int(payload.get("guild_id", 0)), payload.get("channel_id"))


async def _handle_dev_signal(bot: Bot, state: EventState, task_name: str, sig_content: str) -> bool:
    """用途名から処理を選んで走らせる。知らない名前なら False。

    False を返した側（_process_dev_signals）が警告を出す。どの分岐にも
    当たらないと、ファイルだけ消えて「受信」「完了」のログが残り、何も
    実行されないまま成功に見える。名前の打ち間違いや実装漏れが静かに
    埋もれるので、必ず声を上げる。
    """
    if task_name == "news_feeds":
        await run_news_feeds(bot)
    elif task_name == "sticky":
        await process_pending_stickies(bot)
    elif task_name == "djaudio_cache":
        from services.djaudio_cache import _cleanup_expired

        await _cleanup_expired(bot=bot)
    elif task_name == "earthquake_reconnect":
        await _signal_earthquake_reconnect(bot, state)
    elif task_name == "user_state_repair":
        await _signal_user_state_repair(bot, state)
    elif task_name == "eq_replay":
        await _signal_eq_replay(bot, sig_content)
    elif task_name in ("recording_start", "recording_stop"):
        await _signal_recording(bot, task_name, sig_content)
    elif task_name.startswith("test_"):
        await _signal_test_notify(bot, task_name, sig_content)
    else:
        return False
    return True


async def _process_dev_signals(bot: Bot, state: EventState) -> None:
    """開発用シグナルファイル（管理画面など別プロセスからの合図）を1件ずつ処理する。

    1ファイルの処理で例外が出ても内側の try/except で捕まえ、他のシグナルの
    処理やこのループ自体を止めない。
    """
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
            if not await _handle_dev_signal(bot, state, task_name, sig_content):
                logger.warning("[DEV] 未知のシグナルなので何もしませんでした: %s", task_name)
                continue
            logger.info("[DEV] シグナル完了: %s", task_name)
        except Exception as e:
            logger.exception("[DEV] シグナル実行エラー %s: %s", task_name, e)


async def _report_metrics(bot: Bot) -> None:
    """Bot の心拍とアプリ固有の瞬間値を Valkey へ流す。

    出すのは「Netdata が自分では測れないもの」だけにしてある。CPU とメモリは
    Netdata がホスト側で測るので重ねない。ここで psutil を呼ぶと、そのぶん
    イベントループが止まる。

    レイテンシ（bot.latency）は Discord のゲートウェイまでの往復で、秒で来る。
    ミリ秒へ直さずそのまま出す（Prometheus の作法では基本単位の秒で出す）。
    """
    guilds = bot.guilds if hasattr(bot, "guilds") else []
    latency = getattr(bot, "latency", float("nan"))
    gauges = {
        "bot_guilds": float(len(guilds)),
        "bot_members_visible": float(sum(getattr(g, "member_count", 0) or 0 for g in guilds)),
        # 声の接続数。落ちているのに気づきにくい機能なので数を出す。
        "bot_voice_clients": float(len(getattr(bot, "voice_clients", []) or [])),
    }
    # latency は接続前に nan になる。nan を出すと Netdata 側で系列が壊れるので、
    # 数値として妥当なときだけ載せる。
    if isinstance(latency, (int, float)) and latency == latency and latency != float("inf"):
        gauges["bot_gateway_latency_seconds"] = float(latency)
    await report_once("bot", gauges=gauges)


def register(bot: Bot, state: EventState) -> BackgroundLoops:
    """4本の @tasks.loop をクロージャとして定義し、BackgroundLoops にまとめて
    返す（詳細と分割の経緯はモジュール docstring 参照）。ここでは定義する
    だけで start() はしない。実際に動かし始めるのは events.ready.on_ready
    の仕事で、それまでは4本とも停止した Loop オブジェクトのまま返る。

    中身は module 直下の関数に置いてある。ここに残すのは「何を、どの間隔で
    回すか」だけで、その間隔は tests の RegisterBackgroundTasksShapeTests が
    固定している（`seconds=30` を `minutes=30` と書き間違えても型は同じで、
    例外も出ず、60倍遅くなるだけなので）。
    """

    # Discord のプレゼンス更新には 20秒あたり5回という制限がある。5秒間隔だと
    # 20秒あたり4回で、超えてはいないが余裕がほぼ無い（1日 17,280 回）。
    # 内容は CPU/MEM/Ping の数％の揺れなので、間隔を空けたうえで
    # 表示が実際に変わったときだけ送る。
    @tasks.loop(seconds=_STATUS_INTERVAL_SECONDS)
    async def update_status():
        """ステータス更新（中身は _update_status）。"""
        await _update_status(bot, state)

    @tasks.loop(minutes=5)
    async def news_feed_task():
        """_safe で例外を握りつぶす。discord.ext.tasks の loop は中で例外が
        飛ぶとその回のイテレーションで停止し、再始動しない限り二度と
        走らない。ニュース取得先のAPIが一時的に落ちただけでフィード配信が
        完全に止まるのを防ぐ。
        """
        await _safe(run_news_feeds(bot), "news_feed_task")

    @tasks.loop(seconds=30)
    async def pending_sticky_task():
        """_safe を通す理由は news_feed_task と同じ（discord.ext.tasks の
        loop は例外で止まったまま自動では再始動しない）。
        """
        await _safe(process_pending_stickies(bot), "pending_sticky_task")

    @tasks.loop(seconds=30)
    async def dev_signal_task():
        """開発者シグナルファイルの監視（中身は _process_dev_signals）。"""
        await _process_dev_signals(bot, state)

    # Bot は HTTP サーバーを持たないので、Netdata から直接は測れない。ここで
    # Valkey へ心拍と数値を置き、管理画面の /metrics がまとめて出す
    # （services/metrics_registry.py の冒頭）。**このループが止まると
    # sycs_up{app="bot"} が 0 になる。** つまり Bot の死活そのものになるので、
    # 他のループと違って BOT_BACKGROUND_WORKER に関係なく常に回す。
    @tasks.loop(seconds=30)
    async def metrics_task():
        """メトリクスの報告（中身は _report_metrics）。"""
        await _report_metrics(bot)

    return BackgroundLoops(
        update_status=update_status,
        news_feed_task=news_feed_task,
        pending_sticky_task=pending_sticky_task,
        dev_signal_task=dev_signal_task,
        metrics_task=metrics_task,
    )
