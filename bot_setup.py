import asyncio
import json
import logging
import math
import os
import time
from datetime import datetime
from pathlib import Path

import discord
import psutil
from commands.chat_commands import handle_chatgpt_message
from discord.ext import commands, tasks
from discord.ext.commands import Bot
from services.djaudio_cache import cache_cleanup_loop as djaudio_cache_cleanup
from services.djaudio_service import handle_djaudio_message
from services.earthquake_service import run_earthquake_ws
from services.logging_service import log_action
from services.news_service import run_news_feeds
from services.reaction_role_service import handle_reaction_add, handle_reaction_remove
from services.security_service import handle_security_for_message, handle_security_for_voice_join
from services.user_state_service import (
    record_user_state_event,
    repair_user_state_integrity,
    sync_guild_user_states,
)
from config import JST as _JST
from services.settings_store import get_vc_notify_channel_id, get_vc_notify_filter_role_id, get_vc_notify_role_id
from services.sticky_service import handle_sticky, process_pending_stickies
from services.welcome_service import send_goodbye, send_welcome

logger = logging.getLogger(__name__)

_WDAYS = ["月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日", "日曜日"]
_TRUE_SET = {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE_SET


_BOT_BACKGROUND_WORKER = _env_bool("BOT_BACKGROUND_WORKER", True)
_USER_STATE_SYNC_ON_READY = _env_bool("USER_STATE_SYNC_ON_READY", True)
_USER_STATE_SYNC_DELAY_SECONDS = max(0, int(os.getenv("USER_STATE_SYNC_DELAY_SECONDS", "20")))
_USER_STATE_SYNC_GUILD_PAUSE_SECONDS = max(
    0.0,
    float(os.getenv("USER_STATE_SYNC_GUILD_PAUSE_SECONDS", "1.0")),
)
_USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD = max(
    0,
    int(os.getenv("USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", "0")),
)
_USER_STATE_AUTO_REPAIR_ENABLED = _env_bool("USER_STATE_AUTO_REPAIR_ENABLED", True)
_USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS = max(
    300,
    int(os.getenv("USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS", "1800")),
)
_USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS = max(
    0,
    int(os.getenv("USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS", "180")),
)
_USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD = max(
    100,
    int(os.getenv("USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD", "50000")),
)
_USER_STATE_AUTO_REPAIR_WRITE_EVENTS = _env_bool("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", False)

_SIGNAL_DIR = Path(os.getenv("SETTINGS_DIR", str(Path(__file__).parent / "data"))) / "_dev_signals"


def create_bot() -> Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    intents.voice_states = True
    intents.moderation = True
    intents.reactions = True
    return commands.Bot(command_prefix="!", intents=intents)


def setup_events(bot: Bot) -> None:
    _ws_task: asyncio.Task | None = None
    _user_state_sync_task: asyncio.Task | None = None
    _user_state_repair_task: asyncio.Task | None = None
    _user_state_sync_started = False
    _user_state_repair_started = False
    _user_state_sync_lock = asyncio.Lock()
    _vc_join_times: dict[tuple[int, int], float] = {}  # (guild_id, user_id) → 入室時刻
    _vc_last_mention: dict[int, float] = {}            # guild_id → 最後にロールメンションを送った時刻

    async def _find_recent_audit_entry(
        guild: discord.Guild,
        *,
        action: discord.AuditLogAction,
        target_user_id: int,
        window_seconds: int = 20,
        retries: int = 2,
        retry_delay: float = 0.6,
    ) -> discord.AuditLogEntry | None:
        me = guild.me
        if me is None or not me.guild_permissions.view_audit_log:
            return None

        for attempt in range(retries + 1):
            try:
                now_utc = discord.utils.utcnow()
                async for entry in guild.audit_logs(limit=10, action=action):
                    target = getattr(entry, "target", None)
                    if getattr(target, "id", None) != target_user_id:
                        continue

                    created_at = getattr(entry, "created_at", None)
                    if created_at is None:
                        continue

                    age = (now_utc - created_at).total_seconds()
                    if 0 <= age <= window_seconds:
                        return entry
            except Exception as e:
                logger.debug(
                    "[BOT_SETUP] audit log lookup failed action=%s target=%s err=%s",
                    action,
                    target_user_id,
                    e,
                )

            if attempt < retries:
                await asyncio.sleep(retry_delay)
        return None

    async def _fetch_guild_members_for_sync(guild: discord.Guild) -> tuple[list[discord.Member], bool]:
        members: list[discord.Member] = []
        fetched_all = False
        fetch_limit = _USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD or None

        try:
            async for member in guild.fetch_members(limit=fetch_limit):
                members.append(member)
            fetched_all = fetch_limit is None
        except discord.Forbidden:
            logger.warning(
                "[BOT_SETUP] user_state sync: fetch_members forbidden guild=%s. Fallback to cache.",
                guild.id,
            )
            members = list(guild.members)
            fetched_all = False
        except Exception as e:
            logger.exception(
                "[BOT_SETUP] user_state sync: fetch_members error guild=%s err=%s",
                guild.id,
                e,
            )
            members = list(guild.members)
            fetched_all = False

        return members, fetched_all

    async def _fetch_guild_bans_for_sync(guild: discord.Guild) -> list[discord.abc.User]:
        users: list[discord.abc.User] = []
        try:
            async for entry in guild.bans(limit=None):
                users.append(entry.user)
        except discord.Forbidden:
            logger.warning(
                "[BOT_SETUP] user_state sync: bans forbidden guild=%s. Skip ban sync.",
                guild.id,
            )
        except Exception as e:
            logger.exception(
                "[BOT_SETUP] user_state sync: bans fetch error guild=%s err=%s",
                guild.id,
                e,
            )
        return users

    async def _sync_user_state_all_guilds(
        *,
        source: str,
        write_events_on_sync: bool,
        run_integrity_repair: bool,
    ) -> None:
        async with _user_state_sync_lock:
            logger.info(
                "[BOT_SETUP] user_state sync started source=%s guilds=%s",
                source,
                len(bot.guilds),
            )
            total_members = 0
            total_bans = 0
            total_created = 0
            total_updated = 0
            total_left = 0
            total_events = 0
            total_repair_rows = 0
            total_repair_fixed = 0

            for guild in bot.guilds:
                try:
                    members, fetched_all = await _fetch_guild_members_for_sync(guild)
                    banned_users = await _fetch_guild_bans_for_sync(guild)

                    stats = await sync_guild_user_states(
                        guild_id=guild.id,
                        members=members,
                        banned_users=banned_users,
                        source=source,
                        reconcile_missing=fetched_all,
                        write_events_on_sync=write_events_on_sync,
                    )
                    total_members += stats.get("members_seen", 0)
                    total_bans += stats.get("bans_seen", 0)
                    total_created += stats.get("created", 0)
                    total_updated += stats.get("updated", 0)
                    total_left += stats.get("left_reconciled", 0)
                    total_events += stats.get("events_written", 0)

                    repair_stats: dict[str, int] | None = None
                    if run_integrity_repair:
                        repair_stats = await repair_user_state_integrity(
                            guild_id=guild.id,
                            max_rows=_USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD,
                        )
                        total_repair_rows += repair_stats.get("rows_scanned", 0)
                        total_repair_fixed += repair_stats.get("rows_fixed", 0)

                    logger.info(
                        "[BOT_SETUP] user_state sync guild=%s source=%s members=%s bans=%s created=%s updated=%s left=%s events=%s fetched_all=%s repaired_rows=%s repaired_fixed=%s",
                        guild.id,
                        source,
                        stats.get("members_seen", 0),
                        stats.get("bans_seen", 0),
                        stats.get("created", 0),
                        stats.get("updated", 0),
                        stats.get("left_reconciled", 0),
                        stats.get("events_written", 0),
                        fetched_all,
                        0 if repair_stats is None else repair_stats.get("rows_scanned", 0),
                        0 if repair_stats is None else repair_stats.get("rows_fixed", 0),
                    )
                except Exception as e:
                    logger.exception(
                        "[BOT_SETUP] user_state sync failed guild=%s source=%s err=%s",
                        guild.id,
                        source,
                        e,
                    )

                if _USER_STATE_SYNC_GUILD_PAUSE_SECONDS > 0:
                    await asyncio.sleep(_USER_STATE_SYNC_GUILD_PAUSE_SECONDS)

            logger.info(
                "[BOT_SETUP] user_state sync completed source=%s members=%s bans=%s created=%s updated=%s left=%s events=%s repaired_rows=%s repaired_fixed=%s",
                source,
                total_members,
                total_bans,
                total_created,
                total_updated,
                total_left,
                total_events,
                total_repair_rows,
                total_repair_fixed,
            )

    async def _sync_user_state_on_ready() -> None:
        try:
            if _USER_STATE_SYNC_DELAY_SECONDS > 0:
                await asyncio.sleep(_USER_STATE_SYNC_DELAY_SECONDS)
            await _sync_user_state_all_guilds(
                source="on_ready",
                write_events_on_sync=True,
                run_integrity_repair=True,
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] user_state sync fatal error: %s", e)

    async def _user_state_auto_repair_loop() -> None:
        try:
            if _USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS > 0:
                await asyncio.sleep(_USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS)
            while not bot.is_closed():
                await _sync_user_state_all_guilds(
                    source="auto_repair",
                    write_events_on_sync=_USER_STATE_AUTO_REPAIR_WRITE_EVENTS,
                    run_integrity_repair=True,
                )
                await asyncio.sleep(_USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.info("[BOT_SETUP] user_state auto_repair loop cancelled")
            raise
        except Exception as e:
            logger.exception("[BOT_SETUP] user_state auto_repair fatal error: %s", e)

    # --------------------------
    # ステータス更新
    # --------------------------
    @tasks.loop(seconds=5)
    async def update_status():
        if not bot.is_ready() or bot.is_closed():
            return
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            latency_raw = bot.latency
            if isinstance(latency_raw, (int, float)) and math.isfinite(latency_raw):
                latency_display = f"{round(latency_raw * 1000)}ms"
            else:
                latency_display = "N/A"
            await bot.change_presence(
                activity=discord.Game(
                    name=f"Ping: {latency_display} | CPU: {cpu}% | MEM: {mem}%"
                )
            )
        except Exception as e:
            if "Cannot write to closing transport" in str(e) or "ClientConnectionResetError" in type(e).__name__:
                return
            logger.exception("ステータス更新エラー: %s", e)

    # --------------------------
    # ニュースフィード（5分ごと）
    # --------------------------
    @tasks.loop(minutes=5)
    async def news_feed_task():
        try:
            await run_news_feeds(bot)
        except Exception as e:
            logger.exception("[BOT_SETUP] news_feed_task error: %s", e)

    # --------------------------
    # スティッキー pending 処理（30秒ごと）
    # --------------------------
    @tasks.loop(seconds=30)
    async def pending_sticky_task():
        try:
            await process_pending_stickies(bot)
        except Exception as e:
            logger.exception("[BOT_SETUP] pending_sticky_task error: %s", e)

    # --------------------------
    # 開発者シグナルファイル監視（30秒ごと）
    # --------------------------
    @tasks.loop(seconds=30)
    async def dev_signal_task():
        if not _SIGNAL_DIR.exists():
            return
        for sig_file in list(_SIGNAL_DIR.glob("*.signal")):
            task_name = sig_file.stem
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
                    nonlocal _ws_task
                    if _ws_task and not _ws_task.done():
                        _ws_task.cancel()
                    _ws_task = asyncio.create_task(run_earthquake_ws(bot))
                elif task_name == "user_state_repair":
                    await _sync_user_state_all_guilds(
                        source="manual_signal",
                        write_events_on_sync=_USER_STATE_AUTO_REPAIR_WRITE_EVENTS,
                        run_integrity_repair=True,
                    )
                elif task_name == "eq_replay":
                    from services.earthquake_service import _notify_all_guilds
                    event = json.loads(sig_content)
                    await _notify_all_guilds(bot, event)
                elif task_name == "test_welcome":
                    payload = json.loads(sig_content)
                    guild_id = int(payload.get("guild_id", 0))
                    guild = bot.get_guild(guild_id)
                    if guild:
                        from services.settings_store import get_welcome_settings
                        s = get_welcome_settings(guild_id)
                        ch_id = s.get("channel_id")
                        if ch_id:
                            ch = guild.get_channel(int(ch_id))
                            if isinstance(ch, discord.TextChannel):
                                tmpl = s.get("message") or "{user} が **{server}** に参加しました！（現在 {count} 名）"
                                text = (tmpl
                                    .replace("{user}", "**@テストユーザー**")
                                    .replace("{username}", "テストユーザー")
                                    .replace("{server}", guild.name)
                                    .replace("{count}", str(guild.member_count)))
                                await ch.send(f"🧪 **[テスト送信 — ウェルカム]**\n{text}")
                elif task_name == "test_vc_notify":
                    payload = json.loads(sig_content)
                    guild_id = int(payload.get("guild_id", 0))
                    guild = bot.get_guild(guild_id)
                    if guild:
                        from services.settings_store import get_vc_notify_channel_id
                        ch_id = get_vc_notify_channel_id(guild_id)
                        if ch_id:
                            ch = guild.get_channel(ch_id)
                            if isinstance(ch, discord.TextChannel):
                                embed = discord.Embed(
                                    title="🎙️ テストユーザー が参加しました",
                                    description="VC: テストチャンネル",
                                    color=discord.Color.blue(),
                                )
                                embed.set_footer(text="🧪 テスト送信 — VC通知")
                                await ch.send(embed=embed)
                logger.info("[DEV] シグナル完了: %s", task_name)
            except Exception as e:
                logger.exception("[DEV] シグナル実行エラー %s: %s", task_name, e)

    @bot.event
    async def on_ready():
        nonlocal _ws_task, _user_state_sync_task, _user_state_sync_started
        nonlocal _user_state_repair_task, _user_state_repair_started
        logger.info("[BOT] Logged in as %s", bot.user)
        await bot.tree.sync()
        if not update_status.is_running():
            update_status.start()
        if not dev_signal_task.is_running():
            dev_signal_task.start()
        if _BOT_BACKGROUND_WORKER:
            if not news_feed_task.is_running():
                news_feed_task.start()
            if not pending_sticky_task.is_running():
                pending_sticky_task.start()
            if _ws_task is None or _ws_task.done():
                _ws_task = asyncio.create_task(run_earthquake_ws(bot))
            asyncio.create_task(djaudio_cache_cleanup(bot=bot, interval=60))
            logger.info("[BOT] background worker enabled: periodic jobs are active")
        else:
            logger.info("[BOT] BOT_BACKGROUND_WORKER=false: periodic background jobs are disabled")

        if _USER_STATE_SYNC_ON_READY and not _user_state_sync_started:
            _user_state_sync_started = True
            _user_state_sync_task = asyncio.create_task(_sync_user_state_on_ready())
            logger.info(
                "[BOT] USER_STATE_SYNC_ON_READY=true: background sync task started (delay=%ss)",
                _USER_STATE_SYNC_DELAY_SECONDS,
            )

        if _USER_STATE_AUTO_REPAIR_ENABLED and not _user_state_repair_started:
            _user_state_repair_started = True
            _user_state_repair_task = asyncio.create_task(_user_state_auto_repair_loop())
            logger.info(
                "[BOT] USER_STATE_AUTO_REPAIR_ENABLED=true: periodic repair started (interval=%ss)",
                _USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS,
            )

    # --------------------------
    # メッセージ（司令塔）
    # --------------------------
    @bot.event
    async def on_message(message: discord.Message):
        if message.guild is None or message.author.bot:
            return

        logger.debug(
            "[BOT_SETUP] on_message guild=%s ch=%s author=%s",
            message.guild.id,
            message.channel.id,
            message.author,
        )

        async def _safe(coro, name: str) -> None:
            try:
                await coro
            except Exception as e:
                logger.exception("[BOT_SETUP] %s error: %s", name, e)

        async def _tts_handler() -> None:
            from services.tts_service import enqueue_message as _tts_enqueue, get_effective_vc_watch as _get_vc_watch
            from services.tts_store import get_tts_settings as _get_tts_settings
            settings = _get_tts_settings(message.guild.id)
            effective_vc_id, watch_ids = _get_vc_watch(message.guild.id, settings)
            in_vc_text = effective_vc_id is not None and message.channel.id == effective_vc_id
            if (message.channel.id in watch_ids or in_vc_text) and isinstance(message.author, discord.Member):
                await _tts_enqueue(bot, message.guild, message.author, message.content)

        # 各ハンドラーは互いに独立しているため並列実行（VT スキャンが DJAudio をブロックしない）
        await asyncio.gather(
            _safe(handle_security_for_message(bot, message), "security_service"),
            _safe(handle_chatgpt_message(bot, message), "chat_commands"),
            _safe(handle_sticky(message), "sticky"),
            _safe(handle_djaudio_message(bot, message), "djaudio"),
            _safe(_tts_handler(), "tts"),
        )

        await bot.process_commands(message)

    # --------------------------
    # メッセージ削除
    # --------------------------
    @bot.event
    async def on_message_delete(message: discord.Message):
        if message.guild is None:
            return

        fields = {
            "送信日時": message.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M")
            if message.created_at else "(不明)",
            "内容": (message.content or "(内容なし)")[:1024],
            "ユーザーID": str(message.author.id) if message.author else "不明",
            "メッセージID": str(message.id),
        }

        if message.attachments:
            attachment_urls = "\n".join(a.url for a in message.attachments)
            fields["添付ファイル"] = attachment_urls[:1024] + ("... (省略)" if len(attachment_urls) > 1024 else "")

        try:
            await log_action(
                bot,
                message.guild.id,
                "INFO",
                f"{message.author.mention} のメッセージが削除されました。",
                user=message.author,
                fields=fields,
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_message_delete log_action error: %s", e)

    # --------------------------
    # メッセージ編集
    # --------------------------
    @bot.event
    async def on_message_edit(before: discord.Message, after: discord.Message):
        if before.guild is None:
            return
        if before.content == after.content:
            return

        ch_mention = before.channel.mention

        try:
            await log_action(
                bot,
                before.guild.id,
                "INFO",
                f"{before.author.mention} のメッセージが編集されました。",
                user=before.author,
                fields={
                    "チャンネル": ch_mention,
                    "編集前": (before.content or "(なし)")[:1000],
                    "編集後": (after.content or "(なし)")[:1000],
                    "メッセージID": str(before.id),
                },
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_message_edit log_action error: %s", e)

    # --------------------------
    # VC 参加・退出・移動 + セキュリティ + VC通知チャンネル
    # --------------------------
    @bot.event
    async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        # TTS VC参加・退出アナウンス（bot含む全メンバー対象のため早期returnの前に実行）
        if member.guild is not None:
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
                    # 全員退出: 監視VCがBot以外0人になったらTTSを切断（再接続防止）
                    if (
                        _ev == "leave"
                        and _bch is not None
                        and _vid is not None
                        and _bch.id == _vid
                        and not any(m for m in _bch.members if not m.bot)
                    ):
                        await _tts_disconnect(member.guild.id)
                    elif not member.bot and _cfg.get("enabled") and _cfg.get("vc_notify") and _vid:
                        _tch = _ach if _ev == "join" else _bch
                        if _tch and _vid == _tch.id:
                            await _tts_vc_event(bot, member.guild, member, _ev)
            except Exception as e:
                logger.exception("[BOT_SETUP] TTS vc_notify error: %s", e)

        if member.guild is None or member.bot:
            return

        try:
            await handle_security_for_voice_join(bot, member, before, after)
        except Exception as e:
            logger.exception("[BOT_SETUP] VC security error: %s", e)

        # チャンネル参照を一度だけ取得（プロパティ再ルックアップによる None 化を防ぐ）
        before_ch = before.channel
        after_ch  = after.channel

        key      = (member.guild.id, member.id)
        now_ts   = time.time()
        is_join  = before_ch is None and after_ch is not None
        is_leave = before_ch is not None and after_ch is None
        is_move  = before_ch is not None and after_ch is not None and before_ch.id != after_ch.id

        if is_join:
            _vc_join_times[key] = now_ts
        duration_str = ""
        duration_seconds: int | None = None
        if is_leave:
            join_ts = _vc_join_times.pop(key, None)
            if join_ts is not None:
                duration_seconds = int(now_ts - join_ts)
                h, r = divmod(duration_seconds, 3600)
                m, s = divmod(r, 60)
                duration_str = f"{h:02d}:{m:02d}:{s:02d}"

        # VC 参加 / 退出 / 移動 をログチャンネルへ
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

        # VC 参加 / 退出 / 移動 を永続化
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

        # VC 通知チャンネルへ（リッチエンベッド）
        async def _vc_notify_handler() -> None:
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
                    target_ch = after_ch if is_join else before_ch
                    if target_ch and not target_ch.permissions_for(filter_role).view_channel:
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
                if now_ts - _vc_last_mention.get(gid, 0.0) >= 600:
                    content = f"<@&{role_id}>"
                    _vc_last_mention[gid] = now_ts

            await notify_ch.send(content=content, embed=embed)

        try:
            await _vc_notify_handler()
        except Exception as e:
            logger.exception("[BOT_SETUP] VC notify error: %s", e)

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
        except Exception as e:
            logger.exception("[BOT_SETUP] TTS auto_join error: %s", e)

        # TTS 自動退出: VCに人間が誰もいなくなったらBotも退出（temp override も解除）
        try:
            if (is_leave or is_move) and before_ch is not None:
                from services.tts_service import disconnect as _tts_disconnect, get_effective_vc_watch as _get_vc_watch
                from services.tts_store import get_tts_settings as _get_tts_settings
                _tts_cfg = _get_tts_settings(member.guild.id)
                _tts_vc_id, _ = _get_vc_watch(member.guild.id, _tts_cfg)
                if _tts_vc_id and int(_tts_vc_id) == before_ch.id:
                    non_bots = [m for m in before_ch.members if not m.bot]
                    if not non_bots:
                        await _tts_disconnect(member.guild.id)
        except Exception as e:
            logger.exception("[BOT_SETUP] TTS auto_leave error: %s", e)

    # --------------------------
    # メンバー参加・退出
    # --------------------------
    @bot.event
    async def on_member_join(member: discord.Member):
        joined_at = member.joined_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if member.joined_at else "(不明)"
        created_at = member.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if member.created_at else "(不明)"
        try:
            await log_action(
                bot,
                member.guild.id,
                "INFO",
                f"{member.mention} がサーバーに参加しました。",
                user=member,
                fields={
                    "ユーザーID": str(member.id),
                    "アカウント作成日": created_at,
                    "参加日時": joined_at,
                    "メンバー数": str(member.guild.member_count),
                },
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_join log_action error: %s", e)

        try:
            await record_user_state_event(
                guild_id=member.guild.id,
                user_id=member.id,
                event_type="member_join",
                status_after="active",
                user=member,
                in_guild=True,
                is_banned=False,
                timed_out_until=member.timed_out_until,
                payload={
                    "joined_at": member.joined_at.isoformat() if member.joined_at else None,
                    "account_created_at": member.created_at.isoformat() if member.created_at else None,
                    "member_count": int(member.guild.member_count or 0),
                },
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_join user_state persist error: %s", e)

        try:
            await send_welcome(member)
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_join welcome error: %s", e)

    @bot.event
    async def on_member_remove(member: discord.Member):
        roles = [r.mention for r in member.roles if not r.is_default()]
        event_type = "member_leave"
        status_after = "left"
        actor_user: discord.abc.User | None = None
        audit_reason: str | None = None

        try:
            kick_entry = await _find_recent_audit_entry(
                member.guild,
                action=discord.AuditLogAction.kick,
                target_user_id=member.id,
            )
            if kick_entry is not None:
                event_type = "member_kick"
                status_after = "kicked"
                actor_user = kick_entry.user
                audit_reason = kick_entry.reason
        except Exception as e:
            logger.debug("[BOT_SETUP] on_member_remove kick lookup failed: %s", e)

        try:
            await log_action(
                bot,
                member.guild.id,
                "INFO",
                f"{member.mention} がサーバーから退出しました。",
                user=member,
                fields={
                    "ユーザーID": str(member.id),
                    "保有ロール": " ".join(roles) if roles else "なし",
                    "メンバー数": str(member.guild.member_count),
                },
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_remove log_action error: %s", e)

        try:
            await record_user_state_event(
                guild_id=member.guild.id,
                user_id=member.id,
                event_type=event_type,
                status_after=status_after,
                user=member,
                actor=actor_user,
                reason=audit_reason,
                in_guild=False,
                is_banned=False,
                timed_out_until=member.timed_out_until,
                payload={
                    "member_count": int(member.guild.member_count or 0),
                    "roles": [
                        {"id": int(r.id), "name": str(r.name), "position": int(r.position)}
                        for r in member.roles
                        if not r.is_default()
                    ],
                },
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_remove user_state persist error: %s", e)

        try:
            await send_goodbye(member)
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_remove goodbye error: %s", e)

    # --------------------------
    # メンバー情報変更（ニックネーム・ロール・タイムアウト）
    # --------------------------
    @bot.event
    async def on_member_update(before: discord.Member, after: discord.Member):
        # ニックネーム変更
        if before.nick != after.nick:
            try:
                await log_action(
                    bot,
                    after.guild.id,
                    "INFO",
                    f"{after.mention} のニックネームが変更されました。",
                    user=after,
                    fields={
                        "旧": before.nick or "(なし)",
                        "新": after.nick or "(なし)",
                    },
                )
            except Exception as e:
                logger.exception("[BOT_SETUP] on_member_update nickname log_action error: %s", e)
            try:
                await record_user_state_event(
                    guild_id=after.guild.id,
                    user_id=after.id,
                    event_type="member_nickname_changed",
                    status_after="active",
                    user=after,
                    in_guild=True,
                    is_banned=False,
                    timed_out_until=after.timed_out_until,
                    payload={
                        "before_nickname": before.nick,
                        "after_nickname": after.nick,
                    },
                )
            except Exception as e:
                logger.exception("[BOT_SETUP] on_member_update nickname user_state persist error: %s", e)

        # ロール変更
        before_roles = set(r.id for r in before.roles if not r.is_default())
        after_roles = set(r.id for r in after.roles if not r.is_default())
        added_roles = [r for r in after.roles if r.id in (after_roles - before_roles)]
        removed_roles = [r for r in before.roles if r.id in (before_roles - after_roles)]

        if added_roles or removed_roles:
            fields = {}
            if added_roles:
                fields["追加されたロール"] = " ".join(r.mention for r in added_roles)
            if removed_roles:
                fields["削除されたロール"] = " ".join(r.mention for r in removed_roles)
            try:
                await log_action(
                    bot,
                    after.guild.id,
                    "INFO",
                    f"{after.mention} のロールが変更されました。",
                    user=after,
                    fields=fields,
                )
            except Exception as e:
                logger.exception("[BOT_SETUP] on_member_update role log_action error: %s", e)
            try:
                await record_user_state_event(
                    guild_id=after.guild.id,
                    user_id=after.id,
                    event_type="member_role_changed",
                    status_after="active",
                    user=after,
                    in_guild=True,
                    is_banned=False,
                    timed_out_until=after.timed_out_until,
                    payload={
                        "added_roles": [
                            {"id": int(r.id), "name": str(r.name), "position": int(r.position)}
                            for r in added_roles
                        ],
                        "removed_roles": [
                            {"id": int(r.id), "name": str(r.name), "position": int(r.position)}
                            for r in removed_roles
                        ],
                    },
                )
            except Exception as e:
                logger.exception("[BOT_SETUP] on_member_update role user_state persist error: %s", e)

        # タイムアウト
        before_timeout = before.timed_out_until
        after_timeout = after.timed_out_until
        if before_timeout != after_timeout:
            if after_timeout is not None:
                until_jst = after_timeout.astimezone(_JST).strftime("%Y/%m/%d %H:%M")
                try:
                    await log_action(
                        bot,
                        after.guild.id,
                        "ERROR",
                        f"{after.mention} がタイムアウトされました。",
                        user=after,
                        fields={"解除日時 (JST)": until_jst},
                        embed_color=discord.Color.orange(),
                    )
                except Exception as e:
                    logger.exception("[BOT_SETUP] on_member_update timeout log_action error: %s", e)
                try:
                    await record_user_state_event(
                        guild_id=after.guild.id,
                        user_id=after.id,
                        event_type="member_timeout_set",
                        status_after="active",
                        user=after,
                        in_guild=True,
                        is_banned=False,
                        timed_out_until=after_timeout,
                        payload={
                            "timed_out_until": after_timeout.isoformat(),
                        },
                    )
                except Exception as e:
                    logger.exception("[BOT_SETUP] on_member_update timeout user_state persist error: %s", e)
            else:
                try:
                    await log_action(
                        bot,
                        after.guild.id,
                        "INFO",
                        f"{after.mention} のタイムアウトが解除されました。",
                        user=after,
                    )
                except Exception as e:
                    logger.exception("[BOT_SETUP] on_member_update timeout_clear log_action error: %s", e)
                try:
                    await record_user_state_event(
                        guild_id=after.guild.id,
                        user_id=after.id,
                        event_type="member_timeout_cleared",
                        status_after="active",
                        user=after,
                        in_guild=True,
                        is_banned=False,
                        timed_out_until=None,
                        payload={},
                    )
                except Exception as e:
                    logger.exception("[BOT_SETUP] on_member_update timeout_clear user_state persist error: %s", e)

    # --------------------------
    # BAN / BAN 解除
    # --------------------------
    @bot.event
    async def on_member_ban(guild: discord.Guild, user: discord.User):
        actor_user: discord.abc.User | None = None
        audit_reason: str | None = None
        try:
            ban_entry = await _find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.ban,
                target_user_id=user.id,
            )
            if ban_entry is not None:
                actor_user = ban_entry.user
                audit_reason = ban_entry.reason
        except Exception as e:
            logger.debug("[BOT_SETUP] on_member_ban audit lookup failed: %s", e)

        try:
            await log_action(
                bot,
                guild.id,
                "ERROR",
                f"{user.mention} が BAN されました。",
                user=user,
                fields={
                    "ユーザーID": str(user.id),
                    "ユーザー名": str(user),
                },
                embed_color=discord.Color.red(),
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_ban log_action error: %s", e)

        try:
            await record_user_state_event(
                guild_id=guild.id,
                user_id=user.id,
                event_type="member_ban",
                status_after="banned",
                user=user,
                actor=actor_user,
                reason=audit_reason,
                in_guild=False,
                is_banned=True,
                payload={},
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_ban user_state persist error: %s", e)

    @bot.event
    async def on_member_unban(guild: discord.Guild, user: discord.User):
        actor_user: discord.abc.User | None = None
        audit_reason: str | None = None
        try:
            unban_entry = await _find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.unban,
                target_user_id=user.id,
            )
            if unban_entry is not None:
                actor_user = unban_entry.user
                audit_reason = unban_entry.reason
        except Exception as e:
            logger.debug("[BOT_SETUP] on_member_unban audit lookup failed: %s", e)

        try:
            await log_action(
                bot,
                guild.id,
                "INFO",
                f"{user.mention} の BAN が解除されました。",
                user=user,
                fields={
                    "ユーザーID": str(user.id),
                    "ユーザー名": str(user),
                },
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_unban log_action error: %s", e)

        try:
            await record_user_state_event(
                guild_id=guild.id,
                user_id=user.id,
                event_type="member_unban",
                status_after="unbanned",
                user=user,
                actor=actor_user,
                reason=audit_reason,
                in_guild=False,
                is_banned=False,
                payload={},
            )
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_unban user_state persist error: %s", e)

    # --------------------------
    # リアクションロール
    # --------------------------
    @bot.event
    async def on_raw_reaction_add(payload: discord.RawReactionActionEvent):
        try:
            await handle_reaction_add(bot, payload)
        except Exception as e:
            logger.exception("[BOT_SETUP] on_raw_reaction_add error: %s", e)

    @bot.event
    async def on_raw_reaction_remove(payload: discord.RawReactionActionEvent):
        try:
            await handle_reaction_remove(bot, payload)
        except Exception as e:
            logger.exception("[BOT_SETUP] on_raw_reaction_remove error: %s", e)
