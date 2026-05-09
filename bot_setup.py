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
from config import JST as _JST
from services.settings_store import get_vc_notify_channel_id, get_vc_notify_role_id
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

_SIGNAL_DIR = Path(os.getenv("SETTINGS_DIR", str(Path(__file__).parent / "data"))) / "_dev_signals"


def _is_public_vc(channel: discord.abc.GuildChannel | None) -> bool:
    """@everyone が view_channel を持つチャンネルを「公開」とみなす。"""
    if channel is None:
        return False
    return channel.permissions_for(channel.guild.default_role).view_channel


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
    _vc_join_times: dict[tuple[int, int], float] = {}  # (guild_id, user_id) → 入室時刻
    _vc_last_mention: dict[int, float] = {}            # guild_id → 最後にロールメンションを送った時刻

    # --------------------------
    # ステータス更新
    # --------------------------
    @tasks.loop(seconds=5)
    async def update_status():
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
                                    .replace("{username}", "テストユーザー#0000")
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
        nonlocal _ws_task
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

        # 各ハンドラーは互いに独立しているため並列実行（VT スキャンが DJAudio をブロックしない）
        await asyncio.gather(
            _safe(handle_security_for_message(bot, message), "security_service"),
            _safe(handle_chatgpt_message(bot, message), "chat_commands"),
            _safe(handle_sticky(message), "sticky"),
            _safe(handle_djaudio_message(bot, message), "djaudio"),
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
        if is_leave:
            join_ts = _vc_join_times.pop(key, None)
            if join_ts is not None:
                elapsed = int(now_ts - join_ts)
                h, r = divmod(elapsed, 3600)
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

        # VC 通知チャンネルへ（リッチエンベッド）
        try:
            if not (is_join or is_leave or is_move):
                return
            vc_notify_id = get_vc_notify_channel_id(member.guild.id)
            if not vc_notify_id:
                return
            notify_ch = member.guild.get_channel(vc_notify_id)
            if not isinstance(notify_ch, discord.TextChannel):
                return

            # 権限フィルタ: @everyone が view_channel を持たないチャンネルは通知しない
            before_pub = _is_public_vc(before_ch)
            after_pub  = _is_public_vc(after_ch)
            if is_join:
                if not after_pub:
                    return
                eff_action = "join"
            elif is_leave:
                if not before_pub:
                    return
                eff_action = "leave"
            else:  # is_move
                if before_pub and after_pub:
                    eff_action = "move"
                elif after_pub:
                    eff_action = "join"   # 非公開 → 公開: 参加として通知
                elif before_pub:
                    eff_action = "leave"  # 公開 → 非公開: 退出として通知
                else:
                    return  # 両方非公開: スキップ

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

            # ロールメンション: 同ギルドで直近 10 分以内に送信済みならスキップ
            content = None
            role_id = get_vc_notify_role_id(member.guild.id)
            if role_id:
                gid = member.guild.id
                if now_ts - _vc_last_mention.get(gid, 0.0) >= 600:
                    content = f"<@&{role_id}>"
                    _vc_last_mention[gid] = now_ts

            await notify_ch.send(content=content, embed=embed)
        except Exception as e:
            logger.exception("[BOT_SETUP] VC notify error: %s", e)

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
            await send_welcome(member)
        except Exception as e:
            logger.exception("[BOT_SETUP] on_member_join welcome error: %s", e)

    @bot.event
    async def on_member_remove(member: discord.Member):
        roles = [r.mention for r in member.roles if not r.is_default()]
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

    # --------------------------
    # BAN / BAN 解除
    # --------------------------
    @bot.event
    async def on_member_ban(guild: discord.Guild, user: discord.User):
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

    @bot.event
    async def on_member_unban(guild: discord.Guild, user: discord.User):
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
