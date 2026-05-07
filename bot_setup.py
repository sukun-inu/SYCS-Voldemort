import logging
from datetime import timezone, timedelta

import discord
import psutil
from commands.chat_commands import handle_chatgpt_message
from discord.ext import commands, tasks
from discord.ext.commands import Bot
from services.earthquake_service import run_earthquake_check
from services.logging_service import log_action
from services.news_service import run_news_feeds
from services.reaction_role_service import handle_reaction_add, handle_reaction_remove
from services.security_service import handle_security_for_message, handle_security_for_voice_join
from services.settings_store import get_vc_notify_channel_id
from services.sticky_service import handle_sticky
from services.welcome_service import send_goodbye, send_welcome

_JST = timezone(timedelta(hours=9))
logger = logging.getLogger(__name__)


def create_bot() -> Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    intents.voice_states = True
    intents.moderation = True
    intents.reactions = True
    return commands.Bot(command_prefix="!", intents=intents)


def setup_events(bot: Bot) -> None:

    # --------------------------
    # ステータス更新
    # --------------------------
    @tasks.loop(seconds=5)
    async def update_status():
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            latency = round(bot.latency * 1000)
            await bot.change_presence(
                activity=discord.Game(
                    name=f"Ping: {latency}ms | CPU: {cpu}% | MEM: {mem}%"
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
    # 地震アラート（1分ごと）
    # --------------------------
    @tasks.loop(minutes=1)
    async def earthquake_task():
        try:
            await run_earthquake_check(bot)
        except Exception as e:
            logger.exception("[BOT_SETUP] earthquake_task error: %s", e)

    @bot.event
    async def on_ready():
        logger.info("[BOT] Logged in as %s", bot.user)
        await bot.tree.sync()
        if not update_status.is_running():
            update_status.start()
        if not news_feed_task.is_running():
            news_feed_task.start()
        if not earthquake_task.is_running():
            earthquake_task.start()

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

        # ① セキュリティ（最優先）
        try:
            await handle_security_for_message(bot, message)
        except Exception as e:
            logger.exception("[BOT_SETUP] security_service error: %s", e)

        # ② ChatGPT
        try:
            await handle_chatgpt_message(bot, message)
        except Exception as e:
            logger.exception("[BOT_SETUP] chat_commands error: %s", e)

        # ③ スティッキーメッセージ
        try:
            await handle_sticky(message)
        except Exception as e:
            logger.exception("[BOT_SETUP] sticky error: %s", e)

        # ④ コマンド
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
            "内容": message.content or "(内容なし)",
            "ユーザーID": str(message.author.id) if message.author else "不明",
            "メッセージID": str(message.id),
        }

        if message.attachments:
            fields["添付ファイル"] = "\n".join(a.url for a in message.attachments)

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

        ch_mention = before.channel.mention if hasattr(before.channel, "mention") else str(before.channel)

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

        # VC 参加 / 退出 / 移動 をログチャンネルへ
        try:
            if before.channel is None and after.channel is not None:
                await log_action(
                    bot, member.guild.id, "INFO",
                    f"{member.mention} が VC に参加しました。",
                    user=member,
                    fields={"チャンネル": after.channel.mention},
                )
            elif before.channel is not None and after.channel is None:
                await log_action(
                    bot, member.guild.id, "INFO",
                    f"{member.mention} が VC から退出しました。",
                    user=member,
                    fields={"チャンネル": before.channel.mention},
                )
            elif (
                before.channel is not None
                and after.channel is not None
                and before.channel.id != after.channel.id
            ):
                await log_action(
                    bot, member.guild.id, "INFO",
                    f"{member.mention} が VC を移動しました。",
                    user=member,
                    fields={
                        "移動前": before.channel.mention,
                        "移動後": after.channel.mention,
                    },
                )
        except Exception as e:
            logger.exception("[BOT_SETUP] VC log_action error: %s", e)

        # VC 通知チャンネルへ（ユーザー向け通知）
        try:
            vc_notify_id = get_vc_notify_channel_id(member.guild.id)
            if vc_notify_id:
                notify_ch = member.guild.get_channel(vc_notify_id)
                if isinstance(notify_ch, discord.TextChannel):
                    if before.channel is None and after.channel is not None:
                        await notify_ch.send(
                            f"🎙️ {member.mention} が **{after.channel.name}** に参加しました。"
                        )
                    elif before.channel is not None and after.channel is None:
                        await notify_ch.send(
                            f"🚪 {member.mention} が **{before.channel.name}** から退出しました。"
                        )
                    elif (
                        before.channel is not None
                        and after.channel is not None
                        and before.channel.id != after.channel.id
                    ):
                        await notify_ch.send(
                            f"🔀 {member.mention} が **{before.channel.name}** → **{after.channel.name}** に移動しました。"
                        )
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
