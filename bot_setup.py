import discord
from discord.ext import commands, tasks
from discord.ext.commands import Bot
import psutil
from datetime import timezone, timedelta
from services.logging_service import log_action

# 日本標準時
_JST = timezone(timedelta(hours=9))


def create_bot() -> Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    intents.voice_states = True
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
            print(f"ステータス更新エラー: {e}")

    @bot.event
    async def on_ready():
        print(f"Logged in as {bot.user}")
        await bot.tree.sync()
        if not update_status.is_running():
            update_status.start()

    # --------------------------
    # メッセージ（司令塔）
    # --------------------------
    @bot.event
    async def on_message(message: discord.Message):
        if message.guild is None or message.author.bot:
            return

        # on_message が確実に動いているかの簡易ログ
        try:
            print(f"[BOT_SETUP] on_message triggered guild={message.guild.id} ch={message.channel.id} author={message.author}")
        except Exception:
            pass

        # ① セキュリティ（最優先）
        from services.security_service import handle_security_for_message
        try:
            await handle_security_for_message(bot, message)
        except Exception as e:
            print(f"[BOT_SETUP] handle_security_for_message error: {e}")
            import traceback
            traceback.print_exc()

        # ② ChatGPT
        from commands.chat_commands import handle_chatgpt_message
        try:
            await handle_chatgpt_message(bot, message)
        except Exception as e:
            print(f"[BOT_SETUP] handle_chatgpt_message error: {e}")
            import traceback
            traceback.print_exc()

        # ③ コマンド
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

        await log_action(
            bot,
            message.guild.id,
            "INFO",
            f"{message.author.mention} のメッセージが削除されました。",
            user=message.author,
            fields=fields,
        )

    # --------------------------
    # メッセージ編集
    # --------------------------
    @bot.event
    async def on_message_edit(before: discord.Message, after: discord.Message):
        if before.guild is None:
            return

        await log_action(
            bot,
            before.guild.id,
            "INFO",
            f"{before.author.mention} のメッセージが編集されました。",
            user=before.author,
            fields={
                "編集前": before.content or "(なし)",
                "編集後": after.content or "(なし)",
                "ユーザーID": str(before.author.id),
                "メッセージID": str(before.id),
            },
        )

    # --------------------------
    # VC セキュリティ
    # --------------------------
    @bot.event
    async def on_voice_state_update(member, before, after):
        if member.guild is None:
            return

        from services.security_service import handle_security_for_voice_join
        await handle_security_for_voice_join(bot, member, before, after)

    # --------------------------
    # メンバー参加・退出
    # --------------------------
    @bot.event
    async def on_member_join(member: discord.Member):
        await log_action(
            bot,
            member.guild.id,
            "INFO",
            f"{member.mention} がサーバーに参加しました。",
            user=member,
        )

    @bot.event
    async def on_member_remove(member: discord.Member):
        await log_action(
            bot,
            member.guild.id,
            "INFO",
            f"{member.mention} がサーバーから退出しました。",
            user=member,
        )

    # --------------------------
    # ニックネーム変更
    # --------------------------
    @bot.event
    async def on_member_update(before: discord.Member, after: discord.Member):
        if before.nick != after.nick:
            await log_action(
                bot,
                after.guild.id,
                "INFO",
                f"{after.mention} のニックネームが変更されました。",
                user=after,
                fields={"旧": before.nick or "(なし)", "新": after.nick or "(なし)"},
            )
