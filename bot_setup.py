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

    bot = commands.Bot(command_prefix="!", intents=intents)
    return bot


def setup_events(bot: Bot) -> None:

    # --------------------------
    # ステータス更新
    # --------------------------
    @tasks.loop(seconds=5)
    async def update_status():
        try:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            latency = round(bot.latency * 1000)
            status = f'Ping: {latency}ms | CPU: {cpu_percent}% | MEM: {memory_percent}%'
            await bot.change_presence(activity=discord.Game(name=status))
        except Exception as e:
            print(f"ステータス更新エラー: {e}")

    @bot.event
    async def on_ready():
        print(f'Logged in as {bot.user}')
        try:
            await bot.tree.sync()
            print("グローバルコマンド同期完了")
            if not update_status.is_running():
                update_status.start()
        except Exception as e:
            print(f"起動時エラー: {e}")

    # --------------------------
    # メッセージ監査 + セキュリティ
    # --------------------------
    @bot.event
    async def on_message(message: discord.Message):
        if message.guild is None:
            return
        if message.author.bot:
            return

        # === セキュリティ最優先 ===
        from services.security_service import handle_security_for_message
        await handle_security_for_message(message, bot)

        # === コマンド処理 ===
        await bot.process_commands(message)

    # --------------------------
    # メッセージ削除
    # --------------------------
    @bot.event
    async def on_message_delete(message: discord.Message):
        if message.guild is None:
            return

        content = message.content or "(内容なし / キャッシュ外)"
        author = message.author.mention if message.author else "(不明)"
        channel = message.channel.mention if hasattr(message.channel, "mention") else str(message.channel)
        sent_at = message.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if message.created_at else "(不明)"

        fields = {
            "送信日時": sent_at,
            "内容": content,
            "ユーザーID": str(message.author.id) if message.author else "不明",
            "メッセージID": str(message.id),
        }

        if message.attachments:
            fields["添付ファイル"] = "\n".join(a.url for a in message.attachments)

        await log_action(
            bot,
            message.guild.id,
            "INFO",
            f"{author} のメッセージが {channel} で削除されました。",
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
    # VC セキュリティ & ログ
    # --------------------------
    @bot.event
    async def on_voice_state_update(member, before, after):
        if member.guild is None:
            return

        from services.security_service import handle_security_for_voice_join
        await handle_security_for_voice_join(member, before, after, bot)

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
    # ロール・ニックネ変更
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
                fields={"旧": before.nick, "新": after.nick},
            )
