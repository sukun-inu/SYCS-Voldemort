
import discord
from discord.ext import commands, tasks
from discord.ext.commands import Bot
import psutil
from datetime import timezone, timedelta
from services.logging_service import log_action

# 日本標準時タイムゾーン
_JST = timezone(timedelta(hours=9))

def create_bot() -> Bot:
    """Discordボットを初期化して返す"""
    intents = discord.Intents.default()
    # メッセージ内容、ボイス状態、メンバーなどサーバーアクティビティを拾うためのインテント
    intents.message_content = True
    intents.members = True
    intents.voice_states = True
    bot = commands.Bot(command_prefix="!", intents=intents)
    return bot


def setup_events(bot: Bot) -> None:
    """ボットイベントを設定"""
    
    @tasks.loop(seconds=5)
    async def update_status():
        """ボットのステータスを定期的に更新"""
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
        """ボット起動時のイベント"""
        print(f'Logged in as {bot.user}')
        try:
            await bot.tree.sync()
            print("グローバルコマンドが同期されました。")
            if not update_status.is_running():
                update_status.start()
        except Exception as e:
            print(f"同期中のエラー: {e}")

    @bot.event
    async def on_message_delete(message: discord.Message):
        """メッセージ削除ログ（詳細日本語）"""
        if message.guild is None:
            return
        content = message.content or "(内容なし / キャッシュ外)"
        attachment_info = "なし"
        if message.attachments:
            urls = "\n".join(a.url for a in message.attachments)
            attachment_info = urls

        # deleterの特定（監査ログAPIは未使用、基本は不明）
        deleter = None  # ここでは取得不可
        author_mention = message.author.mention if message.author else "(不明)"
        channel_mention = message.channel.mention if hasattr(message.channel, 'mention') else str(message.channel)
        sent_at = message.created_at.astimezone(_JST).strftime("%Y年%m月%d日 %H:%M") if message.created_at else "(不明)"
        msg_id = str(message.id)
        user_id = str(message.author.id) if message.author else "(不明)"

        log_msg = f"{author_mention} のメッセージが {channel_mention} で削除されました。\n"
        log_msg += f"送信日時: {sent_at}\n"
        log_msg += f"内容: {content}\n"
        log_msg += f"ユーザーID: {user_id} | メッセージID: {msg_id}"
        if attachment_info != "なし":
            log_msg += f"\n添付ファイル: {attachment_info}"

        await log_action(
            bot,
            message.guild.id,
            "INFO",
            log_msg,
            user=message.author,
        )

    @bot.event
    async def on_message_edit(before: discord.Message, after: discord.Message):
        """メッセージ編集ログ（詳細日本語）"""
        if before.guild is None:
            return
        before_content = before.content or "(内容なし / キャッシュ外)"
        after_content = after.content or "(内容なし)"
        author_mention = before.author.mention if before.author else "(不明)"
        channel_mention = before.channel.mention if hasattr(before.channel, 'mention') else str(before.channel)
        sent_at = before.created_at.astimezone(_JST).strftime("%Y年%m月%d日 %H:%M") if before.created_at else "(不明)"
        msg_id = str(before.id)
        user_id = str(before.author.id) if before.author else "(不明)"

        log_msg = f"{author_mention} のメッセージが {channel_mention} で編集されました。\n"
        log_msg += f"送信日時: {sent_at}\n"
        log_msg += f"編集前: {before_content}\n"
        log_msg += f"編集後: {after_content}\n"
        log_msg += f"ユーザーID: {user_id} | メッセージID: {msg_id}"

        await log_action(
            bot,
            before.guild.id,
            "INFO",
            log_msg,
            user=before.author,
        )

    @bot.event
    async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        """ボイスチャンネル参加/退出/移動などのログ + セキュリティチェック"""
        guild = member.guild
        if guild is None:
            return

        # セキュリティチェック（VCレイド検知）
        from services.security_service import handle_security_for_voice_join  # 遅延インポートで循環回避

        await handle_security_for_voice_join(member, before, after, bot)

        before_ch = before.channel
        after_ch = after.channel

        description = None
        fields = {}
        if before_ch is None and after_ch is not None:
            description = "ボイスチャンネル参加"
            fields["参加チャンネル"] = after_ch.name
        elif before_ch is not None and after_ch is None:
            description = "ボイスチャンネル退出"
            fields["退出チャンネル"] = before_ch.name
        elif before_ch is not None and after_ch is not None and before_ch.id != after_ch.id:
            description = "ボイスチャンネル移動"
            fields["移動元"] = before_ch.name
            fields["移動先"] = after_ch.name
        else:
            # チャンネル自体は変わっていない場合は、ミュート/デフンなどの変化だけ拾う（DEBUG レベル）
            changes = []
            if before.self_mute != after.self_mute:
                changes.append(f"self_mute: {before.self_mute} -> {after.self_mute}")
            if before.self_deaf != after.self_deaf:
                changes.append(f"self_deaf: {before.self_deaf} -> {after.self_deaf}")
            if before.mute != after.mute:
                changes.append(f"server_mute: {before.mute} -> {after.mute}")
            if before.deaf != after.deaf:
                changes.append(f"server_deaf: {before.deaf} -> {after.deaf}")

            if not changes:
                return

            await log_action(
                bot,
                guild.id,
                "DEBUG",
                "ボイス状態更新",
                user=member,
                fields={"変更内容": "\n".join(changes), "チャンネル": before_ch.name if before_ch else "None"},
            )
            return

        if description:
            await log_action(
                bot,
                guild.id,
                "INFO",
                description,
                user=member,
                fields=fields,
            )

    @bot.event
    async def on_member_join(member: discord.Member):
        """メンバー参加ログ（詳細日本語）"""
        joined_at = member.joined_at.astimezone(_JST).strftime("%Y年%m月%d日 %H:%M") if member.joined_at else "(不明)"
        log_msg = f"{member.mention} がサーバーに参加しました。\n参加日時: {joined_at}\nユーザーID: {member.id}"
        await log_action(
            bot,
            member.guild.id,
            "INFO",
            log_msg,
            user=member,
        )

    @bot.event
    async def on_member_remove(member: discord.Member):
        """メンバー退出ログ（詳細日本語）"""
        log_msg = f"{member.mention} がサーバーから退出しました。\nユーザーID: {member.id}"
        await log_action(
            bot,
            member.guild.id,
            "INFO",
            log_msg,
            user=member,
        )

    @bot.event
    async def on_member_update(before: discord.Member, after: discord.Member):
        """ロール変更やニックネーム変更などのログ（詳細日本語）"""
        guild = after.guild
        if guild is None:
            return

        changes = []
        # ニックネーム変更
        if before.nick != after.nick:
            changes.append(f"ニックネーム: {before.nick} → {after.nick}")

        # ロール変更
        before_roles = set(r for r in before.roles if r.name != "@everyone")
        after_roles = set(r for r in after.roles if r.name != "@everyone")
        added = after_roles - before_roles
        removed = before_roles - after_roles

        if added:
            changes.append("付与されたロール: " + ", ".join(r.name for r in added))
        if removed:
            changes.append("剥奪されたロール: " + ", ".join(r.name for r in removed))

        if not changes:
            return

        log_msg = f"{after.mention} のメンバー情報が更新されました。\n" + "\n".join(changes) + f"\nユーザーID: {after.id}"
        await log_action(
            bot,
            guild.id,
            "INFO",
            log_msg,
            user=after,
        )

    @bot.event
    async def on_guild_channel_create(channel: discord.abc.GuildChannel):
        """チャンネル作成ログ"""
        guild = channel.guild
        await log_action(
            bot,
            guild.id,
            "INFO",
            "チャンネル作成",
            fields={
                "チャンネル": getattr(channel, "mention", channel.name),
                "種別": str(getattr(channel, "type", "unknown")),
            },
        )

    @bot.event
    async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
        """チャンネル削除ログ"""
        guild = channel.guild
        await log_action(
            bot,
            guild.id,
            "INFO",
            "チャンネル削除",
            fields={
                "チャンネル名": channel.name,
                "種別": str(getattr(channel, "type", "unknown")),
            },
        )
