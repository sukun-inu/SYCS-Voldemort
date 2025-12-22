import discord
from services.chatgpt_service import ChatGPT
from services.discord_utils import send_large_message
from services.logging_service import log_action
from services.settings_store import get_response_channel_id
from services.security_service import handle_security_for_message


# ユーザーごとのChatGPTインスタンスを管理
user_chatgpt = {}


def register_message_handler(bot):
    """メッセージハンドラーを登録"""
    
    @bot.event
    async def on_message(message: discord.Message):
        """ユーザーメッセージを処理してChatGPTで応答 + 全メッセージをログ"""
        # ボット自身のメッセージは無視
        if message.author == bot.user:
            return

        # ギルド内の全メッセージをDEBUGレベルで記録
        if message.guild is not None:
            await log_action(
                bot,
                message.guild.id,
                "DEBUG",
                "メッセージ送信",
                user=message.author,
                fields={
                    "チャンネル": message.channel.mention,
                    "内容": message.content or "(内容なし)",
                },
            )

            # セキュリティチェック（レート + GPT判定）
            await handle_security_for_message(message, bot)

        # ChatGPT 応答対象チャンネルをギルド設定(JSON)から取得
        if message.guild is not None:
            target_channel_id = get_response_channel_id(message.guild.id)
        else:
            target_channel_id = 0

        # 応答チャンネルが未設定、または対象外なら終了
        if target_channel_id == 0 or message.channel.id != target_channel_id:
            return

        if message.guild is None:
            # ギルド外(DMなど)は今回は対象外
            return

        user_id = message.author.id
        
        # ユーザーごとのChatGPTインスタンスを作成
        if user_id not in user_chatgpt:
            user_chatgpt[user_id] = ChatGPT()
        
        # ログ: ユーザーからの入力
        await log_action(
            bot,
            message.guild.id,
            "INFO",
            "ChatGPT入力",
            user=message.author,
            fields={
                "チャンネル": message.channel.mention,
                "内容": message.content or "(内容なし)",
            },
        )

        async with message.channel.typing():
            response = await user_chatgpt[user_id].input_message(message.content)
            print("DEBUG: Final Response to send: " + response)

            # ログ: 返答内容（長すぎる場合は一部だけ）
            preview = response[:1800] + ("..." if len(response) > 1800 else "")
            await log_action(
                bot,
                message.guild.id,
                "DEBUG",
                "ChatGPT出力",
                user=message.author,
                fields={
                    "チャンネル": message.channel.mention,
                    "内容プレビュー": preview,
                },
            )

            await send_large_message(message.channel, response)
