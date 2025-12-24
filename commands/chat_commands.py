import discord

from services.chatgpt_service import ChatGPT
from services.discord_utils import send_large_message
from services.logging_service import log_action
from services.settings_store import get_response_channel_id

# ユーザー・ギルドごとのChatGPTインスタンス
user_chatgpt: dict[tuple[int, int], ChatGPT] = {}


async def handle_chatgpt_message(bot, message: discord.Message):
    """
    ChatGPT応答処理（セキュリティ・ログは bot_setup 側で実施）
    """

    # BOT自身は無視
    if message.author == bot.user:
        return

    if message.guild is None:
        return

    # 応答対象チャンネル取得
    target_channel_id = get_response_channel_id(message.guild.id)

    if target_channel_id == 0 or message.channel.id != target_channel_id:
        return

    key = (message.guild.id, message.author.id)

    # ChatGPTインスタンス生成
    if key not in user_chatgpt:
        user_chatgpt[key] = ChatGPT()

    # ログ：入力
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
        try:
            response = await user_chatgpt[key].input_message(message.content)
        except Exception as e:
            await log_action(
                bot,
                message.guild.id,
                "ERROR",
                "ChatGPT呼び出し失敗",
                user=message.author,
                fields={"エラー": str(e)},
            )
            await message.channel.send(f"ヴォルデモートでも手こずるとはな… {e}")
            return

        # ログ：出力（プレビュー）
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
