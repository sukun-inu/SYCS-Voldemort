import time

import discord

from services.chatgpt_service import ChatGPT
from services.discord_utils import send_large_message
from services.logging_service import log_action
from services.settings_store import get_response_channel_id

_CHATGPT_TTL_SECONDS = 3600

user_chatgpt: dict[tuple[int, int], ChatGPT] = {}
_user_last_used: dict[tuple[int, int], float] = {}
_cleanup_counter = 0
_CLEANUP_INTERVAL = 20


def _cleanup_stale_instances() -> None:
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter < _CLEANUP_INTERVAL:
        return
    _cleanup_counter = 0
    now = time.time()
    stale = [key for key, t in list(_user_last_used.items()) if now - t > _CHATGPT_TTL_SECONDS]
    for key in stale:
        user_chatgpt.pop(key, None)
        _user_last_used.pop(key, None)


async def handle_chatgpt_message(bot: discord.Client, message: discord.Message):
    if message.author == bot.user:
        return

    if message.guild is None:
        return

    target_channel_id = get_response_channel_id(message.guild.id)

    # 未設定(0)は「全チャンネル許可」。設定されている場合のみチャンネル一致を要求する。
    if target_channel_id > 0 and message.channel.id != target_channel_id:
        return

    key = (message.guild.id, message.author.id)

    if key not in user_chatgpt:
        user_chatgpt[key] = ChatGPT()

    _user_last_used[key] = time.time()
    _cleanup_stale_instances()

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
            await message.channel.send("ヴォルデモートでも手こずるとはな… 少し待ってから試せ。")
            return

        await send_large_message(message.channel, response)

    # typing コンテキスト外でログ出力（API呼び出しの競合を避ける）
    preview = response[:1800]
    await log_action(
        bot,
        message.guild.id,
        "DEBUG",
        "ChatGPT出力",
        user=message.author,
        fields={
            "チャンネル": message.channel.mention,
            "入力": (message.content or "(内容なし)")[:1024],
            "出力プレビュー": preview[:1024],
        },
    )
