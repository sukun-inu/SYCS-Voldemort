import time
from typing import cast

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
    """呼ばれるたびにではなく、_CLEANUP_INTERVAL 回に1回だけ走査する。

    毎メッセージで dict 全体を舐めるのは無駄なので間引く。カウンタは
    ギルド・ユーザーをまたいだ共通の1本なので、間引きの周期はチャット全体の
    トラフィックで決まる。会話が少ないサーバーだけを見ても、他のサーバーの
    メッセージでカウンタが進んでいれば掃除は走る。
    """
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
    """on_message から呼ばれる、ChatGPT応答チャンネル専用の処理。

    target_channel_id が 0 は「未設定」を表す番兵で、0 のギルドは何も
    しない（未設定を「チャンネルID 0」と誤解して反応してしまう事故を防ぐ）。
    typing() をコンテキストマネージャで使うと5秒ごとに再送されてRate
    Limit(429)に当たるため、ここでは1回だけ直接HTTPを叩いている。
    """
    if message.author == bot.user:
        return

    if message.guild is None:
        return

    target_channel_id = get_response_channel_id(message.guild.id)

    # 未設定(0)は無効。設定されたチャンネルでのみ応答する。
    if target_channel_id <= 0 or message.channel.id != target_channel_id:
        return

    # /chat set で選べるのは TextChannel のみなので、target_channel_id に一致した
    # ここでの message.channel は実行時には必ず TextChannel。
    channel = cast(discord.TextChannel, message.channel)

    key = (message.guild.id, message.author.id)

    if key not in user_chatgpt:
        user_chatgpt[key] = ChatGPT()

    _user_last_used[key] = time.time()
    _cleanup_stale_instances()

    # typing()コンテキストは5秒ごとに再送して429になるため、1回だけ直接送る
    try:
        await message.channel._state.http.send_typing(message.channel.id)
    except discord.HTTPException:
        pass

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

    await send_large_message(channel, response)

    preview = response[:1800]
    await log_action(
        bot,
        message.guild.id,
        "DEBUG",
        "ChatGPT出力",
        user=message.author,
        fields={
            "チャンネル": channel.mention,
            "入力": (message.content or "(内容なし)")[:1024],
            "出力プレビュー": preview[:1024],
        },
    )
