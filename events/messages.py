"""on_message / on_message_delete / on_message_edit。

setup_events(bot) の巨大クロージャからそのまま切り出した。on_message は
「司令塔」で、各サービスへの振り分けを並列実行するだけの薄い作りを保っている。
"""

from __future__ import annotations

import asyncio
import logging

import discord
from commands.chat_commands import handle_chatgpt_message
from discord.ext.commands import Bot
from services.djaudio_service import handle_djaudio_message
from services.logging_service import log_action
from services.security_service import handle_security_for_message
from services.sticky_service import handle_sticky
from config import JST as _JST

from events._util import _safe

logger = logging.getLogger(__name__)


def register(bot: Bot) -> None:
    """on_message・on_message_delete・on_message_edit の3イベントを bot へ
    登録する。on_message は司令塔で、実処理は各サービス（security_service・
    chat_commands等）に委ねる薄い作り（モジュール docstring 参照）。
    """

    # --------------------------
    # メッセージ（司令塔）
    # --------------------------
    @bot.event
    async def on_message(message: discord.Message):
        """botのメッセージ全ての入口。botメッセージ・DM/グループ（guild無し）
        は早期returnで弾く。5つのハンドラをasyncio.gatherで並列実行し、
        それぞれ_safeで個別にくるむため、1つが例外を出しても他は止まらず
        （1つの遅い外部APIが他の応答を巻き込んで遅らせもしない）。最後の
        bot.process_commands(message)を呼び忘れると、通常のprefixコマンドが
        一切反応しなくなる。
        """
        if message.guild is None or message.author.bot:
            return
        # ローカルへ束ねる。下の _tts_handler は入れ子なので、この None 判定を
        # そのままでは持ち込めない（型検査が「まだ None かもしれない」と見る）。
        guild = message.guild

        logger.debug(
            "[BOT_SETUP] on_message guild=%s ch=%s author=%s",
            message.guild.id,
            message.channel.id,
            message.author,
        )

        async def _tts_handler() -> None:
            """on_messageから呼ばれる、TTS読み上げ専用の振り分け。ネストして
            いる理由は本文コメント参照（guildのNone判定を持ち込むため）。
            isinstance チェックは、webhook経由の投稿等 discord.Member でない
            authorを弾く（ユーザー個別の声設定はMemberのuser_idに紐づくため、
            Memberでないと引けない）。
            """
            from services.tts_service import enqueue_message as _tts_enqueue, get_effective_vc_watch as _get_vc_watch
            from services.tts_store import get_tts_settings as _get_tts_settings

            settings = _get_tts_settings(guild.id)
            effective_vc_id, watch_ids = _get_vc_watch(guild.id, settings)
            in_vc_text = effective_vc_id is not None and message.channel.id == effective_vc_id
            if (message.channel.id in watch_ids or in_vc_text) and isinstance(message.author, discord.Member):
                await _tts_enqueue(bot, guild, message.author, message.content)

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
        """メッセージ削除の監査ログ通知。message.author が無いケースへの
        対処を fields だけでなく本文（who の組み立て）にも用意する必要が
        ある理由は本文コメント参照——_safe の外側で AttributeError が出ると
        _safe には守られず、削除ログが出ないまま静かに消える。
        """
        if message.guild is None:
            return

        fields = {
            "送信日時": (
                message.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if message.created_at else "(不明)"
            ),
            "内容": (message.content or "(内容なし)")[:1024],
            "ユーザーID": str(message.author.id) if message.author else "不明",
            "メッセージID": str(message.id),
        }

        if message.attachments:
            attachment_urls = "\n".join(a.url for a in message.attachments)
            fields["添付ファイル"] = attachment_urls[:1024] + ("... (省略)" if len(attachment_urls) > 1024 else "")

        # author が無いときの逃げ道を、本文にも用意する。上の fields は既に
        # 「不明」へ倒しているのに、本文だけ無条件で .mention を読んでいた。
        #
        # しかもここは _safe() では守れない。_safe(coro, name) へ渡すコルーチンは
        # 引数を組み立ててから渡されるので、ここで AttributeError が出ると
        # _safe の中へ入る前に飛ぶ。削除ログが出ないうえ、握りつぶされもしない。
        who = message.author.mention if message.author else "(不明なユーザー)"

        await _safe(
            log_action(
                bot,
                message.guild.id,
                "INFO",
                f"{who} のメッセージが削除されました。",
                user=message.author,
                fields=fields,
            ),
            "on_message_delete log_action",
        )

    # --------------------------
    # メッセージ編集
    # --------------------------
    @bot.event
    async def on_message_edit(before: discord.Message, after: discord.Message):
        """本文が変わった編集だけを対象にする。on_message_editは埋め込み
        展開やピン留め等、本文以外の理由でも発火するため、content比較で
        除外しないと無関係な変化までログに出てしまう。
        """
        if before.guild is None:
            return
        if before.content == after.content:
            return

        # guild を確認済みなので、ここのチャンネルは必ずギルドのチャンネル。
        # 型の上では DM/グループも混ざった共用体のままで、その関係が表せない。
        ch_mention = before.channel.mention  # type: ignore[union-attr]

        await _safe(
            log_action(
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
            ),
            "on_message_edit log_action",
        )
