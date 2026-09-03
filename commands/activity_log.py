"""打たれたスラッシュコマンドを、プロセスのログへ1行ずつ残す。

■ なぜ要るか

`commands/` には172個の関数があるのに、ログを出しているのは**4箇所**
だけだった。つまり **/record start も /log channel も /tts join も、打たれた
事実がプロセスのログに1行も残らない。** 「さっき誰かが何かした直後から
おかしい」という報告に対して、bot.log を見ても手がかりが無かった。

一部のコマンドは `log_action()` で Discord の監査チャンネルへ流している
が、あれは**設定したギルドにしか出ない**うえ、Discord 側に消される。
プロセスのログとは別物である。

■ どう入れるか

コマンドごとに書き足すのではなく、**入口で1箇所**にする。172個へ1行ずつ
足す方式は、次に足すコマンドで必ず忘れる。discord.py が全コマンドの前後で
投げる2つのイベントに乗る。

    on_interaction            打たれた瞬間（開始時刻を控える）
    on_app_command_completion 成功して返ったとき
    tree.on_error             失敗したとき（commands/interaction_utils.py）

`bot.add_listener` を使うのは、`@bot.event` だと**同じ名前の既存ハンドラを
置き換えてしまう**ため。listener は何本でも並べられる。

■ 何を書き、何を書かないか

書くのは「誰が・どのコマンドを・どのギルドで・何ミリ秒で・成功したか」。
**引数の中身は書かない。** 読み上げの辞書やチャットの本文がそのまま
10年分ディスクに残ることになるため（保管期間は services/log_setup.py）。
値まで要る操作は、これまでどおり `log_action()` で監査チャンネルへ出す。
"""

from __future__ import annotations

import logging
import time

import discord
from discord.ext.commands import Bot

from services.ttl_cache import TTLCache

logger = logging.getLogger(__name__)

# interaction.id → 打たれた時刻。応答期限は15分なので、それを超えたものは
# もう完了イベントが来ない。放っておくと増え続けるので期限付きで持つ。
_STARTED: TTLCache[int, float] = TTLCache(ttl=16 * 60, max_entries=4096)


def mark_started(interaction: discord.Interaction) -> None:
    """コマンドが打たれた時刻を控える。所要時間を出すためだけに使う。"""
    _STARTED.set(interaction.id, time.monotonic())


def elapsed_ms(interaction: discord.Interaction) -> int:
    """打たれてから何ミリ秒か。控えが無ければ 0。

    控えが無いのは、Bot の再起動をまたいだ場合と、期限を過ぎた場合。
    どちらも「測れなかった」であって異常ではないので、0 を返して
    ログ自体は出す。
    """
    started = _STARTED.pop(interaction.id)
    return 0 if started is None else int((time.monotonic() - started) * 1000)


def describe(interaction: discord.Interaction) -> str:
    """誰が・どこで打ったか。ログの見出しに使う。

    ギルド外（DM）では guild が None になる。そのまま `guild=None` と
    書くより、`guild=DM` のほうが読んだときに迷わない。
    """
    user = interaction.user
    guild = interaction.guild
    return (
        f"guild={guild.id if guild else 'DM'} "
        f"user={getattr(user, 'display_name', user)}({user.id}) "
        f"ch={interaction.channel_id}"
    )


def install_command_activity_logging(bot: Bot) -> None:
    """全スラッシュコマンドの実行を記録する listener を2本足す。

    main.py から起動時に1回だけ呼ぶ想定。失敗した場合のログは
    tree.on_error 側（commands/interaction_utils.py）にある。
    """

    async def _on_interaction(interaction: discord.Interaction) -> None:
        """打たれた時刻を控える。ボタンやモーダルは対象外。"""
        if interaction.type is discord.InteractionType.application_command:
            mark_started(interaction)

    async def _on_completion(interaction: discord.Interaction, command) -> None:
        """成功して返ったコマンドを1行残す。引数の中身は書かない。"""
        logger.info(
            "[CMD] /%s %s ok %dms",
            getattr(command, "qualified_name", command),
            describe(interaction),
            elapsed_ms(interaction),
        )

    bot.add_listener(_on_interaction, "on_interaction")
    bot.add_listener(_on_completion, "on_app_command_completion")
