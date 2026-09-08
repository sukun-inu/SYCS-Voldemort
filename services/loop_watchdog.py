"""イベントループが止まったとき、止めている場所を名指しでログへ残す。

■ なぜ要るか

「たまにえらく重い」は、**再現しないので静的解析では追えない。** 実際、
配信キャッシュの掃除が 60 秒ごとにループを 600ms 止めていた件は、async 関数の
本体を構文木で走査しても引っかからなかった（`for ... : path.open()` という
形で、`await` の付いていない呼び出しという分類に入らない）。定期実行の中身を
1つずつ読んで、ようやく見つかっている。

同じものが他にもある前提で、**次に起きたときは本番が自分で名乗る**ようにする。

■ どうやって測るか

イベントループの上で一定間隔に時刻を書くタスクと、別スレッドの見張りの2つ。
ループが止まれば時刻の更新も止まるので、見張りから見て「最後の更新から
warn_ms 以上経っている」＝止まっている、と分かる。

止まっていると分かったら `sys._current_frames()` でループのスレッドのスタックを
その場で取る。**これが肝で、「遅い」ではなく「どの行で止まっているか」が出る。**

■ なぜ asyncio のデバッグモードを使わないか

asyncio には `loop.slow_callback_duration` があるが、これは
`loop.set_debug(True)` のときしか効かない。デバッグモードは全てのコールバックを
計測用に包み、コルーチンの生成元も追跡するので、**常時入れておく前提の
仕組みではない。** こちらは「眠っているスレッド1本 + 100ms ごとの時刻書き込み」
だけで、止まっていないときの費用がほぼ無い。

■ 止まっていることを、止まっているループからは報せられない

報告を見張りスレッド側から出しているのはそのため。ループ上のタスクから
出そうとしても、そのタスク自体が動けない。ログの書き込みは同期なので、
見張りスレッドからそのまま呼べる。
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import traceback

from envutil import env_int

logger = logging.getLogger(__name__)

# 既定のしきい値。500ms 止まると、Discord の音声は聞いて分かるほど途切れる。
DEFAULT_WARN_MS = 500

# 見張りの間隔。細かくするほど停止の検知は早いが、そのぶん起きる回数が増える。
# 100ms なら、報告する停止時間の誤差も 100ms 程度に収まる。
DEFAULT_CHECK_MS = 100

# 残すスタックの行数。深い側（＝実際に動いていた場所）から数える。
# 全部残すと discord.py と asyncio の内部で 100 行を超え、ログが読めなくなる。
_MAX_STACK_LINES = 24

# ループが最後に息をした時刻（time.monotonic）。見張りスレッドと共有する。
# float の読み書きは GIL の下で分割されないので、ロックは要らない。
_beat_at = 0.0

# ループが回っているスレッドの ID。スタックを取る相手を決めるのに使う。
_loop_thread_id: int | None = None

# 見張っているループそのもの。**閉じたかどうかを見るために持つ。**
# 心拍はループが止まれば当然止まるので、見張りからは「延々と停止している」
# ように見える。閉じたループを相手に警告を出し続けても意味が無い。
_loop: asyncio.AbstractEventLoop | None = None

# 二重に仕掛けないための印。uvicorn の reload やテストでの再 import で
# 見張りスレッドが増えていくのを防ぐ。
_installed = False

# いま動いている見張りを畳むための合図。**install のたびに作り直す。**
# time.sleep ではなく Event.wait で待つのは、止めたいときに最大 check_ms
# 待たされないため。
#
# 使い回しの Event を1つ置いて clear() するやり方にしてはいけない。
# shutdown() 直後に install() すると、**まだ止まりきっていない古いスレッドが
# clear() で生き返る。** 生き返った側は前のループの古い _beat_at を見るので、
# 止まってもいないのに「延々と停止している」と報告し続ける。
# uvicorn の reload で実際に踏む形で、テストが先に捕まえた。
_stop: threading.Event | None = None

# 心拍のタスク。畳むときに cancel する。
_heartbeat_task: asyncio.Task | None = None


async def _heartbeat(interval_sec: float) -> None:
    """イベントループの上で、一定間隔に時刻を書き続ける。

    ここが遅れること自体が「ループが詰まっている」ことの証拠になる。
    書く以外のことをしない——重い処理を足すと、**測る側が原因になる。**
    """
    global _beat_at
    while True:
        _beat_at = time.monotonic()
        await asyncio.sleep(interval_sec)


def _loop_stack() -> str:
    """イベントループのスレッドが、いまどこを実行しているかを文字列で返す。

    取れなかった場合（スレッドが既に終わっている等）は、その旨を返す。
    **ここで例外を出すと見張りごと死ぬ**ので、握って文字列にする。
    """
    if _loop_thread_id is None:
        return "（ループのスレッドが分かりません）"
    frame = sys._current_frames().get(_loop_thread_id)
    if frame is None:
        return "（ループのスレッドのスタックを取れませんでした）"
    try:
        lines = traceback.format_stack(frame)
    except Exception as exc:  # pragma: no cover - スタック取得はまず失敗しない
        return f"（スタックを整形できませんでした: {exc}）"
    # 末尾＝いちばん深いところ。手前は asyncio と discord.py の内部が並ぶだけ。
    return "".join(lines[-_MAX_STACK_LINES:]).rstrip()


def _watch(stop: threading.Event, warn_sec: float, check_sec: float) -> None:
    """別スレッドで、ループの遅れを見張り続ける。

    同じ停止について何度も書かないよう、報告済みの心拍を覚えておく。
    100ms ごとに気づくたび書くと、**1回の停止で数十行が並んで、本当に
    知りたい最初の1行が埋もれる。**

    stop はこのスレッド専用の Event を受け取る。モジュール変数を直に見ると、
    次の install が作った新しい Event を見てしまい、畳んだはずのスレッドが
    動き続ける。
    """
    reported_beat: float | None = None
    while not stop.wait(check_sec):
        loop = _loop
        if loop is None or loop.is_closed():
            return  # ループごと畳まれた。停止ではないので黙って降りる
        beat = _beat_at
        if beat == 0.0:
            continue  # 心拍がまだ始まっていない
        late = time.monotonic() - beat
        if late < warn_sec:
            if reported_beat is not None:
                # 直前まで止まっていたものが解けた。実際に何 ms 止まって
                # いたかは、解けたこの時点でしか分からない。
                logger.warning(
                    "[stall] イベントループの停止が解けました（約 %.0f ms）",
                    (beat - reported_beat) * 1000,
                    extra={"stall_ms": round((beat - reported_beat) * 1000)},
                )
                reported_beat = None
            continue
        if reported_beat is not None:
            continue  # この停止についてはもう書いた
        reported_beat = beat
        logger.warning(
            "[stall] イベントループが %.0f ms 止まっています。止めている場所:\n%s",
            late * 1000,
            _loop_stack(),
            extra={"stall_ms": round(late * 1000)},
        )


def install() -> bool:
    """見張りを仕掛ける。**実行中のイベントループの中から呼ぶこと。**

    戻り値は実際に仕掛けたかどうか。既に仕掛かっている・環境変数で切られて
    いる場合は False を返す（呼び出し側がログに出せるようにしてある）。

    `LOOP_STALL_WARN_MS` に 0 を渡すと切れる。切る口を用意してあるのは、
    停止が常態化している環境で**警告がログを埋め尽くす**ことがありうるため。
    そのときに直すべきは停止の方だが、直すまでのあいだログを読めなくして
    しまうと、直すための情報まで失う。
    """
    global _installed, _loop_thread_id, _beat_at, _heartbeat_task, _stop, _loop

    if _installed:
        return False

    warn_ms = env_int("LOOP_STALL_WARN_MS", DEFAULT_WARN_MS, minimum=0)
    if warn_ms <= 0:
        logger.info("[stall] LOOP_STALL_WARN_MS=0 のため、イベントループの見張りを入れません")
        return False
    # 見張りの間隔がしきい値より粗いと、検知が最大その間隔ぶん遅れる。
    check_ms = min(env_int("LOOP_STALL_CHECK_MS", DEFAULT_CHECK_MS, minimum=10), warn_ms)

    _loop = asyncio.get_running_loop()
    _loop_thread_id = threading.get_ident()
    _beat_at = time.monotonic()
    _stop = threading.Event()
    # 心拍は見張りの間隔と揃える。粗くすると、止まっていないのに
    # 「最後の更新から時間が経っている」と誤検知する。
    _heartbeat_task = _loop.create_task(_heartbeat(check_ms / 1000))
    threading.Thread(
        target=_watch,
        args=(_stop, warn_ms / 1000, check_ms / 1000),
        name="loop-watchdog",
        daemon=True,  # 本体が終わるときに道連れにしない
    ).start()
    _installed = True
    logger.info("[stall] イベントループの見張りを開始しました（%d ms 以上の停止を残します）", warn_ms)
    return True


def shutdown() -> None:
    """見張りを畳む。

    daemon スレッドなのでプロセス終了時には放っておいても消えるが、
    **同じプロセスで何度も起動・停止する場合**（テスト、uvicorn の reload）に
    見張りが積み上がる。畳む口を用意しておく。

    実行中のループの中から呼ぶ必要は無い（心拍タスクは cancel するだけ）。
    """
    global _installed, _heartbeat_task, _stop, _beat_at, _loop
    if _stop is not None:
        _stop.set()
        _stop = None
    if _heartbeat_task is not None:
        _heartbeat_task.cancel()
        _heartbeat_task = None
    # 心拍を伏せる。残したままにすると、次に仕掛けるまでの隙間で
    # 「最後の更新から何秒も経っている」と読める状態が残る。
    _beat_at = 0.0
    _loop = None
    _installed = False
