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

■ スタックにアプリの行が1つも出ない停止がある

本番で 1016ms 止まったとき、いちばん深いところが asyncio の TLS 読み出し
（sslproto の `_do_read`）で、**アプリのフレームが1行も無かった。** ループを
埋めていたのがこちらのコードではなく「届いた暗号文の復号」だったため。
行番号を眺めても直しようがない。

こういう停止で要るのは「どの接続か」なので、内部フレームの局所変数から
相手を引き出して `相手:` の行を足す（SNI のホスト名・peername・上に載って
いるプロトコル・受信済みのバイト数）。名前解決は挟まない。

同じ理由で、**1回の停止でスタックを1本しか取らないのをやめた。** 短い
コールバックが切れ目なく続いてループが空かない形では、1本はくじ引きに
しかならない。ただし気づくたびに書くとログが埋まるので、場所が変わった
ときだけ書き足す（同じところで止まり続けているなら1行のまま）。

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

# 1回の停止で残すスタックの本数。
#
# **1本では足りない停止がある。** 本番で 1016ms 止まったとき、いちばん深い
# ところが asyncio の TLS 読み出し（sslproto の _do_read）で、アプリの
# フレームが1行も出なかった。この形は「1つの呼び出しが長い」のではなく
# 「短いコールバックが切れ目なく続いてループが空かない」ことが多く、
# そのとき1本のスタックはくじ引きにしかならない。
#
# かといって気づくたびに書くとログが埋まるので、**場所が変わったときだけ**
# 書き足す。同じところで止まり続けている（time.sleep など）なら1行のまま。
_MAX_SAMPLES = 3

# スタックを取りに行く回数の上限。書くのは上の本数までだが、「場所が
# 変わったか」を見るには取る必要がある。長い停止で延々と取り続けない蓋。
_MAX_SAMPLE_TRIES = 60

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


def _peername(obj: object) -> str:
    """transport から相手のアドレスを取り出す。取れなければ空文字。"""
    getter = getattr(obj, "get_extra_info", None)
    if getter is None:
        return ""
    try:
        peer = getter("peername")
    except Exception:
        return ""
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer) if peer else ""


def _buffered_bytes(protocol: object) -> str:
    """受け取り中の本文の大きさ。**「大きな取得が犯人か」を分ける手掛かり。**

    aiohttp の ResponseHandler は読みかけの本文を StreamReader に持っていて、
    そこまでに流し込まれた総量が分かる。他のプロトコルでは取れないので空。
    """
    total = getattr(getattr(protocol, "_payload", None), "total_bytes", None)
    if isinstance(total, int) and total > 0:
        return f"受信 {total / 1024:.0f} KB"
    return ""


def _describe_endpoint(obj: object) -> str:
    """asyncio の transport / SSLProtocol なら、通信の相手を1行で名乗らせる。

    見るのは SNI のホスト名（名前解決を挟まずに相手が分かる）、peername、
    上に載っているプロトコルの型名、受信済みのバイト数。
    それ以外のオブジェクトなら空文字を返す（呼び出し側が次のフレームへ進む）。
    """
    sslobj = getattr(obj, "_sslobj", None)  # asyncio の SSLProtocol
    if sslobj is None and getattr(obj, "_sock", None) is None:
        return ""

    bits: list[str] = []
    host = getattr(sslobj, "server_hostname", None)
    if host:
        bits.append(str(host))

    peer = _peername(obj) or _peername(getattr(obj, "_transport", None))
    if peer:
        bits.append(peer)

    protocol = getattr(obj, "_app_protocol", None) or getattr(obj, "_protocol", None)
    if protocol is not None:
        bits.append(type(protocol).__name__)
        buffered = _buffered_bytes(protocol)
        if buffered:
            bits.append(buffered)
    return " / ".join(bits)


def _peer_of(frame) -> str:
    """スタックをたどって、いま読み書きしている通信の相手を名指しする。

    **TLS の読み出しでループが埋まる形では、行番号から何も分からない。**
    本番で実際にそうなった（1016ms、いちばん深いところが sslproto の
    _do_read で、アプリのフレームが1行も無い）。どこを直すかを決めるには
    「どの接続か」が要る。その内部フレームは相手を知っているので、
    局所変数の self から引き出す。

    フレームの局所変数を別スレッドから覗くので、**取れなくて当たり前**として
    扱う。ここで例外を出せば見張りごと死ぬ。
    """
    depth = 0
    while frame is not None and depth < _MAX_STACK_LINES:
        try:
            described = _describe_endpoint(frame.f_locals.get("self"))
        except Exception:
            described = ""
        if described:
            return described
        frame = frame.f_back
        depth += 1
    return ""


def _loop_sample() -> tuple[str, str]:
    """イベントループのスレッドが、いまどこを実行しているかを写し取る。

    返すのは (ログへ残す文字列, 同じ場所かどうかを見る鍵)。鍵はいちばん深い
    1行で、これが変わらないうちは同じところで止まり続けていると見なす。

    取れなかった場合（スレッドが既に終わっている等）は、その旨を返す。
    **ここで例外を出すと見張りごと死ぬ**ので、握って文字列にする。
    """
    if _loop_thread_id is None:
        return "（ループのスレッドが分かりません）", ""
    frame = sys._current_frames().get(_loop_thread_id)
    if frame is None:
        return "（ループのスレッドのスタックを取れませんでした）", ""
    try:
        lines = traceback.format_stack(frame)
    except Exception as exc:  # pragma: no cover - スタック取得はまず失敗しない
        return f"（スタックを整形できませんでした: {exc}）", ""
    # 末尾＝いちばん深いところ。手前は asyncio と discord.py の内部が並ぶだけ。
    text = "".join(lines[-_MAX_STACK_LINES:]).rstrip()
    peer = _peer_of(frame)
    if peer:
        text += f"\n  相手: {peer}"
    return text, lines[-1].strip() if lines else ""


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
    seen_leaves: set[str] = set()
    tries = 0
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
                seen_leaves = set()
                tries = 0
            continue

        if reported_beat is None:
            reported_beat = beat
            tries = 1
            text, leaf = _loop_sample()
            seen_leaves.add(leaf)
            logger.warning(
                "[stall] イベントループが %.0f ms 止まっています。止めている場所:\n%s",
                late * 1000,
                text,
                extra={"stall_ms": round(late * 1000)},
            )
            continue

        # 同じ停止が続いている。**場所が変わったときだけ**書き足す。
        if len(seen_leaves) >= _MAX_SAMPLES or tries >= _MAX_SAMPLE_TRIES:
            continue
        tries += 1
        text, leaf = _loop_sample()
        if leaf in seen_leaves:
            continue
        seen_leaves.add(leaf)
        logger.warning(
            "[stall] 同じ停止が続いています（%.0f ms 経過）。今度はここにいます:\n%s",
            late * 1000,
            text,
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
