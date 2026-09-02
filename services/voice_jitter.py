"""voice_recv のジッタバッファを、穴が空いても捨てない版へ差し替える。

■ 何が起きていたか

録音中、本番のログにこれが出続けていた。

    [WARNING] discord.ext.voice_recv.opus:
      1 packets were lost being flushed in decoder-1148
       --> (last=20299) [20302, 20303]

読み方に注意が要る。**「1個届かなかった」ではなく「ライブラリが1個捨てた」**
である。20302 と 20303 を抱えた状態で 20302 だけを返し、20303 を落としている。
話者が入れ替わった直後には、1回で6個捨てていた。

      6 packets were lost being flushed in decoder-1352
       --> (last=16781) [16769, 16761, 16768, 16765, 16766, 16762, 16764]

捨てられたぶんは sink まで来ない。こちら側の並べ直し（_StreamAssembler）は
届いたものしか並べ直せないので、これは取り返せない録音の穴になる。

■ なぜそうなるのか

ライブラリの3箇所が噛み合っていない。

  1. `buffer.HeapJitterBuffer._update_has_item`
     先頭が「前に出した番号の次」でなければ `_has_item` を立てない
     （バッファが maxsize=10 まで埋まれば立てる）。穴を待つ側。
  2. `router.PacketRouter._do_run`
     `decoder.pop_data()` を **timeout=0** で呼ぶ。1. で旗が下りているので
     `pop()` は待たずに None を返す。待たない側。
  3. `opus.PacketDecoder._get_next_packet`
     `pop()` が None でバッファが空でないとき `flush()` し、
     **先頭1個だけ返して残りを捨てる**。

さらに `flush()` は `_last_tx_seq` を「捨てたぶんも含めた最大値」へ進めるので、
そのあと遅れて本物が届いても `push()` が「古いパケット」として弾く。

穴が1つ空くたびに、待っている側と待たない側の食い違いのぶんだけ捨てる、という
だけの話で、**パケットそのものは届いている**。

■ どう直したか

1. の判定を「取り出せる状態なら立てる」に変える。これで 2. の
`pop(timeout=0)` が実際に1個返すようになり、3. の捨てる経路へ落ちない。

  - **取り出す順序は変わらない。** heap の先頭はいちばん若い番号なので、
    穴があってもその次に若いものから昇順で出る
  - 「穴が埋まるのを待つ」働きは失われるが、それは `_StreamAssembler` が
    `_REORDER_HOLD_SEC` のあいだ受け持っている。しかもあちらは捨てない
  - `prefsize`（1個ぶんの遊び）は触らない。`_pop_if_ready` の条件はそのまま

差し替えは、`PacketDecoder.__init__` が `JitterBuffer()` を引数なしで作る所を
狙う。`opus.py` が `from .buffer import HeapJitterBuffer as JitterBuffer` で
束縛しているので、そのモジュール属性を置き換える。**listen() を呼ぶ前に**
行うこと。decoder は SSRC ごとに作られるので、後から差し替えても既に
できている decoder には効かない。

■ 直したあとに残る損失

`push()` が「古い」として弾いたぶん（`stats()["late_rejected"]`）。これは
`_last_tx_seq` より後ろへ戻る番号で、ここまで遅れたものは今さら順番へ
差し込めない。数だけ数えて log_summary へ出す。0 でないなら、こちらの
`_REORDER_HOLD_SEC` を延ばしても届かない領域の損失である。
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

try:  # 受信拡張が無い環境でも、録音以外は動かせるようにする
    from discord.ext.voice_recv import opus as _vr_opus
    from discord.ext.voice_recv.buffer import HeapJitterBuffer

    AVAILABLE = True
except ImportError:  # pragma: no cover - 導入済みの環境では通らない
    # 使う側は AVAILABLE を見る。install() は False を返す。
    _vr_opus = None  # type: ignore[assignment]
    HeapJitterBuffer = object  # type: ignore[assignment,misc]
    AVAILABLE = False

# 差し替え済みか。install() を何度呼んでも1回しか効かない。
_installed = False
# push() が「古い」として弾いた数。ギルドをまたいだプロセス全体の合計で、
# バッファ側に SSRC が渡ってこないため内訳は取れない。
_late_rejected = 0
_lock = threading.Lock()


class _LosslessJitterBuffer(HeapJitterBuffer):
    """穴が空いても中身を捨てないジッタバッファ。

    捨てないことだけが元の版との違い。順序も遊び（prefsize）もそのまま。
    """

    def _update_has_item(self) -> None:
        """「次が揃っているか」ではなく「取り出せるか」で旗を立てる。

        元の版は先頭が連番でないと旗を下ろし、それを見た router が
        pop(timeout=0) で None を受け取り、PacketDecoder が flush して
        先頭以外を捨てていた（モジュールの docstring を読むこと）。
        """
        if self._prefill > 0 or len(self._buffer) <= self.prefsize:
            self._has_item.clear()
            return
        self._has_item.set()

    def push(self, packet: Any) -> Any:
        """元の push に、弾かれた数を数える処理だけを足す。

        判定そのものは変えない。`_last_tx_seq` より後ろへ戻る番号は、いま
        差し込んでも順番を乱すだけなので、弾くのは元の版の判断で正しい。
        ただし**何個弾いたかが分からない**と、残っている損失の大きさを
        測れないので、そこだけ数える。

        戻り値を Any にしてあるのは、`Buffer` プロトコルの `push` が None を
        返す約束になっているため（実装の `HeapJitterBuffer.push` は bool を
        返す）。bool と書くと override の不一致で型検査に止められる。
        """
        global _late_rejected
        ok = super().push(packet)
        if not ok:
            with _lock:
                _late_rejected += 1
        return ok


def install() -> bool:
    """ジッタバッファを差し替える。成功したら True。

    listen() を呼ぶ前に呼ぶこと。既に作られている decoder には効かない。
    何度呼んでも差し替えは1回だけ行う。
    """
    global _installed
    if _installed:
        return True
    if not AVAILABLE:
        logger.warning("[jitter] 受信拡張が無いので差し替えません")
        return False
    # 差し替える先が、こちらの想定どおりの形をしているか。ライブラリ側が
    # 変わったときに黙って素通りさせない（元のままなら穴のたびに捨て続ける）。
    if not hasattr(HeapJitterBuffer, "_update_has_item"):
        logger.warning(
            "[jitter] HeapJitterBuffer に _update_has_item がありません。"
            "voice_recv 側の作りが変わっています。差し替えずに続けます"
            "（穴が空くたびにパケットが捨てられる状態のままです）"
        )
        return False
    # 代入の形にすると「型には代入できない」と止められる。setattr なら
    # 同じことを指摘されずに書ける（CONTRIBUTING 6.）。
    setattr(_vr_opus, "JitterBuffer", _LosslessJitterBuffer)
    _installed = True
    logger.info("[jitter] ジッタバッファを差し替えました（穴が空いても捨てない版）")
    return True


def stats() -> dict[str, int | bool]:
    """差し替えの状態と、弾かれたパケットの数。

    録音の要約（log_summary）へ出すためのもの。数はプロセス全体の合計で、
    録音1本ぶんではない。
    """
    with _lock:
        return {"installed": _installed, "late_rejected": _late_rejected}


def reset_stats() -> None:
    """数えた数を 0 に戻す。テストから使う。"""
    global _late_rejected
    with _lock:
        _late_rejected = 0
