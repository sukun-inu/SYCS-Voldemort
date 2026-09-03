"""各プロセスが自分のメトリクスを定期的に Valkey へ流す部分。

bot / admin / web の3つが同じものを使う。**別々に書かないこと。** 心拍の鍵の
付け方や、流せなかったときの戻し方を3箇所で書くと、必ず1箇所だけ違う形になる
（実際に dev_signals で、書く側と読む側の解決の仕方がずれて何も起きなくなった
事例がある）。

■ 何を流すか

  心拍          どのプロセスも必ず。これが sycs_up の元になる。
  カウンタ      CounterBuffer に溜まったぶんの差分。
  ゲージ        呼び出し側が渡す関数の戻り値（アプリ固有の瞬間値）。

■ 流せなかったときに捨てない

カウンタは drain（取り出して空にする）してから送るので、送信に失敗したぶんを
戻さないとそのまま消える。**Valkey が一時的に落ちている間の計数が全部捨てられる**
ことになるので、失敗したら必ず restore する。

ゲージと心拍は「最新の値だけ意味がある」ので、失敗しても捨ててよい（次の回で
上書きされる）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Mapping

from services.metrics_registry import CounterBuffer, MetricsRegistry, counters, metrics_registry

logger = logging.getLogger(__name__)

# 報告の間隔。Netdata 側のスクレイプ間隔（既定10秒）より長くてよい。ここを短く
# しても、Netdata が読む値が新しくなるわけではない（読む頻度は向こうが決める）。
DEFAULT_INTERVAL_SECONDS = 30.0


async def report_once(
    app: str,
    *,
    registry: MetricsRegistry | None = None,
    buffer: CounterBuffer | None = None,
    gauges: Mapping[str, float] | None = None,
) -> None:
    """1回だけ報告する。例外は外へ出さない。

    例外を出さないのは、これを呼ぶのが背景タスクだから。discord.ext.tasks の
    loop は中で例外が飛ぶとその回で停止し、再始動しない限り二度と走らない
    （events/background_tasks.py の _safe と同じ理由）。**メトリクスの報告が
    失敗したせいで、他の背景処理まで止まるのが最悪。**
    """
    registry = registry or metrics_registry()
    buffer = buffer or counters()

    drained = buffer.drain()
    try:
        await registry.heartbeat(app)
        for name, value in (gauges or {}).items():
            await registry.set_gauge(app, name, value)
        for name, labels, amount in drained:
            await registry.incr_counter(name, labels, amount)
    except Exception:  # noqa: BLE001 - 背景タスクを止めないための最後の受け皿
        # drain した計数を戻す。戻さないと、この回のぶんが消える。
        buffer.restore(drained)
        logger.warning("メトリクスの報告に失敗しました（次の回で送り直します）", exc_info=True)


async def report_forever(
    app: str,
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    registry: MetricsRegistry | None = None,
    buffer: CounterBuffer | None = None,
    gauge_source: Callable[[], Mapping[str, float]] | None = None,
) -> None:
    """止められるまで報告し続ける。asyncio.Task として動かす。

    gauge_source は毎回呼ばれる。**重い処理を渡さないこと**（psutil の
    cpu_percent のように待つものを渡すと、その間このループが止まる。ホストの
    CPU とメモリは Netdata 自身が測るので、ここで測る必要は無い）。

    CancelledError は握りつぶさずに投げ直す。握りつぶすと、シャットダウン時に
    このタスクが終わらず、プロセスが落ちるまで待たされる。
    """
    interval = max(1.0, float(interval_seconds))
    while True:
        try:
            gauges = dict(gauge_source()) if gauge_source is not None else None
        except Exception:  # noqa: BLE001 - 呼び出し側の関数が壊れてもループは続ける
            logger.warning("ゲージの収集に失敗しました", exc_info=True)
            gauges = None
        await report_once(app, registry=registry, buffer=buffer, gauges=gauges)
        await asyncio.sleep(interval)
