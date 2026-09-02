from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS
from envutil import env_int

from .forecast_service import load_stored_weekly_forecast, refresh_weekly_forecast_cache
from .models import MetalPriceDaily
from .snapshot_service import (
    JST,
    PRICE_SCALE,
    TRACKED_METALS,
    jst_today,
    load_latest_rows,
    store_snapshot,
)

logger = logging.getLogger(__name__)

_TRACKED_KEYS = {m.key for m in TRACKED_METALS}

# MetalpriceAPIが無料枠(月100回)のため、本日データ欠損時のAPI再取得を無条件で繰り返すと
# (このジョブ自体が既定30分おきに実行される)、API失敗→欠損継続→再試行…の無限ループで
# 枠を食いつぶしてしまう。ここにクールダウンを設け、一定時間は再取得を試みないようにする。
MISSING_DATA_REPAIR_COOLDOWN = timedelta(hours=env_int("METAL_REPAIR_RETRY_COOLDOWN_HOURS", 6, minimum=1))
_last_missing_data_repair_attempt: datetime | None = None


def _quantize_delta(value: Decimal) -> Decimal:
    """既存行のdelta_from_previousと桁数を揃える。揃えないと差分検知(!=)が誤検知する。"""
    return value.quantize(PRICE_SCALE, rounding=ROUND_HALF_UP)


def _forecast_has_drift(payload: dict[str, Any] | None, *, latest_snapshot_date_iso: str | None) -> bool:
    """保存済みの週次予測が、直近スナップショットと噛み合っていないかを見る。

    ここが True を返すケース（as_of_date が最新日と違う、必須フィールドが
    欠けている等）は、価格データだけ直っても予測キャッシュが古いままに
    なる状況。噛み合っていないのに気づかず放置すると、画面には
    「更新されているはずの予測」として古い/不整合な数字が出続ける。
    """
    if payload is None:
        return True

    as_of_date = payload.get("as_of_date")
    if latest_snapshot_date_iso and as_of_date != latest_snapshot_date_iso:
        return True

    forecast = payload.get("forecast")
    if not isinstance(forecast, dict):
        return True

    for metal_key in _TRACKED_KEYS:
        item = forecast.get(metal_key)
        if not isinstance(item, dict):
            return True
        daily = item.get("daily")
        if not isinstance(daily, list) or len(daily) == 0:
            return True
        first = daily[0] if daily else {}
        if not isinstance(first, dict):
            return True
        if not isinstance(first.get("date"), str):
            return True

    return False


async def _missing_today(session: AsyncSession, today: date) -> set[str]:
    """今日ぶんが揃っていない金属。補完の前後で同じ数え方をする。

    補完のあとに数え直さず前の結果を使い回すと、直ったのに「直っていない」
    と記録される。無人実行なので、後から読むのはその数字だけ。
    """
    rows = list((await session.scalars(select(MetalPriceDaily).where(MetalPriceDaily.snapshot_date == today))).all())
    return _TRACKED_KEYS - {row.metal_key for row in rows if row.metal_key in _TRACKED_KEYS}


async def _refill_today(session: AsyncSession, today: date, missing: set[str], stats: dict[str, int]) -> None:
    """今日の不足データをAPI再取得で補う。クールダウン中は見送る。

    無条件にリトライすると無料枠を食い潰すので、前回の試行から一定時間は
    間を空ける。見送ったことも stats とログに残す（黙って何もしないと、
    「補完が動かない」のか「まだ待っている」のかが区別できない）。
    """
    global _last_missing_data_repair_attempt

    now = datetime.now(JST)
    cooldown_until = (
        _last_missing_data_repair_attempt + MISSING_DATA_REPAIR_COOLDOWN
        if _last_missing_data_repair_attempt is not None
        else None
    )
    if cooldown_until is not None and now < cooldown_until:
        stats["missing_data_repair_skipped_cooldown"] = 1
        logger.info(
            "本日データ欠損(%d件)を検知したがクールダウン中のため再取得をスキップ。次回試行可能: %s",
            len(missing),
            cooldown_until.isoformat(),
        )
        return

    _last_missing_data_repair_attempt = now
    stats["missing_data_repair_attempted"] = 1
    await store_snapshot(session, today, skip_if_exists=False)


async def _repair_rows(session: AsyncSession, stats: dict[str, int]) -> None:
    """metal_code と delta_from_previous の不整合を全履歴ぶん直す。

    ローカル計算だけで完結する（MetalpriceAPI など外部APIは一切消費しない）。
    以前は lookback_days(既定60日)で範囲を絞っていたため、「全期間」表示
    追加後に60日より古い行の delta_from_previous が NULL のまま永久に直らない
    不整合が発生していた。日次1行×金属3種の規模では全履歴走査でも軽量なため、
    範囲を絞らず常に全件を対象にする。

    前日値は**金属ごとに**持つ。1本の変数で持ち回すと、金の差分が銀の価格から
    引かれる。並べ替えを外すのも同じ理由で、差分は「1つ前の行」との引き算
    なので、順序が変われば値も変わる。
    """
    stmt = select(MetalPriceDaily).order_by(MetalPriceDaily.metal_key.asc(), MetalPriceDaily.snapshot_date.asc())
    rows = list((await session.scalars(stmt)).all())
    prev_price_by_metal: dict[str, Decimal] = {}

    for row in rows:
        stats["rows_scanned"] += 1
        changed = False

        spec = METAL_COMMANDS.get(row.metal_key)
        if spec is not None and row.metal_code != spec.code:
            row.metal_code = spec.code
            changed = True
            stats["metal_code_fixed"] += 1

        prev_price = prev_price_by_metal.get(row.metal_key)
        expected_delta = _quantize_delta(row.price_per_gram - prev_price) if prev_price is not None else None
        if row.delta_from_previous != expected_delta:
            row.delta_from_previous = expected_delta
            changed = True
            stats["delta_fixed"] += 1

        prev_price_by_metal[row.metal_key] = row.price_per_gram
        if changed:
            stats["rows_fixed"] += 1


async def _refresh_forecast_if_needed(
    session: AsyncSession,
    stats: dict[str, int],
    force_forecast_refresh: bool,
) -> None:
    """保存済みの週次予測が最新の価格と噛み合っていなければ作り直す。

    比べる基準日は、追跡している金属の最新日が全部そろって同じときだけ
    決める。ばらけているときは比べようがないので、ずれとは見なさない
    （その状態で作り直すと、取り込み途中の日で予測が固まる）。
    """
    latest_rows = await load_latest_rows(session)
    latest_dates = {row.snapshot_date for row in latest_rows.values() if row.metal_key in _TRACKED_KEYS}
    latest_snapshot_date_iso = next(iter(latest_dates)).isoformat() if len(latest_dates) == 1 else None

    forecast_payload = await load_stored_weekly_forecast(session, days=7)
    if force_forecast_refresh or _forecast_has_drift(
        forecast_payload,
        latest_snapshot_date_iso=latest_snapshot_date_iso,
    ):
        await refresh_weekly_forecast_cache(session, horizon_days=7)
        stats["forecast_refreshed"] = 1


async def repair_metalprice_integrity(
    session: AsyncSession,
    *,
    force_forecast_refresh: bool = False,
) -> dict[str, int]:
    """定期実行される自己修復ジョブ。何度呼んでも安全（差分がなければ何もしない）。

    やることは3つ: (1) 今日分の欠損をAPIから補完（クールダウン付きで
    無料枠を守る）、(2) 全履歴のmetal_code/delta_from_previousの不整合を
    ローカル計算だけで直す（外部APIは叩かない）、(3) 保存済み週次予測が
    最新の価格と噛み合っていなければ再計算する。呼び出しごとに
    stats を返すのは、無人実行の結果を後からログだけで追えるようにする
    ため。
    """
    today = jst_today()

    stats: dict[str, int] = {
        "rows_scanned": 0,
        "rows_fixed": 0,
        "metal_code_fixed": 0,
        "delta_fixed": 0,
        "missing_today_before": 0,
        "missing_today_after": 0,
        "forecast_refreshed": 0,
        "missing_data_repair_attempted": 0,
        "missing_data_repair_skipped_cooldown": 0,
    }

    missing_today_before = await _missing_today(session, today)
    stats["missing_today_before"] = len(missing_today_before)
    if missing_today_before:
        await _refill_today(session, today, missing_today_before, stats)

    await _repair_rows(session, stats)

    # 補完のあとに数え直す（前の結果を使い回すと、直ったのに直っていないと記録される）。
    stats["missing_today_after"] = len(await _missing_today(session, today))

    await _refresh_forecast_if_needed(session, stats, force_forecast_refresh)

    await session.commit()
    return stats
