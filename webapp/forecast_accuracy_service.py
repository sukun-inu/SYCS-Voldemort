import logging
from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .forecast_utils import PCT_SCALE, PRICE_SCALE, as_decimal, safe_float
from .models import ForecastAccuracyLog, MetalPriceDaily
from .snapshot_service import jst_today

logger = logging.getLogger(__name__)


async def record_forecast_snapshot(session: AsyncSession, payload: dict[str, Any]) -> int:
    """予測payloadから各金属×各予測日の行をUPSERTする。同日内に複数回リフレッシュ
    しても(metal_key, as_of_date, forecast_date)単位で最新の予測に上書きされるため、
    行が増殖しない。過去の予測(as_of_dateが異なる行)はそのまま残り、後日
    reconcile_forecast_accuracyで実勢価格と突き合わせる対象になる。"""
    as_of_raw = payload.get("as_of_date")
    if not isinstance(as_of_raw, str):
        return 0
    as_of_date = date.fromisoformat(as_of_raw)

    forecast_map = payload.get("forecast", {}) if isinstance(payload.get("forecast"), dict) else {}
    rows_upserted = 0
    for metal_key, item in forecast_map.items():
        if not isinstance(item, dict):
            continue
        model_variant = str(item.get("model_variant", "unknown"))
        daily = item.get("daily", []) if isinstance(item.get("daily"), list) else []
        for offset, daily_item in enumerate(daily, start=1):
            if not isinstance(daily_item, dict):
                continue
            forecast_date_raw = daily_item.get("date")
            predicted = safe_float(daily_item.get("price_per_gram"))
            if not isinstance(forecast_date_raw, str) or predicted is None:
                continue
            forecast_date = date.fromisoformat(forecast_date_raw)
            predicted_decimal = as_decimal(predicted, PRICE_SCALE)
            if predicted_decimal is None:
                continue
            stmt = (
                pg_insert(ForecastAccuracyLog)
                .values(
                    metal_key=metal_key,
                    as_of_date=as_of_date,
                    forecast_date=forecast_date,
                    horizon_offset_days=offset,
                    predicted_price_per_gram=predicted_decimal,
                    model_variant=model_variant,
                )
                .on_conflict_do_update(
                    constraint="uq_forecast_accuracy_key_asof_date",
                    set_={
                        "horizon_offset_days": offset,
                        "predicted_price_per_gram": predicted_decimal,
                        "model_variant": model_variant,
                    },
                )
            )
            await session.execute(stmt)
            rows_upserted += 1

    await session.commit()
    return rows_upserted


async def reconcile_forecast_accuracy(session: AsyncSession, *, max_rows: int = 500) -> dict[str, int]:
    """forecast_date <= 今日(JST) かつ actual未確定の行を実勢価格(MetalPriceDaily)と
    突き合わせて埋める。日次スナップショット確定直後(collect_daily_data)に呼ぶ想定。"""
    today = jst_today()
    stmt = (
        select(ForecastAccuracyLog)
        .where(
            ForecastAccuracyLog.forecast_date <= today,
            ForecastAccuracyLog.actual_price_per_gram.is_(None),
        )
        .limit(max_rows)
    )
    pending_rows = list((await session.scalars(stmt)).all())
    if not pending_rows:
        return {"checked": 0, "matched": 0, "unmatched": 0}

    target_dates = {row.forecast_date for row in pending_rows}
    target_keys = {row.metal_key for row in pending_rows}
    price_stmt = select(
        MetalPriceDaily.metal_key,
        MetalPriceDaily.snapshot_date,
        MetalPriceDaily.price_per_gram,
    ).where(
        MetalPriceDaily.snapshot_date.in_(target_dates),
        MetalPriceDaily.metal_key.in_(target_keys),
    )
    price_rows = (await session.execute(price_stmt)).all()
    actual_by_key = {
        (metal_key, snapshot_date): price_per_gram for metal_key, snapshot_date, price_per_gram in price_rows
    }

    matched = 0
    for row in pending_rows:
        actual = actual_by_key.get((row.metal_key, row.forecast_date))
        if actual is None:
            continue
        row.actual_price_per_gram = actual
        predicted = safe_float(row.predicted_price_per_gram)
        actual_f = safe_float(actual)
        if predicted is not None and actual_f:
            row.error_pct = as_decimal(((predicted - actual_f) / actual_f) * 100, PCT_SCALE)
        matched += 1

    await session.commit()
    return {"checked": len(pending_rows), "matched": matched, "unmatched": len(pending_rows) - matched}


async def load_recent_forecast_error(session: AsyncSession, *, lookback_days: int = 14) -> dict[str, float]:
    """金属ごとの直近平均絶対誤差(MAE%)を返す。答え合わせ済みデータが無い金属は
    結果に含まれない(呼び出し側でNone/欠損として扱われる)。"""
    today = jst_today()
    since = today - timedelta(days=lookback_days)
    stmt = (
        select(
            ForecastAccuracyLog.metal_key,
            func.avg(func.abs(ForecastAccuracyLog.error_pct)),
        )
        .where(
            ForecastAccuracyLog.forecast_date >= since,
            ForecastAccuracyLog.forecast_date <= today,
            ForecastAccuracyLog.error_pct.is_not(None),
        )
        .group_by(ForecastAccuracyLog.metal_key)
    )
    rows = (await session.execute(stmt)).all()
    return {metal_key: float(mae) for metal_key, mae in rows if mae is not None}
