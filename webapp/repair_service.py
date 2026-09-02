from __future__ import annotations

import logging
from datetime import datetime, timedelta
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

    # 今日の不足データはAPI再取得で補完を試みるが、クールダウン中は無条件リトライで
    # API枠を消費しないようスキップする。
    global _last_missing_data_repair_attempt
    today_rows_before = list(
        (await session.scalars(select(MetalPriceDaily).where(MetalPriceDaily.snapshot_date == today))).all()
    )
    today_keys_before = {row.metal_key for row in today_rows_before if row.metal_key in _TRACKED_KEYS}
    missing_today_before = _TRACKED_KEYS - today_keys_before
    stats["missing_today_before"] = len(missing_today_before)
    if missing_today_before:
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
                len(missing_today_before),
                cooldown_until.isoformat(),
            )
        else:
            _last_missing_data_repair_attempt = now
            stats["missing_data_repair_attempted"] = 1
            await store_snapshot(session, today, skip_if_exists=False)

    # delta_from_previous・metal_codeの整合性チェックは全行を読み込んでメモリ上で照合し、
    # 差分があった行だけをUPDATEする純粋なローカル計算(MetalpriceAPIなど外部APIは一切
    # 消費しない)。以前はlookback_days(既定60日)で範囲を絞っていたため、「全期間」表示
    # 追加後に60日より古い行のdelta_from_previousがNULLのまま永久に直らない不整合が
    # 発生していた。日次1行×金属3種の規模では全履歴走査でも軽量なため、範囲を絞らず
    # 常に全件を対象にする。
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

    today_rows_after = list(
        (await session.scalars(select(MetalPriceDaily).where(MetalPriceDaily.snapshot_date == today))).all()
    )
    today_keys_after = {row.metal_key for row in today_rows_after if row.metal_key in _TRACKED_KEYS}
    stats["missing_today_after"] = len(_TRACKED_KEYS - today_keys_after)

    latest_rows = await load_latest_rows(session)
    latest_dates = {row.snapshot_date for row in latest_rows.values() if row.metal_key in _TRACKED_KEYS}
    latest_snapshot_date_iso = None
    if len(latest_dates) == 1:
        latest_snapshot_date_iso = next(iter(latest_dates)).isoformat()

    forecast_payload = await load_stored_weekly_forecast(session, days=7)
    if force_forecast_refresh or _forecast_has_drift(
        forecast_payload,
        latest_snapshot_date_iso=latest_snapshot_date_iso,
    ):
        await refresh_weekly_forecast_cache(session, horizon_days=7)
        stats["forecast_refreshed"] = 1

    await session.commit()
    return stats
