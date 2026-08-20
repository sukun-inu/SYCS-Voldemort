import asyncio
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from zoneinfo import ZoneInfo

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS
from services.metal_service import fetch_metal_price_per_gram

from .models import MetalPriceDaily

logger = logging.getLogger(__name__)
JST = ZoneInfo("Asia/Tokyo")
PRICE_SCALE = Decimal("0.0001")


@dataclass(frozen=True)
class MetalRecord:
    key: str
    code: str


TRACKED_METALS = [MetalRecord(key=spec.key, code=spec.code) for spec in METAL_COMMANDS.values()]


def jst_today() -> date:
    return datetime.now(JST).date()


def _as_decimal(value: float) -> Decimal:
    return Decimal(str(value)).quantize(PRICE_SCALE, rounding=ROUND_HALF_UP)


async def _fetch_all_prices() -> dict[str, Decimal]:
    tasks = [fetch_metal_price_per_gram(metal.code) for metal in TRACKED_METALS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    prices: dict[str, Decimal] = {}
    for metal, result in zip(TRACKED_METALS, results):
        if isinstance(result, Exception):
            logger.error("価格取得に失敗: %s (%s)", metal.key, metal.code, exc_info=result)
            continue
        prices[metal.key] = _as_decimal(result)

    if not prices:
        raise RuntimeError("すべての金属価格の取得に失敗した。")
    return prices


async def _rows_for_date(session: AsyncSession, snapshot_date: date) -> dict[str, MetalPriceDaily]:
    stmt = select(MetalPriceDaily).where(MetalPriceDaily.snapshot_date == snapshot_date)
    rows = list((await session.scalars(stmt)).all())
    return {row.metal_key: row for row in rows}


async def _latest_rows_before(session: AsyncSession, snapshot_date: date) -> dict[str, MetalPriceDaily]:
    latest_date_subq = (
        select(
            MetalPriceDaily.metal_key,
            func.max(MetalPriceDaily.snapshot_date).label("latest_date"),
        )
        .where(MetalPriceDaily.snapshot_date < snapshot_date)
        .group_by(MetalPriceDaily.metal_key)
        .subquery()
    )
    stmt = select(MetalPriceDaily).join(
        latest_date_subq,
        and_(
            MetalPriceDaily.metal_key == latest_date_subq.c.metal_key,
            MetalPriceDaily.snapshot_date == latest_date_subq.c.latest_date,
        ),
    )
    rows = list((await session.scalars(stmt)).all())
    return {row.metal_key: row for row in rows}


async def store_snapshot(session: AsyncSession, snapshot_date: date, *, skip_if_exists: bool = True) -> list[MetalPriceDaily]:
    existing_rows = await _rows_for_date(session, snapshot_date)
    if skip_if_exists and len(existing_rows) >= len(TRACKED_METALS):
        return sorted(existing_rows.values(), key=lambda row: row.metal_key)

    prices = await _fetch_all_prices()
    previous_rows = await _latest_rows_before(session, snapshot_date)
    records: list[MetalPriceDaily] = []

    for metal in TRACKED_METALS:
        if metal.key not in prices:
            continue

        price = prices[metal.key]
        previous = previous_rows.get(metal.key)
        delta = (price - previous.price_per_gram).quantize(PRICE_SCALE, rounding=ROUND_HALF_UP) if previous else None

        existing = existing_rows.get(metal.key)
        if existing:
            existing.price_per_gram = price
            existing.delta_from_previous = delta
            existing.metal_code = metal.code
            records.append(existing)
            continue

        created = MetalPriceDaily(
            metal_key=metal.key,
            metal_code=metal.code,
            snapshot_date=snapshot_date,
            price_per_gram=price,
            delta_from_previous=delta,
        )
        session.add(created)
        records.append(created)

    await session.commit()
    return records


async def store_today_snapshot(session: AsyncSession, *, skip_if_exists: bool = True) -> list[MetalPriceDaily]:
    return await store_snapshot(session, jst_today(), skip_if_exists=skip_if_exists)


async def load_earliest_snapshot_date(session: AsyncSession) -> date | None:
    return await session.scalar(select(func.min(MetalPriceDaily.snapshot_date)))


async def load_history(session: AsyncSession, days: int) -> dict[str, list[dict[str, float | str | None]]]:
    start_date = jst_today() - timedelta(days=days - 1)
    stmt = (
        select(
            MetalPriceDaily.metal_key,
            MetalPriceDaily.snapshot_date,
            MetalPriceDaily.price_per_gram,
            MetalPriceDaily.delta_from_previous,
        )
        .where(MetalPriceDaily.snapshot_date >= start_date)
        .order_by(MetalPriceDaily.snapshot_date.asc())
    )
    rows = (await session.execute(stmt)).all()

    history: dict[str, list[dict[str, float | str | None]]] = {metal.key: [] for metal in TRACKED_METALS}
    for metal_key, snapshot_date, price_per_gram, delta_from_previous in rows:
        history.setdefault(metal_key, []).append(
            {
                "date": snapshot_date.isoformat(),
                "price_per_gram": float(price_per_gram),
                "delta_from_previous": float(delta_from_previous) if delta_from_previous is not None else None,
            }
        )
    return history


async def load_latest_rows(session: AsyncSession) -> dict[str, MetalPriceDaily]:
    latest_date_subq = (
        select(
            MetalPriceDaily.metal_key,
            func.max(MetalPriceDaily.snapshot_date).label("latest_date"),
        )
        .group_by(MetalPriceDaily.metal_key)
        .subquery()
    )
    stmt = select(MetalPriceDaily).join(
        latest_date_subq,
        and_(
            MetalPriceDaily.metal_key == latest_date_subq.c.metal_key,
            MetalPriceDaily.snapshot_date == latest_date_subq.c.latest_date,
        ),
    )
    rows = list((await session.scalars(stmt)).all())
    return {row.metal_key: row for row in rows}


async def load_latest(session: AsyncSession) -> dict[str, dict[str, float | str | None]]:
    latest_rows = await load_latest_rows(session)
    latest: dict[str, dict[str, float | str | None]] = {}

    for metal in TRACKED_METALS:
        row = latest_rows.get(metal.key)
        if row is None:
            latest[metal.key] = {
                "date": None,
                "price_per_gram": None,
                "delta_from_previous": None,
            }
            continue
        latest[metal.key] = {
            "date": row.snapshot_date.isoformat(),
            "price_per_gram": float(row.price_per_gram),
            "delta_from_previous": float(row.delta_from_previous) if row.delta_from_previous is not None else None,
        }

    return latest
