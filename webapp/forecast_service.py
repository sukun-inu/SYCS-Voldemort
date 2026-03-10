import asyncio
import json
import logging
import math
from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from statistics import pstdev
from typing import Any
from urllib.parse import quote_plus
from xml.etree import ElementTree

import aiohttp
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS

from .models import WeeklyForecastDaily, WeeklyForecastMeta
from .snapshot_service import JST, load_history

logger = logging.getLogger(__name__)

USDJPY_DAILY_CSV_URL = "https://stooq.com/q/d/l/?s=usdjpy&i=d"
GOOGLE_NEWS_RSS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"
PRICE_SCALE = Decimal("0.0001")
PCT_SCALE = Decimal("0.000001")

NEWS_QUERY_BY_METAL = {
    "gold": "gold price xau bullion federal reserve inflation usd jpy",
    "silver": "silver price xag bullion industrial demand usd jpy",
    "platinum": "platinum price xpt auto catalyst industrial demand usd jpy",
}

POSITIVE_TOKENS = (
    "surge",
    "rise",
    "rises",
    "up",
    "gain",
    "gains",
    "record high",
    "bullish",
    "safe haven",
    "demand jumps",
    "demand grows",
    "weaker dollar",
    "dollar weakens",
    "cuts rates",
    "inflation fears",
    "上昇",
    "高騰",
    "最高値",
)

NEGATIVE_TOKENS = (
    "fall",
    "falls",
    "drop",
    "drops",
    "down",
    "loss",
    "losses",
    "bearish",
    "selloff",
    "strong dollar",
    "dollar strengthens",
    "yields rise",
    "rate hike",
    "recession hopes",
    "下落",
    "急落",
    "安値",
)

FX_BETA_BY_METAL = {
    "gold": 0.30,
    "silver": 0.45,
    "platinum": 0.40,
}


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _safe_float(raw: Any) -> float | None:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def _as_decimal(raw: Any, scale: Decimal = PRICE_SCALE) -> Decimal | None:
    value = _safe_float(raw)
    if value is None:
        return None
    return Decimal(str(value)).quantize(scale, rounding=ROUND_HALF_UP)


def _json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _json_loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


async def _fetch_usdjpy_signal(session: aiohttp.ClientSession) -> dict[str, Any]:
    try:
        async with session.get(USDJPY_DAILY_CSV_URL) as response:
            text = await response.text()
            if response.status != 200:
                raise RuntimeError(f"status={response.status}")
    except Exception as exc:
        logger.warning("USD/JPYデータ取得に失敗: %s", exc)
        return {
            "available": False,
            "source": "Stooq",
            "latest": None,
            "weekly_change_pct": 0.0,
            "daily_factor": 0.0,
        }

    closes: list[float] = []
    lines = text.splitlines()
    for line in lines[1:]:
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 5:
            continue
        close_value = _safe_float(parts[4])
        if close_value is None or close_value <= 0:
            continue
        closes.append(close_value)

    if len(closes) < 2:
        return {
            "available": False,
            "source": "Stooq",
            "latest": None,
            "weekly_change_pct": 0.0,
            "daily_factor": 0.0,
        }

    latest = closes[-1]
    anchor = closes[-6] if len(closes) >= 6 else closes[0]
    weekly_change = ((latest - anchor) / anchor) if anchor > 0 else 0.0
    daily_factor = weekly_change / 5.0
    return {
        "available": True,
        "source": "Stooq",
        "latest": round(latest, 4),
        "weekly_change_pct": round(weekly_change * 100, 3),
        "daily_factor": daily_factor,
    }


def _news_score(text: str) -> int:
    normalized = text.lower()
    score = 0
    for token in POSITIVE_TOKENS:
        if token in normalized:
            score += 1
    for token in NEGATIVE_TOKENS:
        if token in normalized:
            score -= 1
    return score


async def _fetch_news_for_query(
    session: aiohttp.ClientSession,
    query: str,
    *,
    limit: int = 18,
) -> tuple[list[str], float]:
    url = GOOGLE_NEWS_RSS_URL.format(query=quote_plus(query))
    try:
        async with session.get(url) as response:
            body = await response.text()
            if response.status != 200:
                raise RuntimeError(f"status={response.status}")
    except Exception as exc:
        logger.warning("ニュースRSS取得に失敗 query=%s err=%s", query, exc)
        return [], 0.0

    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        logger.warning("ニュースRSSパースに失敗 query=%s", query)
        return [], 0.0

    items = root.findall("./channel/item")
    titles: list[str] = []
    raw_score = 0
    for item in items[:limit]:
        title = (item.findtext("title") or "").strip()
        description = (item.findtext("description") or "").strip()
        if not title:
            continue
        titles.append(title)
        raw_score += _news_score(f"{title} {description}")

    if not titles:
        return [], 0.0

    normalized_score = math.tanh(raw_score / max(2.0, len(titles) * 1.4))
    return titles, normalized_score


async def _fetch_news_signals(session: aiohttp.ClientSession) -> dict[str, Any]:
    tasks = {
        metal_key: asyncio.create_task(_fetch_news_for_query(session, query))
        for metal_key, query in NEWS_QUERY_BY_METAL.items()
    }

    sentiment: dict[str, float] = {}
    article_counts: dict[str, int] = {}
    sample_headlines: dict[str, list[str]] = {}
    for metal_key, task in tasks.items():
        titles, score = await task
        sentiment[metal_key] = score
        article_counts[metal_key] = len(titles)
        sample_headlines[metal_key] = titles[:3]

    available = any(count > 0 for count in article_counts.values())
    return {
        "available": available,
        "source": "Google News RSS",
        "sentiment": {key: round(value, 4) for key, value in sentiment.items()},
        "article_counts": article_counts,
        "sample_headlines": sample_headlines,
    }


def _extract_prices(history_items: list[dict[str, Any]]) -> list[float]:
    prices: list[float] = []
    for item in history_items:
        value = _safe_float(item.get("price_per_gram"))
        if value is None or value <= 0:
            continue
        prices.append(value)
    return prices


def _daily_trend(prices: list[float], *, window: int = 14) -> float:
    if len(prices) < 2:
        return 0.0
    sampled = prices[-min(window, len(prices)) :]
    first = sampled[0]
    last = sampled[-1]
    if first <= 0:
        return 0.0
    if len(sampled) == 2:
        return _clamp((last - first) / first, -0.03, 0.03)
    geometric_daily = (last / first) ** (1.0 / (len(sampled) - 1)) - 1.0
    return _clamp(geometric_daily, -0.03, 0.03)


def _daily_volatility(prices: list[float], *, window: int = 14) -> float:
    if len(prices) < 3:
        return 0.004
    sampled = prices[-min(window, len(prices)) :]
    returns: list[float] = []
    for previous, current in zip(sampled, sampled[1:]):
        if previous <= 0:
            continue
        returns.append((current - previous) / previous)
    if not returns:
        return 0.004
    return float(pstdev(returns))


def _forecast_for_metal(
    *,
    metal_key: str,
    prices: list[float],
    horizon_days: int,
    today: datetime,
    fx_daily_factor: float,
    news_score: float,
    article_count: int,
    fx_available: bool,
) -> dict[str, Any]:
    start_price = prices[-1]
    trend = _daily_trend(prices)
    volatility = _daily_volatility(prices)

    trend_component = trend * 0.60
    fx_component = fx_daily_factor * FX_BETA_BY_METAL.get(metal_key, 0.35)
    news_component = news_score * 0.0025
    implied_daily_return = _clamp(trend_component + fx_component + news_component, -0.04, 0.04)

    daily: list[dict[str, Any]] = []
    current = start_price
    for offset in range(1, horizon_days + 1):
        decay = max(0.65, 1.0 - ((offset - 1) * 0.07))
        projected_return = implied_daily_return * decay
        next_value = max(0.01, current * (1.0 + projected_return))
        forecast_date = (today + timedelta(days=offset)).date().isoformat()
        daily.append(
            {
                "date": forecast_date,
                "price_per_gram": round(next_value, 2),
                "delta_from_previous": round(next_value - current, 2),
            }
        )
        current = next_value

    projected_change = ((current - start_price) / start_price) if start_price > 0 else 0.0

    confidence = 0.35
    if len(prices) >= 30:
        confidence += 0.25
    elif len(prices) >= 14:
        confidence += 0.12
    if fx_available:
        confidence += 0.15
    if article_count >= 8:
        confidence += 0.15
    elif article_count >= 3:
        confidence += 0.08
    confidence -= min(0.20, volatility * 6.0)
    if abs(implied_daily_return) > 0.025:
        confidence -= 0.05
    confidence = _clamp(confidence, 0.1, 0.95)

    drivers = [
        f"直近トレンド: {trend * 100:+.3f}%/日",
        f"USD/JPY感応: {fx_component * 100:+.3f}%/日",
        f"ニュース感応: {news_component * 100:+.3f}%/日 (score={news_score:+.3f})",
    ]
    return {
        "start_price_per_gram": round(start_price, 2),
        "projected_price_per_gram": round(current, 2),
        "projected_change_pct_7d": round(projected_change * 100, 3),
        "confidence": round(confidence, 3),
        "implied_daily_return_pct": round(implied_daily_return * 100, 4),
        "daily": daily,
        "drivers": drivers,
    }


async def build_weekly_forecast(session: AsyncSession, *, horizon_days: int = 7) -> dict[str, Any]:
    history_window_days = max(45, horizon_days * 8)
    history_by_metal = await load_history(session, history_window_days)

    timeout = aiohttp.ClientTimeout(total=14)
    async with aiohttp.ClientSession(timeout=timeout) as client:
        fx_task = asyncio.create_task(_fetch_usdjpy_signal(client))
        news_task = asyncio.create_task(_fetch_news_signals(client))
        fx_signal, news_signal = await asyncio.gather(fx_task, news_task)

    today = datetime.now(JST)
    forecast: dict[str, Any] = {}
    for metal_key in METAL_COMMANDS.keys():
        prices = _extract_prices(history_by_metal.get(metal_key, []))
        if not prices:
            continue
        metal_news_score = float(news_signal["sentiment"].get(metal_key, 0.0))
        metal_article_count = int(news_signal["article_counts"].get(metal_key, 0))
        forecast[metal_key] = _forecast_for_metal(
            metal_key=metal_key,
            prices=prices,
            horizon_days=horizon_days,
            today=today,
            fx_daily_factor=float(fx_signal.get("daily_factor", 0.0)),
            news_score=metal_news_score,
            article_count=metal_article_count,
            fx_available=bool(fx_signal.get("available")),
        )

    if not forecast:
        raise RuntimeError("予測に必要な価格履歴データがありません。")

    return {
        "timezone": "Asia/Tokyo",
        "as_of_date": today.date().isoformat(),
        "generated_at": today.isoformat(),
        "horizon_days": horizon_days,
        "model": {
            "name": "heuristic_fx_news_v1",
            "description": "直近価格トレンド + USD/JPY + ニュース見出し極性を合成した簡易予測。",
        },
        "signals": {
            "usd_jpy": {
                "available": bool(fx_signal.get("available")),
                "source": fx_signal.get("source", "Stooq"),
                "latest": fx_signal.get("latest"),
                "weekly_change_pct": fx_signal.get("weekly_change_pct", 0.0),
            },
            "news": {
                "available": bool(news_signal.get("available")),
                "source": news_signal.get("source", "Google News RSS"),
                "sentiment": news_signal.get("sentiment", {}),
                "article_counts": news_signal.get("article_counts", {}),
                "sample_headlines": news_signal.get("sample_headlines", {}),
            },
        },
        "forecast": forecast,
    }


def _forecast_payload_from_db(
    *,
    meta: WeeklyForecastMeta,
    rows: list[WeeklyForecastDaily],
) -> dict[str, Any]:
    by_metal: dict[str, list[WeeklyForecastDaily]] = {}
    for row in rows:
        by_metal.setdefault(row.metal_key, []).append(row)

    forecast: dict[str, Any] = {}
    for metal_key, metal_rows in by_metal.items():
        sorted_rows = sorted(metal_rows, key=lambda row: row.forecast_date)
        first = sorted_rows[0]
        daily = [
            {
                "date": row.forecast_date.isoformat(),
                "price_per_gram": float(row.price_per_gram),
                "delta_from_previous": float(row.delta_from_previous) if row.delta_from_previous is not None else None,
            }
            for row in sorted_rows
        ]
        forecast[metal_key] = {
            "start_price_per_gram": float(first.start_price_per_gram),
            "projected_price_per_gram": float(first.projected_price_per_gram),
            "projected_change_pct_7d": float(first.projected_change_pct_7d),
            "confidence": float(first.confidence),
            "implied_daily_return_pct": float(first.implied_daily_return_pct),
            "daily": daily,
            "drivers": _json_loads(first.drivers_json, []),
        }

    return {
        "timezone": "Asia/Tokyo",
        "as_of_date": meta.as_of_date.isoformat(),
        "generated_at": meta.generated_at.isoformat(),
        "horizon_days": int(meta.horizon_days),
        "model": {
            "name": meta.model_name,
            "description": meta.model_description,
        },
        "signals": {
            "usd_jpy": {
                "available": bool(meta.usd_jpy_available),
                "source": meta.usd_jpy_source,
                "latest": float(meta.usd_jpy_latest) if meta.usd_jpy_latest is not None else None,
                "weekly_change_pct": float(meta.usd_jpy_weekly_change_pct) if meta.usd_jpy_weekly_change_pct is not None else 0.0,
            },
            "news": {
                "available": bool(meta.news_available),
                "source": meta.news_source,
                "sentiment": _json_loads(meta.news_sentiment_json, {}),
                "article_counts": _json_loads(meta.news_article_counts_json, {}),
                "sample_headlines": _json_loads(meta.news_headlines_json, {}),
            },
        },
        "forecast": forecast,
    }


def _trim_payload_to_days(payload: dict[str, Any], days: int) -> dict[str, Any]:
    horizon = int(payload.get("horizon_days", 7))
    if days >= horizon:
        return payload

    trimmed = json.loads(_json_dumps(payload))
    trimmed["horizon_days"] = days
    for metal_key, item in (trimmed.get("forecast", {}) or {}).items():
        daily = list(item.get("daily", []))[:days]
        item["daily"] = daily
        if not daily:
            continue
        item["projected_price_per_gram"] = daily[-1].get("price_per_gram")
        start_price = _safe_float(item.get("start_price_per_gram"))
        projected = _safe_float(item.get("projected_price_per_gram"))
        if start_price and projected:
            projected_change = ((projected - start_price) / start_price) * 100
            item["projected_change_pct_7d"] = round(projected_change, 3)
    return trimmed


async def load_stored_weekly_forecast(session: AsyncSession, *, days: int = 7) -> dict[str, Any] | None:
    meta = (
        await session.scalars(
            select(WeeklyForecastMeta).order_by(WeeklyForecastMeta.generated_at.desc())
        )
    ).first()
    if meta is None:
        return None

    rows = list(
        (
            await session.scalars(
                select(WeeklyForecastDaily).where(WeeklyForecastDaily.as_of_date == meta.as_of_date)
            )
        ).all()
    )
    if not rows:
        return None

    payload = _forecast_payload_from_db(meta=meta, rows=rows)
    return _trim_payload_to_days(payload, days=days)


async def store_weekly_forecast(
    session: AsyncSession,
    payload: dict[str, Any],
    *,
    horizon_days: int = 7,
) -> None:
    as_of_raw = payload.get("as_of_date")
    if not isinstance(as_of_raw, str):
        raise RuntimeError("as_of_date が予測payloadに存在しません。")
    as_of_date = date.fromisoformat(as_of_raw)
    horizon = max(1, min(horizon_days, int(payload.get("horizon_days", horizon_days))))
    horizon_end = as_of_date + timedelta(days=horizon)

    desired: dict[tuple[str, date], dict[str, Any]] = {}
    forecast_map = payload.get("forecast", {}) if isinstance(payload.get("forecast"), dict) else {}
    for metal_key, item in forecast_map.items():
        if metal_key not in METAL_COMMANDS:
            continue
        daily = item.get("daily", []) if isinstance(item.get("daily"), list) else []
        for daily_item in daily:
            forecast_date_raw = daily_item.get("date")
            if not isinstance(forecast_date_raw, str):
                continue
            forecast_date = date.fromisoformat(forecast_date_raw)
            if forecast_date <= as_of_date or forecast_date > horizon_end:
                continue
            desired[(metal_key, forecast_date)] = {
                "as_of_date": as_of_date,
                "start_price_per_gram": _as_decimal(item.get("start_price_per_gram"), PRICE_SCALE),
                "projected_price_per_gram": _as_decimal(item.get("projected_price_per_gram"), PRICE_SCALE),
                "price_per_gram": _as_decimal(daily_item.get("price_per_gram"), PRICE_SCALE),
                "delta_from_previous": _as_decimal(daily_item.get("delta_from_previous"), PRICE_SCALE),
                "projected_change_pct_7d": _as_decimal(item.get("projected_change_pct_7d"), PCT_SCALE),
                "confidence": _as_decimal(item.get("confidence"), PCT_SCALE),
                "implied_daily_return_pct": _as_decimal(item.get("implied_daily_return_pct"), PCT_SCALE),
                "drivers_json": _json_dumps(item.get("drivers", [])),
            }

    if not desired:
        raise RuntimeError("保存可能な予測データがありません。")

    existing_rows = list((await session.scalars(select(WeeklyForecastDaily))).all())
    existing_by_key = {(row.metal_key, row.forecast_date): row for row in existing_rows}

    for row_key, row_payload in desired.items():
        metal_key, forecast_date = row_key
        row = existing_by_key.get(row_key)
        if row is None:
            row = WeeklyForecastDaily(metal_key=metal_key, forecast_date=forecast_date)
            session.add(row)
        row.as_of_date = row_payload["as_of_date"]
        row.start_price_per_gram = row_payload["start_price_per_gram"] or Decimal("0")
        row.projected_price_per_gram = row_payload["projected_price_per_gram"] or Decimal("0")
        row.price_per_gram = row_payload["price_per_gram"] or Decimal("0")
        row.delta_from_previous = row_payload["delta_from_previous"]
        row.projected_change_pct_7d = row_payload["projected_change_pct_7d"] or Decimal("0")
        row.confidence = row_payload["confidence"] or Decimal("0")
        row.implied_daily_return_pct = row_payload["implied_daily_return_pct"] or Decimal("0")
        row.drivers_json = row_payload["drivers_json"]

    for row in existing_rows:
        if (row.metal_key, row.forecast_date) not in desired:
            await session.delete(row)

    generated_at_raw = payload.get("generated_at")
    generated_at = datetime.now(JST)
    if isinstance(generated_at_raw, str):
        try:
            generated_at = datetime.fromisoformat(generated_at_raw)
        except ValueError:
            pass

    meta = (await session.scalars(select(WeeklyForecastMeta).order_by(WeeklyForecastMeta.id.asc()))).first()
    if meta is None:
        meta = WeeklyForecastMeta()
        session.add(meta)

    model_data = payload.get("model", {}) if isinstance(payload.get("model"), dict) else {}
    signal_data = payload.get("signals", {}) if isinstance(payload.get("signals"), dict) else {}
    usd_jpy = signal_data.get("usd_jpy", {}) if isinstance(signal_data.get("usd_jpy"), dict) else {}
    news = signal_data.get("news", {}) if isinstance(signal_data.get("news"), dict) else {}

    meta.as_of_date = as_of_date
    meta.generated_at = generated_at
    meta.horizon_days = horizon
    meta.model_name = str(model_data.get("name", "heuristic_fx_news_v1"))
    meta.model_description = str(
        model_data.get("description", "直近価格トレンド + USD/JPY + ニュース見出し極性を合成した簡易予測。")
    )
    meta.usd_jpy_available = bool(usd_jpy.get("available"))
    meta.usd_jpy_source = str(usd_jpy.get("source", "Stooq"))
    meta.usd_jpy_latest = _as_decimal(usd_jpy.get("latest"), Decimal("0.000001"))
    meta.usd_jpy_weekly_change_pct = _as_decimal(usd_jpy.get("weekly_change_pct"), Decimal("0.000001"))
    meta.news_available = bool(news.get("available"))
    meta.news_source = str(news.get("source", "Google News RSS"))
    meta.news_sentiment_json = _json_dumps(news.get("sentiment", {}))
    meta.news_article_counts_json = _json_dumps(news.get("article_counts", {}))
    meta.news_headlines_json = _json_dumps(news.get("sample_headlines", {}))

    # 念のため古いメタ行が複数残っている場合は最新1件以外を削除する。
    await session.flush()
    await session.execute(delete(WeeklyForecastMeta).where(WeeklyForecastMeta.id != meta.id))
    await session.commit()


async def refresh_weekly_forecast_cache(
    session: AsyncSession,
    *,
    horizon_days: int = 7,
) -> dict[str, Any]:
    payload = await build_weekly_forecast(session, horizon_days=horizon_days)
    await store_weekly_forecast(session, payload, horizon_days=horizon_days)
    return payload
