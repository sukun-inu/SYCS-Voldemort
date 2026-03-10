import asyncio
import logging
import math
from datetime import datetime, timedelta
from statistics import pstdev
from typing import Any
from urllib.parse import quote_plus
from xml.etree import ElementTree

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS

from .snapshot_service import JST, load_history

logger = logging.getLogger(__name__)

USDJPY_DAILY_CSV_URL = "https://stooq.com/q/d/l/?s=usdjpy&i=d"
GOOGLE_NEWS_RSS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"

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
