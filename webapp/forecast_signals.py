import asyncio
import logging
import math
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote_plus
from xml.etree import ElementTree

import aiohttp

from groq import AsyncGroq

from config import GROQ_API_KEY, METAL_COMMANDS
from .forecast_utils import (
    GOOGLE_NEWS_RSS_URL,
    USDJPY_TIMESERIES_BASE_URL,
    clip_text,
    clamp,
    extract_first_json_object,
    json_dumps,
    read_env_bool,
    safe_float,
)
from .forecast_models import daily_trend, daily_volatility, extract_prices

logger = logging.getLogger(__name__)

_groq_client: AsyncGroq | None = None


def _get_groq_client(timeout: float) -> AsyncGroq:
    global _groq_client
    if _groq_client is None:
        _groq_client = AsyncGroq(api_key=GROQ_API_KEY, timeout=timeout)
    return _groq_client


FORECAST_LLM_ENABLED = read_env_bool("FORECAST_LLM_ENABLED", True)
FORECAST_LLM_MODEL = (os.getenv("FORECAST_LLM_MODEL") or "openai/gpt-oss-120b").strip() or "openai/gpt-oss-120b"
FORECAST_LLM_TIMEOUT_SECONDS = max(8, int(os.getenv("FORECAST_LLM_TIMEOUT_SECONDS", "20")))

NEWS_QUERY_BY_METAL = {
    "gold": "gold price xau bullion federal reserve inflation usd jpy",
    "silver": "silver price xag bullion industrial demand usd jpy",
    "platinum": "platinum price xpt auto catalyst industrial demand usd jpy",
}

# 検索クエリが英語のみのため、ここも英語トークンのみとする(日本語記事はほぼヒットしないため
# 日本語トークンは実質死んでいた)。"up"/"down"のような短い語は単語境界で囲まないと
# support/upgrade/breakdown 等の無関係な語に部分一致してしまうため、_news_score側で
# 正規表現の単語境界(\b)マッチに統一している。
POSITIVE_TOKENS = (
    "surge", "rise", "rises", "up", "gain", "gains", "record high", "bullish",
    "safe haven", "demand jumps", "demand grows", "weaker dollar", "dollar weakens",
    "rate cut", "rate cuts", "cuts rates", "inflation fears", "recession fears",
)

NEGATIVE_TOKENS = (
    "fall", "falls", "drop", "drops", "down", "loss", "losses", "bearish", "selloff",
    "strong dollar", "dollar strengthens", "yields rise", "yields rising", "rate hike", "rate hikes",
)


def _compile_token_pattern(token: str) -> "re.Pattern[str]":
    # 複数語のトークンは語順通り・単語境界つきでマッチさせる(部分文字列マッチの誤検出を防ぐ)。
    words = [re.escape(word) for word in token.split()]
    return re.compile(r"\b" + r"\s+".join(words) + r"\b")


_POSITIVE_PATTERNS = [_compile_token_pattern(token) for token in POSITIVE_TOKENS]
_NEGATIVE_PATTERNS = [_compile_token_pattern(token) for token in NEGATIVE_TOKENS]


_USDJPY_SOURCE_NAME = "Frankfurter (ECB)"


def _empty_usdjpy_signal() -> dict[str, Any]:
    return {
        "available": False,
        "source": _USDJPY_SOURCE_NAME,
        "latest": None,
        "weekly_change_pct": 0.0,
        "daily_factor": 0.0,
        "daily_returns": [],
    }


async def fetch_usdjpy_signal(session: aiohttp.ClientSession) -> dict[str, Any]:
    # ECBは平日のみレートを発表するため、直近1週間の変化率(6営業日前との比較)を安全に
    # 取れるよう45日分の範囲で取得する。
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=45)
    url = f"{USDJPY_TIMESERIES_BASE_URL}/{start.isoformat()}..{today.isoformat()}?from=USD&to=JPY"

    try:
        async with session.get(url) as response:
            if response.status != 200:
                raise RuntimeError(f"status={response.status}")
            payload = await response.json(content_type=None)
    except Exception as exc:
        logger.warning("USD/JPYデータ取得に失敗: %s", exc)
        return _empty_usdjpy_signal()

    rates = payload.get("rates") if isinstance(payload, dict) else None
    if not isinstance(rates, dict) or not rates:
        logger.warning("USD/JPYデータのレスポンス形式が想定外: %r", payload)
        return _empty_usdjpy_signal()

    closes: list[float] = []
    for date_str in sorted(rates.keys()):
        entry = rates.get(date_str)
        close_value = safe_float(entry.get("JPY")) if isinstance(entry, dict) else None
        if close_value is None or close_value <= 0:
            continue
        closes.append(close_value)

    if len(closes) < 2:
        return _empty_usdjpy_signal()

    latest = closes[-1]
    anchor = closes[-6] if len(closes) >= 6 else closes[0]
    weekly_change = ((latest - anchor) / anchor) if anchor > 0 else 0.0
    daily_factor = weekly_change / 5.0
    daily_returns: list[float] = [
        (current - previous) / previous
        for previous, current in zip(closes, closes[1:])
        if previous > 0
    ]
    return {
        "available": True,
        "source": _USDJPY_SOURCE_NAME,
        "latest": round(latest, 4),
        "weekly_change_pct": round(weekly_change * 100, 3),
        "daily_factor": daily_factor,
        "daily_returns": daily_returns[-240:],
    }


def _news_score(text: str) -> int:
    normalized = text.lower()
    score = sum(1 for pattern in _POSITIVE_PATTERNS if pattern.search(normalized))
    score -= sum(1 for pattern in _NEGATIVE_PATTERNS if pattern.search(normalized))
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
            if response.status != 200:
                raise RuntimeError(f"status={response.status} url={url}")
            body = await response.read()
    except Exception as exc:
        logger.warning("ニュースRSS取得に失敗 query=%s err=%s", query, exc)
        return [], 0.0

    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        logger.warning("ニュースRSSパースに失敗 query=%s err=%s body_head=%r", query, exc, body[:300])
        return [], 0.0

    titles: list[str] = []
    raw_score = 0
    for item in root.findall("./channel/item")[:limit]:
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


async def fetch_news_signals(session: aiohttp.ClientSession) -> dict[str, Any]:
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

    return {
        "available": any(count > 0 for count in article_counts.values()),
        "source": "Google News RSS",
        "sentiment": {key: round(value, 4) for key, value in sentiment.items()},
        "article_counts": article_counts,
        "sample_headlines": sample_headlines,
    }


async def fetch_llm_signal(
    *,
    history_by_metal: dict[str, list[dict[str, Any]]],
    fx_signal: dict[str, Any],
    news_signal: dict[str, Any],
) -> dict[str, Any]:
    _empty = {
        "available": False,
        "source": "Groq",
        "model": FORECAST_LLM_MODEL,
        "scores": {key: 0.0 for key in METAL_COMMANDS.keys()},
        "confidences": {key: 0.0 for key in METAL_COMMANDS.keys()},
        "rationales": {key: "" for key in METAL_COMMANDS.keys()},
    }

    if not FORECAST_LLM_ENABLED:
        return {**_empty, "global_comment": "FORECAST_LLM_ENABLED=false"}
    if not GROQ_API_KEY:
        return {**_empty, "global_comment": "GROQ_API_KEY not configured"}

    metal_input: dict[str, Any] = {}
    for metal_key in METAL_COMMANDS.keys():
        prices = extract_prices(history_by_metal.get(metal_key, []))
        headlines = list((news_signal.get("sample_headlines", {}) or {}).get(metal_key, []))[:4]
        metal_input[metal_key] = {
            "latest_price_per_gram": round(prices[-1], 2) if prices else None,
            "trend_14d_pct_per_day": round(daily_trend(prices) * 100, 4) if prices else 0.0,
            "volatility_14d_pct": round(daily_volatility(prices) * 100, 4) if prices else 0.0,
            "news_sentiment": float((news_signal.get("sentiment", {}) or {}).get(metal_key, 0.0)),
            "news_article_count": int((news_signal.get("article_counts", {}) or {}).get(metal_key, 0)),
            "headlines": [clip_text(item, 140) for item in headlines],
        }

    user_payload = {
        "fx": {
            "usd_jpy_weekly_change_pct": float(fx_signal.get("weekly_change_pct", 0.0)),
            "usd_jpy_latest": fx_signal.get("latest"),
            "available": bool(fx_signal.get("available")),
        },
        "metals": metal_input,
    }

    system_prompt = (
        "You are a conservative financial signal analyst for precious metals. "
        "Use only provided inputs. Return STRICT JSON only, no markdown. "
        "For each metal (gold, silver, platinum), output sentiment score [-1,1], "
        "confidence [0,1], and a short rationale."
    )
    user_prompt = (
        "Inputs JSON:\n"
        f"{json_dumps(user_payload)}\n"
        "Return JSON schema:\n"
        "{"
        "\"global_comment\":\"...\","
        "\"metals\":{"
        "\"gold\":{\"score\":0.0,\"confidence\":0.0,\"rationale\":\"...\"},"
        "\"silver\":{\"score\":0.0,\"confidence\":0.0,\"rationale\":\"...\"},"
        "\"platinum\":{\"score\":0.0,\"confidence\":0.0,\"rationale\":\"...\"}"
        "}"
        "}"
    )

    try:
        response = await _get_groq_client(float(FORECAST_LLM_TIMEOUT_SECONDS)).chat.completions.create(
            model=FORECAST_LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.15,
            max_tokens=420,
        )
        content = response.choices[0].message.content or ""
    except Exception as exc:
        logger.warning("LLM予測判定の取得に失敗: %s", exc)
        return {**_empty, "global_comment": "LLM call failed"}
    parsed = extract_first_json_object(str(content)) or {}
    metal_result = parsed.get("metals", {}) if isinstance(parsed.get("metals"), dict) else {}

    scores: dict[str, float] = {}
    confidences: dict[str, float] = {}
    rationales: dict[str, str] = {}
    for metal_key in METAL_COMMANDS.keys():
        item = metal_result.get(metal_key, {}) if isinstance(metal_result.get(metal_key), dict) else {}
        raw_score = safe_float(item.get("score")) or 0.0
        raw_confidence = safe_float(item.get("confidence")) or 0.0
        rationale = clip_text(str(item.get("rationale", "")).strip(), 140)
        scores[metal_key] = round(clamp(raw_score, -1.0, 1.0), 4)
        confidences[metal_key] = round(clamp(raw_confidence, 0.0, 1.0), 4)
        rationales[metal_key] = rationale

    return {
        "available": True,
        "source": "Groq",
        "model": FORECAST_LLM_MODEL,
        "scores": scores,
        "confidences": confidences,
        "rationales": rationales,
        "global_comment": clip_text(str(parsed.get("global_comment", "")).strip(), 180),
    }
