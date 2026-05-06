import asyncio
import logging
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any

import aiohttp
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS

from .forecast_models import (
    FORECAST_SARIMAX_ENABLED,
    FORECAST_SARIMAX_MIN_HISTORY,
    SARIMAX_AVAILABLE,
    extract_prices,
    forecast_for_metal,
)
from .forecast_signals import (
    FORECAST_LLM_MODEL,
    FORECAST_LLM_TIMEOUT_SECONDS,
    fetch_llm_signal,
    fetch_news_signals,
    fetch_usdjpy_signal,
)
from .forecast_utils import PCT_SCALE, PRICE_SCALE, as_decimal, json_dumps, json_loads, safe_float
from .models import WeeklyForecastDaily, WeeklyForecastMeta
from .snapshot_service import JST, load_history

logger = logging.getLogger(__name__)


async def build_weekly_forecast(session: AsyncSession, *, horizon_days: int = 7) -> dict[str, Any]:
    history_window_days = max(45, horizon_days * 8)
    history_by_metal = await load_history(session, history_window_days)

    timeout = aiohttp.ClientTimeout(
        total=max(FORECAST_LLM_TIMEOUT_SECONDS + 10, 30),
        connect=8,
        sock_read=max(FORECAST_LLM_TIMEOUT_SECONDS, 20),
    )
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as client:
        fx_task = asyncio.create_task(fetch_usdjpy_signal(client))
        news_task = asyncio.create_task(fetch_news_signals(client))
        fx_signal, news_signal = await asyncio.gather(fx_task, news_task)
        llm_signal = await fetch_llm_signal(
            history_by_metal=history_by_metal,
            fx_signal=fx_signal,
            news_signal=news_signal,
        )

    today = datetime.now(JST)
    forecast: dict[str, Any] = {}
    for metal_key in METAL_COMMANDS.keys():
        prices = extract_prices(history_by_metal.get(metal_key, []))
        if not prices:
            continue
        forecast[metal_key] = forecast_for_metal(
            metal_key=metal_key,
            prices=prices,
            horizon_days=horizon_days,
            today=today,
            fx_daily_factor=float(fx_signal.get("daily_factor", 0.0)),
            fx_history_returns=[
                safe_float(value) or 0.0
                for value in list(fx_signal.get("daily_returns", []) or [])
            ],
            news_score=float(news_signal["sentiment"].get(metal_key, 0.0)),
            article_count=int(news_signal["article_counts"].get(metal_key, 0)),
            fx_available=bool(fx_signal.get("available")),
            llm_score=float((llm_signal.get("scores", {}) or {}).get(metal_key, 0.0)),
            llm_confidence=float((llm_signal.get("confidences", {}) or {}).get(metal_key, 0.0)),
            llm_rationale=str((llm_signal.get("rationales", {}) or {}).get(metal_key, "")),
            llm_available=bool(llm_signal.get("available")),
        )

    if not forecast:
        raise RuntimeError("予測に必要な価格履歴データがありません。")

    uses_sarimax = any(
        item.get("model_variant") == "sarimax_fused_v1"
        for item in forecast.values()
        if isinstance(item, dict)
    )
    model_name = "sarimax_fused_v1" if uses_sarimax else "heuristic_fx_news_v1"
    model_description = (
        "USD/JPY・ニュース・AIを合算した外生シグナルを含むSARIMAX予測。"
        if uses_sarimax
        else "直近価格トレンド + USD/JPY + ニュース見出し極性を合成した簡易予測。"
    )

    return {
        "timezone": "Asia/Tokyo",
        "as_of_date": today.date().isoformat(),
        "generated_at": today.isoformat(),
        "horizon_days": horizon_days,
        "model": {"name": model_name, "description": model_description},
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
            "llm": {
                "available": bool(llm_signal.get("available")),
                "source": llm_signal.get("source", "OpenAI Chat Completions"),
                "model": llm_signal.get("model", FORECAST_LLM_MODEL),
                "scores": llm_signal.get("scores", {}),
                "confidences": llm_signal.get("confidences", {}),
                "rationales": llm_signal.get("rationales", {}),
                "global_comment": llm_signal.get("global_comment", ""),
            },
            "stat_model": {
                "enabled": FORECAST_SARIMAX_ENABLED,
                "available": SARIMAX_AVAILABLE,
                "min_history": FORECAST_SARIMAX_MIN_HISTORY,
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
            "drivers": json_loads(first.drivers_json, []),
        }

    headlines_payload = json_loads(meta.news_headlines_json, {})
    if isinstance(headlines_payload, dict) and "sample_headlines" in headlines_payload:
        sample_headlines = headlines_payload.get("sample_headlines") or {}
        llm_payload = headlines_payload.get("llm") or {}
        stat_model_payload = headlines_payload.get("stat_model") or {}
    else:
        sample_headlines = headlines_payload if isinstance(headlines_payload, dict) else {}
        llm_payload = {}
        stat_model_payload = {}

    if not llm_payload:
        llm_payload = {
            "available": False,
            "source": "OpenAI Chat Completions",
            "model": FORECAST_LLM_MODEL,
            "scores": {},
            "confidences": {},
            "rationales": {},
            "global_comment": "",
        }
    if not stat_model_payload:
        stat_model_payload = {
            "enabled": FORECAST_SARIMAX_ENABLED,
            "available": SARIMAX_AVAILABLE,
            "min_history": FORECAST_SARIMAX_MIN_HISTORY,
        }

    return {
        "timezone": "Asia/Tokyo",
        "as_of_date": meta.as_of_date.isoformat(),
        "generated_at": meta.generated_at.isoformat(),
        "horizon_days": int(meta.horizon_days),
        "model": {"name": meta.model_name, "description": meta.model_description},
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
                "sentiment": json_loads(meta.news_sentiment_json, {}),
                "article_counts": json_loads(meta.news_article_counts_json, {}),
                "sample_headlines": sample_headlines,
            },
            "llm": llm_payload,
            "stat_model": stat_model_payload,
        },
        "forecast": forecast,
    }


def _trim_payload_to_days(payload: dict[str, Any], days: int) -> dict[str, Any]:
    horizon = int(payload.get("horizon_days", 7))
    if days >= horizon:
        return payload

    trimmed = json_loads(json_dumps(payload), {})
    trimmed["horizon_days"] = days
    for metal_key, item in (trimmed.get("forecast", {}) or {}).items():
        daily = list(item.get("daily", []))[:days]
        item["daily"] = daily
        if not daily:
            continue
        item["projected_price_per_gram"] = daily[-1].get("price_per_gram")
        start_price = safe_float(item.get("start_price_per_gram"))
        projected = safe_float(item.get("projected_price_per_gram"))
        if start_price and projected:
            item["projected_change_pct_7d"] = round(((projected - start_price) / start_price) * 100, 3)
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
                "start_price_per_gram": as_decimal(item.get("start_price_per_gram"), PRICE_SCALE),
                "projected_price_per_gram": as_decimal(item.get("projected_price_per_gram"), PRICE_SCALE),
                "price_per_gram": as_decimal(daily_item.get("price_per_gram"), PRICE_SCALE),
                "delta_from_previous": as_decimal(daily_item.get("delta_from_previous"), PRICE_SCALE),
                "projected_change_pct_7d": as_decimal(item.get("projected_change_pct_7d"), PCT_SCALE),
                "confidence": as_decimal(item.get("confidence"), PCT_SCALE),
                "implied_daily_return_pct": as_decimal(item.get("implied_daily_return_pct"), PCT_SCALE),
                "drivers_json": json_dumps(item.get("drivers", [])),
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
    llm = signal_data.get("llm", {}) if isinstance(signal_data.get("llm"), dict) else {}
    stat_model = signal_data.get("stat_model", {}) if isinstance(signal_data.get("stat_model"), dict) else {}

    meta.as_of_date = as_of_date
    meta.generated_at = generated_at
    meta.horizon_days = horizon
    meta.model_name = str(model_data.get("name", "heuristic_fx_news_v1"))
    meta.model_description = str(model_data.get("description", "直近価格トレンド + USD/JPY + ニュース見出し極性を合成した簡易予測。"))
    meta.usd_jpy_available = bool(usd_jpy.get("available"))
    meta.usd_jpy_source = str(usd_jpy.get("source", "Stooq"))
    meta.usd_jpy_latest = as_decimal(usd_jpy.get("latest"), Decimal("0.000001"))
    meta.usd_jpy_weekly_change_pct = as_decimal(usd_jpy.get("weekly_change_pct"), Decimal("0.000001"))
    meta.news_available = bool(news.get("available"))
    meta.news_source = str(news.get("source", "Google News RSS"))
    meta.news_sentiment_json = json_dumps(news.get("sentiment", {}))
    meta.news_article_counts_json = json_dumps(news.get("article_counts", {}))
    meta.news_headlines_json = json_dumps({
        "sample_headlines": news.get("sample_headlines", {}),
        "llm": {
            "available": bool(llm.get("available")),
            "source": str(llm.get("source", "OpenAI Chat Completions")),
            "model": str(llm.get("model", FORECAST_LLM_MODEL)),
            "scores": llm.get("scores", {}),
            "confidences": llm.get("confidences", {}),
            "rationales": llm.get("rationales", {}),
            "global_comment": str(llm.get("global_comment", "")),
        },
        "stat_model": {
            "enabled": bool(stat_model.get("enabled", FORECAST_SARIMAX_ENABLED)),
            "available": bool(stat_model.get("available", SARIMAX_AVAILABLE)),
            "min_history": int(safe_float(stat_model.get("min_history")) or FORECAST_SARIMAX_MIN_HISTORY),
        },
    })

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
