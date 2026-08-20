import logging
import math
import os
from datetime import datetime, timedelta
from statistics import pstdev
from typing import Any

from .forecast_utils import clamp, safe_float

logger = logging.getLogger(__name__)

try:
    from statsmodels.tsa.statespace.sarimax import SARIMAX  # type: ignore

    SARIMAX_AVAILABLE = True
except Exception:
    SARIMAX = None
    SARIMAX_AVAILABLE = False

FORECAST_SARIMAX_ENABLED = (os.getenv("FORECAST_SARIMAX_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"})
FORECAST_SARIMAX_MIN_HISTORY = max(14, int(os.getenv("FORECAST_SARIMAX_MIN_HISTORY", "24")))

# AI(Groq)判定のスコア×確信度が予測日次リターンにどれだけ反映されるかの係数。
# 以前は0.0035で固定されており、確信度・スコアが最大でも1日あたり最大0.35%しか
# 予測を動かせず、AI判定がほぼ無視される状態だった。既定値を引き上げつつ環境変数で
# 調整可能にする(heuristic_daily_returnのclamp ±4%/日は維持され暴走はしない)。
FORECAST_LLM_WEIGHT = max(0.0, float(os.getenv("FORECAST_LLM_WEIGHT", "0.008")))

FX_BETA_BY_METAL = {
    "gold": 0.30,
    "silver": 0.45,
    "platinum": 0.40,
}


def extract_prices(history_items: list[dict[str, Any]]) -> list[float]:
    prices: list[float] = []
    for item in history_items:
        value = safe_float(item.get("price_per_gram"))
        if value is None or value <= 0:
            continue
        prices.append(value)
    return prices


def daily_trend(prices: list[float], *, window: int = 14) -> float:
    if len(prices) < 2:
        return 0.0
    sampled = prices[-min(window, len(prices)):]
    first, last = sampled[0], sampled[-1]
    if first <= 0:
        return 0.0
    if len(sampled) == 2:
        return clamp((last - first) / first, -0.03, 0.03)
    geometric_daily = (last / first) ** (1.0 / (len(sampled) - 1)) - 1.0
    return clamp(geometric_daily, -0.03, 0.03)


def daily_volatility(prices: list[float], *, window: int = 14) -> float:
    if len(prices) < 3:
        return 0.004
    sampled = prices[-min(window, len(prices)):]
    returns = [
        (current - previous) / previous
        for previous, current in zip(sampled, sampled[1:])
        if previous > 0
    ]
    if not returns:
        return 0.004
    return float(pstdev(returns))


def sarimax_fused_returns(
    prices: list[float],
    horizon_days: int,
    *,
    exog_history: list[float],
    exog_future: list[float],
) -> list[float] | None:
    if not FORECAST_SARIMAX_ENABLED or not SARIMAX_AVAILABLE:
        return None
    if len(prices) < FORECAST_SARIMAX_MIN_HISTORY:
        return None

    log_returns: list[float] = [
        math.log(current / previous)
        for previous, current in zip(prices, prices[1:])
        if previous > 0 and current > 0
    ]

    if len(log_returns) < (FORECAST_SARIMAX_MIN_HISTORY - 1):
        return None

    expected_len = len(log_returns)
    history = list(exog_history[-expected_len:])
    if len(history) < expected_len:
        history = ([0.0] * (expected_len - len(history))) + history
    future = list(exog_future[:horizon_days])
    if len(future) < horizon_days:
        fallback = future[-1] if future else 0.0
        future = future + ([fallback] * (horizon_days - len(future)))

    exog_train = [[value] for value in history]
    exog_forecast = [[value] for value in future]
    seasonal_order = (1, 0, 0, 7) if len(log_returns) >= 21 else (0, 0, 0, 0)
    try:
        model = SARIMAX(
            log_returns,
            exog=exog_train,
            order=(1, 0, 1),
            seasonal_order=seasonal_order,
            trend="c",
            enforce_stationarity=False,
            enforce_invertibility=False,
        )
        fitted = model.fit(disp=False, maxiter=120)
        forecast_returns = fitted.forecast(steps=horizon_days, exog=exog_forecast)
        return [clamp(float(value), -0.06, 0.06) for value in forecast_returns]
    except Exception as exc:
        logger.warning("SARIMAX予測の計算に失敗。heuristicへフォールバック err=%s", exc)
        return None


def forecast_for_metal(
    *,
    metal_key: str,
    prices: list[float],
    horizon_days: int,
    today: datetime,
    fx_daily_factor: float,
    fx_history_returns: list[float],
    news_score: float,
    article_count: int,
    fx_available: bool,
    llm_score: float,
    llm_confidence: float,
    llm_rationale: str,
    llm_available: bool,
) -> dict[str, Any]:
    start_price = prices[-1]
    trend = daily_trend(prices)
    volatility = daily_volatility(prices)

    fx_beta = FX_BETA_BY_METAL.get(metal_key, 0.35)
    fx_component = fx_daily_factor * fx_beta
    news_component = news_score * 0.0025
    llm_component = llm_score * llm_confidence * FORECAST_LLM_WEIGHT
    signal_component = fx_component + news_component + llm_component
    heuristic_daily_return = clamp((trend * 0.60) + signal_component, -0.04, 0.04)

    history_steps = max(0, len(prices) - 1)
    fx_hist = list((fx_history_returns or [])[-history_steps:])
    if len(fx_hist) < history_steps:
        fx_hist = ([0.0] * (history_steps - len(fx_hist))) + fx_hist
    exog_history = [clamp(value * fx_beta, -0.08, 0.08) for value in fx_hist]
    exog_future = [clamp(signal_component, -0.08, 0.08) for _ in range(horizon_days)]

    stat_returns = sarimax_fused_returns(
        prices, horizon_days, exog_history=exog_history, exog_future=exog_future
    )
    uses_stat_model = stat_returns is not None

    daily: list[dict[str, Any]] = []
    projected_returns: list[float] = []
    current = start_price
    for offset in range(1, horizon_days + 1):
        if uses_stat_model and stat_returns is not None:
            projected_return = clamp(stat_returns[offset - 1], -0.05, 0.05)
            next_value = max(0.01, current * math.exp(projected_return))
        else:
            projected_return = heuristic_daily_return
            next_value = max(0.01, current * (1.0 + projected_return))
        projected_returns.append(projected_return)
        forecast_date = (today + timedelta(days=offset)).date().isoformat()
        daily.append({
            "date": forecast_date,
            "price_per_gram": round(next_value, 2),
            "delta_from_previous": round(next_value - current, 2),
        })
        current = next_value

    projected_change = ((current - start_price) / start_price) if start_price > 0 else 0.0
    effective_daily_return = (
        sum(projected_returns) / len(projected_returns) if projected_returns else heuristic_daily_return
    )

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
    if llm_available:
        confidence += 0.07 * clamp(llm_confidence, 0.0, 1.0)
    if uses_stat_model:
        confidence += 0.12
    confidence -= min(0.20, volatility * 6.0)
    if abs(effective_daily_return) > 0.025:
        confidence -= 0.05
    confidence = clamp(confidence, 0.1, 0.95)

    drivers = []
    if uses_stat_model and stat_returns:
        avg_baseline = sum(stat_returns) / len(stat_returns)
        drivers.append(f"統計モデル: SARIMAX(1,0,1)+合算シグナル(exog) {avg_baseline * 100:+.3f}%/日")
        drivers.append(f"合算シグナル入力: {signal_component * 100:+.3f}%/日")
    else:
        drivers.append("統計モデル: ヒューリスティックへフォールバック")
    drivers.extend([
        f"直近トレンド: {trend * 100:+.3f}%/日",
        f"USD/JPY感応: {fx_component * 100:+.3f}%/日",
        f"ニュース感応: {news_component * 100:+.3f}%/日 (score={news_score:+.3f})",
        f"AI判定感応: {llm_component * 100:+.3f}%/日 (score={llm_score:+.3f}, conf={llm_confidence:.3f})",
    ])
    if llm_rationale:
        drivers.append(f"AI判定所見: {llm_rationale}")

    return {
        "start_price_per_gram": round(start_price, 2),
        "projected_price_per_gram": round(current, 2),
        "projected_change_pct_7d": round(projected_change * 100, 3),
        "confidence": round(confidence, 3),
        "implied_daily_return_pct": round(effective_daily_return * 100, 4),
        "model_variant": "sarimax_fused_v1" if uses_stat_model else "heuristic_fx_news_v1",
        "daily": daily,
        "drivers": drivers,
    }
