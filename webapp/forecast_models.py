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


# 為替βを実データから推定する際の設定。推定は「金属の日次リターンをUSD/JPYの日次
# リターンで回帰したときの傾き(OLSのβ)」で、共通日が足りない/分散がほぼ0の場合は
# 下の既定値へフォールバックする。極端な推定値で予測が暴れないよう範囲も制限する。
FX_BETA_MIN_SAMPLES = max(20, int(os.getenv("FORECAST_FX_BETA_MIN_SAMPLES", "40")))
FX_BETA_BOUNDS = (-0.5, 1.5)

# 直近の平均絶対誤差(MAE%)を信頼度へ反映するための閾値。
# GOOD以下なら加点、BAD以上なら大きく減点し、間は線形補間する。
FORECAST_ACCURACY_GOOD_MAE_PCT = max(0.1, float(os.getenv("FORECAST_ACCURACY_GOOD_MAE_PCT", "1.5")))
FORECAST_ACCURACY_BAD_MAE_PCT = max(
    FORECAST_ACCURACY_GOOD_MAE_PCT + 0.1, float(os.getenv("FORECAST_ACCURACY_BAD_MAE_PCT", "6.0"))
)
FORECAST_ACCURACY_MAX_BONUS = 0.05
FORECAST_ACCURACY_MAX_PENALTY = 0.30
# 答え合わせ実績がまだ無い状態で高い信頼度を出すのは過信なので上限を設ける。
FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY = min(
    0.95, max(0.3, float(os.getenv("FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY", "0.75")))
)


def extract_price_series(history_items: list[dict[str, Any]]) -> list[tuple[str, float]]:
    """(日付, 価格) の並びを返す。extract_pricesと違い日付を保持するため、
    為替リターンとの日付突き合わせ(β推定・exog整列)に使える。"""
    series: list[tuple[str, float]] = []
    for item in history_items:
        value = safe_float(item.get("price_per_gram"))
        date_str = item.get("date")
        if value is None or value <= 0 or not isinstance(date_str, str):
            continue
        series.append((date_str, value))
    return series


def daily_returns_by_date(series: list[tuple[str, float]]) -> dict[str, float]:
    """(日付, 価格) 列から日次リターンを日付キーで返す。"""
    returns: dict[str, float] = {}
    for (_, previous), (current_date, current) in zip(series, series[1:]):
        if previous > 0:
            returns[current_date] = (current - previous) / previous
    return returns


def estimate_fx_beta(
    metal_returns: dict[str, float],
    fx_returns: dict[str, float],
    *,
    fallback: float,
) -> tuple[float, int]:
    """金属リターン ~ USD/JPYリターン のOLS傾き(β)を推定する。

    戻り値は (beta, 推定に使ったサンプル数)。サンプル不足や為替側の分散がほぼ0の
    場合は fallback をそのまま返す(サンプル数0)。
    """
    common_dates = sorted(set(metal_returns) & set(fx_returns))
    if len(common_dates) < FX_BETA_MIN_SAMPLES:
        return fallback, 0

    xs = [fx_returns[d] for d in common_dates]
    ys = [metal_returns[d] for d in common_dates]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    variance = sum((x - mean_x) ** 2 for x in xs)
    if variance <= 1e-12:
        return fallback, 0
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    beta = covariance / variance
    if not math.isfinite(beta):
        return fallback, 0
    return clamp(beta, *FX_BETA_BOUNDS), n


def accuracy_confidence_adjustment(mae_pct: float | None) -> float:
    """直近の平均絶対誤差(%)から信頼度の補正値を求める。

    実績が無い(None)場合は0を返し、呼び出し側で別途上限を掛ける。
    """
    if mae_pct is None or not math.isfinite(mae_pct) or mae_pct < 0:
        return 0.0
    if mae_pct <= FORECAST_ACCURACY_GOOD_MAE_PCT:
        return FORECAST_ACCURACY_MAX_BONUS
    if mae_pct >= FORECAST_ACCURACY_BAD_MAE_PCT:
        return -FORECAST_ACCURACY_MAX_PENALTY
    span = FORECAST_ACCURACY_BAD_MAE_PCT - FORECAST_ACCURACY_GOOD_MAE_PCT
    ratio = (mae_pct - FORECAST_ACCURACY_GOOD_MAE_PCT) / span
    return FORECAST_ACCURACY_MAX_BONUS - ratio * (FORECAST_ACCURACY_MAX_BONUS + FORECAST_ACCURACY_MAX_PENALTY)


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
    news_score: float,
    article_count: int,
    fx_available: bool,
    llm_score: float,
    llm_confidence: float,
    llm_rationale: str,
    llm_available: bool,
    price_dates: list[str] | None = None,
    fx_returns_by_date: dict[str, float] | None = None,
    recent_mae_pct: float | None = None,
) -> dict[str, Any]:
    start_price = prices[-1]
    trend = daily_trend(prices)
    volatility = daily_volatility(prices)

    # --- 為替β: 実データから推定し、無理ならハードコードの既定値へフォールバック ---
    fallback_beta = FX_BETA_BY_METAL.get(metal_key, 0.35)
    fx_returns_by_date = fx_returns_by_date or {}
    metal_returns: dict[str, float] = {}
    if price_dates and len(price_dates) == len(prices):
        metal_returns = daily_returns_by_date(list(zip(price_dates, prices)))
    fx_beta, beta_samples = estimate_fx_beta(metal_returns, fx_returns_by_date, fallback=fallback_beta)

    fx_component = fx_daily_factor * fx_beta
    news_component = news_score * 0.0025
    llm_component = llm_score * llm_confidence * FORECAST_LLM_WEIGHT
    signal_component = fx_component + news_component + llm_component
    heuristic_daily_return = clamp((trend * 0.60) + signal_component, -0.04, 0.04)

    # --- exog: 金属側の日次リターン列に日付で揃える(為替が無い日は0) ---
    # ECBは平日のみ公表で金属スナップショットは毎日あるため、位置合わせではズレる。
    history_steps = max(0, len(prices) - 1)
    if price_dates and len(price_dates) == len(prices):
        fx_hist = [fx_returns_by_date.get(date_str, 0.0) for date_str in price_dates[1:]]
    else:
        fx_hist = [0.0] * history_steps
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

    # --- 信頼度 ---
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

    # 以前の信頼度は「入力データが揃っているか」しか見ておらず、実際に当たったかどうかが
    # 一切反映されていなかった(大きく外していても95%と表示され得た)。答え合わせ済みの
    # 直近MAEを反映し、実績が無いうちは上限を掛けて過信を防ぐ。
    accuracy_adjustment = accuracy_confidence_adjustment(recent_mae_pct)
    confidence += accuracy_adjustment
    if recent_mae_pct is None:
        confidence = min(confidence, FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY)
    confidence = clamp(confidence, 0.1, 0.95)

    # --- 根拠の内訳 ---
    # role の意味:
    #   primary   … 実際に予測値を決めた要因
    #   signal    … 予測へ寄与した入力シグナル
    #   reference … 参考値。今回の計算には直接効いていない
    # SARIMAX使用時は統計モデルの出力がそのまま予測値になり、直近トレンドはモデル内部の
    # ARMA項が別途推定するため「参考値」に落ちる。ここを混ぜて表示していたせいで
    # 「箇条書きは全部プラスなのに予測はマイナス」という誤解が生じていた。
    breakdown: list[dict[str, Any]] = []
    if uses_stat_model and stat_returns:
        avg_baseline = sum(stat_returns) / len(stat_returns)
        breakdown.append({
            "label": "統計モデル(SARIMAX)",
            "value_pct_per_day": round(avg_baseline * 100, 3),
            "role": "primary",
            "detail": "この値がそのまま予測値になります",
        })
    else:
        breakdown.append({
            "label": "直近トレンド(統計モデル未使用のため主因)",
            "value_pct_per_day": round(trend * 0.60 * 100, 3),
            "role": "primary",
            "detail": "統計モデルを使えないためトレンドから直接算出しています",
        })

    beta_detail = (
        f"β={fx_beta:.3f}(直近{beta_samples}日の実データから推定)"
        if beta_samples
        else f"β={fx_beta:.3f}(既定値。推定に必要なデータが不足)"
    )
    signal_rows: list[dict[str, Any]] = [
        {
            "label": "USD/JPY感応",
            "value_pct_per_day": round(fx_component * 100, 3),
            "role": "signal",
            "detail": beta_detail,
        },
        {
            "label": "ニュース感応",
            "value_pct_per_day": round(news_component * 100, 3),
            "role": "signal",
            "detail": f"見出しスコア {news_score:+.3f} / {article_count}件",
        },
        {
            "label": "AI判定感応",
            "value_pct_per_day": round(llm_component * 100, 3),
            "role": "signal",
            "detail": f"スコア {llm_score:+.3f} / 確信度 {llm_confidence:.3f}",
        },
    ]
    # 寄与の大きい順に並べ、どれが効いているかを一目で分かるようにする。
    signal_rows.sort(key=lambda row: abs(row["value_pct_per_day"]), reverse=True)
    breakdown.extend(signal_rows)

    if uses_stat_model:
        breakdown.append({
            "label": "直近トレンド",
            "value_pct_per_day": round(trend * 100, 3),
            "role": "reference",
            "detail": "参考値。統計モデルが別途推定するため予測値には直接効いていません",
        })

    if recent_mae_pct is not None:
        breakdown.append({
            "label": "直近14日の平均誤差",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": f"{recent_mae_pct:.2f}%(信頼度を {accuracy_adjustment:+.2f} 補正)",
        })
    else:
        breakdown.append({
            "label": "答え合わせ実績",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": f"まだ無し(信頼度の上限を {FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY:.0%} に制限)",
        })

    if llm_rationale:
        breakdown.append({
            "label": "AI判定所見",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": llm_rationale,
        })

    # 旧フォーマット(文字列の箇条書き)も、古いキャッシュとの互換と要約プロンプト用に維持する。
    drivers: list[str] = []
    for row in breakdown:
        value = row["value_pct_per_day"]
        prefix = f"{value:+.3f}%/日 " if value is not None else ""
        drivers.append(f"{row['label']}: {prefix}({row['detail']})")

    return {
        "start_price_per_gram": round(start_price, 2),
        "projected_price_per_gram": round(current, 2),
        "projected_change_pct_7d": round(projected_change * 100, 3),
        "confidence": round(confidence, 3),
        "implied_daily_return_pct": round(effective_daily_return * 100, 4),
        "model_variant": "sarimax_fused_v1" if uses_stat_model else "heuristic_fx_news_v1",
        "fx_beta": round(fx_beta, 4),
        "fx_beta_samples": beta_samples,
        "daily": daily,
        "drivers": drivers,
        "driver_breakdown": breakdown,
    }
