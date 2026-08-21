"""7日先の価格レンジ(予測区間)を組み立てるモデル。

## なぜ点予測をやめたか

本番の実データでウォークフォワード検証したところ、旧SARIMAXモデルは
「7日後も今日と同じ価格」と言うだけのランダムウォークより明確に劣っていた。

    平均絶対誤差   モデル 5.51%  /  naive 3.37%  /  trend 3.94%
    方向的中率     モデル 40.6%(コイン投げ以下)
    naiveに勝った割合 18.6%

さらに102回中102回すべてマイナス予測になっており、実質「標本期間内のドリフトの
外挿」でしかなかった。ドリフト減衰係数λを較正すると **λ=0(=現在価格をそのまま
中心にする)が最良** で、λを上げるほど単調に悪化した。

そこで点予測をやめ、「現在価格を中心とし、過去の値動きから求めた区間で幅を示す」
モデルに置き換えた。外部シグナル(為替・ニュース・AI判定)は履歴を再現できず
有効性が未検証のため、中心をわずかに傾ける tilt としてのみ残し、影響を
FORECAST_TILT_MAX_PCT_PER_DAY で厳しく制限している。
"""

import logging
import math
import os
from datetime import datetime, timedelta
from statistics import pstdev
from typing import Any

from .forecast_series import (
    build_return_series,
    count_gaps,
    horizon_interval,
    parse_price_history,
    robust_daily_sigma,
)
from .forecast_utils import clamp, safe_float

logger = logging.getLogger(__name__)

MODEL_VARIANT = "interval_rw_v1"

# AI(Groq)判定のスコア×確信度が中心値の傾き(tilt)にどれだけ反映されるかの係数。
FORECAST_LLM_WEIGHT = max(0.0, float(os.getenv("FORECAST_LLM_WEIGHT", "0.008")))

# 中心値の傾きの上限(%/日)。時系列外挿に予測力が無いことは実証済みで、外部シグナルの
# 有効性は未検証のため、中心が現在価格から大きく離れないよう厳しく抑える。
# 既定 0.15%/日 = 7日で約 ±1.05%。
FORECAST_TILT_MAX_PCT_PER_DAY = max(0.0, float(os.getenv("FORECAST_TILT_MAX_PCT_PER_DAY", "0.15"))) / 100.0

# 予測区間の名目確率。既定80%(10%〜90%分位)。
FORECAST_INTERVAL_PROB = min(0.99, max(0.5, float(os.getenv("FORECAST_INTERVAL_PROB", "0.8"))))

# 為替β(金属リターンのUSD/JPY感応度)を実データから推定する際の設定。共通日が足りない
# 場合や為替側の分散がほぼ0の場合は下の既定値へフォールバックする。
FX_BETA_MIN_SAMPLES = max(20, int(os.getenv("FORECAST_FX_BETA_MIN_SAMPLES", "40")))
FX_BETA_BOUNDS = (-0.5, 1.5)

FX_BETA_BY_METAL = {
    "gold": 0.30,
    "silver": 0.45,
    "platinum": 0.40,
}

# 直近の平均絶対誤差(MAE%)を信頼度へ反映するための閾値。
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
# 信頼度を区間の狭さから求めるときの基準。7日の片側幅がこの%なら信頼度への寄与が0になる。
FORECAST_WIDTH_REFERENCE_PCT = max(1.0, float(os.getenv("FORECAST_WIDTH_REFERENCE_PCT", "12.0")))


def extract_prices(history_items: list[dict[str, Any]]) -> list[float]:
    prices: list[float] = []
    for item in history_items:
        value = safe_float(item.get("price_per_gram"))
        if value is None or value <= 0:
            continue
        prices.append(value)
    return prices


def extract_price_series(history_items: list[dict[str, Any]]) -> list[tuple[str, float]]:
    """(日付, 価格) の並びを返す。extract_pricesと違い日付を保持するため、
    為替リターンとの日付突き合わせ(β推定)に使える。"""
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


def coverage_confidence_adjustment(coverage: float | None, *, nominal: float) -> float:
    """区間の実測被覆率が名目からどれだけずれているかを信頼度に反映する。

    被覆率は区間予測にとって最も本質的な品質指標(名目80%なら実測も80%であるべき)。
    ずれが大きいほど減点する。
    """
    if coverage is None or not math.isfinite(coverage):
        return 0.0
    gap = abs(coverage - nominal)
    return -clamp(gap * 0.5, 0.0, 0.15)


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


def forecast_for_metal(
    *,
    metal_key: str,
    history_items: list[dict[str, Any]],
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
    fx_returns_by_date: dict[str, float] | None = None,
    recent_mae_pct: float | None = None,
    recent_coverage: float | None = None,
    tilt_effect: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """1金属ぶんの予測レンジを組み立てる。履歴が足りなければ None。"""
    dated_series = parse_price_history(history_items)
    if len(dated_series) < 2:
        return None

    prices = [price for _, price in dated_series]
    start_price = prices[-1]
    returns = build_return_series(dated_series)
    if not returns:
        return None

    sigma = robust_daily_sigma(returns)
    gaps = count_gaps(dated_series)

    # --- 為替β: 実データから推定し、無理ならハードコードの既定値へフォールバック ---
    fallback_beta = FX_BETA_BY_METAL.get(metal_key, 0.35)
    fx_returns_by_date = fx_returns_by_date or {}
    str_series = [(d.isoformat(), p) for d, p in dated_series]
    metal_returns = daily_returns_by_date(str_series)
    fx_beta, beta_samples = estimate_fx_beta(metal_returns, fx_returns_by_date, fallback=fallback_beta)

    # --- 中心値の傾き(tilt) ---
    fx_component = fx_daily_factor * fx_beta
    news_component = news_score * 0.0025
    llm_component = llm_score * llm_confidence * FORECAST_LLM_WEIGHT
    raw_tilt = fx_component + news_component + llm_component
    tilt = clamp(raw_tilt, -FORECAST_TILT_MAX_PCT_PER_DAY, FORECAST_TILT_MAX_PCT_PER_DAY)

    # --- 予測区間 ---
    lower_log, upper_log, interval_method, interval_samples, interval_multiplier = horizon_interval(
        dated_series,
        returns,
        horizon_days=horizon_days,
        interval_prob=FORECAST_INTERVAL_PROB,
        # 実測被覆率が得られていれば、名目とのズレで幅を自己補正させる。
        measured_coverage=recent_coverage,
    )

    # --- 日次の経路: 中心は tilt で線形、区間は √t で広がる円錐 ---
    daily: list[dict[str, Any]] = []
    previous_center = start_price
    for offset in range(1, horizon_days + 1):
        scale = math.sqrt(offset / horizon_days)
        center = start_price * math.exp(tilt * offset)
        lower = center * math.exp(lower_log * scale)
        upper = center * math.exp(upper_log * scale)
        daily.append({
            "date": (today + timedelta(days=offset)).date().isoformat(),
            "price_per_gram": round(center, 2),
            "delta_from_previous": round(center - previous_center, 2),
            "lower_price_per_gram": round(lower, 2),
            "upper_price_per_gram": round(upper, 2),
        })
        previous_center = center

    final = daily[-1]
    projected_center = final["price_per_gram"]
    projected_lower = final["lower_price_per_gram"]
    projected_upper = final["upper_price_per_gram"]
    projected_change = ((projected_center - start_price) / start_price) if start_price > 0 else 0.0
    lower_change_pct = ((projected_lower - start_price) / start_price * 100) if start_price > 0 else 0.0
    upper_change_pct = ((projected_upper - start_price) / start_price * 100) if start_price > 0 else 0.0

    # --- 信頼度 ---
    # 区間予測にとって本質的な品質指標は被覆率(名目80%なら実測も80%か)なので、
    # それを軸に据える。従来のように「入力データが揃っているか」だけで高い値を
    # 出さないよう、実績が無いうちは上限を掛ける。
    half_width_pct = (upper_change_pct - lower_change_pct) / 2.0
    width_score = clamp(1.0 - half_width_pct / FORECAST_WIDTH_REFERENCE_PCT, 0.0, 1.0)
    confidence = 0.25 + 0.45 * width_score
    if len(prices) >= 60:
        confidence += 0.10
    elif len(prices) >= 30:
        confidence += 0.05
    if interval_method == "empirical":
        confidence += 0.08
    if fx_available:
        confidence += 0.04
    if article_count >= 8:
        confidence += 0.04
    if gaps:
        # 欠損があるぶん区間推定の材料が減っているため素直に減点する。
        confidence -= min(0.10, 0.02 * gaps)

    accuracy_adjustment = accuracy_confidence_adjustment(recent_mae_pct)
    coverage_adjustment = coverage_confidence_adjustment(recent_coverage, nominal=FORECAST_INTERVAL_PROB)
    confidence += accuracy_adjustment + coverage_adjustment
    if recent_mae_pct is None and recent_coverage is None:
        confidence = min(confidence, FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY)
    confidence = clamp(confidence, 0.1, 0.95)

    # --- 根拠の内訳 ---
    # role: primary=予測値を決めた要因 / signal=中心の傾きへの寄与 / reference=参考値
    breakdown: list[dict[str, Any]] = [
        {
            "label": "現在価格(レンジの中心)",
            "value_pct_per_day": None,
            "role": "primary",
            "detail": (
                "7日先の価格は現在価格を中心に置くのが実測で最も誤差が小さいため、"
                "中心は現在価格に固定し、幅で不確実性を示しています"
            ),
        },
        {
            "label": f"予測レンジ({FORECAST_INTERVAL_PROB:.0%})",
            "value_pct_per_day": None,
            "role": "primary",
            "detail": (
                f"{lower_change_pct:+.2f}% 〜 {upper_change_pct:+.2f}%"
                + (
                    f"(過去の7日変動{interval_samples}件の分布から算出"
                    if interval_method == "empirical"
                    else f"(データ不足のため日次ボラ{sigma * 100:.2f}%×√7で近似"
                )
                + f" / 幅補正×{interval_multiplier:.2f})"
            ),
        },
    ]

    signal_rows: list[dict[str, Any]] = [
        {
            "label": "USD/JPY感応",
            "value_pct_per_day": round(fx_component * 100, 3),
            "role": "signal",
            "detail": (
                f"β={fx_beta:.3f}(直近{beta_samples}日の実データから推定)"
                if beta_samples
                else f"β={fx_beta:.3f}(既定値。推定に必要なデータが不足)"
            ),
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
    signal_rows.sort(key=lambda row: abs(row["value_pct_per_day"]), reverse=True)
    breakdown.extend(signal_rows)

    if abs(raw_tilt) > FORECAST_TILT_MAX_PCT_PER_DAY:
        breakdown.append({
            "label": "傾きの上限",
            "value_pct_per_day": round(tilt * 100, 3),
            "role": "reference",
            "detail": (
                f"シグナル合計 {raw_tilt * 100:+.3f}%/日 は上限"
                f"±{FORECAST_TILT_MAX_PCT_PER_DAY * 100:.2f}%/日 に丸めています"
            ),
        })

    if gaps:
        breakdown.append({
            "label": "データ欠損",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": f"履歴に{gaps}箇所の欠損あり。該当区間は1日あたりへ正規化して扱っています",
        })

    if recent_coverage is not None:
        breakdown.append({
            "label": "直近の的中(区間内に収まった割合)",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": f"{recent_coverage:.0%}(名目 {FORECAST_INTERVAL_PROB:.0%} / 信頼度を {coverage_adjustment:+.2f} 補正)",
        })
    if recent_mae_pct is not None:
        breakdown.append({
            "label": "直近14日の平均誤差",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": f"{recent_mae_pct:.2f}%(信頼度を {accuracy_adjustment:+.2f} 補正)",
        })
    if recent_mae_pct is None and recent_coverage is None:
        breakdown.append({
            "label": "答え合わせ実績",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": f"まだ無し(信頼度の上限を {FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY:.0%} に制限)",
        })

    if tilt_effect:
        improvement = safe_float(tilt_effect.get("improvement_pct"))
        samples = int(safe_float(tilt_effect.get("samples")) or 0)
        if improvement is not None and samples:
            verdict = "改善" if improvement > 0 else ("悪化" if improvement < 0 else "変化なし")
            breakdown.append({
                "label": "シグナルの実績(何もしない場合との比較)",
                "value_pct_per_day": None,
                "role": "reference",
                "detail": (
                    f"直近{samples}件で誤差 {safe_float(tilt_effect.get('baseline_mae_pct')):.2f}% → "
                    f"{safe_float(tilt_effect.get('model_mae_pct')):.2f}%({improvement:+.1f}% {verdict})"
                ),
            })

    if llm_rationale:
        breakdown.append({
            "label": "AI判定所見",
            "value_pct_per_day": None,
            "role": "reference",
            "detail": llm_rationale,
        })

    drivers: list[str] = []
    for row in breakdown:
        value = row["value_pct_per_day"]
        prefix = f"{value:+.3f}%/日 " if value is not None else ""
        drivers.append(f"{row['label']}: {prefix}({row['detail']})")

    return {
        "start_price_per_gram": round(start_price, 2),
        "projected_price_per_gram": projected_center,
        "projected_lower_per_gram": projected_lower,
        "projected_upper_per_gram": projected_upper,
        "projected_change_pct_7d": round(projected_change * 100, 3),
        "projected_lower_change_pct": round(lower_change_pct, 3),
        "projected_upper_change_pct": round(upper_change_pct, 3),
        "interval_prob": FORECAST_INTERVAL_PROB,
        "interval_method": interval_method,
        "interval_samples": interval_samples,
        "interval_width_multiplier": round(interval_multiplier, 4),
        "tilt_effect": tilt_effect or None,
        "confidence": round(confidence, 3),
        "implied_daily_return_pct": round(tilt * 100, 4),
        "model_variant": MODEL_VARIANT,
        "fx_beta": round(fx_beta, 4),
        "fx_beta_samples": beta_samples,
        "daily_sigma_pct": round(sigma * 100, 4),
        "history_gaps": gaps,
        "daily": daily,
        "drivers": drivers,
        "driver_breakdown": breakdown,
    }
