"""webapp/ のサービス層(app.py のルート以外)のユニットテスト。

    python -m unittest tests.test_webapp_services -v

対象は forecast_utils / forecast_series / forecast_models / forecast_signals /
forecast_service / forecast_accuracy_service / security / asset_version /
cache / db / push_service / repair_service / snapshot_service。

app.py のFastAPIルートは tests/test_webapp.py が担当するため、このファイルは
サービス関数・純粋計算・ミドルウェアを直接呼び出して検証する(TestClient は使わない)。

DB・外部API(Groq・ニュースRSS・為替・MetalpriceAPI・WebPush)には一切アクセスしない。
AsyncSession や外部呼び出しはすべて unittest.mock で差し替える。
"""

from __future__ import annotations

import asyncio
import math
import os
import random
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import select
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # noqa: E402

from webapp import (  # noqa: E402
    asset_version as asset_version_module,
    cache as cache_module,
    db as db_module,
    forecast_accuracy_service,
    forecast_models,
    forecast_series,
    forecast_service,
    forecast_signals,
    forecast_utils,
    push_service,
    repair_service,
    security as security_module,
    snapshot_service,
)
from webapp.models import (  # noqa: E402
    ForecastAccuracyLog,
    MetalPriceDaily,
    WeeklyForecastDaily,
    WeeklyForecastMeta,
)
from webapp.vapid_service import VapidConfig  # noqa: E402


def _dates(start: date, n: int) -> list[date]:
    return [start + timedelta(days=i) for i in range(n)]


# ======================================================================
# forecast_utils.py — 純粋な数値・JSON変換ヘルパ
# ======================================================================
class ForecastUtilsTests(unittest.TestCase):
    """外部依存の無い変換関数群。壊れた入力に対して例外を投げず既定値へ倒れることを確認する。"""

    def test_clamp_within_bounds(self):
        self.assertEqual(forecast_utils.clamp(5.0, 0.0, 10.0), 5.0)

    def test_clamp_below_lower(self):
        self.assertEqual(forecast_utils.clamp(-1.0, 0.0, 10.0), 0.0)

    def test_clamp_above_upper(self):
        self.assertEqual(forecast_utils.clamp(99.0, 0.0, 10.0), 10.0)

    def test_safe_float_valid(self):
        self.assertEqual(forecast_utils.safe_float("3.5"), 3.5)
        self.assertEqual(forecast_utils.safe_float(3), 3.0)

    def test_safe_float_invalid_string(self):
        self.assertIsNone(forecast_utils.safe_float("abc"))

    def test_safe_float_none(self):
        self.assertIsNone(forecast_utils.safe_float(None))

    def test_safe_float_rejects_nan_and_inf(self):
        self.assertIsNone(forecast_utils.safe_float(float("nan")))
        self.assertIsNone(forecast_utils.safe_float(float("inf")))
        self.assertIsNone(forecast_utils.safe_float(float("-inf")))

    def test_as_decimal_basic_rounding(self):
        self.assertEqual(forecast_utils.as_decimal(1.00005, Decimal("0.0001")), Decimal("1.0001"))
        self.assertEqual(forecast_utils.as_decimal(2, Decimal("0.01")), Decimal("2.00"))

    def test_as_decimal_invalid_returns_none(self):
        self.assertIsNone(forecast_utils.as_decimal(None))
        self.assertIsNone(forecast_utils.as_decimal("not-a-number"))

    def test_json_dumps_keeps_japanese_and_is_compact(self):
        text = forecast_utils.json_dumps({"a": "日本語", "b": 1})
        self.assertIn("日本語", text)  # ensure_ascii=False
        self.assertNotIn(" ", text)  # separators=(",", ":") で空白なし

    def test_json_loads_valid(self):
        self.assertEqual(forecast_utils.json_loads('{"x":1}', {}), {"x": 1})

    def test_json_loads_empty_or_none_returns_default(self):
        self.assertEqual(forecast_utils.json_loads(None, {"d": True}), {"d": True})
        self.assertEqual(forecast_utils.json_loads("", {"d": True}), {"d": True})

    def test_json_loads_invalid_json_returns_default(self):
        self.assertEqual(forecast_utils.json_loads("{not json", [1, 2]), [1, 2])

    def test_extract_first_json_object_plain_dict(self):
        self.assertEqual(forecast_utils.extract_first_json_object('{"a": 1}'), {"a": 1})

    def test_extract_first_json_object_array_is_rejected(self):
        # トップレベルが配列の場合は dict ではないので None
        self.assertIsNone(forecast_utils.extract_first_json_object("[1, 2, 3]"))

    def test_extract_first_json_object_embedded_in_text(self):
        text = 'ここに前置きの文章があります {"score": 0.5, "note": "ok"} 後ろにも文章'
        self.assertEqual(
            forecast_utils.extract_first_json_object(text),
            {"score": 0.5, "note": "ok"},
        )

    def test_extract_first_json_object_no_braces_returns_none(self):
        self.assertIsNone(forecast_utils.extract_first_json_object("no json here"))

    def test_extract_first_json_object_empty_string_returns_none(self):
        self.assertIsNone(forecast_utils.extract_first_json_object("   "))

    def test_extract_first_json_object_malformed_snippet_returns_none(self):
        self.assertIsNone(forecast_utils.extract_first_json_object("prefix { broken json suffix }"))

    def test_clip_text_short_text_collapses_whitespace(self):
        self.assertEqual(forecast_utils.clip_text("  a   b  \n c "), "a b c")

    def test_clip_text_truncates_long_text(self):
        long_text = "あ" * 200
        clipped = forecast_utils.clip_text(long_text, max_chars=180)
        self.assertEqual(len(clipped), 180)
        self.assertTrue(clipped.endswith("…"))


# ======================================================================
# forecast_series.py — 欠損に強い日次リターン系列と予測区間の材料
# ======================================================================
class ForecastSeriesTests(unittest.TestCase):
    """区間推定の核となる純粋計算(補正係数・分位点・σ推定)を検証する。"""

    def test_interval_width_multiplier_small_sample_uses_high_base(self):
        value = forecast_series.interval_width_multiplier(10)
        self.assertEqual(value, forecast_series.FORECAST_INTERVAL_WIDTH_MULTIPLIER)

    def test_interval_width_multiplier_large_sample_uses_low_base(self):
        value = forecast_series.interval_width_multiplier(500)
        self.assertEqual(value, forecast_series.FORECAST_INTERVAL_WIDTH_MULTIPLIER_MIN)

    def test_interval_width_multiplier_interpolates_linearly(self):
        small = forecast_series.INTERVAL_MULTIPLIER_SMALL_N
        large = forecast_series.INTERVAL_MULTIPLIER_LARGE_N
        high = forecast_series.FORECAST_INTERVAL_WIDTH_MULTIPLIER
        low = forecast_series.FORECAST_INTERVAL_WIDTH_MULTIPLIER_MIN
        n = (small + large) // 2
        expected = high + (low - high) * ((n - small) / (large - small))
        self.assertAlmostEqual(forecast_series.interval_width_multiplier(n), expected, places=9)

    def test_interval_width_multiplier_coverage_adjustment_narrows_when_overcovered(self):
        base = forecast_series.interval_width_multiplier(10)
        narrowed = forecast_series.interval_width_multiplier(10, measured_coverage=1.0, nominal_prob=0.8)
        self.assertLess(narrowed, base)
        expected = base * (1.0 - forecast_series.INTERVAL_COVERAGE_ADJUST_GAIN * (1.0 - 0.8))
        self.assertAlmostEqual(narrowed, expected, places=9)

    def test_interval_width_multiplier_coverage_adjustment_widens_when_undercovered(self):
        base = forecast_series.interval_width_multiplier(10)
        widened = forecast_series.interval_width_multiplier(10, measured_coverage=0.5, nominal_prob=0.8)
        self.assertGreater(widened, base)

    def test_interval_width_multiplier_coverage_adjustment_is_bounded(self):
        base = forecast_series.interval_width_multiplier(10)
        low_bound, high_bound = forecast_series.INTERVAL_COVERAGE_ADJUST_BOUNDS
        extreme_narrow = forecast_series.interval_width_multiplier(10, measured_coverage=0.0, nominal_prob=0.8)
        extreme_wide = forecast_series.interval_width_multiplier(10, measured_coverage=1.5, nominal_prob=0.8)
        self.assertAlmostEqual(extreme_narrow, base * high_bound, places=9)
        self.assertAlmostEqual(extreme_wide, base * low_bound, places=9)

    def test_interval_width_multiplier_ignores_nan_coverage(self):
        base = forecast_series.interval_width_multiplier(10)
        self.assertEqual(
            forecast_series.interval_width_multiplier(10, measured_coverage=float("nan")),
            base,
        )

    def test_parse_price_history_sorts_and_filters(self):
        items = [
            {"date": "2026-06-03", "price_per_gram": 105.0},
            {"date": "2026-06-01", "price_per_gram": 100.0},
            {"date": "not-a-date", "price_per_gram": 100.0},  # 不正な日付
            {"date": "2026-06-02", "price_per_gram": -5.0},  # 価格が0以下
            {"date": "2026-06-04", "price_per_gram": None},  # 価格が無い
            {"price_per_gram": 100.0},  # 日付キーが無い
        ]
        result = forecast_series.parse_price_history(items)
        self.assertEqual(result, [(date(2026, 6, 1), 100.0), (date(2026, 6, 3), 105.0)])

    def test_build_return_series_normalizes_by_elapsed_days(self):
        series = [
            (date(2026, 6, 1), 100.0),
            (date(2026, 6, 2), 110.0),  # 1日: そのまま
            (date(2026, 6, 5), 110.0 * math.exp(0.03 * 3)),  # 3日欠損: 1日あたりへ正規化
        ]
        returns = forecast_series.build_return_series(series)
        self.assertEqual(len(returns), 2)
        self.assertAlmostEqual(returns[0][0], math.log(1.1), places=9)
        self.assertEqual(returns[0][1], 1)
        self.assertAlmostEqual(returns[1][0], 0.03, places=9)
        self.assertEqual(returns[1][1], 3)

    def test_build_return_series_skips_non_positive_or_same_day(self):
        series = [
            (date(2026, 6, 1), 100.0),
            (date(2026, 6, 1), 105.0),  # 同日(経過0日)は除外
            (date(2026, 6, 2), -1.0),  # 価格が0以下
        ]
        self.assertEqual(forecast_series.build_return_series(series), [])

    def test_contiguous_returns_filters_gapped_entries(self):
        returns = [(0.01, 1), (0.05, 3), (-0.02, 1)]
        self.assertEqual(forecast_series.contiguous_returns(returns), [0.01, -0.02])

    def test_robust_daily_sigma_uses_mad_when_enough_contiguous_samples(self):
        values = [0.01, -0.01, 0.02, -0.02, 0.01, -0.01, 0.02, -0.02, 0.0, 0.03]
        returns = [(v, 1) for v in values]
        # 昇順ソート後の中央値(=0.005)から求めたMAD(中央絶対偏差)
        mad_expected = 0.015
        sigma = forecast_series.robust_daily_sigma(returns)
        self.assertGreater(sigma, 0.0)
        self.assertAlmostEqual(sigma, forecast_series.MAD_TO_SIGMA * mad_expected, places=6)

    def test_robust_daily_sigma_falls_back_to_pstdev_when_mad_is_zero(self):
        values = [0.0] * 10
        returns = [(v, 1) for v in values]
        self.assertEqual(forecast_series.robust_daily_sigma(returns), 0.0)

    def test_robust_daily_sigma_falls_back_when_too_few_contiguous(self):
        # 経過1日のリターンが1本しかない(<MIN_SIGMA_SAMPLES)ので全リターンへフォールバックする
        returns = [(0.01, 1), (0.05, 3), (-0.03, 2)]
        sigma = forecast_series.robust_daily_sigma(returns)
        clean = [v for v, _ in returns]
        median = 0.01
        mad = 0.02  # median(|0.01-0.01|, |0.05-0.01|, |-0.03-0.01|) = median(0, 0.04, 0.04) = 0.04
        # 実際の中央値・MADを再計算して照合する
        import statistics as _st

        median = _st.median(clean)
        mad = _st.median([abs(v - median) for v in clean])
        expected = forecast_series.MAD_TO_SIGMA * mad if mad > 0 else _st.pstdev(clean)
        self.assertAlmostEqual(sigma, expected, places=9)

    def test_robust_daily_sigma_too_short_returns_zero(self):
        self.assertEqual(forecast_series.robust_daily_sigma([(0.01, 1)]), 0.0)
        self.assertEqual(forecast_series.robust_daily_sigma([]), 0.0)

    def test_horizon_log_returns_rejects_horizon_below_one(self):
        self.assertEqual(forecast_series.horizon_log_returns([(date(2026, 6, 1), 100.0)], 0), [])

    def test_horizon_log_returns_matches_exact_offset_only(self):
        start = date(2026, 6, 1)
        prices = [100.0, 101.0, 102.0, 103.0, 104.0, 105.0, 106.0, 110.0, 111.0, 112.0]
        series = list(zip(_dates(start, len(prices)), prices))
        values = forecast_series.horizon_log_returns(series, 7)
        # base_date + 7 が範囲内(0..2)の3件だけ採用される
        self.assertEqual(len(values), 3)
        self.assertAlmostEqual(values[0], math.log(prices[7] / prices[0]), places=9)
        self.assertAlmostEqual(values[1], math.log(prices[8] / prices[1]), places=9)
        self.assertAlmostEqual(values[2], math.log(prices[9] / prices[2]), places=9)

    def test_horizon_interval_falls_back_to_normal_approx_when_degenerate(self):
        # 複利成長率が一定 → 7日対数リターンが全期間で完全に同一値になり、
        # 平均を引くと分位点が幅0(=degenerate)に潰れて正規近似へフォールバックする。
        start = date(2026, 6, 1)
        daily_rate = 0.001
        n = 60
        prices = [1000.0 * (1 + daily_rate) ** i for i in range(n)]
        series = list(zip(_dates(start, n), prices))
        returns = forecast_series.build_return_series(series)
        lower, upper, method, samples, multiplier = forecast_series.horizon_interval(
            series, returns, horizon_days=7, interval_prob=0.8
        )
        self.assertEqual(method, "normal_approx")
        self.assertGreaterEqual(samples, forecast_series.MIN_QUANTILE_SAMPLES)
        # sigmaがほぼ0のため下限が保証される(MIN_INTERVAL_HALF_WIDTH)
        self.assertAlmostEqual(upper, forecast_series.MIN_INTERVAL_HALF_WIDTH, places=6)
        self.assertAlmostEqual(lower, -forecast_series.MIN_INTERVAL_HALF_WIDTH, places=6)

    def test_horizon_interval_uses_empirical_when_enough_varied_samples(self):
        start = date(2026, 6, 1)
        rng = random.Random(1234)
        n = 80
        price = 1000.0
        prices = [price]
        for _ in range(n - 1):
            price *= math.exp(rng.uniform(-0.02, 0.02))
            prices.append(price)
        series = list(zip(_dates(start, n), prices))
        returns = forecast_series.build_return_series(series)
        lower, upper, method, samples, multiplier = forecast_series.horizon_interval(
            series, returns, horizon_days=7, interval_prob=0.8
        )
        self.assertEqual(method, "empirical")
        self.assertGreaterEqual(samples, forecast_series.MIN_QUANTILE_SAMPLES)
        self.assertLess(lower, 0.0)
        self.assertGreater(upper, 0.0)

    def test_horizon_interval_measured_coverage_narrows_interval(self):
        start = date(2026, 6, 1)
        rng = random.Random(99)
        n = 80
        price = 1000.0
        prices = [price]
        for _ in range(n - 1):
            price *= math.exp(rng.uniform(-0.02, 0.02))
            prices.append(price)
        series = list(zip(_dates(start, n), prices))
        returns = forecast_series.build_return_series(series)
        _, upper_default, _, _, _ = forecast_series.horizon_interval(series, returns, horizon_days=7, interval_prob=0.8)
        _, upper_narrow, _, _, _ = forecast_series.horizon_interval(
            series, returns, horizon_days=7, interval_prob=0.8, measured_coverage=1.0
        )
        self.assertLess(upper_narrow, upper_default)

    def test_count_gaps_counts_multi_day_jumps(self):
        series = [
            (date(2026, 6, 1), 100.0),
            (date(2026, 6, 2), 101.0),  # 1日: 欠損なし
            (date(2026, 6, 5), 102.0),  # 3日ジャンプ: 欠損1
            (date(2026, 6, 6), 103.0),  # 1日: 欠損なし
            (date(2026, 6, 10), 104.0),  # 4日ジャンプ: 欠損2
        ]
        self.assertEqual(forecast_series.count_gaps(series), 2)

    def test_normal_quantile_symmetry_and_known_values(self):
        self.assertAlmostEqual(forecast_series._normal_quantile(0.5), 0.0, places=6)
        # 標準正規分布の97.5%点は約1.95996
        self.assertAlmostEqual(forecast_series._normal_quantile(0.975), 1.959964, places=4)
        q10 = forecast_series._normal_quantile(0.1)
        q90 = forecast_series._normal_quantile(0.9)
        self.assertAlmostEqual(q10, -q90, places=6)


# ======================================================================
# forecast_models.py — 区間予測の組み立て(信頼度補正・傾き・区間)
# ======================================================================
def _build_price_history(n: int, *, start: date = date(2026, 6, 1), seed: int = 42) -> list[dict]:
    """再現可能な擬似乱数で、動きはあるが決定的な価格履歴(欠損なし)を作る。"""
    rng = random.Random(seed)
    price = 5000.0
    items = []
    for i in range(n):
        if i > 0:
            price *= math.exp(rng.uniform(-0.015, 0.015))
        items.append({"date": (start + timedelta(days=i)).isoformat(), "price_per_gram": round(price, 4)})
    return items


class ForecastModelsTests(unittest.TestCase):
    """予測レンジ組み立ての各要素(β推定・信頼度補正・trend/volatility)を検証する。"""

    def test_extract_prices_filters_invalid_entries(self):
        items = [
            {"price_per_gram": 100.0},
            {"price_per_gram": None},
            {"price_per_gram": -1.0},
            {"price_per_gram": "abc"},
            {"price_per_gram": 200.5},
        ]
        self.assertEqual(forecast_models.extract_prices(items), [100.0, 200.5])

    def test_extract_price_series_requires_date_and_positive_price(self):
        items = [
            {"date": "2026-06-01", "price_per_gram": 100.0},
            {"date": None, "price_per_gram": 100.0},
            {"date": "2026-06-02", "price_per_gram": -1.0},
        ]
        self.assertEqual(forecast_models.extract_price_series(items), [("2026-06-01", 100.0)])

    def test_daily_returns_by_date_computes_pct_change(self):
        series = [("2026-06-01", 100.0), ("2026-06-02", 110.0), ("2026-06-03", 99.0)]
        returns = forecast_models.daily_returns_by_date(series)
        self.assertAlmostEqual(returns["2026-06-02"], 0.10, places=9)
        self.assertAlmostEqual(returns["2026-06-03"], -0.10, places=9)

    def test_estimate_fx_beta_recovers_known_slope_from_linear_relationship(self):
        n = forecast_models.FX_BETA_MIN_SAMPLES
        rng = random.Random(7)
        metal_returns = {}
        fx_returns = {}
        for i in range(n):
            key = f"2026-01-{i + 1:03d}"
            fx = rng.uniform(-0.01, 0.01)
            fx_returns[key] = fx
            metal_returns[key] = 0.7 * fx  # 完全な線形関係(β=0.7)
        beta, samples = forecast_models.estimate_fx_beta(metal_returns, fx_returns, fallback=0.35)
        self.assertEqual(samples, n)
        self.assertAlmostEqual(beta, 0.7, places=6)

    def test_estimate_fx_beta_falls_back_when_not_enough_common_dates(self):
        metal_returns = {"2026-01-01": 0.01}
        fx_returns = {"2026-01-01": 0.02}
        beta, samples = forecast_models.estimate_fx_beta(metal_returns, fx_returns, fallback=0.35)
        self.assertEqual((beta, samples), (0.35, 0))

    def test_estimate_fx_beta_falls_back_when_fx_variance_is_zero(self):
        n = forecast_models.FX_BETA_MIN_SAMPLES
        metal_returns = {f"d{i}": 0.01 * i for i in range(n)}
        fx_returns = {f"d{i}": 0.0 for i in range(n)}  # 分散0
        beta, samples = forecast_models.estimate_fx_beta(metal_returns, fx_returns, fallback=0.35)
        self.assertEqual((beta, samples), (0.35, 0))

    def test_estimate_fx_beta_clamps_to_bounds(self):
        n = forecast_models.FX_BETA_MIN_SAMPLES
        rng = random.Random(3)
        metal_returns = {}
        fx_returns = {}
        for i in range(n):
            key = f"d{i}"
            fx = rng.uniform(-0.01, 0.01)
            fx_returns[key] = fx
            metal_returns[key] = 5.0 * fx  # β=5.0 は上限1.5を超える
        beta, samples = forecast_models.estimate_fx_beta(metal_returns, fx_returns, fallback=0.35)
        self.assertEqual(samples, n)
        self.assertEqual(beta, forecast_models.FX_BETA_BOUNDS[1])

    def test_accuracy_confidence_adjustment_none_or_invalid_returns_zero(self):
        self.assertEqual(forecast_models.accuracy_confidence_adjustment(None), 0.0)
        self.assertEqual(forecast_models.accuracy_confidence_adjustment(-1.0), 0.0)
        self.assertEqual(forecast_models.accuracy_confidence_adjustment(float("nan")), 0.0)

    def test_accuracy_confidence_adjustment_good_and_bad_extremes(self):
        good = forecast_models.FORECAST_ACCURACY_GOOD_MAE_PCT
        bad = forecast_models.FORECAST_ACCURACY_BAD_MAE_PCT
        self.assertEqual(
            forecast_models.accuracy_confidence_adjustment(good),
            forecast_models.FORECAST_ACCURACY_MAX_BONUS,
        )
        self.assertEqual(
            forecast_models.accuracy_confidence_adjustment(bad),
            -forecast_models.FORECAST_ACCURACY_MAX_PENALTY,
        )

    def test_accuracy_confidence_adjustment_interpolates_at_midpoint(self):
        good = forecast_models.FORECAST_ACCURACY_GOOD_MAE_PCT
        bad = forecast_models.FORECAST_ACCURACY_BAD_MAE_PCT
        midpoint = (good + bad) / 2.0
        expected = forecast_models.FORECAST_ACCURACY_MAX_BONUS - 0.5 * (
            forecast_models.FORECAST_ACCURACY_MAX_BONUS + forecast_models.FORECAST_ACCURACY_MAX_PENALTY
        )
        self.assertAlmostEqual(
            forecast_models.accuracy_confidence_adjustment(midpoint),
            expected,
            places=9,
        )

    def test_coverage_confidence_adjustment_zero_gap_is_zero(self):
        self.assertEqual(
            forecast_models.coverage_confidence_adjustment(0.8, nominal=0.8),
            0.0,
        )

    def test_coverage_confidence_adjustment_none_or_nan_is_zero(self):
        self.assertEqual(forecast_models.coverage_confidence_adjustment(None, nominal=0.8), 0.0)
        self.assertEqual(forecast_models.coverage_confidence_adjustment(float("nan"), nominal=0.8), 0.0)

    def test_coverage_confidence_adjustment_scales_with_gap(self):
        value = forecast_models.coverage_confidence_adjustment(0.9, nominal=0.8)
        self.assertAlmostEqual(value, -0.05, places=9)

    def test_coverage_confidence_adjustment_clamps_at_max_penalty(self):
        value = forecast_models.coverage_confidence_adjustment(0.3, nominal=0.8)
        self.assertAlmostEqual(value, -0.15, places=9)

    def test_daily_trend_needs_two_prices(self):
        self.assertEqual(forecast_models.daily_trend([]), 0.0)
        self.assertEqual(forecast_models.daily_trend([100.0]), 0.0)

    def test_daily_trend_two_points_clamped(self):
        # (110-100)/100 = 0.10 は上限0.03でクランプされる
        self.assertEqual(forecast_models.daily_trend([100.0, 110.0]), 0.03)

    def test_daily_trend_geometric_mean_over_window(self):
        prices = [100.0, 102.0, 104.0, 106.0, 108.0]
        expected = (108.0 / 100.0) ** (1.0 / 4) - 1.0
        self.assertAlmostEqual(forecast_models.daily_trend(prices, window=14), expected, places=9)

    def test_daily_trend_zero_first_price_returns_zero(self):
        self.assertEqual(forecast_models.daily_trend([0.0, 100.0, 200.0]), 0.0)

    def test_daily_volatility_needs_three_prices(self):
        self.assertEqual(forecast_models.daily_volatility([100.0, 101.0]), 0.004)

    def test_daily_volatility_zero_variance_is_zero(self):
        self.assertEqual(forecast_models.daily_volatility([100.0, 100.0, 100.0, 100.0]), 0.0)

    def test_daily_volatility_matches_manual_pstdev(self):
        import statistics as st

        prices = [100.0, 102.0, 99.0, 101.0, 103.0]
        returns = [(c - p) / p for p, c in zip(prices, prices[1:])]
        expected = st.pstdev(returns)
        self.assertAlmostEqual(forecast_models.daily_volatility(prices, window=14), expected, places=9)

    def _forecast_kwargs(self, **overrides):
        kwargs = dict(
            metal_key="gold",
            history_items=_build_price_history(60),
            horizon_days=7,
            today=datetime(2026, 8, 31, tzinfo=timezone.utc),
            fx_daily_factor=0.0005,
            news_score=0.1,
            article_count=5,
            fx_available=True,
            llm_score=0.2,
            llm_confidence=0.5,
            llm_rationale="材料に大きな偏りは無い",
            llm_available=True,
        )
        kwargs.update(overrides)
        return kwargs

    def test_forecast_for_metal_returns_none_for_insufficient_history(self):
        one_day_history = [{"date": "2026-06-01", "price_per_gram": 100.0}]
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs(history_items=one_day_history))
        self.assertIsNone(result)

    def test_forecast_for_metal_basic_shape(self):
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs())
        self.assertIsNotNone(result)
        self.assertEqual(len(result["daily"]), 7)
        self.assertEqual(result["daily"][-1]["date"], "2026-09-07")
        self.assertEqual(result["history_gaps"], 0)
        self.assertGreaterEqual(result["confidence"], 0.1)
        self.assertLessEqual(result["confidence"], 0.95)
        self.assertEqual(result["model_variant"], forecast_models.MODEL_VARIANT)
        # 欠損が無いので「データ欠損」の内訳行は無いはず
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertNotIn("データ欠損", labels)
        self.assertIn("現在価格(レンジの中心)", labels)

    def test_forecast_for_metal_no_accuracy_history_caps_confidence(self):
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs(recent_mae_pct=None, recent_coverage=None))
        self.assertLessEqual(result["confidence"], forecast_models.FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY)
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertIn("答え合わせ実績", labels)

    def test_forecast_for_metal_with_accuracy_history_adds_breakdown_rows(self):
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs(recent_mae_pct=1.0, recent_coverage=0.8))
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertIn("直近の的中(区間内に収まった割合)", labels)
        self.assertIn("直近14日の平均誤差", labels)
        self.assertNotIn("答え合わせ実績", labels)

    def test_forecast_for_metal_gaps_are_reported_and_penalized(self):
        history = _build_price_history(60)
        # 意図的に1件間引いて欠損を作る
        del history[30]
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs(history_items=history))
        self.assertGreater(result["history_gaps"], 0)
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertIn("データ欠損", labels)

    def test_forecast_for_metal_extreme_tilt_is_clamped_and_reported(self):
        result = forecast_models.forecast_for_metal(
            **self._forecast_kwargs(fx_daily_factor=1.0, news_score=1.0, llm_score=1.0, llm_confidence=1.0)
        )
        max_tilt = forecast_models.FORECAST_TILT_MAX_PCT_PER_DAY
        implied = result["implied_daily_return_pct"] / 100.0
        self.assertAlmostEqual(abs(implied), max_tilt, places=9)
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertIn("傾きの上限", labels)

    def test_forecast_for_metal_tilt_effect_breakdown_wording(self):
        tilt_effect_label = "シグナルの実績(何もしない場合との比較)"
        improved = forecast_models.forecast_for_metal(
            **self._forecast_kwargs(
                tilt_effect={"improvement_pct": 12.5, "samples": 20, "baseline_mae_pct": 2.0, "model_mae_pct": 1.75}
            )
        )
        detail = next(row["detail"] for row in improved["driver_breakdown"] if row["label"] == tilt_effect_label)
        self.assertIn("改善", detail)

        worsened = forecast_models.forecast_for_metal(
            **self._forecast_kwargs(
                tilt_effect={"improvement_pct": -8.0, "samples": 20, "baseline_mae_pct": 2.0, "model_mae_pct": 2.16}
            )
        )
        detail = next(row["detail"] for row in worsened["driver_breakdown"] if row["label"] == tilt_effect_label)
        self.assertIn("悪化", detail)

    def test_forecast_for_metal_tilt_effect_without_samples_is_skipped(self):
        result = forecast_models.forecast_for_metal(
            **self._forecast_kwargs(tilt_effect={"improvement_pct": 5.0, "samples": 0})
        )
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertNotIn("シグナルの実績(何もしない場合との比較)", labels)

    def test_forecast_for_metal_llm_rationale_included_when_present(self):
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs(llm_rationale="強気材料が優勢"))
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertIn("AI判定所見", labels)

    def test_forecast_for_metal_llm_rationale_omitted_when_empty(self):
        result = forecast_models.forecast_for_metal(**self._forecast_kwargs(llm_rationale=""))
        labels = [row["label"] for row in result["driver_breakdown"]]
        self.assertNotIn("AI判定所見", labels)


# ======================================================================
# forecast_for_metal — 割る前に姿を固定するためのゴールデン値
# ======================================================================
class ForecastForMetalGoldenTests(unittest.TestCase):
    """`forecast_for_metal` が返すものを、丸ごと固定する。

    278行ある関数を割る前に、外から見た姿を押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    この関数は純粋計算（入力は全部引数、出力は辞書1つ）なので、固定するのは
    **固定入力に対する出力そのもの**でよい。上の ForecastModelsTests は
    「7件ある」「上限で丸められている」といった性質を見ているが、**丸めや
    係数の掛け順が変わっても気づけない。** 割るときに怖いのはそこなので、
    数値を1つずつ並べて持つ。

    2通りだけ用意してあるのは、内訳の条件分岐を全部通すため。

      TRACK_RECORD           … 答え合わせ実績あり・傾きは上限に達しない・欠損なし
      NO_RECORD_GAPS_CLAMPED … 実績なし・欠損あり・傾きが上限に張り付く

    係数は環境変数で変えられるので、モジュール定数を固定してから呼ぶ。
    そうしないと、`.env` を触った人の手元でだけ落ちる。
    """

    CONSTANTS = {
        "FORECAST_LLM_WEIGHT": 0.008,
        "FORECAST_TILT_MAX_PCT_PER_DAY": 0.0015,
        "FORECAST_INTERVAL_PROB": 0.8,
        "FORECAST_WIDTH_REFERENCE_PCT": 12.0,
        "FORECAST_CONFIDENCE_CAP_WITHOUT_ACCURACY": 0.75,
        "FORECAST_ACCURACY_GOOD_MAE_PCT": 1.5,
        "FORECAST_ACCURACY_BAD_MAE_PCT": 6.0,
    }

    TRACK_RECORD = [
        "confidence = 0.778",
        "daily 2026-09-01 c=4594.17 d=5.51 lo=4516.09 hi=4691.86",
        "daily 2026-09-02 c=4599.69 d=5.52 lo=4489.52 hi=4738.61",
        "daily 2026-09-03 c=4605.21 d=5.52 lo=4470.49 hi=4776.13",
        "daily 2026-09-04 c=4610.74 d=5.53 lo=4455.35 hi=4808.9",
        "daily 2026-09-05 c=4616.28 d=5.54 lo=4442.68 hi=4838.64",
        "daily 2026-09-06 c=4621.82 d=5.54 lo=4431.78 hi=4866.25",
        "daily 2026-09-07 c=4627.37 d=5.55 lo=4422.19 hi=4892.26",
        "daily_sigma_pct = 1.0139",
        "fx_beta = 0.3",
        "fx_beta_samples = 0",
        "history_gaps = 0",
        "implied_daily_return_pct = 0.12",
        "interval_method = 'empirical'",
        "interval_prob = 0.8",
        "interval_samples = 53",
        "interval_width_multiplier = 1.3266",
        "model_variant = 'interval_rw_v1'",
        "projected_change_pct_7d = 0.844",
        "projected_lower_change_pct = -3.628",
        "projected_lower_per_gram = 4422.19",
        "projected_price_per_gram = 4627.37",
        "projected_upper_change_pct = 6.616",
        "projected_upper_per_gram = 4892.26",
        "start_price_per_gram = 4588.66",
        "tilt_effect = {'improvement_pct': 12.5, 'samples': 30, 'baseline_mae_pct': 3.37, 'model_mae_pct': 2.95}",
        "driver 現在価格(レンジの中心): (7日先の価格は現在価格を中心に置くのが実測で最も誤差が小さいため、"
        "中心は現在価格に固定し、幅で不確実性を示しています)",
        "driver 予測レンジ(80%): (-3.63% 〜 +6.62%(過去の7日変動53件の分布から算出 / 幅補正×1.33))",
        "driver AI判定感応: +0.080%/日 (スコア +0.200 / 確信度 0.500)",
        "driver ニュース感応: +0.025%/日 (見出しスコア +0.100 / 5件)",
        "driver USD/JPY感応: +0.015%/日 (β=0.300(既定値。推定に必要なデータが不足))",
        "driver 直近の的中(区間内に収まった割合): (80%(名目 80% / 信頼度を -0.00 補正))",
        "driver 直近14日の平均誤差: (1.00%(信頼度を +0.05 補正))",
        "driver シグナルの実績(何もしない場合との比較): (直近30件で誤差 3.37% → 2.95%(+12.5% 改善))",
        "driver AI判定所見: (材料に大きな偏りは無い)",
        "role primary / 現在価格(レンジの中心)",
        "role primary / 予測レンジ(80%)",
        "role signal / AI判定感応",
        "role signal / ニュース感応",
        "role signal / USD/JPY感応",
        "role reference / 直近の的中(区間内に収まった割合)",
        "role reference / 直近14日の平均誤差",
        "role reference / シグナルの実績(何もしない場合との比較)",
        "role reference / AI判定所見",
    ]

    NO_RECORD_GAPS_CLAMPED = [
        "confidence = 0.657",
        "daily 2026-09-01 c=4595.55 d=6.89 lo=4519.04 hi=4694.94",
        "daily 2026-09-02 c=4602.45 d=6.9 lo=4494.46 hi=4743.84",
        "daily 2026-09-03 c=4609.36 d=6.91 lo=4477.25 hi=4783.38",
        "daily 2026-09-04 c=4616.28 d=6.92 lo=4463.85 hi=4818.1",
        "daily 2026-09-05 c=4623.21 d=6.93 lo=4452.86 hi=4849.77",
        "daily 2026-09-06 c=4630.15 d=6.94 lo=4443.6 hi=4879.28",
        "daily 2026-09-07 c=4637.1 d=6.95 lo=4435.63 hi=4907.17",
        "daily_sigma_pct = 1.1438",
        "fx_beta = 0.3",
        "fx_beta_samples = 0",
        "history_gaps = 1",
        "implied_daily_return_pct = 0.15",
        "interval_method = 'empirical'",
        "interval_prob = 0.8",
        "interval_samples = 51",
        "interval_width_multiplier = 1.3313",
        "model_variant = 'interval_rw_v1'",
        "projected_change_pct_7d = 1.056",
        "projected_lower_change_pct = -3.335",
        "projected_lower_per_gram = 4435.63",
        "projected_price_per_gram = 4637.1",
        "projected_upper_change_pct = 6.941",
        "projected_upper_per_gram = 4907.17",
        "start_price_per_gram = 4588.66",
        "tilt_effect = None",
        "driver 現在価格(レンジの中心): (7日先の価格は現在価格を中心に置くのが実測で最も誤差が小さいため、"
        "中心は現在価格に固定し、幅で不確実性を示しています)",
        "driver 予測レンジ(80%): (-3.34% 〜 +6.94%(過去の7日変動51件の分布から算出 / 幅補正×1.33))",
        "driver USD/JPY感応: +30.000%/日 (β=0.300(既定値。推定に必要なデータが不足))",
        "driver AI判定感応: +0.800%/日 (スコア +1.000 / 確信度 1.000)",
        "driver ニュース感応: +0.250%/日 (見出しスコア +1.000 / 5件)",
        "driver 傾きの上限: +0.150%/日 (シグナル合計 +31.050%/日 は上限±0.15%/日 に丸めています)",
        "driver データ欠損: (履歴に1箇所の欠損あり。該当区間は1日あたりへ正規化して扱っています)",
        "driver 答え合わせ実績: (まだ無し(信頼度の上限を 75% に制限))",
        "driver AI判定所見: (材料に大きな偏りは無い)",
        "role primary / 現在価格(レンジの中心)",
        "role primary / 予測レンジ(80%)",
        "role signal / USD/JPY感応",
        "role signal / AI判定感応",
        "role signal / ニュース感応",
        "role reference / 傾きの上限",
        "role reference / データ欠損",
        "role reference / 答え合わせ実績",
        "role reference / AI判定所見",
    ]

    @staticmethod
    def _flatten(result):
        """辞書を「1行1項目」へ潰す。差分がそのまま読めるようにするため。

        まとめて assertEqual すると、unittest がリストの差分を出してくれる。
        辞書のまま比べると、どの鍵が動いたのかを目で探すことになる。
        """
        rows = []
        for key, value in sorted(result.items()):
            if key == "daily":
                for day in value:
                    rows.append(
                        f"daily {day['date']} c={day['price_per_gram']} "
                        f"d={day['delta_from_previous']} "
                        f"lo={day['lower_price_per_gram']} hi={day['upper_price_per_gram']}"
                    )
            elif key in ("drivers", "driver_breakdown"):
                continue
            else:
                rows.append(f"{key} = {value!r}")
        rows += [f"driver {text}" for text in result["drivers"]]
        rows += [f"role {row['role']} / {row['label']}" for row in result["driver_breakdown"]]
        return rows

    def _kwargs(self, **overrides):
        """ForecastModelsTests と同じ土台の入力（欠損なし60日）。"""
        kwargs = dict(
            metal_key="gold",
            history_items=_build_price_history(60),
            horizon_days=7,
            today=datetime(2026, 8, 31, tzinfo=timezone.utc),
            fx_daily_factor=0.0005,
            news_score=0.1,
            article_count=5,
            fx_available=True,
            llm_score=0.2,
            llm_confidence=0.5,
            llm_rationale="材料に大きな偏りは無い",
            llm_available=True,
        )
        kwargs.update(overrides)
        return kwargs

    def _run(self, **overrides):
        """定数を固定したうえで1回呼び、潰した形で返す。"""
        with patch.multiple(forecast_models, **self.CONSTANTS):
            return self._flatten(forecast_models.forecast_for_metal(**self._kwargs(**overrides)))

    def test_the_forecast_with_a_track_record_is_unchanged(self):
        """実績ありの経路の出力が、1項目も変わらないこと。

        信頼度の補正・区間の幅補正・内訳の並び（signal は絶対値の大きい順）
        まで含めて、数字がそのままであることを見る。
        """
        actual = self._run(
            recent_mae_pct=1.0,
            recent_coverage=0.8,
            tilt_effect={
                "improvement_pct": 12.5,
                "samples": 30,
                "baseline_mae_pct": 3.37,
                "model_mae_pct": 2.95,
            },
        )
        self.assertEqual(actual, self.TRACK_RECORD)

    def test_the_forecast_without_a_record_and_with_gaps_is_unchanged(self):
        """実績なし・欠損あり・傾きが上限に張り付く経路の出力が変わらないこと。

        信頼度の上限、欠損の減点、傾きの丸めという「条件が揃ったときだけ
        通る分岐」を1回でまとめて通す。
        """
        gapped = _build_price_history(60)
        del gapped[30]
        actual = self._run(
            history_items=gapped,
            fx_daily_factor=1.0,
            news_score=1.0,
            llm_score=1.0,
            llm_confidence=1.0,
        )
        self.assertEqual(actual, self.NO_RECORD_GAPS_CLAMPED)


# ======================================================================
# forecast_signals.py — Groq/ニュースRSS/為替APIを呼ばない純粋な部分だけ
# ======================================================================
class ForecastSignalsPureTests(unittest.TestCase):
    """ネットワークに触れない純粋関数(スコアリング・向き判定・矛盾検査)を検証する。"""

    def test_news_score_counts_positive_and_negative_tokens(self):
        text = "gold price surge amid rate cuts, but yields rising"
        # positive: surge, rate cuts(1) -> +2 / negative: yields rising -> -1
        self.assertEqual(forecast_signals._news_score(text), 1)

    def test_news_score_word_boundary_avoids_false_positive(self):
        # "support" は "up" を部分文字列として含むが、単語境界チェックでマッチしない
        self.assertEqual(forecast_signals._news_score("strong support for the market"), 0)

    def test_news_score_multiword_token_matches(self):
        self.assertEqual(forecast_signals._news_score("gold hits a record high today"), 1)

    def test_news_score_neutral_text_is_zero(self):
        self.assertEqual(forecast_signals._news_score("gold prices are unchanged today"), 0)

    def test_empty_usdjpy_signal_shape(self):
        signal = forecast_signals._empty_usdjpy_signal()
        self.assertFalse(signal["available"])
        self.assertEqual(signal["daily_factor"], 0.0)
        self.assertEqual(signal["daily_returns"], [])
        self.assertEqual(signal["daily_returns_by_date"], {})

    def test_range_direction_up(self):
        self.assertEqual(forecast_signals._range_direction(0.5, 1.5), "up")

    def test_range_direction_down(self):
        self.assertEqual(forecast_signals._range_direction(-1.5, -0.5), "down")

    def test_range_direction_flat(self):
        self.assertEqual(forecast_signals._range_direction(-0.1, 0.1), "flat")

    def test_range_direction_unclear_when_straddling_zero(self):
        self.assertEqual(forecast_signals._range_direction(-1.0, 1.0), "unclear")

    def test_contradicts_direction_both_words_present_is_never_contradiction(self):
        self.assertFalse(forecast_signals._contradicts_direction("直近は上昇していますが今後は下落", "up"))

    def test_contradicts_direction_up_rejects_down_word(self):
        self.assertTrue(forecast_signals._contradicts_direction("大きく下落する見込みです", "up"))
        self.assertFalse(forecast_signals._contradicts_direction("上昇が期待できます", "up"))

    def test_contradicts_direction_down_rejects_up_word(self):
        self.assertTrue(forecast_signals._contradicts_direction("値上がりが見込まれます", "down"))
        self.assertFalse(forecast_signals._contradicts_direction("下落が続く見通しです", "down"))

    def test_contradicts_direction_unclear_rejects_any_directional_word(self):
        self.assertTrue(forecast_signals._contradicts_direction("上昇するでしょう", "unclear"))
        self.assertTrue(forecast_signals._contradicts_direction("下落するでしょう", "unclear"))
        self.assertFalse(forecast_signals._contradicts_direction("横ばいが続く見通しです", "unclear"))

    def test_contradicts_direction_flat_never_checked(self):
        self.assertFalse(forecast_signals._contradicts_direction("大きく上昇し値下がりもする", "flat"))
        self.assertFalse(forecast_signals._contradicts_direction("上昇するでしょう", "flat"))


# ======================================================================
# forecast_service.py — DB非依存のペイロード整形関数
# ======================================================================
class _StoreFakeSession:
    """本物の同期 Session に、await できる薄い皮だけ被せて包む。

    本番の SessionLocal は asyncpg 前提で Postgres が無いと動かせない。ここでは
    同じ ORM モデル・同じ SQL 文をインメモリ SQLite の同期セッションで実際に
    実行し、`await` の形だけ本番コードに合わせる（tests/test_user_state.py の
    _FakeAsyncSession と同じ考え方。あちらは delete/flush を使わないので、
    こちらで足している）。
    """

    def __init__(self, sync_session):
        """同期セッションを1つ抱える。"""
        self._session = sync_session

    def add(self, obj):
        """そのまま渡す。"""
        self._session.add(obj)

    async def scalars(self, stmt):
        """await の形だけ合わせる。"""
        return self._session.scalars(stmt)

    async def execute(self, stmt):
        """await の形だけ合わせる。"""
        return self._session.execute(stmt)

    async def delete(self, obj):
        """本番は AsyncSession.delete が待てるので、こちらも待てる形にする。"""
        self._session.delete(obj)

    async def flush(self):
        """await の形だけ合わせる。"""
        self._session.flush()

    async def commit(self):
        """await の形だけ合わせる。"""
        self._session.commit()

    def close(self):
        """後始末。"""
        self._session.close()


class StoreWeeklyForecastTests(unittest.TestCase):
    """store_weekly_forecast が、いつも「直近1回分だけ」を残すこと。

    151行あるこの関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
    **この関数にはテストが1件も無かった。**

    予測は外部API（為替・ニュース）を叩いて作るので、失敗して途中の状態で
    呼び直されることがある。追記になっていると古い予測と新しい予測が並存し、
    フロントがどちらを表示するか・精度集計がどちらを見るかが曖昧になる。
    **並存しても例外は出ない。**画面に古い日付が混ざるだけで、気づくのは
    数字を突き合わせた人だけになる。
    """

    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        self.engine = create_engine("sqlite://")
        WeeklyForecastDaily.__table__.create(bind=self.engine, checkfirst=True)
        WeeklyForecastMeta.__table__.create(bind=self.engine, checkfirst=True)
        self.maker = sessionmaker(bind=self.engine, expire_on_commit=False)

    def _payload(self, *, as_of="2026-08-30", days=("2026-08-31", "2026-09-01"), metals=("gold", "silver")):
        """最小限だが本物と同じ形の payload。"""
        forecast = {}
        for index, metal_key in enumerate(metals):
            forecast[metal_key] = {
                "start_price_per_gram": 5000 + index,
                "projected_price_per_gram": 5010 + index,
                "projected_change_pct_7d": 0.2,
                "confidence": 0.6,
                "implied_daily_return_pct": 0.03,
                "drivers": [f"{metal_key} の根拠"],
                "summary": f"{metal_key} のまとめ",
                "driver_breakdown": [],
                "daily": [
                    {
                        "date": day,
                        "price_per_gram": 5010 + index + offset,
                        "delta_from_previous": 1 + offset,
                        "lower_price_per_gram": 4950 + index,
                        "upper_price_per_gram": 5070 + index,
                    }
                    for offset, day in enumerate(days)
                ],
            }
        return {
            "as_of_date": as_of,
            "horizon_days": 7,
            "generated_at": "2026-08-30T09:00:00+09:00",
            "forecast": forecast,
            "model": {"name": "interval_rw_v1", "description": "テスト"},
            "signals": {},
        }

    def _store(self, payload):
        """本物の store_weekly_forecast を、SQLite のセッションで走らせる。"""
        session = _StoreFakeSession(self.maker())
        try:
            asyncio.run(forecast_service.store_weekly_forecast(session, payload))
        finally:
            session.close()

    def _rows(self):
        """保存された日次行を (金属, 予測日, 中心値) で読み出す。"""
        with self.maker() as session:
            rows = session.scalars(select(WeeklyForecastDaily)).all()
            return sorted((r.metal_key, r.forecast_date.isoformat(), str(r.price_per_gram)) for r in rows)

    def _meta_rows(self):
        """保存された meta を (as_of, horizon, モデル名) で読み出す。"""
        with self.maker() as session:
            metas = session.scalars(select(WeeklyForecastMeta)).all()
            return [(m.as_of_date.isoformat(), m.horizon_days, m.model_name) for m in metas]

    def test_a_stored_forecast_writes_one_row_per_metal_and_day(self):
        """金属×予測日のぶんだけ行が入り、meta が1件できること。"""
        self._store(self._payload())

        self.assertEqual(
            self._rows(),
            [
                ("gold", "2026-08-31", "5010.0000"),
                ("gold", "2026-09-01", "5011.0000"),
                ("silver", "2026-08-31", "5011.0000"),
                ("silver", "2026-09-01", "5012.0000"),
            ],
        )
        self.assertEqual(self._meta_rows(), [("2026-08-30", 7, "interval_rw_v1")])

    def test_re_storing_replaces_the_previous_forecast_instead_of_appending(self):
        """作り直したら、前回の行が残らないこと。

        **この関数のいちばん大事な性質。** 追記になると古い予測と新しい予測が
        並存し、どちらを見ればいいのか誰にも分からなくなる。
        """
        self._store(self._payload())
        self._store(self._payload(as_of="2026-08-31", days=("2026-09-01",), metals=("gold",)))

        self.assertEqual(self._rows(), [("gold", "2026-09-01", "5010.0000")])
        self.assertEqual(self._meta_rows(), [("2026-08-31", 7, "interval_rw_v1")])

    def test_days_outside_the_horizon_are_not_stored(self):
        """予測期間の外の日付は捨てること。

        as_of 当日以前と、horizon を超えた先は入れない。入れてしまうと、
        画面のグラフに「今日より前の予測」が混ざる。
        """
        payload = self._payload(days=("2026-08-29", "2026-08-30", "2026-08-31", "2026-09-30"), metals=("gold",))
        self._store(payload)

        self.assertEqual(self._rows(), [("gold", "2026-08-31", "5012.0000")])

    def test_only_one_meta_row_survives(self):
        """meta が複数あっても、最新の1件だけを残すこと。

        meta は「この予測はいつ・どのモデルで作ったか」を持つ1行で、複数
        あるとフロントがどれを読むかで表示が変わる。**残っていても例外は
        出ない。**過去の版が複数書いていた可能性があるので、毎回掃除する。
        """
        # 2行入れる。1行だけだと、保存側が最古の行を使い回すので掃除が
        # 走らない（＝掃除を消しても落ちない）。過去の版が複数書いていた
        # 状態を作って初めて、この後始末が効いているか確かめられる。
        with self.maker() as session:
            for index in (1, 2):
                session.add(
                    WeeklyForecastMeta(
                        as_of_date=date(2020, 1, index),
                        generated_at=datetime(2020, 1, index, tzinfo=timezone.utc),
                        horizon_days=7,
                        model_name=f"古い版{index}",
                        model_description="前の版が書いた行",
                    )
                )
            session.commit()

        self._store(self._payload())

        self.assertEqual(self._meta_rows(), [("2026-08-30", 7, "interval_rw_v1")])

    def test_a_payload_without_an_as_of_date_is_refused(self):
        """as_of_date が無い payload は保存しないこと。

        黙って今日の日付で保存すると、いつ作った予測なのか分からなくなる。
        どの RuntimeError かまで見る。既定日を入れて先へ進む変異は、結果的に
        別の理由（保存できる行が無い）で落ちるので、種類を見ないと素通りする。
        """
        payload = self._payload()
        del payload["as_of_date"]
        with self.assertRaisesRegex(RuntimeError, "as_of_date"):
            self._store(payload)

    def test_a_payload_with_nothing_storable_is_refused(self):
        """入れられる行が1つも無いなら、保存せずに断ること。

        ここで黙って戻ると、**既存の行を消してから何も書かない**（＝予測が
        丸ごと消える）経路ができる。
        """
        with self.assertRaises(RuntimeError):
            self._store(self._payload(metals=("unknown_metal",)))


class FetchLlmSignalTests(unittest.IsolatedAsyncioTestCase):
    """fetch_llm_signal が、何が起きても同じ形を返すことを固定する。

    132行あるこの関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
    **この関数にもテストが1本も無かった。**

      - 無効化・APIキー未設定・呼び出し失敗・JSON解析失敗のどれでも、
        例外を投げず available=False の同じ形を返すこと
      - 金属のキーが必ず3つとも揃うこと
      - score は [-1,1]、confidence は [0,1] に丸めること
      - JSON が読めなかったときは診断材料をログに残すこと

    1つ目が崩れると **週次予測の再計算そのものが落ちる。** LLM判定は
    「効けば良い追加シグナル」であって前提条件ではないのに、統計モデル
    だけの予測にすら更新できなくなる。
    """

    def setUp(self):
        self.sig = forecast_signals
        self.metals = {"gold", "silver", "platinum"}

    def _inputs(self):
        """呼び出しに要る3つの引数。中身は最小限。"""
        return dict(
            history_by_metal={"gold": [], "silver": [], "platinum": []},
            fx_signal={"available": True, "weekly_change_pct": 0.5, "latest": 150.0},
            news_signal={"sentiment": {}, "article_counts": {}, "sample_headlines": {}},
        )

    def _assert_empty_shape(self, result, *, comment):
        """フォールバックの形（available=False・全金属0埋め）であること。"""
        self.assertFalse(result["available"])
        self.assertEqual(result["global_comment"], comment)
        self.assertEqual(set(result["scores"]), self.metals)
        self.assertEqual(set(result["confidences"]), self.metals)
        self.assertEqual(set(result["rationales"]), self.metals)
        self.assertEqual(set(result["scores"].values()), {0.0})
        self.assertEqual(set(result["confidences"].values()), {0.0})

    async def test_disabled_returns_the_fallback_without_calling_groq(self):
        """FORECAST_LLM_ENABLED=false なら、呼ばずにフォールバックを返すこと。"""
        with (
            patch.object(self.sig, "FORECAST_LLM_ENABLED", False),
            patch.object(self.sig, "create_json_chat_completion", AsyncMock()) as call,
        ):
            result = await self.sig.fetch_llm_signal(**self._inputs())

        call.assert_not_awaited()
        self._assert_empty_shape(result, comment="FORECAST_LLM_ENABLED=false")

    async def test_a_missing_api_key_returns_the_fallback_without_calling_groq(self):
        """APIキーが無いなら、呼ばずにフォールバックを返すこと。"""
        with (
            patch.object(self.sig, "FORECAST_LLM_ENABLED", True),
            patch.object(self.sig, "GROQ_API_KEY", ""),
            patch.object(self.sig, "create_json_chat_completion", AsyncMock()) as call,
        ):
            result = await self.sig.fetch_llm_signal(**self._inputs())

        call.assert_not_awaited()
        self._assert_empty_shape(result, comment="GROQ_API_KEY not configured")

    async def test_a_failed_call_does_not_escape(self):
        """Groq の呼び出しが落ちても、例外を外へ出さないこと。

        ここが例外を投げると**週次予測の再計算全体が失敗し**、LLM抜きの
        統計モデルだけの予測にすら更新できなくなる。
        """
        with (
            patch.object(self.sig, "FORECAST_LLM_ENABLED", True),
            patch.object(self.sig, "GROQ_API_KEY", "dummy"),
            patch.object(self.sig, "_get_groq_client", Mock()),
            patch.object(self.sig, "create_json_chat_completion", AsyncMock(side_effect=RuntimeError("落ちた"))),
            self.assertLogs(self.sig.logger, level="WARNING"),
        ):
            result = await self.sig.fetch_llm_signal(**self._inputs())

        self._assert_empty_shape(result, comment="LLM call failed")

    async def test_an_unparseable_answer_is_reported_with_diagnostics(self):
        """JSON が読めなかったときは、診断材料を残してフォールバックすること。

        静かに0を返すと「AI判定が効いていない」ことに気付けない。
        finish_reason・content の長さ・先頭を必ずログへ残す。
        """
        with (
            patch.object(self.sig, "FORECAST_LLM_ENABLED", True),
            patch.object(self.sig, "GROQ_API_KEY", "dummy"),
            patch.object(self.sig, "_get_groq_client", Mock()),
            patch.object(
                self.sig,
                "create_json_chat_completion",
                AsyncMock(return_value=("これはJSONではない", "length")),
            ),
            self.assertLogs(self.sig.logger, level="WARNING") as captured,
        ):
            result = await self.sig.fetch_llm_signal(**self._inputs())

        self._assert_empty_shape(result, comment="LLM response not parseable")
        logged = "\n".join(captured.output)
        self.assertIn("length", logged)
        self.assertIn("これはJSONではない", logged)

    async def test_out_of_range_numbers_are_clamped_and_missing_metals_filled(self):
        """範囲外の数値は丸め、返ってこなかった金属は0で埋めること。

        LLM は素直に [-1,1] を守るとは限らない。5.0 をそのまま通すと、
        予測の中心が**桁違いに傾く。** 例外は出ず、数字だけが変わる。
        金属を1つ落としてくることもあり、その場合にキーが欠けると
        呼び出し側が KeyError で落ちる。
        """
        answer = forecast_utils.json_dumps(
            {
                "global_comment": "コメント",
                "metals": {
                    "gold": {"score": 5.0, "confidence": 9.0, "rationale": "あ" * 300},
                    "silver": {"score": -7.0, "confidence": -3.0, "rationale": "い"},
                },
            }
        )
        with (
            patch.object(self.sig, "FORECAST_LLM_ENABLED", True),
            patch.object(self.sig, "GROQ_API_KEY", "dummy"),
            patch.object(self.sig, "_get_groq_client", Mock()),
            patch.object(self.sig, "create_json_chat_completion", AsyncMock(return_value=(answer, "stop"))),
        ):
            result = await self.sig.fetch_llm_signal(**self._inputs())

        self.assertTrue(result["available"])
        self.assertEqual(result["scores"]["gold"], 1.0)
        self.assertEqual(result["confidences"]["gold"], 1.0)
        self.assertEqual(result["scores"]["silver"], -1.0)
        self.assertEqual(result["confidences"]["silver"], 0.0)
        # 返ってこなかった金属も、キーごと欠けさせない
        self.assertEqual(result["scores"]["platinum"], 0.0)
        self.assertEqual(result["rationales"]["platinum"], "")
        self.assertLessEqual(len(result["rationales"]["gold"]), 140)


class BuildWeeklyForecastTests(unittest.IsolatedAsyncioTestCase):
    """build_weekly_forecast の組み立て方を固定する。

    128行あるこの関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
    **この関数にはテストが1本も無かった。** 外へ4回問い合わせるので
    書きにくく、そのまま残っていた。

    見るのは、割ったときに黙って変わりうるところだけ。

      - 1金属も作れなければ RuntimeError にすること
      - 一部の金属だけ作れたときは、作れたぶんを返すこと
      - 要約は「予測を作ったあと」に取り、既存の金属にだけ入れること
      - LLM 判定は為替とニュースの結果を受け取ってから呼ぶこと

    1つ目が特に効く。ここで例外にせず空の payload を返すと、呼び出し元の
    バッチが**そのまま「予測なし」をキャッシュへ上書きする。** 古い予測
    ごと消える。
    """

    def setUp(self):
        self.fs = forecast_service

    class _FakeClientSession:
        """aiohttp.ClientSession の代わり。中では何も通信しない。"""

        def __init__(self, *a, **k):
            """引数（timeout/headers）は受け取るだけ。"""

        async def __aenter__(self):
            """自分を返す。"""
            return self

        async def __aexit__(self, *exc):
            """例外は握らない。"""
            return False

    def _item(self, metal_key):
        """forecast_for_metal が返す1金属ぶんの代わり。"""
        return {"start_price_per_gram": 100.0, "drivers": [f"{metal_key}の理由"]}

    def _patched(self, stack, *, for_metal, summaries=None, llm=None):
        """外への問い合わせを全部差し替える。返した mock を辞書で渡す。"""
        order: list[str] = []

        async def fx(*a, **k):
            """為替の取得。"""
            order.append("fx")
            return {"available": True, "daily_factor": 0.0, "daily_returns_by_date": {}, "source": "Stooq"}

        async def news(*a, **k):
            """ニュースの取得。"""
            order.append("news")
            return {"available": True, "sentiment": {}, "article_counts": {}, "sample_headlines": {}}

        async def llm_signal(**kwargs):
            """LLM 判定。為替とニュースの結果を受け取っているかを控える。"""
            order.append("llm")
            order.append(f"llm_saw_fx={bool(kwargs.get('fx_signal'))}")
            order.append(f"llm_saw_news={bool(kwargs.get('news_signal'))}")
            return llm or {"available": False, "scores": {}, "confidences": {}, "rationales": {}}

        async def summaries_fn(*, forecast):
            """要約の取得。呼ばれた時点の金属一覧を控える。"""
            order.append("summaries:" + ",".join(sorted(forecast)))
            return summaries or {}

        mocks = {
            "order": order,
            "load_history": stack.enter_context(
                patch.object(self.fs, "load_history", AsyncMock(return_value={"gold": [1], "silver": [1]}))
            ),
            "accuracy": stack.enter_context(
                patch.object(self.fs, "load_recent_forecast_error", AsyncMock(return_value={}))
            ),
            "session": stack.enter_context(patch.object(self.fs.aiohttp, "ClientSession", self._FakeClientSession)),
            "fx": stack.enter_context(patch.object(self.fs, "fetch_usdjpy_signal", fx)),
            "news": stack.enter_context(patch.object(self.fs, "fetch_news_signals", news)),
            "llm": stack.enter_context(patch.object(self.fs, "fetch_llm_signal", llm_signal)),
            "for_metal": stack.enter_context(patch.object(self.fs, "forecast_for_metal", for_metal)),
            "summaries": stack.enter_context(patch.object(self.fs, "fetch_forecast_summaries", summaries_fn)),
        }
        return mocks

    async def test_no_metal_at_all_raises_instead_of_returning_an_empty_forecast(self):
        """1金属も作れなければ RuntimeError にすること。

        空の payload を返すと、呼び出し元のバッチがそれを**そのまま
        キャッシュへ上書きする。** 古い予測ごと消え、画面から予測が
        まるごと無くなる。例外にしておけば、バッチは古い予測を残せる。
        """
        with ExitStack() as stack:
            self._patched(stack, for_metal=Mock(return_value=None))
            with self.assertRaisesRegex(RuntimeError, "価格履歴"):
                await self.fs.build_weekly_forecast(Mock())

    async def test_the_metals_that_could_be_built_are_returned(self):
        """一部の金属だけ作れたときは、作れたぶんを返すこと。

        履歴が足りない金属が1つあるだけで全部落とすと、残りの予測まで
        出なくなる。
        """

        def for_metal(*, metal_key, **kwargs):
            """gold だけ作れる。"""
            return self._item(metal_key) if metal_key == "gold" else None

        with ExitStack() as stack:
            self._patched(stack, for_metal=for_metal)
            payload = await self.fs.build_weekly_forecast(Mock())

        self.assertEqual(set(payload["forecast"]), {"gold"})

    async def test_the_summary_is_fetched_after_the_forecast_and_only_fills_known_metals(self):
        """要約は予測を作ったあとに取り、既存の金属にだけ入れること。

        要約は drivers を材料に書かせるので、予測より先には取れない。
        また、返ってきた金属名を素直に信じて入れると、**予測が無いのに
        要約だけある金属**が payload に生える。フロントエンドはそれを
        1つの予測として描こうとして落ちる。空文字で既存の要約を
        上書きしないことも併せて見る。
        """

        def for_metal(*, metal_key, **kwargs):
            """gold だけ作れる。"""
            return self._item(metal_key) if metal_key == "gold" else None

        with ExitStack() as stack:
            mocks = self._patched(
                stack,
                for_metal=for_metal,
                summaries={"gold": "金の要約", "platinum": "作れなかった金属の要約", "silver": ""},
            )
            payload = await self.fs.build_weekly_forecast(Mock())

        self.assertIn("summaries:gold", mocks["order"])
        self.assertLess(mocks["order"].index("llm"), mocks["order"].index("summaries:gold"))
        self.assertEqual(set(payload["forecast"]), {"gold"})
        self.assertEqual(payload["forecast"]["gold"]["summary"], "金の要約")

    async def test_the_llm_is_asked_after_the_fx_and_news_results_are_in(self):
        """LLM 判定は、為替とニュースの結果を受け取ってから呼ぶこと。

        LLM はこの2つを材料に採点する。並行に走らせると空のまま採点する
        ことになり、**点は返るが中身が変わる。** 例外も出ないし、
        payload の形も同じなので、出てきた数字を疑うまで気づけない。
        """
        with ExitStack() as stack:
            mocks = self._patched(stack, for_metal=lambda *, metal_key, **k: self._item(metal_key))
            await self.fs.build_weekly_forecast(Mock())

        order = mocks["order"]
        self.assertLess(order.index("fx"), order.index("llm"))
        self.assertLess(order.index("news"), order.index("llm"))
        self.assertIn("llm_saw_fx=True", order)
        self.assertIn("llm_saw_news=True", order)


class ForecastServicePureTests(unittest.TestCase):
    """_forecast_payload_from_db / _trim_payload_to_days をDB無しで検証する。

    WeeklyForecastMeta/WeeklyForecastDaily はSQLAlchemyの宣言モデルだが、セッションへ
    addしない限りDBへは一切触れないため、通常のPythonオブジェクトとして組み立てられる。
    """

    def _make_meta(self, **overrides) -> WeeklyForecastMeta:
        defaults = dict(
            as_of_date=date(2026, 8, 30),
            generated_at=datetime(2026, 8, 30, 9, 0, tzinfo=timezone.utc),
            horizon_days=7,
            model_name="interval_rw_v1",
            model_description="テスト用の説明文",
            usd_jpy_available=True,
            usd_jpy_source="Frankfurter (ECB)",
            news_available=True,
            news_source="Google News RSS",
            news_sentiment_json="{}",
            news_article_counts_json="{}",
            news_headlines_json="{}",
        )
        defaults.update(overrides)
        return WeeklyForecastMeta(**defaults)

    def _make_row(self, **overrides) -> WeeklyForecastDaily:
        defaults = dict(
            metal_key="gold",
            as_of_date=date(2026, 8, 30),
            forecast_date=date(2026, 8, 31),
            start_price_per_gram=Decimal("5000.0000"),
            projected_price_per_gram=Decimal("5010.0000"),
            price_per_gram=Decimal("5010.0000"),
            delta_from_previous=Decimal("10.0000"),
            projected_change_pct_7d=Decimal("0.200000"),
            confidence=Decimal("0.600000"),
            implied_daily_return_pct=Decimal("0.030000"),
            lower_price_per_gram=Decimal("4950.0000"),
            upper_price_per_gram=Decimal("5070.0000"),
            drivers_json="[]",
        )
        defaults.update(overrides)
        return WeeklyForecastDaily(**defaults)

    def test_forecast_payload_from_db_basic_structure(self):
        meta = self._make_meta()
        rows = [self._make_row()]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)
        self.assertEqual(payload["as_of_date"], "2026-08-30")
        self.assertIn("gold", payload["forecast"])
        gold = payload["forecast"]["gold"]
        self.assertEqual(gold["start_price_per_gram"], 5000.0)
        self.assertEqual(len(gold["daily"]), 1)
        self.assertAlmostEqual(gold["projected_lower_change_pct"], -1.0, places=6)
        self.assertAlmostEqual(gold["projected_upper_change_pct"], 1.4, places=6)
        # llm/interval/accuracy が保存されていない旧キャッシュ相当 → 既定値で補う
        self.assertFalse(payload["signals"]["llm"]["available"])
        self.assertEqual(payload["signals"]["interval"]["prob"], forecast_service.FORECAST_INTERVAL_PROB)
        self.assertFalse(payload["signals"]["accuracy"]["available"])

    def test_forecast_payload_from_db_sorts_daily_rows_by_date(self):
        meta = self._make_meta()
        rows = [
            self._make_row(forecast_date=date(2026, 9, 2), price_per_gram=Decimal("5020.0000")),
            self._make_row(forecast_date=date(2026, 8, 31), price_per_gram=Decimal("5010.0000")),
        ]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)
        daily = payload["forecast"]["gold"]["daily"]
        self.assertEqual([d["date"] for d in daily], ["2026-08-31", "2026-09-02"])

    def test_forecast_payload_from_db_reads_new_style_headlines_payload(self):
        headlines_payload = forecast_utils.json_dumps(
            {
                "sample_headlines": {"gold": ["headline1"]},
                "llm": {"available": True, "source": "Groq", "model": "m", "scores": {"gold": 0.4}},
                "interval": {"prob": 0.8, "tilt_max_pct_per_day": 0.15},
                "accuracy": {"available": True, "lookback_days": 14, "mean_abs_error_pct": {"gold": 1.2}},
                "summaries": {"gold": "要約文"},
                "driver_breakdowns": {"gold": [{"label": "x"}]},
            }
        )
        meta = self._make_meta(news_headlines_json=headlines_payload)
        rows = [self._make_row()]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)
        self.assertTrue(payload["signals"]["llm"]["available"])
        self.assertEqual(payload["signals"]["news"]["sample_headlines"], {"gold": ["headline1"]})
        self.assertEqual(payload["forecast"]["gold"]["summary"], "要約文")
        self.assertEqual(payload["forecast"]["gold"]["driver_breakdown"], [{"label": "x"}])

    def test_forecast_payload_from_db_legacy_headlines_payload_is_treated_as_sample_headlines(self):
        # "sample_headlines" キーが無い旧形式では、辞書全体が見出し一覧として扱われる
        legacy_headlines = forecast_utils.json_dumps({"gold": ["旧形式の見出し"]})
        meta = self._make_meta(news_headlines_json=legacy_headlines)
        rows = [self._make_row()]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)
        self.assertEqual(payload["signals"]["news"]["sample_headlines"], {"gold": ["旧形式の見出し"]})
        self.assertEqual(payload["forecast"]["gold"]["summary"], "")

    def test_the_band_comes_from_the_last_day_not_the_first(self):
        """予測帯（projected_lower/upper）は、最終日の行から取ること。

        他の値（start_price・confidence 等）は全部**先頭の行**から取って
        いるので、帯も first から取るのは自然な間違いになる。**1日ぶんしか
        無いテストでは first と last が同じ**ため、既存のテストは全部通った
        ままになる。帯だけが1日目の幅で描かれ、7日先まで同じ太さになる。

        6日先まで割ってあるこの関数を分ける前に押さえる
        （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
        """
        meta = self._make_meta()
        rows = [
            self._make_row(
                forecast_date=date(2026, 8, 31),
                lower_price_per_gram=Decimal("4990.0000"),
                upper_price_per_gram=Decimal("5030.0000"),
            ),
            self._make_row(
                forecast_date=date(2026, 9, 5),
                lower_price_per_gram=Decimal("4800.0000"),
                upper_price_per_gram=Decimal("5300.0000"),
            ),
        ]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)
        gold = payload["forecast"]["gold"]

        self.assertEqual(gold["projected_lower_per_gram"], 4800.0)
        self.assertEqual(gold["projected_upper_per_gram"], 5300.0)
        # 変化率も最終日基準（start_price=5000）
        self.assertAlmostEqual(gold["projected_lower_change_pct"], -4.0, places=6)
        self.assertAlmostEqual(gold["projected_upper_change_pct"], 6.0, places=6)

    def test_rows_saved_before_the_interval_columns_keep_a_missing_band(self):
        """区間列が NULL の古い行は、None のまま返すこと。

        区間列は migration 0004 で足したので、それ以前に保存された行では
        NULL になる。0.0 で埋めると**幅ゼロの帯**が描かれ、「予測が
        ぴたりと当たる」ように見えてしまう。欠けていることは欠けている
        まま渡し、フロントエンドが帯なしで描けるようにする。
        """
        meta = self._make_meta()
        rows = [
            self._make_row(
                forecast_date=date(2026, 8, 31),
                lower_price_per_gram=None,
                upper_price_per_gram=None,
            )
        ]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)
        gold = payload["forecast"]["gold"]

        self.assertIsNone(gold["daily"][0]["lower_price_per_gram"])
        self.assertIsNone(gold["daily"][0]["upper_price_per_gram"])
        self.assertIsNone(gold["projected_lower_per_gram"])
        self.assertIsNone(gold["projected_upper_per_gram"])
        self.assertIsNone(gold["projected_lower_change_pct"])
        self.assertIsNone(gold["projected_upper_change_pct"])

    def test_each_metal_gets_its_own_rows_and_its_own_text(self):
        """金属ごとに、その金属の行・要約・内訳だけが入ること。

        既存のテストは全部 gold 1種類だけで通してきた。金属をまたいで行が
        混ざったり、要約が取り違えられたりしても**1種類しか無いテストでは
        再現しない。** 画面には出るので、見た人が「金の要約がプラチナに
        付いている」と気づくまで分からない。
        """
        headlines_payload = forecast_utils.json_dumps(
            {
                "sample_headlines": {},
                "summaries": {"gold": "金の要約", "platinum": "プラチナの要約"},
                "driver_breakdowns": {"gold": [{"label": "金"}], "platinum": [{"label": "白金"}]},
            }
        )
        meta = self._make_meta(news_headlines_json=headlines_payload)
        rows = [
            self._make_row(metal_key="platinum", forecast_date=date(2026, 9, 2)),
            self._make_row(metal_key="gold", forecast_date=date(2026, 9, 2)),
            self._make_row(metal_key="gold", forecast_date=date(2026, 8, 31)),
        ]
        payload = forecast_service._forecast_payload_from_db(meta=meta, rows=rows)

        self.assertEqual(set(payload["forecast"]), {"gold", "platinum"})
        self.assertEqual([d["date"] for d in payload["forecast"]["gold"]["daily"]], ["2026-08-31", "2026-09-02"])
        self.assertEqual([d["date"] for d in payload["forecast"]["platinum"]["daily"]], ["2026-09-02"])
        self.assertEqual(payload["forecast"]["gold"]["summary"], "金の要約")
        self.assertEqual(payload["forecast"]["platinum"]["summary"], "プラチナの要約")
        self.assertEqual(payload["forecast"]["gold"]["driver_breakdown"], [{"label": "金"}])
        self.assertEqual(payload["forecast"]["platinum"]["driver_breakdown"], [{"label": "白金"}])

    def test_trim_payload_to_days_noop_when_days_covers_full_horizon(self):
        payload = {"horizon_days": 7, "forecast": {"gold": {"daily": [{"price_per_gram": 1.0}] * 7}}}
        result = forecast_service._trim_payload_to_days(payload, 7)
        self.assertEqual(result, payload)

    def test_trim_payload_to_days_trims_and_recomputes_change_pct(self):
        payload = {
            "horizon_days": 7,
            "forecast": {
                "gold": {
                    "start_price_per_gram": 5000.0,
                    "projected_price_per_gram": 5100.0,
                    "projected_change_pct_7d": 2.0,
                    "daily": [
                        {"date": "2026-08-31", "price_per_gram": 5010.0},
                        {"date": "2026-09-01", "price_per_gram": 5020.0},
                        {"date": "2026-09-02", "price_per_gram": 5100.0},
                    ],
                }
            },
        }
        trimmed = forecast_service._trim_payload_to_days(payload, 2)
        gold = trimmed["forecast"]["gold"]
        self.assertEqual(trimmed["horizon_days"], 2)
        self.assertEqual(len(gold["daily"]), 2)
        self.assertEqual(gold["projected_price_per_gram"], 5020.0)
        self.assertAlmostEqual(gold["projected_change_pct_7d"], 0.4, places=6)
        # 元のpayloadは書き換えない(json_dumps/json_loadsでディープコピーされる)
        self.assertEqual(len(payload["forecast"]["gold"]["daily"]), 3)


# ======================================================================
# security.py — 信頼プロキシCIDR・許可ホスト・レート制限
# ======================================================================
class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    """RateLimitMiddleware.dispatch が実際に触れる属性(url.path / client.host /
    headers.get)だけを持つ最小のフェイク。starlette.Request 全体を組み立てずに
    ディスパッチのロジックだけを検証できる。"""

    def __init__(self, *, path="/api/ping", client_host="203.0.113.5", headers=None):
        self.client = _FakeClient(client_host) if client_host is not None else None
        self.headers = headers or {}
        self.url = SimpleNamespace(path=path)


class SecurityHeadersMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    """レスポンスへ固定のセキュリティヘッダ一式が必ず付与されることを確認する。"""

    async def test_dispatch_adds_security_headers(self):
        from starlette.responses import Response

        middleware = security_module.SecurityHeadersMiddleware(app=None)

        async def call_next(_request):
            return Response("ok")

        response = await middleware.dispatch(_FakeRequest(), call_next)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])


class RateLimitMiddlewarePureTests(unittest.TestCase):
    """トークン取り出し・CIDR解析・信頼判定などディスパッチ以外の内部ロジックを検証する。"""

    def _middleware(self, **kwargs):
        return security_module.RateLimitMiddleware(app=None, **kwargs)

    def test_parse_ip_token_plain_ipv4(self):
        m = self._middleware()
        self.assertEqual(m._parse_ip_token("203.0.113.5"), "203.0.113.5")

    def test_parse_ip_token_ipv4_with_port(self):
        m = self._middleware()
        self.assertEqual(m._parse_ip_token("203.0.113.5:8443"), "203.0.113.5")

    def test_parse_ip_token_bracketed_ipv6_with_port(self):
        m = self._middleware()
        self.assertEqual(m._parse_ip_token("[2001:db8::1]:443"), "2001:db8::1")

    def test_parse_ip_token_invalid_or_empty_returns_none(self):
        m = self._middleware()
        self.assertIsNone(m._parse_ip_token("not-an-ip"))
        self.assertIsNone(m._parse_ip_token(""))
        self.assertIsNone(m._parse_ip_token(None))

    def test_parse_proxy_cidrs_skips_invalid_entries(self):
        nets = security_module.RateLimitMiddleware._parse_proxy_cidrs(["10.0.0.0/8", "not-a-cidr", "192.168.1.0/24"])
        self.assertEqual(len(nets), 2)

    def test_is_trusted_proxy_true_within_configured_network(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"])
        self.assertTrue(m._is_trusted_proxy("10.1.2.3"))

    def test_is_trusted_proxy_false_outside_network(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"])
        self.assertFalse(m._is_trusted_proxy("203.0.113.5"))

    def test_is_trusted_proxy_false_when_no_remote_ip(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"])
        self.assertFalse(m._is_trusted_proxy(None))
        self.assertFalse(m._is_trusted_proxy(""))

    def test_extract_client_ip_untrusted_proxy_uses_remote_ip_regardless_of_headers(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"])
        request = _FakeRequest(client_host="203.0.113.5", headers={"cf-connecting-ip": "1.2.3.4"})
        ip, used_cf = m._extract_client_ip(request)
        self.assertEqual(ip, "203.0.113.5")
        self.assertFalse(used_cf)

    def test_extract_client_ip_trusted_proxy_prefers_cf_header(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"], trust_cf_headers=True)
        request = _FakeRequest(client_host="10.0.0.1", headers={"cf-connecting-ip": "198.51.100.9"})
        ip, used_cf = m._extract_client_ip(request)
        self.assertEqual(ip, "198.51.100.9")
        self.assertTrue(used_cf)

    def test_extract_client_ip_trusted_proxy_falls_back_to_x_real_ip(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"], trust_cf_headers=False)
        request = _FakeRequest(client_host="10.0.0.1", headers={"x-real-ip": "198.51.100.9"})
        ip, used_cf = m._extract_client_ip(request)
        self.assertEqual(ip, "198.51.100.9")
        self.assertFalse(used_cf)

    def test_extract_client_ip_trusted_proxy_falls_back_to_x_forwarded_for_first_hop(self):
        m = self._middleware(trusted_proxy_cidrs=["10.0.0.0/8"], trust_cf_headers=False)
        request = _FakeRequest(
            client_host="10.0.0.1",
            headers={"x-forwarded-for": "198.51.100.9, 10.0.0.1"},
        )
        ip, used_cf = m._extract_client_ip(request)
        self.assertEqual(ip, "198.51.100.9")
        self.assertFalse(used_cf)

    def test_cleanup_removes_expired_ip_buckets(self):
        m = self._middleware(window_seconds=60)
        m._hits["default:1.2.3.4"].append(0.0)  # 十分に古いタイムスタンプ
        m._last_cleanup = 0.0
        m._cleanup(now=1000.0)
        self.assertNotIn("default:1.2.3.4", m._hits)

    def test_cleanup_skips_when_called_within_window(self):
        m = self._middleware(window_seconds=60)
        m._hits["default:1.2.3.4"].append(0.0)
        m._last_cleanup = 100.0
        m._cleanup(now=110.0)  # window未満なので何もしない
        self.assertIn("default:1.2.3.4", m._hits)


class RateLimitMiddlewareDispatchTests(unittest.IsolatedAsyncioTestCase):
    """dispatch全体(制限判定・429・403・calculateバケット分離)を検証する。"""

    async def asyncSetUp(self):
        self.middleware = security_module.RateLimitMiddleware(
            app=None,
            requests_per_window=2,
            calculate_requests_per_window=1,
            window_seconds=60,
        )
        self.downstream_called = 0

        async def call_next(_request):
            self.downstream_called += 1
            return SimpleNamespace(sentinel="downstream-response")

        self.call_next = call_next

    async def test_non_api_path_bypasses_rate_limit(self):
        request = _FakeRequest(path="/health")
        response = await self.middleware.dispatch(request, self.call_next)
        self.assertEqual(response.sentinel, "downstream-response")
        self.assertEqual(self.downstream_called, 1)
        self.assertEqual(len(self.middleware._hits), 0)

    async def test_requests_under_limit_pass_through(self):
        request = _FakeRequest(path="/api/ping")
        for _ in range(2):
            response = await self.middleware.dispatch(request, self.call_next)
            self.assertEqual(response.sentinel, "downstream-response")
        self.assertEqual(self.downstream_called, 2)

    async def test_exceeding_limit_returns_429_with_retry_after(self):
        request = _FakeRequest(path="/api/ping")
        for _ in range(2):
            await self.middleware.dispatch(request, self.call_next)
        response = await self.middleware.dispatch(request, self.call_next)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")
        # 429を返した分は call_next(=downstream) へは到達していない
        self.assertEqual(self.downstream_called, 2)

    async def test_calculate_endpoint_uses_its_own_lower_limit_bucket(self):
        calculate_request = _FakeRequest(path="/api/prices/calculate")
        ping_request = _FakeRequest(path="/api/ping")
        first = await self.middleware.dispatch(calculate_request, self.call_next)
        self.assertEqual(first.sentinel, "downstream-response")
        # calculateの上限(1)に達したので次は429
        second = await self.middleware.dispatch(calculate_request, self.call_next)
        self.assertEqual(second.status_code, 429)
        # calculate用バケットとdefaultバケットは別なので、defaultはまだ通る
        third = await self.middleware.dispatch(ping_request, self.call_next)
        self.assertEqual(third.sentinel, "downstream-response")

    async def test_require_cf_connecting_ip_rejects_without_cf_header(self):
        middleware = security_module.RateLimitMiddleware(
            app=None,
            require_cf_connecting_ip=True,
            trusted_proxy_cidrs=["10.0.0.0/8"],
        )
        request = _FakeRequest(path="/api/ping", client_host="10.0.0.1", headers={})
        response = await middleware.dispatch(request, self.call_next)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.downstream_called, 0)

    async def test_require_cf_connecting_ip_allows_with_cf_header(self):
        middleware = security_module.RateLimitMiddleware(
            app=None,
            require_cf_connecting_ip=True,
            trust_cf_headers=True,
            trusted_proxy_cidrs=["10.0.0.0/8"],
        )
        request = _FakeRequest(path="/api/ping", client_host="10.0.0.1", headers={"cf-connecting-ip": "198.51.100.9"})
        response = await middleware.dispatch(request, self.call_next)
        self.assertEqual(response.sentinel, "downstream-response")


class SecurityEnvHelpersTests(unittest.TestCase):
    """read_env_bool / load_allowed_hosts / load_trusted_proxy_cidrs の環境変数解釈を検証する。"""

    def test_read_env_bool_delegates_to_envutil(self):
        with patch.dict(os.environ, {"SOME_FLAG": "true"}, clear=False):
            self.assertTrue(security_module.read_env_bool("SOME_FLAG", False))
        with patch.dict(os.environ, {"SOME_FLAG": "false"}, clear=False):
            self.assertFalse(security_module.read_env_bool("SOME_FLAG", True))

    def test_read_env_bool_falls_back_to_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MISSING_FLAG_XYZ", None)
            self.assertTrue(security_module.read_env_bool("MISSING_FLAG_XYZ", True))

    def test_load_allowed_hosts_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ALLOWED_HOSTS", None)
            self.assertEqual(security_module.load_allowed_hosts(), ["localhost", "127.0.0.1", "::1"])

    def test_load_allowed_hosts_parses_comma_separated_list(self):
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "example.com, api.example.com ,,"}, clear=False):
            self.assertEqual(security_module.load_allowed_hosts(), ["example.com", "api.example.com"])

    def test_load_allowed_hosts_blank_value_falls_back_to_default(self):
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "  , , "}, clear=False):
            self.assertEqual(security_module.load_allowed_hosts(), ["localhost", "127.0.0.1", "::1"])

    def test_load_trusted_proxy_cidrs_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRUSTED_PROXY_CIDRS", None)
            self.assertEqual(security_module.load_trusted_proxy_cidrs(), ["127.0.0.1/32", "::1/128"])

    def test_load_trusted_proxy_cidrs_empty_string_means_no_trusted_proxies(self):
        with patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": ""}, clear=False):
            self.assertEqual(security_module.load_trusted_proxy_cidrs(), [])

    def test_load_trusted_proxy_cidrs_parses_comma_list(self):
        with patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 192.168.0.0/16"}, clear=False):
            self.assertEqual(security_module.load_trusted_proxy_cidrs(), ["10.0.0.0/8", "192.168.0.0/16"])


# ======================================================================
# asset_version.py — 内容ハッシュによるキャッシュバスティング
# ======================================================================
class AssetVersionTests(unittest.TestCase):
    """ファイルI/Oはtempfileの実ファイルで行うが、ネットワーク・DBには一切触れない。"""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix="asset-version-test-")
        self.addCleanup(self.tmpdir.cleanup)
        base = Path(self.tmpdir.name)
        self.app_js = base / "app.js"
        self.styles_css = base / "styles.css"
        self.index_html = base / "index.html"
        self.sw_js = base / "sw.js"
        self.app_js.write_text("console.log('app');", encoding="utf-8")
        self.styles_css.write_text("body { color: red; }", encoding="utf-8")
        self.index_html.write_text(
            '<script src="static/app.js?v=OLD"></script>\n' '<link rel="stylesheet" href="static/styles.css?v=OLD">\n',
            encoding="utf-8",
        )
        self.sw_js.write_text('const CACHE_NAME = "old-cache-name";', encoding="utf-8")
        # モジュールグローバルの _render_cache は他テストと共有されるため、
        # このテストクラスが使うキーだけクリアしてから始める(順序非依存にする)。
        asset_version_module._render_cache.pop("index.html", None)
        asset_version_module._render_cache.pop("sw.js", None)

    def test_render_index_html_replaces_version_query(self):
        expected_version = asset_version_module.asset_version(self.app_js, self.styles_css)
        rendered = asset_version_module.render_index_html(self.index_html, self.app_js, self.styles_css)
        self.assertIn(f"static/app.js?v={expected_version}", rendered)
        self.assertIn(f"static/styles.css?v={expected_version}", rendered)
        self.assertNotIn("?v=OLD", rendered)

    def test_render_index_html_appends_query_when_missing(self):
        self.index_html.write_text('<script src="static/app.js"></script>', encoding="utf-8")
        expected_version = asset_version_module.asset_version(self.app_js, self.styles_css)
        rendered = asset_version_module.render_index_html(self.index_html, self.app_js, self.styles_css)
        self.assertIn(f"static/app.js?v={expected_version}", rendered)

    def test_render_service_worker_replaces_cache_name(self):
        # render_service_worker は sw.js 自身の内容もハッシュへ含めるため、
        # asset_version(app.js, styles.css) とは異なるバージョン文字列になる。
        expected_version = asset_version_module._content_hash([self.app_js, self.styles_css, self.sw_js])
        rendered = asset_version_module.render_service_worker(self.sw_js, self.app_js, self.styles_css)
        self.assertIn(f'CACHE_NAME = "metal-tracker-{expected_version}"', rendered)
        self.assertNotIn("old-cache-name", rendered)

    def test_asset_version_stable_when_content_unchanged(self):
        v1 = asset_version_module.asset_version(self.app_js, self.styles_css)
        v2 = asset_version_module.asset_version(self.app_js, self.styles_css)
        self.assertEqual(v1, v2)
        self.assertEqual(len(v1), 12)

    def test_asset_version_changes_when_content_changes(self):
        v1 = asset_version_module.asset_version(self.app_js, self.styles_css)
        self.styles_css.write_text("body { color: blue; }", encoding="utf-8")
        v2 = asset_version_module.asset_version(self.app_js, self.styles_css)
        self.assertNotEqual(v1, v2)

    def test_asset_version_missing_file_does_not_raise(self):
        missing = Path(self.tmpdir.name) / "does-not-exist.css"
        # 存在しないファイルでも例外を投げず、決定的なハッシュを返す
        v1 = asset_version_module.asset_version(self.app_js, missing)
        v2 = asset_version_module.asset_version(self.app_js, missing)
        self.assertEqual(v1, v2)

    def test_render_reuses_cache_when_stat_unchanged(self):
        """statが変化していない間はファイルを読み直さない(_content_hashが再計算されない)ことを確認する。"""
        original = asset_version_module._content_hash
        wrapped = Mock(side_effect=original)
        with patch.object(asset_version_module, "_content_hash", wrapped):
            first = asset_version_module.render_index_html(self.index_html, self.app_js, self.styles_css)
            call_count_after_first = wrapped.call_count
            second = asset_version_module.render_index_html(self.index_html, self.app_js, self.styles_css)
        self.assertEqual(first, second)
        self.assertEqual(wrapped.call_count, call_count_after_first)  # 2回目はキャッシュヒットで呼ばれない

    def test_render_recomputes_when_dependency_content_changes(self):
        first = asset_version_module.render_index_html(self.index_html, self.app_js, self.styles_css)
        # mtime分解能の粗いファイルシステムでも確実にstatを変えるため明示的にutimeをずらす
        self.styles_css.write_text("body { color: green; }", encoding="utf-8")
        new_stat = self.styles_css.stat()
        os_utime_ns = (new_stat.st_atime_ns, new_stat.st_mtime_ns + 10_000_000_000)
        os.utime(self.styles_css, ns=os_utime_ns)
        second = asset_version_module.render_index_html(self.index_html, self.app_js, self.styles_css)
        self.assertNotEqual(first, second)


# ======================================================================
# cache.py — 非同期TTL付きLRUキャッシュ
# ======================================================================
class TTLCacheTests(unittest.IsolatedAsyncioTestCase):
    """有効期限・LRU退避・アクセス順の更新をwebapp.cache.time.monotonicを差し替えて検証する。"""

    async def test_set_and_get_roundtrip(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60)
        await cache.set("k", "v")
        self.assertEqual(await cache.get("k"), "v")

    async def test_get_missing_key_returns_none(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60)
        self.assertIsNone(await cache.get("nope"))

    async def test_entry_expires_after_ttl(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60)
        with patch.object(cache_module.time, "monotonic", side_effect=[100.0, 100.0, 200.0]):
            await cache.set("k", "v", ttl_seconds=60)  # set: now=100.0 -> expires_at=160.0
            self.assertEqual(await cache.get("k"), "v")  # get: now=100.0 -> まだ有効
            self.assertIsNone(await cache.get("k"))  # get: now=200.0 -> 期限切れ

    async def test_expired_entry_is_removed_from_storage(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60)
        with patch.object(cache_module.time, "monotonic", side_effect=[0.0, 0.0, 1000.0]):
            await cache.set("k", "v")
            await cache.get("k")  # トリガーとして1回消費
            await cache.get("k")  # 期限切れでpopされる
        self.assertNotIn("k", cache._data)

    async def test_max_items_evicts_oldest_when_exceeded(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60, max_items=2)
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("c", 3)  # aが追い出される
        self.assertIsNone(await cache.get("a"))
        self.assertEqual(await cache.get("b"), 2)
        self.assertEqual(await cache.get("c"), 3)

    async def test_get_promotes_key_to_most_recently_used(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60, max_items=2)
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.get("a")  # aを最近使用扱いにする → 次に追い出されるのはb
        await cache.set("c", 3)
        self.assertEqual(await cache.get("a"), 1)
        self.assertIsNone(await cache.get("b"))
        self.assertEqual(await cache.get("c"), 3)

    async def test_clear_removes_all_entries(self):
        cache = cache_module.TTLCache(default_ttl_seconds=60)
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.clear()
        self.assertIsNone(await cache.get("a"))
        self.assertIsNone(await cache.get("b"))

    async def test_default_ttl_and_max_items_are_clamped_to_minimum_one(self):
        cache = cache_module.TTLCache(default_ttl_seconds=0, max_items=0)
        self.assertEqual(cache.default_ttl_seconds, 1)
        self.assertEqual(cache.max_items, 1)


# ======================================================================
# db.py — DB接続URLの組み立てとマイグレーション実行(実DBには繋がない)
# ======================================================================
_POSTGRES_ENV_KEYS = [
    "POSTGRES_DSN",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_PASSWORD_FILE",
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_DB",
]


class _FakeAsyncCM:
    """`async with obj:` で obj 自身を返すだけの最小の非同期コンテキストマネージャ。"""

    def __init__(self, target):
        self._target = target

    async def __aenter__(self):
        return self._target

    async def __aexit__(self, *exc_info):
        return False


class DbUrlTests(unittest.TestCase):
    """_build_database_url / _read_secret_file を実DBやファイルシステムの実挙動と
    切り離して検証する(_read_secret_fileはtempfileの実ファイルを使う)。"""

    def _clean_env(self):
        for key in _POSTGRES_ENV_KEYS:
            os.environ.pop(key, None)

    def test_build_database_url_uses_dsn_directly_when_set(self):
        with patch.dict(os.environ, {}, clear=False):
            self._clean_env()
            os.environ["POSTGRES_DSN"] = "postgresql://custom-dsn-value"
            self.assertEqual(db_module._build_database_url(), "postgresql://custom-dsn-value")

    def test_build_database_url_defaults_when_nothing_set(self):
        with patch.dict(os.environ, {}, clear=False):
            self._clean_env()
            url = db_module._build_database_url()
            self.assertEqual(url, "postgresql+asyncpg://postgres:postgres@localhost:5432/metal_prices")

    def test_build_database_url_quotes_special_characters(self):
        with patch.dict(os.environ, {}, clear=False):
            self._clean_env()
            os.environ["POSTGRES_USER"] = "user name"
            os.environ["POSTGRES_PASSWORD"] = "p@ss/word"
            os.environ["POSTGRES_HOST"] = "db.example.com"
            os.environ["POSTGRES_PORT"] = "5433"
            os.environ["POSTGRES_DB"] = "mydb"
            url = db_module._build_database_url()
            self.assertEqual(
                url,
                "postgresql+asyncpg://user+name:p%40ss%2Fword@db.example.com:5433/mydb",
            )

    def test_build_database_url_reads_password_from_file_when_env_var_absent(self):
        with tempfile.TemporaryDirectory(prefix="db-secret-test-") as tmpdir:
            secret_path = Path(tmpdir) / "postgres_password"
            secret_path.write_text("  secretpass  \n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=False):
                self._clean_env()
                os.environ["POSTGRES_PASSWORD_FILE"] = str(secret_path)
                url = db_module._build_database_url()
                self.assertIn("secretpass", url)

    def test_read_secret_file_strips_whitespace(self):
        with tempfile.TemporaryDirectory(prefix="db-secret-test-") as tmpdir:
            path = Path(tmpdir) / "secret.txt"
            path.write_text("  hello \n", encoding="utf-8")
            self.assertEqual(db_module._read_secret_file(str(path)), "hello")

    def test_read_secret_file_missing_path_returns_none(self):
        self.assertIsNone(db_module._read_secret_file(None))
        self.assertIsNone(db_module._read_secret_file("/no/such/file/exists.txt"))

    def test_read_secret_file_empty_file_returns_none(self):
        with tempfile.TemporaryDirectory(prefix="db-secret-test-") as tmpdir:
            path = Path(tmpdir) / "empty.txt"
            path.write_text("   \n", encoding="utf-8")
            self.assertIsNone(db_module._read_secret_file(str(path)))


class DbInitTests(unittest.IsolatedAsyncioTestCase):
    """init_db()のAlembic分岐(旧式DB検出→stamp+upgrade / 通常→upgradeのみ)を検証する。

    engine・_run_alembic_upgrade・_run_alembic_stampをすべてモックに差し替えるため、
    実DBや実Alembicには一切接続しない。
    """

    async def _run_init_db(self, *, has_alembic: bool, has_metal: bool):
        mock_conn = AsyncMock()
        mock_conn.run_sync = AsyncMock(side_effect=[has_alembic, has_metal])
        fake_engine = Mock(connect=Mock(return_value=_FakeAsyncCM(mock_conn)))
        with (
            patch.object(db_module, "engine", fake_engine),
            patch.object(db_module, "_run_alembic_stamp") as mock_stamp,
            patch.object(db_module, "_run_alembic_upgrade") as mock_upgrade,
        ):
            await db_module.init_db()
        return mock_conn, mock_stamp, mock_upgrade

    async def test_legacy_db_is_stamped_then_upgraded(self):
        mock_conn, mock_stamp, mock_upgrade = await self._run_init_db(has_alembic=False, has_metal=True)
        mock_stamp.assert_called_once_with("0001")
        mock_upgrade.assert_called_once()
        # advisory lock/unlockが同じキーで対になって呼ばれている
        self.assertEqual(mock_conn.execute.await_count, 2)
        lock_key = db_module.DB_MIGRATION_ADVISORY_LOCK_KEY
        called_params = [call.args[1] for call in mock_conn.execute.call_args_list]
        self.assertEqual(called_params, [{"key": lock_key}, {"key": lock_key}])

    async def test_non_legacy_db_only_upgrades(self):
        _, mock_stamp, mock_upgrade = await self._run_init_db(has_alembic=True, has_metal=True)
        mock_stamp.assert_not_called()
        mock_upgrade.assert_called_once()

    async def test_advisory_unlock_runs_even_if_migration_raises(self):
        mock_conn = AsyncMock()
        mock_conn.run_sync = AsyncMock(side_effect=[True, True])
        fake_engine = Mock(connect=Mock(return_value=_FakeAsyncCM(mock_conn)))
        with (
            patch.object(db_module, "engine", fake_engine),
            patch.object(db_module, "_run_alembic_upgrade", side_effect=RuntimeError("boom")),
        ):
            with self.assertRaises(RuntimeError):
                await db_module.init_db()
        # finally節でunlockが実行されるため、lock/unlockの2回は必ず呼ばれる
        self.assertEqual(mock_conn.execute.await_count, 2)

    async def test_close_db_disposes_engine(self):
        fake_engine = Mock(dispose=AsyncMock())
        with patch.object(db_module, "engine", fake_engine):
            await db_module.close_db()
        fake_engine.dispose.assert_awaited_once()


# ======================================================================
# push_service.py — VAPID設定キャッシュとWebPush送信の分岐
# ======================================================================
class PushServiceTests(unittest.IsolatedAsyncioTestCase):
    """VAPID設定のキャッシュとsend_pushの成功/404/410/その他失敗の分岐を検証する。
    pywebpushの実送信・vapid_service.load_vapid_configの実ファイルI/Oはモックする。
    """

    def setUp(self):
        self._original_cached_config = push_service._cached_config
        push_service._cached_config = None
        self.addCleanup(self._restore_cached_config)

    def _restore_cached_config(self):
        push_service._cached_config = self._original_cached_config

    def test_build_push_payload_structure_and_japanese_text(self):
        payload = push_service.build_push_payload(title="金の価格", body="上昇しました", url="./detail")
        import json as _json

        parsed = _json.loads(payload)
        self.assertEqual(
            parsed,
            {"title": "金の価格", "body": "上昇しました", "url": "./detail", "tag": "metal-daily-delta"},
        )

    def test_build_push_payload_default_url(self):
        payload = push_service.build_push_payload(title="t", body="b")
        self.assertIn('"url": "./"', payload)

    def test_refresh_vapid_config_calls_loader_and_caches_result(self):
        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        with patch.object(push_service, "load_vapid_config", return_value=config) as mock_loader:
            result = push_service.refresh_vapid_config()
        mock_loader.assert_called_once()
        self.assertEqual(result, config)
        self.assertEqual(push_service._cached_config, config)

    def test_get_vapid_public_key_uses_cached_config_without_reloading(self):
        config = VapidConfig(public_key="pub-key", private_key="priv", subject="mailto:a@example.com")
        push_service._cached_config = config
        with patch.object(push_service, "load_vapid_config") as mock_loader:
            self.assertEqual(push_service.get_vapid_public_key(), "pub-key")
        mock_loader.assert_not_called()

    def test_get_vapid_public_key_loads_when_not_cached(self):
        config = VapidConfig(public_key="pub-key", private_key="priv", subject="mailto:a@example.com")
        with patch.object(push_service, "load_vapid_config", return_value=config) as mock_loader:
            self.assertEqual(push_service.get_vapid_public_key(), "pub-key")
        mock_loader.assert_called_once()

    def test_is_push_enabled_true_when_all_fields_present(self):
        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        with patch.object(push_service, "load_vapid_config", return_value=config):
            self.assertTrue(push_service.is_push_enabled())

    def test_is_push_enabled_false_when_private_key_missing(self):
        config = VapidConfig(public_key="pub", private_key=None, subject="mailto:a@example.com")
        with patch.object(push_service, "load_vapid_config", return_value=config):
            self.assertFalse(push_service.is_push_enabled())

    async def test_send_push_returns_false_without_calling_webpush_when_unconfigured(self):
        config = VapidConfig(public_key=None, private_key=None, subject="mailto:a@example.com")
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush") as mock_webpush,
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "{}")
        self.assertEqual((success, remove), (False, False))
        mock_webpush.assert_not_called()

    async def test_send_push_success(self):
        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush", return_value=None) as mock_webpush,
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "payload")
        self.assertEqual((success, remove), (True, False))
        mock_webpush.assert_called_once()
        self.assertEqual(mock_webpush.call_args.kwargs["data"], "payload")

    async def test_send_push_404_marks_subscription_for_removal(self):
        from pywebpush import WebPushException

        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        exc = WebPushException("gone", response=Mock(status_code=404))
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush", side_effect=exc),
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "payload")
        self.assertEqual((success, remove), (False, True))

    async def test_send_push_410_marks_subscription_for_removal(self):
        from pywebpush import WebPushException

        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        exc = WebPushException("gone", response=Mock(status_code=410))
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush", side_effect=exc),
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "payload")
        self.assertEqual((success, remove), (False, True))

    async def test_send_push_other_status_does_not_remove_subscription(self):
        from pywebpush import WebPushException

        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        exc = WebPushException("server error", response=Mock(status_code=500))
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush", side_effect=exc),
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "payload")
        self.assertEqual((success, remove), (False, False))

    async def test_send_push_vapid_exception_returns_false_false(self):
        from py_vapid import VapidException

        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush", side_effect=VapidException("bad key")),
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "payload")
        self.assertEqual((success, remove), (False, False))

    async def test_send_push_unexpected_exception_returns_false_false(self):
        config = VapidConfig(public_key="pub", private_key="priv", subject="mailto:a@example.com")
        with (
            patch.object(push_service, "load_vapid_config", return_value=config),
            patch.object(push_service, "webpush", side_effect=RuntimeError("boom")),
        ):
            success, remove = await push_service.send_push({"endpoint": "https://x"}, "payload")
        self.assertEqual((success, remove), (False, False))


# ======================================================================
# snapshot_service.py — 日次スナップショットの取得・保存・読み出し
# ======================================================================
def _scalars_result(items: list) -> Mock:
    """`(await session.scalars(stmt)).all()` を模すための最小フェイク。"""
    return Mock(all=Mock(return_value=items))


class SnapshotServiceTests(unittest.IsolatedAsyncioTestCase):
    """MetalpriceAPI(fetch_metal_prices_per_gram)とAsyncSessionをすべてモックし、
    実DB・実APIには一切アクセスしない。"""

    def test_jst_today_matches_now_in_jst(self):
        expected = datetime.now(snapshot_service.JST).date()
        self.assertEqual(snapshot_service.jst_today(), expected)

    def test_as_decimal_quantizes_to_price_scale(self):
        self.assertEqual(snapshot_service._as_decimal(1.23455), Decimal("1.2346"))

    async def test_fetch_all_prices_success_maps_by_metal_key(self):
        with patch.object(
            snapshot_service,
            "fetch_metal_prices_per_gram",
            AsyncMock(return_value={"XAU": 5000.1234, "XAG": 70.5, "XPT": 3000.9}),
        ) as mock_fetch:
            prices = await snapshot_service._fetch_all_prices()
        mock_fetch.assert_awaited_once()
        self.assertEqual(prices["gold"], Decimal("5000.1234"))
        self.assertEqual(prices["silver"], Decimal("70.5000"))
        self.assertEqual(prices["platinum"], Decimal("3000.9000"))

    async def test_fetch_all_prices_skips_missing_codes(self):
        with patch.object(
            snapshot_service,
            "fetch_metal_prices_per_gram",
            AsyncMock(return_value={"XAU": 5000.0, "XAG": 70.0}),  # XPT欠落
        ):
            prices = await snapshot_service._fetch_all_prices()
        self.assertEqual(set(prices.keys()), {"gold", "silver"})

    async def test_fetch_all_prices_raises_when_all_missing(self):
        with patch.object(snapshot_service, "fetch_metal_prices_per_gram", AsyncMock(return_value={})):
            with self.assertRaises(RuntimeError):
                await snapshot_service._fetch_all_prices()

    async def test_fetch_all_prices_wraps_underlying_exception(self):
        with patch.object(
            snapshot_service, "fetch_metal_prices_per_gram", AsyncMock(side_effect=Exception("api down"))
        ):
            with self.assertRaises(RuntimeError):
                await snapshot_service._fetch_all_prices()

    async def test_store_snapshot_skips_fetch_when_all_metals_already_exist(self):
        today = date(2026, 8, 31)
        existing = [
            MetalPriceDaily(metal_key=key, metal_code=code, snapshot_date=today, price_per_gram=Decimal("1.0000"))
            for key, code in [("gold", "XAU"), ("silver", "XAG"), ("platinum", "XPT")]
        ]
        session = AsyncMock()
        session.scalars = AsyncMock(return_value=_scalars_result(existing))
        with patch.object(snapshot_service, "_fetch_all_prices", AsyncMock()) as mock_fetch:
            result = await snapshot_service.store_snapshot(session, today, skip_if_exists=True)
        mock_fetch.assert_not_called()
        self.assertEqual({row.metal_key for row in result}, {"gold", "silver", "platinum"})
        session.commit.assert_not_called()

    async def test_store_snapshot_creates_new_and_updates_existing_rows(self):
        today = date(2026, 8, 31)
        existing_gold = MetalPriceDaily(
            metal_key="gold",
            metal_code="OLD",
            snapshot_date=today,
            price_per_gram=Decimal("1.0000"),
            delta_from_previous=None,
        )
        previous_gold = MetalPriceDaily(
            metal_key="gold",
            metal_code="XAU",
            snapshot_date=today - timedelta(days=1),
            price_per_gram=Decimal("4990.0000"),
        )
        session = AsyncMock()
        session.add = Mock()
        session.scalars = AsyncMock(
            side_effect=[
                _scalars_result([existing_gold]),  # _rows_for_date(today)
                _scalars_result([previous_gold]),  # _latest_rows_before(today)
            ]
        )
        fetched = {
            "gold": Decimal("5000.0000"),
            "silver": Decimal("70.0000"),
            "platinum": Decimal("3000.0000"),
        }
        with patch.object(snapshot_service, "_fetch_all_prices", AsyncMock(return_value=fetched)):
            records = await snapshot_service.store_snapshot(session, today, skip_if_exists=True)

        self.assertEqual(len(records), 3)
        self.assertEqual(existing_gold.price_per_gram, Decimal("5000.0000"))
        self.assertEqual(existing_gold.delta_from_previous, Decimal("10.0000"))
        self.assertEqual(existing_gold.metal_code, "XAU")
        # 新規のsilver/platinumはsession.addで追加されている(goldは既存なので追加しない)
        self.assertEqual(session.add.call_count, 2)
        session.commit.assert_awaited_once()

    async def test_store_snapshot_skip_if_exists_false_forces_refetch(self):
        today = date(2026, 8, 31)
        existing = [
            MetalPriceDaily(metal_key=key, metal_code=code, snapshot_date=today, price_per_gram=Decimal("1.0000"))
            for key, code in [("gold", "XAU"), ("silver", "XAG"), ("platinum", "XPT")]
        ]
        session = AsyncMock()
        session.add = Mock()
        session.scalars = AsyncMock(
            side_effect=[_scalars_result(existing), _scalars_result([])]  # 既存フル / 前日データ無し
        )
        fetched = {"gold": Decimal("1.0000"), "silver": Decimal("1.0000"), "platinum": Decimal("1.0000")}
        with patch.object(snapshot_service, "_fetch_all_prices", AsyncMock(return_value=fetched)) as mock_fetch:
            await snapshot_service.store_snapshot(session, today, skip_if_exists=False)
        mock_fetch.assert_awaited_once()
        session.commit.assert_awaited_once()

    async def test_load_history_builds_dict_with_all_tracked_metals(self):
        session = AsyncMock()
        rows = [
            ("gold", date(2026, 8, 30), Decimal("5000.0000"), Decimal("10.0000")),
            ("gold", date(2026, 8, 31), Decimal("5010.0000"), None),
        ]
        session.execute = AsyncMock(return_value=Mock(all=Mock(return_value=rows)))
        history = await snapshot_service.load_history(session, 7, end_date=date(2026, 8, 31))
        self.assertEqual(set(history.keys()), {"gold", "silver", "platinum"})
        self.assertEqual(history["silver"], [])
        self.assertEqual(
            history["gold"],
            [
                {"date": "2026-08-30", "price_per_gram": 5000.0, "delta_from_previous": 10.0},
                {"date": "2026-08-31", "price_per_gram": 5010.0, "delta_from_previous": None},
            ],
        )

    async def test_load_latest_rows_maps_by_metal_key(self):
        session = AsyncMock()
        row = MetalPriceDaily(
            metal_key="gold", metal_code="XAU", snapshot_date=date(2026, 8, 31), price_per_gram=Decimal("5000.0000")
        )
        session.scalars = AsyncMock(return_value=_scalars_result([row]))
        latest_rows = await snapshot_service.load_latest_rows(session)
        self.assertEqual(latest_rows, {"gold": row})

    async def test_load_latest_fills_missing_metals_with_none(self):
        row = MetalPriceDaily(
            metal_key="gold",
            metal_code="XAU",
            snapshot_date=date(2026, 8, 31),
            price_per_gram=Decimal("5000.0000"),
            delta_from_previous=Decimal("5.0000"),
        )
        with patch.object(snapshot_service, "load_latest_rows", AsyncMock(return_value={"gold": row})):
            latest = await snapshot_service.load_latest(AsyncMock())
        self.assertEqual(
            latest["gold"],
            {"date": "2026-08-31", "price_per_gram": 5000.0, "delta_from_previous": 5.0},
        )
        self.assertEqual(latest["silver"], {"date": None, "price_per_gram": None, "delta_from_previous": None})

    async def test_load_earliest_snapshot_date_passes_through_scalar_result(self):
        session = AsyncMock()
        session.scalar = AsyncMock(return_value=date(2020, 1, 1))
        result = await snapshot_service.load_earliest_snapshot_date(session)
        self.assertEqual(result, date(2020, 1, 1))
        session.scalar.assert_awaited_once()


# ======================================================================
# repair_service.py — データ整合性の自動修復
# ======================================================================
def _valid_forecast_payload(as_of_date: str = "2026-08-31") -> dict:
    return {
        "as_of_date": as_of_date,
        "forecast": {
            key: {"daily": [{"date": "2026-09-01", "price_per_gram": 100.0}]} for key in ("gold", "silver", "platinum")
        },
    }


class RepairServiceQuantizeAndDriftTests(unittest.TestCase):
    """_quantize_delta / _forecast_has_drift(DBに触れない純粋な判定関数)を検証する。"""

    def test_quantize_delta_rounds_half_up_to_price_scale(self):
        self.assertEqual(repair_service._quantize_delta(Decimal("1.23455")), Decimal("1.2346"))

    def test_forecast_has_drift_none_payload_is_drift(self):
        self.assertTrue(repair_service._forecast_has_drift(None, latest_snapshot_date_iso="2026-08-31"))

    def test_forecast_has_drift_as_of_date_mismatch(self):
        payload = _valid_forecast_payload(as_of_date="2026-08-30")
        self.assertTrue(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso="2026-08-31"))

    def test_forecast_has_drift_forecast_not_dict(self):
        payload = {"as_of_date": "2026-08-31", "forecast": "not-a-dict"}
        self.assertTrue(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso=None))

    def test_forecast_has_drift_missing_metal_key(self):
        payload = _valid_forecast_payload()
        del payload["forecast"]["silver"]
        self.assertTrue(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso=None))

    def test_forecast_has_drift_metal_item_not_dict(self):
        payload = _valid_forecast_payload()
        payload["forecast"]["gold"] = "oops"
        self.assertTrue(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso=None))

    def test_forecast_has_drift_empty_daily_list(self):
        payload = _valid_forecast_payload()
        payload["forecast"]["gold"]["daily"] = []
        self.assertTrue(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso=None))

    def test_forecast_has_drift_first_daily_entry_missing_date(self):
        payload = _valid_forecast_payload()
        payload["forecast"]["gold"]["daily"] = [{"price_per_gram": 1.0}]
        self.assertTrue(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso=None))

    def test_forecast_has_drift_false_for_fully_valid_payload(self):
        payload = _valid_forecast_payload(as_of_date="2026-08-31")
        self.assertFalse(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso="2026-08-31"))

    def test_forecast_has_drift_false_when_no_snapshot_date_to_compare(self):
        payload = _valid_forecast_payload()
        self.assertFalse(repair_service._forecast_has_drift(payload, latest_snapshot_date_iso=None))


class RepairMetalpriceIntegrityTests(unittest.IsolatedAsyncioTestCase):
    """repair_metalprice_integrity のクールダウン制御・不整合検出・予測再生成分岐を検証する。

    session.scalars は「today_rows_before → 全件スキャン → today_rows_after」の順に
    3回呼ばれる実装の並びをそのままside_effectで再現する。store_snapshot /
    load_latest_rows / load_stored_weekly_forecast / refresh_weekly_forecast_cache は
    すべてモックし、実DB・外部APIには一切アクセスしない。
    """

    def setUp(self):
        self._original_last_attempt = repair_service._last_missing_data_repair_attempt
        repair_service._last_missing_data_repair_attempt = None
        self.addCleanup(self._restore_last_attempt)

    def _restore_last_attempt(self):
        repair_service._last_missing_data_repair_attempt = self._original_last_attempt

    def _today_rows(self, keys):
        return [
            MetalPriceDaily(metal_key=k, metal_code="X", snapshot_date=date(2026, 8, 31), price_per_gram=Decimal("1"))
            for k in keys
        ]

    async def test_no_missing_data_and_drifted_forecast_triggers_refresh(self):
        session = AsyncMock()
        session.scalars = AsyncMock(
            side_effect=[
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),  # today_rows_before: 欠損なし
                _scalars_result(
                    [
                        MetalPriceDaily(
                            metal_key="gold",
                            metal_code="WRONG",
                            snapshot_date=date(2026, 8, 1),
                            price_per_gram=Decimal("5000.0000"),
                            delta_from_previous=None,
                        ),
                        MetalPriceDaily(
                            metal_key="gold",
                            metal_code="XAU",
                            snapshot_date=date(2026, 8, 2),
                            price_per_gram=Decimal("5010.0000"),
                            delta_from_previous=Decimal("999.0000"),
                        ),
                    ]
                ),  # 全件スキャン
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),  # today_rows_after
            ]
        )
        with (
            patch.object(repair_service, "jst_today", return_value=date(2026, 8, 31)),
            patch.object(repair_service, "store_snapshot", AsyncMock()) as mock_store_snapshot,
            patch.object(
                repair_service,
                "load_latest_rows",
                AsyncMock(
                    return_value={
                        "gold": MetalPriceDaily(
                            metal_key="gold",
                            metal_code="XAU",
                            snapshot_date=date(2026, 8, 31),
                            price_per_gram=Decimal("1"),
                        )
                    }
                ),
            ),
            patch.object(repair_service, "load_stored_weekly_forecast", AsyncMock(return_value=None)),
            patch.object(repair_service, "refresh_weekly_forecast_cache", AsyncMock()) as mock_refresh,
        ):
            stats = await repair_service.repair_metalprice_integrity(session)

        mock_store_snapshot.assert_not_called()
        self.assertEqual(stats["missing_today_before"], 0)
        self.assertEqual(stats["rows_scanned"], 2)
        self.assertEqual(stats["metal_code_fixed"], 1)
        self.assertEqual(stats["delta_fixed"], 1)
        self.assertEqual(stats["rows_fixed"], 2)
        self.assertEqual(stats["forecast_refreshed"], 1)
        mock_refresh.assert_awaited_once()
        session.commit.assert_awaited_once()

    async def test_missing_today_without_cooldown_triggers_repair_attempt(self):
        session = AsyncMock()
        session.scalars = AsyncMock(
            side_effect=[
                _scalars_result(self._today_rows(["gold"])),  # silver/platinum欠損
                _scalars_result([]),
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),
            ]
        )
        with (
            patch.object(repair_service, "jst_today", return_value=date(2026, 8, 31)),
            patch.object(repair_service, "store_snapshot", AsyncMock()) as mock_store_snapshot,
            patch.object(repair_service, "load_latest_rows", AsyncMock(return_value={})),
            patch.object(repair_service, "load_stored_weekly_forecast", AsyncMock(return_value=None)),
            patch.object(repair_service, "refresh_weekly_forecast_cache", AsyncMock()),
        ):
            stats = await repair_service.repair_metalprice_integrity(session)

        mock_store_snapshot.assert_awaited_once()
        self.assertEqual(stats["missing_today_before"], 2)
        self.assertEqual(stats["missing_data_repair_attempted"], 1)
        self.assertEqual(stats["missing_data_repair_skipped_cooldown"], 0)
        self.assertIsNotNone(repair_service._last_missing_data_repair_attempt)

    async def test_missing_today_within_cooldown_is_skipped(self):
        repair_service._last_missing_data_repair_attempt = datetime.now(repair_service.JST)
        session = AsyncMock()
        session.scalars = AsyncMock(
            side_effect=[
                _scalars_result(self._today_rows(["gold"])),
                _scalars_result([]),
                _scalars_result(self._today_rows(["gold"])),
            ]
        )
        with (
            patch.object(repair_service, "jst_today", return_value=date(2026, 8, 31)),
            patch.object(repair_service, "store_snapshot", AsyncMock()) as mock_store_snapshot,
            patch.object(repair_service, "load_latest_rows", AsyncMock(return_value={})),
            patch.object(repair_service, "load_stored_weekly_forecast", AsyncMock(return_value=None)),
            patch.object(repair_service, "refresh_weekly_forecast_cache", AsyncMock()),
        ):
            stats = await repair_service.repair_metalprice_integrity(session)

        mock_store_snapshot.assert_not_called()
        self.assertEqual(stats["missing_data_repair_attempted"], 0)
        self.assertEqual(stats["missing_data_repair_skipped_cooldown"], 1)

    async def test_force_forecast_refresh_overrides_drift_free_payload(self):
        session = AsyncMock()
        session.scalars = AsyncMock(
            side_effect=[
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),
                _scalars_result([]),
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),
            ]
        )
        latest_row = MetalPriceDaily(
            metal_key="gold", metal_code="XAU", snapshot_date=date(2026, 8, 31), price_per_gram=Decimal("1")
        )
        with (
            patch.object(repair_service, "jst_today", return_value=date(2026, 8, 31)),
            patch.object(repair_service, "store_snapshot", AsyncMock()),
            patch.object(repair_service, "load_latest_rows", AsyncMock(return_value={"gold": latest_row})),
            patch.object(
                repair_service,
                "load_stored_weekly_forecast",
                AsyncMock(return_value=_valid_forecast_payload(as_of_date="2026-08-31")),
            ),
            patch.object(repair_service, "refresh_weekly_forecast_cache", AsyncMock()) as mock_refresh,
        ):
            stats = await repair_service.repair_metalprice_integrity(session, force_forecast_refresh=True)

        mock_refresh.assert_awaited_once()
        self.assertEqual(stats["forecast_refreshed"], 1)

    async def test_drift_free_payload_without_force_skips_refresh(self):
        session = AsyncMock()
        session.scalars = AsyncMock(
            side_effect=[
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),
                _scalars_result([]),
                _scalars_result(self._today_rows(["gold", "silver", "platinum"])),
            ]
        )
        latest_row = MetalPriceDaily(
            metal_key="gold", metal_code="XAU", snapshot_date=date(2026, 8, 31), price_per_gram=Decimal("1")
        )
        with (
            patch.object(repair_service, "jst_today", return_value=date(2026, 8, 31)),
            patch.object(repair_service, "store_snapshot", AsyncMock()),
            patch.object(repair_service, "load_latest_rows", AsyncMock(return_value={"gold": latest_row})),
            patch.object(
                repair_service,
                "load_stored_weekly_forecast",
                AsyncMock(return_value=_valid_forecast_payload(as_of_date="2026-08-31")),
            ),
            patch.object(repair_service, "refresh_weekly_forecast_cache", AsyncMock()) as mock_refresh,
        ):
            stats = await repair_service.repair_metalprice_integrity(session, force_forecast_refresh=False)

        mock_refresh.assert_not_called()
        self.assertEqual(stats["forecast_refreshed"], 0)


# ======================================================================
# forecast_accuracy_service.py — 予測の答え合わせ記録・集計
# ======================================================================
class ForecastAccuracyServiceTests(unittest.IsolatedAsyncioTestCase):
    """record_forecast_snapshot / reconcile_forecast_accuracy / load_recent_forecast_error を
    AsyncSessionをモックして検証する。pg_insert文の中身はSQLAlchemy Coreの領分なので、
    ここではsession.execute/commitの呼び出し回数と、Pythonオブジェクト側に書き戻される
    計算結果(error_pct・within_intervalなど)を確認する。"""

    async def test_record_forecast_snapshot_returns_zero_for_invalid_as_of_date(self):
        session = AsyncMock()
        rows = await forecast_accuracy_service.record_forecast_snapshot(session, {"as_of_date": None})
        self.assertEqual(rows, 0)
        session.execute.assert_not_called()
        session.commit.assert_not_called()

    async def test_record_forecast_snapshot_upserts_each_valid_daily_entry(self):
        session = AsyncMock()
        payload = {
            "as_of_date": "2026-08-31",
            "forecast": {
                "gold": {
                    "model_variant": "interval_rw_v1",
                    "start_price_per_gram": 5000.0,
                    "implied_daily_return_pct": 0.03,
                    "daily": [
                        {
                            "date": "2026-09-01",
                            "price_per_gram": 5010.0,
                            "lower_price_per_gram": 4950.0,
                            "upper_price_per_gram": 5070.0,
                        },
                        {
                            "date": "2026-09-02",
                            "price_per_gram": 5020.0,
                            "lower_price_per_gram": 4940.0,
                            "upper_price_per_gram": 5090.0,
                        },
                    ],
                },
                "silver": {
                    "model_variant": "interval_rw_v1",
                    "start_price_per_gram": 70.0,
                    "daily": [{"date": "2026-09-01", "price_per_gram": 71.0}],
                },
                "ignored_non_dict": "not-a-dict",
            },
        }
        rows = await forecast_accuracy_service.record_forecast_snapshot(session, payload)
        self.assertEqual(rows, 3)
        self.assertEqual(session.execute.await_count, 3)
        session.commit.assert_awaited_once()

    async def test_record_forecast_snapshot_skips_daily_items_missing_price_or_date(self):
        session = AsyncMock()
        payload = {
            "as_of_date": "2026-08-31",
            "forecast": {
                "gold": {
                    "daily": [
                        {"date": None, "price_per_gram": 5000.0},
                        {"date": "2026-09-01", "price_per_gram": None},
                        "not-a-dict",
                    ]
                }
            },
        }
        rows = await forecast_accuracy_service.record_forecast_snapshot(session, payload)
        self.assertEqual(rows, 0)
        session.execute.assert_not_called()
        session.commit.assert_awaited_once()

    async def test_reconcile_forecast_accuracy_returns_early_when_nothing_pending(self):
        session = AsyncMock()
        session.scalars = AsyncMock(return_value=_scalars_result([]))
        with patch.object(forecast_accuracy_service, "jst_today", return_value=date(2026, 8, 31)):
            result = await forecast_accuracy_service.reconcile_forecast_accuracy(session)
        self.assertEqual(result, {"checked": 0, "matched": 0, "unmatched": 0})
        session.execute.assert_not_called()
        session.commit.assert_not_called()

    async def test_reconcile_forecast_accuracy_matches_and_computes_errors(self):
        matched_row = ForecastAccuracyLog(
            metal_key="gold",
            as_of_date=date(2026, 8, 24),
            forecast_date=date(2026, 8, 31),
            horizon_offset_days=7,
            predicted_price_per_gram=Decimal("105.00"),
            baseline_price_per_gram=Decimal("100.00"),
            lower_price_per_gram=Decimal("95.00"),
            upper_price_per_gram=Decimal("110.00"),
            model_variant="interval_rw_v1",
        )
        unmatched_row = ForecastAccuracyLog(
            metal_key="silver",
            as_of_date=date(2026, 8, 24),
            forecast_date=date(2026, 8, 31),
            horizon_offset_days=7,
            predicted_price_per_gram=Decimal("70.00"),
            model_variant="interval_rw_v1",
        )
        session = AsyncMock()
        session.scalars = AsyncMock(return_value=_scalars_result([matched_row, unmatched_row]))
        session.execute = AsyncMock(
            return_value=Mock(all=Mock(return_value=[("gold", date(2026, 8, 31), Decimal("100.00"))]))
        )
        with patch.object(forecast_accuracy_service, "jst_today", return_value=date(2026, 8, 31)):
            result = await forecast_accuracy_service.reconcile_forecast_accuracy(session)

        self.assertEqual(result, {"checked": 2, "matched": 1, "unmatched": 1})
        self.assertEqual(matched_row.actual_price_per_gram, Decimal("100.00"))
        self.assertEqual(matched_row.error_pct, Decimal("5.000000"))
        self.assertEqual(matched_row.baseline_error_pct, Decimal("0.000000"))
        self.assertTrue(matched_row.within_interval)
        self.assertIsNone(unmatched_row.actual_price_per_gram)
        session.commit.assert_awaited_once()

    async def test_load_recent_forecast_error_computes_mae_baseline_tilt_and_coverage(self):
        session = AsyncMock()
        mae_rows = [("gold", 2.0, 4.0, 10)]  # metal, avg(|error_pct|), avg(|baseline_error_pct|), count
        legacy_rows = [("gold", 2.0), ("silver", 1.0)]
        coverage_rows = [("gold", 10, 8)]  # metal, total, hits
        session.execute = AsyncMock(
            side_effect=[
                Mock(all=Mock(return_value=mae_rows)),
                Mock(all=Mock(return_value=legacy_rows)),
                Mock(all=Mock(return_value=coverage_rows)),
            ]
        )
        with patch.object(forecast_accuracy_service, "jst_today", return_value=date(2026, 8, 31)):
            result = await forecast_accuracy_service.load_recent_forecast_error(session, lookback_days=14)

        self.assertEqual(result["lookback_days"], 14)
        self.assertEqual(result["mean_abs_error_pct"], {"gold": 2.0, "silver": 1.0})
        self.assertEqual(result["baseline_mean_abs_error_pct"], {"gold": 4.0})
        self.assertEqual(result["coverage"], {"gold": 0.8})
        tilt = result["tilt_effect"]["gold"]
        self.assertEqual(tilt["model_mae_pct"], 2.0)
        self.assertEqual(tilt["baseline_mae_pct"], 4.0)
        self.assertAlmostEqual(tilt["improvement_pct"], 50.0, places=6)
        self.assertEqual(tilt["samples"], 10)

    async def test_load_recent_forecast_error_empty_results_produce_empty_dicts(self):
        session = AsyncMock()
        session.execute = AsyncMock(
            side_effect=[
                Mock(all=Mock(return_value=[])),
                Mock(all=Mock(return_value=[])),
                Mock(all=Mock(return_value=[])),
            ]
        )
        with patch.object(forecast_accuracy_service, "jst_today", return_value=date(2026, 8, 31)):
            result = await forecast_accuracy_service.load_recent_forecast_error(session)
        self.assertEqual(result["mean_abs_error_pct"], {})
        self.assertEqual(result["baseline_mean_abs_error_pct"], {})
        self.assertEqual(result["tilt_effect"], {})
        self.assertEqual(result["coverage"], {})
