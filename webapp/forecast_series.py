"""価格履歴から、データ欠損に強い日次リターン系列と予測区間の材料を作る。

本番データには収集ジョブの停止によって毎月10〜11日の欠損があり、その多日ぶんの
変動が「1日分のリターン」として扱われていた。通常±1%の系列に6〜10倍の外れ値が
混入し、ボラティリティを実測で約2倍(silver 1.50%→3.07%/日)に見せていたため、
ここで経過日数を考慮した系列を組み立てる。
"""

from __future__ import annotations

import math
import statistics
from datetime import date
from typing import Any, Sequence

from envutil import env_float

# MAD(中央絶対偏差)から標準偏差へ換算する定数。正規分布を仮定した標準的な係数。
MAD_TO_SIGMA = 1.4826

# --- 予測区間の幅にかける補正係数 -------------------------------------------------
#
# 重複ありのhorizonリターン(7日リターンを1日ずらしで集めたもの)は互いに強く自己相関
# しており、見かけの本数ほど情報量が無い。そのため標本分位点は裾を過小評価し、補正なし
# では名目80%の区間の実測被覆率が66.7%にとどまった。本番実データ102点で較正した結果、
# サンプルが少ない今の局面では 1.35 が必要だった。
#
# ただしこの過小評価はサンプルが増えるほど解消する。合成データ(独立系列75本)で
# サンプル数ごとの適正係数を測ると、7日リターンが150本を超えたあたりで補正不要
# (m≈1.0)になり、1.35のまま放置すると被覆率が名目80%に対して90%まで広がってしまう。
# 区間が広すぎると「だいたい何でも入る」ので実用価値が落ちる。
#
# そこで、
#   (1) サンプル数に応じて 1.35 → 1.10 へ逓減させ、
#   (2) さらに実測被覆率が得られたら、そのズレを使って自己補正する
# という二段構えにする。(2) があるので、合成データで求めた (1) のカーブが多少ズレて
# いても、運用しながら正しい幅へ収束する。実測被覆率は forecast_accuracy_log の
# within_interval から供給される。
FORECAST_INTERVAL_WIDTH_MULTIPLIER = env_float("FORECAST_INTERVAL_WIDTH_MULTIPLIER", 1.35, minimum=0.5)
# 逓減の下限。合成データでは1.0まで下がってよいが、実データの裾は合成より重かったため、
# 下げすぎて被覆不足になる方を避ける。
FORECAST_INTERVAL_WIDTH_MULTIPLIER_MIN = env_float("FORECAST_INTERVAL_WIDTH_MULTIPLIER_MIN", 1.10, minimum=0.5)
# 逓減の開始・終了サンプル数(重複あり7日リターンの本数)。
INTERVAL_MULTIPLIER_SMALL_N = 43    # 本番実データで1.35を較正したときの本数
INTERVAL_MULTIPLIER_LARGE_N = 150   # 合成データで補正不要になった本数

# 実測被覆率による自己補正の強さと可動範囲。被覆率が名目より高ければ幅を縮め、
# 低ければ広げる。1回のリフレッシュで大きく動かさず、少しずつ収束させる。
INTERVAL_COVERAGE_ADJUST_GAIN = 0.5
INTERVAL_COVERAGE_ADJUST_BOUNDS = (0.85, 1.20)


def interval_width_multiplier(
    sample_count: int,
    *,
    measured_coverage: float | None = None,
    nominal_prob: float = 0.8,
) -> float:
    """区間幅に掛ける補正係数を求める。

    sample_count はhorizonリターンの本数。実測被覆率が渡された場合は、名目との
    ズレに応じて係数を上下させる(被覆率が高すぎる=幅が広すぎるなら縮める)。
    """
    small, large = INTERVAL_MULTIPLIER_SMALL_N, INTERVAL_MULTIPLIER_LARGE_N
    high, low = FORECAST_INTERVAL_WIDTH_MULTIPLIER, FORECAST_INTERVAL_WIDTH_MULTIPLIER_MIN
    if sample_count <= small:
        base = high
    elif sample_count >= large:
        base = low
    else:
        ratio = (sample_count - small) / (large - small)
        base = high + (low - high) * ratio

    if measured_coverage is None or not math.isfinite(measured_coverage):
        return base

    factor = 1.0 - INTERVAL_COVERAGE_ADJUST_GAIN * (measured_coverage - nominal_prob)
    factor = min(max(factor, INTERVAL_COVERAGE_ADJUST_BOUNDS[0]), INTERVAL_COVERAGE_ADJUST_BOUNDS[1])
    return base * factor

# 経験分位点を使うために最低限必要な、重複ありhorizonリターンの本数。
MIN_QUANTILE_SAMPLES = 20

# 経験分位点が潰れている(幅がほぼ0)と判断する閾値(対数リターン)。
DEGENERATE_INTERVAL_EPSILON = 1e-6
# 区間の片側幅の下限(対数リターン、約0.5%)。価格がまったく動いていない期間でも
# 幅0の区間を出さないための保険。
MIN_INTERVAL_HALF_WIDTH = 0.005
# 頑健σを推定するために最低限必要な、欠損を跨がないリターンの本数。
MIN_SIGMA_SAMPLES = 10


def parse_price_history(history_items: Sequence[dict[str, Any]]) -> list[tuple[date, float]]:
    """APIやDBから来た履歴を (日付, 価格) の昇順リストへ正規化する。"""
    series: list[tuple[date, float]] = []
    for item in history_items:
        raw_date = item.get("date")
        raw_price = item.get("price_per_gram")
        if not isinstance(raw_date, str) or raw_price is None:
            continue
        try:
            parsed_date = date.fromisoformat(raw_date)
            price = float(raw_price)
        except (TypeError, ValueError):
            continue
        if price > 0:
            series.append((parsed_date, price))
    series.sort(key=lambda row: row[0])
    return series


def build_return_series(series: Sequence[tuple[date, float]]) -> list[tuple[float, int]]:
    """(1日あたり対数リターン, 経過日数) の列を返す。

    欠損を跨ぐ区間は経過日数で割って1日あたりへ正規化する。経過日数を併せて返すのは、
    σ推定時に「欠損を跨いだ観測」を除外できるようにするため。
    """
    returns: list[tuple[float, int]] = []
    for (prev_date, prev_price), (curr_date, curr_price) in zip(series, series[1:]):
        elapsed = (curr_date - prev_date).days
        if elapsed < 1 or prev_price <= 0 or curr_price <= 0:
            continue
        returns.append((math.log(curr_price / prev_price) / elapsed, elapsed))
    return returns


def contiguous_returns(returns: Sequence[tuple[float, int]]) -> list[float]:
    """欠損を跨がない(経過1日の)リターンだけを取り出す。"""
    return [value for value, elapsed in returns if elapsed == 1]


def robust_daily_sigma(returns: Sequence[tuple[float, int]]) -> float:
    """外れ値に強い日次ボラティリティ(対数リターンの標準偏差)を推定する。

    欠損を跨ぐリターンは分散が経過日数ぶん大きくなるため除外し、MADベースで推定する。
    サンプルが足りない場合のみ、全リターンの標準偏差へフォールバックする。
    """
    clean = contiguous_returns(returns)
    if len(clean) < MIN_SIGMA_SAMPLES:
        clean = [value for value, _ in returns]
    if len(clean) < 2:
        return 0.0
    median = statistics.median(clean)
    mad = statistics.median([abs(value - median) for value in clean])
    if mad > 0:
        return MAD_TO_SIGMA * mad
    return statistics.pstdev(clean)


def _percentile(sorted_values: Sequence[float], prob: float) -> float:
    """線形補間つきの分位点。statistics.quantiles より境界の扱いが素直。"""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = prob * (len(sorted_values) - 1)
    lower_index = int(math.floor(position))
    upper_index = min(lower_index + 1, len(sorted_values) - 1)
    weight = position - lower_index
    return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight


def horizon_log_returns(series: Sequence[tuple[date, float]], horizon_days: int) -> list[float]:
    """重複ありの「horizon日先までの対数リターン」を集める。

    実日付の差がhorizonと一致する組だけを使う(欠損期間を跨いだ組は採用しない)。
    """
    if horizon_days < 1:
        return []
    by_date = {row[0]: row[1] for row in series}
    values: list[float] = []
    for base_date, base_price in series:
        target_price = by_date.get(base_date.fromordinal(base_date.toordinal() + horizon_days))
        if target_price and base_price > 0:
            values.append(math.log(target_price / base_price))
    return values


def horizon_interval(
    series: Sequence[tuple[date, float]],
    returns: Sequence[tuple[float, int]],
    *,
    horizon_days: int,
    interval_prob: float,
    measured_coverage: float | None = None,
) -> tuple[float, float, str, int, float]:
    """horizon日先の対数リターンの下限・上限を返す。

    戻り値は (下限, 上限, 推定方法, サンプル数, 使用した補正係数)。

    実測では正規分布を仮定した区間は過小だった(名目80%で実測被覆61.8%)ため、
    十分なサンプルがあるときは経験分位点を使う。足りないときだけ
    σ×√horizon による正規近似へフォールバックする。

    経験分位点は**標本平均を除いてから**取る。生の分位点は標本期間の値動きの向きを
    そのまま抱え込むため(下落局面のデータでは区間全体が下へずれる)、ドリフトに
    予測力が無いという検証結果と矛盾する。平均を除くことで「どちら向きか」は中心値の
    tilt に一本化し、区間は「7日でどれくらい動きうるか」だけを表すようにする。
    非対称性(下方向に速く動きやすい等)は平均を除いても残るため保持される。
    """
    tail = max(0.0, min(0.5, (1.0 - interval_prob) / 2.0))
    raw_samples = horizon_log_returns(series, horizon_days)
    multiplier = interval_width_multiplier(
        len(raw_samples), measured_coverage=measured_coverage, nominal_prob=interval_prob
    )
    if len(raw_samples) >= MIN_QUANTILE_SAMPLES:
        mean = statistics.fmean(raw_samples)
        samples = sorted(value - mean for value in raw_samples)
        lower = _percentile(samples, tail) * multiplier
        upper = _percentile(samples, 1.0 - tail) * multiplier
        # 値動きが乏しい期間では分位点が潰れて幅0の区間になりうる。幅0の区間は
        # 「必ず外れる」ため意味を成さないので、その場合は正規近似へ回す。
        if (upper - lower) > DEGENERATE_INTERVAL_EPSILON:
            return lower, upper, "empirical", len(samples), multiplier

    sigma = robust_daily_sigma(returns)
    z = _normal_quantile(1.0 - tail)
    half_width = z * sigma * math.sqrt(horizon_days) * multiplier
    # σ自体がほぼ0(価格が動いていない)場合も、最低限の幅は確保しておく。
    half_width = max(half_width, MIN_INTERVAL_HALF_WIDTH)
    return -half_width, half_width, "normal_approx", len(raw_samples), multiplier


def _normal_quantile(prob: float) -> float:
    """標準正規分布の分位点(Acklam の有理近似)。scipy を持ち込まないための実装。"""
    prob = min(max(prob, 1e-6), 1 - 1e-6)
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]
    plow, phigh = 0.02425, 1 - 0.02425
    if prob < plow:
        q = math.sqrt(-2 * math.log(prob))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
               ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    if prob > phigh:
        q = math.sqrt(-2 * math.log(1 - prob))
        return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
               ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    q = prob - 0.5
    r = q * q
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / \
           (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)


def count_gaps(series: Sequence[tuple[date, float]]) -> int:
    """欠損(2日以上あいている箇所)の件数。内訳表示や運用監視に使う。"""
    return sum(1 for (a, _), (b, _) in zip(series, series[1:]) if (b - a).days > 1)
