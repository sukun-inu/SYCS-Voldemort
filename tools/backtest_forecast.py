"""予測モデルのウォークフォワード検証。

モデルを変更したら必ずこれを通すこと。旧SARIMAXモデルは本番の実データで
「7日後も今日と同じ価格」と言うだけのランダムウォークより明確に劣っていた
(MAE 5.51% vs 3.37%、方向的中率40.6%)。同じ失敗を繰り返さないため、
出荷前にベースラインとの比較を機械的に確認できるようにしてある。

合格基準:
  * MAE がランダムウォーク(naive)を上回らないこと
  * 名目 80% 区間の実測被覆率が 70〜90% に収まること

使い方:
    # 稼働中インスタンスから履歴を取得して検証
    python tools/backtest_forecast.py --url https://metals.example.com

    # 保存済みJSON(/api/prices/history?all=true の生レスポンス)で検証
    python tools/backtest_forecast.py --file history.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webapp.forecast_models import FORECAST_INTERVAL_PROB, forecast_for_metal  # noqa: E402
from webapp.forecast_series import parse_price_history  # noqa: E402

JST = timezone(timedelta(hours=9))

COVERAGE_MIN = 0.70
COVERAGE_MAX = 0.90


def load_history(url: str | None, path: str | None) -> dict:
    if path:
        return dict(json.loads(Path(path).read_text(encoding="utf-8")))
    assert url is not None
    # f-string の中で外側と同じ引用符を使わないこと。`f"{url.rstrip("/")}"` は
    # PEP 701 の構文で、Python 3.12 以降でしか解釈できない。実際この行がその形で
    # 書かれていて、当時の本番・CI（3.11）では import した時点で SyntaxError に
    # なっていた（手元が 3.13 だと動いてしまうため、長く気づかれなかった）。
    #
    # **3.13 へ揃えたので今は書けるが、戻さないこと。** 内側を ' にした形は
    # どの版でも読めるので、対象の Python を将来動かしても壊れない。
    endpoint = f"{url.rstrip('/')}/api/prices/history?all=true"
    with urllib.request.urlopen(endpoint, timeout=30) as response:  # noqa: S310 - 運用者が指定したURL
        return dict(json.loads(response.read().decode("utf-8")))


def daily_trend_baseline(prices: list[float], horizon: int) -> float:
    """比較用: 直近14日の幾何平均トレンドをそのまま外挿する素朴な予測。"""
    from webapp.forecast_models import daily_trend

    return prices[-1] * ((1 + daily_trend(prices)) ** horizon)


def run(history: dict, *, horizon: int, min_history: int) -> int:
    records: list[dict] = []

    for metal_key, rows in (history.get("metals") or {}).items():
        series = parse_price_history(rows)
        prices = [price for _, price in series]
        if len(series) <= min_history + horizon:
            print(f"  {metal_key}: データ不足のためスキップ (点数={len(series)})")
            continue

        for cut in range(min_history, len(series) - horizon):
            window_rows = [{"date": d.isoformat(), "price_per_gram": p} for d, p in series[: cut + 1]]
            actual = prices[cut + horizon]
            last = prices[cut]
            result = forecast_for_metal(
                metal_key=metal_key,
                history_items=window_rows,
                horizon_days=horizon,
                today=datetime.fromisoformat(series[cut][0].isoformat()).replace(tzinfo=JST),
                # 過去時点の外部シグナルは再現できないため中立で流す。
                # 中心のtiltは上限が小さいため、ここで測っているのは主に区間の質。
                fx_daily_factor=0.0,
                news_score=0.0,
                article_count=0,
                fx_available=False,
                llm_score=0.0,
                llm_confidence=0.0,
                llm_rationale="",
                llm_available=False,
                fx_returns_by_date={},
                recent_mae_pct=None,
                recent_coverage=None,
            )
            if result is None:
                continue
            records.append(
                {
                    "metal": metal_key,
                    "actual": actual,
                    "last": last,
                    "model": result["projected_price_per_gram"],
                    "naive": last,
                    "trend": daily_trend_baseline(prices[: cut + 1], horizon),
                    "lower": result["projected_lower_per_gram"],
                    "upper": result["projected_upper_per_gram"],
                    "confidence": result["confidence"],
                }
            )

    if not records:
        print("検証できるデータがありませんでした。")
        return 1

    def mae(key: str, rows: list[dict[str, Any]]) -> float:
        return statistics.mean(abs(float(r[key]) - float(r["actual"])) / float(r["actual"]) * 100 for r in rows)

    def coverage(rows: list[dict]) -> float:
        return sum(r["lower"] <= r["actual"] <= r["upper"] for r in rows) / len(rows)

    print("=" * 74)
    print(f"ウォークフォワード検証  horizon={horizon}日  最低履歴={min_history}点")
    print("=" * 74)

    by_metal: dict[str, list[dict]] = {}
    for record in records:
        by_metal.setdefault(record["metal"], []).append(record)

    for metal_key, rows in by_metal.items():
        print(
            f"\n【{metal_key}】 n={len(rows)}\n"
            f"  MAE%      model={mae('model', rows):6.2f}  naive={mae('naive', rows):6.2f}  "
            f"trend={mae('trend', rows):6.2f}\n"
            f"  区間被覆率 {coverage(rows) * 100:5.1f}%  (名目 {FORECAST_INTERVAL_PROB:.0%})"
        )

    model_mae = mae("model", records)
    naive_mae = mae("naive", records)
    total_coverage = coverage(records)

    print("\n" + "=" * 74)
    print(f"【全体】 n={len(records)}")
    print(f"  MAE%: model={model_mae:.2f}  naive={naive_mae:.2f}  trend={mae('trend', records):.2f}")
    print(f"  naive比: {(model_mae / naive_mae - 1) * 100:+.1f}%  (マイナスなら改善)")
    print(f"  区間被覆率: {total_coverage * 100:.1f}%  (名目 {FORECAST_INTERVAL_PROB:.0%})")

    print("\n【合格判定】")
    failures = 0
    if model_mae <= naive_mae:
        print(f"  [OK]   MAE {model_mae:.2f}% <= naive {naive_mae:.2f}%")
    else:
        print(f"  [NG]   MAE {model_mae:.2f}% > naive {naive_mae:.2f}%  ランダムウォークに負けている")
        failures += 1
    if COVERAGE_MIN <= total_coverage <= COVERAGE_MAX:
        print(f"  [OK]   被覆率 {total_coverage * 100:.1f}% が {COVERAGE_MIN:.0%}〜{COVERAGE_MAX:.0%} に収まっている")
    else:
        state = "狭すぎる" if total_coverage < COVERAGE_MIN else "広すぎる"
        print(f"  [NG]   被覆率 {total_coverage * 100:.1f}% が範囲外({state})")
        failures += 1

    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="稼働中インスタンスのベースURL")
    source.add_argument("--file", help="/api/prices/history?all=true のレスポンスを保存したJSON")
    parser.add_argument("--horizon", type=int, default=7, help="予測日数(既定7)")
    parser.add_argument("--min-history", type=int, default=30, help="予測開始に必要な履歴点数(既定30)")
    args = parser.parse_args()

    history = load_history(args.url, args.file)
    return run(history, horizon=args.horizon, min_history=args.min_history)


if __name__ == "__main__":
    raise SystemExit(main())
