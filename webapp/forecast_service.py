import asyncio
import logging
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any

import aiohttp
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS
from envutil import env_int

from .forecast_accuracy_service import load_recent_forecast_error, record_forecast_snapshot
from .forecast_models import (
    FORECAST_INTERVAL_PROB,
    FORECAST_TILT_MAX_PCT_PER_DAY,
    MODEL_VARIANT,
    forecast_for_metal,
)
from .forecast_signals import (
    FORECAST_LLM_MODEL,
    FORECAST_LLM_TIMEOUT_SECONDS,
    fetch_forecast_summaries,
    fetch_llm_signal,
    fetch_news_signals,
    fetch_usdjpy_signal,
)
from .forecast_utils import PCT_SCALE, PRICE_SCALE, as_decimal, json_dumps, json_loads, safe_float
from .models import WeeklyForecastDaily, WeeklyForecastMeta
from .snapshot_service import JST, load_history

logger = logging.getLogger(__name__)

# 予測区間の推定に使う価格履歴の日数。重複ありの7日リターンを十分な本数集めるため、
# 長めに取る(経験分位点には最低20本必要)。
FORECAST_HISTORY_WINDOW_MIN_DAYS = env_int("FORECAST_HISTORY_WINDOW_MIN_DAYS", 120, minimum=45)


async def build_weekly_forecast(session: AsyncSession, *, horizon_days: int = 7) -> dict[str, Any]:
    """為替・ニュース・LLM判定を集め、金属ごとの週次予測を新規に計算する（DBへの保存は別関数）。

    為替とニュースの取得は asyncio.gather で並行に行い、LLM判定は
    その結果を使うため後で呼ぶ（依存関係があるので並行化できない）。
    1金属も予測が作れなければ RuntimeError にする。呼び出し元
    （バッチジョブ）はこれを握りつぶさず、古い予測をそのままキャッシュに
    残す判断ができるようにするため。
    """
    history_window_days = max(FORECAST_HISTORY_WINDOW_MIN_DAYS, horizon_days * 20)
    history_by_metal = await load_history(session, history_window_days)
    recent_accuracy = await load_recent_forecast_error(session)
    mae_by_metal = recent_accuracy.get("mean_abs_error_pct", {})
    coverage_by_metal = recent_accuracy.get("coverage", {})
    tilt_effect_by_metal = recent_accuracy.get("tilt_effect", {})

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
            recent_accuracy=mae_by_metal,
        )

    today = datetime.now(JST)
    fx_returns_by_date = {
        str(key): safe_float(value) or 0.0 for key, value in (fx_signal.get("daily_returns_by_date") or {}).items()
    }
    forecast: dict[str, Any] = {}
    for metal_key in METAL_COMMANDS.keys():
        item = forecast_for_metal(
            metal_key=metal_key,
            history_items=history_by_metal.get(metal_key, []),
            horizon_days=horizon_days,
            today=today,
            fx_daily_factor=float(fx_signal.get("daily_factor", 0.0)),
            news_score=float(news_signal["sentiment"].get(metal_key, 0.0)),
            article_count=int(news_signal["article_counts"].get(metal_key, 0)),
            fx_available=bool(fx_signal.get("available")),
            llm_score=float((llm_signal.get("scores", {}) or {}).get(metal_key, 0.0)),
            llm_confidence=float((llm_signal.get("confidences", {}) or {}).get(metal_key, 0.0)),
            llm_rationale=str((llm_signal.get("rationales", {}) or {}).get(metal_key, "")),
            llm_available=bool(llm_signal.get("available")),
            fx_returns_by_date=fx_returns_by_date,
            # 答え合わせ済みデータが無い金属はNoneのまま渡し、
            # forecast_for_metal側で信頼度に上限を掛ける。
            recent_mae_pct=mae_by_metal.get(metal_key),
            recent_coverage=coverage_by_metal.get(metal_key),
            tilt_effect=tilt_effect_by_metal.get(metal_key),
        )
        if item is not None:
            forecast[metal_key] = item

    if not forecast:
        raise RuntimeError("予測に必要な価格履歴データがありません。")

    # driversはforecast_for_metal計算後でないと確定しないため、scoring用のfetch_llm_signal
    # とは別にもう一度Groqを呼び、平易な要約文をここで確定させてから各金属へ埋め込む。
    summaries = await fetch_forecast_summaries(forecast=forecast)
    for metal_key, summary_text in summaries.items():
        if metal_key in forecast and summary_text:
            forecast[metal_key]["summary"] = summary_text

    model_name = MODEL_VARIANT
    model_description = (
        f"現在価格を中心に、過去の7日変動分布から求めた{FORECAST_INTERVAL_PROB:.0%}予測区間を示すモデル。"
        "USD/JPY・ニュース・AI判定は中心をわずかに傾けるだけに留める。"
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
                "source": llm_signal.get("source", "Groq"),
                "model": llm_signal.get("model", FORECAST_LLM_MODEL),
                "scores": llm_signal.get("scores", {}),
                "confidences": llm_signal.get("confidences", {}),
                "rationales": llm_signal.get("rationales", {}),
                "global_comment": llm_signal.get("global_comment", ""),
            },
            "interval": {
                "prob": FORECAST_INTERVAL_PROB,
                "tilt_max_pct_per_day": FORECAST_TILT_MAX_PCT_PER_DAY * 100,
            },
            "accuracy": {
                "available": bool(mae_by_metal or coverage_by_metal),
                "lookback_days": int(recent_accuracy.get("lookback_days", 14)),
                "mean_abs_error_pct": mae_by_metal,
                "baseline_mean_abs_error_pct": recent_accuracy.get("baseline_mean_abs_error_pct", {}),
                "tilt_effect": tilt_effect_by_metal,
                "coverage": coverage_by_metal,
            },
        },
        "forecast": forecast,
    }


def _forecast_payload_from_db(
    *,
    meta: WeeklyForecastMeta,
    rows: list[WeeklyForecastDaily],
) -> dict[str, Any]:
    """DBの行から、build_weekly_forecastが返すのと同じ形のpayloadを組み立て直す。

    news_headlines_json は過去のスキーマ変更でネスト形式が変わっている
    ため（後から llm/interval/accuracy 等を1つのJSON列に相乗りさせた）、
    "sample_headlines" キーの有無で新旧どちらの形式かを判定して読み分ける。
    区間列（lower/upper）が無い古い行は None のまま返し、フロントエンドは
    帯なしで描画する。
    """
    by_metal: dict[str, list[WeeklyForecastDaily]] = {}
    for row in rows:
        by_metal.setdefault(row.metal_key, []).append(row)

    headlines_payload = json_loads(meta.news_headlines_json, {})
    if isinstance(headlines_payload, dict) and "sample_headlines" in headlines_payload:
        sample_headlines = headlines_payload.get("sample_headlines") or {}
        llm_payload = headlines_payload.get("llm") or {}
        interval_payload = headlines_payload.get("interval") or {}
        accuracy_payload = headlines_payload.get("accuracy") or {}
        summaries_payload = headlines_payload.get("summaries") or {}
        breakdown_payload = headlines_payload.get("driver_breakdowns") or {}
    else:
        sample_headlines = headlines_payload if isinstance(headlines_payload, dict) else {}
        llm_payload = {}
        interval_payload = {}
        accuracy_payload = {}
        summaries_payload = {}
        breakdown_payload = {}

    forecast: dict[str, Any] = {}
    for metal_key, metal_rows in by_metal.items():
        sorted_rows = sorted(metal_rows, key=lambda row: row.forecast_date)
        first = sorted_rows[0]
        daily = [
            {
                "date": row.forecast_date.isoformat(),
                "price_per_gram": float(row.price_per_gram),
                "delta_from_previous": float(row.delta_from_previous) if row.delta_from_previous is not None else None,
                # 区間列は 0004 で追加したため、それ以前に保存された行では NULL になる。
                # その場合は None のまま返し、フロントエンドは帯なしで描画する。
                "lower_price_per_gram": (
                    float(row.lower_price_per_gram) if row.lower_price_per_gram is not None else None
                ),
                "upper_price_per_gram": (
                    float(row.upper_price_per_gram) if row.upper_price_per_gram is not None else None
                ),
            }
            for row in sorted_rows
        ]
        last_daily = daily[-1] if daily else {}
        start_price = float(first.start_price_per_gram)
        projected_lower = last_daily.get("lower_price_per_gram")
        projected_upper = last_daily.get("upper_price_per_gram")
        forecast[metal_key] = {
            "start_price_per_gram": float(first.start_price_per_gram),
            "projected_price_per_gram": float(first.projected_price_per_gram),
            "projected_change_pct_7d": float(first.projected_change_pct_7d),
            "confidence": float(first.confidence),
            "implied_daily_return_pct": float(first.implied_daily_return_pct),
            "projected_lower_per_gram": projected_lower,
            "projected_upper_per_gram": projected_upper,
            # isinstance は型検査を通すために要る。daily の各要素は dict[str, Any]
            # なので、そこから取り出した値を mypy は object としか見ない。実際の
            # 中身は上の内包表記で float(...) か None に揃えてあるので、この判定が
            # 偽になることは無い（＝実行時の振る舞いは変わらない）。
            "projected_lower_change_pct": (
                round((projected_lower - start_price) / start_price * 100, 3)
                if projected_lower is not None and isinstance(projected_lower, float) and start_price > 0
                else None
            ),
            "projected_upper_change_pct": (
                round((projected_upper - start_price) / start_price * 100, 3)
                if projected_upper is not None and isinstance(projected_upper, float) and start_price > 0
                else None
            ),
            "interval_prob": float(safe_float(interval_payload.get("prob")) or FORECAST_INTERVAL_PROB),
            "daily": daily,
            "drivers": json_loads(first.drivers_json, []),
            "summary": str(summaries_payload.get(metal_key, "")) if isinstance(summaries_payload, dict) else "",
            # 旧キャッシュには driver_breakdowns が無いため、その場合は空リストにして
            # フロントエンドが従来の drivers 箇条書き表示へフォールバックできるようにする。
            "driver_breakdown": (breakdown_payload.get(metal_key) or [] if isinstance(breakdown_payload, dict) else []),
        }

    if not llm_payload:
        llm_payload = {
            "available": False,
            "source": "Groq",
            "model": FORECAST_LLM_MODEL,
            "scores": {},
            "confidences": {},
            "rationales": {},
            "global_comment": "",
        }
    if not interval_payload:
        interval_payload = {
            "prob": FORECAST_INTERVAL_PROB,
            "tilt_max_pct_per_day": FORECAST_TILT_MAX_PCT_PER_DAY * 100,
        }
    if not accuracy_payload:
        accuracy_payload = {"available": False, "lookback_days": 14, "mean_abs_error_pct": {}}

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
                "weekly_change_pct": (
                    float(meta.usd_jpy_weekly_change_pct) if meta.usd_jpy_weekly_change_pct is not None else 0.0
                ),
            },
            "news": {
                "available": bool(meta.news_available),
                "source": meta.news_source,
                "sentiment": json_loads(meta.news_sentiment_json, {}),
                "article_counts": json_loads(meta.news_article_counts_json, {}),
                "sample_headlines": sample_headlines,
            },
            "llm": llm_payload,
            "interval": interval_payload,
            "accuracy": accuracy_payload,
        },
        "forecast": forecast,
    }


def _trim_payload_to_days(payload: dict[str, Any], days: int) -> dict[str, Any]:
    """保存済み7日分のpayloadから先頭days日だけを切り出す。再計算はしない。

    json_dumps→json_loads を介してコピーしているのは、payload（呼び出し元
    がキャッシュしている可能性がある辞書）を直接書き換えて日数の少ない
    リクエストが元データまで短く破壊するのを防ぐため。projected_price_per_gram
    等は切り詰めた最終日に合わせて作り直す。
    """
    horizon = int(payload.get("horizon_days", 7))
    if days >= horizon:
        return payload

    trimmed: dict[str, Any] = json_loads(json_dumps(payload), {})
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
    """DBに保存済みの最新予測を読む（無ければNone、計算はしない）。画面表示・修復判定の両方から呼ばれる。"""
    meta = (await session.scalars(select(WeeklyForecastMeta).order_by(WeeklyForecastMeta.generated_at.desc()))).first()
    if meta is None:
        return None

    rows = list(
        (
            await session.scalars(select(WeeklyForecastDaily).where(WeeklyForecastDaily.as_of_date == meta.as_of_date))
        ).all()
    )
    if not rows:
        return None

    payload = _forecast_payload_from_db(meta=meta, rows=rows)
    return _trim_payload_to_days(payload, days=days)


def _desired_daily_rows(
    payload: dict[str, Any],
    *,
    as_of_date: date,
    horizon_end: date,
) -> dict[tuple[str, date], dict[str, Any]]:
    """payload から「保存すべき日次行」を (金属, 予測日) をキーにして取り出す。

    as_of 当日以前と horizon を超えた先は捨てる。入れてしまうと、画面の
    グラフに「今日より前の予測」が混ざる。知らない金属も捨てる。
    """
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
                "lower_price_per_gram": as_decimal(daily_item.get("lower_price_per_gram"), PRICE_SCALE),
                "upper_price_per_gram": as_decimal(daily_item.get("upper_price_per_gram"), PRICE_SCALE),
                "drivers_json": json_dumps(item.get("drivers", [])),
            }
    return desired


async def _replace_daily_rows(session: AsyncSession, desired: dict[tuple[str, date], dict[str, Any]]) -> None:
    """日次行を desired の内容へ置き換える。**追記ではなく置き換え。**

    今回計算した行に無いものは消す。追記にすると古い予測と新しい予測が
    並存し、フロントがどちらを表示するか・精度集計がどちらを見るかが
    曖昧になる。
    """
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
        row.lower_price_per_gram = row_payload["lower_price_per_gram"]
        row.upper_price_per_gram = row_payload["upper_price_per_gram"]
        row.drivers_json = row_payload["drivers_json"]

    for row in existing_rows:
        if (row.metal_key, row.forecast_date) not in desired:
            await session.delete(row)


def _generated_at_of(payload: dict[str, Any]) -> datetime:
    """payload の生成時刻。読めなければ今の時刻にする。

    ここで例外にしないのは、時刻が読めないことは予測そのものの価値を
    損なわないため。ただし黙って古い時刻にはしない（今にする）。
    """
    raw = payload.get("generated_at")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return datetime.now(JST)


def _headlines_json(payload: dict[str, Any], signal_data: dict[str, Any]) -> str:
    """news_headlines_json に入れる塊。見出し・LLM・区間・精度・要約をまとめる。

    1つの列に押し込んでいるのは、ここが「表示のための添え物」で、検索も
    集計もしないため。列を増やすとマイグレーションが要る。
    """
    news = signal_data.get("news", {}) if isinstance(signal_data.get("news"), dict) else {}
    llm = signal_data.get("llm", {}) if isinstance(signal_data.get("llm"), dict) else {}
    interval = signal_data.get("interval", {}) if isinstance(signal_data.get("interval"), dict) else {}
    accuracy = signal_data.get("accuracy", {}) if isinstance(signal_data.get("accuracy"), dict) else {}
    forecast_map = payload.get("forecast", {}) if isinstance(payload.get("forecast"), dict) else {}
    return json_dumps(
        {
            "sample_headlines": news.get("sample_headlines", {}),
            "llm": {
                "available": bool(llm.get("available")),
                "source": str(llm.get("source", "Groq")),
                "model": str(llm.get("model", FORECAST_LLM_MODEL)),
                "scores": llm.get("scores", {}),
                "confidences": llm.get("confidences", {}),
                "rationales": llm.get("rationales", {}),
                "global_comment": str(llm.get("global_comment", "")),
            },
            "interval": {
                "prob": float(safe_float(interval.get("prob")) or FORECAST_INTERVAL_PROB),
                "tilt_max_pct_per_day": float(
                    safe_float(interval.get("tilt_max_pct_per_day")) or FORECAST_TILT_MAX_PCT_PER_DAY * 100
                ),
            },
            "accuracy": {
                "available": bool(accuracy.get("available")),
                "lookback_days": int(safe_float(accuracy.get("lookback_days")) or 14),
                "mean_abs_error_pct": accuracy.get("mean_abs_error_pct", {}),
            },
            "summaries": {
                metal_key: str((forecast_map.get(metal_key) or {}).get("summary", ""))
                for metal_key in METAL_COMMANDS.keys()
            },
            "driver_breakdowns": {
                metal_key: (forecast_map.get(metal_key) or {}).get("driver_breakdown", [])
                for metal_key in METAL_COMMANDS.keys()
            },
        }
    )


async def _replace_meta_row(
    session: AsyncSession,
    payload: dict[str, Any],
    *,
    as_of_date: date,
    horizon: int,
) -> None:
    """meta を最新の1件だけにする。

    meta は「この予測はいつ・どのモデルで作ったか」を持つ1行で、複数あると
    フロントがどれを読むかで表示が変わる。既存の最も古い行を使い回して
    上書きし、**それ以外を消す**（過去の版が複数書いていた場合の後始末）。
    """
    meta = (await session.scalars(select(WeeklyForecastMeta).order_by(WeeklyForecastMeta.id.asc()))).first()
    if meta is None:
        meta = WeeklyForecastMeta()
        session.add(meta)

    model_data = payload.get("model", {}) if isinstance(payload.get("model"), dict) else {}
    signal_data = payload.get("signals", {}) if isinstance(payload.get("signals"), dict) else {}
    usd_jpy = signal_data.get("usd_jpy", {}) if isinstance(signal_data.get("usd_jpy"), dict) else {}
    news = signal_data.get("news", {}) if isinstance(signal_data.get("news"), dict) else {}

    meta.as_of_date = as_of_date
    meta.generated_at = _generated_at_of(payload)
    meta.horizon_days = horizon
    meta.model_name = str(model_data.get("name", "heuristic_fx_news_v1"))
    meta.model_description = str(
        model_data.get("description", "直近価格トレンド + USD/JPY + ニュース見出し極性を合成した簡易予測。")
    )
    meta.usd_jpy_available = bool(usd_jpy.get("available"))
    meta.usd_jpy_source = str(usd_jpy.get("source", "Stooq"))
    meta.usd_jpy_latest = as_decimal(usd_jpy.get("latest"), Decimal("0.000001"))
    meta.usd_jpy_weekly_change_pct = as_decimal(usd_jpy.get("weekly_change_pct"), Decimal("0.000001"))
    meta.news_available = bool(news.get("available"))
    meta.news_source = str(news.get("source", "Google News RSS"))
    meta.news_sentiment_json = json_dumps(news.get("sentiment", {}))
    meta.news_article_counts_json = json_dumps(news.get("article_counts", {}))
    meta.news_headlines_json = _headlines_json(payload, signal_data)

    await session.flush()
    await session.execute(delete(WeeklyForecastMeta).where(WeeklyForecastMeta.id != meta.id))


async def store_weekly_forecast(
    session: AsyncSession,
    payload: dict[str, Any],
    *,
    horizon_days: int = 7,
) -> None:
    """週次予測を保存する。過去の予測は残さず、最新1回分だけに置き換える。

    weekly_forecast_daily・weekly_forecast_meta とも「今回計算した行」に
    無いものは削除する。予測は外部API（為替・ニュース）を叩いて作るので、
    失敗して途中の状態で呼び直されることがある。追記にすると古い予測と
    新しい予測が並存し、フロントがどちらを表示するか・精度集計がどちらを
    見るかが曖昧になる。同じ日に再実行しても、常に「直近1回分」だけが残る。

    結果は tests の StoreWeeklyForecastTests が行と meta ごと固定している。
    """
    as_of_raw = payload.get("as_of_date")
    if not isinstance(as_of_raw, str):
        raise RuntimeError("as_of_date が予測payloadに存在しません。")
    as_of_date = date.fromisoformat(as_of_raw)
    horizon = max(1, min(horizon_days, int(payload.get("horizon_days", horizon_days))))

    desired = _desired_daily_rows(payload, as_of_date=as_of_date, horizon_end=as_of_date + timedelta(days=horizon))
    if not desired:
        # ここで黙って戻ると、既存の行を消してから何も書かない経路ができる
        # （＝予測が丸ごと消える）。書けないなら、何も触らずに断る。
        raise RuntimeError("保存可能な予測データがありません。")

    await _replace_daily_rows(session, desired)
    await _replace_meta_row(session, payload, as_of_date=as_of_date, horizon=horizon)
    await session.commit()


async def refresh_weekly_forecast_cache(
    session: AsyncSession,
    *,
    horizon_days: int = 7,
) -> dict[str, Any]:
    """計算→保存→精度ログ記録を1回で行う、バッチジョブからの主入口。

    精度ログ（record_forecast_snapshot）の失敗は握りつぶし、予測自体の
    配信・保存は成功として扱う。答え合わせ用の記録が1回落ちても、次回
    実行分から追跡を続けられれば実害は小さい一方、ここで全体を失敗
    させると、精度トラッキングの不具合のせいで予測そのものが更新
    されなくなるという本末転倒が起きる。
    """
    payload = await build_weekly_forecast(session, horizon_days=horizon_days)
    await store_weekly_forecast(session, payload, horizon_days=horizon_days)
    try:
        await record_forecast_snapshot(session, payload)
    except Exception:
        # 精度トラッキングの記録失敗は予測配信自体の失敗にしない。
        logger.exception("予測精度ログの記録に失敗した。")
    return payload
