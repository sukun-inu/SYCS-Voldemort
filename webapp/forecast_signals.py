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

from config import GROQ_API_KEY, METAL_COMMANDS
from services.groq_client import create_json_chat_completion, get_groq_client
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

_GROQ_BUCKET = "forecast"


def _get_groq_client(timeout: float):
    return get_groq_client(timeout=timeout, bucket=_GROQ_BUCKET)


FORECAST_LLM_ENABLED = read_env_bool("FORECAST_LLM_ENABLED", True)
FORECAST_LLM_MODEL = (os.getenv("FORECAST_LLM_MODEL") or "openai/gpt-oss-120b").strip() or "openai/gpt-oss-120b"
FORECAST_LLM_TIMEOUT_SECONDS = max(8, int(os.getenv("FORECAST_LLM_TIMEOUT_SECONDS", "20")))

# 「予測の根拠」に出す統計モデル内訳(SARIMAXの係数やシグナル合成値など)が専門的で
# わかりにくいというフィードバックを受け、Groqで一般利用者向けの平易な要約文に
# 言い換えさせる機能。fetch_llm_signal(スコアリング用)とは別呼び出しになる
# ("drivers"はforecast_for_metal計算後でないと確定しないため合成不可)が、
# 予測リフレッシュ1回につき+1回(既存のscoring callと合わせて計2回)に収まり、
# 共有レート制限(services/groq_client)の対象にもなっているため安全。
FORECAST_SUMMARY_ENABLED = read_env_bool("FORECAST_SUMMARY_ENABLED", True)
FORECAST_SUMMARY_TIMEOUT_SECONDS = max(8, int(os.getenv("FORECAST_SUMMARY_TIMEOUT_SECONDS", "20")))

# gpt-ossは推論モデルで、推論トークンも生成枠を消費する。以前は max_tokens=420/500 という
# 小さすぎる枠を渡していたため、推論だけで枠を使い切って content が空になり、JSONパースが
# 常に失敗していた(scoresもrationalesも常に0/空、AI判定が予測に一切効いていなかった)。
# 推論分を見込んだ十分な枠を確保する。
FORECAST_LLM_MAX_COMPLETION_TOKENS = max(512, int(os.getenv("FORECAST_LLM_MAX_COMPLETION_TOKENS", "3000")))
FORECAST_SUMMARY_MAX_COMPLETION_TOKENS = max(512, int(os.getenv("FORECAST_SUMMARY_MAX_COMPLETION_TOKENS", "3000")))
# 推論の深さ。gpt-ossでは "low" で十分な品質が得られ、レイテンシとトークン消費を抑えられる。
# 空文字を設定するとパラメータ自体を送らない(モデル既定に任せる)。
FORECAST_LLM_REASONING_EFFORT = (os.getenv("FORECAST_LLM_REASONING_EFFORT", "low") or "").strip()

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
        # LLM判定に渡す材料を増やすため、以前(上位3件)より広めに保持しておく。
        # _fetch_news_for_queryは既に上位18件を取得・スコアリング済みなので追加のRSS取得は発生しない。
        sample_headlines[metal_key] = titles[:8]

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
    recent_accuracy: dict[str, float] | None = None,
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
        headlines = list((news_signal.get("sample_headlines", {}) or {}).get(metal_key, []))[:8]
        recent_error = (recent_accuracy or {}).get(metal_key)
        metal_input[metal_key] = {
            "latest_price_per_gram": round(prices[-1], 2) if prices else None,
            "trend_14d_pct_per_day": round(daily_trend(prices) * 100, 4) if prices else 0.0,
            "volatility_14d_pct": round(daily_volatility(prices) * 100, 4) if prices else 0.0,
            "news_sentiment": float((news_signal.get("sentiment", {}) or {}).get(metal_key, 0.0)),
            "news_article_count": int((news_signal.get("article_counts", {}) or {}).get(metal_key, 0)),
            "headlines": [clip_text(item, 140) for item in headlines],
            # 直近の自分自身の予測誤差(平均絶対誤差%)。過去の判断がどれだけ外れて
            # いたかを踏まえて確信度を調整させるためのフィードバック信号。
            "recent_forecast_mean_abs_error_pct": round(recent_error, 3) if recent_error is not None else None,
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
        "confidence [0,1], and a short rationale. "
        "Each metal includes recent_forecast_mean_abs_error_pct: your own forecast's "
        "recent average error rate (null if unavailable). If this value is high, be more "
        "conservative and lower your confidence; if low and your signal is strong, you may "
        "raise confidence accordingly."
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
        content, finish_reason = await create_json_chat_completion(
            _get_groq_client(float(FORECAST_LLM_TIMEOUT_SECONDS)),
            bucket=_GROQ_BUCKET,
            model=FORECAST_LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.15,
            max_completion_tokens=FORECAST_LLM_MAX_COMPLETION_TOKENS,
            reasoning_effort=FORECAST_LLM_REASONING_EFFORT or None,
        )
    except Exception as exc:
        logger.warning("LLM予測判定の取得に失敗: %s", exc)
        return {**_empty, "global_comment": "LLM call failed"}

    parsed = extract_first_json_object(content)
    if not parsed:
        # パース不能時に静かに0を返すと「AI判定が効いていない」ことに気付けないため、
        # 診断材料(finish_reason・content長・先頭)を必ず残し、available=Falseで返す。
        logger.warning(
            "LLM予測判定のJSONパースに失敗した。finish_reason=%s content_len=%s content_head=%r",
            finish_reason,
            len(content),
            content[:200],
        )
        return {**_empty, "global_comment": "LLM response not parseable"}
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


# 予測の向きが「ほぼ横ばい」とみなせる閾値(7日間の合計変化率, %)。
FORECAST_FLAT_THRESHOLD_PCT = 0.3

# 要約文が予測の向きと逆のことを言っていないかを検査するための語彙。
_UP_WORDS = ("値上がり", "上昇", "上向き", "上振れ", "高くなる", "上がる", "強含み", "反発")
_DOWN_WORDS = ("値下がり", "下落", "下向き", "下振れ", "安くなる", "下がる", "弱含み", "反落")


def _direction_of(change_pct: float) -> str:
    if change_pct > FORECAST_FLAT_THRESHOLD_PCT:
        return "up"
    if change_pct < -FORECAST_FLAT_THRESHOLD_PCT:
        return "down"
    return "flat"


def _contradicts_direction(summary: str, direction: str) -> bool:
    """要約文が予測の向きと明確に矛盾している場合にTrueを返す。

    LLMは「直近は上向きですが今後は値下がり」のように両方の語を含む文も書くため、
    両方含む場合は矛盾と断定しない(文末側の結論が正しいことが多く、誤判定で
    有用な要約を捨てる方が損失が大きい)。片方の語しか含まず、それが予測の向きと
    逆の場合のみ矛盾とみなす。
    """
    if direction not in ("up", "down"):
        return False
    has_up = any(word in summary for word in _UP_WORDS)
    has_down = any(word in summary for word in _DOWN_WORDS)
    if has_up and has_down:
        return False
    if direction == "up":
        return has_down and not has_up
    return has_up and not has_down


async def fetch_forecast_summaries(*, forecast: dict[str, Any]) -> dict[str, str]:
    """forecast_for_metalが確定させたdrivers(統計モデル内訳・トレンド・為替・ニュース・
    AI判定感応の箇条書き)を、金融の専門知識が無い利用者にも伝わる短い日本語の説明文に
    Groqで言い換えさせる。3金属分をまとめて1回の呼び出しにし、失敗時は空文字を返して
    呼び出し元(フロントエンド)が従来通りdriversの箇条書き表示にフォールバックできる
    ようにする。"""
    empty = {key: "" for key in METAL_COMMANDS.keys()}
    if not FORECAST_SUMMARY_ENABLED or not GROQ_API_KEY:
        return empty

    metals_input: dict[str, Any] = {}
    expected_direction: dict[str, str] = {}
    for metal_key in METAL_COMMANDS.keys():
        item = forecast.get(metal_key)
        if not isinstance(item, dict):
            continue
        drivers = [str(driver) for driver in (item.get("drivers") or []) if str(driver).strip()]
        if not drivers:
            continue
        change_pct = safe_float(item.get("projected_change_pct_7d")) or 0.0
        direction = _direction_of(change_pct)
        expected_direction[metal_key] = direction
        # driversは「モデルの最終出力(統計モデル)」と「入力シグナル(直近トレンド・
        # 為替・ニュース・AI判定)」が混在しており、両者の符号が逆になることがある
        # (例: 直近トレンドは+0.455%/日でもSARIMAXの出力は-0.430%/日)。結論を
        # supporting_notesと対等に並べるとLLMが入力シグナル側に引きずられ、実際は
        # 下落予測なのに「上昇が見込まれます」と逆の要約を書いてしまうため、
        # 「結論」と「補足」を明確に分けて渡す。
        metals_input[metal_key] = {
            "conclusion": {
                "direction": direction,
                "total_change_pct_over_next_7_days": round(change_pct, 3),
                "confidence_0_to_1": safe_float(item.get("confidence")),
            },
            "supporting_notes": drivers,
        }

    if not metals_input:
        return empty

    system_prompt = (
        "You are a friendly Japanese financial writer explaining a precious-metal price "
        "forecast to everyday retail users with no finance background.\n"
        "For each metal write ONE short paragraph in natural Japanese (roughly 60-100 "
        "characters), plain language, no jargon and no model names.\n"
        "CRITICAL RULES:\n"
        "1. `conclusion` is the authoritative forecast result. Your paragraph MUST agree "
        "with `conclusion.direction` ('up' = 値上がり, 'down' = 値下がり, 'flat' = 横ばい). "
        "Never state the opposite direction.\n"
        "2. `supporting_notes` are internal model details. Some of them are INPUT signals "
        "that may point the opposite way from the final result. They must NOT override "
        "`conclusion`. Use them only to briefly explain the background.\n"
        "3. If you mention a percentage it must be "
        "`conclusion.total_change_pct_over_next_7_days`, which is the TOTAL change over the "
        "next 7 days (not a per-day figure). Never quote per-day numbers from "
        "`supporting_notes`. Mentioning no number at all is acceptable.\n"
        "4. When the direction conflicts with the background signals, say so honestly "
        "(e.g. 「直近は上向きですが、今後1週間は値下がりが見込まれます」).\n"
        "Return STRICT JSON only, no markdown."
    )
    user_prompt = (
        "Inputs JSON:\n"
        f"{json_dumps({'metals': metals_input})}\n"
        "Return JSON schema:\n"
        "{\"summaries\":{\"gold\":\"...\",\"silver\":\"...\",\"platinum\":\"...\"}}\n"
        "Omit keys for metals not present in the input."
    )

    try:
        content, finish_reason = await create_json_chat_completion(
            _get_groq_client(float(FORECAST_SUMMARY_TIMEOUT_SECONDS)),
            bucket=_GROQ_BUCKET,
            model=FORECAST_LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_completion_tokens=FORECAST_SUMMARY_MAX_COMPLETION_TOKENS,
            reasoning_effort=FORECAST_LLM_REASONING_EFFORT or None,
        )
    except Exception as exc:
        logger.warning("予測根拠の要約取得に失敗: %s", exc)
        return empty

    parsed = extract_first_json_object(content)
    if not parsed:
        logger.warning(
            "予測根拠の要約JSONパースに失敗した。finish_reason=%s content_len=%s content_head=%r",
            finish_reason,
            len(content),
            content[:200],
        )
        return empty
    raw_summaries = parsed.get("summaries", {}) if isinstance(parsed.get("summaries"), dict) else {}
    summaries = dict(empty)
    for metal_key in METAL_COMMANDS.keys():
        text = str(raw_summaries.get(metal_key, "")).strip()
        if not text:
            continue
        # プロンプトで向きを守るよう強く指示しているが、LLMが従う保証は無い。
        # 実際に「-2.97%の下落予測」に対して「上昇が期待できます」と真逆の要約が
        # 出た事例があったため、コード側でも検査し、矛盾する要約は採用しない
        # (空文字にすればフロントエンドが従来のdrivers箇条書き表示へ戻る)。
        direction = expected_direction.get(metal_key, "flat")
        if _contradicts_direction(text, direction):
            logger.warning(
                "予測の向きと矛盾する要約を破棄した metal=%s direction=%s summary=%r",
                metal_key,
                direction,
                text[:120],
            )
            continue
        summaries[metal_key] = clip_text(text, 200)
    return summaries
