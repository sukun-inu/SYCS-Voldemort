import json
import math
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

PRICE_SCALE = Decimal("0.0001")
PCT_SCALE = Decimal("0.000001")

# Stooqは2026年8月頃からサーバーサイドアクセスに対しJS実行が必要なPoW型bot検証を
# 挟むようになり、aiohttpから直接CSVを取得できなくなった。代わりにECB公式レートを
# APIキー不要で配信するFrankfurter(https://frankfurter.dev)を使う。
USDJPY_TIMESERIES_BASE_URL = "https://api.frankfurter.dev/v1"
GOOGLE_NEWS_RSS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def safe_float(raw: Any) -> float | None:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def as_decimal(raw: Any, scale: Decimal = PRICE_SCALE) -> Decimal | None:
    value = safe_float(raw)
    if value is None:
        return None
    return Decimal(str(value)).quantize(scale, rounding=ROUND_HALF_UP)


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def json_loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


def extract_first_json_object(text: str) -> dict[str, Any] | None:
    raw = text.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end <= start:
        return None
    snippet = raw[start : end + 1]
    try:
        parsed = json.loads(snippet)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def clip_text(text: str, max_chars: int = 180) -> str:
    trimmed = " ".join((text or "").split())
    if len(trimmed) <= max_chars:
        return trimmed
    return f"{trimmed[: max_chars - 1]}…"
