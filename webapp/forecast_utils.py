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
    """LLMや外部シグナルが出した値を、モデルが許容する範囲へ強制的に収める。

    予測の傾き・信頼度・確率はどれも、外れ値を1件通すだけで週次予測
    全体が非現実的な値になる。ここで削るのは異常値ではなく範囲外の
    部分だけで、None にはしない（呼び出し側を分岐だらけにしないため）。
    """
    return max(lower, min(upper, value))


def safe_float(raw: Any) -> float | None:
    """外部由来の値をfloatへ寄せる。変換できない/NaN・Infは None として弾く。

    為替APIやLLM応答のJSONは型が保証されない（文字列の数値、欠損、
    "NaN" 相当の値が来ることがある）。ここで弾かずに通すと、後段の
    Decimal 変換や四則演算で例外になったり、NaN が保存されて画面表示や
    差分計算が壊れたりする。
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def as_decimal(raw: Any, scale: Decimal = PRICE_SCALE) -> Decimal | None:
    """DBのNumericカラムへ入れる形（指定桁で丸めたDecimal）に揃える。

    float のまま保存すると桁が微妙にずれ、同じ入力でも実行ごとに
    最終桁が変わることがある。str(value) を経由してから quantize する
    のは、float を直接 Decimal() に渡すと2進浮動小数点の誤差
    （0.1 が 0.1000000000000000055...になる類い）をそのまま
    引き継いでしまうため。
    """
    value = safe_float(raw)
    if value is None:
        return None
    return Decimal(str(value)).quantize(scale, rounding=ROUND_HALF_UP)


def json_dumps(data: Any) -> str:
    """DBのTextカラムに詰める用のJSON文字列化。区切りを詰めて容量を抑える。"""
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def json_loads(text: str | None, default: Any) -> Any:
    """DBから読んだJSON文字列を戻す。None/空文字/壊れたJSONは既定値にする。

    weekly_forecast_meta などの JSON カラムは過去のスキーマ変更で
    形式が変わったことがある。ここで例外を投げると1行の不整合が
    ページ全体の500に波及するので、既定値へ倒して呼び出し側に
    「無かった」体で続行させる。
    """
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


def extract_first_json_object(text: str) -> dict[str, Any] | None:
    """LLM応答からJSONオブジェクトを取り出す。前後に説明文が付いていても拾う。

    Groqへの指示にも関わらず、応答が素のJSONではなく
    「```json ... ```」や前置きの文章付きで返ることがある。まず全体を
    そのままパースし、失敗したら最初の '{' 〜 最後の '}' を切り出して
    再挑戦する。dict 以外（配列や数値）が返った場合は None にする。
    """
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
    """ニュース見出し等をDBカラム長・画面表示に収まる長さへ切り詰める。

    改行や連続空白も1つのスペースへ畳む。RSS由来の見出しは改行や
    タブを含むことがあり、そのまま保存するとJSON化や画面レイアウトが
    崩れる。
    """
    trimmed = " ".join((text or "").split())
    if len(trimmed) <= max_chars:
        return trimmed
    return f"{trimmed[: max_chars - 1]}…"
