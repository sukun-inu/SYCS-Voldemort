import asyncio
import logging
import time
from typing import Dict, Iterable, Mapping, Sequence

import aiohttp

from config import METALPRICE_BASE_URL, METALPRICE_API_KEY, METALPRICE_CACHE_TTL_SECONDS

logger = logging.getLogger(__name__)

TROY_OUNCE_GRAMS = 31.1035


class MetalPriceError(RuntimeError):
    """金属価格取得に関するエラー"""


# 金属コードごとの価格キャッシュ。(価格, 取得時刻[monotonic]) を保持する。
# Discordコマンドの連打やWeb/Bot双方からの呼び出しで、外部APIを毎回叩かないようにするための
# プロセス内キャッシュ（MetalpriceAPIは無料枠のリクエスト数が限られているため）。
_price_cache: dict[str, tuple[float, float]] = {}
_price_cache_lock = asyncio.Lock()


def _cached_price(metal_code: str, now: float) -> float | None:
    cached = _price_cache.get(metal_code)
    if cached is not None and now - cached[1] < METALPRICE_CACHE_TTL_SECONDS:
        return cached[0]
    return None


async def fetch_metal_prices_per_gram(metal_codes: Sequence[str]) -> dict[str, float]:
    """複数金属の現在価格を **1リクエストで** まとめて取得する。

    MetalpriceAPIの `currencies` はカンマ区切りの複数指定に対応しており、1回の呼び出しで
    全金属のレートが返る。以前は金属ごとに個別リクエストしていたため、日次スナップショット
    だけで3回/日=約90回/月を消費し、無料枠(100回/月)をDiscordコマンドや修復リトライと
    奪い合って毎月10日前後のデータ欠損を起こしていた。ここを1回/日に集約する。

    キャッシュ済みのコードはAPIを叩かずに返す。バッチ応答に含まれなかったコードだけは
    個別取得へフォールバックする(APIの挙動差に対する保険)。
    """
    codes = list(dict.fromkeys(code for code in metal_codes if code))
    if not codes:
        return {}

    now = time.monotonic()
    resolved: dict[str, float] = {}
    missing: list[str] = []
    for code in codes:
        price = _cached_price(code, now)
        if price is None:
            missing.append(code)
        else:
            resolved[code] = price
    if not missing:
        return resolved

    async with _price_cache_lock:
        # ロック待機中に他のタスクが取得済みの可能性があるため再チェック
        now = time.monotonic()
        still_missing = []
        for code in missing:
            price = _cached_price(code, now)
            if price is None:
                still_missing.append(code)
            else:
                resolved[code] = price
        if not still_missing:
            return resolved

        batch_failed = False
        try:
            fetched = await _fetch_metal_prices_live(still_missing)
        except MetalPriceError as exc:
            # カンマ区切りの複数指定をAPIが受け付けなかった場合の保険。ここで諦めると
            # その日の日次スナップショットごと落ちてしまい、まさに解消したかった
            # 「データ欠損」を自分で作ることになるため、必ず個別取得へ落とす。
            if len(still_missing) <= 1:
                raise
            logger.warning(
                "金属APIのバッチ取得に失敗したため個別取得へフォールバックする codes=%s err=%s",
                ",".join(still_missing),
                exc,
            )
            fetched = {}
            batch_failed = True

        now = time.monotonic()
        for code, price in fetched.items():
            _price_cache[code] = (price, now)
        resolved.update(fetched)

        # バッチで取れなかったコードを個別に取り直す。1金属の失敗で全体を落とさないよう、
        # ここでは例外を握って次の金属へ進む(取得できたぶんは保存対象として残す)。
        leftovers = [code for code in still_missing if code not in fetched]
        for code in leftovers:
            if not batch_failed:
                logger.warning("金属APIのバッチ応答に %s が含まれなかったため個別取得へフォールバックする。", code)
            try:
                # 変数名を price のままにすると、上のループで float | None と
                # 推論された同名のローカル変数と mypy 上で型が衝突するため
                # single_price という別名にする（動作は変えていない）。
                single_price = await _fetch_metal_prices_live([code])
            except MetalPriceError as exc:
                logger.error("金属価格の個別取得にも失敗した code=%s err=%s", code, exc)
                continue
            if code in single_price:
                _price_cache[code] = (single_price[code], time.monotonic())
                resolved[code] = single_price[code]

        if not resolved:
            raise MetalPriceError(f"{','.join(still_missing)} の価格取得に失敗した。")

    return resolved


async def fetch_metal_price_per_gram(metal_code: str) -> float:
    """金属の現在価格を返す（キャッシュヒット時はAPIを呼ばない）"""
    prices = await fetch_metal_prices_per_gram([metal_code])
    if metal_code not in prices:
        raise MetalPriceError(f"{metal_code} の価格取得に失敗した。")
    return prices[metal_code]


async def _fetch_metal_prices_live(metal_codes: Iterable[str]) -> dict[str, float]:
    """指定した金属の価格をAPIから1リクエストで取得し、1グラムあたりの価格を返す。

    取得できたコードだけを返す(欠けたコードの扱いは呼び出し側に委ねる)。
    """
    codes = list(metal_codes)
    if not codes:
        return {}
    if not METALPRICE_API_KEY:
        raise MetalPriceError("METALPRICE_API_KEY が設定されていない。")

    params = {"api_key": METALPRICE_API_KEY, "base": "JPY", "currencies": ",".join(codes)}
    timeout = aiohttp.ClientTimeout(total=12)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(METALPRICE_BASE_URL, params=params) as resp:
            try:
                data = await resp.json()
            except aiohttp.ContentTypeError:
                text = await resp.text()
                raise MetalPriceError(f"金属APIレスポンスが不正: {resp.status} {text[:200]}")

            logger.debug("金属APIレスポンス(%s): %s", ",".join(codes), data)

            if resp.status != 200 or not (data.get("success", True) if isinstance(data, dict) else False):
                message = ""
                if isinstance(data, dict):
                    message = data.get("error", {}).get("message") or str(data)
                raise MetalPriceError(f"金属API呼び出しに失敗 ({resp.status}): {message}")

    rates = data.get("rates", {}) if isinstance(data, dict) else {}
    prices: dict[str, float] = {}
    for code in codes:
        rate = rates.get(f"JPY{code}") or 0
        if rate:
            prices[code] = rate / TROY_OUNCE_GRAMS  # トロイオンス->グラム換算

    if not prices:
        raise MetalPriceError(f"{','.join(codes)} の価格取得に失敗した。")
    return prices


async def calculate_metal_value(grams: float, metal_code: str, purity: Mapping[str, float]) -> Dict[str, int]:
    if grams <= 0:
        raise MetalPriceError("グラム数は正の値で指定せよ。")
    price_per_gram = await fetch_metal_price_per_gram(metal_code)
    return {grade: int(price_per_gram * grams * ratio) for grade, ratio in purity.items()}
