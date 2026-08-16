import asyncio
import logging
import time
from typing import Dict, Mapping

import aiohttp

from config import METALPRICE_BASE_URL, METALPRICE_API_KEY, METALPRICE_CACHE_TTL_SECONDS

logger = logging.getLogger(__name__)


class MetalPriceError(RuntimeError):
    """金属価格取得に関するエラー"""


# 金属コードごとの価格キャッシュ。(価格, 取得時刻[monotonic]) を保持する。
# Discordコマンドの連打やWeb/Bot双方からの呼び出しで、外部APIを毎回叩かないようにするための
# プロセス内キャッシュ（MetalpriceAPIは無料枠のリクエスト数が限られているため）。
_price_cache: dict[str, tuple[float, float]] = {}
_price_cache_lock = asyncio.Lock()


async def fetch_metal_price_per_gram(metal_code: str) -> float:
    """金属の現在価格を返す（キャッシュヒット時はAPIを呼ばない）"""
    now = time.monotonic()
    cached = _price_cache.get(metal_code)
    if cached is not None and now - cached[1] < METALPRICE_CACHE_TTL_SECONDS:
        return cached[0]

    async with _price_cache_lock:
        # ロック待機中に他のタスクが取得済みの可能性があるため再チェック
        now = time.monotonic()
        cached = _price_cache.get(metal_code)
        if cached is not None and now - cached[1] < METALPRICE_CACHE_TTL_SECONDS:
            return cached[0]

        price = await _fetch_metal_price_per_gram_live(metal_code)
        _price_cache[metal_code] = (price, now)
        return price


async def _fetch_metal_price_per_gram_live(metal_code: str) -> float:
    """金属の現在価格をAPIから取得し、1グラムあたりの価格を返す（キャッシュを経由しない直接呼び出し）"""
    if not METALPRICE_API_KEY:
        raise MetalPriceError("METALPRICE_API_KEY が設定されていない。")

    params = {"api_key": METALPRICE_API_KEY, "base": "JPY", "currencies": metal_code}
    timeout = aiohttp.ClientTimeout(total=12)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(METALPRICE_BASE_URL, params=params) as resp:
            try:
                data = await resp.json()
            except aiohttp.ContentTypeError:
                text = await resp.text()
                raise MetalPriceError(f"金属APIレスポンスが不正: {resp.status} {text[:200]}")

            logger.debug("金属APIレスポンス(%s): %s", metal_code, data)

            if resp.status != 200 or not data.get("success", True):
                message = ""
                if isinstance(data, dict):
                    message = data.get("error", {}).get("message") or str(data)
                raise MetalPriceError(f"金属API呼び出しに失敗 ({resp.status}): {message}")

    rate = 0
    if isinstance(data, dict):
        rate = data.get("rates", {}).get(f"JPY{metal_code}", 0)

    if not rate:
        raise MetalPriceError(f"{metal_code} の価格取得に失敗した。")

    return rate / 31.1035  # トロイオンス->グラム換算


async def calculate_metal_value(grams: float, metal_code: str, purity: Mapping[str, float]) -> Dict[str, int]:
    if grams <= 0:
        raise MetalPriceError("グラム数は正の値で指定せよ。")
    price_per_gram = await fetch_metal_price_per_gram(metal_code)
    return {grade: int(price_per_gram * grams * ratio) for grade, ratio in purity.items()}
