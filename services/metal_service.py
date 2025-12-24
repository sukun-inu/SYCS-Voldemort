import logging
from typing import Dict, Mapping

import aiohttp

from config import METALPRICE_BASE_URL, METALPRICE_API_KEY

logger = logging.getLogger(__name__)


class MetalPriceError(RuntimeError):
    """金属価格取得に関するエラー"""


async def fetch_metal_price_per_gram(metal_code: str) -> float:
    """金属の現在価格をAPIから取得し、1グラムあたりの価格を返す"""
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


async def calculate_metal_value(grams: float, metal_code: str, purity: Mapping[str, float] | None = None) -> Dict[str, int] | int:
    """指定グラム数の金属価値を計算"""
    if grams <= 0:
        raise MetalPriceError("グラム数は正の値で指定せよ。")

    price_per_gram = await fetch_metal_price_per_gram(metal_code)

    if purity:
        return {grade: int(price_per_gram * grams * ratio) for grade, ratio in purity.items()}

    return int(price_per_gram * grams)
