import asyncio
import logging
import os
import random
import time
from typing import Any

from groq import AsyncGroq, RateLimitError

from config import GROQ_API_KEY

logger = logging.getLogger(__name__)

# GROQ_API_KEYは会話AI(chatgpt_service)・コンテンツモデレーション(content_moderation)・
# ニュース要約(news_service)・metalprice週次予測(forecast_signals)の4機能で共有されている。
# 呼び出し側同士に調整が無いと、あるサービスの呼び出しバーストが他サービスを巻き込んで
# レート制限(429)を誘発しかねないため、用途ごと(bucket)に同時実行数と最小呼び出し間隔を
# 制御する共通ラッパーをここに集約する。
GROQ_MAX_CONCURRENT_REQUESTS = max(1, int(os.getenv("GROQ_MAX_CONCURRENT_REQUESTS", "3")))
GROQ_MIN_REQUEST_INTERVAL_SECONDS = max(0.0, float(os.getenv("GROQ_MIN_REQUEST_INTERVAL_SECONDS", "0.25")))
GROQ_MAX_RETRIES = max(0, int(os.getenv("GROQ_MAX_RETRIES", "2")))
GROQ_RETRY_BASE_DELAY_SECONDS = max(0.5, float(os.getenv("GROQ_RETRY_BASE_DELAY_SECONDS", "2.0")))
GROQ_RETRY_MAX_DELAY_SECONDS = max(
    GROQ_RETRY_BASE_DELAY_SECONDS, float(os.getenv("GROQ_RETRY_MAX_DELAY_SECONDS", "20.0"))
)

_clients: dict[str, AsyncGroq] = {}
_semaphores: dict[str, asyncio.Semaphore] = {}
_interval_locks: dict[str, asyncio.Lock] = {}
_last_call_at: dict[str, float] = {}


def get_groq_client(*, timeout: float, bucket: str = "default") -> AsyncGroq:
    """用途(bucket)ごとにAsyncGroqクライアントを使い回す。"""
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY が設定されていない。")
    client = _clients.get(bucket)
    if client is None:
        client = AsyncGroq(api_key=GROQ_API_KEY, timeout=timeout)
        _clients[bucket] = client
    return client


def _get_semaphore(bucket: str) -> asyncio.Semaphore:
    semaphore = _semaphores.get(bucket)
    if semaphore is None:
        semaphore = asyncio.Semaphore(GROQ_MAX_CONCURRENT_REQUESTS)
        _semaphores[bucket] = semaphore
    return semaphore


async def _respect_min_interval(bucket: str) -> None:
    if GROQ_MIN_REQUEST_INTERVAL_SECONDS <= 0:
        return
    lock = _interval_locks.setdefault(bucket, asyncio.Lock())
    async with lock:
        last = _last_call_at.get(bucket, 0.0)
        wait = GROQ_MIN_REQUEST_INTERVAL_SECONDS - (time.monotonic() - last)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_call_at[bucket] = time.monotonic()


def _retry_after_seconds(exc: RateLimitError) -> float | None:
    response = getattr(exc, "response", None)
    header = response.headers.get("retry-after") if response is not None else None
    if header is None:
        return None
    try:
        return max(0.0, float(header))
    except (TypeError, ValueError):
        return None


async def create_chat_completion(client: AsyncGroq, *, bucket: str, **create_kwargs: Any):
    """chat.completions.createを、プロセス内の同時実行数制限・最小呼び出し間隔・
    429(RateLimitError)時のリトライ付きで呼び出す共通ラッパー。

    bucketは呼び出し元の用途("forecast"/"chat"/"news_summary"/"moderation"等)ごとに
    分離すること。あるbucketのバーストが他bucketの呼び出しを足止めしないようにするため。
    """
    semaphore = _get_semaphore(bucket)
    async with semaphore:
        attempt = 0
        while True:
            await _respect_min_interval(bucket)
            try:
                return await client.chat.completions.create(**create_kwargs)
            except RateLimitError as exc:
                if attempt >= GROQ_MAX_RETRIES:
                    raise
                retry_after = _retry_after_seconds(exc)
                if retry_after is not None:
                    delay = retry_after
                else:
                    delay = min(
                        GROQ_RETRY_MAX_DELAY_SECONDS,
                        GROQ_RETRY_BASE_DELAY_SECONDS * (2**attempt),
                    )
                delay += random.uniform(0, 0.5)
                logger.warning(
                    "Groq APIレート制限を検知。%.1f秒待機してリトライ bucket=%s attempt=%s/%s",
                    delay,
                    bucket,
                    attempt + 1,
                    GROQ_MAX_RETRIES,
                )
                await asyncio.sleep(delay)
                attempt += 1
