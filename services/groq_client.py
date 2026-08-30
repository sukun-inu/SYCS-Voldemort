import asyncio
import logging
import random
import time
from typing import Any

from groq import AsyncGroq, BadRequestError, RateLimitError

from config import GROQ_API_KEY
from envutil import env_float, env_int

logger = logging.getLogger(__name__)

# GROQ_API_KEYは会話AI(chatgpt_service)・コンテンツモデレーション(content_moderation)・
# ニュース要約(news_service)・metalprice週次予測(forecast_signals)の4機能で共有されている。
# 呼び出し側同士に調整が無いと、あるサービスの呼び出しバーストが他サービスを巻き込んで
# レート制限(429)を誘発しかねないため、用途ごと(bucket)に同時実行数と最小呼び出し間隔を
# 制御する共通ラッパーをここに集約する。
# 素の int()/float() は空文字や壊れた値でインポート時に例外を投げるため envutil を使う。
GROQ_MAX_CONCURRENT_REQUESTS = env_int("GROQ_MAX_CONCURRENT_REQUESTS", 3, minimum=1)
GROQ_MIN_REQUEST_INTERVAL_SECONDS = env_float("GROQ_MIN_REQUEST_INTERVAL_SECONDS", 0.25, minimum=0.0)
GROQ_MAX_RETRIES = env_int("GROQ_MAX_RETRIES", 2, minimum=0)
GROQ_RETRY_BASE_DELAY_SECONDS = env_float("GROQ_RETRY_BASE_DELAY_SECONDS", 2.0, minimum=0.5)
GROQ_RETRY_MAX_DELAY_SECONDS = env_float(
    "GROQ_RETRY_MAX_DELAY_SECONDS",
    20.0,
    minimum=GROQ_RETRY_BASE_DELAY_SECONDS,
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


# --- JSON応答を要求する呼び出し用のヘルパー -------------------------------------
#
# Groqの `openai/gpt-oss-*` は推論(reasoning)モデルで、推論トークンも生成トークンとして
# max_tokens / max_completion_tokens の枠を消費する。予測系の2箇所だけが小さな
# max_tokens(420/500)を指定していたため、推論だけで枠を使い切って `message.content` が
# 空(または途中で切れたJSON)になり、パースが常に失敗していた。
# (他の3機能はmax_tokensを指定しておらずモデル既定の大きな枠が使われるため無事だった)
#
# ここでは以下をまとめて面倒みる:
#   * response_format={"type":"json_object"} でJSONとして妥当な応答を保証する
#   * reasoning_format="hidden" で推論テキストが content に混ざらないようにする
#   * max_completion_tokens に十分な枠を渡す(max_tokensは非推奨)
#   * 上記パラメータを解釈できないモデルが設定された場合(400)は、最小構成へ自動フォール
#     バックして呼び出し自体は成立させる(枠だけは広げたまま維持する)
JSON_RESPONSE_FORMAT = {"type": "json_object"}


async def create_json_chat_completion(
    client: AsyncGroq,
    *,
    bucket: str,
    model: str,
    messages: list[dict[str, Any]],
    max_completion_tokens: int,
    temperature: float | None = None,
    reasoning_effort: str | None = None,
) -> tuple[str, str | None]:
    """JSON応答を要求してcontentを取り出す。戻り値は (content, finish_reason)。

    パース側で診断できるよう finish_reason も返す("length"なら枠不足が明白になる)。
    """
    base_kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_completion_tokens": max_completion_tokens,
    }
    if temperature is not None:
        base_kwargs["temperature"] = temperature

    preferred_kwargs = dict(base_kwargs)
    preferred_kwargs["response_format"] = JSON_RESPONSE_FORMAT
    preferred_kwargs["reasoning_format"] = "hidden"
    if reasoning_effort:
        preferred_kwargs["reasoning_effort"] = reasoning_effort

    try:
        response = await create_chat_completion(client, bucket=bucket, **preferred_kwargs)
    except BadRequestError as exc:
        # 設定されたモデルがresponse_format/reasoning_*に対応していない場合の保険。
        # 枠(max_completion_tokens)だけは維持したまま素の呼び出しへ落とす。
        logger.warning(
            "GroqのJSONモード指定が拒否されたため最小構成で再試行する bucket=%s model=%s err=%s",
            bucket,
            model,
            exc,
        )
        response = await create_chat_completion(client, bucket=bucket, **base_kwargs)

    choice = response.choices[0] if response.choices else None
    message = getattr(choice, "message", None)
    content = getattr(message, "content", None) or ""
    finish_reason = getattr(choice, "finish_reason", None)
    return str(content), finish_reason
