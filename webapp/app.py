import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS
from .cache import TTLCache
from .db import SessionLocal, close_db, init_db
from .models import NotificationDispatch, PushSubscription
from .push_service import (
    build_push_payload,
    get_vapid_public_key,
    is_push_enabled,
    refresh_vapid_config,
    send_push,
)
from .security import RateLimitMiddleware, SecurityHeadersMiddleware, load_allowed_hosts, read_env_bool
from .snapshot_service import JST, load_history, load_latest_rows, store_today_snapshot

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
SW_FILE = STATIC_DIR / "sw.js"
MANIFEST_FILE = STATIC_DIR / "manifest.webmanifest"
RESERVED_TOP_LEVEL_PATHS = {"api", "static", "health", "docs", "redoc", "openapi.json", "sw.js", "manifest.webmanifest"}
API_RESPONSE_CACHE_SECONDS = max(1, int(os.getenv("API_RESPONSE_CACHE_SECONDS", "20")))
PURITY_OPTIONS_CACHE_SECONDS = max(60, int(os.getenv("PURITY_OPTIONS_CACHE_SECONDS", "3600")))
PUSH_PUBLIC_KEY_CACHE_SECONDS = max(300, int(os.getenv("PUSH_PUBLIC_KEY_CACHE_SECONDS", "3600")))
PUSH_NOTIFY_HOUR_JST = max(0, min(23, int(os.getenv("PUSH_NOTIFY_HOUR_JST", "11"))))
PUSH_NOTIFY_MINUTE_JST = max(0, min(59, int(os.getenv("PUSH_NOTIFY_MINUTE_JST", "0"))))
NOTIFY_TOP_DELTA_TYPE = "daily_top_delta"

history_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=64)
latest_prices_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=8)
calculate_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=1024)
PURITY_OPTIONS_PAYLOAD = {
    "metals": {
        key: {
            "display_name": spec.display_name,
            "purity": [{"grade": grade, "ratio": ratio} for grade, ratio in spec.purity.items()],
        }
        for key, spec in METAL_COMMANDS.items()
    }
}


class PushSubscriptionKeys(BaseModel):
    p256dh: str = Field(min_length=1, max_length=2048)
    auth: str = Field(min_length=1, max_length=2048)


class PushSubscribeRequest(BaseModel):
    endpoint: str = Field(min_length=1, max_length=4096)
    keys: PushSubscriptionKeys
    expirationTime: int | None = None  # noqa: N815 - browser spec field


class PushUnsubscribeRequest(BaseModel):
    endpoint: str = Field(min_length=1, max_length=4096)


async def get_db_session():
    async with SessionLocal() as session:
        yield session


def _cache_headers(ttl_seconds: int) -> dict[str, str]:
    return {
        "Cache-Control": f"public, max-age={ttl_seconds}, s-maxage={ttl_seconds}, stale-while-revalidate={ttl_seconds}",
    }


async def _clear_response_caches() -> None:
    await history_cache.clear()
    await latest_prices_cache.clear()
    await calculate_cache.clear()


async def _get_latest_prices(session: AsyncSession) -> dict[str, dict[str, str | None]]:
    cache_key = f"latest:{datetime.now(JST).date().isoformat()}"
    cached = await latest_prices_cache.get(cache_key)
    if cached is not None:
        return cached

    latest_rows = await load_latest_rows(session)
    snapshot: dict[str, dict[str, str | None]] = {}
    for metal_key in METAL_COMMANDS.keys():
        row = latest_rows.get(metal_key)
        if row is None:
            snapshot[metal_key] = {
                "date": None,
                "price_per_gram": None,
                "delta_from_previous": None,
            }
            continue
        snapshot[metal_key] = {
            "date": row.snapshot_date.isoformat(),
            "price_per_gram": str(row.price_per_gram),
            "delta_from_previous": str(row.delta_from_previous) if row.delta_from_previous is not None else None,
        }

    await latest_prices_cache.set(cache_key, snapshot)
    return snapshot


def _latest_prices_public(snapshot: dict[str, dict[str, str | None]]) -> dict[str, dict[str, float | str | None]]:
    latest: dict[str, dict[str, float | str | None]] = {}
    for metal_key in METAL_COMMANDS.keys():
        item = snapshot.get(metal_key, {})
        price = item.get("price_per_gram")
        delta = item.get("delta_from_previous")
        latest[metal_key] = {
            "date": item.get("date"),
            "price_per_gram": float(price) if price is not None else None,
            "delta_from_previous": float(delta) if delta is not None else None,
        }
    return latest


def _pick_top_delta(snapshot: dict[str, dict[str, str | None]]) -> tuple[str, Decimal, str] | None:
    top_metal_key: str | None = None
    top_delta: Decimal | None = None
    top_date: str | None = None

    for metal_key in METAL_COMMANDS.keys():
        item = snapshot.get(metal_key)
        if not item:
            continue
        delta_raw = item.get("delta_from_previous")
        snapshot_date = item.get("date")
        if delta_raw is None or snapshot_date is None:
            continue

        delta = Decimal(delta_raw)
        if top_delta is None or abs(delta) > abs(top_delta):
            top_metal_key = metal_key
            top_delta = delta
            top_date = snapshot_date

    if top_metal_key is None or top_delta is None or top_date is None:
        return None
    return top_metal_key, top_delta, top_date


async def _already_dispatched(session: AsyncSession, *, snapshot_date: str) -> bool:
    stmt = select(NotificationDispatch.id).where(
        NotificationDispatch.notification_type == NOTIFY_TOP_DELTA_TYPE,
        NotificationDispatch.snapshot_date == datetime.fromisoformat(snapshot_date).date(),
    )
    return (await session.scalar(stmt)) is not None


async def dispatch_top_delta_notification(*, enforce_schedule_time: bool = False) -> None:
    if not is_push_enabled():
        return

    now = datetime.now(JST)
    if enforce_schedule_time and (now.hour, now.minute) < (PUSH_NOTIFY_HOUR_JST, PUSH_NOTIFY_MINUTE_JST):
        return

    async with SessionLocal() as session:
        latest_snapshot = await _get_latest_prices(session)
        top = _pick_top_delta(latest_snapshot)
        if top is None:
            return

        metal_key, delta_value, snapshot_date = top
        if await _already_dispatched(session, snapshot_date=snapshot_date):
            return

        subscriptions = list((await session.scalars(select(PushSubscription))).all())
        if not subscriptions:
            return

        spec = METAL_COMMANDS[metal_key]
        delta_sign = "+" if delta_value >= 0 else ""
        payload = build_push_payload(
            title="本日の価格変動通知 (JST 11:00)",
            body=f"{spec.display_name}の前日差が最大: {delta_sign}{delta_value:.2f} 円/g ({snapshot_date})",
            url="/",
        )

        stale_endpoints: list[str] = []
        success_count = 0
        for sub in subscriptions:
            ok, should_remove = await send_push(
                {
                    "endpoint": sub.endpoint,
                    "keys": {
                        "p256dh": sub.p256dh_key,
                        "auth": sub.auth_key,
                    },
                },
                payload,
            )
            if ok:
                success_count += 1
            elif should_remove:
                stale_endpoints.append(sub.endpoint)

        if stale_endpoints:
            await session.execute(delete(PushSubscription).where(PushSubscription.endpoint.in_(stale_endpoints)))

        session.add(
            NotificationDispatch(
                notification_type=NOTIFY_TOP_DELTA_TYPE,
                snapshot_date=datetime.fromisoformat(snapshot_date).date(),
                detail=f"{metal_key}:{delta_value}",
            )
        )
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            logger.info("日次Push通知は別インスタンスで送信済みのためスキップ。snapshot=%s", snapshot_date)
            return
        logger.info(
            "日次Push通知を送信した。snapshot=%s success=%s stale_removed=%s",
            snapshot_date,
            success_count,
            len(stale_endpoints),
        )


async def collect_daily_snapshot() -> None:
    async with SessionLocal() as session:
        try:
            await store_today_snapshot(session, skip_if_exists=True)
            await _clear_response_caches()
            logger.info("日次価格スナップショットを保存した。")
        except Exception:
            logger.exception("日次価格スナップショット保存に失敗した。")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    refresh_vapid_config()
    await collect_daily_snapshot()
    await dispatch_top_delta_notification(enforce_schedule_time=True)

    scheduler = AsyncIOScheduler(timezone=JST)
    scheduler.add_job(
        collect_daily_snapshot,
        CronTrigger(hour=0, minute=0, timezone=JST),
        id="jst_daily_metal_snapshot",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        dispatch_top_delta_notification,
        CronTrigger(hour=PUSH_NOTIFY_HOUR_JST, minute=PUSH_NOTIFY_MINUTE_JST, timezone=JST),
        id="jst_daily_top_delta_push_notify",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=7200,
    )
    scheduler.start()

    try:
        yield
    finally:
        scheduler.shutdown(wait=False)
        await close_db()


app = FastAPI(
    title="Metal Price Tracker",
    description="JST midnight snapshots for gold, silver, and platinum.",
    version="1.0.0",
    lifespan=lifespan,
    root_path=os.getenv("APP_ROOT_PATH", ""),
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=load_allowed_hosts())
app.add_middleware(
    RateLimitMiddleware,
    requests_per_window=int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "120")),
    calculate_requests_per_window=int(os.getenv("API_CALCULATE_RATE_LIMIT_PER_MINUTE", "60")),
    window_seconds=60,
    trust_cf_headers=read_env_bool("TRUST_CF_HEADERS", True),
    require_cf_connecting_ip=read_env_bool("REQUIRE_CF_CONNECTING_IP", False),
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=500)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(INDEX_FILE)


@app.get("/index.html", include_in_schema=False)
async def index_html() -> FileResponse:
    return FileResponse(INDEX_FILE)


@app.get("/sw.js", include_in_schema=False)
async def service_worker() -> FileResponse:
    return FileResponse(
        SW_FILE,
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/manifest.webmanifest", include_in_schema=False)
async def manifest() -> FileResponse:
    return FileResponse(
        MANIFEST_FILE,
        media_type="application/manifest+json",
        headers=_cache_headers(PURITY_OPTIONS_CACHE_SECONDS),
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/prices/history")
async def price_history(
    days: int = Query(default=365, ge=7, le=3650),
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    today = datetime.now(JST).date()
    cache_key = f"history:{today.isoformat()}:{days}"
    cached = await history_cache.get(cache_key)
    if cached is not None:
        return JSONResponse(cached, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))

    history = await load_history(session, days)
    latest_snapshot = await _get_latest_prices(session)
    latest = _latest_prices_public(latest_snapshot)
    start_date = today - timedelta(days=days - 1)
    payload = {
        "timezone": "Asia/Tokyo",
        "snapshot_policy": "daily_at_jst_midnight",
        "range_start": start_date.isoformat(),
        "range_end": today.isoformat(),
        "days": days,
        "metals": history,
        "latest": latest,
    }
    await history_cache.set(cache_key, payload)
    return JSONResponse(payload, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))


@app.get("/api/purity/options")
async def purity_options() -> JSONResponse:
    return JSONResponse(PURITY_OPTIONS_PAYLOAD, headers=_cache_headers(PURITY_OPTIONS_CACHE_SECONDS))


@app.get("/api/push/public-key")
async def push_public_key() -> JSONResponse:
    public_key = get_vapid_public_key()
    enabled = is_push_enabled() and public_key is not None
    return JSONResponse(
        {
            "enabled": enabled,
            "public_key": public_key if enabled else None,
            "notify_time_jst": f"{PUSH_NOTIFY_HOUR_JST:02d}:{PUSH_NOTIFY_MINUTE_JST:02d}",
        },
        headers=_cache_headers(PUSH_PUBLIC_KEY_CACHE_SECONDS),
    )


@app.post("/api/push/subscribe")
async def push_subscribe(
    payload: PushSubscribeRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, bool]:
    if not is_push_enabled():
        raise HTTPException(status_code=503, detail="Push通知が無効です。VAPID設定を確認してください。")

    endpoint = payload.endpoint.strip()
    existing = (
        await session.scalars(select(PushSubscription).where(PushSubscription.endpoint == endpoint))
    ).first()
    if existing:
        existing.p256dh_key = payload.keys.p256dh
        existing.auth_key = payload.keys.auth
        existing.user_agent = request.headers.get("user-agent")
    else:
        session.add(
            PushSubscription(
                endpoint=endpoint,
                p256dh_key=payload.keys.p256dh,
                auth_key=payload.keys.auth,
                user_agent=request.headers.get("user-agent"),
            )
        )

    await session.commit()
    return {"ok": True}


@app.post("/api/push/unsubscribe")
async def push_unsubscribe(
    payload: PushUnsubscribeRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, int | bool]:
    result = await session.execute(delete(PushSubscription).where(PushSubscription.endpoint == payload.endpoint.strip()))
    await session.commit()
    return {"ok": True, "deleted": int(result.rowcount or 0)}


@app.get("/api/prices/calculate")
async def calculate_by_purity(
    metal: str = Query(..., min_length=1),
    grams: float = Query(..., gt=0, le=100000),
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    metal_key = metal.strip().lower()
    spec = METAL_COMMANDS.get(metal_key)
    if spec is None:
        raise HTTPException(status_code=400, detail="metal は gold/silver/platinum のいずれかを指定してください。")

    latest_snapshot = await _get_latest_prices(session)
    latest_row = latest_snapshot.get(metal_key, {})
    snapshot_date = latest_row.get("date")
    price_per_gram_raw = latest_row.get("price_per_gram")
    if snapshot_date is None or price_per_gram_raw is None:
        raise HTTPException(status_code=503, detail="価格データがまだありません。日次取得完了後に再実行してください。")

    grams_decimal = Decimal(str(grams))
    grams_key = f"{grams_decimal:.4f}"
    cache_key = f"calculate:{snapshot_date}:{metal_key}:{grams_key}"
    cached = await calculate_cache.get(cache_key)
    if cached is not None:
        return JSONResponse(cached, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))

    price_per_gram = Decimal(price_per_gram_raw)
    pure_value = int(price_per_gram * grams_decimal)
    by_purity = {
        grade: int(price_per_gram * grams_decimal * Decimal(str(ratio)))
        for grade, ratio in spec.purity.items()
    }

    payload = {
        "metal": metal_key,
        "display_name": spec.display_name,
        "snapshot_date": snapshot_date,
        "price_per_gram": float(price_per_gram),
        "grams": grams,
        "pure_value": pure_value,
        "by_purity": by_purity,
    }
    await calculate_cache.set(cache_key, payload)
    return JSONResponse(payload, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))


@app.get("/{page_path:path}", include_in_schema=False)
async def fallback_page(page_path: str) -> FileResponse:
    first = page_path.split("/", 1)[0] if page_path else ""
    if first in RESERVED_TOP_LEVEL_PATHS:
        raise HTTPException(status_code=404, detail="Not Found")
    return FileResponse(INDEX_FILE)
