import logging
import os
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession

from config import METAL_COMMANDS
from services.url_safety import URLSafetyError, validate_public_http_url
from .cache import TTLCache
from .db import SessionLocal, close_db, init_db
from .forecast_service import load_stored_weekly_forecast, refresh_weekly_forecast_cache
from .models import NotificationDispatch, PushSubscription
from .push_service import (
    build_push_payload,
    get_vapid_public_key,
    is_push_enabled,
    refresh_vapid_config,
    send_push,
)
from .repair_service import repair_metalprice_integrity
from .security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    load_allowed_hosts,
    load_trusted_proxy_cidrs,
    read_env_bool,
)
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
FORECAST_CACHE_SECONDS = max(60, int(os.getenv("FORECAST_CACHE_SECONDS", "1800")))
FORECAST_REFRESH_MINUTE_JST = max(0, min(59, int(os.getenv("FORECAST_REFRESH_MINUTE_JST", "5"))))
PUSH_NOTIFY_HOUR_JST = max(0, min(23, int(os.getenv("PUSH_NOTIFY_HOUR_JST", "11"))))
PUSH_NOTIFY_MINUTE_JST = max(0, min(59, int(os.getenv("PUSH_NOTIFY_MINUTE_JST", "0"))))
NOTIFY_TOP_DELTA_TYPE = "daily_top_delta"
APP_PUBLIC_PATH = (os.getenv("APP_PUBLIC_PATH") or os.getenv("APP_ROOT_PATH") or "/").strip() or "/"
PUSH_MAX_SUBSCRIPTIONS = max(100, int(os.getenv("PUSH_MAX_SUBSCRIPTIONS", "50000")))
_PUSH_ALLOWED_ENDPOINT_SUFFIXES = tuple(
    part.strip().lower()
    for part in os.getenv("PUSH_ALLOWED_ENDPOINT_SUFFIXES", "").split(",")
    if part.strip()
)


def _normalize_public_path(path: str) -> str:
    if path in {"", "/"}:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    if not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _is_repairable_db_error(exc: Exception) -> bool:
    return isinstance(exc, (OperationalError, ProgrammingError))


async def _try_db_self_heal(*, context: str, exc: Exception) -> bool:
    if not _is_repairable_db_error(exc):
        return False
    logger.warning("[WEB] %s failed with DB error. trying self-heal: %s", context, exc)
    try:
        await init_db()
        return True
    except Exception:
        logger.exception("[WEB] DB self-heal failed at %s", context)
        return False


APP_PUBLIC_ROOT = _normalize_public_path(APP_PUBLIC_PATH)
STARTUP_TEST_MODE = read_env_bool("STARTUP_TEST_MODE", False)
STARTUP_TEST_REQUIRE_DOCKER = read_env_bool("STARTUP_TEST_REQUIRE_DOCKER", True)
STARTUP_TEST_RUN_PUSH_ON_BOOT = read_env_bool("STARTUP_TEST_RUN_PUSH_ON_BOOT", False)
STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT = read_env_bool("STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT", False)
STARTUP_TEST_FORCE_SNAPSHOT_REFRESH = read_env_bool("STARTUP_TEST_FORCE_SNAPSHOT_REFRESH", True)
WEB_SCHEDULER_ENABLED = read_env_bool("WEB_SCHEDULER_ENABLED", True)
METAL_AUTO_REPAIR_ENABLED = read_env_bool("METAL_AUTO_REPAIR_ENABLED", True)
METAL_AUTO_REPAIR_INTERVAL_MINUTES = max(5, int(os.getenv("METAL_AUTO_REPAIR_INTERVAL_MINUTES", "30")))
METAL_AUTO_REPAIR_LOOKBACK_DAYS = max(7, int(os.getenv("METAL_AUTO_REPAIR_LOOKBACK_DAYS", "60")))
METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH = read_env_bool("METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH", False)

history_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=64)
latest_prices_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=8)
calculate_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=1024)
forecast_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=FORECAST_CACHE_SECONDS, max_items=32)
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


def _validate_push_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    try:
        validate_public_http_url(endpoint, allow_http=False)
    except URLSafetyError as e:
        raise HTTPException(status_code=400, detail=f"無効なPush endpointです: {e}") from e

    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="無効なPush endpointです: hostが不正です")

    if _PUSH_ALLOWED_ENDPOINT_SUFFIXES:
        if not any(host == suffix or host.endswith(f".{suffix}") for suffix in _PUSH_ALLOWED_ENDPOINT_SUFFIXES):
            raise HTTPException(status_code=400, detail="Push endpoint のホストが許可リスト外です")

    return endpoint


async def _clear_response_caches() -> None:
    await history_cache.clear()
    await latest_prices_cache.clear()
    await calculate_cache.clear()
    await forecast_cache.clear()


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


async def _claim_dispatch_slot(session: AsyncSession, *, snapshot_date: date) -> int | None:
    """通知送信スロットを先に確保して、多重インスタンスの重複送信を防ぐ。"""
    dispatch = NotificationDispatch(
        notification_type=NOTIFY_TOP_DELTA_TYPE,
        snapshot_date=snapshot_date,
        detail="pending",
    )
    session.add(dispatch)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return None
    return dispatch.id


async def _send_push_to_subscriptions(
    subscriptions: list,
    payload: str,
    session: AsyncSession,
) -> tuple[int, list[str]]:
    stale_endpoints: list[str] = []
    success_count = 0
    for sub in subscriptions:
        ok, should_remove = await send_push(
            {"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh_key, "auth": sub.auth_key}},
            payload,
        )
        if ok:
            success_count += 1
        elif should_remove:
            stale_endpoints.append(sub.endpoint)

    if stale_endpoints:
        await session.execute(delete(PushSubscription).where(PushSubscription.endpoint.in_(stale_endpoints)))

    return success_count, stale_endpoints


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
        subscriptions = list((await session.scalars(select(PushSubscription))).all())
        if not subscriptions:
            return

        snapshot_date_value = datetime.fromisoformat(snapshot_date).date()
        dispatch_id = await _claim_dispatch_slot(session, snapshot_date=snapshot_date_value)
        if dispatch_id is None:
            logger.info("日次Push通知は別インスタンスで処理中/送信済みのためスキップ。snapshot=%s", snapshot_date)
            return

        spec = METAL_COMMANDS[metal_key]
        delta_sign = "+" if delta_value >= 0 else ""
        payload = build_push_payload(
            title="本日の価格変動通知 (JST 11:00)",
            body=f"{spec.display_name}の前日差が最大: {delta_sign}{delta_value:.2f} 円/g ({snapshot_date})",
            url=APP_PUBLIC_ROOT,
        )

        try:
            success_count, stale_endpoints = await _send_push_to_subscriptions(subscriptions, payload, session)
            await session.execute(
                update(NotificationDispatch)
                .where(NotificationDispatch.id == dispatch_id)
                .values(detail=f"{metal_key}:{delta_value}:ok={success_count}:stale={len(stale_endpoints)}")
            )
            await session.commit()
        except Exception:
            await session.rollback()
            try:
                await session.execute(delete(NotificationDispatch).where(NotificationDispatch.id == dispatch_id))
                await session.commit()
            except Exception:
                await session.rollback()
            raise

        logger.info(
            "日次Push通知を送信した。snapshot=%s success=%s stale_removed=%s",
            snapshot_date,
            success_count,
            len(stale_endpoints),
        )


def _running_in_container() -> bool:
    if Path("/.dockerenv").exists():
        return True
    cgroup_file = Path("/proc/1/cgroup")
    if not cgroup_file.exists():
        return False
    try:
        cgroup_text = cgroup_file.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False
    return "docker" in cgroup_text or "containerd" in cgroup_text or "kubepods" in cgroup_text


def _startup_test_enabled() -> bool:
    if not STARTUP_TEST_MODE:
        if STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT or STARTUP_TEST_RUN_PUSH_ON_BOOT:
            logger.warning(
                "起動テスト設定を検出したが STARTUP_TEST_MODE=false のため無効化。"
            )
        return False
    if STARTUP_TEST_REQUIRE_DOCKER and not _running_in_container():
        logger.warning("起動テストモードをスキップ: コンテナ外で STARTUP_TEST_REQUIRE_DOCKER=true")
        return False
    return True


async def _dispatch_startup_test_push_notification() -> None:
    # 起動時テスト通知は通常運用の重複判定・送信履歴に影響させない。
    if not is_push_enabled():
        logger.warning("起動時テストPushをスキップ: Push通知が未設定")
        return

    async with SessionLocal() as session:
        latest_snapshot = await _get_latest_prices(session)
        top = _pick_top_delta(latest_snapshot)
        if top is None:
            logger.warning("起動時テストPushをスキップ: 送信対象データが未取得")
            return

        metal_key, delta_value, snapshot_date = top
        subscriptions = list((await session.scalars(select(PushSubscription))).all())
        if not subscriptions:
            logger.warning("起動時テストPushをスキップ: 購読ユーザーが存在しない")
            return

        spec = METAL_COMMANDS[metal_key]
        delta_sign = "+" if delta_value >= 0 else ""
        payload = build_push_payload(
            title="【テスト】起動時 Push 通知",
            body=f"{spec.display_name} 変動テスト: {delta_sign}{delta_value:.2f} 円/g ({snapshot_date})",
            url=APP_PUBLIC_ROOT,
        )

        success_count, stale_endpoints = await _send_push_to_subscriptions(subscriptions, payload, session)
        await session.commit()

        logger.warning(
            "起動時テストPushを送信した。snapshot=%s success=%s stale_removed=%s",
            snapshot_date,
            success_count,
            len(stale_endpoints),
        )


async def _run_startup_test_jobs() -> None:
    if not _startup_test_enabled():
        return
    logger.warning(
        "起動テストモード有効: midnight_job=%s push=%s force_snapshot=%s",
        STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT,
        STARTUP_TEST_RUN_PUSH_ON_BOOT,
        STARTUP_TEST_FORCE_SNAPSHOT_REFRESH,
    )

    if STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT:
        try:
            await collect_daily_data(
                force_snapshot_refresh=STARTUP_TEST_FORCE_SNAPSHOT_REFRESH,
                force_forecast_refresh=STARTUP_TEST_FORCE_SNAPSHOT_REFRESH,
            )
            logger.warning("起動時テスト: 0時更新ジョブを即時実行した。")
        except Exception:
            logger.exception("起動時テスト: 0時更新ジョブの即時実行に失敗した。")

    if STARTUP_TEST_RUN_PUSH_ON_BOOT:
        try:
            await _dispatch_startup_test_push_notification()
        except Exception:
            logger.exception("起動時テスト: Push通知の即時送信に失敗した。")


async def collect_daily_snapshot(*, force_refresh: bool = False) -> None:
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                await store_today_snapshot(session, skip_if_exists=not force_refresh)
                await _clear_response_caches()
                logger.info("日次価格スナップショットを保存した。force_refresh=%s", force_refresh)
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="collect_daily_snapshot", exc=e):
                    continue
                logger.exception("日次価格スナップショット保存に失敗した。")
                return


async def collect_weekly_forecast_cache(*, force_refresh: bool = False) -> None:
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                today_iso = datetime.now(JST).date().isoformat()
                if not force_refresh:
                    existing_payload = await load_stored_weekly_forecast(session, days=7)
                    if existing_payload and existing_payload.get("as_of_date") == today_iso:
                        logger.info("7日予測データは最新のため更新をスキップした。as_of_date=%s", today_iso)
                        return
                await refresh_weekly_forecast_cache(session, horizon_days=7)
                await forecast_cache.clear()
                logger.info("7日予測データを更新し、DBに保存した。force_refresh=%s", force_refresh)
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="collect_weekly_forecast_cache", exc=e):
                    continue
                logger.exception("7日予測データの更新保存に失敗した。")
                return


async def auto_repair_metalprice_data(*, force_forecast_refresh: bool = False) -> None:
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stats = await repair_metalprice_integrity(
                    session,
                    lookback_days=METAL_AUTO_REPAIR_LOOKBACK_DAYS,
                    force_forecast_refresh=force_forecast_refresh,
                )
                await _clear_response_caches()
                logger.info(
                    "metalprice自動修復を実行した。rows_scanned=%s rows_fixed=%s code_fixed=%s delta_fixed=%s missing_today_before=%s missing_today_after=%s forecast_refreshed=%s",
                    stats.get("rows_scanned", 0),
                    stats.get("rows_fixed", 0),
                    stats.get("metal_code_fixed", 0),
                    stats.get("delta_fixed", 0),
                    stats.get("missing_today_before", 0),
                    stats.get("missing_today_after", 0),
                    stats.get("forecast_refreshed", 0),
                )
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="auto_repair_metalprice_data", exc=e):
                    continue
                logger.exception("metalprice自動修復に失敗した。")
                return


async def collect_daily_data(*, force_snapshot_refresh: bool = False, force_forecast_refresh: bool = False) -> None:
    await collect_daily_snapshot(force_refresh=force_snapshot_refresh)
    await collect_weekly_forecast_cache(force_refresh=force_forecast_refresh)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    refresh_vapid_config()
    scheduler: AsyncIOScheduler | None = None

    if WEB_SCHEDULER_ENABLED:
        await collect_daily_data()
        if METAL_AUTO_REPAIR_ENABLED:
            await auto_repair_metalprice_data(
                force_forecast_refresh=METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH
            )
        await dispatch_top_delta_notification(enforce_schedule_time=True)
        await _run_startup_test_jobs()

        scheduler = AsyncIOScheduler(timezone=JST)
        scheduler.add_job(
            collect_daily_data,
            CronTrigger(hour=0, minute=0, timezone=JST),
            id="jst_daily_metal_snapshot_and_forecast",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            misfire_grace_time=3600,
        )
        scheduler.add_job(
            collect_weekly_forecast_cache,
            CronTrigger(minute=FORECAST_REFRESH_MINUTE_JST, timezone=JST),
            kwargs={"force_refresh": True},
            id="jst_hourly_forecast_refresh",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            misfire_grace_time=1800,
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
        if METAL_AUTO_REPAIR_ENABLED:
            scheduler.add_job(
                auto_repair_metalprice_data,
                IntervalTrigger(minutes=METAL_AUTO_REPAIR_INTERVAL_MINUTES, timezone=JST),
                kwargs={"force_forecast_refresh": METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH},
                id="jst_metalprice_auto_repair",
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=max(300, METAL_AUTO_REPAIR_INTERVAL_MINUTES * 60),
            )
        scheduler.start()
        logger.info("WEB_SCHEDULER_ENABLED=true: background scheduler started")
    else:
        logger.info("WEB_SCHEDULER_ENABLED=false: startup jobs and scheduler are disabled")

    try:
        yield
    finally:
        if scheduler is not None:
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
    trust_cf_headers=read_env_bool("TRUST_CF_HEADERS", False),
    require_cf_connecting_ip=read_env_bool("REQUIRE_CF_CONNECTING_IP", False),
    trusted_proxy_cidrs=load_trusted_proxy_cidrs(),
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=500)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(
        INDEX_FILE,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/index.html", include_in_schema=False)
async def index_html() -> FileResponse:
    return FileResponse(
        INDEX_FILE,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/sw.js", include_in_schema=False)
async def service_worker() -> FileResponse:
    return FileResponse(
        SW_FILE,
        media_type="application/javascript",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Service-Worker-Allowed": APP_PUBLIC_ROOT,
        },
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


@app.get("/api/prices/forecast-weekly")
async def weekly_forecast(
    days: int = Query(default=7, ge=1, le=7),
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    cache_key = f"forecast:{datetime.now(JST).date().isoformat()}:{days}"
    cached = await forecast_cache.get(cache_key)
    if cached is not None:
        return JSONResponse(cached, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"})

    payload = await load_stored_weekly_forecast(session, days=days)
    if payload is None:
        raise HTTPException(status_code=503, detail="予測データがまだありません。次回の予測更新後に利用できます。")

    await forecast_cache.set(cache_key, payload)
    return JSONResponse(
        payload,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/api/purity/options")
async def purity_options() -> JSONResponse:
    return JSONResponse(PURITY_OPTIONS_PAYLOAD, headers=_cache_headers(PURITY_OPTIONS_CACHE_SECONDS))


@app.get("/api/push/public-key")
async def push_public_key() -> JSONResponse:
    public_key = get_vapid_public_key()
    enabled = is_push_enabled() and public_key is not None
    reason = None if enabled else "vapid_not_configured_or_generation_failed"
    return JSONResponse(
        {
            "enabled": enabled,
            "public_key": public_key if enabled else None,
            "notify_time_jst": f"{PUSH_NOTIFY_HOUR_JST:02d}:{PUSH_NOTIFY_MINUTE_JST:02d}",
            "reason": reason,
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

    endpoint = _validate_push_endpoint(payload.endpoint)
    existing = (
        await session.scalars(select(PushSubscription).where(PushSubscription.endpoint == endpoint))
    ).first()
    if existing:
        existing.p256dh_key = payload.keys.p256dh
        existing.auth_key = payload.keys.auth
        existing.user_agent = request.headers.get("user-agent")
    else:
        current_count = await session.scalar(select(func.count(PushSubscription.id)))
        if int(current_count or 0) >= PUSH_MAX_SUBSCRIPTIONS:
            raise HTTPException(status_code=429, detail="Push購読数が上限に達しています。")
        session.add(
            PushSubscription(
                endpoint=endpoint,
                p256dh_key=payload.keys.p256dh,
                auth_key=payload.keys.auth,
                user_agent=request.headers.get("user-agent"),
            )
        )

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        logger.debug("push_subscribe: 同一エンドポイントの重複リクエストを無視")
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
