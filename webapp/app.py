import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession

from .db import SessionLocal, close_db, init_db
from .security import RateLimitMiddleware, SecurityHeadersMiddleware, load_allowed_hosts
from .snapshot_service import JST, load_history, load_latest, store_today_snapshot

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
RESERVED_TOP_LEVEL_PATHS = {"api", "static", "health", "docs", "redoc", "openapi.json"}


async def get_db_session():
    async with SessionLocal() as session:
        yield session


async def collect_daily_snapshot() -> None:
    async with SessionLocal() as session:
        try:
            await store_today_snapshot(session, skip_if_exists=True)
            logger.info("日次価格スナップショットを保存した。")
        except Exception:
            logger.exception("日次価格スナップショット保存に失敗した。")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    await collect_daily_snapshot()

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
    window_seconds=60,
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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/prices/history")
async def price_history(
    days: int = Query(default=365, ge=7, le=3650),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    history = await load_history(session, days)
    latest = await load_latest(session)
    return {
        "timezone": "Asia/Tokyo",
        "generated_at": datetime.now(ZoneInfo("Asia/Tokyo")).isoformat(),
        "days": days,
        "metals": history,
        "latest": latest,
    }


@app.get("/{page_path:path}", include_in_schema=False)
async def fallback_page(page_path: str) -> FileResponse:
    first = page_path.split("/", 1)[0] if page_path else ""
    if first in RESERVED_TOP_LEVEL_PATHS:
        raise HTTPException(status_code=404, detail="Not Found")
    return FileResponse(INDEX_FILE)
