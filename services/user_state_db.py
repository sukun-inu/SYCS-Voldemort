from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import quote_plus

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from webapp.models import UserStateCurrent, UserStateEvent

logger = logging.getLogger(__name__)


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
            return value or None
    except OSError:
        return None


def _build_user_state_database_url() -> str:
    dsn = os.getenv("USER_STATE_POSTGRES_DSN")
    if dsn:
        return dsn

    user = quote_plus(os.getenv("USER_STATE_POSTGRES_USER", os.getenv("POSTGRES_USER", "postgres")))
    password_raw = (
        os.getenv("USER_STATE_POSTGRES_PASSWORD")
        or _read_secret_file(os.getenv("USER_STATE_POSTGRES_PASSWORD_FILE"))
        or os.getenv("POSTGRES_PASSWORD")
        or _read_secret_file(os.getenv("POSTGRES_PASSWORD_FILE"))
        or "postgres"
    )
    password = quote_plus(password_raw)
    host = os.getenv("USER_STATE_POSTGRES_HOST", os.getenv("POSTGRES_HOST", "localhost"))
    port = os.getenv("USER_STATE_POSTGRES_PORT", os.getenv("POSTGRES_PORT", "5432"))
    db_name = os.getenv("USER_STATE_POSTGRES_DB", "user_state_audit")
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db_name}"


DATABASE_URL = _build_user_state_database_url()

DB_POOL_SIZE = max(1, int(os.getenv("USER_STATE_DB_POOL_SIZE", os.getenv("DB_POOL_SIZE", "5"))))
DB_MAX_OVERFLOW = max(0, int(os.getenv("USER_STATE_DB_MAX_OVERFLOW", os.getenv("DB_MAX_OVERFLOW", "10"))))
DB_POOL_TIMEOUT = max(5, int(os.getenv("USER_STATE_DB_POOL_TIMEOUT", os.getenv("DB_POOL_TIMEOUT", "30"))))
DB_POOL_RECYCLE = max(60, int(os.getenv("USER_STATE_DB_POOL_RECYCLE", os.getenv("DB_POOL_RECYCLE", "1800"))))

engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    pool_timeout=DB_POOL_TIMEOUT,
    pool_recycle=DB_POOL_RECYCLE,
)

SessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

_init_lock: asyncio.Lock | None = None
_initialized = False


def _create_tables(sync_conn) -> None:
    UserStateCurrent.__table__.create(bind=sync_conn, checkfirst=True)
    UserStateEvent.__table__.create(bind=sync_conn, checkfirst=True)


async def ensure_user_state_db(*, force: bool = False) -> None:
    global _initialized, _init_lock
    if _initialized and not force:
        return
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    async with _init_lock:
        if _initialized and not force:
            return
        async with engine.begin() as conn:
            await conn.run_sync(_create_tables)
        _initialized = True
        if force:
            logger.warning("User state DB self-heal completed (force recheck).")
        else:
            logger.info("User state DB initialized.")


async def close_user_state_db() -> None:
    await engine.dispose()
