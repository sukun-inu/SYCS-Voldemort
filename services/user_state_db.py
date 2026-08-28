from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import quote_plus

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from envutil import env_int, env_raw
from webapp.models import UserStateCurrent, UserStateEvent

logger = logging.getLogger(__name__)


def _pooled_int(primary_key: str, fallback_key: str, default: int, *, minimum: int) -> int:
    """primary_key → fallback_key → default の優先順で整数設定を読む。

    関数引数は呼び出し時に必ず両方とも評価されるため、無条件に
    env_int(primary, env_int(fallback, ...)) と入れ子にすると、primary が
    有効な値のときでも fallback 側の壊れた値について筋違いの警告が出て
    しまう。先に env_raw でどちらが実際に効くかを決めてから1回だけ読む。
    """
    key = primary_key if env_raw(primary_key) is not None else fallback_key
    return env_int(key, default, minimum=minimum)


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
            return value or None
    except OSError as e:
        # ここで None を返すと、呼び出し側の _build_user_state_database_url は
        # 「ファイル指定なし」と区別できず、次の候補（さらには既定パスワード
        # "postgres"）へ静かに落ちる。*_FILE を明示的に指定したのに読めない、
        # というのは設定ミスの可能性が高いので、必ず理由を残す。
        logger.warning("シークレットファイルを読めませんでした %s: %s", path, e)
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

DB_POOL_SIZE = _pooled_int("USER_STATE_DB_POOL_SIZE", "DB_POOL_SIZE", 5, minimum=1)
DB_MAX_OVERFLOW = _pooled_int("USER_STATE_DB_MAX_OVERFLOW", "DB_MAX_OVERFLOW", 10, minimum=0)
DB_POOL_TIMEOUT = _pooled_int("USER_STATE_DB_POOL_TIMEOUT", "DB_POOL_TIMEOUT", 30, minimum=5)
DB_POOL_RECYCLE = _pooled_int("USER_STATE_DB_POOL_RECYCLE", "DB_POOL_RECYCLE", 1800, minimum=60)

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
