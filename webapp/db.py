import asyncio
import logging
import os
from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .models import Base

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent.parent / "migrations"


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
            return value or None
    except OSError:
        return None


def _build_database_url() -> str:
    dsn = os.getenv("POSTGRES_DSN")
    if dsn:
        return dsn

    user = quote_plus(os.getenv("POSTGRES_USER", "postgres"))
    password_raw = (
        os.getenv("POSTGRES_PASSWORD")
        or _read_secret_file(os.getenv("POSTGRES_PASSWORD_FILE"))
        or "postgres"
    )
    password = quote_plus(password_raw)
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db_name = os.getenv("POSTGRES_DB", "metal_prices")
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db_name}"


DATABASE_URL = _build_database_url()

engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=30,
    pool_timeout=30,
    pool_recycle=1800,
)

SessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def _detect_legacy_db() -> bool:
    """create_all で作られた旧式DBかどうかを確認する。

    alembic_version テーブルがなく、既存テーブルが存在する場合は旧式DB。
    """
    async with engine.connect() as conn:
        has_alembic = await conn.run_sync(
            lambda c: inspect(c).has_table("alembic_version")
        )
        has_metal = await conn.run_sync(
            lambda c: inspect(c).has_table("metal_price_daily")
        )
    return has_metal and not has_alembic


def _run_alembic_upgrade() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(cfg, "head")


def _run_alembic_stamp_head() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.stamp(cfg, "head")


async def init_db() -> None:
    is_legacy = await _detect_legacy_db()

    if is_legacy:
        logger.warning(
            "旧式DB（create_all 作成）を検出。Alembic の初期リビジョンをスタンプします。"
        )
        await asyncio.to_thread(_run_alembic_stamp_head)
        logger.info("スタンプ完了。以降のマイグレーションは Alembic で管理されます。")
    else:
        logger.info("Alembic マイグレーションを実行します。")
        await asyncio.to_thread(_run_alembic_upgrade)
        logger.info("マイグレーション完了。")


async def close_db() -> None:
    await engine.dispose()
