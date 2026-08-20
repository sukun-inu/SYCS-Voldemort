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

DB_POOL_SIZE = max(1, int(os.getenv("DB_POOL_SIZE", "5")))
DB_MAX_OVERFLOW = max(0, int(os.getenv("DB_MAX_OVERFLOW", "10")))
DB_POOL_TIMEOUT = max(5, int(os.getenv("DB_POOL_TIMEOUT", "30")))
DB_POOL_RECYCLE = max(60, int(os.getenv("DB_POOL_RECYCLE", "1800")))

engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    pool_timeout=DB_POOL_TIMEOUT,
    pool_recycle=DB_POOL_RECYCLE,
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


def _run_alembic_stamp(revision: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.stamp(cfg, revision)


# uvicorn --workers での複数プロセス起動時、各ワーカーが起動時に init_db() を呼ぶため、
# ガード無しだと複数ワーカーが同時に `alembic upgrade head` を実行してしまう。CREATE TABLE
# など同じDDLが競合し "duplicate key value violates unique constraint
# pg_class_relname_nsp_index"（SERIAL列が暗黙に作るシーケンスの衝突）のようなエラーで起動が
# 失敗することを本番で確認した。app.py の SCHEDULER_ADVISORY_LOCK_KEY と同じ advisory lock
# パターンでマイグレーション実行そのものを直列化する（webapp/app.py 側の定期ジョブ用ロックとは
# 別のキーを使い、両者が干渉しないようにする）。
DB_MIGRATION_ADVISORY_LOCK_KEY = 721045777


async def init_db() -> None:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": DB_MIGRATION_ADVISORY_LOCK_KEY})
        try:
            is_legacy = await _detect_legacy_db()

            if is_legacy:
                logger.warning(
                    "旧式DB（create_all 作成）を検出。Alembic 初期リビジョン(0001)をスタンプ後、head へアップグレードします。"
                )
                await asyncio.to_thread(_run_alembic_stamp, "0001")
                await asyncio.to_thread(_run_alembic_upgrade)
                logger.info("旧式DBの移行完了。以降のマイグレーションは Alembic で管理されます。")
            else:
                logger.info("Alembic マイグレーションを実行します。")
                await asyncio.to_thread(_run_alembic_upgrade)
                logger.info("マイグレーション完了。")
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": DB_MIGRATION_ADVISORY_LOCK_KEY})


async def close_db() -> None:
    await engine.dispose()
