import asyncio
import logging
import os
from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from envutil import env_int

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent.parent / "migrations"


def _read_secret_file(path: str | None) -> str | None:
    """パスワードファイルを読む。読めなければ None。

    **読めなかったことを黙って握りつぶさない。** 呼び出し元はここが None だと
    既定値 "postgres" へ倒れるので、マウント忘れや権限不足を握りつぶすと、
    「認証エラー」ではなく「既定パスワードで接続を試みて失敗する」という
    追いにくい形になる。ログが無いと、そこへ辿り着く手がかりが残らない。

    既定値へ倒れること自体は変えていない（初回起動時にパスワードを生成する
    構成なので、無い状態から始まるのが正常な経路でもある）。
    """
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
    except OSError as e:
        logger.error(
            "パスワードファイル %s を読めませんでした（既定値で接続を試みます）: %s",
            path,
            e,
        )
        return None
    if not value:
        logger.error("パスワードファイル %s が空です（既定値で接続を試みます）", path)
        return None
    return value


def _build_database_url() -> str:
    """POSTGRES_DSNがあれば最優先。無ければ個別項目から組み立てる。

    user/password は quote_plus を通す。パスワードに `@` や `/` 等の
    URL予約文字が入っていると、素のままではDSNの区切りと衝突して
    別ホスト・別ユーザーに解釈されたり、接続文字列として壊れたりする。
    """
    dsn = os.getenv("POSTGRES_DSN")
    if dsn:
        return dsn

    user = quote_plus(os.getenv("POSTGRES_USER", "postgres"))
    password_raw = (
        os.getenv("POSTGRES_PASSWORD") or _read_secret_file(os.getenv("POSTGRES_PASSWORD_FILE")) or "postgres"
    )
    password = quote_plus(password_raw)
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db_name = os.getenv("POSTGRES_DB", "metal_prices")
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db_name}"


DATABASE_URL = _build_database_url()

DB_POOL_SIZE = env_int("DB_POOL_SIZE", 5, minimum=1)
DB_MAX_OVERFLOW = env_int("DB_MAX_OVERFLOW", 10, minimum=0)
DB_POOL_TIMEOUT = env_int("DB_POOL_TIMEOUT", 30, minimum=5)
DB_POOL_RECYCLE = env_int("DB_POOL_RECYCLE", 1800, minimum=60)

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
        has_alembic = await conn.run_sync(lambda c: inspect(c).has_table("alembic_version"))
        has_metal = await conn.run_sync(lambda c: inspect(c).has_table("metal_price_daily"))
    return has_metal and not has_alembic


def _run_alembic_upgrade() -> None:
    """DBをAlembicのheadまで進める。同期APIなので呼び出し側でto_threadに包むこと。

    alembic.command は同期実装しか無い。await せず直接呼ぶと
    イベントループを実行中ずっとブロックし、その間は他のリクエストも
    バックグラウンドジョブも進まなくなる。
    """
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(cfg, "head")


def _run_alembic_stamp(revision: str) -> None:
    """DDLを実行せず、alembic_versionテーブルにだけ指定リビジョンを書き込む。

    旧式（create_all で作られた）DBは既にテーブルが存在するので、
    0001のマイグレーションをそのまま流すとテーブル重複エラーになる。
    実体には触れず「ここまで適用済み」という記録だけ作り、以降の
    差分だけを upgrade で当てる。
    """
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
    """起動時にDBスキーマをheadへ揃える。advisory lockで複数ワーカー間を直列化する。

    ロックを取らずに複数ワーカーが同時にこれを呼ぶと、同じDDLが競合し
    "duplicate key value violates unique constraint
    pg_class_relname_nsp_index" のようなエラーで起動が失敗することを
    本番で確認している（詳細は DB_MIGRATION_ADVISORY_LOCK_KEY の定義
    コメントを参照）。
    """
    async with engine.connect() as conn:
        await conn.execute(
            text("SELECT pg_advisory_lock(:key)"),
            {"key": DB_MIGRATION_ADVISORY_LOCK_KEY},
        )
        try:
            is_legacy = await _detect_legacy_db()

            if is_legacy:
                logger.warning(
                    "旧式DB（create_all 作成）を検出。"
                    "Alembic 初期リビジョン(0001)をスタンプ後、head へアップグレードします。"
                )
                await asyncio.to_thread(_run_alembic_stamp, "0001")
                await asyncio.to_thread(_run_alembic_upgrade)
                logger.info("旧式DBの移行完了。以降のマイグレーションは Alembic で管理されます。")
            else:
                logger.info("Alembic マイグレーションを実行します。")
                await asyncio.to_thread(_run_alembic_upgrade)
                logger.info("マイグレーション完了。")
        finally:
            await conn.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": DB_MIGRATION_ADVISORY_LOCK_KEY},
            )


async def close_db() -> None:
    """シャットダウン時に全コネクションを閉じる。呼び忘れるとプロセス終了時に接続が残る。"""
    await engine.dispose()
