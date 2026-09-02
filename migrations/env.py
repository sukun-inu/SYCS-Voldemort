import asyncio
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# プロジェクトルートを sys.path に追加
sys.path.insert(0, str(Path(__file__).parent.parent))

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from webapp.models import Base  # noqa: E402

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """接続を張らず、実行するはずの SQL をそのまま出力する経路。

    DB が用意できない場所（デプロイ前のレビューなど）で流す SQL を
    確認するために使う。literal_binds を立てているのはパラメータを
    bind せず値をそのまま埋め込むためで、これを外すと生成される SQL に
    プレースホルダしか残らず、確認用として意味を成さなくなる。
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    """同期の Connection を受け取って実マイグレーションを走らせる。

    Alembic のマイグレーション実行部は同期 API しか無いため、非同期の
    Connection をそのまま渡せない。run_sync 経由で同期版の
    Connection に変換してもらってからこの関数に渡す（呼び出し元参照）。
    """
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """本番の DSN（asyncpg）でそのまま接続し、マイグレーションを流す。

    アプリ本体が非同期ドライバで DB に繋いでいるため、alembic の DSN も
    同じものを使う。NullPool にしているのは、マイグレーション実行後に
    プロセスごと終了するこの用途でコネクションプールを保持する意味が
    無く、接続を張ったまま終了して残ると次回起動時に食い合うため。
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """CLI から同期で呼ばれる alembic に、非同期の実行経路を繋ぐ入口。"""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
