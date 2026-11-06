"""Postgres 向けの async セッションを、インメモリ SQLite の同期セッションで代用する。

CI に Postgres は無い。本番の SessionLocal は asyncpg 前提で動かせないので、
同じ SQLAlchemy の式を SQLite で実際に実行し、`async with` / `await` の形だけ
本番に合わせる（tests/test_user_state.py の _FakeAsyncSession と同じ考え方）。

**SQLite は FOR UPDATE SKIP LOCKED を黙って捨てる。** 行ロックに頼る部分は、
ここを通したテストでは確かめられない。そこは Postgres 向けに組み立てた SQL を
直接見るテストで押さえること。
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


class FakeAsyncSession:
    """本物の同期 Session に、await できる薄い皮だけを被せる。"""

    def __init__(self, sync_session: Session):
        self._session = sync_session

    async def __aenter__(self) -> "FakeAsyncSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        self._session.close()
        return False

    async def execute(self, stmt: Any) -> Any:
        return self._session.execute(stmt)

    async def scalar(self, stmt: Any) -> Any:
        return self._session.scalar(stmt)

    async def commit(self) -> None:
        self._session.commit()

    async def rollback(self) -> None:
        self._session.rollback()


def sqlite_engine() -> Engine:
    """テスト1本ぶんの空のデータベース。

    StaticPool と check_same_thread=False にしているのは、TestClient が
    アプリを別スレッドで動かすため。既定のままだと、表を作った接続と
    使う接続が別物になって「表が無い」と言われる。
    """
    return create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)


def use_sqlite_for_dev_signals(testcase: unittest.TestCase) -> Engine:
    """services.dev_signals の置き場を、このテストのあいだだけ SQLite にする。

    表は作らずに渡す。本番と同じく、最初に使ったときに dev_signals 自身が
    作ることまで含めて確かめるため。
    """
    from services import dev_signals

    engine = sqlite_engine()
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    async def create_table() -> None:
        """本番の _create_table と同じく、checkfirst で表を作る。"""
        dev_signals.metadata.create_all(engine, checkfirst=True)

    patchers = [
        patch.object(dev_signals, "_session", lambda: FakeAsyncSession(maker())),
        patch.object(dev_signals, "_create_table", create_table),
        # 「作成済み」の印はモジュールに残る。前のテストの印を持ち越すと、
        # 新しい空のデータベースで表を作らないまま使いに行く。
        patch.object(dev_signals, "_initialized", False),
        patch.object(dev_signals, "_init_lock", None),
    ]
    for patcher in patchers:
        patcher.start()
        testcase.addCleanup(patcher.stop)
    testcase.addCleanup(engine.dispose)
    return engine
