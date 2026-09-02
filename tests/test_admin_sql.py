"""管理画面 SQL コンソール（webapp_admin/api/sql.py）のテスト。

    python -m unittest discover -s tests -t .

いちばん重視しているのは「どのクエリを許して、どれを拒むか」の境界線:
  - 既定（write=False）は Postgres の READ ONLY トランザクションで実行される
    こと（SQL 文字列を見て判定しているわけではない）
  - write=True のときだけ書き込みトランザクションになり、commit されること
  - VACUUM 等の「トランザクション外で流す」逃げ道は write=True かつ
    1文のときにしか働かないこと
  - 接続先サーバはアプリが持つ DSN の一覧からしか選べない（画面から任意の
    ホストへは繋げない）こと
  - 開発者以外・CSRF なしでは一切叩けないこと

実 DB・実ネットワークには一切触れない。asyncpg の Connection/Transaction/
PreparedStatement/Cursor はすべてこのファイル内の最小限のダブルに差し替える。
"""

from __future__ import annotations

import base64
import json
import math
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, time as dt_time, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

# webapp_admin/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# プロジェクトの import より前に一時ディレクトリへ差し替える
# （tests/test_admin_api.py の作法に合わせる）。
os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="admin-sql-test-")
os.environ["ADMIN_FLASK_SECRET_KEY"] = "x" * 64
os.environ["TTS_BASE_URL"] = "http://127.0.0.1:9"
os.environ["DEV_USER_ID"] = "4242"
os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp(prefix="admin-sql-test-cache-")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio  # noqa: E402

import asyncpg  # noqa: E402
import itsdangerous  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import webapp_admin.api.sql as sql  # noqa: E402
from webapp_admin.app import app  # noqa: E402
from webapp_admin.extensions import limiter  # noqa: E402

SECRET = "x" * 64
CSRF = "t" * 64
CSRF_HEADER = {"X-CSRFToken": CSRF}
BASE = "/admin/api/sql"

# _sources() をこの1本に差し替えて使う。host:port/user から
# server_id は "db.internal:5432/appuser" になる（webapp_admin.api.sql._servers 参照）。
FAKE_DSN = "postgresql+asyncpg://appuser:secret@db.internal:5432/appdb"
SERVER_ID = "db.internal:5432/appuser"
DATABASE = "appdb"


def make_client(user_id: str = "4242", csrf: str | None = CSRF) -> TestClient:
    """dev 権限を持つ（あるいは持たない）セッション付き TestClient を作る。

    sql.py のエンドポイントは check_guild を要求しないので、
    tests/test_admin_api.py の make_client と違いギルド関連の情報は含めない。
    """
    session = {"user": {"id": user_id, "username": "tester", "global_name": "Tester", "avatar": None}}
    if csrf is not None:
        session["_csrf_token"] = csrf

    client = TestClient(app)
    signed = itsdangerous.TimestampSigner(SECRET).sign(base64.b64encode(json.dumps(session).encode()))
    client.cookies.set("admin_session", signed.decode())
    return client


def anonymous_client() -> TestClient:
    return TestClient(app)


# ── asyncpg の最小限のダブル ─────────────────────────────────


class _FakeCursor:
    def __init__(self, records: list) -> None:
        self.records = records
        self.fetched_n: int | None = None

    async def fetch(self, n: int, timeout: float | None = None):
        self.fetched_n = n
        return self.records[:n]


class _FakeStatement:
    """conn.prepare() が返す想定のオブジェクト。

    attributes が空でなければ SELECT 系（cursor 経由で行を取る）、
    空なら DDL/DML 系（fetch を1回叩くだけ）として _run_one に扱われる。
    """

    def __init__(self, *, attributes=None, records=None, statusmsg: str = "SELECT 0"):
        self._attributes = attributes or []
        self._records = records or []
        self._statusmsg = statusmsg
        self.last_cursor: _FakeCursor | None = None

    def get_attributes(self):
        return self._attributes

    async def cursor(self, timeout: float | None = None):
        self.last_cursor = _FakeCursor(self._records)
        return self.last_cursor

    async def fetch(self, timeout: float | None = None):
        return None

    def get_statusmsg(self):
        return self._statusmsg


def select_statement(columns: list[tuple[str, str]], rows: list[list], statusmsg="SELECT") -> _FakeStatement:
    attributes = [SimpleNamespace(name=name, type=SimpleNamespace(name=type_name)) for name, type_name in columns]
    return _FakeStatement(attributes=attributes, records=rows, statusmsg=statusmsg)


def command_statement(statusmsg: str) -> _FakeStatement:
    return _FakeStatement(attributes=[], statusmsg=statusmsg)


class _FakeTransaction:
    def __init__(self, readonly: bool) -> None:
        self.readonly = readonly
        self.started = False
        self.committed = False
        self.rolled_back = False

    async def start(self):
        self.started = True

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


class _FakeConnection:
    """asyncpg.Connection の代わり。sql.py が実際に呼ぶメソッドだけを持つ。

    plan: prepare()/execute() が呼ばれるたびに1つずつ消費するリスト。
          BaseException を積んでおけばそこで例外を投げる。
    fetch_queue: list_objects/list_servers/table_ddl のように conn.fetch() を
          複数回呼ぶ経路向けに、呼び出し順で返す行リストを積む。
    """

    def __init__(self, *, plan=None, fetch_queue=None, fetchval=None, server_pid=4242):
        self._plan = list(plan or [])
        self._fetch_queue = list(fetch_queue or [])
        self._fetchval = fetchval
        self._server_pid = server_pid
        self.closed = False
        self.transactions: list[_FakeTransaction] = []
        self.executed: list[str] = []
        self.prepared: list[str] = []
        self.fetch_calls: list[tuple] = []

    def get_server_pid(self):
        return self._server_pid

    def transaction(self, readonly: bool = False):
        tx = _FakeTransaction(readonly)
        self.transactions.append(tx)
        return tx

    async def prepare(self, sql_text: str, timeout: float | None = None):
        self.prepared.append(sql_text)
        item = self._plan.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def execute(self, sql_text: str, timeout: float | None = None):
        self.executed.append(sql_text)
        item = self._plan.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def fetch(self, query: str, *args, timeout: float | None = None):
        self.fetch_calls.append((query, args))
        if self._fetch_queue:
            return self._fetch_queue.pop(0)
        return []

    async def fetchval(self, query: str, *args, timeout: float | None = None):
        self.fetch_calls.append((query, args))
        return self._fetchval

    async def close(self):
        self.closed = True


def _pg_error(message="構文エラー", *, sqlstate="42601", detail=None, hint=None, position=None):
    """asyncpg.PostgresError のダブル。

    実際の asyncpg は Postgres からのエラー応答を受けて .message 等の属性を
    個別に埋める。素の PostgresError(message) だけでは .message 属性が付かず
    str(exc) 頼みになってしまう（しかも str() は DETAIL/HINT まで連結して
    しまうため、_error_payload() が実際に .message を優先する経路を確認
    できない）ので、ここで明示的に埋める。
    """
    exc = asyncpg.PostgresError(message)
    exc.message = message
    exc.sqlstate = sqlstate
    exc.detail = detail
    exc.hint = hint
    exc.position = position
    return exc


# ── 共通の土台 ───────────────────────────────────────────────


class _SqlApiTestBase(unittest.TestCase):
    """接続先を FAKE_DSN 1本に差し替え、_RUNNING とレート制限をテスト間で汚さない。"""

    def setUp(self):
        self.dev = make_client(user_id="4242")
        self.normal = make_client(user_id="1")
        limiter.reset()
        sql._RUNNING.clear()

        self._sources_patcher = patch.object(sql, "_sources", return_value=[("テスト用途", FAKE_DSN)])
        self._sources_patcher.start()
        self.addCleanup(self._sources_patcher.stop)

    def tearDown(self):
        sql._RUNNING.clear()

    def patch_connect(self, conn: "_FakeConnection"):
        """_connect を差し替えて conn を返すようにする。呼び出し引数も記録する。"""
        calls: list[tuple] = []

        async def _fake_connect(server, database, *, timeout_ms=None):
            calls.append((server, database, timeout_ms))
            return conn

        patcher = patch.object(sql, "_connect", _fake_connect)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def query(self, conn: "_FakeConnection", sql_text="SELECT 1", **overrides):
        self.patch_connect(conn)
        body = {"server": SERVER_ID, "database": DATABASE, "sql": sql_text}
        body.update(overrides)
        return self.dev.post(f"{BASE}/query", json=body, headers=CSRF_HEADER)


# ── split_statements: 文の分割 ─────────────────────────────────


class SplitStatementsTests(unittest.TestCase):
    """`;` 区切りが、文字列・識別子・ドル引用・コメントの中では効かないこと。"""

    def test_splits_on_semicolons(self):
        self.assertEqual(sql.split_statements("SELECT 1; SELECT 2"), ["SELECT 1", "SELECT 2"])

    def test_trailing_statement_without_semicolon_is_kept(self):
        self.assertEqual(sql.split_statements("SELECT 1"), ["SELECT 1"])

    def test_semicolon_inside_single_quoted_string_does_not_split(self):
        self.assertEqual(sql.split_statements("SELECT ';'; SELECT 2;"), ["SELECT ';'", "SELECT 2"])

    def test_doubled_quote_is_an_escaped_quote_not_a_terminator(self):
        self.assertEqual(sql.split_statements("SELECT 'it''s'; SELECT 2;"), ["SELECT 'it''s'", "SELECT 2"])

    def test_backslash_does_not_escape_the_closing_quote(self):
        """standard_conforming_strings=on を前提にしているので \\ はただの文字。"""
        script = "SELECT 'a\\'; SELECT 2;"
        self.assertEqual(sql.split_statements(script), ["SELECT 'a\\'", "SELECT 2"])

    def test_semicolon_inside_double_quoted_identifier_does_not_split(self):
        self.assertEqual(sql.split_statements('SELECT "a;b"; SELECT 2'), ['SELECT "a;b"', "SELECT 2"])

    def test_semicolon_inside_dollar_quote_does_not_split(self):
        self.assertEqual(sql.split_statements("SELECT $$a;b$$; SELECT 2"), ["SELECT $$a;b$$", "SELECT 2"])

    def test_semicolon_inside_tagged_dollar_quote_does_not_split(self):
        self.assertEqual(
            sql.split_statements("SELECT $tag$a;b$tag$; SELECT 2"),
            ["SELECT $tag$a;b$tag$", "SELECT 2"],
        )

    def test_semicolon_inside_line_comment_does_not_split(self):
        self.assertEqual(sql.split_statements("-- a;b\nSELECT 1;"), ["-- a;b\nSELECT 1"])

    def test_semicolon_inside_block_comment_does_not_split(self):
        self.assertEqual(sql.split_statements("/* a;b */ SELECT 1;"), ["/* a;b */ SELECT 1"])

    def test_statements_that_are_only_comments_are_dropped(self):
        self.assertEqual(sql.split_statements("-- just a comment\n;"), [])

    def test_empty_or_whitespace_script_yields_no_statements(self):
        self.assertEqual(sql.split_statements(""), [])
        self.assertEqual(sql.split_statements("   ;;; "), [])


# ── _cell / _clip: 値の JSON 化 ─────────────────────────────────


class CellConversionTests(unittest.TestCase):
    """DB の値を JSON にする際、精度落ちやシリアライズ失敗が起きないこと。"""

    def test_primitives_pass_through(self):
        self.assertIsNone(sql._cell(None))
        self.assertIs(sql._cell(True), True)
        self.assertEqual(sql._cell(42), 42)
        self.assertEqual(sql._cell("abc"), "abc")

    def test_nan_and_infinity_become_postgres_style_strings(self):
        """allow_nan=False の JSONResponse へそのまま渡すと 500 になるため文字列化する。"""
        self.assertEqual(sql._cell(float("nan")), "NaN")
        self.assertEqual(sql._cell(float("inf")), "Infinity")
        self.assertEqual(sql._cell(float("-inf")), "-Infinity")
        self.assertTrue(math.isclose(sql._cell(1.5), 1.5))

    def test_decimal_is_stringified_to_avoid_precision_loss(self):
        self.assertEqual(sql._cell(Decimal("1.50")), "1.50")

    def test_datetime_date_time_use_isoformat(self):
        self.assertEqual(sql._cell(datetime(2020, 1, 2, 3, 4, 5)), "2020-01-02T03:04:05")
        self.assertEqual(sql._cell(date(2020, 1, 2)), "2020-01-02")
        self.assertEqual(sql._cell(dt_time(3, 4, 5)), "03:04:05")

    def test_timedelta_and_uuid_are_stringified(self):
        self.assertEqual(sql._cell(timedelta(days=1, seconds=5)), "1 day, 0:00:05")
        u = UUID("12345678-1234-5678-1234-567812345678")
        self.assertEqual(sql._cell(u), str(u))

    def test_bytes_become_hex_with_backslash_x_prefix(self):
        self.assertEqual(sql._cell(b"\x00\x01\xff"), "\\x0001ff")

    def test_large_bytes_are_clipped_with_ellipsis(self):
        big = b"\x00" * (sql.MAX_CELL_CHARS)
        out = sql._cell(big)
        self.assertTrue(out.endswith("…"))

    def test_list_and_dict_are_converted_recursively(self):
        self.assertEqual(sql._cell([1, "a", None]), [1, "a", None])
        self.assertEqual(sql._cell({"k": Decimal("1")}), {"k": "1"})

    def test_long_text_is_clipped(self):
        text = "x" * (sql.MAX_CELL_CHARS + 1000)
        out = sql._cell(text)
        self.assertEqual(len(out), sql.MAX_CELL_CHARS + 1)
        self.assertTrue(out.endswith("…"))

    def test_short_text_is_untouched(self):
        self.assertEqual(sql._cell("short"), "short")

    def test_unknown_type_falls_back_to_clipped_str(self):
        class Weird:
            def __str__(self):
                return "weird-value"

        self.assertEqual(sql._cell(Weird()), "weird-value")


# ── _affected / _clamp ────────────────────────────────────────


class AffectedRowsTests(unittest.TestCase):
    def test_parses_trailing_number(self):
        self.assertEqual(sql._affected("UPDATE 3"), 3)
        self.assertEqual(sql._affected("DELETE 0"), 0)
        self.assertEqual(sql._affected("INSERT 0 5"), 5)

    def test_non_numeric_or_missing_status_is_zero(self):
        self.assertEqual(sql._affected("SELECT"), 0)
        self.assertEqual(sql._affected("VACUUM"), 0)
        self.assertEqual(sql._affected(None), 0)
        self.assertEqual(sql._affected(""), 0)


class ClampTests(unittest.TestCase):
    def test_value_within_range_is_kept(self):
        self.assertEqual(sql._clamp(5, 1, 10, 3), 5)

    def test_value_above_range_is_capped(self):
        self.assertEqual(sql._clamp(999, 1, 10, 3), 10)

    def test_value_below_range_is_raised(self):
        self.assertEqual(sql._clamp(-5, 1, 10, 3), 1)

    def test_non_numeric_value_falls_back(self):
        self.assertEqual(sql._clamp("abc", 1, 10, 3), 3)
        self.assertEqual(sql._clamp(None, 1, 10, 3), 3)


# ── DSN 組み立て：ホスト/資格情報は差し替えられない ─────────────


class DsnTests(unittest.TestCase):
    """画面から渡せるのは database 名だけで、host/user/password は固定であること。"""

    def test_database_is_swapped_but_host_user_password_are_kept(self):
        url = "postgresql+asyncpg://user:pass@host:5432/original"
        self.assertEqual(sql._asyncpg_dsn(url), "postgresql://user:pass@host:5432/original")
        self.assertEqual(
            sql._asyncpg_dsn(url, "other_db"),
            "postgresql://user:pass@host:5432/other_db",
        )

    def test_database_name_is_percent_encoded(self):
        url = "postgresql+asyncpg://user:pass@host:5432/original"
        self.assertIn("my%20db", sql._asyncpg_dsn(url, "my db"))

    def test_arbitrary_database_name_is_not_checked_against_a_whitelist(self):
        """`database` はアプリが把握しているDB名の一覧と突き合わせていない。

        つまり画面から任意のDB名（同じPostgresサーバ上にあれば何でも）を
        指定できてしまう。ホスト/利用者は固定でも、DB名の側には
        ホワイトリストが無いことを明示するための回帰テスト。
        """
        url = "postgresql+asyncpg://user:pass@host:5432/original"
        self.assertEqual(
            sql._asyncpg_dsn(url, "postgres"),
            "postgresql://user:pass@host:5432/postgres",
        )


# ── _servers / _server_or_404：接続先はアプリの一覧からしか選べない ──


class ServersTests(unittest.TestCase):
    def test_same_host_port_user_are_grouped_into_one_server(self):
        with patch.object(
            sql,
            "_sources",
            return_value=[
                ("貴金属価格", "postgresql+asyncpg://u:p@host:5432/metal"),
                ("ユーザー状態監査", "postgresql+asyncpg://u:p@host:5432/userstate"),
            ],
        ):
            servers = sql._servers()
        self.assertEqual(len(servers), 1)
        entry = next(iter(servers.values()))
        self.assertEqual(entry["used_by"], ["貴金属価格", "ユーザー状態監査"])

    def test_different_users_are_separate_servers(self):
        with patch.object(
            sql,
            "_sources",
            return_value=[
                ("A", "postgresql+asyncpg://alice:p@host:5432/a"),
                ("B", "postgresql+asyncpg://bob:p@host:5432/b"),
            ],
        ):
            servers = sql._servers()
        self.assertEqual(len(servers), 2)

    def test_unknown_server_id_is_404(self):
        with patch.object(sql, "_sources", return_value=[("A", FAKE_DSN)]):
            with self.assertRaises(Exception) as ctx:
                sql._server_or_404("host-that-does-not-exist:5432/nobody")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_known_server_id_resolves(self):
        with patch.object(sql, "_sources", return_value=[("A", FAKE_DSN)]):
            server = sql._server_or_404(SERVER_ID)
        self.assertEqual(server["host"], "db.internal")
        self.assertEqual(server["user"], "appuser")


# ── _NON_TRANSACTIONAL：トランザクション外へ逃がす文の境界 ─────────


class NonTransactionalPatternTests(unittest.TestCase):
    """VACUUM 等、書き込みモード・単文のときだけトランザクションを張らない対象の一覧。"""

    def test_matches_administrative_statements(self):
        for stmt in [
            "VACUUM",
            "  vacuum ANALYZE t",
            "CREATE DATABASE foo",
            "DROP DATABASE foo",
            "CREATE TABLESPACE ts LOCATION '/x'",
            "DROP TABLESPACE ts",
            "ALTER SYSTEM SET work_mem = '64MB'",
            "CREATE INDEX CONCURRENTLY idx ON t(a)",
            "CREATE UNIQUE INDEX CONCURRENTLY idx ON t(a)",
            "DROP INDEX CONCURRENTLY idx",
            "REINDEX TABLE CONCURRENTLY t",
        ]:
            with self.subTest(stmt=stmt):
                self.assertTrue(sql._NON_TRANSACTIONAL.match(stmt))

    def test_does_not_match_ordinary_statements(self):
        for stmt in [
            "SELECT 1",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "DROP TABLE t",
            "CREATE TABLE t(a int)",
            "CREATE INDEX idx ON t(a)",  # CONCURRENTLY なし
            "REINDEX TABLE t",  # CONCURRENTLY なし
            "VACUUMX",  # 別語の一部
        ]:
            with self.subTest(stmt=stmt):
                self.assertFalse(sql._NON_TRANSACTIONAL.match(stmt))


# ── _error_payload / _quote_ident / _remember_running ───────────


class ErrorPayloadTests(unittest.TestCase):
    def test_all_fields_are_extracted(self):
        exc = _pg_error("構文エラー", sqlstate="42601", detail="詳細", hint="ヒント", position="12")
        payload = sql._error_payload(exc)
        self.assertEqual(
            payload,
            {"message": "構文エラー", "sqlstate": "42601", "detail": "詳細", "hint": "ヒント", "position": 12},
        )

    def test_missing_position_is_none(self):
        exc = _pg_error()
        self.assertIsNone(sql._error_payload(exc)["position"])


class QuoteIdentTests(unittest.TestCase):
    def test_wraps_in_double_quotes(self):
        self.assertEqual(sql._quote_ident("users"), '"users"')

    def test_embedded_quote_is_doubled(self):
        self.assertEqual(sql._quote_ident('a"b'), '"a""b"')


class RunningTokenTests(unittest.TestCase):
    """実行中クエリの記録（cancel 用）。"""

    def setUp(self):
        sql._RUNNING.clear()

    def tearDown(self):
        sql._RUNNING.clear()

    def test_empty_token_is_ignored(self):
        sql._remember_running("", "server", "db", 1)
        self.assertEqual(sql._RUNNING, {})

    def test_registers_token(self):
        sql._remember_running("tok", "server", "db", 123)
        self.assertEqual(sql._RUNNING["tok"], ("server", "db", 123))

    def test_oldest_entry_is_evicted_at_capacity(self):
        for i in range(sql.MAX_RUNNING):
            sql._remember_running(f"tok{i}", "server", "db", i)
        self.assertEqual(len(sql._RUNNING), sql.MAX_RUNNING)

        sql._remember_running("tok-new", "server", "db", 999)

        self.assertEqual(len(sql._RUNNING), sql.MAX_RUNNING)
        self.assertNotIn("tok0", sql._RUNNING)
        self.assertIn("tok-new", sql._RUNNING)


# ── _connect: 例外の握りつぶし方 ─────────────────────────────────


class ConnectExceptionMappingTests(unittest.TestCase):
    """接続失敗が 500 ではなく 502 として画面に伝わること。"""

    def _server(self):
        return {"url": FAKE_DSN, "default_database": DATABASE}

    def test_postgres_error_becomes_502(self):
        async def _boom(*a, **k):
            raise asyncpg.PostgresError("接続拒否")

        with patch.object(sql.asyncpg, "connect", _boom):
            with self.assertRaises(Exception) as ctx:
                asyncio.run(sql._connect(self._server(), None))
        self.assertEqual(ctx.exception.status_code, 502)

    def test_os_error_becomes_502(self):
        async def _boom(*a, **k):
            raise OSError("network unreachable")

        with patch.object(sql.asyncpg, "connect", _boom):
            with self.assertRaises(Exception) as ctx:
                asyncio.run(sql._connect(self._server(), None))
        self.assertEqual(ctx.exception.status_code, 502)

    def test_timeout_becomes_502(self):
        async def _boom(*a, **k):
            raise asyncio.TimeoutError()

        with patch.object(sql.asyncpg, "connect", _boom):
            with self.assertRaises(Exception) as ctx:
                asyncio.run(sql._connect(self._server(), None))
        self.assertEqual(ctx.exception.status_code, 502)


# ── 認可: 開発者専用 & CSRF ──────────────────────────────────────


class AuthGuardTests(_SqlApiTestBase):
    """dev 権限が無い/CSRF が無いと、どのエンドポイントも通らないこと。"""

    def test_anonymous_get_is_redirected_to_login(self):
        response = anonymous_client().get(f"{BASE}/servers", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/admin/login", response.headers["location"])

    def test_non_developer_gets_403_on_every_endpoint(self):
        self.assertEqual(self.normal.get(f"{BASE}/servers").status_code, 403)
        self.assertEqual(
            self.normal.get(f"{BASE}/objects", params={"server": SERVER_ID, "database": DATABASE}).status_code,
            403,
        )
        self.assertEqual(
            self.normal.post(f"{BASE}/query", json={"sql": "SELECT 1"}, headers=CSRF_HEADER).status_code,
            403,
        )
        self.assertEqual(self.normal.post(f"{BASE}/cancel", json={}, headers=CSRF_HEADER).status_code, 403)

    def test_when_dev_user_id_is_unset_panel_does_not_exist(self):
        """DEV_USER_ID 未設定は「開発者パネルが存在しない」扱い（403 ではなく404）。"""
        with patch("webapp_admin.api.dev.dev_user_id", return_value=""):
            response = self.dev.get(f"{BASE}/servers")
        self.assertEqual(response.status_code, 404)

    def test_post_without_csrf_header_is_403(self):
        response = self.dev.post(f"{BASE}/query", json={"sql": "SELECT 1"})
        self.assertEqual(response.status_code, 403)

    def test_post_with_wrong_csrf_token_is_403(self):
        response = self.dev.post(f"{BASE}/query", json={"sql": "SELECT 1"}, headers={"X-CSRFToken": "wrong" * 20})
        self.assertEqual(response.status_code, 403)


# ── /query: 入力の検証 ────────────────────────────────────────


class QueryValidationTests(_SqlApiTestBase):
    def test_empty_sql_is_400(self):
        response = self.dev.post(
            f"{BASE}/query", json={"server": SERVER_ID, "database": DATABASE, "sql": "   "}, headers=CSRF_HEADER
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_sql_key_is_400(self):
        response = self.dev.post(f"{BASE}/query", json={"server": SERVER_ID, "database": DATABASE}, headers=CSRF_HEADER)
        self.assertEqual(response.status_code, 400)

    def test_non_string_sql_is_400(self):
        response = self.dev.post(
            f"{BASE}/query", json={"server": SERVER_ID, "database": DATABASE, "sql": 123}, headers=CSRF_HEADER
        )
        self.assertEqual(response.status_code, 400)

    def test_sql_over_max_chars_is_400(self):
        too_long = "SELECT 1; -- " + "x" * sql.MAX_SQL_CHARS
        response = self.dev.post(
            f"{BASE}/query", json={"server": SERVER_ID, "database": DATABASE, "sql": too_long}, headers=CSRF_HEADER
        )
        self.assertEqual(response.status_code, 400)

    def test_only_comments_yields_no_executable_statement_400(self):
        response = self.dev.post(
            f"{BASE}/query",
            json={"server": SERVER_ID, "database": DATABASE, "sql": "-- just a comment"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 400)

    def test_too_many_statements_is_400(self):
        script = "; ".join(["SELECT 1"] * (sql.MAX_STATEMENTS + 1))
        response = self.dev.post(
            f"{BASE}/query", json={"server": SERVER_ID, "database": DATABASE, "sql": script}, headers=CSRF_HEADER
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_server_is_404(self):
        response = self.dev.post(
            f"{BASE}/query",
            json={"server": "nope:1/nobody", "database": DATABASE, "sql": "SELECT 1"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 404)

    def test_malformed_json_body_is_400(self):
        response = self.dev.post(
            f"{BASE}/query",
            content=b"{not json",
            headers={**CSRF_HEADER, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)

    def test_non_object_json_body_is_400(self):
        response = self.dev.post(
            f"{BASE}/query",
            content=b"[1, 2, 3]",
            headers={**CSRF_HEADER, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)


# ── /query: 読み取り専用トランザクションが既定であること ────────────


class QueryReadonlyTests(_SqlApiTestBase):
    """write を送らない・false のときは Postgres の READ ONLY で必ず実行されること。"""

    def test_default_write_is_false_and_transaction_is_readonly(self):
        conn = _FakeConnection(plan=[select_statement([("n", "int4")], [[1]])])
        response = self.query(conn, "SELECT 1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(conn.transactions), 1)
        self.assertTrue(conn.transactions[0].readonly)

    def test_readonly_transaction_is_always_rolled_back_even_on_success(self):
        """write=false のときは成功しても commit しない（コンソールから書き込ませない）。"""
        conn = _FakeConnection(plan=[select_statement([("n", "int4")], [[1]])])
        response = self.query(conn, "SELECT 1", write=False)
        payload = response.json()
        self.assertFalse(payload["committed"])
        self.assertTrue(conn.transactions[0].rolled_back)
        self.assertFalse(conn.transactions[0].committed)

    def test_explicit_write_false_is_readonly_even_for_write_looking_sql(self):
        """UPDATE文字列でも write=false ならそのまま READ ONLY トランザクションへ送るだけ

        （文字列を見て弾いているのではなく、Postgres 自身の READ ONLY 制約に
        任せている、という設計を確認する）。
        """
        conn = _FakeConnection(plan=[command_statement("UPDATE 1")])
        response = self.query(conn, "UPDATE t SET a = 1", write=False)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(conn.transactions[0].readonly)
        self.assertFalse(conn.transactions[0].committed)


class QueryWriteTests(_SqlApiTestBase):
    def test_write_true_uses_write_transaction_and_commits(self):
        conn = _FakeConnection(plan=[command_statement("UPDATE 1")])
        response = self.query(conn, "UPDATE t SET a = 1", write=True)
        payload = response.json()
        self.assertTrue(payload["committed"])
        self.assertFalse(conn.transactions[0].readonly)
        self.assertTrue(conn.transactions[0].committed)
        self.assertFalse(conn.transactions[0].rolled_back)

    def test_write_true_but_query_errors_rolls_back_and_does_not_commit(self):
        conn = _FakeConnection(plan=[_pg_error("構文エラー")])
        response = self.query(conn, "UPDATE t SET bad(", write=True)
        payload = response.json()
        self.assertFalse(payload["committed"])
        self.assertTrue(conn.transactions[0].rolled_back)
        self.assertFalse(conn.transactions[0].committed)


class QueryNonTransactionalEscapeTests(_SqlApiTestBase):
    """VACUUM 等の「トランザクションを張らない」逃げ道の境界。"""

    def test_write_true_single_vacuum_statement_bypasses_transaction(self):
        conn = _FakeConnection(plan=["VACUUM"])
        response = self.query(conn, "VACUUM", write=True)
        payload = response.json()
        self.assertTrue(payload["outsideTransaction"])
        self.assertEqual(conn.executed, ["VACUUM"])
        self.assertEqual(conn.transactions, [])  # トランザクションを一切張っていない

    def test_write_false_vacuum_stays_inside_readonly_transaction(self):
        """write=false のときは VACUUM でも逃げ道を使わず、普通に readonly tx を張る。"""
        conn = _FakeConnection(plan=[command_statement("VACUUM")])
        response = self.query(conn, "VACUUM", write=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(conn.executed, [])
        self.assertEqual(len(conn.transactions), 1)
        self.assertTrue(conn.transactions[0].readonly)

    def test_multiple_statements_do_not_bypass_even_with_write_true(self):
        """1文のときだけの逃げ道であること（複数文なら通常のトランザクション経路）。"""
        conn = _FakeConnection(plan=[command_statement("VACUUM"), command_statement("VACUUM")])
        response = self.query(conn, "VACUUM; VACUUM", write=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(conn.executed, [])
        self.assertEqual(len(conn.transactions), 1)
        self.assertFalse(conn.transactions[0].readonly)


class QueryErrorAndTimeoutTests(_SqlApiTestBase):
    def test_error_mid_batch_keeps_prior_results_and_reports_index(self):
        conn = _FakeConnection(plan=[command_statement("INSERT 0 1"), _pg_error("重複キー", sqlstate="23505")])
        response = self.query(conn, "INSERT INTO t VALUES (1); INSERT INTO t VALUES (1);", write=True)
        payload = response.json()
        self.assertEqual(len(payload["results"]), 1)
        self.assertEqual(payload["error"]["statementIndex"], 1)
        self.assertEqual(payload["error"]["sqlstate"], "23505")
        self.assertFalse(payload["committed"])

    def test_timeout_is_reported_and_transaction_rolled_back(self):
        conn = _FakeConnection(plan=[asyncio.TimeoutError()])
        response = self.query(conn, "SELECT pg_sleep(999)", timeout=1)
        payload = response.json()
        self.assertIn("打ち切りました", payload["error"]["message"])
        self.assertEqual(payload["error"]["sqlstate"], "57014")
        self.assertTrue(conn.transactions[0].rolled_back)

    def test_connection_is_always_closed_after_query(self):
        conn = _FakeConnection(plan=[select_statement([("n", "int4")], [[1]])])
        self.query(conn, "SELECT 1")
        self.assertTrue(conn.closed)

    def test_running_token_is_cleared_after_query_completes(self):
        conn = _FakeConnection(plan=[select_statement([("n", "int4")], [[1]])])
        self.query(conn, "SELECT 1", token="my-token")
        self.assertNotIn("my-token", sql._RUNNING)


class QueryAuditAndCancellationTests(_SqlApiTestBase):
    """実行の記録と、途中で止められることを固定する。

    118行ある run_query を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
    この関数は読み取り専用・コミット・打ち切り・行数上限まで手厚く見られて
    いるが、次の3つは崩しても全部通る。

      - 誰が何を実行したかをログに残すこと
      - 実行**前**に token を登録すること（走っている間に止められる）
      - 非トランザクション経路（VACUUM 等）でも後始末をすること

    1つ目は開発者専用の生 SQL 実行なので、記録が消えると**誰が何をしたかを
    後から辿る手立てが無くなる。** 2つ目は登録が実行より後ろへずれると、
    止めたい長いクエリの最中だけ token が無く、**キャンセルが効くのは
    終わったあとだけ**になる。どちらも普通に使うぶんには何も起きない。
    """

    def test_the_execution_is_written_to_the_log_with_who_and_what(self):
        """誰が・どのDBへ・どのモードで・何を投げたかを残すこと。"""
        conn = _FakeConnection(plan=[_FakeStatement()])
        with self.assertLogs(sql.logger, level="WARNING") as captured:
            response = self.query(conn, "SELECT 42", write=True)

        self.assertEqual(response.status_code, 200)
        logged = "\n".join(captured.output)
        self.assertIn("SQL実行", logged)
        self.assertIn("4242", logged)  # 実行した開発者
        self.assertIn(DATABASE, logged)
        self.assertIn("write", logged)
        self.assertIn("SELECT 42", logged)

    def test_the_cancel_token_is_registered_while_the_query_runs(self):
        """token の登録は、文を投げる**前**に済ませること。

        登録が後ろへずれると、止めたい長いクエリの最中だけ token が無く、
        **キャンセルが効くのは終わったあとだけ**になる。終わってしまえば
        止める必要も無い。
        """
        seen: list[dict] = []
        conn = _FakeConnection(plan=[_FakeStatement()])

        real_run_one = sql._run_one

        async def spy(connection, statement, limit, timeout):
            """1文の実行。走っている最中の _RUNNING を控える。"""
            seen.append(dict(sql._RUNNING))
            return await real_run_one(connection, statement, limit, timeout)

        with patch.object(sql, "_run_one", spy):
            self.query(conn, "SELECT 1", token="tok-1")

        self.assertEqual(len(seen), 1)
        self.assertIn("tok-1", seen[0], "実行中に token が登録されていない")
        self.assertEqual(seen[0]["tok-1"][2], conn.get_server_pid())
        # 終わったら消えていること（既存テストと同じ後始末）
        self.assertNotIn("tok-1", sql._RUNNING)

    def test_the_non_transactional_path_also_cleans_up(self):
        """VACUUM 経路でも、token を消して接続を閉じること。

        こちらはトランザクションを張らない別の道なので、後始末を書き忘れて
        も**普通の SELECT のテストは全部通る。** 残ると接続が漏れ、token が
        居座って別のクエリのキャンセルが誤爆する。
        """
        conn = _FakeConnection(plan=["VACUUM"])
        response = self.query(conn, "VACUUM some_table", write=True, token="tok-2")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["outsideTransaction"])
        self.assertTrue(conn.closed, "接続が閉じられていない")
        self.assertNotIn("tok-2", sql._RUNNING)

    def test_the_statement_is_executed_exactly_as_written(self):
        """コメントの除去は判定用だけで、実行は原文のままにすること。

        先頭のコメントは「トランザクション内で実行できない文か」の判定の
        邪魔になるので落とすが、**落とした文字列をそのまま実行してはいけない。**
        VACUUM は通ってしまうため、動くかどうかでは気づけない。
        """
        conn = _FakeConnection(plan=["VACUUM"])
        script = "-- 定期整理\nVACUUM some_table"
        self.query(conn, script, write=True)

        self.assertEqual(conn.executed, [script])


class QueryRowLimitTests(_SqlApiTestBase):
    def test_rows_beyond_limit_are_truncated(self):
        statement = select_statement([("n", "int4")], [[1], [2], [3]])
        conn = _FakeConnection(plan=[statement])
        response = self.query(conn, "SELECT n FROM t", limit=2)
        payload = response.json()
        result = payload["results"][0]
        self.assertEqual(result["rowCount"], 2)
        self.assertTrue(result["truncated"])
        self.assertEqual(statement.last_cursor.fetched_n, 3)  # limit+1 を取りに行っている

    def test_limit_above_max_is_clamped(self):
        statement = select_statement([("n", "int4")], [[1]])
        conn = _FakeConnection(plan=[statement])
        self.query(conn, "SELECT n FROM t", limit=999_999)
        self.assertEqual(statement.last_cursor.fetched_n, sql.MAX_ROWS + 1)

    def test_invalid_limit_falls_back_to_default(self):
        statement = select_statement([("n", "int4")], [[1]])
        conn = _FakeConnection(plan=[statement])
        self.query(conn, "SELECT n FROM t", limit="abc")
        self.assertEqual(statement.last_cursor.fetched_n, sql.DEFAULT_ROWS + 1)

    def test_rows_within_limit_are_not_truncated(self):
        statement = select_statement([("n", "int4")], [[1], [2]])
        conn = _FakeConnection(plan=[statement])
        response = self.query(conn, "SELECT n FROM t", limit=5)
        result = response.json()["results"][0]
        self.assertFalse(result["truncated"])
        self.assertEqual(result["rowCount"], 2)


class QueryJsonRenderingTests(_SqlApiTestBase):
    def test_nan_cell_does_not_crash_the_response(self):
        """float('nan') を含む結果でも 500 にならず、文字列 'NaN' として返る。

        以前は Decimal と同じ扱いをせずに素通ししていたため、Starlette の
        JSONResponse(allow_nan=False) が ValueError を投げて 500 になっていた。
        """
        statement = select_statement([("x", "float8")], [[float("nan")]])
        conn = _FakeConnection(plan=[statement])
        response = self.query(conn, "SELECT 'NaN'::float8")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"][0]["rows"], [["NaN"]])

    def test_big_snowflake_like_integers_are_stringified(self):
        big = 2**60
        statement = select_statement([("id", "int8")], [[big]])
        conn = _FakeConnection(plan=[statement])
        response = self.query(conn, "SELECT id FROM t")
        self.assertEqual(response.json()["results"][0]["rows"], [[str(big)]])


# ── /servers ────────────────────────────────────────────────────


class ServersEndpointTests(_SqlApiTestBase):
    def test_lists_databases_and_version_on_success(self):
        conn = _FakeConnection(
            fetch_queue=[[{"name": "appdb", "bytes": 100, "owner": "appuser"}]],
            fetchval="PostgreSQL 16.0",
        )
        self.patch_connect(conn)
        response = self.dev.get(f"{BASE}/servers")
        payload = response.json()
        self.assertEqual(len(payload["servers"]), 1)
        entry = payload["servers"][0]
        self.assertIsNone(entry["error"])
        self.assertEqual(entry["databases"], [{"name": "appdb", "bytes": 100, "owner": "appuser"}])
        self.assertEqual(entry["version"], "PostgreSQL 16.0")
        self.assertTrue(conn.closed)

    def test_connect_failure_is_captured_per_server_not_raised(self):
        async def _fail_connect(server, database, *, timeout_ms=None):
            raise sql.HTTPException(status_code=502, detail="接続できませんでした")

        patcher = patch.object(sql, "_connect", _fail_connect)
        patcher.start()
        self.addCleanup(patcher.stop)

        response = self.dev.get(f"{BASE}/servers")
        self.assertEqual(response.status_code, 200)
        entry = response.json()["servers"][0]
        self.assertIsNotNone(entry["error"])
        self.assertEqual(entry["databases"], [])


# ── /objects, /ddl ────────────────────────────────────────────


class ObjectsEndpointTests(_SqlApiTestBase):
    def test_builds_schema_table_column_tree(self):
        conn = _FakeConnection(
            fetch_queue=[
                [{"schema": "public", "name": "users", "kind": "r", "approx_rows": 10, "bytes": 500, "comment": None}],
                [
                    {
                        "schema": "public",
                        "table": "users",
                        "name": "id",
                        "type": "integer",
                        "not_null": True,
                        "is_pk": True,
                        "default_value": None,
                    }
                ],
            ]
        )
        self.patch_connect(conn)
        response = self.dev.get(f"{BASE}/objects", params={"server": SERVER_ID, "database": DATABASE})
        payload = response.json()
        self.assertEqual(payload["schemas"][0]["name"], "public")
        table = payload["schemas"][0]["tables"][0]
        self.assertEqual(table["name"], "users")
        self.assertEqual(table["columns"][0]["name"], "id")
        self.assertTrue(table["columns"][0]["pk"])


class DdlEndpointTests(_SqlApiTestBase):
    def test_unknown_table_is_404(self):
        conn = _FakeConnection(fetch_queue=[[]])
        self.patch_connect(conn)
        response = self.dev.get(
            f"{BASE}/ddl", params={"server": SERVER_ID, "database": DATABASE, "schema": "public", "table": "nope"}
        )
        self.assertEqual(response.status_code, 404)

    def test_ddl_includes_columns_and_constraints(self):
        conn = _FakeConnection(
            fetch_queue=[
                [{"name": "id", "type": "integer", "not_null": True, "default_value": None}],
                [{"name": "users_pkey", "definition": "PRIMARY KEY (id)"}],
                [{"name": "users_pkey", "definition": "CREATE UNIQUE INDEX users_pkey ON users(id)"}],
            ]
        )
        self.patch_connect(conn)
        response = self.dev.get(
            f"{BASE}/ddl", params={"server": SERVER_ID, "database": DATABASE, "schema": "public", "table": "users"}
        )
        ddl = response.json()["ddl"]
        self.assertIn('CREATE TABLE "public"."users"', ddl)
        self.assertIn('"id" integer NOT NULL', ddl)
        self.assertIn("CONSTRAINT", ddl)
        # 主キー由来の索引は制約側にすでに出ているので重複させない
        self.assertNotIn("CREATE UNIQUE INDEX users_pkey", ddl)


# ── /cancel ─────────────────────────────────────────────────────


class CancelEndpointTests(_SqlApiTestBase):
    def test_unknown_token_reports_not_running(self):
        response = self.dev.post(f"{BASE}/cancel", json={"token": "nope"}, headers=CSRF_HEADER)
        payload = response.json()
        self.assertFalse(payload["cancelled"])

    def test_known_token_calls_pg_cancel_backend_with_the_right_pid(self):
        sql._RUNNING["tok"] = (SERVER_ID, DATABASE, 777)
        conn = _FakeConnection(fetchval=True)
        self.patch_connect(conn)

        response = self.dev.post(f"{BASE}/cancel", json={"token": "tok"}, headers=CSRF_HEADER)
        payload = response.json()
        self.assertTrue(payload["cancelled"])
        self.assertEqual(conn.fetch_calls[0][1], (777,))


if __name__ == "__main__":
    unittest.main()
