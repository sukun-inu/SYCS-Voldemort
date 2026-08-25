"""SQL エディタの API（開発者専用）。

pgAdmin を別に立てなくても、管理画面のデスクトップから Postgres を
見て触れるようにするためのもの。

接続先はアプリ自身が持っている DSN だけを使う（画面からホストや資格情報を
指定することはできない）。切り替えられるのは「同じサーバ上のデータベース名」
だけで、これは DSN のデータベース部分の差し替えとして扱う。

安全側の既定:
  - 読み取り専用トランザクション（Postgres 側で READ ONLY を宣言する。
    SQL の文字列判定ではないので、抜け道が無い）
  - statement_timeout をセッションに設定する
  - 行はサーバ側カーソルで上限まで（+1行）しか取り出さない
  - 接続はリクエストごとに開いて閉じる。アプリ本体のコネクションプールとは
    別なので、重いクエリを投げても Bot や管理画面の動作を止めない
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from datetime import date, datetime, time as dt_time, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from webapp_admin.api.jsonsafe import SafeJSONResponse as JSONResponse

from webapp_admin.api.dev import check_dev
from webapp_admin.extensions import limiter
from webapp_admin.security import check_csrf

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_SQL_CHARS = 100_000
MAX_STATEMENTS = 50
MAX_ROWS = 5_000
DEFAULT_ROWS = 500
MAX_TIMEOUT_SECONDS = 120
DEFAULT_TIMEOUT_SECONDS = 15
CONNECT_TIMEOUT_SECONDS = 8
MAX_CELL_CHARS = 4_000  # 1セルの表示上限。巨大な text/bytea で画面を潰さない
SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast")

# 実行中のクエリ（キャンセル用）。token -> (server_id, database, backend pid)
_RUNNING: dict[str, tuple[str, str, int]] = {}
MAX_RUNNING = 32


# ── 接続先 ───────────────────────────────────────────────────

def _sources() -> list[tuple[str, str]]:
    """アプリが持っている DSN。(用途のラベル, DSN)

    engine を作らずに済むよう、モジュールの import はここで遅延させる。
    """
    from services import user_state_db
    from webapp import db as metal_db

    return [
        ("貴金属価格", metal_db.DATABASE_URL),
        ("ユーザー状態監査", user_state_db.DATABASE_URL),
    ]


def _asyncpg_dsn(url: str, database: str | None = None) -> str:
    """SQLAlchemy 形式の URL を asyncpg が読める DSN にする。

    database を渡すとデータベース名だけ差し替える。ホスト・利用者・パスワードは
    差し替えられない（画面からの入力で接続先を変えられないようにするため）。
    """
    parts = urlsplit(url)
    scheme = parts.scheme.split("+", 1)[0] or "postgresql"
    path = parts.path if database is None else "/" + quote(database, safe="")
    return urlunsplit((scheme, parts.netloc, path, "", ""))


def _servers() -> dict[str, dict[str, Any]]:
    """接続先サーバの一覧。ホスト・ポート・利用者が同じものは1つにまとめる。"""
    servers: dict[str, dict[str, Any]] = {}
    for label, url in _sources():
        parts = urlsplit(url)
        host = parts.hostname or "localhost"
        port = parts.port or 5432
        user = parts.username or ""
        server_id = f"{host}:{port}/{user}"
        entry = servers.get(server_id)
        if entry is None:
            servers[server_id] = {
                "id": server_id,
                "label": f"{user}@{host}:{port}",
                "host": host,
                "port": port,
                "user": user,
                "url": url,
                "default_database": (parts.path or "/").lstrip("/") or "postgres",
                "used_by": [label],
            }
        else:
            entry["used_by"].append(label)
    return servers


def _server_or_404(server_id: str) -> dict[str, Any]:
    server = _servers().get(server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="その接続先は登録されていません。")
    return server


async def _connect(server: dict[str, Any], database: str | None, *, timeout_ms: int | None = None):
    """1回のリクエストのための接続。プールは使わない。"""
    settings = {"application_name": "sycs-admin-sql"}
    if timeout_ms:
        settings["statement_timeout"] = str(timeout_ms)
    dsn = _asyncpg_dsn(server["url"], database or server["default_database"])
    try:
        return await asyncpg.connect(dsn, timeout=CONNECT_TIMEOUT_SECONDS, server_settings=settings)
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=502, detail=f"接続できませんでした（{exc}）")
    except (OSError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=502, detail=f"接続できませんでした（{exc or type(exc).__name__}）")


# ── 値の変換 ─────────────────────────────────────────────────

def _cell(value: Any) -> Any:
    """1セルを JSON にできる形にする。数値は精度を落とさないよう文字列で返す。"""
    if value is None or isinstance(value, (bool, int, str)):
        return _clip(value) if isinstance(value, str) else value
    if isinstance(value, float):
        # Postgres の float8/float4 は 'NaN' / 'Infinity' / '-Infinity' を取れるが、
        # Starlette の JSONResponse は allow_nan=False で dumps するため、素通しすると
        # ValueError で 500 になり結果が一切表示されない。Decimal と同じく文字列で返す。
        # 表記は psql と揃える（Python の 'nan' / 'inf' ではなく Postgres の綴り）。
        if math.isfinite(value):
            return value
        if math.isnan(value):
            return "NaN"
        return "Infinity" if value > 0 else "-Infinity"
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        head = raw[: MAX_CELL_CHARS // 2].hex()
        return f"\\x{head}" + ("…" if len(raw) * 2 > MAX_CELL_CHARS else "")
    if isinstance(value, (list, tuple)):
        return [_cell(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _cell(v) for k, v in value.items()}
    return _clip(str(value))


def _clip(text: str) -> str:
    return text if len(text) <= MAX_CELL_CHARS else text[:MAX_CELL_CHARS] + "…"


# ── SQL の分割 ───────────────────────────────────────────────

_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)


def split_statements(script: str) -> list[str]:
    """`;` で文に切り分ける。

    文字列・引用付き識別子・ドル引用（$$ … $$）・コメントの中の `;` では切らない。
    standard_conforming_strings=on を前提にするので、'' の中の \\ は普通の文字。
    """
    statements: list[str] = []
    buf: list[str] = []
    i, n = 0, len(script)

    while i < n:
        ch = script[i]

        if script.startswith("--", i):
            end = script.find("\n", i)
            end = n if end == -1 else end + 1
            buf.append(script[i:end])
            i = end
            continue

        if script.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if script.startswith("/*", j):
                    depth += 1
                    j += 2
                elif script.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            buf.append(script[i:j])
            i = j
            continue

        if ch in ("'", '"'):
            j = i + 1
            while j < n:
                if script[j] == ch:
                    if j + 1 < n and script[j + 1] == ch:  # '' / "" は中身のエスケープ
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            buf.append(script[i:j])
            i = j
            continue

        if ch == "$":
            tag = _DOLLAR_TAG.match(script, i)
            if tag:
                end = script.find(tag.group(0), tag.end())
                j = n if end == -1 else end + len(tag.group(0))
                buf.append(script[i:j])
                i = j
                continue

        if ch == ";":
            statements.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    statements.append("".join(buf))
    return [s.strip() for s in statements if _COMMENTS.sub("", s).strip()]


# ── 実行 ─────────────────────────────────────────────────────

def _error_payload(exc: asyncpg.PostgresError) -> dict[str, Any]:
    """Postgres のエラーを、画面でそのまま出せる形にする。"""
    return {
        "message": str(getattr(exc, "message", None) or exc),
        "sqlstate": getattr(exc, "sqlstate", None),
        "detail": getattr(exc, "detail", None),
        "hint": getattr(exc, "hint", None),
        # position は「その文の先頭からの1始まりの文字位置」
        "position": int(exc.position) if getattr(exc, "position", None) else None,
    }


async def _run_one(conn, sql: str, limit: int, timeout: float) -> dict[str, Any]:
    """1文を実行して、結果（列と行、または状態メッセージ）を返す。"""
    started = time.perf_counter()
    statement = await conn.prepare(sql, timeout=timeout)
    attributes = statement.get_attributes()

    if attributes:
        cursor = await statement.cursor(timeout=timeout)
        records = await cursor.fetch(limit + 1, timeout=timeout)
        truncated = len(records) > limit
        records = records[:limit]
        columns = [{"name": a.name, "type": a.type.name} for a in attributes]
        rows = [[_cell(value) for value in record] for record in records]
        elapsed = (time.perf_counter() - started) * 1000
        return {
            "columns": columns,
            "rows": rows,
            "rowCount": len(rows),
            "truncated": truncated,
            "status": statement.get_statusmsg() or "SELECT",
            "elapsedMs": round(elapsed, 1),
            "sql": sql,
        }

    await statement.fetch(timeout=timeout)
    elapsed = (time.perf_counter() - started) * 1000
    return {
        "columns": [],
        "rows": [],
        "rowCount": _affected(statement.get_statusmsg()),
        "truncated": False,
        "status": statement.get_statusmsg() or "OK",
        "elapsedMs": round(elapsed, 1),
        "sql": sql,
    }


def _timeout_error(timeout: int, index: int) -> dict[str, Any]:
    return {
        "message": f"{timeout} 秒で打ち切りました。",
        "sqlstate": "57014",
        "detail": None,
        "hint": "上限を延ばすか、条件を絞ってください。",
        "position": None,
        "statementIndex": index,
    }


def _affected(status: str | None) -> int:
    """"UPDATE 3" のような状態メッセージから件数を取り出す。"""
    if not status:
        return 0
    tail = status.rsplit(" ", 1)[-1]
    return int(tail) if tail.isdigit() else 0


# トランザクションの中では実行できない文。これらだけは（書き込みモードで1文のとき）
# トランザクションを張らずにそのまま流す。pgAdmin の自動コミットに相当する逃げ道。
_NON_TRANSACTIONAL = re.compile(
    r"""^\s*(
        VACUUM\b
      | CREATE\s+DATABASE\b | DROP\s+DATABASE\b
      | CREATE\s+TABLESPACE\b | DROP\s+TABLESPACE\b
      | ALTER\s+SYSTEM\b
      | (CREATE|DROP)\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY\b
      | REINDEX\s+.*\bCONCURRENTLY\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def _remember_running(token: str, server_id: str, database: str, pid: int) -> None:
    if not token:
        return
    if len(_RUNNING) >= MAX_RUNNING:
        _RUNNING.pop(next(iter(_RUNNING)), None)
    _RUNNING[token] = (server_id, database, pid)


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON を解釈できませんでした。")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON オブジェクトを送ってください。")
    return body


def _clamp(value: Any, low: int, high: int, fallback: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return fallback


# ── エンドポイント ───────────────────────────────────────────

@router.get("/servers")
@limiter.limit("30/minute")
async def list_servers(request: Request, _=Depends(check_dev)):
    """接続先と、そのサーバ上のデータベース一覧。"""
    out = []
    for server in _servers().values():
        entry = {
            "id": server["id"],
            "label": server["label"],
            "host": server["host"],
            "port": server["port"],
            "user": server["user"],
            "usedBy": server["used_by"],
            "defaultDatabase": server["default_database"],
            "databases": [],
            "version": None,
            "error": None,
        }
        try:
            conn = await _connect(server, None)
        except HTTPException as exc:
            entry["error"] = str(exc.detail)
            out.append(entry)
            continue
        try:
            rows = await conn.fetch(
                """
                SELECT d.datname AS name,
                       pg_catalog.pg_database_size(d.datname) AS bytes,
                       pg_catalog.pg_get_userbyid(d.datdba) AS owner
                  FROM pg_catalog.pg_database d
                 WHERE NOT d.datistemplate AND d.datallowconn
                 ORDER BY d.datname
                """,
                timeout=10,
            )
            entry["databases"] = [
                {"name": r["name"], "bytes": int(r["bytes"] or 0), "owner": r["owner"]} for r in rows
            ]
            entry["version"] = await conn.fetchval("SHOW server_version", timeout=5)
        except asyncpg.PostgresError as exc:
            entry["error"] = str(exc)
        finally:
            await conn.close()
        out.append(entry)
    return JSONResponse({"servers": out})


@router.get("/objects")
@limiter.limit("60/minute")
async def list_objects(
    request: Request,
    _=Depends(check_dev),
    server: str = Query(...),
    database: str = Query(...),
):
    """スキーマ → テーブル/ビュー → 列 の木。"""
    target = _server_or_404(server)
    conn = await _connect(target, database)
    try:
        tables = await conn.fetch(
            """
            -- relkind は "char"（内部用の1バイト型）で、asyncpg は str ではなく
            -- bytes で返す。素通しすると JSONResponse の json.dumps で
            -- "Object of type bytes is not JSON serializable" になるため text へ。
            SELECT n.nspname AS schema, c.relname AS name, c.relkind::text AS kind,
                   c.reltuples::bigint AS approx_rows,
                   pg_catalog.pg_total_relation_size(c.oid) AS bytes,
                   obj_description(c.oid, 'pg_class') AS comment
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relkind = ANY('{r,p,v,m,f}')
               AND n.nspname <> ALL($1::text[])
             ORDER BY n.nspname, c.relname
             LIMIT 3000
            """,
            list(SYSTEM_SCHEMAS),
            timeout=20,
        )
        columns = await conn.fetch(
            """
            SELECT n.nspname AS schema, c.relname AS table, a.attname AS name,
                   pg_catalog.format_type(a.atttypid, a.atttypmod) AS type,
                   a.attnotnull AS not_null,
                   COALESCE(bool_or(i.indisprimary), false) AS is_pk,
                   pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS default_value
              FROM pg_catalog.pg_attribute a
              JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
              LEFT JOIN pg_catalog.pg_index i
                     ON i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY(i.indkey)
             WHERE a.attnum > 0 AND NOT a.attisdropped
               AND c.relkind = ANY('{r,p,v,m,f}')
               AND n.nspname <> ALL($1::text[])
             GROUP BY n.nspname, c.relname, a.attname, a.attnum, a.atttypid, a.atttypmod,
                      a.attnotnull, d.adbin, d.adrelid
             ORDER BY n.nspname, c.relname, a.attnum
             LIMIT 20000
            """,
            list(SYSTEM_SCHEMAS),
            timeout=20,
        )
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        await conn.close()

    by_table: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in columns:
        by_table.setdefault((row["schema"], row["table"]), []).append({
            "name": row["name"],
            "type": row["type"],
            "notNull": row["not_null"],
            "pk": row["is_pk"],
            "default": row["default_value"],
        })

    schemas: dict[str, list[dict[str, Any]]] = {}
    for row in tables:
        schemas.setdefault(row["schema"], []).append({
            "name": row["name"],
            "kind": row["kind"],
            "approxRows": max(int(row["approx_rows"] or 0), 0),
            "bytes": int(row["bytes"] or 0),
            "comment": row["comment"],
            "columns": by_table.get((row["schema"], row["name"]), []),
        })

    return JSONResponse({
        "database": database,
        "schemas": [{"name": name, "tables": schemas[name]} for name in sorted(schemas)],
    })


@router.get("/ddl")
@limiter.limit("30/minute")
async def table_ddl(
    request: Request,
    _=Depends(check_dev),
    server: str = Query(...),
    database: str = Query(...),
    schema: str = Query(...),
    table: str = Query(...),
):
    """CREATE TABLE 相当の定義文（列・制約・索引）を組み立てて返す。"""
    target = _server_or_404(server)
    conn = await _connect(target, database)
    try:
        columns = await conn.fetch(
            """
            SELECT a.attname AS name,
                   pg_catalog.format_type(a.atttypid, a.atttypmod) AS type,
                   a.attnotnull AS not_null,
                   pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS default_value
              FROM pg_catalog.pg_attribute a
              JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
             WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped
             ORDER BY a.attnum
            """,
            schema, table, timeout=10,
        )
        if not columns:
            raise HTTPException(status_code=404, detail="そのテーブルは見つかりませんでした。")
        constraints = await conn.fetch(
            """
            SELECT con.conname AS name, pg_catalog.pg_get_constraintdef(con.oid) AS definition
              FROM pg_catalog.pg_constraint con
              JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1 AND c.relname = $2
             ORDER BY con.contype, con.conname
            """,
            schema, table, timeout=10,
        )
        indexes = await conn.fetch(
            """
            SELECT indexname AS name, indexdef AS definition
              FROM pg_catalog.pg_indexes
             WHERE schemaname = $1 AND tablename = $2
             ORDER BY indexname
            """,
            schema, table, timeout=10,
        )
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        await conn.close()

    lines = [f'CREATE TABLE {_quote_ident(schema)}.{_quote_ident(table)} (']
    body = []
    for column in columns:
        piece = f'    {_quote_ident(column["name"])} {column["type"]}'
        if column["default_value"]:
            piece += f' DEFAULT {column["default_value"]}'
        if column["not_null"]:
            piece += " NOT NULL"
        body.append(piece)
    for constraint in constraints:
        body.append(f'    CONSTRAINT {_quote_ident(constraint["name"])} {constraint["definition"]}')
    lines.append(",\n".join(body))
    lines.append(");")

    index_lines = [
        f'{index["definition"]};'
        for index in indexes
        # 主キー・一意制約から自動で作られる索引は制約側で出ているので重ねない
        if not any(index["name"] == c["name"] for c in constraints)
    ]
    ddl = "\n".join(lines)
    if index_lines:
        ddl += "\n\n" + "\n".join(index_lines)
    return JSONResponse({"ddl": ddl})


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@router.post("/query")
@limiter.limit("60/minute")
async def run_query(request: Request, _dev=Depends(check_dev), _csrf=Depends(check_csrf)):
    """SQL を実行する。既定は読み取り専用トランザクション。"""
    body = await _json_body(request)
    server_id = str(body.get("server") or "")
    database = str(body.get("database") or "")
    script = body.get("sql")
    write = bool(body.get("write"))
    limit = _clamp(body.get("limit"), 1, MAX_ROWS, DEFAULT_ROWS)
    timeout = _clamp(body.get("timeout"), 1, MAX_TIMEOUT_SECONDS, DEFAULT_TIMEOUT_SECONDS)
    token = str(body.get("token") or "")[:64]

    if not isinstance(script, str) or not script.strip():
        raise HTTPException(status_code=400, detail="SQL が空です。")
    if len(script) > MAX_SQL_CHARS:
        raise HTTPException(status_code=400, detail=f"SQL が長すぎます（{MAX_SQL_CHARS} 文字まで）。")
    statements = split_statements(script)
    if not statements:
        raise HTTPException(status_code=400, detail="実行できる文がありません。")
    if len(statements) > MAX_STATEMENTS:
        raise HTTPException(status_code=400, detail=f"文が多すぎます（{MAX_STATEMENTS} 文まで）。")

    target = _server_or_404(server_id)
    user = request.session.get("user") or {}
    logger.warning(
        "SQL実行 user=%s db=%s/%s mode=%s statements=%d sql=%.500s",
        user.get("id"), server_id, database, "write" if write else "read", len(statements), script,
    )

    conn = await _connect(target, database, timeout_ms=timeout * 1000)
    _remember_running(token, server_id, database, conn.get_server_pid())
    results: list[dict[str, Any]] = []
    started = time.perf_counter()

    # VACUUM のようにトランザクション内で実行できない文は、書き込みモードで
    # 1文だけ投げられたときに限り、トランザクションを張らずにそのまま流す。
    # 先頭のコメントは判定の邪魔になるので、判定用にだけ落とす（実行は原文のまま）
    if write and len(statements) == 1 and _NON_TRANSACTIONAL.match(_COMMENTS.sub("", statements[0])):
        try:
            begun = time.perf_counter()
            status = await conn.execute(statements[0], timeout=float(timeout))
            results.append({
                "columns": [], "rows": [], "rowCount": _affected(status), "truncated": False,
                "status": status or "OK", "elapsedMs": round((time.perf_counter() - begun) * 1000, 1),
                "sql": statements[0],
            })
            error = None
        except asyncpg.PostgresError as exc:
            error = {**_error_payload(exc), "statementIndex": 0}
        except asyncio.TimeoutError:
            error = _timeout_error(timeout, 0)
        finally:
            _RUNNING.pop(token, None)
            await conn.close()
        return JSONResponse({
            "results": results,
            "error": error,
            "committed": error is None,
            "outsideTransaction": True,
            "elapsedMs": round((time.perf_counter() - started) * 1000, 1),
        })

    transaction = conn.transaction(readonly=not write)
    try:
        await transaction.start()
        try:
            for statement in statements:
                results.append(await _run_one(conn, statement, limit, float(timeout)))
        except asyncpg.PostgresError as exc:
            await transaction.rollback()
            return JSONResponse(
                {
                    "results": results,
                    "error": {**_error_payload(exc), "statementIndex": len(results)},
                    "committed": False,
                    "elapsedMs": round((time.perf_counter() - started) * 1000, 1),
                },
                status_code=200,  # 「SQL が失敗した」であって API の失敗ではない
            )
        except asyncio.TimeoutError:
            await transaction.rollback()
            return JSONResponse({
                "results": results,
                "error": _timeout_error(timeout, len(results)),
                "committed": False,
                "elapsedMs": round((time.perf_counter() - started) * 1000, 1),
            })

        if write:
            await transaction.commit()
        else:
            await transaction.rollback()
    finally:
        _RUNNING.pop(token, None)
        await conn.close()

    return JSONResponse({
        "results": results,
        "error": None,
        "committed": write,
        "elapsedMs": round((time.perf_counter() - started) * 1000, 1),
    })


@router.post("/cancel")
@limiter.limit("30/minute")
async def cancel_query(request: Request, _dev=Depends(check_dev), _csrf=Depends(check_csrf)):
    """実行中のクエリを止める（別の接続から pg_cancel_backend を呼ぶ）。"""
    body = await _json_body(request)
    token = str(body.get("token") or "")[:64]
    running = _RUNNING.get(token)
    if not running:
        return JSONResponse({"cancelled": False, "message": "実行中のクエリはありません。"})

    server_id, database, pid = running
    target = _server_or_404(server_id)
    conn = await _connect(target, database)
    try:
        cancelled = await conn.fetchval("SELECT pg_cancel_backend($1)", pid, timeout=5)
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        await conn.close()
    return JSONResponse({
        "cancelled": bool(cancelled),
        "message": "クエリを止めました。" if cancelled else "すでに終わっていました。",
    })
