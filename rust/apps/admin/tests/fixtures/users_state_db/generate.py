"""利用者の状態の読み出しの基準（expected.json）を、本物の Python と空の Postgres から作る。

対象は services/user_state_service.py の list_recent_user_states・count_user_states・get_user_state_detail
（管理画面の利用者の状態の API が呼ぶ 3 つ。中の _apply_state_filter・並び・件数の丸め・JSON の列の読み方・
表の自己修復も通る）。Rust の rust/apps/admin/src/users/store.rs を、tests/users_state_db_golden.rs が
同じ行・同じ引数で突き合わせる。

手順（cases.json）:

1. 本物の ensure_user_state_db で表を作る（Python の SQLAlchemy が作る形）
2. current・events の行を、列を全部書いて入れる（defaults に行ごとの値を上書きしたもの。時刻は ISO 8601 の文字を
   Postgres に読ませる。入れる SQL は insert_sql。Rust のテストも同じ文で入れる）
3. steps を順に回す。fn の step は本物の関数を呼んで答えを書く（admin_harness の encode。datetime は
   {"$datetime": isoformat}）。sql の step はその文を流す（表を消して自己修復を確かめる）

ほかに、str.isdigit() が真で str.isdecimal() が偽の文字の範囲（digit_only）も書く（_apply_state_filter の
q.isdigit() と int(q) の食い違い。Rust の DIGIT_ONLY と比べる）。

作り直すとき（本番と同じ依存 requirements.txt と、空の Postgres。CI の「基準」が tools/fixtures/regen.py から回す。
regen.py が USER_STATE_POSTGRES_DSN に新しいデータベースを入れる）:

    USER_STATE_POSTGRES_DSN=postgresql+asyncpg://… python rust/apps/admin/tests/fixtures/users_state_db/generate.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/users_state_db/generate.py"
# 時刻の列（文字を Postgres に timestamptz として読ませる）。
TIMESTAMP_COLUMNS = frozenset(
    {
        "timed_out_until",
        "last_event_at",
        "first_seen_at",
        "last_joined_at",
        "last_left_at",
        "created_at",
        "updated_at",
        "event_at",
    }
)
# step の fn → 呼ぶ関数の名前と、step から引数を作る鍵（位置引数・名前つき引数）。
FUNCTIONS = {
    "list": ("list_recent_user_states", ("guild_id",), ("query", "limit", "offset")),
    "count": ("count_user_states", ("guild_id",), ("query",)),
    "detail": ("get_user_state_detail", ("guild_id", "user_id"), ("event_limit",)),
}


def insert_sql(table: str, columns: list[str]) -> str:
    """行を入れる文（SQLAlchemy の text() の :名前 の書き方。時刻は文字を timestamptz に読ませる）。"""
    values = ", ".join(f"(:{c})::text::timestamptz" if c in TIMESTAMP_COLUMNS else f":{c}" for c in columns)
    return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({values})"


def merged_rows(defaults: dict[str, Any], rows: list[dict[str, Any]], columns: list[str]) -> list[dict[str, Any]]:
    """行ごとに defaults へ上書きし、列の並びの辞書にする（足りない列・知らない列があれば止める）。"""
    merged = []
    for row in rows:
        full = {**defaults, **row}
        missing = [c for c in columns if c not in full]
        unknown = [c for c in full if c not in columns]
        if missing or unknown:
            raise SystemExit(f"行 {row.get('id')}: 足りない列 {missing}・知らない列 {unknown}")
        merged.append({c: full[c] for c in columns})
    return merged


def digit_only_ranges() -> list[list[int]]:
    """str.isdigit() が真で str.isdecimal() が偽の文字（Unicode の Numeric_Type=Digit）の範囲（始めと終わり）。"""
    ranges: list[list[int]] = []
    for code in range(sys.maxunicode + 1):
        char = chr(code)
        if not (char.isdigit() and not char.isdecimal()):
            continue
        if ranges and ranges[-1][1] == code - 1:
            ranges[-1][1] = code
        else:
            ranges.append([code, code])
    return ranges


def call_arguments(step: dict[str, Any]) -> tuple[str, list[Any], dict[str, Any]]:
    """step から、呼ぶ関数の名前・位置引数・名前つき引数を作る（{"$int": …} は Python の int にする）。"""
    name, positional, named = FUNCTIONS[step["fn"]]
    args = [harness.decode(step[key], {}) for key in positional]
    kwargs = {key: harness.decode(step[key], {}) for key in named}
    return name, args, kwargs


async def _insert(engine: Any, document: dict[str, Any]) -> None:
    """current・events の行を入れる。"""
    from sqlalchemy import text

    tables = (
        ("user_state_current", "current_columns", "current_defaults", "current"),
        ("user_state_event", "event_columns", "event_defaults", "events"),
    )
    async with engine.begin() as conn:
        for table, columns_key, defaults_key, rows_key in tables:
            columns = document[columns_key]
            statement = text(insert_sql(table, columns))
            for row in merged_rows(document[defaults_key], document[rows_key], columns):
                await conn.execute(statement, row)


async def _run(document: dict[str, Any]) -> list[dict[str, Any]]:
    """表を作って行を入れ、steps を順に回して、step ごとの答えを返す。"""
    from sqlalchemy import text

    from services import user_state_db as udb
    from services import user_state_service as uss

    await udb.ensure_user_state_db()
    await _insert(udb.engine, document)
    results = []
    for step in document["steps"]:
        if "sql" in step:
            async with udb.engine.begin() as conn:
                await conn.execute(text(step["sql"]))
            results.append({"name": step["name"], "sql": step["sql"]})
            continue
        name, args, kwargs = call_arguments(step)
        result = await getattr(uss, name)(*args, **kwargs)
        results.append({"name": step["name"], "fn": name, "result": harness.encode(result)})
    await udb.engine.dispose()
    return results


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    if not os.environ.get("USER_STATE_POSTGRES_DSN"):
        raise SystemExit("USER_STATE_POSTGRES_DSN が無い（空の Postgres が要る。tools/fixtures/regen.py から回す）")
    os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="admin-fixture-settings-")
    os.environ.pop("SETTINGS_BACKEND", None)
    if str(harness.ROOT) not in sys.path:
        sys.path.insert(0, str(harness.ROOT))
    names = [step["name"] for step in document["steps"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"step の名前が重なっている: {', '.join(duplicated)}")
    return {
        "generated_by": GENERATED_BY,
        "steps": asyncio.run(_run(document)),
        "digit_only": digit_only_ranges(),
    }


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
