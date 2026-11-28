"""Rust のテストが読む基準（fixtures）を、本番と同じ Python で作り直す。

CI の「基準」（.github/workflows/fixtures.yml）が回す。作り直したあとに git の差分が出たら、
基準がリポジトリの Python と食い違っている（Python を直したのに基準を作り直していない、など）。
作り直したものは CI の成果物（fixtures）として置かれるので、取ってきてコミットする。

**手元の PC では回さない**（重いので。本人の指示 2026-11-28）。CI の中では、リポジトリの直下が
/app にある前提で動く（生成の道具が sys.path に /app を足すため。CI はリンクを張る）。

使い方（CI の中）:
    python tools/fixtures/regen.py               # 全部
    python tools/fixtures/regen.py chat user_state   # 名前で絞る

空の Postgres が要るものは、PG_ADMIN_DSN（postgresql://…/postgres）で、作り直すたびに新しい
データベースを作って渡す（前の作り直しの行が残ると、基準が変わる）。

ここに無い基準（地震・DJAudio・読み上げ など）は、まだ CI で作り直していない。作り方は各 fixtures の
generate*.py の先頭の説明にある。足すときは GENERATORS に 1 行足す。
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
F = "rust/apps/bot/tests/fixtures"

# (名前, 作業ディレクトリ, 引数, 標準出力の書き先〔None なら道具が自分で書く〕, 空の Postgres が要るか)
GENERATORS = [
    ("url_safety", ".", ["rust/crates/sycs-core/tests/fixtures/url_safety/generate.py"], None, False),
    ("message_security", f"{F}/message_security", ["generate.py", "cases.json"], "expected.jsonl", False),
    # スパムの「同じ内容」の比べ方に使う casefold の表（Rust の src に置く。rust-09 の S3）。
    ("casefold", ".", [f"{F}/message_security/generate_casefold.py"], "rust/apps/bot/src/security_casefold.tsv", False),
    ("chat", f"{F}/chat", ["generate.py", "cases.json"], "expected.jsonl", False),
    (
        "user_state",
        ".",
        [f"{F}/user_state/generate.py", f"{F}/user_state/cases.json"],
        f"{F}/user_state/expected.json",
        True,
    ),
    (
        "user_state_sync",
        ".",
        [f"{F}/user_state_sync/generate.py", f"{F}/user_state_sync/cases.json"],
        f"{F}/user_state_sync/expected.json",
        True,
    ),
    # 管理画面（rust/apps/admin）: 設定パネルの定義の書き出し（schema.json）と、API の基準（expected.json）。
    # どちらも道具が自分の隣に書き出す（標準出力は使わない）。
    ("admin_schema", ".", ["rust/apps/admin/tests/fixtures/schema/generate.py"], None, False),
    ("admin_users_state", ".", ["rust/apps/admin/tests/fixtures/users_state/generate.py"], None, False),
    # 管理画面の骨組み（A1）: セッションの Cookie と秘密鍵、エラーの答え・経路・確かめ・回数の制限・数とインシデント。
    ("admin_session", ".", ["rust/apps/admin/tests/fixtures/session/generate.py"], None, False),
    ("admin_errors", ".", ["rust/apps/admin/tests/fixtures/errors/generate.py"], None, False),
    # 信頼するプロキシの読み方（uvicorn の ProxyHeadersMiddleware。Rust の web の土台 sycs-web。W0）。
    ("web_proxy", ".", ["rust/crates/sycs-web/tests/fixtures/proxy/generate.py"], None, False),
    # 配信（/dlaudio/。管理画面のアプリに入っている dlaudio_router。Rust の apps/cdn。W1・rust-07）。
    ("cdn_dlaudio", ".", ["rust/apps/cdn/tests/fixtures/dlaudio/generate.py"], None, False),
    # Web（rust/apps/web）: API の基準（expected.json）。道具が自分の隣に書き出す（W3 の下ごしらえ）。
    ("web_prices_calculate", ".", ["rust/apps/web/tests/fixtures/prices_calculate/generate.py"], None, False),
    # 管理画面のテンプレート（minijinja が Jinja2・markupsafe と同じ HTML を書くか。A2）。道具が自分の隣に書き出す。
    ("admin_templates", ".", ["rust/apps/admin/tests/fixtures/templates/generate.py"], None, False),
    # 管理画面の利用者の状態の読み出し（A4）。空の Postgres に行を入れて作る。道具が自分の隣に書き出す。
    ("admin_users_state_db", ".", ["rust/apps/admin/tests/fixtures/users_state_db/generate.py"], None, True),
    # 管理画面のログインとサーバー選択（偽物の Discord に当てる。A3）と、user_still_admin の権限の組み立て。
    ("admin_auth", ".", ["rust/apps/admin/tests/fixtures/auth/generate.py"], None, False),
    ("admin_check", ".", ["rust/apps/admin/tests/fixtures/admin_check/generate.py"], None, False),
    # 管理画面の設定パネルの読む側（偽物の Discord・TTS に当てる。A5）と、値を読む関数（設定の JSON → 答え）。
    ("admin_apps_read", ".", ["rust/apps/admin/tests/fixtures/apps_read/generate.py"], None, False),
    ("admin_getters", ".", ["rust/apps/admin/tests/fixtures/getters/generate.py"], None, False),
    # 管理画面の監視（A7）: /admin/api/metrics・incidents と整形の関数・/proc の読み方・監視の巡回（monitor）、
    # Netdata が読む /metrics の接続元の判定と本文（prometheus）。どちらも道具が自分の隣に書き出す。
    ("admin_monitor", ".", ["rust/apps/admin/tests/fixtures/monitor/generate.py"], None, False),
    ("admin_prometheus", ".", ["rust/apps/admin/tests/fixtures/prometheus/generate.py"], None, False),
]


async def _create_database(admin_dsn: str, name: str) -> None:
    """空のデータベースを作る（同じ名前があれば消してから）。"""
    import asyncpg

    conn = await asyncpg.connect(admin_dsn)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


def _fresh_dsn(name: str) -> str:
    """その基準のための空のデータベースを作り、SQLAlchemy（asyncpg）の接続先を返す。"""
    admin = os.environ.get("PG_ADMIN_DSN")
    if not admin:
        raise SystemExit("PG_ADMIN_DSN が無い（空の Postgres が要る基準を作り直せない）")
    database = f"regen_{name}"
    asyncio.run(_create_database(admin, database))
    parts = urlsplit(admin)
    return urlunsplit(("postgresql+asyncpg", parts.netloc, f"/{database}", "", ""))


def run(name: str, cwd: str, args: list[str], stdout: str | None, needs_pg: bool) -> bool:
    """1 つの基準を作り直す。うまくいけば True。"""
    env = dict(os.environ)
    if needs_pg:
        env["USER_STATE_POSTGRES_DSN"] = _fresh_dsn(name)
    where = ROOT / cwd
    print(f"== {name}", flush=True)
    if stdout is None:
        done = subprocess.run([sys.executable, *args], cwd=where, env=env)
    else:
        with open(where / stdout, "wb") as out:
            done = subprocess.run([sys.executable, *args], cwd=where, env=env, stdout=out)
    if done.returncode != 0:
        print(f"{name}: 作り直しに失敗した（終了コード {done.returncode}）", flush=True)
        return False
    return True


def main(names: list[str]) -> int:
    """名前で絞った基準（無ければ全部）を作り直す。1 つでも失敗したら 1 を返す。"""
    known = {g[0] for g in GENERATORS}
    unknown = [n for n in names if n not in known]
    if unknown:
        print(f"知らない名前: {', '.join(unknown)}（あるのは {', '.join(sorted(known))}）")
        return 2
    ok = True
    for name, cwd, args, stdout, needs_pg in GENERATORS:
        if names and name not in names:
            continue
        ok = run(name, cwd, args, stdout, needs_pg) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
