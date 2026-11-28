"""管理画面のログインとサーバー選択（A3）の基準（expected.json）を、本物の Python と偽物の Discord で作る。

Rust の管理画面（rust/apps/admin）の tests/auth_golden.rs が読む。本物の管理画面（webapp_admin/app.py の app）を
starlette の TestClient で回し、Discord の API（webapp_admin/auth.py の _API）は偽物（../fake_discord.py）へ向ける。
層は全部本物（セッション・slowapi・見張り・見出し・数・例外の係・経路・テンプレート）。

経路: /admin/login・/admin/auth・/admin/callback・/admin/logout（GET・POST）・/admin/・/admin/guilds・
/admin/guilds/select・/admin/overview・/（Bot のサーバー数の 5 分の使い回し）・/terms（既定の回数の制限）。

例（cases.json）は要求の並び（steps）を順に送る。要求ごとに書けるもの:

    method・target・headers・form・json・repeat   送る要求（repeat は同じ要求を何回送るか。最後の答えだけ書く）
    session（名前）                              その中身の Cookie（その要求の時刻で署名）を付ける
    cookie: "carry"                              前の答えの Set-Cookie の値を付ける（ブラウザのように持ち回る）
    at                                           例の now からの秒（時刻はこれに決まる）
    discord                                      偽物の Discord の答え方（例の discord に上書きする）
    expect_status                                道具の確かめ（違えば作り直しを止める）

例には config（Discord の設定。文書の discord に上書き）と stored_guilds（設定のあるサーバーの数。
{"$raise": …} なら投げる）も書ける。target・headers・form の {csrf:N} と {state:N} は、その例の N 番目の CSRF の
印と認可の state（下の決まった並び）に置き換える。答え方と sessions の中では $ref（library）が使える。

2 回作ってバイトまで同じにするために決めてあること:

- 時刻（views・auth・metrics の time.time と、署名の時計）は要求ごとに now + at に止める
- CSRF の印（secrets.token_hex）は f"{TOKEN_BASE + n:064x}"、認可の state（secrets.token_urlsafe）は
  f"{STATE_BASE + n:043x}"、インシデントの ID は f"{ID_BASE + n:032x}"（どれも例ごとに 1 から）
- 偽物の Discord に届いた要求は中身で並べる（本人と Bot の一覧を並べて取るので、届く順は決まらない）
- Bot のサーバー数の使い回し・slowapi の数・数え口は例ごとに空にする
- HTML の資材の URL は static の置き場を無い場所にして ?v=admin の形にそろえる
- DISCORD_CLIENT_ID は文書の discord.client_id を import の前に入れる（公開ページの招待リンクは app を作るときに
  名前を取り込むので、公開ページを踏む例では client_id を変えない。道具が確かめる）

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/auth/generate.py

**`from __future__ import annotations` を書かないこと**（FastAPI が注釈を引けなくなる。errors/generate.py の説明）。
"""

import json
import os
import re
import secrets
import sys
import time
import types
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402
import fake_discord  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/auth/generate.py"
TOKEN_BASE = 0xA3000000
STATE_BASE = 0x5A3E0000
ID_BASE = 0x1A300000
PLACEHOLDER = re.compile(r"\{(csrf|state):(\d+)\}")
PUBLIC_PATHS = ("/", "/guide", "/privacy", "/terms")
STATIC_ROOT = Path("/nonexistent-admin-fixture-static")


def csrf_token(n: int) -> str:
    """その例の n 番目の CSRF の印。"""
    return f"{TOKEN_BASE + n:064x}"


def state_token(n: int) -> str:
    """その例の n 番目の認可の state。"""
    return f"{STATE_BASE + n:043x}"


def fill(text: str) -> str:
    """{csrf:N}・{state:N} を置き換える。"""

    def replace(match: re.Match[str]) -> str:
        """1 つの印を置き換える。"""
        n = int(match[2])
        return csrf_token(n) if match[1] == "csrf" else state_token(n)

    return PLACEHOLDER.sub(replace, text)


class Sequence:
    """例ごとに決まる CSRF の印・認可の state・インシデントの ID の並び。"""

    def __init__(self) -> None:
        """1 つ目から数える。"""
        self.tokens = 0
        self.states = 0
        self.ids = 0

    def token_hex(self, nbytes: int = 32) -> str:
        """secrets.token_hex の代わり（長さは見ない）。"""
        self.tokens += 1
        return csrf_token(self.tokens)

    def token_urlsafe(self, nbytes: int = 32) -> str:
        """secrets.token_urlsafe の代わり（長さは見ない）。"""
        self.states += 1
        return state_token(self.states)

    def uuid4(self) -> Any:
        """uuid.uuid4 の代わり（hex だけ使う）。"""
        self.ids += 1
        return types.SimpleNamespace(hex=f"{ID_BASE + self.ids:032x}")


class Clock:
    """time モジュールの代わり（time() は決めた時刻。sleep は本物）。"""

    def __init__(self, now: float) -> None:
        """いまの時刻を決める。"""
        self.now = now

    def time(self) -> float:
        """time.time の代わり。"""
        return self.now

    def sleep(self, seconds: float) -> None:
        """time.sleep（監視の巡回のスレッドが使う）。"""
        time.sleep(seconds)


class StoredGuilds:
    """settings_store.get_all_guild_ids の偽物（例の stored_guilds の数だけ ID を返す。$raise なら投げる）。"""

    def __init__(self, spec: Any) -> None:
        """例の stored_guilds を受け取る。"""
        self.spec = spec
        self.calls = 0

    def __call__(self) -> list[int]:
        """呼ばれた数を数えて答える。"""
        self.calls += 1
        if isinstance(self.spec, dict) and "$raise" in self.spec:
            raise RuntimeError(str(self.spec.get("message", "")))
        return list(range(1, int(self.spec) + 1))

    def take(self) -> int:
        """前に聞いてから呼ばれた数。"""
        calls, self.calls = self.calls, 0
        return calls


def _patches(config: dict[str, Any], fake: Any, sequence: Sequence, clock: Clock, stored: StoredGuilds) -> list[Any]:
    """例のあいだ差し替えるもの（Discord の設定と行き先・時刻・乱数・サーバー数の使い回し・static）。"""
    from itsdangerous import TimestampSigner

    import services.settings_store as settings_store
    from webapp_admin import auth, metrics, security, templating
    from webapp_admin.views import auth_views, dashboard_views

    def signer_time(self: Any) -> int:
        """署名の時計（その要求の時刻の整数部）。"""
        return int(clock.now)

    security_secrets = types.SimpleNamespace(token_hex=sequence.token_hex, compare_digest=secrets.compare_digest)
    view_secrets = types.SimpleNamespace(token_urlsafe=sequence.token_urlsafe, compare_digest=secrets.compare_digest)
    targets = [
        (auth, "_API", fake.api_base),
        (auth, "DISCORD_CLIENT_ID", config["client_id"]),
        (auth_views, "DISCORD_CLIENT_ID", config["client_id"]),
        (auth, "DISCORD_CLIENT_SECRET", config["client_secret"]),
        (auth, "DISCORD_REDIRECT_URI", config["redirect_uri"]),
        (auth, "DISCORD_BOT_TOKEN", config["bot_token"]),
        (auth, "DISCORD_OAUTH_PROMPT", config["prompt"]),
        (dashboard_views, "ADMIN_GUILDS_MAX_AGE_SECONDS", int(config["guilds_max_age"])),
        (auth, "_guild_count_cache", None),
        (settings_store, "get_all_guild_ids", stored),
        (security, "secrets", security_secrets),
        (auth_views, "secrets", view_secrets),
        (metrics, "uuid", types.SimpleNamespace(uuid4=sequence.uuid4)),
        (metrics, "time", clock),
        (auth, "time", clock),
        (auth_views, "time", clock),
        (dashboard_views, "time", clock),
        (templating, "_static_root", STATIC_ROOT),
        (TimestampSigner, "get_timestamp", signer_time),
    ]
    return [patch.object(target, name, value) for target, name, value in targets]


def _check_case(case: dict[str, Any], document: dict[str, Any]) -> None:
    """公開ページを踏む例で client_id を変えていないか（招待リンクは import のときの値で固まる）。"""
    client_id = (case.get("config") or {}).get("client_id", document["discord"]["client_id"])
    if client_id == document["discord"]["client_id"]:
        return
    for step in case["steps"]:
        if step["target"].split("?", 1)[0] in PUBLIC_PATHS:
            raise SystemExit(f"{case['name']}: 公開ページを踏む例では client_id を変えられない")


def _cookie(
    step: dict[str, Any], sessions: dict[str, Any], document: dict[str, Any], clock: Clock, carried: Any
) -> Any:
    """その要求に付ける Cookie の値（名前のセッション・持ち回り・無し）。"""
    if "session" in step:
        return harness.session_cookie(sessions[step["session"]], document["secret"], signed_at=int(clock.now))
    if step.get("cookie") == "carry":
        return carried
    return None


def _send(client: Any, step: dict[str, Any], cookie: Any) -> Any:
    """1 つの要求を repeat 回送り、最後の応答を返す（TestClient の Cookie は毎回空にする）。"""
    headers = [(str(name).lower(), fill(str(value))) for name, value in (step.get("headers") or {}).items()]
    if cookie is not None:
        headers.append(("cookie", f"{harness.COOKIE_NAME}={cookie}"))
    kwargs: dict[str, Any] = {"headers": headers, "follow_redirects": False}
    if "json" in step:
        kwargs["json"] = step["json"]
    if "form" in step:
        kwargs["data"] = {str(name): fill(str(value)) for name, value in step["form"].items()}
    response = None
    for _ in range(int(step.get("repeat", 1))):
        client.cookies.clear()
        response = client.request(step["method"], fill(step["target"]), **kwargs)
    return response


def _carried(response: Any, cookie: Any) -> Any:
    """答えの Set-Cookie を持ち回りの値にする（消す Cookie なら無し。Set-Cookie が無ければ前のまま）。"""
    prefix = f"{harness.COOKIE_NAME}="
    for name, value in response.headers.multi_items():
        if name.lower() == "set-cookie" and value.startswith(prefix):
            data = value.split(";", 1)[0][len(prefix) :]
            cookie = None if data == "null" else data
    return cookie


def _record_request(response: Any) -> dict[str, Any]:
    """実際に送った要求（httpx が整えたあとのパス・見出し・本文）。"""
    request = response.request
    return {
        "method": request.method,
        "target": request.url.raw_path.decode("ascii"),
        "headers": [[name.lower(), value] for name, value in request.headers.multi_items()],
        "body_hex": request.content.hex(),
    }


def _counters() -> list[list[Any]]:
    """数え口に溜まった数（名前とラベルの順）。"""
    from services.metrics_registry import counters

    drained = counters().drain()
    return sorted(
        ([name, dict(sorted(labels.items())), amount] for name, labels, amount in drained),
        key=lambda item: (item[0], sorted(item[1].items())),
    )


def _incident_bytes() -> bytes:
    """incidents.jsonl のいまの中身（無ければ空）。"""
    path = Path(os.environ["SETTINGS_DIR"]) / "admin_monitor" / "incidents.jsonl"
    return path.read_bytes() if path.exists() else b""


class Runner:
    """1 つの例を回す（要求を順に送り、Discord に届いたものと答えを控える）。"""

    def __init__(self, app: Any, document: dict[str, Any], sessions: dict[str, Any], fake: Any) -> None:
        """app・文書・名前のセッション・偽物の Discord を受け取る。"""
        self.app = app
        self.document = document
        self.sessions = sessions
        self.fake = fake
        self.library = document.get("library") or {}

    def _step(self, client: Any, case: dict[str, Any], step: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        """1 つの要求を送り、控えを作る。state は時計・サーバー数の偽物・持ち回りの Cookie。"""
        clock: Clock = state["clock"]
        clock.now = float(self.document["now"]) + float(step.get("at", 0))
        answers = {
            **harness.decode(case.get("discord") or {}, self.library),
            **harness.decode(step.get("discord") or {}, self.library),
        }
        self.fake.script(answers)
        cookie = _cookie(step, self.sessions, self.document, clock, state["carried"])
        response = _send(client, step, cookie)
        seen = self.fake.take()
        unexpected = fake_discord.unexpected(seen)
        if unexpected:
            raise SystemExit(f"{case['name']}: 例に書いていない Discord の要求: {', '.join(unexpected)}")
        expected_status = step.get("expect_status")
        if expected_status is not None and response.status_code != expected_status:
            raise SystemExit(
                f"{case['name']}: {step['target']} の状態が {response.status_code}（確かめでは {expected_status}）"
            )
        state["carried"] = _carried(response, state["carried"])
        entry: dict[str, Any] = {
            "at": step.get("at", 0),
            "now": clock.now,
            "request": _record_request(response),
            "discord_responses": answers,
            "discord": seen,
            "stored_guild_calls": state["stored"].take(),
            "response": harness.record_response(response),
        }
        if int(step.get("repeat", 1)) != 1:
            entry["repeat"] = int(step["repeat"])
        return entry

    def run(self, case: dict[str, Any]) -> dict[str, Any]:
        """例を回し、要求ごとの控えと、例で足した数とインシデントの行を返す。"""
        from starlette.testclient import TestClient

        from webapp_admin.extensions import limiter

        _check_case(case, self.document)
        limiter.reset()
        _counters()
        before = _incident_bytes()
        config = {**self.document["discord"], **(case.get("config") or {})}
        sequence = Sequence()
        clock = Clock(float(self.document["now"]))
        stored = StoredGuilds(case.get("stored_guilds", 0))
        state: dict[str, Any] = {"clock": clock, "stored": stored, "carried": None}
        steps: list[dict[str, Any]] = []
        with ExitStack() as stack:
            for patcher in _patches(config, self.fake, sequence, clock, stored):
                stack.enter_context(patcher)
            client = TestClient(self.app, base_url=harness.BASE_URL, raise_server_exceptions=False)
            try:
                steps = [self._step(client, case, step, state) for step in case["steps"]]
            finally:
                client.close()
        added = _incident_bytes()[len(before) :].decode("utf-8")
        return {
            "name": case["name"],
            "config": config,
            "stored_guilds": case.get("stored_guilds", 0),
            "steps": steps,
            "counters": _counters(),
            "incidents": added.split("\n")[:-1] if added else [],
        }


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    extra = {"DISCORD_CLIENT_ID": document["discord"]["client_id"], "ADMIN_MONITOR_INTERVAL_SECONDS": "86400"}
    harness.prepare_environment(document["secret"], extra)
    from webapp_admin.app import app

    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    library = document.get("library") or {}
    sessions = {name: harness.decode(value, library) for name, value in document["sessions"].items()}
    fake = fake_discord.FakeDiscord()
    try:
        runner = Runner(app, document, sessions, fake)
        cases = [runner.run(case) for case in document["cases"]]
    finally:
        fake.close()
    return {
        "generated_by": GENERATED_BY,
        "base_url": harness.BASE_URL,
        "cookie_name": harness.COOKIE_NAME,
        "secret": document["secret"],
        "now": document["now"],
        "token_base": TOKEN_BASE,
        "state_base": STATE_BASE,
        "id_base": ID_BASE,
        "discord": document["discord"],
        "sessions": sessions,
        "cases": cases,
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
