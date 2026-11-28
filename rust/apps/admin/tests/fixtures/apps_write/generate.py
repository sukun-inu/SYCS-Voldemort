"""設定パネルの書く側（A6）の基準（expected.json）を、本物の Python と偽物の Discord・TTS で作る。

Rust の管理画面（rust/apps/admin）の tests/apps_write_golden.rs が読む。本物の管理画面（webapp_admin/app.py の app）を
starlette の TestClient で回す（層は全部本物。apps_read/generate.py と同じ）。Discord の API と読み上げの API は
../fake_discord.py の偽物（2 つ立てる）へ向ける。

**設定の置き場は本物の services.settings_pg.PostgresSettings を、使い捨ての SQLite に向けて使う**
（tests/sqlite_session.py。tests/test_settings_pg.py と同じ）。書き換えの規則（settings_store._mutate_settings の
null の落とし方・控え・触られた時刻）も、版番号の上げ方（変わったギルドがあるときだけ 1 上げる。本物の Postgres
では、このとき bot_settings_changed に版番号を流して Bot に知らせる）も本物のまま回る。SQLite は JSON を書いた
鍵の並びのまま返すので、書いたあとの設定を鍵の並びまで比べられる（Postgres の JSONB は鍵を並べ替えるが、それは
Python と Rust で同じ。読み込んだ順に足していく並びは、手元の設定〔キャッシュ〕に残る）。

経路: PUT /admin/api/apps/{id}、POST・PUT・DELETE /admin/api/apps/{id}/collections/{key}…、
DELETE /admin/api/guild-data（とその 400・403・404・405・307・422・500）。

例（cases.json）は要求の並び（steps）を順に送る。例に書けるもの:

    settings      設定の全体（{"guilds": {...}}。$ref が使える）。置き場に取り込んでから始める（版番号 1）。
                  {"$raise": …, "message": …} なら読み込めない置き場（読むたび・書くたびに SettingsNotLoaded）
    discord・tts  偽物の答え方（step の discord・tts で上書き）
    bot_token     Discord の Bot のトークン（無ければ文書の discord.bot_token）
    user_states   サーバーのデータの削除で、利用者の状態を消す関数（services.user_state_service.
                  delete_guild_user_states）の答え（{"events", "states"}。{"$raise": …} なら例外）
    dev_user_id   DEV_USER_ID

要求（steps）に書けるもの: method・target・headers・session（名前）・json（本文。TestClient が JSON にする。
{"$repeat": 文字, "times": 回数} は文字をくり返したもの）・body（本文の文字。headers の content-type と一緒に）・at・
discord・tts・expect_status。

要求ごとに書くもの: 送った要求・偽物に届いたもの・答え（apps_read と同じ）に加えて、書いたあとの設定（ギルドの鍵の
順に並べ、ギルドの中は鍵の並びのまま）・版番号・その要求で書き換えを呼んだ回数ぶんの「書いたあとの版番号」
（変わらなければ前と同じ番号。読み込めない置き場は 0）・利用者の状態を消す関数に届いたサーバーの ID。

2 回作ってバイトまで同じにするために決めてあること（apps_read と同じものに加えて）:

- 触られた時刻（settings_store.datetime.now）は文書の stamp に止める
- ニュースのフィードの ID（news_feeds.uuid.uuid4().hex[:8]）とインシデントの ID は、例ごとに 1 から数える同じ並び
  （f"{ID_BASE + n:08x}" に 0 を 24 個。Rust のテストも同じ並びを、同じ 1 つの乱数の口から引く）

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/apps_write/generate.py

**`from __future__ import annotations` を書かないこと**（FastAPI が注釈を引けなくなる。errors/generate.py の説明）。
"""

import copy
import json
import os
import secrets
import sys
import time
import types
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402
import fake_discord  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/apps_write/generate.py"
TOKEN_BASE = 0xA6000000
ID_BASE = 0xA6100000
STATIC_ROOT = Path("/nonexistent-admin-fixture-static")
VOICES_TIMEOUT = 3.0
# Python の既定（600・30・3）と違う値にして、Rust が環境変数を読んでいることも確かめる（apps_read と同じ）。
DJAUDIO_ENV = {
    "DJAUDIO_CACHE_TTL_SECONDS": "720",
    "DJAUDIO_COOLDOWN_SECONDS": "45",
    "DJAUDIO_MAX_URLS_PER_MSG": "4",
}


class Sequence:
    """例ごとに決まる CSRF の印・ID の並び（インシデントとニュースのフィードが同じ並びを引く）。"""

    def __init__(self) -> None:
        """1 つ目から数える。"""
        self.tokens = 0
        self.ids = 0

    def token_hex(self, nbytes: int = 32) -> str:
        """secrets.token_hex の代わり（長さは見ない）。"""
        self.tokens += 1
        return f"{TOKEN_BASE + self.tokens:064x}"

    def uuid4(self) -> Any:
        """uuid.uuid4 の代わり（hex だけ使う。先頭の 8 文字が例ごとに変わる）。"""
        self.ids += 1
        return types.SimpleNamespace(hex=f"{ID_BASE + self.ids:08x}" + "0" * 24)


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


def frozen_datetime(stamp: str) -> Any:
    """settings_store.datetime の代わり（now だけ。触られた時刻を stamp に止める）。"""
    fixed = datetime.fromisoformat(stamp)

    class FrozenDatetime:
        """datetime.now(timezone.utc) がいつも同じ時刻を返す。"""

        @staticmethod
        def now(tz: Any = None) -> datetime:
            """決めた時刻。"""
            return fixed

    return FrozenDatetime


class Fakes:
    """偽物の Discord と、偽物の読み上げの API（どちらも fake_discord.FakeDiscord）。"""

    def __init__(self) -> None:
        """2 つ立てる。"""
        self.discord = fake_discord.FakeDiscord()
        self.tts = fake_discord.FakeDiscord()

    @property
    def tts_base(self) -> str:
        """TTS_BASE_URL に入れる場所（偽物の口。/api/v10 は付けない）。"""
        return self.tts.api_base[: -len(fake_discord.API_PREFIX)]

    def close(self) -> None:
        """2 つとも止める。"""
        self.discord.close()
        self.tts.close()


class FailingStore:
    """読み込めない置き場（読むたび・書くたびに SettingsNotLoaded）。"""

    def __init__(self, message: str) -> None:
        """投げる文を決める。"""
        self.message = message

    def snapshot(self) -> Any:
        """読む（いつも失敗）。"""
        from services.settings_pg import SettingsNotLoaded

        raise SettingsNotLoaded(self.message)

    def transact(self, fn: Any) -> Any:
        """書く（いつも失敗）。"""
        from services.settings_pg import SettingsNotLoaded

        raise SettingsNotLoaded(self.message)

    def version(self) -> int:
        """版番号（読めないので 0）。"""
        return 0

    def close(self) -> None:
        """止めるものは無い。"""


class Store:
    """例の設定の置き場（本物の PostgresSettings を SQLite に向けたもの）と、書き換えを呼んだ回数の控え。"""

    def __init__(self, spec: Any, library: dict[str, Any]) -> None:
        """置き場を作り、例の設定を取り込んで読み込みが済むまで待つ（読み込めない例は FailingStore）。"""
        self.engine: Any = None
        self.writes: list[int] = []
        legacy = harness.decode(spec, library)
        if isinstance(legacy, dict) and "$raise" in legacy:
            self.inner: Any = FailingStore(str(legacy.get("message", "")))
            return
        from sqlalchemy.orm import sessionmaker

        from services import settings_pg
        from tests.sqlite_session import FakeAsyncSession, sqlite_engine

        engine = sqlite_engine()
        maker = sessionmaker(bind=engine, expire_on_commit=False)

        async def create_tables() -> None:
            """本番と同じく checkfirst で表を作る。"""
            settings_pg.metadata.create_all(engine, checkfirst=True)

        def load_legacy() -> tuple[dict[str, Any], str]:
            """取り込み元（例の設定の写し）。"""
            return copy.deepcopy(legacy), "fixture"

        self.engine = engine
        self.inner = settings_pg.PostgresSettings(
            session_factory=lambda: FakeAsyncSession(maker()),
            create_tables=create_tables,
            load_legacy=load_legacy,
            dialect="sqlite",
            listen_dsn=None,
            poll_seconds=3600.0,
            write_timeout=10.0,
            load_timeout=30.0,
        )
        self.inner.snapshot()

    def snapshot(self) -> Any:
        """読む（settings_store._load_all が呼ぶ。本物の snapshot）。"""
        return self.inner.snapshot()

    def version(self) -> int:
        """手元の版番号。"""
        return int(self.inner.version())

    def transact(self, fn: Any) -> Any:
        """書く（本物の transact）。書いたあとの版番号を控える（失敗しても控える）。"""
        try:
            return self.inner.transact(fn)
        finally:
            self.writes.append(self.inner.version())

    def take_writes(self) -> list[int]:
        """控えた版番号（控えは空にする）。"""
        writes, self.writes = self.writes, []
        return writes

    def guilds(self) -> Any:
        """いまの手元の設定のギルド（鍵の順。中は鍵の並びのまま）。読み込めなければ None。"""
        if isinstance(self.inner, FailingStore):
            return None
        guilds = self.inner.snapshot()["guilds"]
        return harness.encode({key: guilds[key] for key in sorted(guilds)})

    def close(self) -> None:
        """置き場と SQLite を止める。"""
        self.inner.close()
        if self.engine is not None:
            self.engine.dispose()


def user_state_eraser(spec: Any, calls: list[str]) -> Any:
    """services.user_state_service.delete_guild_user_states の偽物（届いたサーバーの ID を控える）。"""

    async def delete_guild_user_states(guild_id: int) -> dict[str, int]:
        """例の答えを返す（{"$raise": …} なら RuntimeError）。"""
        calls.append(str(guild_id))
        if isinstance(spec, dict) and "$raise" in spec:
            raise RuntimeError(str(spec.get("message", "")))
        return {"events": int(spec["events"]), "states": int(spec["states"])}

    return delete_guild_user_states


def _patches(case: dict[str, Any], document: dict[str, Any], fakes: Fakes, state: dict[str, Any]) -> list[Any]:
    """例のあいだ差し替えるもの（行き先・設定の置き場・時刻・乱数・使い回しの入れ物・static・DEV_USER_ID）。"""
    from itsdangerous import TimestampSigner

    import services.settings_store as settings_store
    import services.tts_service as tts_service
    import services.user_state_service as user_state_service
    from webapp_admin import auth, metrics, security, templating
    from webapp_admin.schema import choices
    from webapp_admin.schema.panels import news_feeds

    clock: Clock = state["clock"]
    sequence: Sequence = state["sequence"]
    store: Store = state["store"]

    def signer_time(self: Any) -> int:
        """署名の時計（その要求の時刻の整数部）。"""
        return int(clock.now)

    security_secrets = types.SimpleNamespace(token_hex=sequence.token_hex, compare_digest=secrets.compare_digest)
    ids = types.SimpleNamespace(uuid4=sequence.uuid4)
    erased = case.get("user_states", {"events": 0, "states": 0})
    targets = [
        (auth, "_API", fakes.discord.api_base),
        (auth, "DISCORD_BOT_TOKEN", str(case.get("bot_token", document["discord"]["bot_token"]))),
        (auth, "_guild_count_cache", None),
        (auth, "_guild_channels_cache", {}),
        (auth, "_guild_channels_locks", state["locks"]),
        (auth, "_guild_channels_cooldown", {}),
        (auth, "time", clock),
        (metrics, "time", clock),
        (metrics, "uuid", ids),
        (news_feeds, "uuid", ids),
        (security, "secrets", security_secrets),
        (settings_store, "_BACKEND", "postgres"),
        (settings_store, "_pg", store),
        (settings_store, "datetime", frozen_datetime(document["stamp"])),
        (user_state_service, "delete_guild_user_states", user_state_eraser(erased, state["erased"])),
        (tts_service, "TTS_BASE_URL", fakes.tts_base),
        (choices, "_VOICES_TIMEOUT", VOICES_TIMEOUT),
        (templating, "_static_root", STATIC_ROOT),
        (TimestampSigner, "get_timestamp", signer_time),
    ]
    patches: list[Any] = [patch.object(target, name, value) for target, name, value in targets]
    dev = str(case.get("dev_user_id", document["dev_user_id"]))
    patches.append(patch.dict(os.environ, {"DEV_USER_ID": dev}))
    return patches


def repeated(value: Any) -> Any:
    """本文の印を開く（{"$repeat": 文字, "times": 回数} は文字をくり返したもの。並びと辞書の中も）。"""
    if isinstance(value, dict):
        if set(value) == {"$repeat", "times"}:
            return str(value["$repeat"]) * int(value["times"])
        return {key: repeated(item) for key, item in value.items()}
    if isinstance(value, list):
        return [repeated(item) for item in value]
    return value


def _send(client: Any, step: dict[str, Any], cookie: Any) -> Any:
    """1 つの要求を送り、応答を返す（TestClient の Cookie は毎回空にする）。"""
    headers = [(str(name).lower(), str(value)) for name, value in (step.get("headers") or {}).items()]
    if cookie is not None:
        headers.append(("cookie", f"{harness.COOKIE_NAME}={cookie}"))
    client.cookies.clear()
    options: dict[str, Any] = {}
    if "json" in step:
        options["json"] = repeated(step["json"])
    elif "body" in step:
        options["content"] = str(step["body"]).encode("utf-8")
    return client.request(step["method"], step["target"], headers=headers, follow_redirects=False, **options)


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


def _answers(case: dict[str, Any], step: dict[str, Any], key: str, library: dict[str, Any]) -> dict[str, Any]:
    """偽物の答え方（例のものに、要求のものを上書き）。"""
    return {**harness.decode(case.get(key) or {}, library), **harness.decode(step.get(key) or {}, library)}


class Runner:
    """1 つの例を回す（要求を順に送り、偽物に届いたもの・答え・書いたあとの設定を控える）。"""

    def __init__(self, app: Any, document: dict[str, Any], sessions: dict[str, Any], fakes: Fakes) -> None:
        """app・文書・名前のセッション・偽物を受け取る。"""
        self.app = app
        self.document = document
        self.sessions = sessions
        self.fakes = fakes
        self.library = document.get("library") or {}

    def _step(self, client: Any, case: dict[str, Any], step: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        """1 つの要求を送り、控えを作る。"""
        clock: Clock = state["clock"]
        store: Store = state["store"]
        clock.now = float(self.document["now"]) + float(step.get("at", 0))
        state["locks"].clear()
        discord_answers = _answers(case, step, "discord", self.library)
        tts_answers = _answers(case, step, "tts", self.library)
        self.fakes.discord.script(discord_answers)
        self.fakes.tts.script(tts_answers)
        cookie = None
        if "session" in step:
            session = self.sessions[step["session"]]
            cookie = harness.session_cookie(session, self.document["secret"], signed_at=int(clock.now))
        response = _send(client, step, cookie)
        seen_discord = self.fakes.discord.take()
        seen_tts = self.fakes.tts.take()
        unexpected = fake_discord.unexpected(seen_discord) + fake_discord.unexpected(seen_tts)
        if unexpected:
            raise SystemExit(f"{case['name']}: 例に書いていない要求: {', '.join(unexpected)}")
        expected_status = step.get("expect_status")
        if expected_status is not None and response.status_code != expected_status:
            raise SystemExit(
                f"{case['name']}: {step['target']} の状態が {response.status_code}（確かめでは {expected_status}）"
                f": {response.text[:300]}"
            )
        erased, state["erased"][:] = list(state["erased"]), []
        return {
            "at": step.get("at", 0),
            "now": clock.now,
            "request": _record_request(response),
            "discord_responses": discord_answers,
            "discord": seen_discord,
            "tts_responses": tts_answers,
            "tts": seen_tts,
            "response": harness.record_response(response),
            "settings": store.guilds(),
            "version": store.inner.version(),
            "writes": store.take_writes(),
            "user_states": erased,
        }

    def run(self, case: dict[str, Any]) -> dict[str, Any]:
        """例を回し、要求ごとの控えと、例で足した数とインシデントの行を返す。"""
        from starlette.testclient import TestClient

        from webapp_admin.extensions import limiter

        limiter.reset()
        _counters()
        before = _incident_bytes()
        store = Store(case.get("settings", {"guilds": {}}), self.library)
        state: dict[str, Any] = {
            "clock": Clock(float(self.document["now"])),
            "sequence": Sequence(),
            "locks": {},
            "store": store,
            "erased": [],
        }
        initial_version = store.inner.version()
        try:
            with ExitStack() as stack:
                for patcher in _patches(case, self.document, self.fakes, state):
                    stack.enter_context(patcher)
                client = TestClient(self.app, base_url=harness.BASE_URL, raise_server_exceptions=False)
                try:
                    steps = [self._step(client, case, step, state) for step in case["steps"]]
                finally:
                    client.close()
        finally:
            store.close()
        added = _incident_bytes()[len(before) :].decode("utf-8")
        spec = case.get("settings", {"guilds": {}})
        return {
            "name": case["name"],
            "settings": harness.encode(harness.decode(spec, self.library)),
            "initial_version": initial_version,
            "bot_token": str(case.get("bot_token", self.document["discord"]["bot_token"])),
            "dev_user_id": str(case.get("dev_user_id", self.document["dev_user_id"])),
            "user_states": case.get("user_states", {"events": 0, "states": 0}),
            "steps": steps,
            "counters": _counters(),
            "incidents": added.split("\n")[:-1] if added else [],
        }


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    extra = {
        "DISCORD_CLIENT_ID": document["discord"]["client_id"],
        "ADMIN_MONITOR_INTERVAL_SECONDS": "86400",
        **DJAUDIO_ENV,
    }
    harness.prepare_environment(document["secret"], extra)
    import config
    import services.tts_service  # noqa: F401  （差し替える前に読み込んでおく）
    import services.user_state_service  # noqa: F401
    from webapp_admin.app import app

    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    library = document.get("library") or {}
    sessions = {name: harness.decode(value, library) for name, value in document["sessions"].items()}
    fakes = Fakes()
    try:
        runner = Runner(app, document, sessions, fakes)
        cases = [runner.run(case) for case in document["cases"]]
    finally:
        fakes.close()
    return {
        "generated_by": GENERATED_BY,
        "base_url": harness.BASE_URL,
        "cookie_name": harness.COOKIE_NAME,
        "secret": document["secret"],
        "now": document["now"],
        "stamp": document["stamp"],
        "token_base": TOKEN_BASE,
        "id_base": ID_BASE,
        "voices_timeout": VOICES_TIMEOUT,
        "discord": document["discord"],
        "djaudio": {
            "cache_ttl": config.DJAUDIO_CACHE_TTL,
            "cooldown": config.DJAUDIO_COOLDOWN,
            "max_urls": config.DJAUDIO_MAX_URLS,
        },
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
