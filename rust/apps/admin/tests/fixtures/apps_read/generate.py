"""設定パネルの読む側（A5）の基準（expected.json）を、本物の Python と偽物の Discord・TTS で作る。

Rust の管理画面（rust/apps/admin）の tests/apps_read_golden.rs が読む。本物の管理画面（webapp_admin/app.py の app）を
starlette の TestClient で回す。層は全部本物（セッション・slowapi・見張り・見出し・数・例外の係・経路）。
Discord の API（webapp_admin/auth.py の _API）と読み上げの API（services/tts_service.py の TTS_BASE_URL）は、
どちらも ../fake_discord.py の偽物（2 つ立てる）へ向ける。設定は services.settings_store._load_all を差し替えて渡す。

経路: GET /admin/api/apps・/admin/api/apps/{id}（とその 405・307・404）と、公開トップ /（Bot のサーバー数が 0 か
失敗のときの、設定のあるサーバーの数。A3 のフォールバックを A5 の設定の置き場につないだもの）。

例（cases.json）は要求の並び（steps）を順に送る。例に書けるもの:

    settings                 設定の全体（{"guilds": {...}}。$ref が使える）。{"$raise": …, "message": …} なら
                             読み込めない（services.settings_pg.SettingsNotLoaded を投げる）
    discord・tts             偽物の答え方（step の discord・tts で上書き）。tts の鍵は "GET /api/v1/voices?locale=ja"
    dev_user_id              DEV_USER_ID（無ければ文書の dev_user_id）
    voices_timeout           声の一覧を待つ秒（webapp_admin/schema/choices.py の _VOICES_TIMEOUT。無ければ 3.0）

要求（steps）に書けるもの: method・target・headers・session（名前。その要求の時刻で署名した Cookie）・at（例の now
からの秒）・discord・tts・expect_status（道具の確かめ）。

2 回作ってバイトまで同じにするために決めてあること:

- 時刻（auth・metrics の time.time と、署名の時計）は要求ごとに now + at に止める
- CSRF の印は f"{TOKEN_BASE + n:064x}"、インシデントの ID は f"{ID_BASE + n:032x}"（例ごとに 1 から）
- チャンネルの一覧の使い回し・429 の待ち・Bot のサーバー数の使い回し・slowapi の数・数え口は例ごとに空にする。
  サーバーごとの錠（_guild_channels_locks）は要求ごとに空にする（TestClient は要求ごとに別のイベントループで回すので、
  前の要求の錠を使うと「別のループに結び付いた錠」で落ちる。本番は 1 つのループなので、錠を空にしても同じ）
- 偽物に届いた要求は中身で並べる（選択肢は並べて取るので、届く順は決まらない）
- HTML の資材の URL は static の置き場を無い場所にして ?v=admin の形にそろえる
- DJAudio の数の既定は環境変数（DJAUDIO_*）を Python の既定と違う値にして import する（Rust のテストも同じ値）

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/apps_read/generate.py

**`from __future__ import annotations` を書かないこと**（FastAPI が注釈を引けなくなる。errors/generate.py の説明）。
"""

import json
import os
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
GENERATED_BY = "rust/apps/admin/tests/fixtures/apps_read/generate.py"
TOKEN_BASE = 0xA5000000
ID_BASE = 0x1A500000
STATIC_ROOT = Path("/nonexistent-admin-fixture-static")
DEFAULT_VOICES_TIMEOUT = 3.0
# Python の既定（600・30・3）と違う値にして、Rust が環境変数を読んでいることも確かめる。
DJAUDIO_ENV = {
    "DJAUDIO_CACHE_TTL_SECONDS": "720",
    "DJAUDIO_COOLDOWN_SECONDS": "45",
    "DJAUDIO_MAX_URLS_PER_MSG": "4",
}


class Sequence:
    """例ごとに決まる CSRF の印・インシデントの ID の並び。"""

    def __init__(self) -> None:
        """1 つ目から数える。"""
        self.tokens = 0
        self.ids = 0

    def token_hex(self, nbytes: int = 32) -> str:
        """secrets.token_hex の代わり（長さは見ない）。"""
        self.tokens += 1
        return f"{TOKEN_BASE + self.tokens:064x}"

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


def settings_record(spec: Any, library: dict[str, Any]) -> Any:
    """基準に書く設定（$ref を開いたもの。読み込めない例は印のまま）。"""
    if isinstance(spec, dict) and "$raise" in spec:
        return {"$raise": "SettingsNotLoaded", "message": str(spec.get("message", ""))}
    return harness.decode(spec, library)


def settings_loader(spec: Any, library: dict[str, Any]) -> Any:
    """settings_store._load_all の偽物（例の settings。{"$raise": …} なら SettingsNotLoaded を投げる）。"""
    from services.settings_pg import SettingsNotLoaded

    def load_all() -> Any:
        """呼ばれるたびに例の中身を作り直して返す。"""
        if isinstance(spec, dict) and "$raise" in spec:
            raise SettingsNotLoaded(str(spec.get("message", "")))
        return harness.decode(spec, library)

    return load_all


def _patches(case: dict[str, Any], document: dict[str, Any], fakes: Fakes, state: dict[str, Any]) -> list[Any]:
    """例のあいだ差し替えるもの（行き先・設定・時刻・乱数・使い回しの入れ物・static・DEV_USER_ID）。"""
    from itsdangerous import TimestampSigner

    import services.settings_store as settings_store
    import services.tts_service as tts_service
    from webapp_admin import auth, metrics, security, templating
    from webapp_admin.schema import choices

    clock: Clock = state["clock"]
    sequence: Sequence = state["sequence"]

    def signer_time(self: Any) -> int:
        """署名の時計（その要求の時刻の整数部）。"""
        return int(clock.now)

    library = document.get("library") or {}
    security_secrets = types.SimpleNamespace(token_hex=sequence.token_hex, compare_digest=secrets.compare_digest)
    timeout = float(case.get("voices_timeout", DEFAULT_VOICES_TIMEOUT))
    targets = [
        (auth, "_API", fakes.discord.api_base),
        (auth, "DISCORD_BOT_TOKEN", document["discord"]["bot_token"]),
        (auth, "_guild_count_cache", None),
        (auth, "_guild_channels_cache", {}),
        (auth, "_guild_channels_locks", state["locks"]),
        (auth, "_guild_channels_cooldown", {}),
        (auth, "time", clock),
        (metrics, "time", clock),
        (metrics, "uuid", types.SimpleNamespace(uuid4=sequence.uuid4)),
        (security, "secrets", security_secrets),
        (settings_store, "_load_all", settings_loader(case.get("settings", {"guilds": {}}), library)),
        (tts_service, "TTS_BASE_URL", fakes.tts_base),
        (choices, "_VOICES_TIMEOUT", timeout),
        (templating, "_static_root", STATIC_ROOT),
        (TimestampSigner, "get_timestamp", signer_time),
    ]
    patches: list[Any] = [patch.object(target, name, value) for target, name, value in targets]
    dev = str(case.get("dev_user_id", document["dev_user_id"]))
    patches.append(patch.dict(os.environ, {"DEV_USER_ID": dev}))
    return patches


def _send(client: Any, step: dict[str, Any], cookie: Any) -> Any:
    """1 つの要求を送り、応答を返す（TestClient の Cookie は毎回空にする）。"""
    headers = [(str(name).lower(), str(value)) for name, value in (step.get("headers") or {}).items()]
    if cookie is not None:
        headers.append(("cookie", f"{harness.COOKIE_NAME}={cookie}"))
    client.cookies.clear()
    return client.request(step["method"], step["target"], headers=headers, follow_redirects=False)


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
    """1 つの例を回す（要求を順に送り、偽物に届いたものと答えを控える）。"""

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
            )
        return {
            "at": step.get("at", 0),
            "now": clock.now,
            "request": _record_request(response),
            "discord_responses": discord_answers,
            "discord": seen_discord,
            "tts_responses": tts_answers,
            "tts": seen_tts,
            "response": harness.record_response(response),
        }

    def run(self, case: dict[str, Any]) -> dict[str, Any]:
        """例を回し、要求ごとの控えと、例で足した数とインシデントの行を返す。"""
        from starlette.testclient import TestClient

        from webapp_admin.extensions import limiter

        limiter.reset()
        _counters()
        before = _incident_bytes()
        state: dict[str, Any] = {
            "clock": Clock(float(self.document["now"])),
            "sequence": Sequence(),
            "locks": {},
        }
        with ExitStack() as stack:
            for patcher in _patches(case, self.document, self.fakes, state):
                stack.enter_context(patcher)
            client = TestClient(self.app, base_url=harness.BASE_URL, raise_server_exceptions=False)
            try:
                steps = [self._step(client, case, step, state) for step in case["steps"]]
            finally:
                client.close()
        added = _incident_bytes()[len(before) :].decode("utf-8")
        return {
            "name": case["name"],
            "settings": settings_record(case.get("settings", {"guilds": {}}), self.library),
            "dev_user_id": str(case.get("dev_user_id", self.document["dev_user_id"])),
            "voices_timeout": float(case.get("voices_timeout", DEFAULT_VOICES_TIMEOUT)),
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
        "token_base": TOKEN_BASE,
        "id_base": ID_BASE,
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
