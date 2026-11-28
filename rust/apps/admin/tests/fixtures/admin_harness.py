"""管理画面の API の基準（expected.json）を作る道具の共通部分。Rust の管理画面（rust/apps/admin）のテストが読む。

本物の Python の管理画面（webapp_admin/app.py の app）を FastAPI の TestClient で叩き、例ごとに、送った要求・偽物の
services に届いた呼び出し・応答（状態・見出し・本文）を書き出す。外のもの（Postgres・Valkey・Discord）にはつながない。
services の関数は、API のモジュールが import した名前のところで差し替える（tests/test_admin_api.py と同じやり方）。
使い方は users_state/generate.py を見る。新しい API の基準は、それを写して作る（W2 の計画の「基準の作り方の型」）。

どの API の基準でも同じに決めてあること:

- セッションの Cookie は starlette の SessionMiddleware と同じ作り方（JSON を base64 にして itsdangerous の
  TimestampSigner で署名）。署名の時計（TimestampSigner.get_timestamp）は例の文書の now に止める。管理画面が Cookie を
  読むときも、応答の Set-Cookie を書くときも同じ時計なので、Set-Cookie は毎回同じ値になる。Rust のテストも時計を now に
  合わせること
- 送る Cookie（例の cookie）: fresh は now に署名、edge は now - 3600（期限ちょうど。まだ読める）、expired は
  now - 3601、future は now + 1、tampered は fresh の 1 文字目を変えたもの。session を書かない例は Cookie を送らない
- 例の中の値は JSON で書き、JSON に無いものだけ印を付ける。{"$datetime": "2026-08-21T03:30:00+00:00"} は
  datetime.fromisoformat（時差を書かなければ時差の無い datetime）。{"$ref": "名前"} は文書の library の値、
  {"$ref": "名前", "with": {...}} はそれに上書きしたもの。偽物の戻り値に {"$raise": "RuntimeError", "message": "…"}
  と書くと、その関数は例外を投げる。例に書いていない関数が呼ばれたら、作り直しを止める（例の書き漏らし）
- 基準に書く呼び出しの引数で、64 ビットに収まらない整数は {"$int": "99999999999999999999"} にする（Rust の
  serde_json は、そのまま数で書くと浮動小数に丸めて読むため）。例の中でも同じ印で書ける
- 例の expect_status は道具の確かめ（Cookie の作り方が starlette と食い違っていないか）。違えば作り直しを止める
- 地方時は本番と同じ日本時間（TZ=JST-9。本番は TZ=Asia/Tokyo。tzdata が無くても同じになる書き方）
- 管理画面の振る舞いを変える環境変数（FLASK_SECURE_COOKIES・DEV_USER_ID・DISCORD_* など）は消してから import する。
  要る例は prepare_environment の extra で渡す
- 見出しは名前（小文字）の順に並べ直す（同じ名前の中は Python の順のまま）。allow の値は語を並べ直す（Python の set の
  並びで、起動のたびに変わりうるため）
"""

from __future__ import annotations

import base64
import builtins
import json
import os
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator

ROOT = Path(__file__).resolve().parents[5]
BASE_URL = "http://testserver"
COOKIE_NAME = "admin_session"
# starlette の SessionMiddleware に渡している max_age（webapp_admin/app.py の _register_middleware）。
MAX_AGE = 3600
# 送る Cookie の署名の時刻を now からどれだけずらすか（モジュールの説明）。
COOKIE_OFFSETS = {"fresh": 0, "edge": -MAX_AGE, "expired": -(MAX_AGE + 1), "future": 1, "tampered": 0}
# 管理画面の振る舞いを変える環境変数。CI や手元に残っていても基準が変わらないよう、import の前に消す。
_CLEARED_ENV = (
    "ADMIN_ASSET_VERSION",
    "ADMIN_MONITOR_DIR",
    "DEV_USER_ID",
    "DISCORD_BOT_TOKEN",
    "DISCORD_CLIENT_ID",
    "DISCORD_CLIENT_SECRET",
    "DISCORD_OAUTH_PROMPT",
    "DISCORD_REDIRECT_URI",
    "FLASK_SECURE_COOKIES",
    "METRICS_ALLOWED_CIDRS",
    "METRICS_PATH",
    "SETTINGS_BACKEND",
)


def prepare_environment(secret: str, extra: dict[str, str] | None = None) -> None:
    """管理画面を import する前に、環境変数と地方時を決め、リポジトリを import できるようにする。

    services の一部は import した時点で SETTINGS_DIR などを読むので、webapp_admin を import する前に呼ぶこと。
    置き場はどれも使い捨ての一時ディレクトリ（本物の設定・ログ・キャッシュには触らない）。
    """
    for name in _CLEARED_ENV:
        os.environ.pop(name, None)
    os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="admin-fixture-settings-")
    os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp(prefix="admin-fixture-cache-")
    os.environ["ADMIN_FLASK_SECRET_KEY"] = secret
    os.environ["ADMIN_LIMITER_STORAGE_URI"] = "memory://"
    os.environ["TTS_BASE_URL"] = "http://127.0.0.1:9"
    os.environ.update(extra or {})
    os.environ["TZ"] = "JST-9"
    if hasattr(time, "tzset"):
        time.tzset()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def decode(value: Any, library: dict[str, Any]) -> Any:
    """例の JSON を Python の値にする（印の意味はモジュールの説明）。"""
    if isinstance(value, list):
        return [decode(item, library) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"$datetime"}:
        return datetime.fromisoformat(value["$datetime"])
    if set(value) == {"$int"}:
        return int(value["$int"])
    if "$ref" in value and set(value) <= {"$ref", "with"}:
        base = decode(library[value["$ref"]], library)
        if "with" in value:
            base = {**base, **decode(value["with"], library)}
        return base
    return {key: decode(item, library) for key, item in value.items()}


def encode(value: Any) -> Any:
    """Python の値を、例と同じ書き方の JSON にする（datetime と 64 ビットに収まらない整数は印、タプルは配列）。"""
    if isinstance(value, datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**64:
        return {"$int": str(value)}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {str(key): encode(item) for key, item in value.items()}
    return value


def _exception(spec: dict[str, Any]) -> Exception:
    """{"$raise": "RuntimeError", "message": "…"} から、投げる例外を作る（組み込みの例外だけ）。"""
    kind = getattr(builtins, str(spec["$raise"]), None)
    if not (isinstance(kind, type) and issubclass(kind, Exception)):
        raise SystemExit(f"$raise に書けるのは組み込みの例外だけ: {spec['$raise']}")
    return kind(str(spec.get("message", "")))


def fake_function(
    name: str,
    result: Any,
    calls: list[dict[str, Any]],
    library: dict[str, Any],
    *,
    is_async: bool = True,
) -> Callable[..., Any]:
    """呼ばれたら引数を calls に控え、決めた値を返す（または例外を投げる）偽物を作る。

    戻り値は呼ばれるたびに作り直す（API が戻り値を書き換えても、次の呼び出しに響かない）。
    """

    def answer(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        """控えてから、決めた値を返すか例外を投げる。"""
        calls.append({"fn": name, "args": encode(list(args)), "kwargs": encode(dict(kwargs))})
        if isinstance(result, dict) and "$raise" in result:
            raise _exception(result)
        return decode(result, library)

    async def fake_async(*args: Any, **kwargs: Any) -> Any:
        """async の services の偽物。"""
        return answer(args, kwargs)

    def fake_sync(*args: Any, **kwargs: Any) -> Any:
        """同期の services の偽物。"""
        return answer(args, kwargs)

    return fake_async if is_async else fake_sync


def unexpected_function(name: str, calls: list[dict[str, Any]], *, is_async: bool = True) -> Callable[..., Any]:
    """例に書いていない services の偽物。呼ばれたら控えて例外を投げる（run_case が作り直しを止める）。"""
    spec = {"$raise": "RuntimeError", "message": f"例に書いていない {name} が呼ばれた"}
    inner = fake_function(name, spec, calls, {}, is_async=is_async)

    async def flagged_async(*args: Any, **kwargs: Any) -> Any:
        """呼ばれたことに印を付けてから、偽物に回す。"""
        calls.append({"fn": name, "unexpected": True})
        return await inner(*args, **kwargs)

    def flagged_sync(*args: Any, **kwargs: Any) -> Any:
        """同期の版。"""
        calls.append({"fn": name, "unexpected": True})
        return inner(*args, **kwargs)

    return flagged_async if is_async else flagged_sync


@contextmanager
def frozen_signer_clock(now: int) -> Iterator[None]:
    """itsdangerous の署名の時計を now に止める（Cookie を作るときも、管理画面が読み書きするときも）。"""
    from unittest.mock import patch

    from itsdangerous import TimestampSigner

    with patch.object(TimestampSigner, "get_timestamp", lambda self: now):
        yield


def session_cookie(session: dict[str, Any], secret: str, *, signed_at: int) -> str:
    """starlette の SessionMiddleware が書くのと同じ形の Cookie の値（署名した時刻は signed_at）。"""
    from itsdangerous import TimestampSigner

    data = base64.b64encode(json.dumps(session).encode("utf-8"))
    with frozen_signer_clock(signed_at):
        return TimestampSigner(secret).sign(data).decode("utf-8")


def cookie_header(case: dict[str, Any], document: dict[str, Any]) -> str | None:
    """例の session と cookie から、送る Cookie の見出しを作る（session が無い例は None）。"""
    name = case.get("session")
    if name is None:
        return None
    mode = case.get("cookie", "fresh")
    if mode not in COOKIE_OFFSETS:
        raise SystemExit(f"{case['name']}: 知らない cookie の作り方: {mode}")
    now = int(document["now"])
    value = session_cookie(document["sessions"][name], document["secret"], signed_at=now + COOKIE_OFFSETS[mode])
    if mode == "tampered":
        value = ("f" if value[0] != "f" else "e") + value[1:]
    return f"{COOKIE_NAME}={value}"


def _header_value(name: str, value: str) -> str:
    """見出しの値を比べられる形にする（allow だけ、語の並びを決める。モジュールの説明）。"""
    if name == "allow":
        return ", ".join(sorted(part.strip() for part in value.split(",")))
    return value


def record_response(response: Any) -> dict[str, Any]:
    """応答を比べられる形にする（状態・見出し・本文。本文が JSON なら読んだものも添える）。"""
    pairs = [[name.lower(), _header_value(name.lower(), value)] for name, value in response.headers.multi_items()]
    body = response.content.decode("utf-8")
    is_json = response.headers.get("content-type", "").startswith("application/json")
    return {
        "status": response.status_code,
        "headers": sorted(pairs, key=lambda pair: pair[0]),
        "body": body,
        "json": json.loads(body) if is_json and body else None,
    }


def request_headers(case: dict[str, Any], cookie: str | None) -> dict[str, str]:
    """例の要求に付ける見出し（例の headers と Cookie）。"""
    headers = {str(key).lower(): str(value) for key, value in (case.get("headers") or {}).items()}
    if cookie is not None:
        headers["cookie"] = cookie
    return headers


def send(app: Any, case: dict[str, Any], headers: dict[str, str]) -> Any:
    """例の要求を 1 回送り、応答を返す（リダイレクトは追わない。起動時の処理は動かさない）。

    TestClient を with で開かないのは、起動時の処理（設定の読み込み・メトリクスの報告）を動かさないため
    （tests/test_admin_api.py と同じ）。例ごとに作り直すのは、前の例の Set-Cookie を持ち越さないため。
    """
    from starlette.testclient import TestClient

    client = TestClient(app, base_url=BASE_URL)
    try:
        return client.request(
            case["method"],
            case["target"],
            headers=headers,
            json=case.get("json"),
            data=case.get("form"),
            follow_redirects=False,
        )
    finally:
        client.close()


def run_case(
    app: Any,
    case: dict[str, Any],
    document: dict[str, Any],
    patches: Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], list[Any]],
) -> dict[str, Any]:
    """1 つの例を回し、送った要求・偽物に届いた呼び出し・応答を返す。

    patches は（例の service・呼び出しを控える list・library）から、差し替える patch の並びを作る関数
    （API ごとに違う。users_state/generate.py の _patches）。
    """
    calls: list[dict[str, Any]] = []
    headers = request_headers(case, cookie_header(case, document))
    with ExitStack() as stack:
        for patcher in patches(case.get("service") or {}, calls, document.get("library") or {}):
            stack.enter_context(patcher)
        stack.enter_context(frozen_signer_clock(int(document["now"])))
        response = send(app, case, headers)
    unexpected = [call["fn"] for call in calls if call.get("unexpected")]
    if unexpected:
        raise SystemExit(f"{case['name']}: 例に書いていない {', '.join(unexpected)} が呼ばれた")
    expected_status = case.get("expect_status")
    if expected_status is not None and response.status_code != expected_status:
        raise SystemExit(f"{case['name']}: 状態が {response.status_code}（道具の確かめでは {expected_status}）")
    request: dict[str, Any] = {
        "method": case["method"],
        "target": response.request.url.raw_path.decode("ascii"),
        "headers": sorted([name, value] for name, value in headers.items()),
    }
    for key in ("json", "form"):
        if case.get(key) is not None:
            request[key] = case[key]
    return {"name": case["name"], "request": request, "calls": calls, "response": record_response(response)}


def run_cases(
    app: Any,
    document: dict[str, Any],
    patches: Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], list[Any]],
) -> list[dict[str, Any]]:
    """文書の例を順に回す。例の名前が重なっていたら止める（Rust のテストは名前で引く）。"""
    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    return [run_case(app, case, document, patches) for case in document["cases"]]


def header(document: dict[str, Any], generated_by: str) -> dict[str, Any]:
    """基準の先頭に置く、Rust のテストが要求を作り直すのに要る値。"""
    return {
        "generated_by": generated_by,
        "base_url": BASE_URL,
        "cookie_name": COOKIE_NAME,
        "secret": document["secret"],
        "now": int(document["now"]),
        "max_age": MAX_AGE,
    }


def write_json(path: Path, data: Any) -> None:
    """基準を書き出す（UTF-8・LF・字下げ 1・末尾に改行。キーの並びは作った順のまま）。"""
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
