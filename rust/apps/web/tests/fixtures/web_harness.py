"""Web（貴金属の公開サイト）の API の基準（expected.json）を作る道具の共通部分。Rust の Web（rust/apps/web）が読む。

本物の Python の Web（webapp/app.py の app）を FastAPI の TestClient で叩き、要求ごとに、送った要求・偽物に届いた
呼び出し・応答（状態・見出し・本文）を書き出す。外のもの（Postgres・Valkey・MetalpriceAPI・Groq・Push の送り先）には
つながない。DB や外へ行く関数は webapp/app.py が import した名前のところで差し替え、DB のセッション
（Depends(get_db_session)）は app.dependency_overrides で偽物に替える（tests/test_webapp.py と同じやり方）。
使い方は prices_calculate/generate.py を見る。新しい API の基準は、それを写して作る（W3 の計画の「基準の作り方の型」）。

管理画面の道具（rust/apps/admin/tests/fixtures/admin_harness.py）と同じ決めごとで書いてある。Web で足したもの・
違うもの:

- 1 つの例は要求の並び（requests）。応答のキャッシュ（webapp/app.py の 4 つの TTLCache）とレート制限の数え
  （RateLimitMiddleware）は、例の始めに空にして、例の中では持ち越す（2 回目がキャッシュから返る・上限を超えた回が
  429 になる、を例にできる）。要求に repeat を書くと、同じ要求をその回数送る（1 回ずつ記録する）
- 値の印は管理画面と同じもの（$datetime・$int・$ref/with・$raise）に、$date（date.fromisoformat）・$decimal
  （Decimal。文字列で書く）・$row（属性で読める行。SQLAlchemy の行の代わり）を足した。with を重ねられるのは辞書
  だけ。基準には $ref を開いたあとの service も書く（Rust のテストは expected.json だけを読めばよい）
- DB のセッションの偽物は {"$session": true} と書き出す。API がセッションに直に触ったら（差し替えていない DB の
  操作）、例に書いていない関数と同じく作り直しを止める
- 接続元（request.client）は要求の client（無ければ DEFAULT_CLIENT）。本番では uvicorn が X-Forwarded-For で
  直したあとの接続元にあたる（直し方は sycs-web の proxy の基準が決める）。アプリが見るのはここから先だけ
- 圧縮は要求で明示する。accept-encoding を書かない要求は identity を送る。GZipMiddleware は 500 バイト以上を
  gzip にするが、圧縮した中身と長さは zlib の版で変わりうるので、基準で比べるのは圧縮しない応答にする
- 時計: 例の文書の now に、webapp/app.py の datetime.now を止める（ほかのモジュールは道具ごとに足す）。
  キャッシュの期限とレート制限の窓は time.monotonic のまま（1 つの例は窓の 60 秒より十分短く終わる）
- 環境変数: Web の振る舞いを変えるものは全部消してから、FIXTURE_ENV（と道具ごとの extra）を入れて import する。
  入れたものは基準の env に書く（Rust のテストは同じ設定で app を組む）。DB の接続先は使われない番地にしておく
  （差し替え漏れがあっても本物の DB には届かず、すぐに失敗する）
- 500 も記録する（TestClient の raise_server_exceptions=False）。starlette の ServerErrorMiddleware が返す素の
  「Internal Server Error」で、見出しのミドルウェアより外なので CSP などは付かない
- 見出しは名前（小文字）の順に並べ直す（同じ名前の中は Python の順のまま）。allow の値は語を並べ直す
  （管理画面と同じ）。本文は UTF-8 の文字列で書き、読めないもの（画像など）だけ body_base64 に書く
- 例の note（何を確かめる例か）は基準にも写す（Rust のテストが落ちたときの言葉に使える）
"""

from __future__ import annotations

import base64
import builtins
import importlib
import json
import os
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from datetime import date, datetime, tzinfo
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator, Callable, Iterator

ROOT = Path(__file__).resolve().parents[5]
BASE_URL = "http://testserver"
WEB_MODULE = "webapp.app"
# 接続元の既定（TEST-NET-2。信頼するプロキシの帯域の外）。ポートはアプリが見ないので固定。
DEFAULT_CLIENT = "198.51.100.7"
CLIENT_PORT = 50000
# 要求に書かなくても付ける見出し（モジュールの説明の「圧縮」）。
DEFAULT_HEADERS = {"accept-encoding": "identity", "user-agent": "sycs-fixture"}
# webapp/app.py の応答のキャッシュ（例の始めに空にする）。
CACHE_NAMES = ("history_cache", "latest_prices_cache", "calculate_cache", "forecast_cache")
# DB や外へ行く、webapp/app.py が import した関数（どれも async）。例の service に書かなかったものが呼ばれたら止める。
WEB_SERVICES = (
    "load_latest_rows",
    "load_history",
    "load_earliest_snapshot_date",
    "load_stored_weekly_forecast",
    "validate_public_http_url_async",
)
# Web の振る舞いを変える環境変数（基準の env に書く）。レート制限の上限は、例を短くするために小さくしてある。
FIXTURE_ENV = {
    "ALLOWED_HOSTS": "testserver,localhost,127.0.0.1,::1",
    "TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128,172.16.0.0/12",
    "API_RATE_LIMIT_PER_MINUTE": "8",
    "API_CALCULATE_RATE_LIMIT_PER_MINUTE": "5",
    "TRUST_CF_HEADERS": "false",
    "REQUIRE_CF_CONNECTING_IP": "false",
    "APP_PUBLIC_PATH": "/",
    "WEB_SCHEDULER_ENABLED": "false",
    "METAL_AUTO_REPAIR_ENABLED": "false",
    "VAPID_AUTO_GENERATE": "false",
}
# import の前に消す環境変数の頭と名前（CI や手元に残っていても基準が変わらないように）。
_CLEARED_PREFIXES = (
    "API_",
    "APP_",
    "DB_",
    "FORECAST_",
    "GROQ_",
    "METAL",
    "POSTGRES_",
    "PURITY_",
    "PUSH_",
    "STARTUP_TEST_",
    "USER_STATE_POSTGRES_",
    "VALKEY_",
    "VAPID_",
    "WEB_",
)
_CLEARED_NAMES = ("ALLOWED_HOSTS", "TRUSTED_PROXY_CIDRS", "TRUST_CF_HEADERS", "REQUIRE_CF_CONNECTING_IP")
# 使われない番地（discard の 9 番）。差し替え漏れがあっても本物の DB には届かず、すぐに失敗する。
_UNREACHABLE_DSN = "postgresql+asyncpg://fixture:fixture@127.0.0.1:9/fixture"


def prepare_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Web を import する前に、環境変数と地方時を決め、リポジトリを import できるようにする。

    webapp/app.py は import した時点で環境変数を読む（レート制限・許すホスト・キャッシュの秒数など）ので、
    import より前に呼ぶこと。戻り値は基準の env に書くもの（FIXTURE_ENV に extra を重ねたもの）。
    置き場（設定・VAPID の鍵）はどれも使い捨ての一時ディレクトリで、基準には書かない（振る舞いを変えない）。
    """
    for name in list(os.environ):
        if name.startswith(_CLEARED_PREFIXES) or name in _CLEARED_NAMES:
            del os.environ[name]
    env = {**FIXTURE_ENV, **(extra or {})}
    os.environ.update(env)
    os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="web-fixture-settings-")
    os.environ["VAPID_KEYS_DIR"] = tempfile.mkdtemp(prefix="web-fixture-vapid-")
    os.environ["POSTGRES_DSN"] = _UNREACHABLE_DSN
    os.environ["TZ"] = "JST-9"
    if hasattr(time, "tzset"):
        time.tzset()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return env


def load_web(extra: dict[str, str] | None = None) -> tuple[Any, dict[str, str]]:
    """環境を整えてから webapp/app.py を読み込み、（モジュール, 基準に書く環境変数）を返す。"""
    env = prepare_environment(extra)
    return importlib.import_module(WEB_MODULE), env


def decode(value: Any, library: dict[str, Any]) -> Any:
    """例の JSON を Python の値にする（印の意味はモジュールの説明）。"""
    if isinstance(value, list):
        return [decode(item, library) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"$datetime"}:
        return datetime.fromisoformat(value["$datetime"])
    if set(value) == {"$date"}:
        return date.fromisoformat(value["$date"])
    if set(value) == {"$decimal"}:
        return Decimal(value["$decimal"])
    if set(value) == {"$int"}:
        return int(value["$int"])
    if set(value) == {"$row"}:
        return SimpleNamespace(**decode(value["$row"], library))
    if "$ref" in value and set(value) <= {"$ref", "with"}:
        base = decode(library[value["$ref"]], library)
        if "with" in value:
            base = {**base, **decode(value["with"], library)}
        return base
    return {key: decode(item, library) for key, item in value.items()}


def encode(value: Any) -> Any:
    """Python の値を、例と同じ書き方の JSON にする（印はモジュールの説明。タプルは配列）。"""
    if isinstance(value, FakeSession):
        return {"$session": True}
    if isinstance(value, datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, date):
        return {"$date": value.isoformat()}
    if isinstance(value, Decimal):
        return {"$decimal": str(value)}
    if isinstance(value, SimpleNamespace):
        return {"$row": encode(vars(value))}
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
        """async の関数の偽物。"""
        return answer(args, kwargs)

    def fake_sync(*args: Any, **kwargs: Any) -> Any:
        """同期の関数の偽物。"""
        return answer(args, kwargs)

    return fake_async if is_async else fake_sync


def unexpected_function(name: str, calls: list[dict[str, Any]], *, is_async: bool = True) -> Callable[..., Any]:
    """例に書いていない関数の偽物。呼ばれたら控えて例外を投げる（run_case が作り直しを止める）。"""
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


class FakeSession:
    """DB のセッションの偽物。API が直に触ったら控えて止める（DB に触るのは差し替えた関数だけのはず）。"""

    def __init__(self, calls: list[dict[str, Any]]) -> None:
        """触られたことを書く控え（例の calls）を受け取る。"""
        self._calls = calls

    def __getattr__(self, name: str) -> Any:
        """どの属性を引かれても、控えてから例外を投げる（例の書き漏らし。run_case が作り直しを止める）。"""
        self._calls.append({"fn": f"session.{name}", "unexpected": True})
        raise RuntimeError(f"例に書いていない DB の操作 session.{name} が呼ばれた")


def service_patches(
    names: tuple[str, ...],
    service: dict[str, Any],
    calls: list[dict[str, Any]],
    library: dict[str, Any],
) -> list[Any]:
    """webapp/app.py が import した名前を、例の service の偽物（書いていなければ止める偽物）に差し替える patch を作る。

    service の鍵は関数の名前そのもの。names に無い鍵が書いてあったら止める（書き間違えると偽物が効かず、
    「書いていない関数が呼ばれた」で止まるまで原因が分からないため）。
    """
    from unittest.mock import patch

    unknown = sorted(set(service) - set(names))
    if unknown:
        raise SystemExit(f"差し替えられない service の鍵: {', '.join(unknown)}")
    patchers = []
    for name in names:
        if name in service:
            fake = fake_function(name, service[name], calls, library)
        else:
            fake = unexpected_function(name, calls)
        patchers.append(patch(f"{WEB_MODULE}.{name}", fake))
    return patchers


@contextmanager
def frozen_clock(now: datetime, modules: tuple[str, ...]) -> Iterator[None]:
    """モジュールが import した datetime の now() を、例の文書の now に止める（ほかの働きはそのまま）。"""
    from unittest.mock import patch

    class FrozenDatetime(datetime):
        """now() だけを止めた datetime。"""

        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            """止めた時刻を、渡された時差で返す（時差を渡されなければ地方時の、時差の無い時刻）。"""
            if tz is None:
                return now.astimezone().replace(tzinfo=None)
            return now.astimezone(tz)

    with ExitStack() as stack:
        for module in modules:
            stack.enter_context(patch(f"{module}.datetime", FrozenDatetime))
        yield


class ClientAddress:
    """要求ごとの接続元（request.client）を差し込む ASGI の包み。TestClient の既定（testclient）は IP にならない。"""

    def __init__(self, app: Any) -> None:
        """包む app を受け取る。接続元は DEFAULT_CLIENT から始める。"""
        self.app = app
        self.host = DEFAULT_CLIENT

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """http の要求だけ、scope の client をいまの接続元に替えて渡す。"""
        if scope["type"] == "http":
            scope = {**scope, "client": (self.host, CLIENT_PORT)}
        await self.app(scope, receive, send)


def reset_state(web: Any) -> None:
    """例の始めに、前の例から持ち越す状態（応答のキャッシュ・レート制限の数え）を空にする。

    キャッシュは一次（プロセス内）だけを消す。二次（Valkey）は VALKEY_URL を消してあるので使われない。
    レート制限の数えはミドルウェアの中にあるので、ミドルウェアの組を作り直させる（starlette は
    middleware_stack が None なら、次の要求で組み直す）。
    """
    for name in CACHE_NAMES:
        getattr(web, name)._data.clear()
    web.app.middleware_stack = None


def request_headers(spec: dict[str, Any]) -> dict[str, str]:
    """要求に付ける見出し（DEFAULT_HEADERS に要求の headers を重ねたもの。名前は小文字）。"""
    headers = dict(DEFAULT_HEADERS)
    headers.update({str(key).lower(): str(value) for key, value in (spec.get("headers") or {}).items()})
    return headers


def _header_value(name: str, value: str) -> str:
    """見出しの値を比べられる形にする（allow だけ、語の並びを決める。管理画面と同じ）。"""
    if name == "allow":
        return ", ".join(sorted(part.strip() for part in value.split(",")))
    return value


def record_response(response: Any) -> dict[str, Any]:
    """応答を比べられる形にする（状態・見出し・本文。本文が JSON なら読んだものも添える）。"""
    pairs = [[name.lower(), _header_value(name.lower(), value)] for name, value in response.headers.multi_items()]
    record: dict[str, Any] = {"status": response.status_code, "headers": sorted(pairs, key=lambda pair: pair[0])}
    try:
        body = response.content.decode("utf-8")
    except UnicodeDecodeError:
        record["body_base64"] = base64.b64encode(response.content).decode("ascii")
        record["json"] = None
        return record
    is_json = response.headers.get("content-type", "").startswith("application/json")
    record["body"] = body
    record["json"] = json.loads(body) if is_json and body else None
    return record


def send(client: Any, spec: dict[str, Any], headers: dict[str, str]) -> Any:
    """要求を 1 回送り、応答を返す（リダイレクトは追わない）。content は JSON にしない生の本文（壊れた JSON など）。"""
    return client.request(
        spec["method"],
        spec["target"],
        headers=headers,
        json=spec.get("json"),
        content=spec.get("content"),
        follow_redirects=False,
    )


def _expanded(case: dict[str, Any]) -> list[dict[str, Any]]:
    """例の requests を、repeat を開いた 1 回ずつの並びにする。"""
    specs: list[dict[str, Any]] = []
    for spec in case["requests"]:
        specs.extend([spec] * int(spec.get("repeat", 1)))
    return specs


def _step(client: Any, wrapper: ClientAddress, spec: dict[str, Any], calls: list[dict[str, Any]]) -> dict[str, Any]:
    """要求を 1 回送り、送った要求・その間に偽物に届いた呼び出し・応答を返す。"""
    headers = request_headers(spec)
    wrapper.host = str(spec.get("client", DEFAULT_CLIENT))
    start = len(calls)
    response = send(client, spec, headers)
    request: dict[str, Any] = {
        "method": spec["method"],
        "target": response.request.url.raw_path.decode("ascii"),
        "client": wrapper.host,
        "headers": sorted([name, value] for name, value in headers.items()),
    }
    for key in ("json", "content"):
        if spec.get(key) is not None:
            request[key] = spec[key]
    return {"request": request, "calls": calls[start:], "response": record_response(response)}


def _check(name: str, index: int, spec: dict[str, Any], step: dict[str, Any]) -> None:
    """道具の確かめ。例に書いていない関数が呼ばれた・状態が expect_status と違う、なら作り直しを止める。

    expect_status は、Python の振る舞いの見立てではなく道具の確かめに使う（偽物が効かずに全部 500 になる、
    許すホストの設定が効かずに全部 400 になる、を黙って基準にしない）。
    """
    unexpected = [call["fn"] for call in step["calls"] if call.get("unexpected")]
    if unexpected:
        raise SystemExit(f"{name} の {index} 回目: 例に書いていない {', '.join(unexpected)} が呼ばれた")
    expected = spec.get("expect_status")
    status = step["response"]["status"]
    if expected is not None and status != expected:
        raise SystemExit(f"{name} の {index} 回目: 状態が {status}（道具の確かめでは {expected}）")


def run_case(
    web: Any,
    case: dict[str, Any],
    document: dict[str, Any],
    patches: Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], list[Any]],
    clock_modules: tuple[str, ...] = (WEB_MODULE,),
) -> dict[str, Any]:
    """1 つの例（要求の並び）を回し、開いた service と、要求ごとの送った要求・呼び出し・応答を返す。

    patches は（例の service・呼び出しを控える list・library）から、差し替える patch の並びを作る関数
    （prices_calculate/generate.py の _patches）。状態（キャッシュ・レート制限）は例の始めに空にする。
    TestClient を with で開かないのは、起動時の処理（DB の移行・スケジューラ・メトリクス）を動かさないため
    （tests/test_webapp.py と同じ）。
    """
    from starlette.testclient import TestClient

    library = document.get("library") or {}
    service = case.get("service") or {}
    calls: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    reset_state(web)
    wrapper = ClientAddress(web.app)

    async def fake_db_session() -> AsyncIterator[FakeSession]:
        """Depends(get_db_session) の代わり。直に触られたら止まる偽物のセッションを渡す。"""
        yield FakeSession(calls)

    web.app.dependency_overrides[web.get_db_session] = fake_db_session
    client = TestClient(wrapper, base_url=BASE_URL, raise_server_exceptions=False)
    try:
        with ExitStack() as stack:
            for patcher in patches(service, calls, library):
                stack.enter_context(patcher)
            stack.enter_context(frozen_clock(datetime.fromisoformat(document["now"]), clock_modules))
            for index, spec in enumerate(_expanded(case), start=1):
                step = _step(client, wrapper, spec, calls)
                _check(case["name"], index, spec, step)
                steps.append(step)
    finally:
        client.close()
        web.app.dependency_overrides.pop(web.get_db_session, None)
    result: dict[str, Any] = {"name": case["name"]}
    if case.get("note"):
        result["note"] = case["note"]
    result["service"] = encode(decode(service, library))
    result["steps"] = steps
    return result


def run_cases(
    web: Any,
    document: dict[str, Any],
    patches: Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], list[Any]],
    clock_modules: tuple[str, ...] = (WEB_MODULE,),
) -> list[dict[str, Any]]:
    """文書の例を順に回す。例の名前が重なっていたら止める（Rust のテストは名前で引く）。"""
    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    return [run_case(web, case, document, patches, clock_modules) for case in document["cases"]]


def header(document: dict[str, Any], env: dict[str, str], generated_by: str) -> dict[str, Any]:
    """基準の先頭に置く、Rust のテストが app と要求を組み直すのに要る値。"""
    return {
        "generated_by": generated_by,
        "base_url": BASE_URL,
        "now": document["now"],
        "env": dict(sorted(env.items())),
        "default_client": DEFAULT_CLIENT,
        "default_headers": dict(sorted(DEFAULT_HEADERS.items())),
    }


def write_json(path: Path, data: Any) -> None:
    """基準を書き出す（UTF-8・LF・字下げ 1・末尾に改行。キーの並びは作った順のまま）。"""
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
