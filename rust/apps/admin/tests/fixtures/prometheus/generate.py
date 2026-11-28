"""Netdata が読む /metrics（webapp_admin/prometheus_view.py と services/metrics_registry.py）の基準（expected.json）を、
本物の Python で作る。Rust の管理画面（rust/apps/admin）の tests/prometheus_golden.rs が読む。

■ requests（いちばん大事。接続元の判定と本文）

本番と同じ並びで通す: **本物の uvicorn の ProxyHeadersMiddleware**（trusted_hosts は本物の
services/log_setup.trusted_proxies()。uvicorn を proxy_headers=True で起動したときと同じ包み方）→ 本物の管理画面
（webapp_admin/app.py の app。セッション・回数の制限・見張り・見出し・数・例外の係も本物）。ASGI の scope を直に作り、
直接つないできた相手（peer。None は分からない相手）と見出し（X-Forwarded-For など）を例のとおりに渡す。TestClient を
使わないのは、接続元が testclient に決まってしまうため。

差し替えるのは、Valkey（本物の SharedCache に、例の valkey の答えを返す偽物の client を client_factory で渡す。
SCAN の 1 ページずつ・MGET・途中で切れる・UTF-8 でない値・client を作れない）と、時刻（metrics_registry・
prometheus_view・webapp_admin.metrics の time）・_APP_STARTED_AT・_REQUEST_TIMESTAMPS。環境変数は例の env
（METRICS_ALLOWED_CIDRS・TRUSTED_PROXY_CIDRS・METRICS_STALE_AFTER_SECONDS）と、バックアップの状態のファイル
（BACKUP_STATUS_FILE を例ごとの置き場に向け、例の backup のとおりに置く）。

基準には例ごとに、Valkey から読めたもの（scan: 本物の SharedCache.scan_values の答えと、そのあとの available、
偽物に届いた SCAN・MGET の並び。Rust の偽物の Valkey の確かめにも使う）と、答え（状態・見出し〔名前の順〕・本文）を
書く。

■ functions

- metrics_path(): METRICS_PATH の値 → パス
- client_allowed(): METRICS_ALLOWED_CIDRS × 接続元の文字 → 通すか（帯域の読み方〔strict=False〕と、アドレスの
  読み方の表）
- _parse_float(): Valkey の値の文字 → 小数（repr）か読めない
- _format_value(): 小数（repr の文字）→ 書き方か例外の型の名前と文

例は 2 回作ってバイトまで同じになる（時刻・Valkey の中身・置き場をどれも例で決める）。本物の監視のスレッド（app を
読み込むと始まる）は間隔をとても長くして、起動のときの処理が済むのを待ってから回す。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/prometheus/generate.py

**`from __future__ import annotations` を書かないこと**（管理画面の道具の決まり）。
"""

import asyncio
import json
import os
import sys
import tempfile
import time
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/prometheus/generate.py"
# 例の env で決める環境変数（ほかから入っていても基準が変わらないよう、例ごとに消してから入れる）。
REQUEST_ENV = ("METRICS_ALLOWED_CIDRS", "TRUSTED_PROXY_CIDRS", "METRICS_STALE_AFTER_SECONDS", "METRICS_PATH")
# 本物の監視のスレッドを眠らせておく間隔（秒）。
IDLE_INTERVAL = "1000000000"
# 偽物の Valkey の名前空間（services/metrics_registry.NAMESPACE）。
NAMESPACE = "metrics"


class FakeClock:
    """各モジュールの time の代わり（time() は例の時刻。monotonic・sleep は本物）。"""

    def __init__(self, now: float) -> None:
        """止める時刻を決める。"""
        self._now = now

    def time(self) -> float:
        """止めた時刻。"""
        return self._now

    def monotonic(self) -> float:
        """本物の monotonic（遮断器が使う）。"""
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        """本物の sleep。"""
        time.sleep(seconds)


class FakeRedis:
    """redis.asyncio の client の代わり。例の valkey（pages・values・hex_values・fail_at）のとおりに答え、控える。

    SCAN のカーソルは pages の何ページ目か（最後のページの次は 0）。MGET は values の値（無ければ None）。hex_values に
    ある鍵は、UTF-8 でない値（本物は答えを文字にするところで UnicodeDecodeError）。fail_at 番目（0 から。SCAN と MGET を
    通して数える）の呼び出しは、つながりが切れたことにする（ConnectionError）。
    """

    def __init__(self, spec: dict[str, Any], calls: list[Any]) -> None:
        """例の valkey と、呼び出しを控える並び。"""
        self._pages = spec.get("pages") or []
        self._values = spec.get("values") or {}
        self._hex = spec.get("hex_values") or {}
        self._fail_at = spec.get("fail_at")
        self._calls = calls

    def _record(self, call: list[Any]) -> None:
        """呼び出しを控え、fail_at 番目なら切れたことにする。"""
        index = len(self._calls)
        self._calls.append(call)
        if self._fail_at is not None and index == self._fail_at:
            raise ConnectionError("fixture: つながりが切れた")

    async def scan(self, cursor: int = 0, match: Any = None, count: Any = None) -> tuple[int, list[str]]:
        """SCAN の 1 ページ（次のカーソルと鍵）。"""
        self._record(["scan", cursor, match, count])
        keys = list(self._pages[cursor]) if cursor < len(self._pages) else []
        following = cursor + 1 if cursor + 1 < len(self._pages) else 0
        return following, keys

    async def mget(self, keys: list[str]) -> list[Any]:
        """MGET（UTF-8 でない値があれば、答えごと読めない）。"""
        self._record(["mget", list(keys)])
        for key in keys:
            if key in self._hex:
                raw = bytes.fromhex(self._hex[key])
                raise UnicodeDecodeError("utf-8", raw, 0, len(raw), "invalid start byte")
        return [self._values.get(key) for key in keys]

    async def aclose(self) -> None:
        """閉じる（何もしない）。"""
        return None


def make_cache(spec: dict[str, Any], calls: list[Any]) -> Any:
    """例の valkey から本物の SharedCache を作る（url が空なら何もしない。factory_raises なら client が作れない）。"""
    from services.shared_cache import SharedCache

    def factory() -> Any:
        """偽物の client（factory_raises なら作れない）。"""
        if spec.get("factory_raises"):
            raise RuntimeError("fixture: client を作れない")
        return FakeRedis(spec, calls)

    return SharedCache(spec.get("url", ""), client_factory=factory)


async def record_scan(spec: dict[str, Any]) -> dict[str, Any]:
    """本物の SharedCache.scan_values の答えと、そのあとの available と、偽物に届いた呼び出し（別の入れ物で読む）。"""
    calls: list[Any] = []
    cache = make_cache(spec, calls)
    items = await cache.scan_values(NAMESPACE)
    return {"items": items, "available": cache.available, "calls": calls}


def write_backup(directory: Path, spec: dict[str, Any] | None) -> Path:
    """バックアップの状態のファイルを例のとおりに置き、BACKUP_STATUS_FILE に入れるパスを返す。

    spec が None なら置き場のディレクトリも無い。{"dir": true} はディレクトリだけ、text（文字）か hex（バイト）が
    あればファイルも置く。
    """
    folder = directory / "backups"
    if spec is not None:
        folder.mkdir()
        if "text" in spec:
            (folder / "status.json").write_bytes(spec["text"].encode("utf-8"))
        elif "hex" in spec:
            (folder / "status.json").write_bytes(bytes.fromhex(spec["hex"]))
    return folder / "status.json"


def asgi_scope(case: dict[str, Any]) -> dict[str, Any]:
    """例の要求を ASGI の scope にする（uvicorn が作るものと同じ鍵。見出しは latin-1 のバイト）。"""
    target = case.get("target", "/metrics")
    path, _, query = target.partition("?")
    peer = case.get("peer")
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "server": ("127.0.0.1", 5001),
        "client": None if peer is None else (peer, 40000),
        "scheme": "http",
        "method": case.get("method", "GET"),
        "root_path": "",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": query.encode("latin-1"),
        "headers": [(str(n).lower().encode("latin-1"), str(v).encode("latin-1")) for n, v in case.get("headers", [])],
        "state": {},
    }


async def call(app: Any, scope: dict[str, Any]) -> dict[str, Any]:
    """ASGI の app を 1 回呼び、答え（状態・見出し〔名前の順〕・本文）を集める。"""
    messages: list[dict[str, Any]] = []
    done = asyncio.Event()
    sent = False

    async def receive() -> dict[str, Any]:
        """本文の無い要求。2 回目からは、答えを送り終えるまで待って切断（starlette の TestClient と同じ）。"""
        nonlocal sent
        if sent:
            await done.wait()
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        """答えの断片を控える（本文の最後で、送り終えた印を立てる）。"""
        messages.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            done.set()

    await app(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    pairs = [[name.decode("latin-1").lower(), value.decode("latin-1")] for name, value in start["headers"]]
    return {"status": start["status"], "headers": sorted(pairs, key=lambda pair: pair[0]), "body": body.decode("utf-8")}


def valkey_spec(case: dict[str, Any], specs: dict[str, Any]) -> dict[str, Any]:
    """例の valkey（valkey_specs の名前か、その場で書いた中身。無ければ空）。"""
    spec = case.get("valkey")
    if isinstance(spec, str):
        return specs[spec]
    return spec or {}


async def run_requests(cases: list[dict[str, Any]], specs: dict[str, Any]) -> list[dict[str, Any]]:
    """requests の例を 1 つのイベントループで順に回す。"""
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    from services import metrics_registry as registry_module
    from services.log_setup import trusted_proxies
    from envutil import env_float
    from webapp_admin import metrics as admin_metrics
    from webapp_admin import prometheus_view
    from webapp_admin.app import app
    from webapp_admin.extensions import limiter

    out = []
    for case in cases:
        now = float(case.get("now", "1800000000.0"))
        spec = valkey_spec(case, specs)
        with tempfile.TemporaryDirectory(prefix="admin-fixture-prometheus-") as tmp:
            env = {name: value for name, value in os.environ.items() if name not in REQUEST_ENV}
            env.update(case.get("env") or {})
            env["ADMIN_MONITOR_DIR"] = str(Path(tmp) / "monitor")
            env["BACKUP_STATUS_FILE"] = str(write_backup(Path(tmp), case.get("backup")))
            requests = deque(float(t) for t in case.get("requests", []))
            clock = FakeClock(now)
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(registry_module, "time", clock),
                patch.object(prometheus_view, "time", clock),
                patch.object(admin_metrics, "time", clock),
                patch.object(admin_metrics, "_APP_STARTED_AT", float(case.get("started", "0"))),
                patch.object(admin_metrics, "_REQUEST_TIMESTAMPS", requests),
            ):
                stale = env_float("METRICS_STALE_AFTER_SECONDS", 90.0, minimum=5.0)
                registry = registry_module.MetricsRegistry(make_cache(spec, []), stale_after_seconds=stale)
                registry_module.set_metrics_registry(registry)
                limiter.reset()
                try:
                    wrapped = ProxyHeadersMiddleware(app, trusted_hosts=trusted_proxies())
                    response = await call(wrapped, asgi_scope(case))
                finally:
                    registry_module.set_metrics_registry(None)
        expected_status = case.get("expect_status")
        if expected_status is not None and response["status"] != expected_status:
            raise SystemExit(f"{case['name']}: 状態が {response['status']}（道具の確かめでは {expected_status}）")
        out.append({"name": case["name"], "scan": await record_scan(spec), "response": response})
    return out


def run_functions(spec: dict[str, Any]) -> dict[str, Any]:
    """metrics_path・client_allowed・_parse_float・_format_value の答え。"""
    from services import metrics_registry as registry_module
    from webapp_admin import prometheus_view

    paths = []
    for value in spec["metrics_path"]:
        with patch.dict(os.environ, {} if value is None else {"METRICS_PATH": value}):
            if value is None:
                os.environ.pop("METRICS_PATH", None)
            paths.append([value, prometheus_view.metrics_path()])
    allowed = []
    for setting in spec["allowed_settings"]:
        with patch.dict(os.environ, {} if setting is None else {"METRICS_ALLOWED_CIDRS": setting}):
            if setting is None:
                os.environ.pop("METRICS_ALLOWED_CIDRS", None)
            for host in spec["clients"]:
                request = SimpleNamespace(client=None if host is None else SimpleNamespace(host=host))
                allowed.append([setting, host, prometheus_view.client_allowed(request)])
    floats = []
    for text in spec["parse_float"]:
        value = registry_module._parse_float(text)
        floats.append([text, None if value is None else repr(value)])
    formats = []
    for text in spec["format_value"]:
        try:
            formats.append([text, {"value": registry_module._format_value(float(text))}])
        except Exception as exc:  # noqa: BLE001 - 例外になることも基準に書く
            formats.append([text, {"error": type(exc).__name__, "message": str(exc)}])
    return {"metrics_path": paths, "client_allowed": allowed, "parse_float": floats, "format_value": formats}


def wait_for_monitor_startup(timeout: float = 30.0) -> None:
    """本物の監視のスレッドが、起動のときの処理（心拍を書く）を済ませるまで待つ。"""
    heartbeat = Path(os.environ["SETTINGS_DIR"]) / "admin_monitor" / "heartbeat.json"
    deadline = time.monotonic() + timeout
    while not heartbeat.exists():
        if time.monotonic() > deadline:
            raise SystemExit("監視のスレッドが心拍を書かない（起動のときの処理が終わらない）")
        time.sleep(0.05)


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment(document["secret"], {"ADMIN_MONITOR_INTERVAL_SECONDS": IDLE_INTERVAL})
    for name in REQUEST_ENV:
        os.environ.pop(name, None)
    functions = run_functions(document["functions"])
    import webapp_admin.app  # noqa: F401 - 監視のスレッドを先に始めさせ、起動のときの処理を待つ

    wait_for_monitor_startup()
    names = [case["name"] for case in document["requests"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    requests = asyncio.run(run_requests(document["requests"], document["valkey_specs"]))
    return {"generated_by": GENERATED_BY, "functions": functions, "requests": requests}


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
