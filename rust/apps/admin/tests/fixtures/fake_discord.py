"""管理画面の基準を作る道具が使う、偽物の Discord（127.0.0.1 の空いた口で待ち受ける HTTP のサーバー）。

本物の管理画面（webapp_admin/auth.py）は aiohttp で Discord の API（https://discord.com/api/v10）を呼ぶ。
基準を作るときは auth._API をこのサーバーへ向ける。サーバーは、例に書いた答え方を返し、届いた要求
（メソッド・パス・Authorization・Content-Type・本文）を控える。Rust のテスト（tests/support/mod.rs の
FakeDiscord）も同じ決まりで答える偽物を立て、同じ要求が届くかを比べる。

答え方は「メソッド パス 認証の種類」か「メソッド パス」の鍵で引く（認証の種類は Authorization の最初の語。
本人の一覧〔Bearer〕と Bot の一覧〔Bot〕は同じパスなので分ける）。パスは /api/v10 を落とし、? から後も含む。

    {"status": 200, "json": 値}          本文は json.dumps(値)、Content-Type は application/json
    {"status": 200, "body": "文字"}       本文はその文字（UTF-8）。Content-Type は付けない
    {"status": 404}                       本文は空

content_type を書けば（null なら付けない）それにする。status の既定は 200。例に無い要求には 500 を返し、
控えに unexpected を付ける（作り直しを止める合図）。
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

API_PREFIX = "/api/v10"


def response_of(spec: Any) -> tuple[int, str | None, bytes]:
    """答え方から（状態・Content-Type・本文）を作る（モジュールの説明の決まり）。"""
    if spec is None:
        return 500, "text/plain", b"unexpected"
    status = int(spec.get("status", 200))
    content_type: str | None = None
    if "json" in spec:
        body = json.dumps(spec["json"]).encode("utf-8")
        content_type = "application/json"
    elif "body" in spec:
        body = str(spec["body"]).encode("utf-8")
    else:
        body = b""
    if "content_type" in spec:
        content_type = spec["content_type"]
    return status, content_type, body


def lookup(answers: dict[str, Any], method: str, path: str, authorization: str | None) -> Any:
    """例の答え方を引く（認証の種類つきの鍵 → 無しの鍵の順）。無ければ None。"""
    if authorization:
        scheme = authorization.split(" ", 1)[0]
        key = f"{method} {path} {scheme}"
        if key in answers:
            return answers[key]
    return answers.get(f"{method} {path}")


class FakeDiscord:
    """偽物の Discord。script で答え方を決め、take で届いた要求を受け取る。"""

    def __init__(self) -> None:
        """空いた口で待ち受けを始める（裏のスレッド）。"""
        self._lock = threading.Lock()
        self._answers: dict[str, Any] = {}
        self._seen: list[dict[str, Any]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler_class())
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def api_base(self) -> str:
        """auth._API に入れる場所（http://127.0.0.1:口/api/v10）。"""
        return f"http://127.0.0.1:{self._server.server_address[1]}{API_PREFIX}"

    def script(self, answers: dict[str, Any]) -> None:
        """答え方を決める。控えは空にする。"""
        with self._lock:
            self._answers = dict(answers)
            self._seen = []

    def take(self) -> list[dict[str, Any]]:
        """届いた要求（並びは中身で決める。2 つの一覧を並べて取るので、届く順は毎回変わりうる）。控えは空にする。"""
        with self._lock:
            seen, self._seen = self._seen, []
        return sorted(seen, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))

    def close(self) -> None:
        """待ち受けを止める。"""
        self._server.shutdown()
        self._server.server_close()

    def _serve(self, handler: BaseHTTPRequestHandler) -> None:
        """1 つの要求を控え、答え方のとおりに答える。"""
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length) if length else b""
        target = handler.path
        path = target[len(API_PREFIX) :] if target.startswith(API_PREFIX) else target
        authorization = handler.headers.get("Authorization")
        record: dict[str, Any] = {
            "method": handler.command,
            "path": path,
            "authorization": authorization,
            "content_type": handler.headers.get("Content-Type"),
            "body": body.decode("utf-8", "replace"),
        }
        with self._lock:
            spec = lookup(self._answers, handler.command, path, authorization)
            if spec is None:
                record["unexpected"] = True
            self._seen.append(record)
        status, content_type, payload = response_of(spec)
        handler.send_response(status)
        if content_type is not None:
            handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        """http.server に渡す係の型（どのメソッドも _serve へ回す）。"""
        fake = self

        class Handler(BaseHTTPRequestHandler):
            """偽物の Discord の係。"""

            def do_GET(self) -> None:
                """GET。"""
                fake._serve(self)

            def do_POST(self) -> None:
                """POST。"""
                fake._serve(self)

            def do_PUT(self) -> None:
                """PUT。"""
                fake._serve(self)

            def do_DELETE(self) -> None:
                """DELETE。"""
                fake._serve(self)

            def log_message(self, format: str, *args: Any) -> None:
                """要求ごとの記録を標準エラーに出さない。"""

        return Handler


def unexpected(requests: list[dict[str, Any]]) -> list[str]:
    """例に書いていなかった要求（メソッドとパス）。"""
    return [f"{item['method']} {item['path']}" for item in requests if item.get("unexpected")]
