"""管理画面の骨組み（エラーの答え・見出し・経路・確かめ・回数の制限・数とインシデント）の基準を、本物の Python で作る。

Rust の管理画面（rust/apps/admin）の tests/errors_golden.rs が読む。本物の管理画面（webapp_admin/app.py の app）を
starlette の TestClient で回す。層は全部本物（セッション・slowapi・見張り・見出し・数・例外の係・経路）。

骨組みの振る舞いを、ほかの塊の経路に頼らずに見るため、**基準のためだけの経路**（make_probes）を app の最後に足す
（Rust のテストも同じ形の経路を同じ順に足す）:

    /admin/api/__a1/http/{code}   HTTPException を投げる（?detail=理由、?dict=1 で文字でない理由、?header=名前:値）
    /__a1/http/{code}             同じもの（/admin/api/ の外。HTML の答えになる）
    /admin/api/__a1/crash, /__a1/crash   組み込みの例外を投げる（?type=…&message=…）
    /admin/api/__a1/status/{code} その状態で {"ok": true} を返す（例外ではなく答えとしての 5xx）
    /admin/api/__a1/limited, /__a1/limited   @limiter.limit("2/minute")
    /admin/api/__a1/limited-login           check_login のあとに @limiter.limit("2/minute")
    /admin/api/__a1/login・guild・dev   check_login・check_guild・check_dev を通ったら {"ok": true}（dev は user も）
    /admin/api/__a1/csrf（POST）・guild-csrf（POST）・csrf-any（GET POST PUT PATCH DELETE OPTIONS）
    /admin/api/__a1/router-guild  check_guild（これだけ APIRouter に入れて include_router で足す）

どれも app に直に足すので、デコレータの無いものには slowapi の既定の 1 分 300 回が掛かる（本物の旧 URL と同じ）。

例（cases.json）は、要求の並び（requests）を順に送る。要求ごとに Cookie（session と cookie の作り方、raw_cookie、
cookies の生の見出し）、見出し、本文（json・form・body）、repeat（同じ要求を何回送るか。最後の答えだけ書く）を書く。
例ごとに、slowapi の数・数え口（counters）を空にし、CSRF の印（secrets.token_hex）とインシデントの ID（uuid4）と
時刻（time.time。now + 0.25）を決まった並びにする。基準には、要求ごとに実際に送った要求（パス・見出し・本文）と
答え（状態・見出し〔名前の順〕・本文）、例ごとに足した数とインシデントの行（incidents.jsonl に足された行）を書く。

- CSRF の印は 1 つ目から f"{TOKEN_BASE + n:064x}"、インシデントの ID は f"{ID_BASE + n:032x}"（例ごとに 1 から）
- 応答は TestClient の raise_server_exceptions=False で受ける（層の外へ抜ける例外の素の 500 も答えとして書く）
- Cookie の持ち越しはしない（要求ごとに TestClient の Cookie を空にする）
- rust_skip の付いた例は、Rust では違う答えにすると決めたもの（理由は例に書く）。Python の答えを残すために回す
- 監視の巡回（webapp_admin/metrics.py の背景のスレッド）は、間隔を 1 日にして、作り直しの間に動かないようにする
- HTML のページの資材の URL（admin_asset_url）は、static の置き場を無い場所にして ?v=admin の形にそろえる（ファイルの
  時刻はチェックアウトのたびに変わる）。HTML の本文は A2 が比べる

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/errors/generate.py
"""

from __future__ import annotations

import builtins
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

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/errors/generate.py"
# インシデントの時刻（time.time）は now にこれを足したもの（マイクロ秒の書き方も見るため）。
NOW_FRACTION = 0.25
TOKEN_BASE = 0xC5F00000
ID_BASE = 0x1D000000
API_PROBE = "/admin/api/__a1"
PAGE_PROBE = "/__a1"
# これより大きい本文は 16 進で書かず、例の body（つなぎ方）をそのまま書く。
BODY_HEX_LIMIT = 4096


class Sequence:
    """例ごとに決まる CSRF の印とインシデントの ID の並び。"""

    def __init__(self) -> None:
        """1 つ目から数える。"""
        self.tokens = 0
        self.ids = 0

    def token_hex(self, nbytes: int = 32) -> str:
        """secrets.token_hex の代わり（長さは見ない。いつも 64 文字）。"""
        self.tokens += 1
        return f"{TOKEN_BASE + self.tokens:064x}"

    def uuid4(self) -> Any:
        """uuid.uuid4 の代わり（hex だけ使う）。"""
        self.ids += 1
        return types.SimpleNamespace(hex=f"{ID_BASE + self.ids:032x}")


def make_probes() -> tuple[list[tuple[str, Any, list[str], list[Any]]], Any]:
    """基準のためだけの経路（モジュールの説明）と、ルーターに入れた経路を 1 回だけ作る。

    slowapi のデコレータは、関数の名前ごとに上限を登録簿へ足していく。2 つの app のために 2 回飾ると、同じ名前に
    上限が 2 つ並び、1 回の要求で 2 回数えてしまう。なので飾るのは 1 回だけにして、同じ関数を両方の app に足す。
    """
    from fastapi import APIRouter, Depends, HTTPException, Request
    from fastapi.responses import JSONResponse

    from webapp_admin.api.dev import check_dev
    from webapp_admin.extensions import limiter
    from webapp_admin.security import check_csrf, check_guild, check_login

    async def probe_http(request: Request, code: int):
        """HTTPException を投げる。"""
        params = request.query_params
        headers = None
        if "header" in params:
            name, _, value = params["header"].partition(":")
            headers = {name: value}
        if "dict" in params:
            raise HTTPException(status_code=code, detail={"reason": "x"}, headers=headers)
        raise HTTPException(status_code=code, detail=params.get("detail"), headers=headers)

    async def probe_crash(request: Request):
        """組み込みの例外を投げる（文は message を repeat 回つないだもの）。"""
        params = request.query_params
        kind = getattr(builtins, params.get("type", "RuntimeError"))
        raise kind(params.get("message", "") * int(params.get("repeat", "1")))

    async def probe_status(code: int):
        """その状態で {"ok": true} を返す。"""
        return JSONResponse({"ok": True}, status_code=code)

    async def probe_limited(request: Request):
        """1 分 2 回の制限の付いた経路。"""
        return JSONResponse({"ok": True})

    async def probe_limited_login(request: Request):
        """ログインの確かめのあとに 1 分 2 回の制限。"""
        return JSONResponse({"ok": True})

    async def probe_ok():
        """確かめを通ったら {"ok": true}。"""
        return JSONResponse({"ok": True})

    async def probe_dev(user: dict = Depends(check_dev)):
        """開発者の確かめを通ったら、確かめが返した利用者も返す。"""
        return JSONResponse({"ok": True, "user": user})

    limited = limiter.limit("2/minute")(probe_limited)
    limited_login = limiter.limit("2/minute")(probe_limited_login)
    probes = [
        (f"{API_PROBE}/http/{{code}}", probe_http, ["GET"], []),
        (f"{PAGE_PROBE}/http/{{code}}", probe_http, ["GET"], []),
        (f"{API_PROBE}/crash", probe_crash, ["GET"], []),
        (f"{PAGE_PROBE}/crash", probe_crash, ["GET"], []),
        (f"{API_PROBE}/status/{{code}}", probe_status, ["GET"], []),
        (f"{API_PROBE}/limited", limited, ["GET"], []),
        (f"{PAGE_PROBE}/limited", limited, ["GET"], []),
        (f"{API_PROBE}/limited-login", limited_login, ["GET"], [Depends(check_login)]),
        (f"{API_PROBE}/login", probe_ok, ["GET"], [Depends(check_login)]),
        (f"{API_PROBE}/guild", probe_ok, ["GET"], [Depends(check_guild)]),
        (f"{API_PROBE}/dev", probe_dev, ["GET"], []),
        (f"{API_PROBE}/csrf", probe_ok, ["POST"], [Depends(check_csrf)]),
        (f"{API_PROBE}/guild-csrf", probe_ok, ["POST"], [Depends(check_guild), Depends(check_csrf)]),
        (
            f"{API_PROBE}/csrf-any",
            probe_ok,
            ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            [Depends(check_csrf)],
        ),
    ]
    # ルーターに入れた経路（include_router。本物の画面と API と同じ入れ方）。既定の回数の制限が掛かるかを見る。
    router = APIRouter()
    router.add_api_route(f"{API_PROBE}/router-guild", probe_ok, methods=["GET"], dependencies=[Depends(check_guild)])
    return probes, router


def build_apps() -> dict[str, Any]:
    """FLASK_SECURE_COOKIES の無い app（import したもの）と、ある app（作り直したもの）。どちらにも経路を足す。"""
    from webapp_admin import app as admin_app

    os.environ["FLASK_SECURE_COOKIES"] = "1"
    try:
        secure = admin_app.create_app()
    finally:
        os.environ.pop("FLASK_SECURE_COOKIES", None)
    apps = {"plain": admin_app.app, "secure": secure}
    probes, router = make_probes()
    for app in apps.values():
        for path, endpoint, methods, dependencies in probes:
            app.add_api_route(path, endpoint, methods=methods, dependencies=dependencies)
        app.include_router(router)
    return apps


def _body(step: dict[str, Any]) -> bytes | None:
    """例の body（[文字, 回数] か {"hex": …} の並び）をつないだ本文。無ければ None。"""
    if "body" not in step:
        return None
    body = b""
    for piece in step["body"]:
        if isinstance(piece, dict):
            body += bytes.fromhex(piece["hex"])
        else:
            body += str(piece[0]).encode("latin-1") * int(piece[1])
    return body


def _cookie_values(step: dict[str, Any], document: dict[str, Any]) -> list[str]:
    """要求に付ける Cookie の見出しの値（session と cookie、raw_cookie、cookies）。"""
    from itsdangerous import TimestampSigner

    values = []
    header = harness.cookie_header({"name": step.get("target", ""), **step}, document)
    if header is not None:
        values.append(header)
    raw = step.get("raw_cookie")
    if raw is not None:
        now = int(document["now"])
        secret = raw.get("secret", document["secret"])
        if "session" in raw:
            value = harness.session_cookie(
                document["sessions"][raw["session"]], secret, signed_at=int(raw.get("signed_at", now))
            )
        else:
            with harness.frozen_signer_clock(int(raw.get("signed_at", now))):
                value = TimestampSigner(secret).sign(str(raw["payload"]).encode("utf-8")).decode("utf-8")
        values.append(f"{harness.COOKIE_NAME}={value}")
    fresh = {
        name: harness.session_cookie(session, document["secret"], signed_at=int(document["now"]))
        for name, session in document["sessions"].items()
    }
    for text in step.get("cookies", []):
        for name, value in fresh.items():
            text = text.replace("{fresh:%s}" % name, value)
        values.append(text)
    return values


def _send(client: Any, step: dict[str, Any], document: dict[str, Any]) -> Any:
    """1 つの要求を repeat 回送り、最後の応答を返す（Cookie は持ち越さない）。"""
    headers = [(str(name).lower(), str(value)) for name, value in (step.get("headers") or {}).items()]
    headers += [("cookie", value) for value in _cookie_values(step, document)]
    kwargs: dict[str, Any] = {"headers": headers, "follow_redirects": False}
    if "json" in step:
        kwargs["json"] = step["json"]
    if "form" in step:
        kwargs["data"] = step["form"]
    body = _body(step)
    if body is not None:
        kwargs["content"] = body
    response = None
    for _ in range(int(step.get("repeat", 1))):
        client.cookies.clear()
        response = client.request(step["method"], step["target"], **kwargs)
    return response


def _record_request(response: Any, step: dict[str, Any]) -> dict[str, Any]:
    """実際に送った要求（httpx が整えたあとのパス・見出し・本文）。"""
    request = response.request
    out: dict[str, Any] = {
        "method": request.method,
        "target": request.url.raw_path.decode("ascii"),
        "headers": [[name.lower(), value] for name, value in request.headers.multi_items()],
    }
    content = request.content
    if len(content) <= BODY_HEX_LIMIT:
        out["body_hex"] = content.hex()
    elif "body" in step:
        out["body"] = step["body"]
    else:
        raise SystemExit(f"{step['target']}: 大きい本文は body（つなぎ方）で書くこと")
    return out


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


def run_case(apps: dict[str, Any], case: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    """1 つの例を回す（要求を順に送り、数とインシデントは例の中で足し合わせる）。"""
    from starlette.testclient import TestClient

    from webapp_admin.extensions import limiter

    limiter.reset()
    _counters()
    before = _incident_bytes()
    secure = bool(case.get("secure", False))
    env = {str(k): str(v) for k, v in (case.get("env") or {}).items()}
    if secure:
        env["FLASK_SECURE_COOKIES"] = "1"
    sequence = Sequence()
    now = int(document["now"])
    clock = types.SimpleNamespace(time=lambda: now + NOW_FRACTION, sleep=time.sleep)
    secrets_module = types.SimpleNamespace(token_hex=sequence.token_hex, compare_digest=secrets.compare_digest)
    steps = []
    with ExitStack() as stack:
        stack.enter_context(harness.frozen_signer_clock(now))
        stack.enter_context(patch("webapp_admin.security.secrets", secrets_module))
        stack.enter_context(patch("webapp_admin.metrics.uuid", types.SimpleNamespace(uuid4=sequence.uuid4)))
        stack.enter_context(patch("webapp_admin.metrics.time", clock))
        # HTML のページの資材の URL は、ファイルの時刻と大きさを ?v= に入れる。チェックアウトのたびに時刻が変わるので、
        # 置き場を無い場所にして、読めないときの形（?v=admin）にそろえる。
        stack.enter_context(patch("webapp_admin.templating._static_root", Path("/nonexistent-admin-fixture-static")))
        stack.enter_context(patch.dict(os.environ, env))
        app = apps["secure" if secure else "plain"]
        client = TestClient(app, base_url=harness.BASE_URL, raise_server_exceptions=False)
        try:
            for step in case["requests"]:
                response = _send(client, step, document)
                expected_status = step.get("expect_status")
                if expected_status is not None and response.status_code != expected_status:
                    raise SystemExit(
                        f"{case['name']}: {step['target']} の状態が {response.status_code}"
                        f"（道具の確かめでは {expected_status}）"
                    )
                entry = {"request": _record_request(response, step), "response": harness.record_response(response)}
                if int(step.get("repeat", 1)) != 1:
                    entry["repeat"] = int(step["repeat"])
                steps.append(entry)
        finally:
            client.close()
    added = _incident_bytes()[len(before) :].decode("utf-8")
    result = {
        "name": case["name"],
        "secure": secure,
        "dev_user_id": env.get("DEV_USER_ID", ""),
        "steps": steps,
        "counters": _counters(),
        "incidents": added.split("\n")[:-1] if added else [],
    }
    if "rust_skip" in case:
        result["rust_skip"] = case["rust_skip"]
    return result


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment(document["secret"], {"ADMIN_MONITOR_INTERVAL_SECONDS": "86400"})
    apps = build_apps()
    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    cases = [run_case(apps, case, document) for case in document["cases"]]
    return {
        **harness.header(document, GENERATED_BY),
        "now_fraction": NOW_FRACTION,
        "token_base": TOKEN_BASE,
        "id_base": ID_BASE,
        "sessions": document["sessions"],
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
