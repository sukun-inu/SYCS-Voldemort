"""管理画面のセッション（Cookie）と秘密鍵の基準（expected.json）を、本物の Python から作る。

Rust の管理画面（rust/apps/admin）の tests/session_golden.rs が読む。Python と Rust が同じ Cookie を読み書きできること
（切り替えても戻しても、ログインが切れないこと）を、次の表で確かめる。どれも例の文書（cases.json）に書いた入力を、
本物の Python の部品に通した答え:

- signing: セッションの中身・秘密鍵・時刻 → Cookie の値（starlette の SessionMiddleware と同じ作り方。
  ../admin_harness.py の session_cookie）。json.dumps の書き方も添える
- raw: 好きな中身（base64 にする前のバイト）に署名した Cookie の値（itsdangerous の TimestampSigner）。署名は合うのに
  中身が壊れているものを作るため
- reading: Cookie の見出し → starlette の SessionMiddleware がそのまま読んだセッション（か、層の外へ抜けた例外の
  名前）と、セッションに決めた操作をしたあとの Set-Cookie・Vary（starlette 1.x の Session は、触ったか・書き換えたか
  で決める）
- secrets: 環境変数と SETTINGS_DIR の置き方 → resolve_session_secret の答え（どこから得たか・ファイルの中身）
- dumps・floats・b64decode・cookie_headers・ints・compact・forms: 部品ごとの表（json.dumps の 2 つの書き方と repr、
  base64 の緩い読み方、Cookie の見出しの読み方、str(int(x))、_compact_admin_guilds、request.form()）

時計は例の文書の now に止める（itsdangerous の TimestampSigner.get_timestamp）。読み方の表の Cookie の値は、文書の
{signing:名前}・{raw:名前}・{tampered:名前}（signing の値の 1 文字目を変えたもの）を埋めたもので、基準には埋めた
あとの見出しをそのまま書く（Rust のテストは同じ見出しを渡す）。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/session/generate.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/session/generate.py"
# 長い値は、基準には長さと頭だけ書く（1MB の欄の例がある）。
LONG_VALUE = 200


def _payload(spec: dict[str, Any]) -> bytes:
    """raw の例の中身（base64 にしたあとのバイト）。payload は文字のまま、payload_json は json.dumps して base64、
    payload_hex はそのバイトを base64 にする。"""
    if "payload" in spec:
        return str(spec["payload"]).encode("utf-8")
    if "payload_json" in spec:
        return base64.b64encode(json.dumps(spec["payload_json"]).encode("utf-8"))
    if "payload_text" in spec:
        return base64.b64encode(str(spec["payload_text"]).encode("utf-8"))
    return base64.b64encode(bytes.fromhex(spec["payload_hex"]))


def build_signing(document: dict[str, Any]) -> list[dict[str, Any]]:
    """セッションの中身 → Cookie の値の表。"""
    now = int(document["now"])
    out = []
    for case in document.get("signing", []):
        secret = case.get("secret", document["secret"])
        signed_at = int(case.get("signed_at", now))
        out.append(
            {
                "name": case["name"],
                "secret": secret,
                "signed_at": signed_at,
                "session": case["session"],
                "json": json.dumps(case["session"]),
                "cookie": harness.session_cookie(case["session"], secret, signed_at=signed_at),
            }
        )
    return out


def build_raw(document: dict[str, Any]) -> list[dict[str, Any]]:
    """好きな中身に署名した Cookie の表。"""
    from itsdangerous import TimestampSigner

    now = int(document["now"])
    out = []
    for case in document.get("raw", []):
        secret = case.get("secret", document["secret"])
        signed_at = int(case.get("signed_at", now))
        payload = _payload(case)
        with harness.frozen_signer_clock(signed_at):
            cookie = TimestampSigner(secret).sign(payload).decode("utf-8")
        entry = {
            "name": case["name"],
            "secret": secret,
            "signed_at": signed_at,
            "payload": payload.decode("latin-1"),
            "cookie": cookie,
        }
        if "rust_skip" in case:
            entry["rust_skip"] = case["rust_skip"]
        out.append(entry)
    return out


def _fill(text: str, signing: dict[str, str], raw: dict[str, str]) -> str:
    """{signing:名前}・{raw:名前}・{tampered:名前} を Cookie の値で埋める。"""
    for name, value in signing.items():
        text = text.replace("{signing:%s}" % name, value)
        flipped = ("f" if value[0] != "f" else "e") + value[1:]
        text = text.replace("{tampered:%s}" % name, flipped)
    for name, value in raw.items():
        text = text.replace("{raw:%s}" % name, value)
    if any(mark in text for mark in ("{signing:", "{raw:", "{tampered:")):
        raise SystemExit(f"埋められない名前がある: {text}")
    return text


def _apply(session: Any, ops: list[list[Any]]) -> None:
    """読み方の表の操作をセッションに当てる（starlette 1.x の Session の印の付き方を見るため）。"""
    for op in ops:
        kind = op[0]
        if kind == "access":
            session.mark_accessed()
        elif kind == "set":
            session[op[1]] = op[2]
        elif kind == "pop":
            session.pop(op[1], None)
        elif kind == "delete":
            try:
                del session[op[1]]
            except KeyError:
                pass
        elif kind == "clear":
            session.clear()
        elif kind == "setdefault":
            session.setdefault(op[1], op[2])
        elif kind == "update":
            session.update(op[1])
        else:
            raise SystemExit(f"知らない操作: {kind}")


async def _through_middleware(secret: str, secure: bool, cookies: list[str], ops: list[list[Any]]) -> dict[str, Any]:
    """starlette の SessionMiddleware（管理画面と同じ引数）に 1 回通し、読んだセッションと帰りの見出しを返す。"""
    from starlette.middleware.sessions import SessionMiddleware

    seen: dict[str, Any] = {}

    async def inner(scope: dict[str, Any], receive: Any, send: Any) -> None:
        """読んだセッションを控え、操作を当て、決まった答えを返す。"""
        session = scope["session"]
        seen["session"] = json.dumps(dict(session))
        _apply(session, ops)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive() -> dict[str, Any]:
        """本文の無い要求。"""
        return {"type": "http.request", "body": b"", "more_body": False}

    messages: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        """答えを控える。"""
        messages.append(message)

    middleware = SessionMiddleware(
        inner,
        secret_key=secret,
        session_cookie=harness.COOKIE_NAME,
        max_age=harness.MAX_AGE,
        same_site="lax",
        https_only=secure,
    )
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"cookie", cookie.encode("latin-1")) for cookie in cookies],
    }
    try:
        await middleware(scope, receive, send)
    except Exception as exc:
        return {"raised": type(exc).__name__}
    start = messages[0]
    headers = [
        [name.decode("latin-1"), value.decode("latin-1")]
        for name, value in start["headers"]
        if name in (b"set-cookie", b"vary")
    ]
    return {"session_json": seen["session"], "headers": headers}


def build_reading(document: dict[str, Any], signing: list[dict[str, Any]], raw: list[dict[str, Any]]) -> list[Any]:
    """Cookie の見出し → 読んだセッションと帰りの見出しの表。"""
    by_signing = {entry["name"]: entry["cookie"] for entry in signing}
    by_raw = {entry["name"]: entry["cookie"] for entry in raw}
    out = []
    with harness.frozen_signer_clock(int(document["now"])):
        for case in document.get("reading", []):
            cookies = [_fill(text, by_signing, by_raw) for text in case.get("cookies", [])]
            ops = case.get("ops", [])
            secure = bool(case.get("secure", False))
            result = asyncio.run(_through_middleware(document["secret"], secure, cookies, ops))
            entry = {"name": case["name"], "cookies": cookies, "ops": ops, "secure": secure, **result}
            if "rust_skip" in case:
                entry["rust_skip"] = case["rust_skip"]
            out.append(entry)
    return out


def _setup_secret_case(root: Path, case: dict[str, Any]) -> Path:
    """秘密鍵の例の置き場を作り、SETTINGS_DIR にするパスを返す。"""
    setup = case.get("setup", "dir")
    settings = root / "settings"
    if setup == "missing":
        return root / "a" / "b"
    if setup == "file_as_settings":
        settings.write_bytes(b"x")
        return settings
    settings.mkdir()
    secret_file = settings / ".admin_session_secret"
    if setup == "secret_dir":
        secret_file.mkdir()
    if "file_text" in case:
        secret_file.write_bytes(str(case["file_text"]).encode("utf-8"))
    if "file_hex" in case:
        secret_file.write_bytes(bytes.fromhex(case["file_hex"]))
    return settings


def _run_secret_case(case: dict[str, Any]) -> dict[str, Any]:
    """1 つの秘密鍵の例を回す（環境変数は例の値にして、終わったら戻す）。"""
    from webapp_admin.core import config as admin_config

    root = Path(tempfile.mkdtemp(prefix="admin-secret-fixture-"))
    settings = _setup_secret_case(root, case)
    secret_file = settings / ".admin_session_secret"
    before = secret_file.read_bytes() if secret_file.is_file() else None
    saved = {key: os.environ.get(key) for key in ("SETTINGS_DIR", "ADMIN_FLASK_SECRET_KEY")}
    os.environ["SETTINGS_DIR"] = str(settings)
    if case.get("env") is None:
        os.environ.pop("ADMIN_FLASK_SECRET_KEY", None)
    else:
        os.environ["ADMIN_FLASK_SECRET_KEY"] = str(case["env"])
    try:
        secret = admin_config.resolve_session_secret()
    except Exception as exc:
        return {"name": case["name"], "raised": type(exc).__name__}
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    after = secret_file.read_bytes() if secret_file.is_file() else None
    if (case.get("env") or "").strip():
        source = "env"
    elif before is not None and secret == secret_file.read_text(encoding="utf-8").strip():
        source = "file"
    elif before is None and after == secret.encode("utf-8"):
        source = "generated"
    else:
        source = "temporary"
    # 作った鍵は乱数なので、基準には中身を書かない（作り直すたびに変わらないように）。ファイルが鍵と同じかだけ書く。
    generated = source == "generated"
    return {
        "name": case["name"],
        "source": source,
        "secret": secret if source in ("env", "file") else None,
        "length": len(secret),
        "is_hex": all(c in "0123456789abcdef" for c in secret),
        "file_after_hex": after.hex() if after is not None and not generated else None,
        "file_is_the_secret": generated and after == secret.encode("utf-8"),
        "mode": oct(stat.S_IMODE(secret_file.stat().st_mode)) if generated else None,
    }


def build_secrets(document: dict[str, Any]) -> list[dict[str, Any]]:
    """秘密鍵の決め方の表（例の setup・env・file_text か file_hex をそのまま添える）。"""
    out = []
    for case in document.get("secrets", []):
        result = _run_secret_case(case)
        result["case"] = case
        out.append(result)
    return out


def _b64(fn: Any, text: str) -> str | None:
    """base64 を読んだバイトの 16 進（読めなければ None）。"""
    try:
        return bytes(fn(text.encode("latin-1"))).hex()
    except Exception:
        return None


def _int_text(value: Any) -> dict[str, str]:
    """str(int(value)) か、投げた例外の名前。"""
    try:
        return {"text": str(int(value))}
    except Exception as exc:
        return {"raised": type(exc).__name__}


def _form_body(pieces: list[Any]) -> bytes:
    """フォームの例の本文（[文字, 回数] か {"hex": …} の並びをつなぐ）。"""
    body = b""
    for piece in pieces:
        if isinstance(piece, dict):
            body += bytes.fromhex(piece["hex"])
        else:
            body += str(piece[0]).encode("latin-1") * int(piece[1])
    return body


def _short(value: str) -> Any:
    """長い値は長さと頭の 20 文字にする。"""
    if len(value) <= LONG_VALUE:
        return value
    return {"length": len(value), "head": value[:20]}


async def _read_form(content_type: str | None, body: bytes) -> dict[str, Any]:
    """starlette の request.form() で読んだ欄の並び（か、断ったときの状態と理由）。"""
    from starlette.exceptions import HTTPException
    from starlette.requests import Request

    sent = False

    async def receive() -> dict[str, Any]:
        """本文を 1 回で渡す。"""
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    headers = [] if content_type is None else [(b"content-type", content_type.encode("latin-1"))]
    scope = {"type": "http", "method": "POST", "path": "/", "query_string": b"", "headers": headers, "app": object()}
    try:
        form = await Request(scope, receive).form()
    except HTTPException as exc:
        return {"status": exc.status_code, "detail": exc.detail}
    return {"items": [[name, _short(str(value))] for name, value in form.multi_items()]}


def build_forms(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Content-Type と本文 → 読んだフォームの表。"""
    out = []
    for case in document.get("forms", []):
        result = asyncio.run(_read_form(case.get("content_type"), _form_body(case.get("body", []))))
        entry = {"name": case["name"], "content_type": case.get("content_type"), "body": case.get("body", []), **result}
        if "rust_skip" in case:
            entry["rust_skip"] = case["rust_skip"]
        out.append(entry)
    return out


def build_parts(document: dict[str, Any]) -> dict[str, Any]:
    """部品ごとの表（json.dumps・repr・base64・Cookie の見出し・int・_compact_admin_guilds）。"""
    from itsdangerous.encoding import base64_decode
    from starlette.requests import cookie_parser

    from webapp_admin.app import _compact_admin_guilds

    cookie_headers = []
    for headers in document.get("cookie_headers", []):
        parsed: dict[str, str] = {}
        for header in headers:
            parsed.update(cookie_parser(header))
        cookie_headers.append({"headers": headers, "cookies": [[k, v] for k, v in parsed.items()]})
    return {
        "dumps": [
            {
                "value": value,
                "default": json.dumps(value),
                "compact": json.dumps(value, ensure_ascii=False, separators=(",", ":")),
            }
            for value in document.get("dumps", [])
        ],
        "floats": [{"value": value, "repr": repr(float(value))} for value in document.get("floats", [])],
        "b64decode": [
            {"input": text, "standard": _b64(base64.b64decode, text), "itsdangerous": _b64(base64_decode, text)}
            for text in document.get("b64decode", [])
        ],
        "cookie_headers": cookie_headers,
        "ints": [{"value": value, **_int_text(value)} for value in document.get("ints", [])],
        "compact": [{"value": value, "compact": _compact_admin_guilds(value)} for value in document.get("compact", [])],
    }


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment(document["secret"], {"ADMIN_MONITOR_INTERVAL_SECONDS": "86400"})
    signing = build_signing(document)
    raw = build_raw(document)
    return {
        **harness.header(document, GENERATED_BY),
        "signing": signing,
        "raw": raw,
        "reading": build_reading(document, signing, raw),
        "secrets": build_secrets(document),
        "forms": build_forms(document),
        **build_parts(document),
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
