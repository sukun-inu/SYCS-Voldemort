"""管理画面のテンプレートの基準（expected.json）を、本物の Python（Jinja2・markupsafe と templating.py）から作る。

Rust の管理画面（rust/apps/admin の src/templates/）は、Python と同じテンプレートのファイル（webapp_admin/templates/）を
minijinja で描く。minijinja は Jinja2 と同じ書き方を読むが、エスケープの書き方（markupsafe は ' を &#39;、" を &#34; に
する。minijinja の既定は &#x27;・&quot; で、/ まで逃がす）や None の形が違う。HTML がバイトまで同じかを、この基準で
確かめる（W2 の計画の 4.）。

基準に書くもの（どれも本物の Python が返したもの）:

    functions  テンプレートの関数を直に呼んだ答え（_admin_asset_url・_icon・_url_for・招待リンク・markupsafe.escape・
               小数の str）
    snippets   短いテンプレートの文字を Jinja2 の環境（templates.env.from_string）で描いたもの。minijinja との違いを
               1 つずつ（エスケープ・None・True・未定義・文字の添字・組・改行・include）
    pages      templating.render を直に呼んだもの（テンプレート・セッション・経路の値 → 本文と描いたあとのセッション）
    cases      本物の管理画面（webapp_admin/app.py の app）に TestClient で送った要求（/・/guide・/privacy・/terms・
               旧 URL の 301・ログイン画面・ログアウトの確認・サーバー選択・シェル・エラーのページ）の応答と、
               Set-Cookie から読んだ、描いたあとのセッション

2 回作ってバイトまで同じにするために決めてあること:

- static は偽物の置き場（cases.json の static。大きさと更新時刻〔ns〕を決めたファイルとリンク）を一時ディレクトリに
  作り、templating._static_root をそこへ向ける。Rust のテストも同じものを作る（置き場の場所は答えに出ない）
- CSRF の印（webapp_admin.security が使う secrets.token_hex）は、cases.json の issued_token を返す偽物にする。
  呼ばれたら calls に残す
- Bot のサーバー数（GET / の get_bot_guild_count）は、例の service の guild_count を返す偽物にする。GET / の閉包は
  app を作るときに名前を取り込むので、app を import する前に差し替える
- DISCORD_CLIENT_ID は cases.json の client_id（app を import する前に入れる。公開ページに招待リンクが出る）
- それ以外（Cookie の作り方・署名の時計・値の印・見出しの並べ方）は ../admin_harness.py の説明のとおり

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/templates/generate.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/templates/generate.py"
COOKIE_PREFIX = f"{harness.COOKIE_NAME}="

# GET / の偽物（Bot のサーバー数）が読む、いまの例の service と呼び出しの控え（_route_patches が例ごとに入れる）。
_CURRENT: dict[str, Any] = {}


async def _fake_guild_count() -> int:
    """get_bot_guild_count の偽物。例の service の guild_count を返す（書いていなければ印を付けて例外を投げる）。"""
    calls = _CURRENT.get("calls")
    service = _CURRENT.get("service") or {}
    if calls is None:
        raise RuntimeError("例の外で get_bot_guild_count が呼ばれた")
    if "guild_count" not in service:
        calls.append({"fn": "get_bot_guild_count", "unexpected": True})
        raise RuntimeError("例に書いていない get_bot_guild_count が呼ばれた")
    calls.append({"fn": "get_bot_guild_count", "args": [], "kwargs": {}})
    return int(service["guild_count"])


@contextmanager
def _asset_version(version: str | None) -> Iterator[None]:
    """ADMIN_ASSET_VERSION を決める（None なら入れない。prepare_environment が消してある）。"""
    if version is None:
        yield
        return
    from unittest.mock import patch

    with patch.dict(os.environ, {"ADMIN_ASSET_VERSION": version}):
        yield


def _make_static(spec: dict[str, Any]) -> Path:
    """偽物の static を一時ディレクトリに作り、static のパス（親は解いたもの。templating と同じ形）を返す。

    ファイルは b"x" を大きさの数だけ並べたもの。更新時刻は ns で決める（無ければ spec の mtime_ns）。リンクの先は
    相対で書く（置き場の場所によらず同じに解ける）。時刻はリンクを作ったあとに決める。
    """
    base = Path(tempfile.mkdtemp(prefix="admin-fixture-static-")).resolve()
    root = base / "static"
    root.mkdir()
    default_mtime = int(spec["mtime_ns"])
    placed: list[tuple[Path, int]] = []
    for where, items in ((root, spec.get("files") or []), (base, spec.get("outside") or [])):
        for item in items:
            path = where / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * int(item["size"]))
            placed.append((path, int(item.get("mtime_ns", default_mtime))))
    for item in spec.get("symlinks") or []:
        link = root / item["path"]
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(item["target"], link)
    for path, mtime in placed:
        os.utime(path, ns=(mtime, mtime))
    return root


def _functions(spec: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """テンプレートの関数を直に呼んだ答え（cases.json の functions の並びのまま）。"""
    from unittest.mock import patch

    import markupsafe

    from webapp_admin import templating
    from webapp_admin.views import auth_views

    assets = []
    for item in spec["admin_asset_url"]:
        version = item.get("asset_version")
        with _asset_version(version):
            url = templating._admin_asset_url(item["filename"])
        assets.append({"filename": item["filename"], "asset_version": version, "url": url})
    icons = []
    for item in spec["icon"]:
        kwargs = {"css_class": item["css_class"]} if "css_class" in item else {}
        icons.append({**item, "markup": str(templating._icon(item["name"], **kwargs))})
    urls = []
    for item in spec["url_for"]:
        params = {str(key): str(value) for key, value in item.get("params") or []}
        path = templating._url_for(item["name"], **params)
        urls.append({"name": item["name"], "params": item.get("params") or [], "path": path})
    invites = []
    for client_id in spec["invite_url"]:
        with patch.object(auth_views, "DISCORD_CLIENT_ID", client_id):
            invites.append({"client_id": client_id, "url": auth_views._build_invite_url()})
    return {
        "admin_asset_url": assets,
        "icon": icons,
        "url_for": urls,
        "invite_url": invites,
        "escape": [{"text": text, "escaped": str(markupsafe.escape(text))} for text in spec["escape"]],
        "float_repr": [{"number": number, "text": str(float(number))} for number in spec["float_repr"]],
    }


def _snippets(document: dict[str, Any]) -> list[dict[str, Any]]:
    """短いテンプレートを Jinja2 の環境で描いたもの（render と同じく url_for を文脈に入れる）。"""
    from webapp_admin import templating

    library = document.get("library") or {}
    out = []
    for item in document["snippets"]:
        context = harness.decode(item.get("context") or {}, library)
        template = templating.templates.env.from_string(item["source"])
        body = template.render(**context, url_for=templating._url_for)
        out.append({"name": item["name"], "source": item["source"], "context": harness.encode(context), "body": body})
    return out


def _request(session: dict[str, Any], headers: dict[str, str]) -> Any:
    """render に渡す要求（セッションと見出しだけを持つ。経路は通さない）。"""
    from starlette.requests import Request

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": [(name.encode("latin-1"), value.encode("latin-1")) for name, value in headers.items()],
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "session": session,
    }
    return Request(scope)


def _token_patch(document: dict[str, Any], calls: list[dict[str, Any]], library: dict[str, Any]) -> Any:
    """CSRF の印を作る secrets.token_hex を、issued_token を返す偽物にする patch（呼ばれたら calls に残す）。"""
    from unittest.mock import patch

    from webapp_admin import security

    fake = harness.fake_function("token_hex", document["issued_token"], calls, library, is_async=False)
    return patch.object(security.secrets, "token_hex", fake)


def _pages(document: dict[str, Any], sessions: dict[str, Any]) -> list[dict[str, Any]]:
    """templating.render を直に呼び、本文と描いたあとのセッションを控える（例の並びのまま）。"""
    from webapp_admin import templating

    library = document.get("library") or {}
    out = []
    for item in document["pages"]:
        name = item.get("session")
        session = json.loads(json.dumps(sessions[name])) if name else {}
        before = json.loads(json.dumps(session))
        headers = {str(key).lower(): str(value) for key, value in (item.get("headers") or {}).items()}
        ctx = harness.decode(item.get("ctx") or {}, library)
        calls: list[dict[str, Any]] = []
        request = _request(session, headers)
        with _token_patch(document, calls, library), _asset_version(item.get("asset_version")):
            response = templating.render(request, item["template"], status_code=int(item.get("status", 200)), **ctx)
        out.append(
            {
                "name": item["name"],
                "template": item["template"],
                "session": before,
                "headers": sorted([key, value] for key, value in headers.items()),
                "asset_version": item.get("asset_version"),
                "ctx": harness.encode(ctx),
                "calls": calls,
                "status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "body": response.body.decode("utf-8"),
                "session_after": harness.encode(dict(request.session)),
            }
        )
    return out


def _route_patches(document: dict[str, Any]) -> Callable[..., list[Any]]:
    """harness.run_case に渡す、例ごとの patch を作る関数（CSRF の印と、Bot のサーバー数の偽物）。"""

    def patches(service: dict[str, Any], calls: list[dict[str, Any]], library: dict[str, Any]) -> list[Any]:
        """CSRF の印の偽物と、_fake_guild_count が読む例の service と控えの置き場。"""
        from unittest.mock import patch

        return [_token_patch(document, calls, library), patch.dict(_CURRENT, {"service": service, "calls": calls})]

    return patches


def _session_after(response: dict[str, Any]) -> dict[str, Any]:
    """応答の Set-Cookie から、描いたあとのセッションを読む（Set-Cookie が無い・消す Cookie なら空）。

    starlette の SessionMiddleware は、セッションが空でなければどの応答でも Cookie を書き直す。値の先頭
    （最初の . まで）が JSON の base64。
    """
    values = [value for name, value in response["headers"] if name == "set-cookie" and value.startswith(COOKIE_PREFIX)]
    if not values:
        return {}
    data = values[-1].split(";", 1)[0][len(COOKIE_PREFIX) :]
    if data == "null":
        return {}
    return json.loads(base64.b64decode(data.split(".", 1)[0]))


def _cases(app: Any, document: dict[str, Any]) -> list[dict[str, Any]]:
    """本物の管理画面に例の要求を送り、応答に例のページの印・service・描いたあとのセッションを添える。"""
    results = harness.run_cases(app, document, _route_patches(document))
    by_name = {case["name"]: case for case in document["cases"]}
    for result in results:
        case = by_name[result["name"]]
        result["session"] = case.get("session")
        result["page"] = case["page"]
        result["service"] = case.get("service") or {}
        result["session_after"] = _session_after(result["response"])
    return results


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    from unittest.mock import patch

    library = document.get("library") or {}
    sessions = {name: harness.decode(value, library) for name, value in document["sessions"].items()}
    resolved = {**document, "sessions": sessions}
    harness.prepare_environment(document["secret"], {"DISCORD_CLIENT_ID": document["client_id"]})
    import webapp_admin.auth as auth

    with patch.object(auth, "get_bot_guild_count", _fake_guild_count):
        from webapp_admin.app import app
    from webapp_admin import templating

    static_root = _make_static(document["static"])
    with patch.object(templating, "_static_root", static_root):
        functions = _functions(document["functions"])
        snippets = _snippets(document)
        pages = _pages(document, sessions)
        cases = _cases(app, resolved)
    return {
        **harness.header(document, GENERATED_BY),
        "client_id": document["client_id"],
        "issued_token": document["issued_token"],
        "static": document["static"],
        "sessions": sessions,
        "functions": functions,
        "snippets": snippets,
        "pages": pages,
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
