import json as _json
import os
import re as _re
from pathlib import Path

from markupsafe import Markup

from fastapi import Request
from fastapi.templating import Jinja2Templates

_template_dir = Path(__file__).resolve().parent / "templates"
_static_root = Path(__file__).resolve().parent / "static"

templates = Jinja2Templates(directory=str(_template_dir))

# テンプレートが url_for で引く名前だけを持つ。
# 設定画面と開発者パネルはデスクトップUI（/admin/overview のウィンドウ）と
# /admin/api/* に移ったため、かつてここにあった dev_* / *_settings の約30件は
# どのテンプレートからも参照されず、しかも既に存在しない URL
# （/admin/dev/earthquake-replay など）を指していた。
# 名前を足すときは、テンプレート側の url_for と対で足すこと。
_ROUTE_MAP: dict[str, str] = {
    "landing": "/",
    "guide": "/guide",
    "privacy": "/privacy",
    "terms": "/terms",
    "login": "/admin/login",
    "oauth_start": "/admin/auth",
    "callback": "/admin/callback",
    "logout": "/admin/logout",
    "index": "/admin/",
    "admin_root": "/admin/",
    "guild_select": "/admin/guilds",
    "select_guild": "/admin/guilds/select",
    "overview": "/admin/overview",
    "static": "/static/{path}",
}


def _url_for(name: str, **kwargs: str) -> str:
    """テンプレートの `url_for` はここへ来る。FastAPI のルーティングは見ない。

    `_ROUTE_MAP` を引くだけの静的な表引きで、実在するルートかどうかは検証
    しない。表に無い名前は `/{name}` を黙って返すので、テンプレートを書き
    間違えても実行時エラーにはならず、リンク切れとして現れる。名前を足す
    ときは `_ROUTE_MAP` へ対で足すこと（表のコメント参照）。
    """
    short = name.split(".")[-1] if "." in name else name
    dotted_as_underscore = name.replace(".", "_") if "." in name else ""
    path = (
        _ROUTE_MAP.get(short)
        or (dotted_as_underscore and _ROUTE_MAP.get(dotted_as_underscore))
        or _ROUTE_MAP.get(name, f"/{name}")
    )
    for k, v in kwargs.items():
        path = path.replace(f"{{{k}}}", str(v))
    return path


def _admin_asset_url(filename: str) -> str:
    """静的アセットの URL にキャッシュバスター（?v=）を付ける。

    ファイルの mtime とサイズから作るので、内容を更新すれば URL が自動で
    変わり、ブラウザ・CDN の古いキャッシュを踏まない。static/ の外を指す
    パスや読めないファイルは relative_to() / stat() で弾き、その場合は
    ADMIN_ASSET_VERSION（無ければ固定文字列）だけの URL にフォールバックする
    ── 404 にはしないが、キャッシュは更新されなくなる。
    """
    version_seed = os.environ.get("ADMIN_ASSET_VERSION", "admin")
    version = version_seed
    try:
        asset_path = (_static_root / filename).resolve()
        asset_path.relative_to(_static_root)
        stat = asset_path.stat()
        version = f"{version_seed}-{stat.st_mtime_ns:x}-{stat.st_size:x}"
    except (OSError, ValueError):
        pass
    return f"/static/{filename}?v={version}"


_ICON_NAME = _re.compile(r"^[a-z0-9-]+$")


def _icon(name: str, css_class: str = "icon") -> Markup:
    """同梱スプライトを参照するアイコン。webfont は使わない。"""
    ident = str(name).removeprefix("bi-")
    if not _ICON_NAME.match(ident):
        return Markup("")
    return Markup(
        f'<svg class="{css_class}" aria-hidden="true" focusable="false">'
        f'<use href="/static/icons/sprite.svg#{ident}"></use></svg>'
    )


templates.env.globals["admin_asset_url"] = _admin_asset_url
templates.env.globals["icon"] = _icon
templates.env.filters["tojson"] = lambda v: _json.dumps(v, ensure_ascii=False)


def _get_csrf_token(request: Request) -> str:
    """render() から呼ぶための薄いラッパー。発行そのものは security 側の責務。

    関数を分けているのは、発行ロジックを security.issue_csrf_token 側に一本化
    して、check_csrf が検証するトークンと画面へ埋め込むトークンが常に同じ
    経路で発行されるようにするため。ここで別実装を持つと、発行と検証がずれて
    フォームに埋まったトークンが常に不一致になりかねない。
    """
    # 発行そのものは security 側に持たせる（ログイン確定時と HTML 描画時の
    # 両方から同じ関数を使うため）。
    from webapp_admin.security import issue_csrf_token

    return issue_csrf_token(request)


def flash(request: Request, message: str, category: str = "info") -> None:
    """次に render() するページで1回だけ表示するメッセージを積む。

    セッションに溜めるだけで、消費（pop）は render() 側が担う。ここで pop
    すると、リダイレクトを挟んで別リクエストで表示する使い方（ログイン失敗
    など）が壊れる。
    """
    request.session.setdefault("_flashes", []).append([category, message])


def render(request: Request, template_name: str, status_code: int = 200, **ctx):
    """テンプレートを描画する。flash・CSRF トークン・埋め込み判定を必ず context へ足す。

    ここを通さず TemplateResponse を直接使うと、csrf_token が context に
    乗らずフォームの hidden input が空になり、そのフォームからの POST は
    check_csrf で必ず 403 になる。
    """
    messages = request.session.pop("_flashes", [])
    csrf_token = _get_csrf_token(request)
    # デスクトップUIのウィンドウ（<iframe>）内で読み込まれているかをFetch Metadataヘッダで判定する。
    # クエリパラメータ方式だとPOST後のリダイレクトで簡単に失われるが、
    # Sec-Fetch-Dest はそのiframeナビゲーションが続く限りリダイレクト後も維持されるため頑丈。
    is_embedded = request.headers.get("sec-fetch-dest", "").lower() == "iframe"
    ctx.setdefault("is_embedded", is_embedded)
    ctx.update(
        {
            "request": request,
            "session": request.session,
            "messages": messages,
            "csrf_token": csrf_token,
            "url_for": _url_for,
        }
    )
    # Starlette のバージョン差分:
    # - 新: TemplateResponse(request=..., name=..., context=...)
    # - 旧: TemplateResponse(name, context, ...)
    try:
        return templates.TemplateResponse(
            request=request,
            name=template_name,
            context=ctx,
            status_code=status_code,
        )
    except TypeError:
        # 型スタブは新しい TemplateResponse(request=..., name=..., context=...) 形式
        # しか知らないため、Starlette 旧バージョン互換のこの位置引数呼び出しは
        # 型検査に引っかかる。実際に来る Starlette のバージョンによって分岐する
        # フォールバックそのものは変えない。
        return templates.TemplateResponse(template_name, ctx, status_code=status_code)  # type: ignore[arg-type]
