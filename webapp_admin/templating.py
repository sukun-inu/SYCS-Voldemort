import json as _json
import os
import re as _re
import secrets
from pathlib import Path

from markupsafe import Markup

from fastapi import Request
from fastapi.templating import Jinja2Templates

_template_dir = Path(__file__).resolve().parent / "templates"
_static_root = Path(__file__).resolve().parent / "static"

templates = Jinja2Templates(directory=str(_template_dir))

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
    "user_state_dashboard": "/admin/users/state",
    "system_metrics": "/admin/api/metrics",
    "monitor_incidents": "/admin/api/incidents",
    "logging_settings": "/admin/settings/logging",
    "welcome_settings": "/admin/settings/welcome",
    "vc_notify": "/admin/settings/vc-notify",
    "sticky": "/admin/settings/sticky",
    "reaction_roles": "/admin/settings/reaction-roles",
    "news_feeds": "/admin/settings/news-feeds",
    "earthquake": "/admin/settings/earthquake",
    "security_settings": "/admin/settings/security",
    "djaudio_settings": "/admin/settings/djaudio",
    "tts_settings": "/admin/settings/tts",
    "dev_index": "/admin/dev",
    "dev_send_message": "/admin/dev/send-message",
    "dev_forward_message": "/admin/dev/forward-message",
    "dev_settings_guild": "/admin/dev/settings/{guild_id}",
    "dev_delete_cache_entry": "/admin/dev/cache/delete",
    "dev_purge_cache": "/admin/dev/cache/purge",
    "dev_news_send": "/admin/dev/news-send",
    "dev_earthquake_replay": "/admin/dev/earthquake-replay",
    "dev_api_channels": "/admin/dev/api/channels",
    "dev_api_logs": "/admin/dev/api/logs",
    "dev_api_user": "/admin/dev/api/user",
    "dev_export_guild": "/admin/dev/settings/{guild_id}/export",
    "dev_import_guild": "/admin/dev/settings/{guild_id}/import",
    "dev_test_notify_welcome": "/admin/dev/test-notify/welcome",
    "dev_test_notify_vc": "/admin/dev/test-notify/vc",
    "dlaudio_health": "/dlaudio/health",
    "serve_file": "/dlaudio/files/{guild_id}/{token}",
    "file_info": "/dlaudio/info/{guild_id}/{token}",
    "static": "/static/{path}",
}


def _url_for(name: str, **kwargs: str) -> str:
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
    if "_csrf_token" not in request.session:
        request.session["_csrf_token"] = secrets.token_hex(32)
    return request.session["_csrf_token"]


def flash(request: Request, message: str, category: str = "info") -> None:
    request.session.setdefault("_flashes", []).append([category, message])


def render(request: Request, template_name: str, status_code: int = 200, **ctx):
    messages = request.session.pop("_flashes", [])
    csrf_token = _get_csrf_token(request)
    # デスクトップUIのウィンドウ（<iframe>）内で読み込まれているかをFetch Metadataヘッダで判定する。
    # クエリパラメータ方式だとPOST後のリダイレクトで簡単に失われるが、
    # Sec-Fetch-Dest はそのiframeナビゲーションが続く限りリダイレクト後も維持されるため頑丈。
    is_embedded = request.headers.get("sec-fetch-dest", "").lower() == "iframe"
    ctx.setdefault("is_embedded", is_embedded)
    ctx.update({
        "request": request,
        "session": request.session,
        "messages": messages,
        "csrf_token": csrf_token,
        "url_for": _url_for,
    })
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
        return templates.TemplateResponse(template_name, ctx, status_code=status_code)
