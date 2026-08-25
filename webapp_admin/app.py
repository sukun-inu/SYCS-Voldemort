import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from webapp_admin.core.config import resolve_session_secret, settings_dir

_LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_log_dir = settings_dir() / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)
_fh = RotatingFileHandler(_log_dir / "admin.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
_fh.setFormatter(logging.Formatter(_LOG_FMT))
logging.getLogger().addHandler(_fh)

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse, RedirectResponse

from webapp_admin.schema.registry import PATH_TO_ID
from webapp_admin.extensions import limiter
from webapp_admin.metrics import (
    record_error_response,
    record_exception,
    record_request,
    start_background_monitor,
)
from webapp_admin.security import _NeedsGuild, _NeedsLogin
from webapp_admin.templating import render

logger = logging.getLogger(__name__)


def _flatten_exception_group(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        leaves: list[BaseException] = []
        for child in exc.exceptions:
            leaves.extend(_flatten_exception_group(child))
        return leaves
    return [exc]


def _unwrap_exception_group(exc: BaseException) -> BaseException:
    leaves = _flatten_exception_group(exc)
    return leaves[0] if leaves else exc


def _compact_admin_guilds(value):
    if not isinstance(value, list):
        return []
    compact: list[dict[str, str | None]] = []
    for guild in value:
        if not isinstance(guild, dict):
            continue
        try:
            guild_id = str(int(guild.get("id")))
        except (TypeError, ValueError):
            continue
        icon = guild.get("icon")
        compact.append({
            "id": guild_id,
            "name": str(guild.get("name") or "Unknown"),
            "icon": icon if isinstance(icon, str) else None,
        })
    return compact


def _make_json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _make_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_make_json_safe(v) for v in value]
    return str(value)


def _sanitize_session_payload(session: dict) -> None:
    if "admin_guilds" in session:
        session["admin_guilds"] = _compact_admin_guilds(session.get("admin_guilds"))

    try:
        json.dumps(session)
        return
    except (TypeError, ValueError):
        pass

    safe = _make_json_safe(session)
    if isinstance(safe, dict):
        session.clear()
        session.update(safe)


def _register_legacy_redirects(app: FastAPI) -> None:
    from webapp_admin.schema.registry import PANELS
    from webapp_admin.security import check_guild

    def _make_handler(app_id: str):
        async def handler(request: Request, _=Depends(check_guild)):
            return RedirectResponse(f"/admin/overview#{app_id}", status_code=303)

        return handler

    for panel in PANELS:
        if panel.path:
            app.add_api_route(panel.path, _make_handler(panel.id), methods=["GET"], include_in_schema=False)


def create_app() -> FastAPI:
    secret = resolve_session_secret()

    app = FastAPI(docs_url=None, redoc_url=None)
    app.state.limiter = limiter

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    from webapp_admin.views.auth_views import router as auth_router
    from webapp_admin.views.dashboard_views import router as dashboard_router
    from webapp_admin.api.apps import router as apps_api_router
    from webapp_admin.api.dev import router as dev_api_router
    from webapp_admin.api.recording import router as recording_api_router
    from webapp_admin.api.sql import router as sql_api_router
    from webapp_admin.api.users import router as users_api_router
    from services.djaudio_cdn import dlaudio_router

    app.include_router(auth_router, prefix="/admin")
    app.include_router(dashboard_router, prefix="/admin")
    app.include_router(apps_api_router, prefix="/admin/api")
    app.include_router(users_api_router, prefix="/admin/api")
    app.include_router(recording_api_router, prefix="/admin/api")
    app.include_router(dev_api_router, prefix="/admin/api/dev")
    app.include_router(sql_api_router, prefix="/admin/api/sql")
    app.include_router(dlaudio_router, prefix="/dlaudio")

    # 旧ページのURL（/admin/settings/... など）はブックマークやリンクが残っているので、
    # デスクトップ上の該当ウィンドウを開く形へ寄せる。対応表はパネル定義から作る。
    _register_legacy_redirects(app)

    from webapp_admin.auth import DISCORD_CLIENT_ID, get_bot_guild_count

    def _invite_url() -> str | None:
        if not DISCORD_CLIENT_ID:
            return None
        return (
            "https://discord.com/api/oauth2/authorize"
            f"?client_id={DISCORD_CLIENT_ID}"
            "&permissions=8&scope=bot+applications.commands"
        )

    @app.get("/")
    async def landing(request: Request):
        return render(request, "landing.html", invite_url=_invite_url(), guild_count=await get_bot_guild_count())

    @app.get("/guide")
    async def guide(request: Request):
        return render(request, "guide.html", invite_url=_invite_url())

    @app.get("/privacy")
    async def privacy(request: Request):
        return render(request, "privacy.html", invite_url=_invite_url())

    @app.get("/terms")
    async def terms(request: Request):
        return render(request, "terms.html", invite_url=_invite_url())

    @app.get("/admin/guide")
    async def redirect_admin_guide():
        return RedirectResponse("/guide", status_code=301)

    @app.get("/admin/privacy")
    async def redirect_admin_privacy():
        return RedirectResponse("/privacy", status_code=301)

    @app.get("/admin/terms")
    async def redirect_admin_terms():
        return RedirectResponse("/terms", status_code=301)

    @app.exception_handler(_NeedsLogin)
    async def needs_login_handler(request: Request, exc: _NeedsLogin):
        return RedirectResponse("/admin/login", status_code=303)

    @app.exception_handler(_NeedsGuild)
    async def needs_guild_handler(request: Request, exc: _NeedsGuild):
        return RedirectResponse("/admin/guilds", status_code=303)

    def _is_api(request: Request) -> bool:
        """JSON で返すべき相手か。

        画面から fetch する先は /admin/api/ だけではない（配信の /dlaudio/ も
        ミキサーが読む）。HTML のエラーページを返すと、fetch する側は本文を
        読めず「HTTP 400」としか言えない。Accept を見て使い分ける。
        ブラウザの遷移は text/html を要求するので、これまでどおり画面が出る。
        """
        if request.url.path.startswith("/admin/api/"):
            return True
        accept = request.headers.get("accept", "")
        return "application/json" in accept and "text/html" not in accept

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        message = "リクエストが多すぎます。しばらく待ってから再試行してください。"
        if _is_api(request):
            return JSONResponse({"detail": message}, status_code=429)
        return render(request, "error.html", status_code=429, code=429, message=message)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        msgs = {
            400: "不正なリクエストです。",
            403: "アクセス権限がありません。",
            404: "ページが見つかりません。",
            500: "サーバーエラーが発生しました。",
        }
        msg = msgs.get(exc.status_code, "エラーが発生しました。")
        # 断った理由が書いてあるなら、そのまま見せる。「不正なリクエストです」
        # だけでは、何を直せばいいのか分からない。
        detail = exc.detail if isinstance(exc.detail, str) and exc.detail else ""
        description = detail if detail and detail != msg else None
        # API は JSON で返す。HTML のエラーページを返すと、fetch する側は本文を
        # 読めず「HTTP 502」としか言えない。detail に入れた理由をそのまま渡す。
        if _is_api(request):
            return JSONResponse({"detail": detail or msg}, status_code=exc.status_code,
                                headers=getattr(exc, "headers", None))
        return render(request, "error.html", status_code=exc.status_code,
                      code=exc.status_code, message=msg, description=description)

    @app.exception_handler(ExceptionGroup)
    async def exception_group_handler(request: Request, exc: ExceptionGroup):
        root = _unwrap_exception_group(exc)
        if isinstance(root, _NeedsLogin):
            return RedirectResponse("/admin/login", status_code=303)
        if isinstance(root, _NeedsGuild):
            return RedirectResponse("/admin/guilds", status_code=303)
        if isinstance(root, HTTPException):
            return await http_exception_handler(request, root)

        leaves = _flatten_exception_group(exc)
        logger.error(
            "Unhandled ExceptionGroup path=%s method=%s root=%s leaves=%s",
            request.url.path,
            request.method,
            type(root).__name__,
            [f"{type(leaf).__name__}: {leaf}" for leaf in leaves],
            exc_info=exc,
        )
        return render(
            request, "error.html", status_code=500,
            code=500, message="サーバーエラーが発生しました。",
        )

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        client_ip = request.headers.get("CF-Connecting-IP") or (
            request.client.host if request.client else "unknown"
        )
        snap = {"method": request.method, "path": request.url.path, "endpoint": None, "remote_addr": client_ip}
        try:
            response = await call_next(request)
            if not request.url.path.startswith("/static"):
                record_request()
                record_error_response(response.status_code, snap)
        except Exception as exc:
            # ここに来るのは HTTPException / RateLimitExceeded / ExceptionGroup の
            # どれにも拾われなかった、想定していない例外（実装バグ）。それらは
            # 内側の ExceptionMiddleware で先に Response へ変換されるため、
            # ここへは来ない ＝ 監視・ログはこれまでどおり動く。
            record_exception(exc, snap)
            root = _unwrap_exception_group(exc) if isinstance(exc, BaseExceptionGroup) else exc
            logger.exception(
                "Request failed method=%s path=%s root=%s detail=%s",
                request.method,
                request.url.path,
                type(root).__name__,
                root,
            )
            # raise すると Starlette の既定ハンドラがプレーンテキスト（デバッグ
            # 時は HTML）を返し、fetch する側は本文を読めず「HTTP 500」としか
            # 言えなくなる（実例: relkind が asyncpg で bytes として返り、
            # JSONResponse の json.dumps がそのまま TypeError で落ちていた）。
            message = "サーバーエラーが発生しました。"
            if _is_api(request):
                return JSONResponse({"detail": message}, status_code=500)
            return render(request, "error.html", status_code=500, code=500, message=message)
        return response

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        secure = os.environ.get("FLASK_SECURE_COOKIES", "false").lower() == "true"
        if request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "no-cache, max-age=0, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        # iframe を使わなくなったので、埋め込みは全面的に拒否できる。
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # CDN からのスクリプト/スタイル読み込みは廃止した（アイコンも同梱スプライト）。
        # 残る外部は Discord のアバター画像と、Cloudflare が注入する計測スクリプトのみ。
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://static.cloudflareinsights.com; "
            "style-src 'self'; "
            "img-src 'self' https://cdn.discordapp.com data:; "
            "font-src 'self'; "
            "connect-src 'self' https://static.cloudflareinsights.com; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    @app.middleware("http")
    async def session_serialization_guard_middleware(request: Request, call_next):
        response = await call_next(request)
        session = getattr(request, "session", None)
        if isinstance(session, dict):
            _sanitize_session_payload(session)
        return response

    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie="admin_session",
        max_age=3600,
        same_site="lax",
        https_only=os.environ.get("FLASK_SECURE_COOKIES", "false").lower() == "true",
    )

    start_background_monitor(logger)

    return app


app = create_app()
