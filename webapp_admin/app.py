import logging
import os
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

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


def create_app() -> FastAPI:
    secret = os.environ.get("ADMIN_FLASK_SECRET_KEY")
    if not secret:
        secret = secrets.token_hex(32)
        logger.warning(
            "ADMIN_FLASK_SECRET_KEY が未設定のため一時キーを生成しました。"
            "マルチインスタンス運用では固定値を設定してください。"
        )

    app = FastAPI(docs_url=None, redoc_url=None)
    app.state.limiter = limiter

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    from webapp_admin.views.auth_views import router as auth_router
    from webapp_admin.views.dashboard_views import router as dashboard_router
    from webapp_admin.views.djaudio_views import dlaudio_router, router as djaudio_router
    from webapp_admin.views.settings_views import router as settings_router

    app.include_router(auth_router, prefix="/admin")
    app.include_router(dashboard_router, prefix="/admin")
    app.include_router(settings_router, prefix="/admin/settings")
    app.include_router(djaudio_router, prefix="/admin/settings")
    app.include_router(dlaudio_router, prefix="/dlaudio")

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
        return render(request, "landing.html", invite_url=_invite_url(), guild_count=get_bot_guild_count())

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

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return render(
            request, "error.html", status_code=429,
            code=429, message="リクエストが多すぎます。しばらく待ってから再試行してください。",
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        msgs = {
            400: "不正なリクエストです。",
            403: "アクセス権限がありません。",
            404: "ページが見つかりません。",
            500: "サーバーエラーが発生しました。",
        }
        msg = msgs.get(exc.status_code, "エラーが発生しました。")
        return render(request, "error.html", status_code=exc.status_code, code=exc.status_code, message=msg)

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
            record_exception(exc, snap)
            raise
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
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' https://cdn.discordapp.com data:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com "
            "https://fonts.gstatic.com https://static.cloudflareinsights.com"
        )
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
