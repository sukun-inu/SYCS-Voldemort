import logging
import os
import secrets
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_log_dir = Path(os.getenv("SETTINGS_DIR", str(Path(__file__).parent.parent / "data"))) / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)
_fh = RotatingFileHandler(_log_dir / "admin.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
_fh.setFormatter(logging.Formatter(_LOG_FMT))
logging.getLogger().addHandler(_fh)

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


def _get_or_create_secret_key() -> str:
    env_secret = os.environ.get("ADMIN_FLASK_SECRET_KEY", "").strip()
    if env_secret:
        return env_secret

    settings_dir = Path(os.getenv("SETTINGS_DIR", str(Path(__file__).parent.parent / "data")))
    secret_file = settings_dir / ".admin_session_secret"

    try:
        content = secret_file.read_text(encoding="utf-8").strip()
        if len(content) >= 32:
            return content
    except OSError:
        pass

    new_secret = secrets.token_hex(32)
    try:
        settings_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(secret_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_secret)
        logger.info("セッションシークレットをファイルに保存しました: %s", secret_file)
        return new_secret
    except FileExistsError:
        try:
            content = secret_file.read_text(encoding="utf-8").strip()
            if len(content) >= 32:
                return content
        except OSError:
            pass
    except OSError as e:
        logger.warning(
            "セッションシークレットの保存に失敗しました (%s)。"
            "マルチワーカー環境では ADMIN_FLASK_SECRET_KEY を設定してください。",
            e,
        )

    logger.warning(
        "ADMIN_FLASK_SECRET_KEY が未設定でファイル保存も失敗しました。"
        "一時キーを使用します。再起動またはワーカー切り替えでセッションが失われます。"
    )
    return new_secret


def create_app() -> FastAPI:
    secret = _get_or_create_secret_key()

    app = FastAPI(docs_url=None, redoc_url=None)
    app.state.limiter = limiter

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    from webapp_admin.views.auth_views import router as auth_router
    from webapp_admin.views.dashboard_views import router as dashboard_router
    from webapp_admin.views.dev_views import router as dev_router
    from webapp_admin.views.djaudio_views import dlaudio_router, router as djaudio_router
    from webapp_admin.views.settings_views import router as settings_router
    from webapp_admin.views.tts_views import router as tts_router

    app.include_router(auth_router, prefix="/admin")
    app.include_router(dashboard_router, prefix="/admin")
    app.include_router(dev_router, prefix="/admin/dev")
    app.include_router(settings_router, prefix="/admin/settings")
    app.include_router(djaudio_router, prefix="/admin/settings")
    app.include_router(tts_router, prefix="/admin/settings")
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
            record_exception(exc, snap)
            root = _unwrap_exception_group(exc) if isinstance(exc, BaseExceptionGroup) else exc
            logger.exception(
                "Request failed method=%s path=%s root=%s detail=%s",
                request.method,
                request.url.path,
                type(root).__name__,
                root,
            )
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
