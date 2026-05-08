import logging
import os
import secrets
from pathlib import Path

from flask import Flask, got_request_exception, request, url_for

from webapp_admin.extensions import csrf, limiter
from webapp_admin.metrics import (
    record_error_response,
    record_exception,
    record_request,
    start_background_monitor,
)

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    secret = os.environ.get("ADMIN_FLASK_SECRET_KEY")
    if not secret:
        secret = secrets.token_hex(32)
        logger.warning(
            "ADMIN_FLASK_SECRET_KEY が未設定のため一時キーを生成しました。"
            "マルチインスタンス運用では固定値を設定してください。"
        )
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_SECURE_COOKIES", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=3600,
        WTF_CSRF_TIME_LIMIT=3600,
        SEND_FILE_MAX_AGE_DEFAULT=0,
        ADMIN_ASSET_VERSION=os.environ.get("ADMIN_ASSET_VERSION", "admin"),
    )

    static_root = Path(app.static_folder or "").resolve()

    def admin_asset_url(filename: str) -> str:
        version_seed = app.config.get("ADMIN_ASSET_VERSION", "admin")
        version = version_seed

        try:
            asset_path = (static_root / filename).resolve()
            asset_path.relative_to(static_root)
            stat = asset_path.stat()
            version = f"{version_seed}-{stat.st_mtime_ns:x}-{stat.st_size:x}"
        except (OSError, ValueError):
            pass

        return url_for("static", filename=filename, v=version)

    @app.context_processor
    def inject_asset_helpers():
        return {"admin_asset_url": admin_asset_url}

    csrf.init_app(app)
    limiter.init_app(app)

    from webapp_admin.views.auth_views import auth_bp
    from webapp_admin.views.dashboard_views import dashboard_bp
    from webapp_admin.views.djaudio_views import djaudio_bp, dlaudio_bp
    from webapp_admin.views.settings_views import settings_bp

    from webapp_admin.auth import DISCORD_CLIENT_ID, get_bot_guild_count

    def _invite_url() -> str | None:
        if not DISCORD_CLIENT_ID:
            return None
        return (
            "https://discord.com/api/oauth2/authorize"
            f"?client_id={DISCORD_CLIENT_ID}"
            "&permissions=8&scope=bot+applications.commands"
        )

    @app.route("/")
    @limiter.limit("60 per minute")
    def landing():
        from flask import render_template
        return render_template(
            "landing.html",
            invite_url=_invite_url(),
            guild_count=get_bot_guild_count(),
        )

    app.register_blueprint(auth_bp, url_prefix="/admin")
    app.register_blueprint(dashboard_bp, url_prefix="/admin")
    app.register_blueprint(settings_bp, url_prefix="/admin/settings")
    app.register_blueprint(djaudio_bp, url_prefix="/admin/settings")
    app.register_blueprint(dlaudio_bp, url_prefix="/dlaudio")

    def request_snapshot():
        return {
            "method": request.method,
            "path": request.path,
            "endpoint": request.endpoint,
            "remote_addr": request.headers.get("CF-Connecting-IP") or request.remote_addr,
        }

    def log_unhandled_exception(sender, exception, **extra):
        record_exception(exception, request_snapshot())

    got_request_exception.connect(log_unhandled_exception, app)
    start_background_monitor(app.logger)

    @app.after_request
    def set_security_headers(response):
        if request.endpoint == "static":
            response.headers["Cache-Control"] = "no-cache, max-age=0, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        else:
            record_request()
            record_error_response(response.status_code, request_snapshot())

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' https://cdn.discordapp.com data:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com https://static.cloudflareinsights.com"
        )
        return response

    @app.errorhandler(400)
    def bad_request(e):
        from flask import render_template
        return render_template("error.html", code=400, message="不正なリクエストです。"), 400

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template("error.html", code=403, message="アクセス権限がありません。"), 403

    @app.errorhandler(429)
    def too_many_requests(e):
        from flask import render_template
        return render_template("error.html", code=429, message="リクエストが多すぎます。しばらく待ってから再試行してください。"), 429

    @app.errorhandler(500)
    def internal_error(e):
        from flask import render_template
        return render_template("error.html", code=500, message="サーバーエラーが発生しました。"), 500

    return app
