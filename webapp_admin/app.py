import os
import secrets

from flask import Flask

from webapp_admin.extensions import csrf, limiter


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    secret = os.environ.get("ADMIN_FLASK_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_SECURE_COOKIES", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=3600,
        WTF_CSRF_TIME_LIMIT=3600,
    )

    csrf.init_app(app)
    limiter.init_app(app)

    from webapp_admin.views.auth_views import auth_bp
    from webapp_admin.views.dashboard_views import dashboard_bp
    from webapp_admin.views.settings_views import settings_bp

    app.register_blueprint(auth_bp, url_prefix="/admin")
    app.register_blueprint(dashboard_bp, url_prefix="/admin")
    app.register_blueprint(settings_bp, url_prefix="/admin/settings")

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' https://cdn.discordapp.com data:; "
            "font-src 'self' https://cdn.jsdelivr.net"
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
