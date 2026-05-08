import secrets

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from webapp_admin.auth import DISCORD_CLIENT_ID, exchange_code, get_admin_guilds, get_oauth_url, get_user_info
from webapp_admin.extensions import limiter

auth_bp = Blueprint("auth", __name__)


def _build_invite_url() -> str | None:
    if not DISCORD_CLIENT_ID:
        return None
    return (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        "&permissions=8&scope=bot+applications.commands"
    )


@auth_bp.route("/login")
@limiter.limit("30 per minute")
def login():
    if "user" in session:
        return redirect(url_for("dashboard.index"))
    return render_template("login.html", invite_url=_build_invite_url())


@auth_bp.route("/guide")
@limiter.limit("60 per minute")
def guide():
    return render_template("guide.html", invite_url=_build_invite_url())



@auth_bp.route("/auth")
@limiter.limit("10 per minute")
def oauth_start():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session.permanent = True
    return redirect(get_oauth_url(state))


@auth_bp.route("/callback")
@limiter.limit("10 per minute")
def callback():
    if request.args.get("error"):
        flash("Discord 認証がキャンセルされました。", "danger")
        return redirect(url_for("auth.login"))

    state = request.args.get("state", "")
    expected = session.pop("oauth_state", None)
    if not expected or not secrets.compare_digest(state, expected):
        flash("不正なリクエストです（state 不一致）。", "danger")
        return redirect(url_for("auth.login"))

    code = request.args.get("code", "")
    if not code:
        flash("認証コードが取得できませんでした。", "danger")
        return redirect(url_for("auth.login"))

    token_data = exchange_code(code)
    if not token_data or "access_token" not in token_data:
        flash("Discord 認証に失敗しました。", "danger")
        return redirect(url_for("auth.login"))

    access_token = token_data["access_token"]
    user_info = get_user_info(access_token)
    if not user_info:
        flash("ユーザー情報の取得に失敗しました。", "danger")
        return redirect(url_for("auth.login"))

    admin_guilds = get_admin_guilds(access_token)
    if not admin_guilds:
        flash("管理者権限を持つサーバーが見つかりませんでした。Bot が参加しているサーバーで管理者権限が必要です。", "warning")
        return redirect(url_for("auth.login"))

    session.clear()
    session.permanent = True
    session["user"] = {
        "id": user_info["id"],
        "username": user_info.get("username", ""),
        "global_name": user_info.get("global_name"),
        "avatar": user_info.get("avatar"),
    }
    session["admin_guilds"] = admin_guilds

    return redirect(url_for("dashboard.guild_select"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("ログアウトしました。", "info")
    return redirect(url_for("auth.login"))
