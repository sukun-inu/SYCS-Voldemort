import secrets

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse

from webapp_admin.auth import DISCORD_CLIENT_ID, exchange_code, get_admin_guilds, get_oauth_url, get_user_info
from webapp_admin.extensions import limiter
from webapp_admin.security import check_login
from webapp_admin.templating import flash, render

router = APIRouter()


def _build_invite_url() -> str | None:
    if not DISCORD_CLIENT_ID:
        return None
    return (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        "&permissions=8&scope=bot+applications.commands"
    )


@router.get("/login")
@limiter.limit("30/minute")
async def login(request: Request):
    if "user" in request.session:
        target = "/admin/overview" if "guild_id" in request.session else "/admin/guilds"
        return RedirectResponse(target, status_code=303)
    return render(request, "login.html", invite_url=_build_invite_url())


@router.get("/auth")
@limiter.limit("10/minute")
async def oauth_start(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    return RedirectResponse(get_oauth_url(state), status_code=303)


@router.get("/callback")
@limiter.limit("10/minute")
async def callback(request: Request):
    if request.query_params.get("error"):
        flash(request, "Discord 認証がキャンセルされました。", "danger")
        return RedirectResponse("/admin/login", status_code=303)

    state = request.query_params.get("state", "")
    expected = request.session.pop("oauth_state", None)
    if not expected or not secrets.compare_digest(state, expected):
        flash(request, "不正なリクエストです（state 不一致）。", "danger")
        return RedirectResponse("/admin/login", status_code=303)

    code = request.query_params.get("code", "")
    if not code:
        flash(request, "認証コードが取得できませんでした。", "danger")
        return RedirectResponse("/admin/login", status_code=303)

    token_data = await exchange_code(code)
    if not token_data or "access_token" not in token_data:
        flash(request, "Discord 認証に失敗しました。", "danger")
        return RedirectResponse("/admin/login", status_code=303)

    access_token = token_data["access_token"]
    user_info = await get_user_info(access_token)
    if not user_info:
        flash(request, "ユーザー情報の取得に失敗しました。", "danger")
        return RedirectResponse("/admin/login", status_code=303)

    admin_guilds = await get_admin_guilds(access_token)
    if not admin_guilds:
        flash(request, "管理者権限を持つサーバーが見つかりませんでした。Bot が参加しているサーバーで管理者権限が必要です。", "warning")
        return RedirectResponse("/admin/login", status_code=303)

    request.session.clear()
    request.session["user"] = {
        "id": user_info["id"],
        "username": user_info.get("username", ""),
        "global_name": user_info.get("global_name"),
        "avatar": user_info.get("avatar"),
    }
    request.session["admin_guilds"] = admin_guilds

    return RedirectResponse("/admin/guilds", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    flash(request, "ログアウトしました。", "info")
    return RedirectResponse("/admin/login", status_code=303)
