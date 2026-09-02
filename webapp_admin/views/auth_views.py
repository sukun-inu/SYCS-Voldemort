import secrets
import time

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse

from webapp_admin.auth import DISCORD_CLIENT_ID, exchange_code, get_admin_guilds, get_oauth_url, get_user_info
from webapp_admin.extensions import limiter
from webapp_admin.security import check_csrf, issue_csrf_token
from webapp_admin.templating import flash, render

router = APIRouter()


def _build_invite_url() -> str | None:
    """ログイン前でも見せる「Botを招待」ボタンの遷移先。未設定なら None（ボタンは隠す）。

    app.py にも同じ組み立て（_invite_url）が別実装として存在する。scope や
    permissions を変えるときはそちらとも揃える必要があり、片方だけ直すと
    ページによって招待時の権限が違うという食い違いが起きる。
    """
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
    """ログイン画面。既にログイン済みなら画面を出さず先へ飛ばす。

    guild_id がまだセッションに無ければギルド選択へ、あればオーバービューへ
    直行させる。ログイン済みの利用者が再度ログイン画面を踏んでも、
    毎回ギルド選択からやり直しにはならない。
    """
    if "user" in request.session:
        target = "/admin/overview" if "guild_id" in request.session else "/admin/guilds"
        return RedirectResponse(target, status_code=303)
    return render(request, "login.html", invite_url=_build_invite_url())


@router.get("/auth")
@limiter.limit("10/minute")
async def oauth_start(request: Request):
    """Discord の認可画面へ渡す。CSRF 対策の state をここで発行しセッションへ積む。

    state は callback() が `oauth_state` として pop し、Discord から返って
    きた state と比較する。ここで保存し忘れる／別の値を使うと、callback 側の
    比較が常に不一致になりログインできなくなる。
    """
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    return RedirectResponse(get_oauth_url(state), status_code=303)


@router.get("/callback")
@limiter.limit("10/minute")
async def callback(request: Request):
    """Discord からの戻り先。state 検証 → トークン交換 → 管理者ギルドの絞り込み。

    どの段階が失敗しても例外にはせず、flash メッセージを積んでログイン画面へ
    戻す（Discord 側のエラー・state 不一致・トークン交換失敗・管理者ギルドが
    0件、のいずれも同じ形で処理する）。session.clear() を先に呼んでから
    書き込むのは、oauth_state など認証途中の値を新しいセッションへ持ち越さ
    ないため。CSRF トークンをここで issue_csrf_token() するのは、ログイン
    確定より前に発行すると未ログインのセッションのトークンが使われてしまう
    のを避けるため（security.issue_csrf_token のコメント参照）。
    """
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
        flash(
            request,
            "管理者権限を持つサーバーが見つかりませんでした。Bot が参加しているサーバーで管理者権限が必要です。",
            "warning",
        )
        return RedirectResponse("/admin/login", status_code=303)

    request.session.clear()
    request.session["user"] = {
        "id": user_info["id"],
        "username": user_info.get("username", ""),
        "global_name": user_info.get("global_name"),
        "avatar": user_info.get("avatar"),
    }
    request.session["admin_guilds"] = admin_guilds
    # 管理権限の一覧をいつ取得したか。ギルド選択時に古すぎたら取り直す
    # （Discord 側で権限を外されても、セッションが切れるまで管理できてしまう）。
    request.session["admin_guilds_at"] = time.time()
    # ログイン確定と同時に CSRF トークンを発行する。以前は HTML を描画する
    # ときにしか作られず、トークンが無いセッションでは検証が素通りしていた。
    issue_csrf_token(request)

    return RedirectResponse("/admin/guilds", status_code=303)


@router.post("/logout")
async def logout(request: Request, _csrf=Depends(check_csrf)):
    """実際にログアウトする経路。POST 専用（GET は logout_get で確認画面を挟む）。"""
    request.session.clear()
    flash(request, "ログアウトしました。", "info")
    return RedirectResponse("/admin/login", status_code=303)


@router.get("/logout")
async def logout_get(request: Request):
    """GET でのログアウトは受け付けない。

    以前は GET だけで実行できたため、外部サイトが <img src=".../admin/logout">
    を置くだけで強制ログアウトさせられた。確認ページを出し、実行は POST に寄せる。
    """
    if "user" not in request.session:
        return RedirectResponse("/admin/login", status_code=303)
    return render(request, "logout_confirm.html")
