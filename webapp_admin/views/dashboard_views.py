"""デスクトップのシェルとギルド選択。

設定値や監査データの受け渡しは webapp_admin/api/ が担当する。
このモジュールは「どのHTMLを返すか」だけを持つ。
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import JSONResponse, RedirectResponse

from webapp_admin.metrics import collect_host_metrics, list_incidents
from webapp_admin.security import check_csrf, check_guild, check_login
from webapp_admin.templating import flash, render

router = APIRouter()


@router.get("/")
async def admin_root(request: Request, _=Depends(check_login)):
    if "guild_id" not in request.session:
        return RedirectResponse("/admin/guilds", status_code=303)
    return RedirectResponse("/admin/overview", status_code=303)


@router.get("/guilds")
async def guild_select(request: Request, _=Depends(check_login)):
    return render(request, "guild_select.html", guilds=request.session.get("admin_guilds", []))


@router.post("/guilds/select")
async def select_guild(request: Request, _=Depends(check_login), _csrf=Depends(check_csrf)):
    form = await request.form()
    guild_id_str = form.get("guild_id", "")
    try:
        guild_id = int(guild_id_str)
    except ValueError:
        flash(request, "無効なサーバーIDです。", "danger")
        return RedirectResponse("/admin/guilds", status_code=303)

    admin_guilds = request.session.get("admin_guilds", [])
    valid = {int(g["id"]) for g in admin_guilds}
    if guild_id not in valid:
        flash(request, "アクセス権限がありません。", "danger")
        return RedirectResponse("/admin/guilds", status_code=303)

    request.session["guild_id"] = guild_id
    for g in admin_guilds:
        if int(g["id"]) == guild_id:
            request.session["guild_name"] = g.get("name", "Unknown")
            request.session["guild_icon"] = g.get("icon")
            break

    return RedirectResponse("/admin/overview", status_code=303)


@router.get("/overview")
async def overview(request: Request, _=Depends(check_guild)):
    # シェルはHTMLとしては骨だけを返す。タイル一覧も各アプリの中身も
    # クライアントが /admin/api/apps から取得して描く。
    return render(request, "shell.html")


@router.get("/api/metrics")
async def system_metrics(request: Request, _=Depends(check_guild)):
    return JSONResponse(collect_host_metrics())


@router.get("/api/incidents")
async def monitor_incidents(request: Request, _=Depends(check_guild)):
    return JSONResponse({"incidents": list_incidents(limit=30)})
