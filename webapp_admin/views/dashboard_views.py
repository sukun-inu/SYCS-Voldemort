from fastapi import APIRouter, Depends, Request
from starlette.responses import JSONResponse, RedirectResponse

from services.logging_service import get_log_settings
from services.settings_store import (
    get_bypass_role_ids,
    get_djaudio_runtime_settings,
    get_earthquake_settings,
    get_goodbye_settings,
    get_news_feeds,
    get_reaction_roles,
    get_response_channel_id,
    get_sticky_messages,
    get_trusted_user_ids,
    get_vc_notify_channel_id,
    get_welcome_settings,
)
from webapp_admin.auth import get_guild_channels
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
    gid = request.session["guild_id"]
    log_s = get_log_settings(gid)
    ws = get_welcome_settings(gid)
    gs = get_goodbye_settings(gid)
    feeds = get_news_feeds(gid)
    eq = get_earthquake_settings(gid)
    rr = get_reaction_roles(gid)
    djaudio = get_djaudio_runtime_settings(gid)

    stats = {
        "log_channel": log_s.get("channel_id"),
        "log_level": log_s.get("level", "INFO"),
        "welcome_ch": ws.get("channel_id"),
        "goodbye_ch": gs.get("channel_id"),
        "vc_notify_ch": get_vc_notify_channel_id(gid) or None,
        "chatgpt_ch": get_response_channel_id(gid) or None,
        "sticky_count": len(get_sticky_messages(gid)),
        "rr_count": sum(len(v) for v in rr.values()),
        "news_feed_count": len(feeds),
        "eq_channel": eq.get("channel_id"),
        "eq_min_scale": eq.get("min_scale", 30),
        "trusted_count": len(get_trusted_user_ids(gid)),
        "bypass_count": len(get_bypass_role_ids(gid)),
        "djaudio_watch_channel": djaudio.watch_channel_id or None,
        "djaudio_cache_ttl": djaudio.cache_ttl,
        "djaudio_cooldown": djaudio.cooldown,
        "djaudio_max_urls": djaudio.max_urls,
    }
    channels = await get_guild_channels(gid)
    ch_map = {str(c["id"]): c["name"] for c in channels}
    return render(request, "dashboard.html", stats=stats, ch_map=ch_map)


@router.get("/api/metrics")
async def system_metrics(request: Request, _=Depends(check_guild)):
    return JSONResponse(collect_host_metrics())


@router.get("/api/incidents")
async def monitor_incidents(request: Request, _=Depends(check_guild)):
    return JSONResponse({"incidents": list_incidents(limit=30)})
