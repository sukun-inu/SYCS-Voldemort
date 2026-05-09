import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from starlette.responses import JSONResponse, RedirectResponse

from config import JST as _JST
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
from services.user_state_service import get_user_state_detail, list_recent_user_states
from webapp_admin.auth import get_guild_channels
from webapp_admin.metrics import collect_host_metrics, list_incidents
from webapp_admin.security import check_csrf, check_guild, check_login
from webapp_admin.templating import flash, render

router = APIRouter()

_STATUS_LABELS: dict[str, str] = {
    "active": "在籍",
    "left": "退出",
    "kicked": "KICK",
    "banned": "BAN中",
    "unbanned": "BAN解除",
    "unknown": "不明",
}

_EVENT_LABELS: dict[str, str] = {
    "member_join": "サーバー参加",
    "member_leave": "サーバー退出",
    "member_kick": "KICK",
    "member_ban": "BAN",
    "member_unban": "BAN解除",
    "member_nickname_changed": "ニック変更",
    "member_role_changed": "ロール変更",
    "member_timeout_set": "タイムアウト設定",
    "member_timeout_cleared": "タイムアウト解除",
    "voice_join": "VC参加",
    "voice_leave": "VC退出",
    "voice_move": "VC移動",
}


def _status_label(value: str | None) -> str:
    if not value:
        return _STATUS_LABELS["unknown"]
    return _STATUS_LABELS.get(value, value)


def _status_tone(value: str | None) -> str:
    if value == "active":
        return "success"
    if value in {"banned", "kicked"}:
        return "danger"
    if value in {"left", "unbanned"}:
        return "warning"
    return "accent"


def _event_label(value: str | None) -> str:
    if not value:
        return "-"
    return _EVENT_LABELS.get(value, value)


def _fmt_jst(value: datetime | None) -> str:
    if value is None:
        return "-"
    try:
        return value.astimezone(_JST).strftime("%Y/%m/%d %H:%M:%S")
    except Exception:
        return str(value)


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


@router.get("/users/state")
async def user_state_dashboard(
    request: Request,
    _=Depends(check_guild),
    q: str = Query(default="", max_length=128),
    user_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    event_limit: int = Query(default=200, ge=1, le=500),
):
    gid = int(request.session["guild_id"])
    keyword = q.strip()

    states_raw = await list_recent_user_states(
        gid,
        query=keyword or None,
        limit=limit,
    )
    states: list[dict] = []
    for row in states_raw:
        roles = row.get("roles", [])
        if not isinstance(roles, list):
            roles = []
        abilities = row.get("abilities", {})
        if not isinstance(abilities, dict):
            abilities = {}

        role_names: list[str] = []
        for role in roles:
            if not isinstance(role, dict):
                continue
            name = role.get("name")
            if isinstance(name, str) and name:
                role_names.append(name)

        enabled_abilities: list[str] = []
        for key, enabled in abilities.items():
            if bool(enabled):
                enabled_abilities.append(str(key))

        states.append(
            {
                **row,
                "status_label": _status_label(row.get("status")),
                "status_tone": _status_tone(row.get("status")),
                "last_event_label": _event_label(row.get("last_event_type")),
                "last_event_at_label": _fmt_jst(row.get("last_event_at")),
                "roles_preview": role_names[:5],
                "roles_count": len(role_names),
                "abilities_preview": enabled_abilities[:6],
                "abilities_count": len(enabled_abilities),
            }
        )

    selected_user: dict | None = None
    selected_events: list[dict] = []
    selected_missing = False
    if user_id is not None:
        detail = await get_user_state_detail(gid, user_id, event_limit=event_limit)
        if detail is None:
            selected_missing = True
        else:
            current = detail.get("current")
            if isinstance(current, dict):
                current_roles = current.get("roles", [])
                if not isinstance(current_roles, list):
                    current_roles = []
                current_abilities = current.get("abilities", {})
                if not isinstance(current_abilities, dict):
                    current_abilities = {}
                selected_user = {
                    **current,
                    "status_label": _status_label(current.get("status")),
                    "status_tone": _status_tone(current.get("status")),
                    "last_event_label": _event_label(current.get("last_event_type")),
                    "last_event_at_label": _fmt_jst(current.get("last_event_at")),
                    "first_seen_at_label": _fmt_jst(current.get("first_seen_at")),
                    "last_joined_at_label": _fmt_jst(current.get("last_joined_at")),
                    "last_left_at_label": _fmt_jst(current.get("last_left_at")),
                    "timed_out_until_label": _fmt_jst(current.get("timed_out_until")),
                    "roles": current_roles,
                    "abilities_enabled": sorted(
                        [str(k) for k, enabled in current_abilities.items() if bool(enabled)]
                    ),
                }

            for event in detail.get("events", []):
                if not isinstance(event, dict):
                    continue
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    payload = {}
                selected_events.append(
                    {
                        **event,
                        "event_label": _event_label(event.get("event_type")),
                        "event_at_label": _fmt_jst(event.get("event_at")),
                        "payload_pretty": json.dumps(payload, ensure_ascii=False, indent=2),
                    }
                )

    return render(
        request,
        "user_state.html",
        query=keyword,
        states=states,
        selected_user_id=user_id,
        selected_user=selected_user,
        selected_events=selected_events,
        selected_missing=selected_missing,
        limit=limit,
        event_limit=event_limit,
    )


@router.get("/api/metrics")
async def system_metrics(request: Request, _=Depends(check_guild)):
    return JSONResponse(collect_host_metrics())


@router.get("/api/incidents")
async def monitor_incidents(request: Request, _=Depends(check_guild)):
    return JSONResponse({"incidents": list_incidents(limit=30)})
