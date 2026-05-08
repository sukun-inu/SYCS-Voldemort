from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

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
from services.logging_service import get_log_settings
from webapp_admin.auth import get_guild_channels
from webapp_admin.metrics import collect_host_metrics, list_incidents
from webapp_admin.security import login_required, guild_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    if "guild_id" not in session:
        return redirect(url_for("dashboard.guild_select"))
    return redirect(url_for("dashboard.overview"))


@dashboard_bp.route("/guilds")
@login_required
def guild_select():
    return render_template("guild_select.html", guilds=session.get("admin_guilds", []))


@dashboard_bp.route("/guilds/select", methods=["POST"])
@login_required
def select_guild():
    guild_id_str = request.form.get("guild_id", "")
    try:
        guild_id = int(guild_id_str)
    except ValueError:
        flash("無効なサーバーIDです。", "danger")
        return redirect(url_for("dashboard.guild_select"))

    admin_guilds = session.get("admin_guilds", [])
    valid = {int(g["id"]) for g in admin_guilds}
    if guild_id not in valid:
        flash("アクセス権限がありません。", "danger")
        return redirect(url_for("dashboard.guild_select"))

    session["guild_id"] = guild_id
    for g in admin_guilds:
        if int(g["id"]) == guild_id:
            session["guild_name"] = g.get("name", "Unknown")
            session["guild_icon"] = g.get("icon")
            break

    return redirect(url_for("dashboard.overview"))


@dashboard_bp.route("/overview")
@guild_required
def overview():
    gid = session["guild_id"]
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
    channels = get_guild_channels(gid)
    ch_map = {str(c["id"]): c["name"] for c in channels}
    return render_template("dashboard.html", stats=stats, ch_map=ch_map)


@dashboard_bp.route("/api/metrics")
@guild_required
def system_metrics():
    return jsonify(collect_host_metrics())


@dashboard_bp.route("/api/incidents")
@guild_required
def monitor_incidents():
    return jsonify({"incidents": list_incidents(limit=30)})
