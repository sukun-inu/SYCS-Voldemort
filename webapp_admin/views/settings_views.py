import uuid

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse

from config import SCALE_LABELS
from services.logging_service import get_log_settings, set_log_channel, set_log_level
from services.settings_store import (
    add_bypass_roles,
    add_news_feed,
    add_reaction_role,
    add_trusted_users,
    get_bypass_role_ids,
    get_earthquake_notify_types,
    get_earthquake_settings,
    get_goodbye_settings,
    get_news_feeds,
    get_reaction_roles,
    get_response_channel_id,
    get_sticky_messages,
    get_trusted_user_ids,
    get_vc_notify_channel_id,
    get_vc_notify_role_id,
    get_welcome_settings,
    mark_sticky_pending_delete,
    remove_bypass_roles,
    remove_news_feed,
    remove_reaction_role,
    remove_trusted_users,
    set_earthquake_channel,
    set_earthquake_min_scale,
    set_earthquake_notify_types,
    set_goodbye_channel,
    set_goodbye_message,
    set_response_channel_id,
    set_sticky_message,
    set_vc_notify_channel_id,
    set_vc_notify_role_id,
    set_welcome_channel,
    set_welcome_message,
    update_news_feed,
)
from webapp_admin.auth import get_guild_channels, get_guild_roles
from webapp_admin.security import (
    check_csrf,
    check_guild,
    sanitize,
    validate_channel_id,
    validate_choice,
    validate_int,
)
from webapp_admin.templating import flash, render

router = APIRouter()

_LOG_LEVELS = {"NONE", "ERROR", "INFO", "DEBUG"}
_VALID_SCALES = {10, 20, 30, 40, 45, 50, 55, 60, 65, 70}
_NOTIFY_TYPE_LABELS: dict[str, str] = {
    "eew_forecast": "緊急地震速報（予報）",
    "eew_warning":  "緊急地震速報（警報）",
    "tsunami":      "津波情報",
    "quake_info":   "地震情報",
    "bot_news":     "ボットに関するお知らせ",
}


# ── ログ設定 ───────────────────────────────────────────────

@router.api_route("/logging", methods=["GET", "POST"])
async def logging_settings(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "set_log":
            ch_id = form.get("log_channel_id", "")
            level = sanitize(form.get("log_level", "INFO"), 10)
            validate_choice(level, _LOG_LEVELS)
            if ch_id and ch_id != "0":
                set_log_channel(gid, validate_channel_id(ch_id))
            elif ch_id == "0":
                set_log_channel(gid, None)
            set_log_level(gid, level)
            flash(request, "ログ設定を更新した。", "success")
        elif action == "set_chatgpt":
            ch_id = form.get("chatgpt_channel_id", "")
            if ch_id == "0" or not ch_id:
                set_response_channel_id(gid, None)
            else:
                set_response_channel_id(gid, validate_channel_id(ch_id))
            flash(request, "ChatGPT 応答チャンネルを更新した。", "success")
        return RedirectResponse("/admin/settings/logging", status_code=303)

    channels = await get_guild_channels(gid)
    ch_map = {c["id"]: c["name"] for c in channels}
    return render(
        request, "settings/logging.html",
        channels=channels,
        ch_map=ch_map,
        log_settings=get_log_settings(gid),
        chatgpt_ch=get_response_channel_id(gid),
        log_levels=sorted(_LOG_LEVELS),
    )


# ── ウェルカム / グッバイ ─────────────────────────────────

@router.api_route("/welcome", methods=["GET", "POST"])
async def welcome_settings(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "set_welcome":
            ch_id = form.get("welcome_channel_id", "")
            msg = sanitize(form.get("welcome_message", ""), 1000)
            if ch_id == "0" or not ch_id:
                set_welcome_channel(gid, None)
            else:
                set_welcome_channel(gid, validate_channel_id(ch_id))
            set_welcome_message(gid, msg or None)
            flash(request, "ウェルカム設定を更新した。", "success")
        elif action == "set_goodbye":
            ch_id = form.get("goodbye_channel_id", "")
            msg = sanitize(form.get("goodbye_message", ""), 1000)
            if ch_id == "0" or not ch_id:
                set_goodbye_channel(gid, None)
            else:
                set_goodbye_channel(gid, validate_channel_id(ch_id))
            set_goodbye_message(gid, msg or None)
            flash(request, "グッバイ設定を更新した。", "success")
        return RedirectResponse("/admin/settings/welcome", status_code=303)

    channels = await get_guild_channels(gid)
    ch_map = {c["id"]: c["name"] for c in channels}
    return render(
        request, "settings/welcome.html",
        channels=channels,
        ch_map=ch_map,
        welcome_s=get_welcome_settings(gid),
        goodbye_s=get_goodbye_settings(gid),
    )


# ── VC 通知 ───────────────────────────────────────────────

@router.api_route("/vc-notify", methods=["GET", "POST"])
async def vc_notify(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "set_channel":
            ch_id = form.get("vc_notify_channel_id", "")
            if ch_id == "0" or not ch_id:
                set_vc_notify_channel_id(gid, None)
                flash(request, "VC 通知チャンネルを解除した。", "success")
            else:
                set_vc_notify_channel_id(gid, validate_channel_id(ch_id))
                flash(request, "VC 通知チャンネルを設定した。", "success")
        elif action == "set_role":
            rid_str = form.get("vc_notify_role_id", "")
            if rid_str == "0" or not rid_str:
                set_vc_notify_role_id(gid, None)
                flash(request, "VC 通知ロールを解除した。", "success")
            else:
                try:
                    set_vc_notify_role_id(gid, int(rid_str))
                    flash(request, "VC 通知ロールを設定した。", "success")
                except ValueError:
                    flash(request, "無効なロールIDです。", "warning")
        return RedirectResponse("/admin/settings/vc-notify", status_code=303)

    channels = await get_guild_channels(gid)
    ch_map = {c["id"]: c["name"] for c in channels}
    return render(
        request, "settings/vc_notify.html",
        channels=channels,
        ch_map=ch_map,
        roles=await get_guild_roles(gid),
        current_ch=get_vc_notify_channel_id(gid),
        current_role=get_vc_notify_role_id(gid),
    )


# ── スティッキーメッセージ ────────────────────────────────

@router.api_route("/sticky", methods=["GET", "POST"])
async def sticky(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    channels = await get_guild_channels(gid)
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action in ("add", "set"):
            ch_id = form.get("channel_id", "")
            content = sanitize(form.get("content", ""), 1000).strip()
            if not content:
                flash(request, "内容を入力してください。", "warning")
                return RedirectResponse("/admin/settings/sticky", status_code=303)
            set_sticky_message(gid, validate_channel_id(ch_id), content)
            flash(request, "スティッキーメッセージを設定した。", "success")
        elif action == "remove":
            ch_id = form.get("channel_id", "")
            mark_sticky_pending_delete(gid, validate_channel_id(ch_id))
            flash(request, "スティッキーメッセージを解除した。", "success")
        return RedirectResponse("/admin/settings/sticky", status_code=303)

    ch_map = {c["id"]: c["name"] for c in channels}
    return render(
        request, "settings/sticky.html",
        channels=channels,
        stickies=get_sticky_messages(gid),
        ch_map=ch_map,
    )


# ── リアクションロール ────────────────────────────────────

@router.api_route("/reaction-roles", methods=["GET", "POST"])
async def reaction_roles(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    roles = await get_guild_roles(gid)
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "add":
            msg_id_str = sanitize(form.get("message_id", ""), 20)
            emoji = sanitize(form.get("emoji", ""), 50).strip()
            role_id_str = form.get("role_id", "")
            try:
                msg_id = int(msg_id_str)
            except ValueError:
                flash(request, "メッセージIDは数値で入力してください。", "warning")
                return RedirectResponse("/admin/settings/reaction-roles", status_code=303)
            if not emoji:
                flash(request, "絵文字を入力してください。", "warning")
                return RedirectResponse("/admin/settings/reaction-roles", status_code=303)
            try:
                role_id = int(role_id_str)
            except ValueError:
                flash(request, "ロールを選択してください。", "warning")
                return RedirectResponse("/admin/settings/reaction-roles", status_code=303)
            add_reaction_role(gid, msg_id, emoji, role_id)
            flash(request, "リアクションロールを追加した。", "success")
        elif action == "remove":
            msg_id_str = sanitize(form.get("message_id", ""), 20)
            emoji = sanitize(form.get("emoji", ""), 50).strip()
            try:
                msg_id = int(msg_id_str)
            except ValueError:
                flash(request, "無効なメッセージIDです。", "warning")
                return RedirectResponse("/admin/settings/reaction-roles", status_code=303)
            ok = remove_reaction_role(gid, msg_id, emoji)
            flash(request, "リアクションロールを削除した。" if ok else "該当するエントリが見つからなかった。",
                  "success" if ok else "warning")
        return RedirectResponse("/admin/settings/reaction-roles", status_code=303)

    role_map = {str(r["id"]): r["name"] for r in roles}
    return render(
        request, "settings/reaction_roles.html",
        roles=roles,
        rr=get_reaction_roles(gid),
        role_map=role_map,
    )


# ── ニュースフィード ──────────────────────────────────────

@router.api_route("/news-feeds", methods=["GET", "POST"])
async def news_feeds(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    channels = await get_guild_channels(gid)
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "add":
            ch_id = form.get("channel_id", "")
            query = sanitize(form.get("query", ""), 200).strip()
            interval_str = form.get("interval", "60")
            if not query:
                flash(request, "検索クエリを入力してください。", "warning")
                return RedirectResponse("/admin/settings/news-feeds", status_code=303)
            feeds = get_news_feeds(gid)
            if len(feeds) >= 10:
                flash(request, "フィードは最大 10 件まで登録できる。", "warning")
                return RedirectResponse("/admin/settings/news-feeds", status_code=303)
            fid = uuid.uuid4().hex[:8]
            add_news_feed(gid, fid, validate_channel_id(ch_id), query, validate_int(interval_str, 5, 1440))
            flash(request, f"ニュースフィードを追加した。（ID: {fid}）", "success")
        elif action == "edit":
            fid = sanitize(form.get("feed_id", ""), 8)
            ch_id = form.get("channel_id", "")
            query = sanitize(form.get("query", ""), 200).strip()
            interval_str = form.get("interval", "60")
            if not query:
                flash(request, "検索クエリを入力してください。", "warning")
                return RedirectResponse("/admin/settings/news-feeds", status_code=303)
            ok = update_news_feed(gid, fid, validate_channel_id(ch_id), query, validate_int(interval_str, 5, 1440))
            flash(request, "フィードを更新した。" if ok else "該当するフィードが見つからなかった。",
                  "success" if ok else "warning")
        elif action == "remove":
            fid = sanitize(form.get("feed_id", ""), 8)
            ok = remove_news_feed(gid, fid)
            flash(request, "フィードを削除した。" if ok else "該当するフィードが見つからなかった。",
                  "success" if ok else "warning")
        return RedirectResponse("/admin/settings/news-feeds", status_code=303)

    ch_map = {c["id"]: c["name"] for c in channels}
    return render(
        request, "settings/news_feeds.html",
        channels=channels,
        feeds=get_news_feeds(gid),
        ch_map=ch_map,
    )


# ── 地震アラート ──────────────────────────────────────────

@router.api_route("/earthquake", methods=["GET", "POST"])
async def earthquake(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "set_channel":
            ch_id = form.get("channel_id", "")
            if ch_id == "0" or not ch_id:
                set_earthquake_channel(gid, None)
                flash(request, "地震アラートチャンネルを解除した。", "success")
            else:
                set_earthquake_channel(gid, validate_channel_id(ch_id))
                flash(request, "地震アラートチャンネルを設定した。", "success")
        elif action == "set_scale":
            scale = validate_int(form.get("min_scale", "30"), 10, 70)
            if scale not in _VALID_SCALES:
                flash(request, "無効な震度値です。", "warning")
                return RedirectResponse("/admin/settings/earthquake", status_code=303)
            set_earthquake_min_scale(gid, scale)
            flash(request, f"最小震度を {SCALE_LABELS.get(scale, scale)} に設定した。", "success")
        elif action == "set_notify_types":
            valid_keys = set(_NOTIFY_TYPE_LABELS.keys())
            types = {k: (f"notify_{k}" in form) for k in valid_keys}
            set_earthquake_notify_types(gid, types)
            flash(request, "通知タイプを更新した。", "success")
        return RedirectResponse("/admin/settings/earthquake", status_code=303)

    channels = await get_guild_channels(gid)
    ch_map = {c["id"]: c["name"] for c in channels}
    return render(
        request, "settings/earthquake.html",
        channels=channels,
        ch_map=ch_map,
        eq_s=get_earthquake_settings(gid),
        scale_labels=SCALE_LABELS,
        valid_scales=sorted(_VALID_SCALES),
        notify_types=get_earthquake_notify_types(gid),
        notify_type_labels=_NOTIFY_TYPE_LABELS,
    )


# ── セキュリティ設定 ──────────────────────────────────────

@router.api_route("/security", methods=["GET", "POST"])
async def security_settings(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    roles = await get_guild_roles(gid)
    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")
        if action == "add_trusted":
            uid_str = sanitize(form.get("user_id", ""), 20)
            try:
                uid = int(uid_str)
            except ValueError:
                flash(request, "ユーザーIDは数値で入力してください。", "warning")
                return RedirectResponse("/admin/settings/security", status_code=303)
            add_trusted_users(gid, [uid])
            flash(request, f"ユーザー {uid} を信頼済みに追加した。", "success")
        elif action == "remove_trusted":
            uid_str = sanitize(form.get("user_id", ""), 20)
            try:
                uid = int(uid_str)
            except ValueError:
                flash(request, "無効なユーザーIDです。", "warning")
                return RedirectResponse("/admin/settings/security", status_code=303)
            remove_trusted_users(gid, [uid])
            flash(request, f"ユーザー {uid} を信頼済みから削除した。", "success")
        elif action == "add_bypass":
            try:
                rid = int(form.get("role_id", ""))
            except ValueError:
                flash(request, "ロールを選択してください。", "warning")
                return RedirectResponse("/admin/settings/security", status_code=303)
            add_bypass_roles(gid, [rid])
            flash(request, "バイパスロールを追加した。", "success")
        elif action == "remove_bypass":
            try:
                rid = int(form.get("role_id", ""))
            except ValueError:
                flash(request, "無効なロールIDです。", "warning")
                return RedirectResponse("/admin/settings/security", status_code=303)
            remove_bypass_roles(gid, [rid])
            flash(request, "バイパスロールを削除した。", "success")
        return RedirectResponse("/admin/settings/security", status_code=303)

    role_map = {str(r["id"]): r["name"] for r in roles}
    return render(
        request, "settings/security.html",
        roles=roles,
        trusted_ids=get_trusted_user_ids(gid),
        bypass_ids=get_bypass_role_ids(gid),
        role_map=role_map,
    )
