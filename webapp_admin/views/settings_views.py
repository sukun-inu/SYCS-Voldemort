import uuid

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from services.logging_service import get_log_settings, set_log_channel, set_log_level
from services.settings_store import (
    add_bypass_roles,
    add_news_feed,
    update_news_feed,
    add_reaction_role,
    add_trusted_users,
    get_bypass_role_ids,
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
    set_goodbye_channel,
    set_goodbye_message,
    set_response_channel_id,
    set_sticky_message,
    set_vc_notify_channel_id,
    set_vc_notify_role_id,
    set_welcome_channel,
    set_welcome_message,
)
from webapp_admin.auth import get_guild_channels, get_guild_roles
from webapp_admin.security import (
    guild_required,
    sanitize,
    validate_channel_id,
    validate_choice,
    validate_int,
)

settings_bp = Blueprint("settings", __name__)

_LOG_LEVELS = {"NONE", "ERROR", "INFO", "DEBUG"}
_VALID_SCALES = {10, 20, 30, 40, 45, 50, 55, 60, 65, 70}
_SCALE_LABELS = {
    10: "1", 20: "2", 30: "3", 40: "4", 45: "4強",
    50: "5弱", 55: "5強", 60: "6弱", 65: "6強", 70: "7",
}


def _gid() -> int:
    return session["guild_id"]


def _channels():
    return get_guild_channels(_gid())


def _roles():
    return get_guild_roles(_gid())


# ── ログ設定 ───────────────────────────────────────────────

@settings_bp.route("/logging", methods=["GET", "POST"])
@guild_required
def logging_settings():
    gid = _gid()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "set_log":
            ch_id = request.form.get("log_channel_id", "")
            level = sanitize(request.form.get("log_level", "INFO"), 10)
            validate_choice(level, _LOG_LEVELS)
            if ch_id and ch_id != "0":
                set_log_channel(gid, validate_channel_id(ch_id))
            elif ch_id == "0":
                set_log_channel(gid, None)
            set_log_level(gid, level)
            flash("ログ設定を更新した。", "success")
        elif action == "set_chatgpt":
            ch_id = request.form.get("chatgpt_channel_id", "")
            if ch_id == "0" or not ch_id:
                set_response_channel_id(gid, None)
            else:
                set_response_channel_id(gid, validate_channel_id(ch_id))
            flash("ChatGPT 応答チャンネルを更新した。", "success")
        return redirect(url_for("settings.logging_settings"))

    return render_template(
        "settings/logging.html",
        channels=_channels(),
        log_settings=get_log_settings(gid),
        chatgpt_ch=get_response_channel_id(gid),
        log_levels=sorted(_LOG_LEVELS),
    )


# ── ウェルカム / グッバイ ─────────────────────────────────

@settings_bp.route("/welcome", methods=["GET", "POST"])
@guild_required
def welcome_settings():
    gid = _gid()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "set_welcome":
            ch_id = request.form.get("welcome_channel_id", "")
            msg = sanitize(request.form.get("welcome_message", ""), 1000)
            if ch_id == "0" or not ch_id:
                set_welcome_channel(gid, None)
            else:
                set_welcome_channel(gid, validate_channel_id(ch_id))
            set_welcome_message(gid, msg or None)
            flash("ウェルカム設定を更新した。", "success")
        elif action == "set_goodbye":
            ch_id = request.form.get("goodbye_channel_id", "")
            msg = sanitize(request.form.get("goodbye_message", ""), 1000)
            if ch_id == "0" or not ch_id:
                set_goodbye_channel(gid, None)
            else:
                set_goodbye_channel(gid, validate_channel_id(ch_id))
            set_goodbye_message(gid, msg or None)
            flash("グッバイ設定を更新した。", "success")
        return redirect(url_for("settings.welcome_settings"))

    return render_template(
        "settings/welcome.html",
        channels=_channels(),
        welcome_s=get_welcome_settings(gid),
        goodbye_s=get_goodbye_settings(gid),
    )


# ── VC 通知 ───────────────────────────────────────────────

@settings_bp.route("/vc-notify", methods=["GET", "POST"])
@guild_required
def vc_notify():
    gid = _gid()
    if request.method == "POST":
        action = request.form.get("action", "set_channel")
        if action == "set_channel":
            ch_id = request.form.get("vc_notify_channel_id", "")
            if ch_id == "0" or not ch_id:
                set_vc_notify_channel_id(gid, None)
                flash("VC 通知チャンネルを解除した。", "success")
            else:
                set_vc_notify_channel_id(gid, validate_channel_id(ch_id))
                flash("VC 通知チャンネルを設定した。", "success")
        elif action == "set_role":
            rid_str = request.form.get("vc_notify_role_id", "")
            if rid_str == "0" or not rid_str:
                set_vc_notify_role_id(gid, None)
                flash("VC 通知ロールを解除した。", "success")
            else:
                try:
                    set_vc_notify_role_id(gid, int(rid_str))
                    flash("VC 通知ロールを設定した。", "success")
                except ValueError:
                    flash("無効なロールIDです。", "warning")
        return redirect(url_for("settings.vc_notify"))

    return render_template(
        "settings/vc_notify.html",
        channels=_channels(),
        roles=_roles(),
        current_ch=get_vc_notify_channel_id(gid),
        current_role=get_vc_notify_role_id(gid),
    )


# ── スティッキーメッセージ ────────────────────────────────

@settings_bp.route("/sticky", methods=["GET", "POST"])
@guild_required
def sticky():
    gid = _gid()
    channels = _channels()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action in ("add", "set"):
            ch_id = request.form.get("channel_id", "")
            content = sanitize(request.form.get("content", ""), 1000).strip()
            if not content:
                flash("内容を入力してください。", "warning")
                return redirect(url_for("settings.sticky"))
            set_sticky_message(gid, validate_channel_id(ch_id), content)
            flash("スティッキーメッセージを設定した。", "success")
        elif action == "remove":
            ch_id = request.form.get("channel_id", "")
            mark_sticky_pending_delete(gid, validate_channel_id(ch_id))
            flash("スティッキーメッセージを解除した。", "success")
        return redirect(url_for("settings.sticky"))

    ch_map = {c["id"]: c["name"] for c in channels}
    return render_template(
        "settings/sticky.html",
        channels=channels,
        stickies=get_sticky_messages(gid),
        ch_map=ch_map,
    )


# ── リアクションロール ────────────────────────────────────

@settings_bp.route("/reaction-roles", methods=["GET", "POST"])
@guild_required
def reaction_roles():
    gid = _gid()
    roles = _roles()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "add":
            msg_id_str = sanitize(request.form.get("message_id", ""), 20)
            emoji = sanitize(request.form.get("emoji", ""), 50).strip()
            role_id_str = request.form.get("role_id", "")
            try:
                msg_id = int(msg_id_str)
            except ValueError:
                flash("メッセージIDは数値で入力してください。", "warning")
                return redirect(url_for("settings.reaction_roles"))
            if not emoji:
                flash("絵文字を入力してください。", "warning")
                return redirect(url_for("settings.reaction_roles"))
            try:
                role_id = int(role_id_str)
            except ValueError:
                flash("ロールを選択してください。", "warning")
                return redirect(url_for("settings.reaction_roles"))
            add_reaction_role(gid, msg_id, emoji, role_id)
            flash("リアクションロールを追加した。", "success")
        elif action == "remove":
            msg_id_str = sanitize(request.form.get("message_id", ""), 20)
            emoji = sanitize(request.form.get("emoji", ""), 50).strip()
            try:
                msg_id = int(msg_id_str)
            except ValueError:
                flash("無効なメッセージIDです。", "warning")
                return redirect(url_for("settings.reaction_roles"))
            ok = remove_reaction_role(gid, msg_id, emoji)
            flash("リアクションロールを削除した。" if ok else "該当するエントリが見つからなかった。",
                  "success" if ok else "warning")
        return redirect(url_for("settings.reaction_roles"))

    role_map = {str(r["id"]): r["name"] for r in roles}
    return render_template(
        "settings/reaction_roles.html",
        roles=roles,
        rr=get_reaction_roles(gid),
        role_map=role_map,
    )


# ── ニュースフィード ──────────────────────────────────────

@settings_bp.route("/news-feeds", methods=["GET", "POST"])
@guild_required
def news_feeds():
    gid = _gid()
    channels = _channels()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "add":
            ch_id = request.form.get("channel_id", "")
            query = sanitize(request.form.get("query", ""), 200).strip()
            interval_str = request.form.get("interval", "60")
            if not query:
                flash("検索クエリを入力してください。", "warning")
                return redirect(url_for("settings.news_feeds"))
            feeds = get_news_feeds(gid)
            if len(feeds) >= 10:
                flash("フィードは最大 10 件まで登録できる。", "warning")
                return redirect(url_for("settings.news_feeds"))
            fid = uuid.uuid4().hex[:8]
            add_news_feed(gid, fid, validate_channel_id(ch_id), query, validate_int(interval_str, 5, 1440))
            flash(f"ニュースフィードを追加した。（ID: {fid}）", "success")
        elif action == "edit":
            fid = sanitize(request.form.get("feed_id", ""), 8)
            ch_id = request.form.get("channel_id", "")
            query = sanitize(request.form.get("query", ""), 200).strip()
            interval_str = request.form.get("interval", "60")
            if not query:
                flash("検索クエリを入力してください。", "warning")
                return redirect(url_for("settings.news_feeds"))
            ok = update_news_feed(gid, fid, validate_channel_id(ch_id), query, validate_int(interval_str, 5, 1440))
            flash("フィードを更新した。" if ok else "該当するフィードが見つからなかった。",
                  "success" if ok else "warning")
        elif action == "remove":
            fid = sanitize(request.form.get("feed_id", ""), 8)
            ok = remove_news_feed(gid, fid)
            flash("フィードを削除した。" if ok else "該当するフィードが見つからなかった。",
                  "success" if ok else "warning")
        return redirect(url_for("settings.news_feeds"))

    ch_map = {c["id"]: c["name"] for c in channels}
    return render_template(
        "settings/news_feeds.html",
        channels=channels,
        feeds=get_news_feeds(gid),
        ch_map=ch_map,
    )


# ── 地震アラート ──────────────────────────────────────────

@settings_bp.route("/earthquake", methods=["GET", "POST"])
@guild_required
def earthquake():
    gid = _gid()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "set_channel":
            ch_id = request.form.get("channel_id", "")
            if ch_id == "0" or not ch_id:
                set_earthquake_channel(gid, None)
                flash("地震アラートチャンネルを解除した。", "success")
            else:
                set_earthquake_channel(gid, validate_channel_id(ch_id))
                flash("地震アラートチャンネルを設定した。", "success")
        elif action == "set_scale":
            scale = validate_int(request.form.get("min_scale", "30"), 10, 70)
            if scale not in _VALID_SCALES:
                flash("無効な震度値です。", "warning")
                return redirect(url_for("settings.earthquake"))
            set_earthquake_min_scale(gid, scale)
            flash(f"最小震度を {_SCALE_LABELS.get(scale, scale)} に設定した。", "success")
        return redirect(url_for("settings.earthquake"))

    return render_template(
        "settings/earthquake.html",
        channels=_channels(),
        eq_s=get_earthquake_settings(gid),
        scale_labels=_SCALE_LABELS,
        valid_scales=sorted(_VALID_SCALES),
    )


# ── セキュリティ設定 ──────────────────────────────────────

@settings_bp.route("/security", methods=["GET", "POST"])
@guild_required
def security_settings():
    gid = _gid()
    roles = _roles()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "add_trusted":
            uid_str = sanitize(request.form.get("user_id", ""), 20)
            try:
                uid = int(uid_str)
            except ValueError:
                flash("ユーザーIDは数値で入力してください。", "warning")
                return redirect(url_for("settings.security_settings"))
            add_trusted_users(gid, [uid])
            flash(f"ユーザー {uid} を信頼済みに追加した。", "success")
        elif action == "remove_trusted":
            uid_str = sanitize(request.form.get("user_id", ""), 20)
            try:
                uid = int(uid_str)
            except ValueError:
                flash("無効なユーザーIDです。", "warning")
                return redirect(url_for("settings.security_settings"))
            remove_trusted_users(gid, [uid])
            flash(f"ユーザー {uid} を信頼済みから削除した。", "success")
        elif action == "add_bypass":
            try:
                rid = int(request.form.get("role_id", ""))
            except ValueError:
                flash("ロールを選択してください。", "warning")
                return redirect(url_for("settings.security_settings"))
            add_bypass_roles(gid, [rid])
            flash("バイパスロールを追加した。", "success")
        elif action == "remove_bypass":
            try:
                rid = int(request.form.get("role_id", ""))
            except ValueError:
                flash("無効なロールIDです。", "warning")
                return redirect(url_for("settings.security_settings"))
            remove_bypass_roles(gid, [rid])
            flash("バイパスロールを削除した。", "success")
        return redirect(url_for("settings.security_settings"))

    role_map = {str(r["id"]): r["name"] for r in roles}
    return render_template(
        "settings/security.html",
        roles=roles,
        trusted_ids=get_trusted_user_ids(gid),
        bypass_ids=get_bypass_role_ids(gid),
        role_map=role_map,
    )
