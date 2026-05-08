"""
DJAudio-DL: MP3 ファイル配信 + 設定管理 Blueprint。
- /dlaudio/files/<guild_id>/<token>  → MP3 配信
- /dlaudio/info/<guild_id>/<token>   → ファイル情報 JSON
- /dlaudio/health                    → ヘルスチェック
- /admin/settings/djaudio            → 設定ページ
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from config import DJAUDIO_CACHE_DIR
from services.djaudio_cache import get_meta
from services.settings_store import (
    get_djaudio_cache_ttl,
    get_djaudio_cooldown,
    get_djaudio_max_urls,
    get_djaudio_settings,
    get_djaudio_watch_channel,
    set_djaudio_settings,
    set_djaudio_watch_channel,
)
from webapp_admin.auth import get_guild_channels
from webapp_admin.security import guild_required, validate_channel_id, validate_int

logger = logging.getLogger(__name__)

djaudio_bp  = Blueprint("djaudio", __name__)
dlaudio_bp  = Blueprint("dlaudio", __name__)  # ファイル配信用（URL prefix は /dlaudio）


# ────────────────────────────────────────────
# ヘルパー
# ────────────────────────────────────────────

def _validate_token(token: str) -> bool:
    return token.isalnum() and len(token) == 32


def _validate_guild_id(guild_id: str) -> bool:
    return guild_id.isdigit()


# ────────────────────────────────────────────
# ファイル配信 Blueprint（/dlaudio）
# ────────────────────────────────────────────

@dlaudio_bp.route("/health")
def health():
    return jsonify({"status": "ok"})


@dlaudio_bp.route("/files/<guild_id>/<token>")
def serve_file(guild_id: str, token: str):
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        abort(404)

    meta = get_meta(token)
    if meta is None:
        abort(410)

    if meta.get("guild_id") != guild_id:
        logger.warning("guild_id 不一致: URL=%s meta=%s token=%s", guild_id, meta.get("guild_id"), token)
        abort(403)

    mp3_path = DJAUDIO_CACHE_DIR / f"{token}.mp3"
    if not mp3_path.exists():
        abort(410)

    raw_name  = meta.get("filename", f"{token}.mp3")
    safe_name = "".join(c for c in raw_name if c.isalnum() or c in " ._-").strip() or f"{token}.mp3"
    if not safe_name.endswith(".mp3"):
        safe_name += ".mp3"

    logger.info("配信: guild=%s token=%s → %s", guild_id, token, safe_name)
    return send_file(
        str(mp3_path),
        as_attachment=True,
        download_name=safe_name,
        mimetype="audio/mpeg",
    )


@dlaudio_bp.route("/info/<guild_id>/<token>")
def file_info(guild_id: str, token: str):
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        abort(404)

    meta = get_meta(token)
    if meta is None:
        abort(410)

    if meta.get("guild_id") != guild_id:
        abort(403)

    now       = datetime.now(timezone.utc).timestamp()
    remaining = max(0, int(meta["expires_at"] - now))
    return jsonify({
        "token":             token,
        "title":             meta.get("title", ""),
        "filename":          meta.get("filename", ""),
        "expires_at":        meta.get("expires_at"),
        "remaining_seconds": remaining,
        "remaining_minutes": remaining // 60,
    })


@dlaudio_bp.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "アクセスが拒否されました", "code": 403}), 403


@dlaudio_bp.errorhandler(404)
def not_found(e):
    return jsonify({"error": "ファイルが見つかりません", "code": 404}), 404


@dlaudio_bp.errorhandler(410)
def gone(e):
    return jsonify({"error": "リンクの有効期限が切れています", "code": 410}), 410


# ────────────────────────────────────────────
# 設定管理 Blueprint（/admin/settings）
# ────────────────────────────────────────────

def _gid() -> int:
    return session["guild_id"]


@djaudio_bp.route("/djaudio", methods=["GET", "POST"])
@guild_required
def djaudio_settings():
    gid      = _gid()
    channels = get_guild_channels(gid)

    if request.method == "POST":
        action = request.form.get("action")

        if action == "set_channel":
            raw_ch = request.form.get("channel_id", "0")
            ch_id  = validate_channel_id(raw_ch)
            set_djaudio_watch_channel(gid, ch_id if ch_id else None)
            flash("監視チャンネルを保存しました。", "success")
            return redirect(url_for("djaudio.djaudio_settings"))

        elif action == "set_limits":
            cache_ttl = validate_int(request.form.get("cache_ttl", "600"), min_val=60, max_val=86400)
            cooldown  = validate_int(request.form.get("cooldown",  "30"),  min_val=0,  max_val=3600)
            max_urls  = validate_int(request.form.get("max_urls",  "3"),   min_val=1,  max_val=10)
            set_djaudio_settings(gid, {"cache_ttl": cache_ttl, "cooldown": cooldown, "max_urls": max_urls})
            flash("制限設定を保存しました。", "success")
            return redirect(url_for("djaudio.djaudio_settings"))

    current_ch  = get_djaudio_watch_channel(gid)
    current_ttl = get_djaudio_cache_ttl(gid)
    current_cd  = get_djaudio_cooldown(gid)
    current_mu  = get_djaudio_max_urls(gid)
    return render_template(
        "settings/djaudio.html",
        channels=channels,
        current_channel_id=current_ch,
        cache_ttl=current_ttl,
        cooldown=current_cd,
        max_urls=current_mu,
    )
