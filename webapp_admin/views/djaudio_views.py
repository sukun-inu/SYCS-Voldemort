"""
DJAudio-DL: MP3 ファイル配信 + 設定管理 Router。
- /dlaudio/files/<guild_id>/<token>  → MP3 配信
- /dlaudio/info/<guild_id>/<token>   → ファイル情報 JSON
- /dlaudio/health                    → ヘルスチェック
- /admin/settings/djaudio            → 設定ページ
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse

from config import DJAUDIO_CACHE_DIR
from services.djaudio_cache import get_meta
from services.settings_store import (
    get_djaudio_runtime_settings,
    set_djaudio_output_channel,
    set_djaudio_settings,
    set_djaudio_watch_channel,
)
from webapp_admin.auth import get_guild_channels
from webapp_admin.security import check_csrf, check_guild, validate_channel_id, validate_int
from webapp_admin.templating import flash, render

logger = logging.getLogger(__name__)

router = APIRouter()
dlaudio_router = APIRouter()


# ────────────────────────────────────────────
# ヘルパー
# ────────────────────────────────────────────

def _validate_token(token: str) -> bool:
    return token.isalnum() and len(token) == 32


def _validate_guild_id(guild_id: str) -> bool:
    return guild_id.isdigit()


# ────────────────────────────────────────────
# ファイル配信 Router（/dlaudio）
# ────────────────────────────────────────────

@dlaudio_router.get("/health")
async def dlaudio_health():
    return JSONResponse({"status": "ok"})


@dlaudio_router.get("/files/{guild_id}/{token}")
async def serve_file(guild_id: str, token: str):
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410)

    if meta.get("guild_id") != guild_id:
        logger.warning("guild_id 不一致: URL=%s meta=%s token=%s", guild_id, meta.get("guild_id"), token)
        raise HTTPException(status_code=403)

    mp3_path = DJAUDIO_CACHE_DIR / f"{token}.mp3"
    if not mp3_path.exists():
        raise HTTPException(status_code=410)

    raw_name = meta.get("filename", f"{token}.mp3")
    safe_name = "".join(c for c in raw_name if c.isalnum() or c in " ._-").strip() or f"{token}.mp3"
    if not safe_name.endswith(".mp3"):
        safe_name += ".mp3"

    logger.info("配信: guild=%s token=%s → %s", guild_id, token, safe_name)
    return FileResponse(str(mp3_path), media_type="audio/mpeg", filename=safe_name)


@dlaudio_router.get("/info/{guild_id}/{token}")
async def file_info(guild_id: str, token: str):
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410)

    if meta.get("guild_id") != guild_id:
        raise HTTPException(status_code=403)

    now = datetime.now(timezone.utc).timestamp()
    remaining = max(0, int(meta["expires_at"] - now))
    return JSONResponse({
        "token": token,
        "title": meta.get("title", ""),
        "filename": meta.get("filename", ""),
        "expires_at": meta.get("expires_at"),
        "remaining_seconds": remaining,
        "remaining_minutes": remaining // 60,
    })


# ────────────────────────────────────────────
# 設定管理 Router（/admin/settings）
# ────────────────────────────────────────────

@router.api_route("/djaudio", methods=["GET", "POST"])
async def djaudio_settings(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]
    channels = await get_guild_channels(gid)

    if request.method == "POST":
        form = await request.form()
        action = form.get("action")

        if action == "set_channel":
            raw_ch = form.get("channel_id", "")
            if raw_ch == "0" or not raw_ch:
                set_djaudio_watch_channel(gid, None)
                flash(request, "監視チャンネルを解除しました。", "success")
            else:
                set_djaudio_watch_channel(gid, validate_channel_id(raw_ch))
                flash(request, "監視チャンネルを保存しました。", "success")
            return RedirectResponse("/admin/settings/djaudio", status_code=303)

        elif action == "set_output_channel":
            raw_ch = form.get("output_channel_id", "")
            if raw_ch == "0" or not raw_ch:
                set_djaudio_output_channel(gid, None)
                flash(request, "出力チャンネルを解除しました（監視チャンネルに返信します）。", "success")
            else:
                set_djaudio_output_channel(gid, validate_channel_id(raw_ch))
                flash(request, "出力チャンネルを保存しました。", "success")
            return RedirectResponse("/admin/settings/djaudio", status_code=303)

        elif action == "set_limits":
            cache_ttl = validate_int(form.get("cache_ttl", "600"), min_val=60, max_val=86400)
            cooldown = validate_int(form.get("cooldown", "30"), min_val=0, max_val=3600)
            max_urls = validate_int(form.get("max_urls", "3"), min_val=1, max_val=10)
            set_djaudio_settings(gid, {"cache_ttl": cache_ttl, "cooldown": cooldown, "max_urls": max_urls})
            flash(request, "制限設定を保存しました。", "success")
            return RedirectResponse("/admin/settings/djaudio", status_code=303)

    runtime = get_djaudio_runtime_settings(gid)
    return render(
        request, "settings/djaudio.html",
        channels=channels,
        current_channel_id=runtime.watch_channel_id,
        current_output_channel_id=runtime.output_channel_id,
        cache_ttl=runtime.cache_ttl,
        cooldown=runtime.cooldown,
        max_urls=runtime.max_urls,
    )
