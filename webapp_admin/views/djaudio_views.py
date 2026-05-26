"""
DJAudio-DL 設定管理 Router。
- /admin/settings/djaudio → 設定ページ

CDN 配信ルート（/dlaudio/...）は services/djaudio_cdn.py に定義。
"""

import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse

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
