"""
DJAudio-DL CDN 配信ルーター。
- /dlaudio/files/<guild_id>/<token>  → MP3 配信
- /dlaudio/info/<guild_id>/<token>   → ファイル情報 JSON
- /dlaudio/health                    → ヘルスチェック

webapp_admin にも cdn_main にも依存せず、どちらからでも import できる。
"""

import logging

from fastapi import APIRouter, HTTPException
from starlette.responses import FileResponse, JSONResponse
from datetime import datetime, timezone

from config import DJAUDIO_CACHE_DIR
from services.djaudio_cache import get_meta

logger = logging.getLogger(__name__)

dlaudio_router = APIRouter()


def _validate_token(token: str) -> bool:
    return token.isalnum() and len(token) == 32


def _validate_guild_id(guild_id: str) -> bool:
    return guild_id.isdigit()


@dlaudio_router.get("/health")
async def dlaudio_health():
    return JSONResponse({"status": "ok"})


_LINK_INVALID = "リンクが正しくありません。Discordに投稿されたリンクをそのまま開いてください。"
_LINK_EXPIRED = "このリンクの有効期限が切れました。Discordでもう一度URLを投稿して、新しいリンクを取得してください。"
_LINK_WRONG_GUILD = "このリンクは別のサーバー向けに発行されたものです。"


@dlaudio_router.get("/files/{guild_id}/{token}")
async def serve_file(guild_id: str, token: str):
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    if meta.get("guild_id") != guild_id:
        logger.warning("guild_id 不一致: URL=%s meta=%s token=%s", guild_id, meta.get("guild_id"), token)
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)

    mp3_path = DJAUDIO_CACHE_DIR / f"{token}.mp3"
    if not mp3_path.exists():
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    raw_name = meta.get("filename", f"{token}.mp3")
    safe_name = "".join(c for c in raw_name if c.isalnum() or c in " ._-").strip() or f"{token}.mp3"
    if not safe_name.endswith(".mp3"):
        safe_name += ".mp3"

    logger.info("配信: guild=%s token=%s → %s", guild_id, token, safe_name)
    return FileResponse(str(mp3_path), media_type="audio/mpeg", filename=safe_name)


@dlaudio_router.get("/info/{guild_id}/{token}")
async def file_info(guild_id: str, token: str):
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    if meta.get("guild_id") != guild_id:
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)

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
