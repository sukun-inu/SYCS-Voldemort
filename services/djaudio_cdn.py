"""
DJAudio-DL CDN 配信ルーター。
- /dlaudio/files/<guild_id>/<token>  → MP3 配信
- /dlaudio/info/<guild_id>/<token>   → ファイル情報 JSON
- /dlaudio/health                    → ヘルスチェック

webapp_admin にも cdn_main にも依存せず、どちらからでも import できる。
"""

import json
import logging
import re
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from datetime import datetime, timezone

from config import DJAUDIO_CACHE_DIR
from services.djaudio_cache import content_type_for, get_meta, payload_path

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

    # 録音は ZIP でまとめて渡すため、拡張子はメタから決める（旧エントリは .mp3）。
    extension = str(meta.get("extension") or ".mp3")
    path = payload_path(token, meta)
    if path is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    raw_name = meta.get("filename", f"{token}{extension}")
    safe_name = "".join(c for c in raw_name if c.isalnum() or c in " ._-").strip() or f"{token}{extension}"
    if not safe_name.endswith(extension):
        safe_name += extension

    logger.info("配信: guild=%s token=%s → %s", guild_id, token, safe_name)
    return FileResponse(str(path), media_type=content_type_for(extension), filename=safe_name)


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


# ── 録音ミキサー用 ───────────────────────────────────────────
#
# 管理画面のミキサーは、ZIP を丸ごと落とさずに「索引」と「トラック1本」を
# 個別に取りに来る。配信の入口は既存の serve_file と同じ（トークン＋ギルド照合）。

def _recording_zip(guild_id: str, token: str) -> Path:
    """録音の ZIP を返す。合わないものは 404/410 で弾く。"""
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)
    if meta.get("guild_id") != guild_id:
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)
    if meta.get("kind") != "recording" or meta.get("extension") != ".zip":
        raise HTTPException(status_code=404, detail="これは録音ではありません。")

    path = payload_path(token, meta)
    if path is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)
    return path


def _stored_member_range(zip_path: Path, name: str) -> tuple[int, int] | None:
    """ZIP 内の無圧縮メンバーの (開始位置, 長さ)。無圧縮でなければ None。

    ローカルヘッダの長さは可変（ファイル名と拡張フィールド）なので、実際に
    読んで足す。ここが分かると、ZIP を展開せずにその範囲だけ配れる。
    """
    try:
        with zipfile.ZipFile(zip_path) as archive:
            info = archive.getinfo(name)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    if info.compress_type != zipfile.ZIP_STORED:
        return None

    try:
        with open(zip_path, "rb") as handle:
            handle.seek(info.header_offset)
            header = handle.read(30)
    except OSError:
        return None
    if len(header) < 30 or header[:4] != b"PK\x03\x04":
        return None

    name_len = int.from_bytes(header[26:28], "little")
    extra_len = int.from_bytes(header[28:30], "little")
    return info.header_offset + 30 + name_len + extra_len, info.file_size


def _read_manifest(zip_path: Path) -> dict:
    from services.recording_service import MANIFEST_NAME

    try:
        with zipfile.ZipFile(zip_path) as archive:
            return json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
    except KeyError:
        # 索引を入れる前に録った古いアーカイブ。中身から最低限を組み立てる。
        try:
            with zipfile.ZipFile(zip_path) as archive:
                names = [n for n in archive.namelist() if n.lower().endswith(".mp3")]
        except (OSError, zipfile.BadZipFile):
            names = []
        return {
            "version": 0,
            "duration_seconds": 0,
            "bucket_seconds": 0.25,
            "legacy": True,
            "stems": [
                {"index": i, "file": n, "name": Path(n).stem, "peaks": []}
                for i, n in enumerate(sorted(names))
            ],
        }
    except (OSError, zipfile.BadZipFile, ValueError, UnicodeDecodeError) as e:
        logger.warning("録音の索引を読めませんでした token=%s: %s", zip_path.stem, e)
        raise HTTPException(status_code=500, detail="録音の索引を読めませんでした。")


@dlaudio_router.get("/files/{guild_id}/{token}/mixer")
async def recording_manifest(guild_id: str, token: str):
    """ミキサーが読む索引（トラックの並び・波形・長さ）。"""
    manifest = _read_manifest(_recording_zip(guild_id, token))
    for stem in manifest.get("stems", []):
        stem["url"] = f"/dlaudio/files/{guild_id}/{token}/stem/{stem['index']}"
    return JSONResponse(manifest)


@dlaudio_router.get("/files/{guild_id}/{token}/stem/{index}")
async def recording_stem(guild_id: str, token: str, index: int, request: Request):
    """トラック1本を配信する。頭出しのため Range に対応する。"""
    zip_path = _recording_zip(guild_id, token)
    stems = _read_manifest(zip_path).get("stems", [])
    stem = next((s for s in stems if int(s.get("index", -1)) == index), None)
    if stem is None:
        raise HTTPException(status_code=404, detail="そのトラックはありません。")

    name = str(stem.get("file", ""))
    found = _stored_member_range(zip_path, name)

    if found is None:
        # 圧縮して入っている古いアーカイブ。範囲指定はできないので通しで返す。
        try:
            with zipfile.ZipFile(zip_path) as archive:
                data = archive.read(name)
        except (KeyError, OSError, zipfile.BadZipFile):
            raise HTTPException(status_code=404, detail="そのトラックを読めませんでした。")
        return Response(content=data, media_type="audio/mpeg")

    start, size = found
    begin, end = 0, size - 1
    range_header = request.headers.get("range", "")
    partial = False
    match = re.match(r"bytes=(\d*)-(\d*)$", range_header.strip())
    if match:
        raw_begin, raw_end = match.group(1), match.group(2)
        if raw_begin:
            begin = int(raw_begin)
            end = int(raw_end) if raw_end else size - 1
        elif raw_end:                       # bytes=-N（末尾から N バイト）
            begin = max(0, size - int(raw_end))
        if begin >= size:
            return Response(status_code=416, headers={"Content-Range": f"bytes */{size}"})
        end = min(end, size - 1)
        partial = True

    length = end - begin + 1

    def stream():
        remaining = length
        with open(zip_path, "rb") as handle:
            handle.seek(start + begin)
            while remaining > 0:
                chunk = handle.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    headers = {
        "Content-Length": str(length),
        "Accept-Ranges": "bytes",
        "Cache-Control": "private, max-age=600",
    }
    if partial:
        headers["Content-Range"] = f"bytes {begin}-{end}/{size}"
    return StreamingResponse(
        stream(), status_code=206 if partial else 200,
        media_type="audio/mpeg", headers=headers,
    )
