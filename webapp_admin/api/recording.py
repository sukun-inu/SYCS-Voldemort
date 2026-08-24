"""VC録音の管理 API。

管理画面は Bot とは別プロセスなので、開始・停止は _dev_signals へシグナルを
置いて Bot に拾わせる（開発者パネルと同じ仕組み）。状態は Bot が書き出した
_recording_state.json を読む。録音済みの一覧はキャッシュのメタから作る。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.responses import JSONResponse

from config import DJAUDIO_CACHE_DIR
from webapp_admin.extensions import limiter
from webapp_admin.security import check_csrf, check_guild

logger = logging.getLogger(__name__)

router = APIRouter()


def _guild_id(request: Request) -> int:
    return int(request.session["guild_id"])


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON を解釈できませんでした。")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON オブジェクトを送ってください。")
    return body


def _require_id(value, label: str) -> int:
    text = str(value or "").strip()
    if not text.isdigit():
        raise HTTPException(status_code=400, detail=f"{label}は数字のIDで指定してください。")
    return int(text)


def _write_signal(name: str, payload: dict) -> None:
    from webapp_admin.api.dev import _SIGNAL_DIR

    _SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    (_SIGNAL_DIR / f"{name}.signal").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8",
    )


def _recordings(guild_id: int) -> list[dict]:
    """このギルドの録音済みアーカイブ。新しい順。"""
    now = datetime.now(timezone.utc).timestamp()
    rows: list[dict] = []
    try:
        meta_paths = sorted(
            DJAUDIO_CACHE_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []

    for path in meta_paths:
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if meta.get("kind") != "recording":
            continue
        if str(meta.get("guild_id")) != str(guild_id):
            continue
        expires_at = float(meta.get("expires_at") or 0)
        if now > expires_at:
            continue
        rows.append({
            "token": meta.get("token"),
            "title": meta.get("title", ""),
            "filename": meta.get("filename", ""),
            "size_mb": round(int(meta.get("size_bytes") or 0) / 1024 / 1024, 1),
            "expires_at": expires_at,
            "remaining_hours": max(0, int((expires_at - now) // 3600)),
            "url": f"/dlaudio/files/{guild_id}/{meta.get('token')}",
        })
    return rows


@router.get("/recording")
@limiter.limit("60/minute")
async def recording_overview(
    request: Request,
    _=Depends(check_guild),
    include_channels: int = Query(1),
):
    """録音の状況と、保存されているアーカイブ一覧。

    画面は状況を数秒おきに取り直すが、チャンネル一覧はそう変わらない。
    毎回付けると Discord への問い合わせが積み上がるため、必要なときだけ載せる。
    """
    from services.recording_service import preferred_vc_channel_id, read_state
    from services.settings_store import get_recording_settings
    from webapp_admin.schema import choices as choice_resolver
    from webapp_admin.schema.types import ChoiceSource

    guild_id = _guild_id(request)
    state = read_state()
    session = state.get("sessions", {}).get(str(guild_id))

    payload = {
        "settings": get_recording_settings(guild_id),
        "session": session,
        "state_updated_at": state.get("updated_at", 0),
        "recordings": _recordings(guild_id),
        # 手動で始めるときの初期値。毎回ゼロから選び直させないため、
        # 設定済みの対象VC（無ければ読み上げの対象VC）を渡す。
        "default_vc_channel_id": preferred_vc_channel_id(guild_id),
    }

    if include_channels:
        # チャンネルは ID を手打ちさせず選ばせたいので、状況と一緒に返す。
        # 取得に失敗した供給元は空リストで返る（画面側は手入力へ切り替える）。
        picks = await choice_resolver.resolve(
            {ChoiceSource.CHANNELS, ChoiceSource.VOICE_CHANNELS}, guild_id,
        )
        payload["channels"] = picks.get(ChoiceSource.CHANNELS.value, [])
        payload["voice_channels"] = picks.get(ChoiceSource.VOICE_CHANNELS.value, [])

    return JSONResponse(payload)


@router.post("/recording/start")
@limiter.limit("10/minute")
async def recording_start(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    guild_id = _guild_id(request)
    body = await _json_body(request)
    channel_id = _require_id(body.get("channel_id"), "VCのチャンネルID")

    _write_signal("recording_start", {
        "guild_id": guild_id,
        "channel_id": channel_id,
        "started_by": (request.session.get("user") or {}).get("global_name")
                      or (request.session.get("user") or {}).get("username")
                      or "管理画面",
    })
    return JSONResponse({
        "message": "録音の開始をキューに追加しました。数十秒以内に開始され、VCへ通知が出ます。",
    })


@router.post("/recording/stop")
@limiter.limit("10/minute")
async def recording_stop(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    guild_id = _guild_id(request)
    _write_signal("recording_stop", {"guild_id": guild_id})
    return JSONResponse({
        "message": "録音の停止をキューに追加しました。書き出しが終わるとリンクが出ます。",
    })


@router.put("/recording/settings")
@limiter.limit("30/minute")
async def recording_settings(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    from services.settings_store import get_recording_settings, set_recording_settings

    guild_id = _guild_id(request)
    body = await _json_body(request)
    patch: dict = {}

    if "enabled" in body:
        patch["enabled"] = bool(body["enabled"])

    if "auto_start" in body:
        patch["auto_start"] = bool(body["auto_start"])

    if "vc_channel_id" in body:
        raw = str(body["vc_channel_id"] or "").strip()
        patch["vc_channel_id"] = _require_id(raw, "録音するVCのID") if raw else None

    if "max_minutes" in body:
        try:
            minutes = int(body["max_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="上限時間は分（数字）で指定してください。")
        # 0 は「時間では止めない」。VC が無人になるまで録り続ける。
        from services.recording_service import MAX_MINUTES_LIMIT

        if not (0 <= minutes <= MAX_MINUTES_LIMIT):
            raise HTTPException(
                status_code=400,
                detail=f"上限時間は 0〜{MAX_MINUTES_LIMIT} 分で指定してください（0 で無制限）。",
            )
        patch["max_minutes"] = minutes

    if "retention_days" in body:
        try:
            days = int(body["retention_days"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="保存期間は日数（数字）で指定してください。")
        from services.recording_service import RETENTION_DAYS_MAX, RETENTION_DAYS_MIN

        if not (RETENTION_DAYS_MIN <= days <= RETENTION_DAYS_MAX):
            raise HTTPException(
                status_code=400,
                detail=f"保存期間は {RETENTION_DAYS_MIN}〜{RETENTION_DAYS_MAX} 日で指定してください。",
            )
        patch["retention_days"] = days

    if "announce_channel_id" in body:
        raw = str(body["announce_channel_id"] or "").strip()
        patch["announce_channel_id"] = _require_id(raw, "通知チャンネルID") if raw else None

    if "excluded_user_ids" in body:
        raw_list = body["excluded_user_ids"]
        if not isinstance(raw_list, list):
            raise HTTPException(status_code=400, detail="除外ユーザーは配列で指定してください。")
        patch["excluded_user_ids"] = [_require_id(v, "ユーザーID") for v in raw_list]

    if not patch:
        raise HTTPException(status_code=400, detail="変更する項目がありません。")

    set_recording_settings(guild_id, patch)
    return JSONResponse({
        "message": "録音の設定を保存しました。",
        "settings": get_recording_settings(guild_id),
    })
