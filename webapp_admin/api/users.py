"""ユーザー状態監査の API。

一覧は絞り込み・ページ送りともサーバ側で行う。以前は全件を HTML に描画してから
クライアントで分割していたため、件数が増えるほど重くなっていた。

表示用のラベル（状態・イベント種別・権限）と JST 整形もここで行い、
クライアントは受け取った文字列をそのまま並べるだけにする。
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from webapp_admin.api.jsonsafe import SafeJSONResponse as JSONResponse

from config import JST
from services.user_state_service import (
    count_user_states,
    get_user_state_detail,
    list_recent_user_states,
)
from webapp_admin.security import check_guild

logger = logging.getLogger(__name__)

router = APIRouter()

STATUS_LABELS: dict[str, str] = {
    "active": "在籍",
    "left": "退出",
    "kicked": "KICK",
    "banned": "BAN中",
    "unbanned": "BAN解除",
    "unknown": "不明",
}

STATUS_TONES: dict[str, str] = {
    "active": "success",
    "banned": "danger",
    "kicked": "danger",
    "left": "warning",
    "unbanned": "warning",
}

EVENT_LABELS: dict[str, str] = {
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
    "sync_discovered_member": "定期同期で検出（メンバー）",
    "sync_discovered_ban": "定期同期で検出（BAN）",
    "sync_mark_left": "定期同期で退出を反映",
}

# 定期同期 (services/user_state_service.py の sync_guild_user_states) が書き込む
# "sync_member_<source>" のようなイベント種別は、起点(source)部分が可変のため
# 辞書に個別登録せず、接頭辞と起点名を組み合わせてラベル化する。
SYNC_PREFIX_LABELS: dict[str, str] = {
    "sync_member_": "メンバー状態を同期",
    "sync_ban_": "BAN状態を同期",
    "sync_left_": "退出を同期反映",
}
SYNC_SOURCE_LABELS: dict[str, str] = {
    "on_ready": "起動時",
    "auto_repair": "自動修復",
    "manual_signal": "手動実行",
    "startup_sync": "起動時",
}

ABILITY_LABELS: dict[str, str] = {
    "administrator": "管理者権限",
    "manage_guild": "サーバー管理",
    "kick_members": "メンバーをキック",
    "ban_members": "メンバーをBAN",
    "moderate_members": "タイムアウト権限",
    "manage_roles": "ロール管理",
    "trusted_user": "信頼済みユーザー",
    "bypass_role": "セキュリティバイパス",
    "is_bot": "BOT",
}


def status_label(value: str | None) -> str:
    if not value:
        return STATUS_LABELS["unknown"]
    return STATUS_LABELS.get(value, value)


def status_tone(value: str | None) -> str:
    return STATUS_TONES.get(value or "", "accent")


def event_label(value: str | None) -> str:
    if not value:
        return "-"
    if value in EVENT_LABELS:
        return EVENT_LABELS[value]
    for prefix, base in SYNC_PREFIX_LABELS.items():
        if value.startswith(prefix):
            source = value[len(prefix) :]
            return f"{base}（{SYNC_SOURCE_LABELS.get(source, source)}）"
    return value


def ability_label(value: str) -> str:
    return ABILITY_LABELS.get(value, value)


def format_jst(value: Any) -> str:
    if value is None:
        return "-"
    if not isinstance(value, datetime):
        return str(value)
    try:
        return value.astimezone(JST).strftime("%Y/%m/%d %H:%M:%S")
    except (ValueError, OSError):
        return str(value)


def _roles(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [role for role in raw if isinstance(role, dict)]


def _enabled_abilities(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return []
    return sorted(ability_label(str(key)) for key, enabled in raw.items() if enabled)


def _row(state: dict[str, Any]) -> dict[str, Any]:
    roles = _roles(state.get("roles"))
    role_names = [str(role.get("name")) for role in roles if role.get("name")]
    abilities = _enabled_abilities(state.get("abilities"))
    return {
        "user_id": str(state.get("user_id")),
        "username": state.get("username"),
        "display_name": state.get("display_name"),
        "avatar_url": state.get("avatar_url"),
        "status": state.get("status"),
        "status_label": status_label(state.get("status")),
        "status_tone": status_tone(state.get("status")),
        "is_in_guild": bool(state.get("is_in_guild")),
        "is_banned": bool(state.get("is_banned")),
        "is_timed_out": bool(state.get("is_timed_out")),
        "last_event_label": event_label(state.get("last_event_type")),
        "last_event_at": format_jst(state.get("last_event_at")),
        "roles": role_names,
        "abilities": abilities,
    }


@router.get("/users/state")
async def list_states(
    request: Request,
    _=Depends(check_guild),
    q: str = Query(default="", max_length=128),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    guild_id = int(request.session["guild_id"])
    keyword = q.strip() or None

    rows = await list_recent_user_states(guild_id, query=keyword, limit=limit, offset=offset)
    total = await count_user_states(guild_id, query=keyword)

    return JSONResponse(
        {
            "rows": [_row(state) for state in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            # 行が返らなかったページの先に「次へ」を出さない。
            # total は別クエリなので、削除直後などに食い違うことがある。
            "has_more": bool(rows) and offset + len(rows) < total,
        }
    )


@router.get("/users/state/{user_id}")
async def user_detail(
    user_id: int,
    request: Request,
    _=Depends(check_guild),
    event_limit: int = Query(default=100, ge=1, le=500),
):
    guild_id = int(request.session["guild_id"])
    detail = await get_user_state_detail(guild_id, user_id, event_limit=event_limit)
    if detail is None:
        return JSONResponse({"found": False, "user_id": str(user_id)}, status_code=404)

    current = detail.get("current") if isinstance(detail.get("current"), dict) else None
    payload: dict[str, Any] = {"found": True, "user_id": str(user_id)}

    if current is not None:
        payload["current"] = {
            **_row(current),
            "timed_out_until": format_jst(current.get("timed_out_until")),
            "first_seen_at": format_jst(current.get("first_seen_at")),
            "last_joined_at": format_jst(current.get("last_joined_at")),
            "last_left_at": format_jst(current.get("last_left_at")),
            "updated_at": format_jst(current.get("updated_at")),
            "role_details": _roles(current.get("roles")),
        }
    else:
        payload["current"] = None

    events = []
    for event in detail.get("events", []):
        if not isinstance(event, dict):
            continue
        payload_data = event.get("payload")
        events.append(
            {
                "id": event.get("id"),
                "event_label": event_label(event.get("event_type")),
                "event_type": event.get("event_type"),
                "event_at": format_jst(event.get("event_at")),
                "status_after_label": status_label(event.get("status_after")),
                "status_after_tone": status_tone(event.get("status_after")),
                "actor_name": event.get("actor_name"),
                "reason": event.get("reason"),
                "payload": payload_data if isinstance(payload_data, dict) else {},
            }
        )
    payload["events"] = events

    return JSONResponse(payload)
