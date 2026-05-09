from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import String, cast, delete, func, or_, select

from services.settings_store import get_bypass_role_ids, get_trusted_user_ids
from webapp.db import SessionLocal
from webapp.models import UserStateCurrent, UserStateEvent

logger = logging.getLogger(__name__)

USER_STATE_RETENTION_DAYS = max(3650, int(os.getenv("USER_STATE_RETENTION_DAYS", "3650")))
USER_STATE_CLEANUP_INTERVAL_SECONDS = max(
    300,
    int(os.getenv("USER_STATE_CLEANUP_INTERVAL_SECONDS", "21600")),
)

_last_cleanup_at: datetime | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_aware_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return _utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_json_dumps(value: Any, default_json: str) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return default_json


def _safe_json_loads(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def _extract_user_fields(user: Any | None) -> dict[str, Any]:
    if user is None:
        return {
            "username": None,
            "display_name": None,
            "avatar_url": None,
        }

    username = getattr(user, "name", None)
    if username is not None:
        username = str(username)[:128]

    display_name = getattr(user, "display_name", None)
    if display_name is not None:
        display_name = str(display_name)[:128]
    elif username is not None:
        display_name = username

    avatar_url: str | None = None
    try:
        avatar_url = str(user.display_avatar.url)[:512]  # type: ignore[attr-defined]
    except Exception:
        try:
            avatar_url = str(user.avatar.url)[:512]  # type: ignore[attr-defined]
        except Exception:
            avatar_url = None

    return {
        "username": username,
        "display_name": display_name,
        "avatar_url": avatar_url,
    }


def _extract_role_snapshot(member: Any | None) -> list[dict[str, Any]]:
    if member is None:
        return []

    roles = getattr(member, "roles", None)
    if not isinstance(roles, list):
        return []

    rows: list[dict[str, Any]] = []
    for role in roles:
        try:
            if role.is_default():
                continue
            rows.append(
                {
                    "id": int(role.id),
                    "name": str(role.name),
                    "position": int(role.position),
                }
            )
        except Exception:
            continue

    rows.sort(key=lambda r: r.get("position", 0), reverse=True)
    return rows


def _extract_ability_snapshot(member: Any | None, guild_id: int) -> dict[str, Any]:
    abilities: dict[str, Any] = {}
    if member is None:
        return abilities

    member_id = getattr(member, "id", None)
    permissions = getattr(member, "guild_permissions", None)
    if permissions is not None:
        abilities.update(
            {
                "administrator": bool(getattr(permissions, "administrator", False)),
                "manage_guild": bool(getattr(permissions, "manage_guild", False)),
                "kick_members": bool(getattr(permissions, "kick_members", False)),
                "ban_members": bool(getattr(permissions, "ban_members", False)),
                "moderate_members": bool(getattr(permissions, "moderate_members", False)),
                "manage_roles": bool(getattr(permissions, "manage_roles", False)),
            }
        )

    try:
        trusted_ids = set(get_trusted_user_ids(guild_id))
    except Exception:
        trusted_ids = set()
    try:
        bypass_ids = set(get_bypass_role_ids(guild_id))
    except Exception:
        bypass_ids = set()

    roles = getattr(member, "roles", None)
    has_bypass_role = False
    if isinstance(roles, list):
        for role in roles:
            try:
                if int(role.id) in bypass_ids:
                    has_bypass_role = True
                    break
            except Exception:
                continue

    abilities["trusted_user"] = bool(member_id in trusted_ids)
    abilities["bypass_role"] = has_bypass_role
    abilities["is_bot"] = bool(getattr(member, "bot", False))
    return abilities


def _is_timed_out_until(until: datetime | None, now: datetime) -> bool:
    if until is None:
        return False
    return _to_aware_utc(until) > now


async def _cleanup_old_events_if_needed(now: datetime) -> None:
    global _last_cleanup_at
    if _last_cleanup_at is not None:
        elapsed = (now - _last_cleanup_at).total_seconds()
        if elapsed < USER_STATE_CLEANUP_INTERVAL_SECONDS:
            return

    cutoff = now - timedelta(days=USER_STATE_RETENTION_DAYS)

    async with SessionLocal() as session:
        await session.execute(
            delete(UserStateEvent).where(UserStateEvent.event_at < cutoff)
        )
        await session.commit()
    _last_cleanup_at = now


def _sanitize_status(status_after: str) -> str:
    normalized = str(status_after or "").strip().lower()
    if not normalized:
        return "unknown"
    return normalized[:32]


def _update_current_state_fields(
    current: UserStateCurrent,
    *,
    event_type: str,
    status_after: str,
    now: datetime,
    user_fields: dict[str, Any],
    in_guild: bool | None,
    is_banned: bool | None,
    timed_out_until: datetime | None,
    role_snapshot: list[dict[str, Any]] | None,
    ability_snapshot: dict[str, Any] | None,
) -> None:
    if user_fields.get("username"):
        current.username = user_fields["username"]
    if user_fields.get("display_name"):
        current.display_name = user_fields["display_name"]
    if user_fields.get("avatar_url"):
        current.avatar_url = user_fields["avatar_url"]

    current.status = status_after
    current.last_event_type = event_type
    current.last_event_at = now
    current.updated_at = now

    if in_guild is not None:
        current.is_in_guild = bool(in_guild)
    else:
        if status_after in {"active"}:
            current.is_in_guild = True
        elif status_after in {"left", "kicked", "banned"}:
            current.is_in_guild = False

    if is_banned is not None:
        current.is_banned = bool(is_banned)
    else:
        if status_after == "banned":
            current.is_banned = True
        elif status_after in {"active", "left", "kicked", "unbanned"}:
            current.is_banned = False

    if timed_out_until is not None:
        timed_out_aware = _to_aware_utc(timed_out_until)
        current.timed_out_until = timed_out_aware
        current.is_timed_out = _is_timed_out_until(timed_out_aware, now)
    elif event_type == "member_timeout_cleared":
        current.timed_out_until = None
        current.is_timed_out = False
    elif current.timed_out_until is not None:
        current.is_timed_out = _is_timed_out_until(current.timed_out_until, now)

    if role_snapshot is not None:
        current.roles_json = _safe_json_dumps(role_snapshot, "[]")

    if ability_snapshot is not None:
        current.abilities_json = _safe_json_dumps(ability_snapshot, "{}")

    if event_type == "member_join":
        current.last_joined_at = now
    elif event_type in {"member_leave", "member_kick", "member_ban"}:
        current.last_left_at = now


async def record_user_state_event(
    *,
    guild_id: int,
    user_id: int,
    event_type: str,
    status_after: str,
    user: Any | None = None,
    actor: Any | None = None,
    reason: str | None = None,
    in_guild: bool | None = None,
    is_banned: bool | None = None,
    timed_out_until: datetime | None = None,
    payload: dict[str, Any] | None = None,
    event_at: datetime | None = None,
) -> None:
    now = _to_aware_utc(event_at)
    status_after = _sanitize_status(status_after)
    event_type = str(event_type).strip().lower()[:48]

    user_fields = _extract_user_fields(user)
    actor_fields = _extract_user_fields(actor)
    has_member_context = hasattr(user, "guild_permissions") and hasattr(user, "roles")
    role_snapshot = _extract_role_snapshot(user) if has_member_context else []
    ability_snapshot = _extract_ability_snapshot(user, guild_id) if has_member_context else {}

    event_payload: dict[str, Any] = dict(payload or {})
    if has_member_context:
        event_payload["roles"] = role_snapshot
    if has_member_context:
        event_payload["abilities"] = ability_snapshot
    if timed_out_until is not None:
        event_payload["timed_out_until"] = _to_aware_utc(timed_out_until).isoformat()

    try:
        await _cleanup_old_events_if_needed(now)
    except Exception:
        logger.exception("[user_state_service] retention cleanup failed")

    async with SessionLocal() as session:
        try:
            event_row = UserStateEvent(
                guild_id=int(guild_id),
                user_id=int(user_id),
                event_type=event_type,
                status_after=status_after,
                actor_user_id=int(getattr(actor, "id", 0) or 0) or None,
                actor_name=actor_fields.get("display_name") or actor_fields.get("username"),
                reason=(str(reason)[:2000] if reason else None),
                payload_json=_safe_json_dumps(event_payload, "{}"),
                event_at=now,
            )
            session.add(event_row)

            current = (
                await session.scalars(
                    select(UserStateCurrent).where(
                        UserStateCurrent.guild_id == int(guild_id),
                        UserStateCurrent.user_id == int(user_id),
                    )
                )
            ).first()

            if current is None:
                current = UserStateCurrent(
                    guild_id=int(guild_id),
                    user_id=int(user_id),
                    status="unknown",
                    is_in_guild=False,
                    is_banned=False,
                    is_timed_out=False,
                    roles_json="[]",
                    abilities_json="{}",
                )
                session.add(current)

            _update_current_state_fields(
                current,
                event_type=event_type,
                status_after=status_after,
                now=now,
                user_fields=user_fields,
                in_guild=in_guild,
                is_banned=is_banned,
                timed_out_until=timed_out_until,
                role_snapshot=role_snapshot if has_member_context else None,
                ability_snapshot=ability_snapshot if has_member_context else None,
            )

            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception(
                "[user_state_service] failed to record event guild_id=%s user_id=%s event_type=%s",
                guild_id,
                user_id,
                event_type,
            )


def _row_to_state_payload(row: UserStateCurrent) -> dict[str, Any]:
    return {
        "guild_id": int(row.guild_id),
        "user_id": int(row.user_id),
        "username": row.username,
        "display_name": row.display_name,
        "avatar_url": row.avatar_url,
        "status": row.status,
        "is_in_guild": bool(row.is_in_guild),
        "is_banned": bool(row.is_banned),
        "is_timed_out": bool(row.is_timed_out),
        "timed_out_until": row.timed_out_until,
        "roles": _safe_json_loads(row.roles_json, []),
        "abilities": _safe_json_loads(row.abilities_json, {}),
        "last_event_type": row.last_event_type,
        "last_event_at": row.last_event_at,
        "first_seen_at": row.first_seen_at,
        "last_joined_at": row.last_joined_at,
        "last_left_at": row.last_left_at,
        "updated_at": row.updated_at,
    }


def _event_to_payload(row: UserStateEvent) -> dict[str, Any]:
    payload = _safe_json_loads(row.payload_json, {})
    return {
        "id": int(row.id),
        "event_type": row.event_type,
        "status_after": row.status_after,
        "actor_user_id": int(row.actor_user_id) if row.actor_user_id is not None else None,
        "actor_name": row.actor_name,
        "reason": row.reason,
        "event_at": row.event_at,
        "payload": payload if isinstance(payload, dict) else {},
    }


async def list_recent_user_states(
    guild_id: int,
    *,
    query: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    q = (query or "").strip()
    safe_limit = max(1, min(200, int(limit)))

    async with SessionLocal() as session:
        stmt = select(UserStateCurrent).where(UserStateCurrent.guild_id == int(guild_id))
        if q:
            if q.isdigit():
                uid = int(q)
                stmt = stmt.where(
                    or_(
                        UserStateCurrent.user_id == uid,
                        cast(UserStateCurrent.user_id, String).like(f"{q}%"),
                    )
                )
            else:
                needle = f"%{q.lower()}%"
                stmt = stmt.where(
                    or_(
                        func.lower(UserStateCurrent.username).like(needle),
                        func.lower(UserStateCurrent.display_name).like(needle),
                    )
                )

        stmt = stmt.order_by(
            UserStateCurrent.last_event_at.desc().nullslast(),
            UserStateCurrent.updated_at.desc().nullslast(),
            UserStateCurrent.id.desc(),
        ).limit(safe_limit)

        rows = (await session.scalars(stmt)).all()
        return [_row_to_state_payload(r) for r in rows]


async def get_user_state_detail(
    guild_id: int,
    user_id: int,
    *,
    event_limit: int = 200,
) -> dict[str, Any] | None:
    safe_limit = max(1, min(500, int(event_limit)))

    async with SessionLocal() as session:
        current = (
            await session.scalars(
                select(UserStateCurrent).where(
                    UserStateCurrent.guild_id == int(guild_id),
                    UserStateCurrent.user_id == int(user_id),
                )
            )
        ).first()
        event_rows = (
            await session.scalars(
                select(UserStateEvent)
                .where(
                    UserStateEvent.guild_id == int(guild_id),
                    UserStateEvent.user_id == int(user_id),
                )
                .order_by(UserStateEvent.event_at.desc(), UserStateEvent.id.desc())
                .limit(safe_limit)
            )
        ).all()

    if current is None and not event_rows:
        return None

    return {
        "current": _row_to_state_payload(current) if current is not None else None,
        "events": [_event_to_payload(row) for row in event_rows],
    }
