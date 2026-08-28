from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from sqlalchemy import String, cast, delete, func, or_, select
from sqlalchemy.exc import OperationalError, ProgrammingError

from envutil import env_int
from services.settings_store import get_bypass_role_ids, get_trusted_user_ids
from services.user_state_db import SessionLocal, ensure_user_state_db
from webapp.models import UserStateCurrent, UserStateEvent

logger = logging.getLogger(__name__)

# 「ユーザー状態監査DB（10年保持）」は機能として謳っている保証であり、下限を
# 既定値と同じ3650日にしているのは意図的。env で短縮できる値にすると、
# 誤って短い値を入れただけで監査履歴が10年より早く消える事故になる。
# 伸ばす方向（3650日超）だけを env で受け付ける。
USER_STATE_RETENTION_DAYS = env_int("USER_STATE_RETENTION_DAYS", 3650, minimum=3650)
USER_STATE_CLEANUP_INTERVAL_SECONDS = env_int(
    "USER_STATE_CLEANUP_INTERVAL_SECONDS", 21600, minimum=300,
)

_last_cleanup_at: datetime | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_repairable_db_error(exc: Exception) -> bool:
    return isinstance(exc, (OperationalError, ProgrammingError))


async def _try_db_self_heal(*, context: str, exc: Exception) -> bool:
    if not _is_repairable_db_error(exc):
        return False
    logger.warning(
        "[user_state_service] %s failed with DB error. trying self-heal: %s",
        context,
        exc,
    )
    try:
        await ensure_user_state_db(force=True)
        return True
    except Exception:
        logger.exception("[user_state_service] DB self-heal failed at %s", context)
        return False


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
    await ensure_user_state_db()
    if _last_cleanup_at is not None:
        elapsed = (now - _last_cleanup_at).total_seconds()
        if elapsed < USER_STATE_CLEANUP_INTERVAL_SECONDS:
            return

    cutoff = now - timedelta(days=USER_STATE_RETENTION_DAYS)
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                await session.execute(
                    delete(UserStateEvent).where(UserStateEvent.event_at < cutoff)
                )
                await session.commit()
                _last_cleanup_at = now
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="cleanup_old_events", exc=e):
                    continue
                raise


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
    await ensure_user_state_db()
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

    for attempt in range(2):
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
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="record_user_state_event", exc=e):
                    continue
                logger.exception(
                    "[user_state_service] failed to record event guild_id=%s user_id=%s event_type=%s",
                    guild_id,
                    user_id,
                    event_type,
                )
                return


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


def _apply_state_filter(stmt, guild_id: int, query: str | None):
    """一覧と件数で同じ絞り込みを使うためのヘルパー。"""
    stmt = stmt.where(UserStateCurrent.guild_id == int(guild_id))
    q = (query or "").strip()
    if not q:
        return stmt

    if q.isdigit():
        return stmt.where(
            or_(
                UserStateCurrent.user_id == int(q),
                cast(UserStateCurrent.user_id, String).like(f"{q}%"),
            )
        )

    needle = f"%{q.lower()}%"
    return stmt.where(
        or_(
            func.lower(UserStateCurrent.username).like(needle),
            func.lower(UserStateCurrent.display_name).like(needle),
        )
    )


async def list_recent_user_states(
    guild_id: int,
    *,
    query: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    await ensure_user_state_db()
    safe_limit = max(1, min(200, int(limit)))
    safe_offset = max(0, int(offset))
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stmt = _apply_state_filter(select(UserStateCurrent), guild_id, query)
                stmt = stmt.order_by(
                    UserStateCurrent.last_event_at.desc().nullslast(),
                    UserStateCurrent.updated_at.desc().nullslast(),
                    UserStateCurrent.id.desc(),
                ).limit(safe_limit).offset(safe_offset)

                rows = (await session.scalars(stmt)).all()
                return [_row_to_state_payload(r) for r in rows]
            except Exception as e:
                if attempt == 0 and await _try_db_self_heal(context="list_recent_user_states", exc=e):
                    continue
                logger.exception("[user_state_service] list_recent_user_states failed guild_id=%s", guild_id)
                return []


async def count_user_states(guild_id: int, *, query: str | None = None) -> int:
    """絞り込み条件に一致する件数。ページ送りの総数表示に使う。"""
    await ensure_user_state_db()
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stmt = _apply_state_filter(select(func.count(UserStateCurrent.id)), guild_id, query)
                return int((await session.scalar(stmt)) or 0)
            except Exception as e:
                if attempt == 0 and await _try_db_self_heal(context="count_user_states", exc=e):
                    continue
                logger.exception("[user_state_service] count_user_states failed guild_id=%s", guild_id)
                return 0


async def get_user_state_detail(
    guild_id: int,
    user_id: int,
    *,
    event_limit: int = 200,
) -> dict[str, Any] | None:
    await ensure_user_state_db()
    safe_limit = max(1, min(500, int(event_limit)))
    for attempt in range(2):
        try:
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
        except Exception as e:
            if attempt == 0 and await _try_db_self_heal(context="get_user_state_detail", exc=e):
                continue
            logger.exception(
                "[user_state_service] get_user_state_detail failed guild_id=%s user_id=%s",
                guild_id,
                user_id,
            )
            return None


def _empty_user_fields() -> dict[str, Any]:
    return {"username": None, "display_name": None, "avatar_url": None}


def _build_state_event(
    *,
    guild_id: int,
    user_id: int,
    event_type: str,
    status_after: str,
    now: datetime,
    actor_user_id: int | None = None,
    actor_name: str | None = None,
    reason: str | None = None,
    payload: dict[str, Any] | None = None,
) -> UserStateEvent:
    return UserStateEvent(
        guild_id=int(guild_id),
        user_id=int(user_id),
        event_type=str(event_type)[:48],
        status_after=_sanitize_status(status_after),
        actor_user_id=actor_user_id,
        actor_name=(str(actor_name)[:128] if actor_name else None),
        reason=(str(reason)[:2000] if reason else None),
        payload_json=_safe_json_dumps(payload or {}, "{}"),
        event_at=now,
    )


async def repair_user_state_integrity(
    *,
    guild_id: int | None = None,
    max_rows: int = 50000,
) -> dict[str, int]:
    await ensure_user_state_db()
    now = _utc_now()
    safe_max_rows = max(100, min(200000, int(max_rows)))
    stats: dict[str, int] = {
        "rows_scanned": 0,
        "rows_fixed": 0,
        "status_fixed": 0,
        "json_fixed": 0,
        "flag_fixed": 0,
        "timeout_fixed": 0,
    }

    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stmt = select(UserStateCurrent).order_by(UserStateCurrent.id.asc()).limit(safe_max_rows)
                if guild_id is not None:
                    stmt = stmt.where(UserStateCurrent.guild_id == int(guild_id))

                rows = (await session.scalars(stmt)).all()
                stats["rows_scanned"] = len(rows)

                for row in rows:
                    changed = False
                    normalized_status = _sanitize_status(row.status)
                    if row.status != normalized_status:
                        row.status = normalized_status
                        changed = True
                        stats["status_fixed"] += 1

                    roles = _safe_json_loads(row.roles_json, [])
                    if not isinstance(roles, list):
                        row.roles_json = "[]"
                        changed = True
                        stats["json_fixed"] += 1
                    else:
                        normalized_roles = _safe_json_dumps(roles, "[]")
                        if normalized_roles != row.roles_json:
                            row.roles_json = normalized_roles
                            changed = True
                            stats["json_fixed"] += 1

                    abilities = _safe_json_loads(row.abilities_json, {})
                    if not isinstance(abilities, dict):
                        row.abilities_json = "{}"
                        changed = True
                        stats["json_fixed"] += 1
                    else:
                        normalized_abilities = _safe_json_dumps(abilities, "{}")
                        if normalized_abilities != row.abilities_json:
                            row.abilities_json = normalized_abilities
                            changed = True
                            stats["json_fixed"] += 1

                    expected_in_guild = bool(row.is_in_guild)
                    expected_banned = bool(row.is_banned)
                    if row.status == "banned":
                        expected_banned = True
                        expected_in_guild = False
                    elif row.status in {"left", "kicked"}:
                        expected_in_guild = False
                    elif row.status == "active":
                        expected_banned = False

                    if bool(row.is_in_guild) != expected_in_guild:
                        row.is_in_guild = expected_in_guild
                        changed = True
                        stats["flag_fixed"] += 1
                    if bool(row.is_banned) != expected_banned:
                        row.is_banned = expected_banned
                        changed = True
                        stats["flag_fixed"] += 1

                    expected_timed_out = _is_timed_out_until(row.timed_out_until, now)
                    if bool(row.is_timed_out) != expected_timed_out:
                        row.is_timed_out = expected_timed_out
                        changed = True
                        stats["timeout_fixed"] += 1

                    if changed:
                        row.updated_at = now
                        stats["rows_fixed"] += 1

                await session.commit()
                return stats
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="repair_user_state_integrity", exc=e):
                    continue
                logger.exception(
                    "[user_state_service] repair_user_state_integrity failed guild_id=%s",
                    guild_id,
                )
                return stats

    return stats


async def sync_guild_user_states(
    *,
    guild_id: int,
    members: Sequence[Any],
    banned_users: Sequence[Any] | None = None,
    source: str = "startup_sync",
    reconcile_missing: bool = True,
    write_events_on_sync: bool = True,
) -> dict[str, int]:
    await ensure_user_state_db()
    now = _utc_now()
    safe_guild_id = int(guild_id)
    safe_source = str(source or "startup_sync")[:32]
    banned_users = banned_users or []
    empty_stats: dict[str, int] = {
        "members_seen": 0,
        "bans_seen": 0,
        "created": 0,
        "updated": 0,
        "left_reconciled": 0,
        "events_written": 0,
    }
    stats = dict(empty_stats)

    try:
        await _cleanup_old_events_if_needed(now)
    except Exception:
        logger.exception("[user_state_service] retention cleanup failed before sync")

    for attempt in range(2):
        stats = dict(empty_stats)
        async with SessionLocal() as session:
            try:
                existing_rows = (
                    await session.scalars(
                        select(UserStateCurrent).where(UserStateCurrent.guild_id == safe_guild_id)
                    )
                ).all()
                rows_by_user_id: dict[int, UserStateCurrent] = {
                    int(row.user_id): row for row in existing_rows
                }

                present_member_ids: set[int] = set()
                banned_user_ids: set[int] = set()

                for member in members:
                    try:
                        user_id = int(getattr(member, "id"))
                    except Exception:
                        continue

                    present_member_ids.add(user_id)
                    stats["members_seen"] += 1
                    current = rows_by_user_id.get(user_id)
                    created = False
                    if current is None:
                        current = UserStateCurrent(
                            guild_id=safe_guild_id,
                            user_id=user_id,
                            status="unknown",
                            is_in_guild=False,
                            is_banned=False,
                            is_timed_out=False,
                            roles_json="[]",
                            abilities_json="{}",
                        )
                        session.add(current)
                        rows_by_user_id[user_id] = current
                        created = True
                        stats["created"] += 1
                    else:
                        stats["updated"] += 1

                    _update_current_state_fields(
                        current,
                        event_type=f"sync_member_{safe_source}",
                        status_after="active",
                        now=now,
                        user_fields=_extract_user_fields(member),
                        in_guild=True,
                        is_banned=False,
                        timed_out_until=getattr(member, "timed_out_until", None),
                        role_snapshot=_extract_role_snapshot(member),
                        ability_snapshot=_extract_ability_snapshot(member, safe_guild_id),
                    )

                    if created and write_events_on_sync:
                        session.add(
                            _build_state_event(
                                guild_id=safe_guild_id,
                                user_id=user_id,
                                event_type="sync_discovered_member",
                                status_after="active",
                                now=now,
                                payload={"source": safe_source},
                            )
                        )
                        stats["events_written"] += 1

                for banned_user in banned_users:
                    try:
                        user_id = int(getattr(banned_user, "id"))
                    except Exception:
                        continue

                    banned_user_ids.add(user_id)
                    stats["bans_seen"] += 1
                    current = rows_by_user_id.get(user_id)
                    created = False
                    before_status = None
                    before_banned = None

                    if current is None:
                        current = UserStateCurrent(
                            guild_id=safe_guild_id,
                            user_id=user_id,
                            status="unknown",
                            is_in_guild=False,
                            is_banned=True,
                            is_timed_out=False,
                            roles_json="[]",
                            abilities_json="{}",
                        )
                        session.add(current)
                        rows_by_user_id[user_id] = current
                        created = True
                        stats["created"] += 1
                    else:
                        before_status = current.status
                        before_banned = bool(current.is_banned)
                        stats["updated"] += 1

                    _update_current_state_fields(
                        current,
                        event_type=f"sync_ban_{safe_source}",
                        status_after="banned",
                        now=now,
                        user_fields=_extract_user_fields(banned_user),
                        in_guild=False,
                        is_banned=True,
                        timed_out_until=None,
                        role_snapshot=None,
                        ability_snapshot=None,
                    )

                    if write_events_on_sync and (
                        created
                        or before_status != "banned"
                        or before_banned is False
                    ):
                        session.add(
                            _build_state_event(
                                guild_id=safe_guild_id,
                                user_id=user_id,
                                event_type="sync_discovered_ban",
                                status_after="banned",
                                now=now,
                                payload={"source": safe_source},
                            )
                        )
                        stats["events_written"] += 1

                if reconcile_missing:
                    for user_id, current in rows_by_user_id.items():
                        if user_id in present_member_ids or user_id in banned_user_ids:
                            continue
                        if bool(current.is_banned):
                            continue

                        should_mark_left = bool(current.is_in_guild) or current.status in {"active", "unknown"}
                        if not should_mark_left:
                            continue

                        _update_current_state_fields(
                            current,
                            event_type=f"sync_left_{safe_source}",
                            status_after="left",
                            now=now,
                            user_fields=_empty_user_fields(),
                            in_guild=False,
                            is_banned=False,
                            timed_out_until=None,
                            role_snapshot=None,
                            ability_snapshot=None,
                        )
                        stats["left_reconciled"] += 1

                        if write_events_on_sync:
                            session.add(
                                _build_state_event(
                                    guild_id=safe_guild_id,
                                    user_id=user_id,
                                    event_type="sync_mark_left",
                                    status_after="left",
                                    now=now,
                                    payload={"source": safe_source},
                                )
                            )
                            stats["events_written"] += 1

                await session.commit()
                return stats
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="sync_guild_user_states", exc=e):
                    continue
                logger.exception("[user_state_service] sync_guild_user_states failed guild_id=%s", guild_id)
                return stats

    return stats
