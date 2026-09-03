from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple, Sequence

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
    "USER_STATE_CLEANUP_INTERVAL_SECONDS",
    21600,
    minimum=300,
)

_last_cleanup_at: datetime | None = None


def _utc_now() -> datetime:
    """現在時刻を UTC aware で返す。DB のタイムゾーン無し値と比較して
    ずれないよう、このモジュールでは常にこれを起点にする。
    """
    return datetime.now(timezone.utc)


def _is_repairable_db_error(exc: Exception) -> bool:
    """自己修復（DBの再作成）で直る可能性があるエラーかどうか。
    接続断やスキーマ不整合はここで拾い、それ以外の例外はそのまま
    呼び出し元へ伝播させて隠さない。
    """
    return isinstance(exc, (OperationalError, ProgrammingError))


async def _try_db_self_heal(*, context: str, exc: Exception) -> bool:
    """修復可能なDBエラーなら、DBを作り直してから再試行してよいと伝える。
    修復不能なエラーや修復自体の失敗では False を返し、呼び出し元は
    最初の例外をそのまま外へ出す。
    """
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
    """naive な datetime は UTC とみなして aware にする。None なら現在時刻。
    DBから読んだ値・イベント引数として渡ってきた値のどちらも tzinfo の
    有無が揃っていない前提で、比較の前に必ずこれを通す。
    """
    if dt is None:
        return _utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_json_dumps(value: Any, default_json: str) -> str:
    """JSON化に失敗しても例外を投げず、default_json を返す。
    ここで例外を出すとユーザー状態イベントの記録そのものが止まるため、
    シリアライズできない値が混ざっていても記録は続ける。
    """
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return default_json


def _safe_json_loads(raw: str | None, fallback: Any) -> Any:
    """JSON文字列が空・壊れている場合は fallback を返す。
    保存時点では壊れていなくても、手動編集やスキーマ変更で読めなくなった
    行に当たっても例外で落ちないようにする。
    """
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def _extract_user_fields(user: Any | None) -> dict[str, Any]:
    """discord.User/Member から保存用のフィールドを抜き出す。

    avatar は display_avatar → avatar の順で試す。カスタムアバターが
    無いユーザーでは display_avatar が例外を投げるため。user が None
    （退出後などで参照が切れた場合）でも空の辞書を返し、呼び出し側で
    None チェックを増やさずに済むようにする。
    """
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
        avatar_url = str(user.display_avatar.url)[:512]
    except Exception:
        try:
            avatar_url = str(user.avatar.url)[:512]
        except Exception:
            avatar_url = None

    return {
        "username": username,
        "display_name": display_name,
        "avatar_url": avatar_url,
    }


def _extract_role_snapshot(member: Any | None) -> list[dict[str, Any]]:
    """member のロールをイベント記録用の配列へ変換する。

    @everyone（is_default）は全員が持つため記録から除外する。位置
    (position) の降順にしておくのは、表示側で毎回ソートし直さずに
    済むようにするため。
    """
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


# 設定の読み出しに失敗したことを既に知らせたギルド。(guild_id, 種類) で覚える。
# 下の関数は同期のたびにメンバー1人ずつ呼ばれるので、毎回警告を出すと、
# 数千人のギルドでは同じ行でログが埋まって他が読めなくなる。
_warned_ability_lookup: set[tuple[int, str]] = set()


def _lookup_ability_ids(getter: Any, guild_id: int, what: str) -> set[int]:
    """設定ストアから ID の集合を読む。読めなければ空集合を返す。

    以前はここだけ例外を無言で握りつぶしていた。このファイルの他の場所
    （自己修復や保持期間の掃除の失敗）は必ず理由をログに残すのに、ここが
    失敗しても「信頼ユーザーやバイパスロールの扱いが外れた状態で記録が残る」
    だけで、設定ストアが恒常的に壊れていても誰も気づけない構造だった。

    空集合へ落とすこと自体は変えていない。ここで例外を上へ投げると、
    ユーザー状態の記録そのものが止まってしまう。
    """
    key = (guild_id, what)
    try:
        ids = {int(value) for value in getter(guild_id)}
    except Exception:
        if key not in _warned_ability_lookup:
            _warned_ability_lookup.add(key)
            logger.warning(
                "[user_state_service] %s の設定を読めませんでした guild_id=%s。"
                "読めるようになるまで、その扱いが外れた状態で記録します。",
                what,
                guild_id,
                exc_info=True,
            )
        return set()
    _warned_ability_lookup.discard(key)
    return ids


def _extract_ability_snapshot(member: Any | None, guild_id: int) -> dict[str, Any]:
    """退出・BAN後でも「当時どんな権限・扱いだったか」を追えるように、
    権限フラグと信頼ユーザー/バイパスロールの判定結果をイベント発生時点で
    固定して残す。あとから settings_store の設定を変えても、この
    スナップショットは書き換わらない。
    """
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

    trusted_ids = _lookup_ability_ids(get_trusted_user_ids, guild_id, "信頼ユーザー")
    bypass_ids = _lookup_ability_ids(get_bypass_role_ids, guild_id, "バイパスロール")

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
    """timed_out_until が未来なら「今もタイムアウト中」と判定する。
    None は「タイムアウトしていない」を意味する。
    """
    if until is None:
        return False
    return _to_aware_utc(until) > now


async def _cleanup_old_events_if_needed(now: datetime) -> None:
    """保持期間を過ぎたイベントを間引く。

    記録のたびに毎回スキャンすると重いため、
    USER_STATE_CLEANUP_INTERVAL_SECONDS 未満の間隔では何もしない。
    _last_cleanup_at はプロセス内メモリだけで持つので、再起動直後は
    間隔を無視して必ず1回実行される。
    """
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
                await session.execute(delete(UserStateEvent).where(UserStateEvent.event_at < cutoff))
                await session.commit()
                _last_cleanup_at = now
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="cleanup_old_events", exc=e):
                    continue
                raise


def _sanitize_status(status_after: str) -> str:
    """status を保存用に正規化する。小文字化・前後空白除去のうえ、
    空文字は "unknown" にフォールバックし、DB のカラム長に合わせて
    32文字で切り詰める。
    """
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
    """current 行を、渡された新しい状態でその場更新する。

    引数が None のフィールドは「今回のイベントでは分からない」ことを
    意味し、既存の値や status_after からの推測に任せて上書きしない
    （明示的な False と「不明」を区別するために Optional にしている）。
    """
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


def _member_snapshot(user: Any, guild_id: int) -> tuple[list, dict] | None:
    """discord.Member 相当なら (ロール一覧, 権限の一覧) を返す。違えば None。

    **roles と guild_permissions の両方**が揃ってはじめて Member 扱いにする。
    片方だけで通すと、権限を持たない相手に対して権限の一覧を組み立てに行き、
    payload に空の abilities が入って「役職が無い」のか「調べられなかった」
    のかが区別できなくなる。webhook 経由の投稿者など、属性が欠けた相手は
    実際に来る。
    """
    if not (hasattr(user, "guild_permissions") and hasattr(user, "roles")):
        return None
    return _extract_role_snapshot(user), _extract_ability_snapshot(user, guild_id)


def _event_payload_for(
    payload: dict[str, Any] | None,
    snapshot: tuple[list, dict] | None,
    timed_out_until: datetime | None,
) -> dict[str, Any]:
    """履歴に残す payload を組み立てる。

    タイムアウトの期限は最新状態にも入るが、そちらは**次のイベントで
    上書きされる**。「いつまでの制限だったか」を後から辿れるのは履歴側だけ。
    """
    event_payload: dict[str, Any] = dict(payload or {})
    if snapshot is not None:
        event_payload["roles"], event_payload["abilities"] = snapshot
    if timed_out_until is not None:
        event_payload["timed_out_until"] = _to_aware_utc(timed_out_until).isoformat()
    return event_payload


def _find_or_create_current(session, guild_id: int, user_id: int, rows):
    """最新状態の行を取り出す。無ければ空の行を作って session へ足す。"""
    current = rows.first()
    if current is not None:
        return current
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
    return current


async def _write_state_event(
    *,
    guild_id: int,
    user_id: int,
    event_type: str,
    status_after: str,
    now: datetime,
    actor: Any | None,
    actor_fields: dict[str, Any],
    reason: str | None,
    event_payload: dict[str, Any],
    user_fields: dict[str, Any],
    in_guild: bool | None,
    is_banned: bool | None,
    timed_out_until: datetime | None,
    snapshot: tuple[list, dict] | None,
) -> None:
    """履歴と最新状態を1つのトランザクションで書く。失敗したら例外を上げる。

    **2つを同じコミットに入れること。** 別々にすると、あいだで落ちたときに
    履歴には残っているのに最新状態が古いまま、という食い違いが残る。管理画面は
    この2つを並べて出すので、見た人はどちらを信じるか分からない。
    """
    async with SessionLocal() as session:
        try:
            session.add(
                UserStateEvent(
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
            )

            rows = await session.scalars(
                select(UserStateCurrent).where(
                    UserStateCurrent.guild_id == int(guild_id),
                    UserStateCurrent.user_id == int(user_id),
                )
            )
            current = _find_or_create_current(session, guild_id, user_id, rows)

            _update_current_state_fields(
                current,
                event_type=event_type,
                status_after=status_after,
                now=now,
                user_fields=user_fields,
                in_guild=in_guild,
                is_banned=is_banned,
                timed_out_until=timed_out_until,
                role_snapshot=snapshot[0] if snapshot is not None else None,
                ability_snapshot=snapshot[1] if snapshot is not None else None,
            )

            await session.commit()
        except Exception:
            await session.rollback()
            raise


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
    """入退室・BAN・ロール変更などのイベントを1件、履歴（UserStateEvent）
    と最新状態（UserStateCurrent）の両方へ書き込む。

    失敗しても例外を上げず、ログに残して呼び出し元（Discordのイベント
    ハンドラ）を止めない。DBエラーは自己修復付きで一度だけ再試行する。
    """
    await ensure_user_state_db()
    now = _to_aware_utc(event_at)
    status_after = _sanitize_status(status_after)
    event_type = str(event_type).strip().lower()[:48]

    snapshot = _member_snapshot(user, guild_id)
    event_payload = _event_payload_for(payload, snapshot, timed_out_until)

    # 掃除は付随処理。ここで例外が抜けると、掃除が失敗しているあいだじゅう
    # BAN も入退室も1件も残らなくなる。
    try:
        await _cleanup_old_events_if_needed(now)
    except Exception:
        logger.exception("[user_state_service] retention cleanup failed")

    for attempt in range(2):
        try:
            await _write_state_event(
                guild_id=guild_id,
                user_id=user_id,
                event_type=event_type,
                status_after=status_after,
                now=now,
                actor=actor,
                actor_fields=_extract_user_fields(actor),
                reason=reason,
                event_payload=event_payload,
                user_fields=_extract_user_fields(user),
                in_guild=in_guild,
                is_banned=is_banned,
                timed_out_until=timed_out_until,
                snapshot=snapshot,
            )
            return
        except Exception as e:
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
    """DBの行を、API/管理画面がそのまま JSON にできる辞書へ変換する。"""
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
    """イベント履歴の1行を辞書へ変換する。payload_json が壊れていたり
    dict でなかったりしても空の dict にフォールバックし、呼び出し側の
    型を保証する。
    """
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


async def list_recent_user_states(  # type: ignore[return]
    guild_id: int,
    *,
    query: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    # for attempt in range(2): の全分岐が return するため実際には
    # 関数末尾へ到達しないが、mypy はループが必ず実行されるとまでは
    # 検証できず「return 文が無い」と誤検知する。
    """直近の更新順にユーザー状態を並べて返す。

    DBエラー時は例外を投げず空リストを返す（一覧表示が丸ごと落ちるより
    空表示のほうがまし、という判断）。自己修復を一度だけ試みてから諦める。
    """
    await ensure_user_state_db()
    safe_limit = max(1, min(200, int(limit)))
    safe_offset = max(0, int(offset))
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stmt = _apply_state_filter(select(UserStateCurrent), guild_id, query)
                stmt = (
                    stmt.order_by(
                        UserStateCurrent.last_event_at.desc().nullslast(),
                        UserStateCurrent.updated_at.desc().nullslast(),
                        UserStateCurrent.id.desc(),
                    )
                    .limit(safe_limit)
                    .offset(safe_offset)
                )

                rows = (await session.scalars(stmt)).all()
                return [_row_to_state_payload(r) for r in rows]
            except Exception as e:
                if attempt == 0 and await _try_db_self_heal(context="list_recent_user_states", exc=e):
                    continue
                logger.exception("[user_state_service] list_recent_user_states failed guild_id=%s", guild_id)
                return []


async def count_user_states(guild_id: int, *, query: str | None = None) -> int:  # type: ignore[return]
    """絞り込み条件に一致する件数。ページ送りの総数表示に使う。"""
    # for attempt in range(2): の全分岐が return するため実際には
    # 関数末尾へ到達しないが、mypy はそこまで検証できず誤検知する。
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


async def get_user_state_detail(  # type: ignore[return]
    guild_id: int,
    user_id: int,
    *,
    event_limit: int = 200,
) -> dict[str, Any] | None:
    # for attempt in range(2): の全分岐が return するため実際には
    # 関数末尾へ到達しないが、mypy はそこまで検証できず誤検知する。
    """1ユーザーの現在状態と直近イベント履歴をまとめて返す。

    current・events のどちらも無ければ None（＝そもそも記録が無い
    ユーザー）を返し、呼び出し側が「未記録」と「読み込み失敗」を
    区別できるようにする。
    """
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
    """_extract_user_fields(None) と同じ形の空の辞書を返す。actor 情報が
    無いイベント（システム起因の記録など）で使う。
    """
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
    """UserStateEvent の行オブジェクトを組み立てるだけで、セッションへの
    追加やコミットはしない。sync_guild_user_states のように複数件を
    1トランザクションでまとめて書きたい呼び出し元のためのヘルパー。
    """
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


def _empty_repair_stats() -> dict[str, int]:
    """整合性の修復で数える項目。試行ごとに新しいものを使う。"""
    return {
        "rows_scanned": 0,
        "rows_fixed": 0,
        "status_fixed": 0,
        "json_fixed": 0,
        "flag_fixed": 0,
        "timeout_fixed": 0,
    }


def _repair_status(row, stats: dict[str, int]) -> bool:
    """status を正規化する。直したら True。"""
    normalized = _sanitize_status(row.status)
    if row.status == normalized:
        return False
    row.status = normalized
    stats["status_fixed"] += 1
    return True


def _repair_json_columns(row, stats: dict[str, int]) -> bool:
    """roles_json / abilities_json を、読める形と決まった書き方へ揃える。直したら True。

    型が違う（配列のはずが文字列など）ものは空へ倒す。型は合っていても
    書き方が違うものは書き直す。揃えておかないと、同じ中身なのに毎回
    「直った」と数え続けることになる。
    """
    changed = False
    for column, loader, empty in (
        ("roles_json", list, "[]"),
        ("abilities_json", dict, "{}"),
    ):
        raw = getattr(row, column)
        value = _safe_json_loads(raw, [] if loader is list else {})
        if not isinstance(value, loader):
            setattr(row, column, empty)
            stats["json_fixed"] += 1
            changed = True
            continue
        normalized = _safe_json_dumps(value, empty)
        if normalized != raw:
            setattr(row, column, normalized)
            stats["json_fixed"] += 1
            changed = True
    return changed


def _repair_flags(row, stats: dict[str, int]) -> bool:
    """status から導ける在室・BAN の旗を揃える。直したら True。

    **active では在室に手を出さない。** 在室かどうかは同期
    （sync_guild_user_states）が Discord に問い合わせて決めるもので、ここで
    一緒に True へ倒すと、すでに抜けた人を「居る」ことにしてしまう。
    """
    expected_in_guild = bool(row.is_in_guild)
    expected_banned = bool(row.is_banned)
    if row.status == "banned":
        expected_banned = True
        expected_in_guild = False
    elif row.status in {"left", "kicked"}:
        expected_in_guild = False
    elif row.status == "active":
        expected_banned = False

    changed = False
    if bool(row.is_in_guild) != expected_in_guild:
        row.is_in_guild = expected_in_guild
        stats["flag_fixed"] += 1
        changed = True
    if bool(row.is_banned) != expected_banned:
        row.is_banned = expected_banned
        stats["flag_fixed"] += 1
        changed = True
    return changed


def _repair_timeout(row, now: datetime, stats: dict[str, int]) -> bool:
    """期限を過ぎたタイムアウトの旗を下ろす。直したら True。"""
    expected = _is_timed_out_until(row.timed_out_until, now)
    if bool(row.is_timed_out) == expected:
        return False
    row.is_timed_out = expected
    stats["timeout_fixed"] += 1
    return True


def _repair_row(row, now: datetime, stats: dict[str, int]) -> None:
    """1行ぶんを直す。**直した行だけ** updated_at を進める。

    全行に触ると「最後に状態が変わった時刻」がバッチを回した時刻に揃い、
    誰がいつ抜けたのかが読めなくなる（壊れた行が1つも無いのが通常なので、
    これは毎回そうなる）。
    """
    changed = _repair_status(row, stats)
    changed = _repair_json_columns(row, stats) or changed
    changed = _repair_flags(row, stats) or changed
    changed = _repair_timeout(row, now, stats) or changed
    if changed:
        row.updated_at = now
        stats["rows_fixed"] += 1


async def _repair_attempt(guild_id: int | None, safe_max_rows: int, now: datetime) -> dict[str, int]:
    """走査と修復を1回ぶん。失敗したら例外を上げる（呼び出し側がやり直す）。"""
    stats = _empty_repair_stats()
    async with SessionLocal() as session:
        try:
            stmt = select(UserStateCurrent).order_by(UserStateCurrent.id.asc()).limit(safe_max_rows)
            if guild_id is not None:
                stmt = stmt.where(UserStateCurrent.guild_id == int(guild_id))

            rows = (await session.scalars(stmt)).all()
            stats["rows_scanned"] = len(rows)
            for row in rows:
                _repair_row(row, now, stats)

            await session.commit()
            return stats
        except Exception:
            await session.rollback()
            raise


async def delete_guild_user_states(guild_id: int) -> dict[str, int]:
    """1ギルドぶんの監査履歴と現在状態を消す。消した件数を返す。

    利用者が「このサーバーのデータを削除」を選んだときの片側
    （services/guild_retention.py が呼ぶ）。**保管期間の掃除とは別の口**で、
    こちらは期間を見ずに全部消す。

    履歴と現在状態は同じトランザクションで消す。片方だけ残ると、
    **誰も居ないのに「BAN されている人が1人」といった表示が残る。**
    """
    await ensure_user_state_db()
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                events = await session.execute(delete(UserStateEvent).where(UserStateEvent.guild_id == int(guild_id)))
                states = await session.execute(
                    delete(UserStateCurrent).where(UserStateCurrent.guild_id == int(guild_id))
                )
                await session.commit()
                # rowcount は DELETE を返す CursorResult にしか無い。Result で
                # 受けている型の上では見えないので、実体から取り出す。
                return {
                    "events": int(getattr(events, "rowcount", 0) or 0),
                    "states": int(getattr(states, "rowcount", 0) or 0),
                }
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="delete_guild_user_states", exc=e):
                    continue
                raise

    return {"events": 0, "states": 0}


async def repair_user_state_integrity(
    *,
    guild_id: int | None = None,
    max_rows: int = 50000,
) -> dict[str, int]:
    """保存済みの現在状態行を走査し、正規化ルールに反した値を直す。

    record_user_state_event を経由せずDBを直接触った過去データや、
    ルール変更前に保存された行を後追いで揃えるためのバッチ処理。
    どこを何件直したかを stats として返す。
    """
    await ensure_user_state_db()
    now = _utc_now()
    safe_max_rows = max(100, min(200000, int(max_rows)))

    stats = _empty_repair_stats()
    for attempt in range(2):
        try:
            # 数え直す。前の試行は rollback しているのに、そこで数えた分を
            # 残すと**直した件数が倍になって報告される**（無人で回るバッチ
            # なので、あとから読めるのはこの数字だけ）。
            return await _repair_attempt(guild_id, safe_max_rows, now)
        except Exception as e:
            if attempt == 0 and await _try_db_self_heal(context="repair_user_state_integrity", exc=e):
                continue
            logger.exception(
                "[user_state_service] repair_user_state_integrity failed guild_id=%s",
                guild_id,
            )
            return stats

    return stats


class _SyncContext(NamedTuple):
    """同期1回ぶんの、どの段でも同じ値。

    メンバー・BAN・不在者の3段が同じギルド・同じ時刻・同じ source を見る。
    別々に渡すと、途中の1段だけ違う時刻で書く事故が起こりうる。
    """

    guild_id: int
    source: str
    now: datetime
    write_events: bool


def _new_state_row(guild_id: int, user_id: int, *, is_banned: bool) -> UserStateCurrent:
    """まだ行が無いユーザーのための、空の現在状態。

    中身は直後に _update_current_state_fields が埋める。ここで status を
    "unknown" にしておくのは、埋める前に落ちても「分からない」として残す
    ため（"active" で作ると、埋まらなかった行が居るように見える）。
    """
    return UserStateCurrent(
        guild_id=guild_id,
        user_id=user_id,
        status="unknown",
        is_in_guild=False,
        is_banned=is_banned,
        is_timed_out=False,
        roles_json="[]",
        abilities_json="{}",
    )


def _sync_members(
    session: Any,
    rows_by_user_id: dict[int, UserStateCurrent],
    stats: dict[str, int],
    members: Sequence[Any],
    ctx: _SyncContext,
) -> set[int]:
    """メンバー一覧をDBへ反映し、見えた user_id の集合を返す。

    返す集合は、あとの「どちらの一覧にも居ない人を left にする」段が使う。
    """
    present_member_ids: set[int] = set()
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
            current = _new_state_row(ctx.guild_id, user_id, is_banned=False)
            session.add(current)
            rows_by_user_id[user_id] = current
            created = True
            stats["created"] += 1
        else:
            stats["updated"] += 1

        _update_current_state_fields(
            current,
            event_type=f"sync_member_{ctx.source}",
            status_after="active",
            now=ctx.now,
            user_fields=_extract_user_fields(member),
            in_guild=True,
            is_banned=False,
            timed_out_until=getattr(member, "timed_out_until", None),
            role_snapshot=_extract_role_snapshot(member),
            ability_snapshot=_extract_ability_snapshot(member, ctx.guild_id),
        )

        if created and ctx.write_events:
            session.add(
                _build_state_event(
                    guild_id=ctx.guild_id,
                    user_id=user_id,
                    event_type="sync_discovered_member",
                    status_after="active",
                    now=ctx.now,
                    payload={"source": ctx.source},
                )
            )
            stats["events_written"] += 1
    return present_member_ids


def _sync_bans(
    session: Any,
    rows_by_user_id: dict[int, UserStateCurrent],
    stats: dict[str, int],
    banned_users: Sequence[Any],
    ctx: _SyncContext,
) -> set[int]:
    """BAN 一覧をDBへ反映し、見えた user_id の集合を返す。

    メンバー一覧のあとに走るので、同じ人が両方に居れば BAN が勝つ。
    """
    banned_user_ids: set[int] = set()
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
            current = _new_state_row(ctx.guild_id, user_id, is_banned=True)
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
            event_type=f"sync_ban_{ctx.source}",
            status_after="banned",
            now=ctx.now,
            user_fields=_extract_user_fields(banned_user),
            in_guild=False,
            is_banned=True,
            timed_out_until=None,
            role_snapshot=None,
            ability_snapshot=None,
        )

        # 既に banned だった人に、同期のたびイベントを積まない。積むと起動の
        # たびに同じ BAN が並び、履歴から「何回 BAN されたか」が読めなくなる。
        if ctx.write_events and (created or before_status != "banned" or before_banned is False):
            session.add(
                _build_state_event(
                    guild_id=ctx.guild_id,
                    user_id=user_id,
                    event_type="sync_discovered_ban",
                    status_after="banned",
                    now=ctx.now,
                    payload={"source": ctx.source},
                )
            )
            stats["events_written"] += 1
    return banned_user_ids


def _reconcile_absent(
    session: Any,
    rows_by_user_id: dict[int, UserStateCurrent],
    stats: dict[str, int],
    present_member_ids: set[int],
    banned_user_ids: set[int],
    ctx: _SyncContext,
) -> None:
    """どちらの一覧にも出てこなかった行を left にする。

    BAN 済みの行は触らない（`should_mark_left` の条件でも弾かれるが、
    「BAN を left で上書きしない」は意図として明示しておく）。
    """
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
            event_type=f"sync_left_{ctx.source}",
            status_after="left",
            now=ctx.now,
            user_fields=_empty_user_fields(),
            in_guild=False,
            is_banned=False,
            timed_out_until=None,
            role_snapshot=None,
            ability_snapshot=None,
        )
        stats["left_reconciled"] += 1

        if ctx.write_events:
            session.add(
                _build_state_event(
                    guild_id=ctx.guild_id,
                    user_id=user_id,
                    event_type="sync_mark_left",
                    status_after="left",
                    now=ctx.now,
                    payload={"source": ctx.source},
                )
            )
            stats["events_written"] += 1


async def _run_sync_attempt(
    session: Any,
    ctx: _SyncContext,
    stats: dict[str, int],
    *,
    members: Sequence[Any],
    banned_users: Sequence[Any],
    reconcile_missing: bool,
) -> None:
    """同期1回ぶん。3段を順に流して commit する。

    **順序に意味がある。** メンバー → BAN の順なので、同じ人が両方に居れば
    BAN が勝つ。不在者の整合は最後で、前の2段が見た user_id を除いて回す。
    例外はそのまま外へ出す（retry と rollback は呼び出し側が持つ）。
    """
    existing_rows = (
        await session.scalars(select(UserStateCurrent).where(UserStateCurrent.guild_id == ctx.guild_id))
    ).all()
    rows_by_user_id: dict[int, UserStateCurrent] = {int(row.user_id): row for row in existing_rows}

    present_member_ids = _sync_members(session, rows_by_user_id, stats, members, ctx)
    banned_user_ids = _sync_bans(session, rows_by_user_id, stats, banned_users, ctx)
    if reconcile_missing:
        _reconcile_absent(session, rows_by_user_id, stats, present_member_ids, banned_user_ids, ctx)

    await session.commit()


async def sync_guild_user_states(
    *,
    guild_id: int,
    members: Sequence[Any],
    banned_users: Sequence[Any] | None = None,
    source: str = "startup_sync",
    reconcile_missing: bool = True,
    write_events_on_sync: bool = True,
) -> dict[str, int]:
    """起動時などにDiscord側の実際のメンバー/BAN一覧とDBを突き合わせ、
    ズレを一括で解消する。

    Bot が落ちていた間の入退室・BANは個別イベントとして記録されない
    ため、このタイミングでまとめて追いつかせないと監査履歴に空白期間が
    できる。

    中身は _run_sync_attempt（3段）にあり、ここが持つのは前準備と、
    1回だけの再試行。結果は tests の SyncGuildUserStatesWholeRunTests が
    統計と最終状態ごと固定している。
    """
    await ensure_user_state_db()
    now = _utc_now()
    ctx = _SyncContext(
        guild_id=int(guild_id),
        source=str(source or "startup_sync")[:32],
        now=now,
        write_events=write_events_on_sync,
    )
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
                await _run_sync_attempt(
                    session,
                    ctx,
                    stats,
                    members=members,
                    banned_users=banned_users,
                    reconcile_missing=reconcile_missing,
                )
                return stats
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="sync_guild_user_states", exc=e):
                    continue
                logger.exception("[user_state_service] sync_guild_user_states failed guild_id=%s", guild_id)
                # 0 を返す。stats は段の中で加算していくので、ここまで来ると
                # 「作成 1 件」などが入っている。しかし直前で rollback しており
                # DB には1行も残っていない。加算済みの値を返すと、呼び出し元
                # （events/user_state_sync.py の全ギルド同期）がそれを成功件数と
                # してログや監視に出し、まるごと失敗した同期が「一部成功」に
                # 見えてしまう。
                return dict(empty_stats)

    return stats
