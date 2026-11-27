"""利用者の状態の記録の基準（expected.json）を、本物の Python から作る。

本物のイベント処理（events/members.py・events/voice.py）に、discord.py の本物の Member・User・Role を渡し、
本物の record_user_state_event に本物の Postgres へ書かせる。1 件ごとに、足された履歴の行と、その人の
最新状態の行を読み出す。ログチャンネルへの書き込みと歓迎は差し替える。時刻は例ごとに固定する。

監査ログの選び方（_find_recent_audit_entry）は、偽物の監査ログを読ませて、選んだ ID と読んだ回数を出す。
表の形（列・索引・制約）も、Python が作った表から読み出す。

使い方（本番と同じ依存で、リポジトリの直下を /app に置き、空の Postgres を渡す）:

    USER_STATE_POSTGRES_DSN=postgresql+asyncpg://postgres:pw@host:5432/postgres \
        python generate.py cases.json > expected.json
"""

import asyncio
import datetime
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import discord  # noqa: E402
from sqlalchemy import text  # noqa: E402

import events.members as members  # noqa: E402
import events.user_state_sync as sync  # noqa: E402
import events.voice as voice  # noqa: E402
from services import settings_store  # noqa: E402
from services import user_state_db as udb  # noqa: E402
from services import user_state_service as uss  # noqa: E402

data = json.load(open(sys.argv[1], encoding="utf-8"))
G = int(data["guild"]["id"])
state = Mock()
state.store_user.side_effect = lambda d, *a, **k: discord.User(state=state, data=d)
guild = Mock()
guild.id = G
guild.owner_id = int(data["guild"]["owner_id"])
roles = {}
guild.get_role.side_effect = lambda rid: roles.get(int(rid))
for r in data["guild"]["roles"]:
    roles[int(r["id"])] = discord.Role(guild=guild, state=state, data=r)
guild.default_role = roles[G]
clock = {"now": None}


def member(m):
    """Discord の JSON から、discord.py の本物の Member を作る。"""
    return discord.Member(data={k: v for k, v in m.items() if k != "guild_id"}, guild=guild, state=state)


def user(u):
    """Discord の JSON から、discord.py の本物の User を作る。"""
    return discord.User(state=state, data=u)


def audit_entry(a):
    """監査ログで見つかった 1 件（実行者はキャッシュのメンバーか、応答のユーザー）。"""
    if a is None:
        return None
    who = member(a["member"]) if "member" in a else user(a["user"])
    return SimpleNamespace(user=who, reason=a.get("reason"))


def channel(c):
    """VC（ID と名前だけ使われる）。"""
    return SimpleNamespace(id=int(c["id"]), name=c["name"]) if c else None


TS = "to_char({0} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US')"
EVENT_SQL = (
    "SELECT id, event_type, status_after, actor_user_id, actor_name, reason, payload_json, "
    + TS.format("event_at")
    + " FROM user_state_event WHERE id > :last ORDER BY id"
)
CURRENT_SQL = (
    "SELECT username, display_name, avatar_url, status, is_in_guild, is_banned, is_timed_out, "
    + TS.format("timed_out_until")
    + ", roles_json, abilities_json, last_event_type, "
    + ", ".join(TS.format(c) for c in ("last_event_at", "last_joined_at", "last_left_at", "updated_at"))
    + ", first_seen_at IS NOT NULL, created_at IS NOT NULL"
    " FROM user_state_current WHERE guild_id = :g AND user_id = :u"
)
TABLES = "('user_state_current', 'user_state_event')"
SCHEMA_SQL = {
    "columns": "SELECT table_name, column_name, data_type, character_maximum_length, is_nullable, column_default "
    f"FROM information_schema.columns WHERE table_schema = current_schema() AND table_name IN {TABLES} "
    "ORDER BY table_name, ordinal_position",
    "indexes": "SELECT tablename, indexname, replace(indexdef, current_schema() || '.', '') FROM pg_indexes "
    f"WHERE schemaname = current_schema() AND tablename IN {TABLES} ORDER BY tablename, indexname",
    "constraints": "SELECT c.relname, n.conname, n.contype::text, pg_get_constraintdef(n.oid) FROM pg_constraint n "
    "JOIN pg_class c ON c.oid = n.conrelid WHERE n.connamespace = current_schema()::regnamespace "
    f"AND c.relname IN {TABLES} ORDER BY c.relname, n.conname",
}


async def rows(sql, **params):
    """SQL を流して、行をリストで返す。"""
    async with udb.engine.connect() as conn:
        return [list(r) for r in (await conn.execute(text(sql), params)).all()]


async def run_member_step(bot, s):
    """メンバーのイベント 1 件を本物の処理に流し、相手の JSON を返す。"""
    kind = s["kind"]
    if kind == "join":
        await members._on_member_join(bot, member(s["member"]))
        return s["member"]["user"]
    if kind == "remove":
        await members._on_member_remove(bot, member(s["member"]))
        return s["member"]["user"]
    if kind == "update":
        await members._on_member_update(bot, member(s["before"]), member(s["after"]))
        return s["after"]["user"]
    if kind == "ban":
        # discord.py は、まだキャッシュに残っていればメンバーを渡す。
        target = member(s["cached"]) if s.get("cached") else user(s["user"])
        await members._on_member_ban(bot, guild, target)
        return s["user"]
    if kind == "unban":
        await members._on_member_unban(bot, guild, user(s["user"]))
        return s["user"]
    raise ValueError(kind)


async def run_voice_step(s):
    """VC のイベント 1 件を本物の処理に流し、相手の JSON を返す。"""
    stay = s.get("stay")
    await voice._persist_vc_transition(
        member(s["member"]),
        s["change"] == "join",
        s["change"] == "leave",
        s["change"] == "move",
        channel(s.get("before")),
        channel(s.get("after")),
        stay[0] if stay else None,
        stay[1] if stay else "",
    )
    return s["member"]["user"]


async def run_step(s):
    """手順 1 つを流して、相手の ID を返す。"""
    clock["now"] = datetime.datetime.fromisoformat(s["at"])
    guild.member_count = s.get("count")
    find = AsyncMock(return_value=audit_entry(s.get("audit")))
    with patch.object(members, "_find_recent_audit_entry", find):
        who = await (run_voice_step(s) if s["kind"] == "voice" else run_member_step(Mock(), s))
    return int(who["id"])


async def run_audit(case):
    """本物の _find_recent_audit_entry に偽物の監査ログを読ませる。"""
    calls = {"n": 0}
    sleeps = []

    def audit_logs(limit, action):
        """guild.audit_logs の代わり。読むたびに次の回の中身を返す（何回読んだかを数えるため）。"""
        i = calls["n"]
        calls["n"] += 1
        page = case["pages"][i] if i < len(case["pages"]) else []

        async def gen():
            """その回の監査ログを新しい順に流す。"raise" の回は読むのに失敗したことにする。"""
            if page == "raise":
                raise RuntimeError("boom")
            for eid, target in page:
                yield SimpleNamespace(
                    id=int(eid),
                    target=SimpleNamespace(id=int(target)) if target else None,
                    created_at=discord.utils.snowflake_time(int(eid)),
                )

        return gen()

    me = SimpleNamespace(guild_permissions=SimpleNamespace(view_audit_log=True))
    fake = SimpleNamespace(me=me, audit_logs=audit_logs)
    now = datetime.datetime.fromtimestamp(case["now_ms"] / 1000, datetime.timezone.utc)

    async def no_sleep(seconds):
        """待たずに、待とうとした秒数だけ控える（読み直しの間の待ちを数えるため）。"""
        sleeps.append(seconds)

    with patch.object(discord.utils, "utcnow", lambda: now), patch.object(sync.asyncio, "sleep", no_sleep):
        hit = await sync._find_recent_audit_entry(
            fake, action=discord.AuditLogAction.kick, target_user_id=int(case["target"])
        )
    return [case["id"], str(hit.id) if hit else None, calls["n"], sleeps]


async def main():
    """全部の手順を流して、基準を JSON で出す。"""
    out = {"steps": [], "audit": []}
    last = 0
    for s in data["steps"]:
        uid = await run_step(s)
        added = await rows(EVENT_SQL, last=last)
        if added:
            last = added[-1][0]
        current = await rows(CURRENT_SQL, g=G, u=uid)
        out["steps"].append({"events": [r[1:] for r in added], "current": current[0] if current else None})
    out["totals"] = {
        "events": (await rows("SELECT count(*) FROM user_state_event"))[0][0],
        "current": (await rows("SELECT count(*) FROM user_state_current"))[0][0],
    }
    out["schema"] = {name: await rows(sql) for name, sql in SCHEMA_SQL.items()}
    for case in data["audit"]:
        out["audit"].append(await run_audit(case))
    await udb.engine.dispose()
    print(json.dumps(out, ensure_ascii=False, indent=1))


with (
    patch.object(members, "log_action", AsyncMock()),
    patch.object(members, "send_welcome", AsyncMock()),
    patch.object(members, "send_goodbye", AsyncMock()),
    patch.object(settings_store, "get_guild_settings", lambda gid: data["settings"]),
    patch.object(uss, "_utc_now", lambda: clock["now"]),
    patch.object(discord.utils, "utcnow", lambda: clock["now"]),
    patch.object(udb.logger, "info"),
):
    asyncio.run(main())
