"""利用者の状態の同期・修復・掃除の基準（expected.json）を、本物の Python から作る。

- 同期と修復: 本物の sync_guild_user_states・repair_user_state_integrity・record_user_state_event に、discord.py の
  本物の Member・User を渡して本物の Postgres へ書かせる。手順ごとに、数えた結果・足された履歴・最新状態の行を
  読み出す。時刻は手順ごとに固定する
- Discord からの取り方: 本物の _fetch_guild_members_for_sync・_fetch_guild_bans_for_sync（discord.py の
  Guild.fetch_members・Guild.bans）に偽物の HTTP を読ませ、要求（件数と after）と並びを出す
- 修復の 1 行・JSON の読み書き・時刻の読み方・鍵の読み方・放棄の判断: 本物の関数をそのまま呼ぶ
- 掃除: 本物の purge_abandoned_guilds に、ファイルの設定（settings.json）を読ませる

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
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import discord  # noqa: E402
from sqlalchemy import text  # noqa: E402

import events.user_state_sync as sync  # noqa: E402
from services import guild_retention as gr  # noqa: E402
from services import settings_store  # noqa: E402
from services import user_state_db as udb  # noqa: E402
from services import user_state_service as uss  # noqa: E402

data = json.load(open(sys.argv[1], encoding="utf-8"))
G = int(data["guild"]["id"])
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
state = Mock()
state.store_user.side_effect = lambda d, *a, **k: discord.User(state=state, data=d)
state._intents.members = True
guild = Mock()
guild.id = G
guild.owner_id = int(data["guild"]["owner_id"])
roles = {}
guild.get_role.side_effect = lambda rid: roles.get(int(rid))
for r in data["guild"]["roles"]:
    roles[int(r["id"])] = discord.Role(guild=guild, state=state, data=r)
guild.default_role = roles[G]
clock = {"now": None}


def at(stamp):
    """ISO 8601 の文字を、時差つきの datetime に（無ければ None）。"""
    return datetime.datetime.fromisoformat(stamp) if stamp else None


def member(m, owner=guild):
    """Discord の JSON から、discord.py の本物の Member を作る。"""
    return discord.Member(data={k: v for k, v in m.items() if k != "guild_id"}, guild=owner, state=state)


def user(u):
    """Discord の JSON から、discord.py の本物の User を作る。"""
    return discord.User(state=state, data=u)


def clean(value):
    """対になっていないサロゲートを U+FFFD に置き換える（出力の JSON を UTF-8 で書けるように）。"""
    if not isinstance(value, str):
        return value
    return "".join("�" if 0xD800 <= ord(c) <= 0xDFFF else c for c in value)


def has_surrogate(value):
    """対になっていないサロゲートが入っているか。"""
    return isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value)


TS = "to_char({0} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US')"
CURRENT_SQL = (
    "SELECT guild_id::text, user_id::text, username, display_name, avatar_url, status, is_in_guild, is_banned, "
    "is_timed_out, "
    + TS.format("timed_out_until")
    + ", roles_json, abilities_json, last_event_type, "
    + ", ".join(TS.format(c) for c in ("last_event_at", "last_joined_at", "last_left_at", "updated_at"))
    + ", first_seen_at IS NOT NULL, created_at IS NOT NULL"
    " FROM user_state_current WHERE guild_id = :g ORDER BY user_id"
)
EVENT_SQL = (
    "SELECT id, guild_id::text, user_id::text, event_type, status_after, actor_user_id::text, actor_name, reason, "
    "payload_json, " + TS.format("event_at") + " FROM user_state_event WHERE id > :last ORDER BY id"
)
SEED_ROW = (
    "INSERT INTO user_state_current (guild_id, user_id, username, display_name, avatar_url, status, is_in_guild, "
    "is_banned, is_timed_out, timed_out_until, roles_json, abilities_json, last_event_type, last_event_at, "
    "last_joined_at, last_left_at, updated_at) VALUES (:guild_id, :user_id, :username, :display_name, :avatar_url, "
    ":status, :is_in_guild, :is_banned, :is_timed_out, :timed_out_until, :roles_json, :abilities_json, "
    ":last_event_type, :last_event_at, :last_joined_at, :last_left_at, :updated_at)"
)
SEED_EVENT = (
    "INSERT INTO user_state_event (guild_id, user_id, event_type, status_after, payload_json, event_at) "
    "VALUES (:guild_id, :user_id, :event_type, :status_after, :payload_json, :event_at)"
)
TIMES = ("timed_out_until", "last_event_at", "last_joined_at", "last_left_at", "updated_at", "event_at")


async def rows(sql, **params):
    """SQL を流して、行をリストで返す。"""
    async with udb.engine.connect() as conn:
        return [list(r) for r in (await conn.execute(text(sql), params)).all()]


async def seed(s):
    """初めの行と履歴を、同じ SQL でそのまま入れる（Rust の側も同じ文で入れる）。"""

    def bind(r):
        """ID は整数に、時刻は datetime に（asyncpg は文字を時刻として受けない）。"""
        out = dict(r)
        out["guild_id"], out["user_id"] = int(r["guild_id"]), int(r["user_id"])
        for key in TIMES:
            if key in out:
                out[key] = at(out[key])
        return out

    async with udb.engine.begin() as conn:
        for r in s.get("rows", []):
            await conn.execute(text(SEED_ROW), bind(r))
        for e in s.get("events", []):
            await conn.execute(text(SEED_EVENT), bind(e))


async def run_step(s):
    """手順 1 つを流して、数えた結果を返す（無い手順は None）。"""
    if s["kind"] == "seed":
        await seed(s)
        return None
    clock["now"] = at(s["at"])
    if s["kind"] == "record":
        await uss.record_user_state_event(
            guild_id=int(s["guild_id"]),
            user_id=int(s["user_id"]),
            event_type=s["event_type"],
            status_after=s["status_after"],
            in_guild=s["in_guild"],
            is_banned=s["is_banned"],
        )
        return None
    if s["kind"] == "sync":
        with patch.object(settings_store, "get_guild_settings", lambda gid: dict(data["settings"])):
            return await uss.sync_guild_user_states(
                guild_id=G,
                members=[member(m) for m in s["members"]],
                banned_users=[user(b) for b in s["bans"]],
                source=s["source"],
                reconcile_missing=s["reconcile"],
                write_events_on_sync=s["write_events"],
            )
    if s["kind"] == "repair":
        return await uss.repair_user_state_integrity(
            guild_id=int(s["guild"]) if s["guild"] else None, max_rows=s["max_rows"]
        )
    raise ValueError(s["kind"])


async def run_steps():
    """全部の手順を流し、手順ごとの結果を返す。"""
    await udb.ensure_user_state_db()
    out = []
    last = 0
    for s in data["steps"]:
        stats = await run_step(s)
        added = await rows(EVENT_SQL, last=last)
        if added:
            last = added[-1][0]
        current = []
        for g in s.get("dump", []):
            current.extend(await rows(CURRENT_SQL, g=int(g)))
        count = (await rows("SELECT count(*) FROM user_state_event"))[0][0]
        out.append({"stats": stats, "events": [r[1:] for r in added], "current": current, "event_count": count})
    return out


def page_member(i, base):
    """偽物の Discord が返すメンバー（ID は base + i）。"""
    return {
        "user": {"id": str(base + i), "username": f"m{i}", "discriminator": "0", "avatar": None, "global_name": None},
        "roles": [],
        "joined_at": "2026-11-01T00:00:00+00:00",
        "deaf": False,
        "mute": False,
        "flags": 0,
    }


def failure(status):
    """偽物の Discord の失敗（403 は Forbidden、ほかは DiscordServerError）。"""
    response = SimpleNamespace(status=status, reason="X")
    if status == 403:
        return discord.Forbidden(response, {"message": "Missing Access", "code": 50001})
    return discord.DiscordServerError(response, "boom")


async def run_fetch(case):
    """本物の取り方に偽物の HTTP を読ませ、要求と結果を返す。"""
    calls = []
    base = case["base"]
    fstate = Mock()
    fstate._intents.members = True
    fstate.store_user.side_effect = lambda d, *a, **k: discord.User(state=fstate, data=d)
    fguild = Mock()
    fguild.id = int(case["guild"])
    fguild._state = fstate
    fguild.get_role.return_value = None
    fguild.members = [member(page_member(i, base), owner=fguild) for i in case.get("cached", [])]
    fguild.fetch_members = types.MethodType(discord.Guild.fetch_members, fguild)
    fguild.bans = types.MethodType(discord.Guild.bans, fguild)
    every = list(range(1, case["total"] + 1))

    def page(limit, after):
        """after より後ろを limit 件。決めた回なら失敗する。"""
        calls.append([limit, after or None])
        if case.get("fail_page") == len(calls) - 1:
            raise failure(case["status"])
        return [i for i in every if base + i > (after or 0)][:limit]

    async def get_members(guild_id, limit, after):
        """discord.py の http.get_members の代わり。"""
        return [page_member(i, base) for i in page(limit, after)]

    async def get_bans(guild_id, limit, before=None, after=None):
        """discord.py の http.get_bans の代わり。"""
        return [{"user": page_member(i, base)["user"], "reason": None} for i in page(limit, after)]

    fstate.http.get_members = get_members
    fstate.http.get_bans = get_bans
    if case["what"] == "members":
        with patch.object(sync, "_USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", case["max"]):
            got, fetched_all = await sync._fetch_guild_members_for_sync(fguild)
    else:
        got, fetched_all = await sync._fetch_guild_bans_for_sync(fguild), None
    return {"id": case["id"], "requests": calls, "ids": [str(m.id) for m in got], "fetched_all": fetched_all}


def run_repair_rows():
    """修復の 1 行（本物の _repair_row）。"""
    now = at(data["repair_now"])
    out = []
    for c in data["repair_rows"]:
        row = SimpleNamespace(**c)
        row.timed_out_until = at(c["timed_out_until"])
        row.updated_at = None
        stats = uss._empty_repair_stats()
        uss._repair_row(row, now, stats)
        unwritable = has_surrogate(row.roles_json) or has_surrogate(row.abilities_json)
        out.append(
            {
                "row": [
                    row.status,
                    row.is_in_guild,
                    row.is_banned,
                    row.is_timed_out,
                    None if has_surrogate(row.roles_json) else row.roles_json,
                    None if has_surrogate(row.abilities_json) else row.abilities_json,
                    row.updated_at is not None,
                ],
                "unwritable": unwritable,
                "stats": stats,
            }
        )
    return out


def run_json():
    """JSON の読み書き（Python の json.loads と json.dumps(ensure_ascii=False)）。"""
    out = []
    for raw in data["json"]:
        try:
            value = json.loads(raw)
        except Exception:
            out.append(None)
            continue
        kind = "list" if isinstance(value, list) else "dict" if isinstance(value, dict) else "other"
        dumped = json.dumps(value, ensure_ascii=False)
        out.append([kind, clean(dumped), has_surrogate(dumped)])
    return out


def micros(dt):
    """時差つきの datetime を UNIX マイクロ秒に。"""
    return (dt - EPOCH) // datetime.timedelta(microseconds=1)


def run_iso():
    """時刻の読み方（本物の guild_retention._parse）。"""
    out = []
    for stamp in data["iso"]:
        parsed = gr._parse(stamp)
        out.append(None if parsed is None else micros(parsed))
    return out


def run_int_keys():
    """設定の鍵の読み方（Python の int()）。"""
    out = []
    for key in data["int_keys"]:
        try:
            out.append(str(int(key)))
        except ValueError:
            out.append(None)
    return out


def run_abandoned():
    """放棄の判断（本物の is_abandoned と touched_at。設定の全体だけを差し替える）。"""
    out = []
    for c in data["abandoned"]:
        whole = {"guilds": {"77": c["settings"]}}
        with (
            patch.object(settings_store, "_load_all", lambda: whole),
            patch.object(gr, "ABANDONED_AFTER_DAYS", c["days"]),
        ):
            try:
                out.append(gr.is_abandoned(77, present=c["present"], now=at(c["now"])))
            except Exception:
                out.append("error")
    return out


async def run_purge():
    """掃除（本物の purge_abandoned_guilds に、ファイルの設定を読ませる）。"""
    p = data["purge"]
    path = Path(os.environ["SETTINGS_DIR"]) / "settings.json"
    path.write_text(json.dumps({"guilds": p["guilds"]}, ensure_ascii=False), encoding="utf-8")
    fixed = at(p["now"])

    class Clock(datetime.datetime):
        """now() だけを決めた時刻にした datetime。"""

        @classmethod
        def now(cls, tz=None):
            """決めた時刻を返す。"""
            return fixed

    with patch.object(gr, "datetime", Clock), patch.object(gr, "ABANDONED_AFTER_DAYS", p["days"]):
        removed = await gr.purge_abandoned_guilds({int(g) for g in p["present"]})
    left = json.loads(path.read_text(encoding="utf-8"))["guilds"]
    return {"removed": [str(g) for g in removed], "guilds": left}


async def main():
    """全部を流して、基準を JSON で出す。"""
    out = {"steps": await run_steps()}
    out["totals"] = {
        "events": (await rows("SELECT count(*) FROM user_state_event"))[0][0],
        "current": (await rows("SELECT count(*) FROM user_state_current"))[0][0],
    }
    await udb.engine.dispose()
    out["fetch"] = [await run_fetch(c) for c in data["fetch"]]
    out["repair_rows"] = run_repair_rows()
    out["json"] = run_json()
    out["iso"] = run_iso()
    out["int_keys"] = run_int_keys()
    out["abandoned"] = run_abandoned()
    out["purge"] = await run_purge()
    print(dump_lines(out))


def dump_lines(out):
    """上の段の値を、並びなら 1 件 1 行で書く（差分が読めて、ファイルが膨らまない）。"""

    def one(value):
        """1 件を 1 行の JSON に。"""
        return json.dumps(value, ensure_ascii=False)

    parts = []
    for key, value in out.items():
        if isinstance(value, list):
            body = "[\n" + ",\n".join(one(v) for v in value) + "\n]"
        else:
            body = one(value)
        parts.append(f"{one(key)}: {body}")
    return "{\n" + ",\n".join(parts) + "\n}"


with (
    patch.object(uss, "_utc_now", lambda: clock["now"]),
    patch.object(discord.utils, "utcnow", lambda: clock["now"]),
    patch.object(udb.logger, "info"),
    patch.object(sync.logger, "exception"),
    patch.object(sync.logger, "warning"),
):
    asyncio.run(main())
