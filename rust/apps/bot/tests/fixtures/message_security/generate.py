"""メッセージの検査の基準（expected.jsonl）を、本物の Python から作る。

本物の services/security_service.handle_security_for_message を、Discord・VirusTotal・Groq を記録するだけの
偽物に差し替えて回し、Discord への書き込み（送る・書き換える・消す・剥がす・ログ）と Groq に渡したものを
順に書き出す。時刻は固定する。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate.py cases.json > expected.jsonl
"""

import asyncio
import datetime
import json
import math
import os
import re
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import discord  # noqa: E402
from services import raid_detection, security_service as ss, settings_store, spam_detection  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
CHANNEL = 1505310388051251261
NOW = 1795565100.25
JST = datetime.timezone(datetime.timedelta(hours=9))
UTC = datetime.timezone.utc
cases = json.load(open(sys.argv[1], encoding="utf-8"))
clock = {"t": NOW}


def embed_dict(e):
    d = e.to_dict()
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "color": d.get("color"),
        "fields": [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])],
        "footer": (d.get("footer") or {}).get("text"),
    }


def http_error():
    return discord.HTTPException(MagicMock(status=404, reason="Not Found"), "Unknown Message")


async def run(case):
    calls = []
    scanned = []
    spam_detection._user_message_times.clear()
    spam_detection._cleanup_counter = 0
    raid_detection._vc_join_history.clear()
    raid_detection._cleanup_counter = 0
    vc = case.get("voice")
    for dt in case.get("prior_posts", []):
        clock["t"] = NOW + dt
        spam_detection.check_spam(GUILD, USER)
    for dt, name in case.get("prior_joins", []):
        clock["t"] = NOW + dt
        raid_detection.check_vc_raid(SimpleNamespace(display_name=name, id=1), vc)
    clock["t"] = NOW

    edits = {"n": 0}
    fail_at = set(case.get("edit_fail_at", []))

    async def edit(embed):
        edits["n"] += 1
        calls.append(["edit", embed_dict(embed)])
        if edits["n"] in fail_at:
            raise http_error()

    progress = SimpleNamespace(edit=edit)

    async def send_log_embed(bot, guild_id, level, embed):
        calls.append(["send", level, embed_dict(embed)])
        return progress if case.get("log_channel", True) else None

    async def log_action(bot, guild_id, level, message, user=None, fields=None, embed_color=None):
        calls.append(
            [
                "log",
                level,
                message,
                [[k, v] for k, v in (fields or {}).items()],
                embed_color.value if embed_color else None,
            ]
        )

    async def scan(session, url):
        scanned.append(url)
        r = case.get("vt", {}).get(url)
        if r == "raise":
            raise ValueError("boom")
        if r is None:
            return {"status": "ok", "type": "url", "malicious": 0, "suspicious": 0}
        return dict(r)

    async def assess(text, vt_results, spam_count=0, min_interval=float("inf"), is_new_member=False):
        calls.append(
            [
                "assess",
                text,
                [[r.get("malicious"), r.get("suspicious")] for r in vt_results],
                spam_count,
                "inf" if math.isinf(min_interval) else min_interval,
                is_new_member,
            ]
        )
        return case.get("gpt", "SAFE")

    async def remove_roles(*roles, reason=None):
        calls.append(["strip", [r.id for r in roles], reason])

    member = MagicMock(spec=discord.Member)
    member.bot = False
    member.id = USER
    member.guild = SimpleNamespace(id=GUILD)
    member.roles = [SimpleNamespace(id=r, is_default=(lambda r=r: r == GUILD)) for r in [GUILD] + case.get("roles", [])]
    joined = case.get("joined_days_ago", 400)
    member.joined_at = None if joined is None else datetime.datetime.fromtimestamp(NOW - joined * 86400, UTC)
    member.voice = SimpleNamespace(channel=SimpleNamespace(id=vc)) if vc else None
    member.display_name = case.get("name", "nelly")
    member.remove_roles = remove_roles
    delete = AsyncMock(side_effect=http_error() if case.get("delete_fails") else None)
    message = SimpleNamespace(
        author=member,
        guild=SimpleNamespace(id=GUILD),
        content=case.get("content", ""),
        attachments=[SimpleNamespace(url=u) for u in case.get("attachments", [])],
        channel=SimpleNamespace(id=case.get("channel", CHANNEL)),
        delete=delete,
    )

    async def delete_and_record():
        calls.append(["delete"])
        await delete()

    message.delete = delete_and_record
    with (
        patch.object(ss, "send_log_embed", send_log_embed),
        patch.object(ss, "log_action", log_action),
        patch.object(ss, "vt_scan_target", scan),
        patch.object(ss, "gpt_assess", assess),
        patch.object(ss, "get_session", lambda: None),
        patch.object(settings_store, "get_guild_settings", lambda gid: case.get("settings", {})),
    ):
        await ss.handle_security_for_message(MagicMock(), message)
    return calls, sorted(scanned)


async def main():
    out = []
    for case in cases:
        calls, scanned = await run(case)
        line = json.dumps([case["id"], calls, scanned], ensure_ascii=False, separators=(",", ":"))
        # 走査の落ち方の名前は言語で違う（Python は例外の型、Rust は panic）。
        out.append(re.sub(r"scan_failed:\w+", "scan_failed:*", line))
    print("\n".join(out))


with (
    patch.object(spam_detection, "time", SimpleNamespace(time=lambda: clock["t"])),
    patch.object(raid_detection, "time", SimpleNamespace(time=lambda: clock["t"])),
    patch.object(discord.utils, "utcnow", lambda: datetime.datetime.fromtimestamp(clock["t"], UTC)),
    patch.object(ss, "now_jst", lambda: datetime.datetime.fromtimestamp(clock["t"], JST).strftime("%Y-%m-%d %H:%M:%S")),
    patch.object(ss.logger, "warning"),
    patch.object(ss.logger, "exception"),
    patch.object(ss.logger, "info"),
):
    asyncio.run(main())
