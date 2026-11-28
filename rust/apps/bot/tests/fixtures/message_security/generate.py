"""メッセージの検査の基準（expected.jsonl）を、本物の Python から作る。

本物の services/security_service.handle_security_for_message を、Discord・VirusTotal・Groq を記録するだけの
偽物に差し替えて回し、Discord への書き込み（送る・書き換える・消す・タイムアウト・剥がす・ログ）と Groq に
渡したものを順に書き出す。時刻は固定する。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate.py cases.json > expected.jsonl

例（cases.json）の書き方:

- prior_posts: 前の投稿（スパムの記録に入れる）。数なら秒（この投稿と同じ本文・添付・チャンネル）、
  {"dt", "content", "channel", "attachments"} なら中身を変えられる。メッセージの ID は 100 から順に振る
- prior_joins: 前の VC への参加（入って間もない人として記録に入れる）。[秒, ユーザー ID か "self"]
- attachments: URL（ファイル名は URL の最後、大きさは 0）か [URL, ファイル名, 大きさ]
- account_days_ago: アカウントを作ってからの日数（発言した人の ID を、その日時の snowflake にする）
- can_timeout: Bot にタイムアウトの権限があるか（既定は真）。admin: 発言した人が管理者か
- settings: サーバーの設定。タイムアウトを使うのは {"security_timeout_enabled": true} の例だけ（設定の既定は
  無効。無効なら権限があっても、危険なものはロールを外し、スパムは消すだけ）
- timeout_fail: "forbidden"（権限不足）か "error"（ほかの失敗）でタイムアウトを断る
- delete_fails・delete_gone: この投稿の削除を失敗させる（ほかの失敗・既に消えていた）。
  delete_fail_ids・delete_gone_ids: 前の投稿のうち、その ID の削除を同じく失敗させる
- settings_error: 設定を読むと失敗する（管理者は設定を読む前に飛ばすことを見る）
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
from unittest.mock import MagicMock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import aiohttp  # noqa: E402
import discord  # noqa: E402
from services import raid_detection, security_service as ss, settings_store, spam_detection  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
CHANNEL = 1505310388051251261
MESSAGE = 2
NOW = 1795565100.25
DISCORD_EPOCH_MS = 1420070400000
JST = datetime.timezone(datetime.timedelta(hours=9))
UTC = datetime.timezone.utc
cases = json.load(open(sys.argv[1], encoding="utf-8"))
clock = {"t": NOW}


def embed_dict(e):
    """Embed から、比べる項目（題・本文・色・項目・足元）だけを取り出す。"""
    d = e.to_dict()
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "color": d.get("color"),
        "fields": [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])],
        "footer": (d.get("footer") or {}).get("text"),
    }


def http_error():
    """Discord が断ったときの例外（消せない・書き換えられないときに使う）。"""
    return discord.HTTPException(MagicMock(status=404, reason="Not Found"), "Unknown Message")


def not_found():
    """既に消えていたときの例外（discord.NotFound）。"""
    return discord.NotFound(MagicMock(status=404, reason="Not Found"), "Unknown Message")


def forbidden():
    """権限が足りないときの例外（ロールを剥がせない・タイムアウトできないときに使う）。"""
    return discord.Forbidden(MagicMock(status=403, reason="Forbidden"), "Missing Permissions")


def delete_error(case, message_id):
    """その投稿の削除で投げる例外（例が決めたもの。無ければ None）。

    この投稿は delete_fails・delete_gone、前の投稿は delete_fail_ids・delete_gone_ids で決める。
    """
    if message_id == MESSAGE:
        fails, gone = case.get("delete_fails", False), case.get("delete_gone", False)
    else:
        fails, gone = message_id in case.get("delete_fail_ids", []), message_id in case.get("delete_gone_ids", [])
    if fails:
        return http_error()
    if gone:
        return not_found()
    return None


def timeout_error(case):
    """タイムアウトで投げる例外（例の timeout_fail が "forbidden" なら権限不足、"error" ならほかの失敗）。"""
    return {"forbidden": forbidden, "error": http_error}.get(case.get("timeout_fail"), lambda: None)()


def member_id(case):
    """発言した人の ID。account_days_ago があれば、その日時に作ったアカウントの ID（snowflake）にする。"""
    days = case.get("account_days_ago")
    if days is None:
        return USER
    return (int((NOW - days * 86400) * 1000) - DISCORD_EPOCH_MS) << 22


def attachment(entry):
    """添付 1 つ（URL・ファイル名・大きさ）。URL だけなら、ファイル名は URL の最後、大きさは 0。"""
    if isinstance(entry, str):
        return SimpleNamespace(url=entry, filename=entry.rsplit("/", 1)[-1], size=0)
    url, filename, size = entry
    return SimpleNamespace(url=url, filename=filename, size=size)


def record_prior(case):
    """前の投稿と VC への参加を、スパムと VC の荒らしの記録に入れる（時刻は NOW からの秒）。"""
    spam_detection._user_posts.clear()
    spam_detection._cleanup_counter = 0
    raid_detection._vc_join_history.clear()
    raid_detection._vc_enforced.clear()
    raid_detection._cleanup_counter = 0
    uid = member_id(case)
    for i, post in enumerate(case.get("prior_posts", [])):
        post = post if isinstance(post, dict) else {"dt": post}
        clock["t"] = NOW + post["dt"]
        files = [attachment(a) for a in post.get("attachments", case.get("attachments", []))]
        spam_detection.check_spam(
            GUILD,
            uid,
            post.get("channel", case.get("channel", CHANNEL)),
            100 + i,
            post.get("content", case.get("content", "")),
            [(a.filename, a.size) for a in files],
        )
    for dt, who in case.get("prior_joins", []):
        clock["t"] = NOW + dt
        raid_detection.check_vc_raid(SimpleNamespace(id=uid if who == "self" else who), case.get("voice"))
    clock["t"] = NOW


async def run(case):
    """例を 1 つ回し、Discord への書き込みと Groq に渡したもの（順に）と、走査した URL を返す。"""
    calls = []
    scanned = []
    record_prior(case)
    vc = case.get("voice")
    channel = case.get("channel", CHANNEL)

    edits = {"n": 0}
    fail_at = set(case.get("edit_fail_at", []))

    async def edit(embed):
        """進み具合の Embed の書き換え。例が指定した回で失敗させる。"""
        edits["n"] += 1
        calls.append(["edit", embed_dict(embed)])
        if edits["n"] in fail_at:
            # 例が "network" と決めたら、Discord の応答ではない通信の失敗にする。
            if case.get("edit_error") == "network":
                raise aiohttp.ClientConnectionError("Connection reset by peer")
            raise http_error()

    progress = SimpleNamespace(edit=edit)

    async def send_log_embed(bot, guild_id, level, embed):
        """ログチャンネルへの Embed の送信。ログチャンネルが無い例では None を返す。"""
        calls.append(["send", level, embed_dict(embed)])
        return progress if case.get("log_channel", True) else None

    async def log_action(bot, guild_id, level, message, user=None, fields=None, embed_color=None):
        """ログ 1 件の送信（レベル・本文・項目・色を記録する）。"""
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
        """VirusTotal の走査。例が決めた結果を返すか、例外を投げる。"""
        scanned.append(url)
        r = case.get("vt", {}).get(url)
        if r == "raise":
            raise ValueError("boom")
        if r is None:
            return {"status": "ok", "type": "url", "malicious": 0, "suspicious": 0}
        return dict(r)

    async def assess(text, vt_results, spam=None, is_new_member=False, is_new_account=False):
        """Groq の判定。渡されたものを記録して、例が決めた判定を返す。"""
        spam = spam or spam_detection.SpamCheck()
        calls.append(
            [
                "assess",
                text,
                [[r.get("malicious"), r.get("suspicious")] for r in vt_results],
                [spam.repeat, spam.repeat_count, spam.repeat_channels, spam.flood, spam.flood_count],
                "inf" if math.isinf(spam.min_interval) else spam.min_interval,
                is_new_member,
                is_new_account,
            ]
        )
        return case.get("gpt", "SAFE")

    async def remove_roles(*roles, reason=None):
        """ロールの剥奪（剥がすロールの並びと理由を記録する）。例が決めたロールで失敗させる。"""
        calls.append(["strip", [r.id for r in roles], reason])
        if case.get("strip_fail_at") in [r.id for r in roles]:
            raise forbidden()
        if case.get("strip_error_at") in [r.id for r in roles]:
            raise http_error()

    async def timeout(until, reason=None):
        """タイムアウト（秒と理由を記録する）。例が決めたら断る。"""
        calls.append(["timeout", int(until.total_seconds()), reason])
        error = timeout_error(case)
        if error:
            raise error

    async def delete_by_id(bot, channel_id, message_id):
        """前の投稿の削除（ID で。記録してから消す。例によっては失敗する）。"""
        calls.append(["delete", channel_id, message_id])
        error = delete_error(case, message_id)
        if error:
            raise error

    async def delete_this():
        """この投稿の削除（記録してから消す。例によっては失敗する）。"""
        calls.append(["delete", channel, MESSAGE])
        error = delete_error(case, MESSAGE)
        if error:
            raise error

    me = SimpleNamespace(guild_permissions=SimpleNamespace(moderate_members=case.get("can_timeout", True)))
    member = MagicMock(spec=discord.Member)
    member.bot = False
    member.id = member_id(case)
    member.guild = SimpleNamespace(id=GUILD, me=me)
    member.guild_permissions = SimpleNamespace(administrator=case.get("admin", False))
    member.roles = [SimpleNamespace(id=r, is_default=(lambda r=r: r == GUILD)) for r in [GUILD] + case.get("roles", [])]
    joined = case.get("joined_days_ago", 400)
    member.joined_at = None if joined is None else datetime.datetime.fromtimestamp(NOW - joined * 86400, UTC)
    member.voice = SimpleNamespace(channel=SimpleNamespace(id=vc)) if vc else None
    member.display_name = case.get("name", "nelly")
    member.remove_roles = remove_roles
    member.timeout = timeout
    message = SimpleNamespace(
        id=MESSAGE,
        author=member,
        guild=SimpleNamespace(id=GUILD),
        content=case.get("content", ""),
        attachments=[attachment(a) for a in case.get("attachments", [])],
        channel=SimpleNamespace(id=channel),
        delete=delete_this,
    )

    def guild_settings(gid):
        """サーバーの設定。例が settings_error なら読めない。"""
        if case.get("settings_error"):
            raise RuntimeError("設定が読めない")
        return case.get("settings", {})

    with (
        patch.object(ss, "send_log_embed", send_log_embed),
        patch.object(ss, "log_action", log_action),
        patch.object(ss, "vt_scan_target", scan),
        patch.object(ss, "gpt_assess", assess),
        patch.object(ss, "delete_message", delete_by_id),
        patch.object(ss, "get_session", lambda: None),
        patch.object(settings_store, "get_guild_settings", guild_settings),
    ):
        await ss.handle_security_for_message(MagicMock(), message)
    return calls, sorted(scanned)


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
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
    patch.object(ss.logger, "error"),
    patch.object(ss.logger, "debug"),
):
    asyncio.run(main())
