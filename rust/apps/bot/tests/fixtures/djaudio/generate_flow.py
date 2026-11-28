"""DJAudio の流れ（見張るチャンネルの投稿 → リアクション → 落とす → 返信）の基準（flow_expected.jsonl）を、本物の
Python から作る。

本物の `services/djaudio_service.py` の `handle_djaudio_message` を、記録するだけの偽物の Bot・メッセージで呼ぶ。
落とすところ（`_download_and_register`）・行き先の安全確認（`validate_public_http_url_async`）・登録への書き足し
（`update_discord_message`）・単調な時計は、例ごとの台本で答える偽物に差し替える。

1 行に 1 例。``[例, したことの並び]``。したことは次の形:

- ``["react", 絵文字]``・``["unreact", 絵文字]``（Bot 自身のリアクションを外す）
- ``["reply", 本文, Embed]``（返信。作者には通知しない）・``["send", チャンネル, Embed]``（出力チャンネルへ）
- ``["download", URL, 有効期間]``・``["record", 印, チャンネル, メッセージ]``
- ``["raised"]``（`handle_djaudio_message` から例外が外へ抜けた。Bot の受け皿がログに残すところ）

台本（例の鍵）:

- ``settings``: そのサーバーの設定。``messages``: 投稿の並び（``content``・``author``・``at``〔単調な時計の秒〕・
  ``message``〔メッセージの ID〕）。``duplicate``: 同じ投稿を 2 つ同時に渡す（Discord の重複配信）
- ``downloads``: URL ごとの結果（``results``〔題と印の並び〕・``error``・``timeout``）
- ``channels``: Bot から見えるチャンネル（ID → ``text``〔送れる〕・``category``〔送れない〕）
- ``fail``: 断られる働きかけ。``react:<絵文字>``・``unreact:<絵文字>``・``reply:<何回目>``・``send``（Discord の
  `HTTPException`）。末尾に ``!`` を付けると、Discord に断られたのではない失敗（通信の失敗など）
- 安全でない行き先は、URL に ``UNSAFE`` が入っているもの

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_flow.py > flow_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, "/app")
import discord  # noqa: E402

from services import djaudio_service, settings_store  # noqa: E402
from services.ttl_cache import TTLCache  # noqa: E402
from services.url_safety import URLSafetyError  # noqa: E402

GUILD = 1399617700363370556
CHANNEL = 1505310388051251000
BOT = 1350672236612288633
REPLY_ID = 7001
SENT_ID = 7002
BASE = "https://dl.example"
TIMEOUT = 0.2
CLOCK = [0.0]


def write_settings(guild_settings):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): guild_settings}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def embed_json(embed):
    """Embed から、比べる項目（題・本文・色・項目・足元）だけを取り出す。"""
    if embed is None:
        return None
    d = embed.to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    footer = (d.get("footer") or {}).get("text")
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "color": d.get("color"),
        "fields": fields,
        "footer": footer,
    }


class Failures:
    """台本の「断られる働きかけ」。何回目の返信かを数える。"""

    def __init__(self, spec):
        """台本（``["react:⏳", "reply:2!"]`` のような並び）を読む。"""
        self.spec = spec
        self.replies = 0

    def check(self, what):
        """その働きかけが断られるなら、例外を投げる。"""
        for item in self.spec:
            other = item.endswith("!")
            name = item.rstrip("!")
            if name == what:
                if other:
                    raise RuntimeError(f"connection reset ({what})")
                raise discord.HTTPException(MagicMock(status=403, reason="Forbidden"), f"refused ({what})")


def make_bot(case):
    """Bot（見えるチャンネル。送れるものだけ `send` を持つ）。"""
    channels = {}
    effects = case["_effects"]
    failures = case["_failures"]
    for key, kind in case.get("channels", {}).items():
        channel_id = int(key)
        if kind == "text":

            async def send(embed=None, _id=channel_id):
                """出力チャンネルへ送る。"""
                failures.check("send")
                effects.append(["send", _id, embed_json(embed)])
                return SimpleNamespace(channel=SimpleNamespace(id=_id), id=SENT_ID)

            channels[channel_id] = SimpleNamespace(id=channel_id, send=send)
        else:
            channels[channel_id] = SimpleNamespace(id=channel_id)
    return SimpleNamespace(user=SimpleNamespace(id=BOT), get_channel=channels.get)


def make_message(case, spec):
    """投稿（リアクション・返信を記録する）。"""
    effects = case["_effects"]
    failures = case["_failures"]
    author = spec.get("author", 42)
    message_id = spec.get("message", 5001)

    async def add_reaction(emoji):
        """リアクションを付ける。"""
        failures.check(f"react:{emoji}")
        effects.append(["react", emoji])

    async def remove_reaction(emoji, member):
        """Bot 自身のリアクションを外す。"""
        assert member.id == BOT
        failures.check(f"unreact:{emoji}")
        effects.append(["unreact", emoji])

    async def reply(content=None, *, embed=None, mention_author=None):
        """返信する（作者には通知しない）。"""
        assert mention_author is False
        failures.replies += 1
        failures.check(f"reply:{failures.replies}")
        effects.append(["reply", content, embed_json(embed)])
        return SimpleNamespace(channel=SimpleNamespace(id=CHANNEL), id=REPLY_ID)

    return SimpleNamespace(
        guild=SimpleNamespace(id=GUILD),
        channel=SimpleNamespace(id=spec.get("channel", CHANNEL)),
        id=message_id,
        author=SimpleNamespace(id=author, display_name=spec.get("name", f"user{author}")),
        content=spec["content"],
        jump_url=f"https://discord.com/channels/{GUILD}/{spec.get('channel', CHANNEL)}/{message_id}",
        add_reaction=add_reaction,
        remove_reaction=remove_reaction,
        reply=reply,
    )


def install_fakes(case):
    """落とすところ・安全確認・登録への書き足し・時計を、台本で答えるものに差し替える。"""
    effects = case["_effects"]
    downloads = case.get("downloads", {})

    async def fake_download(url, guild_id, tmpdir, cache_ttl):
        """台本どおりに落とす（1 回は待つ。同時の重複配信のときに、もう片方が先へ進めるように）。"""
        assert guild_id == GUILD
        effects.append(["download", url, cache_ttl])
        await asyncio.sleep(0)
        plan = downloads.get(url, {"results": [["T", "tok"]]})
        if plan.get("timeout"):
            await asyncio.sleep(TIMEOUT * 20)
        if "error" in plan:
            raise RuntimeError(plan["error"])
        return [tuple(r) for r in plan["results"]]

    async def fake_validate(url, **kwargs):
        """URL に UNSAFE が入っていれば、安全でない行き先として断る。"""
        if "UNSAFE" in url:
            raise URLSafetyError("private_ip")

    def fake_record(token, channel_id, message_id):
        """登録への書き足し。"""
        effects.append(["record", token, channel_id, message_id])

    djaudio_service._download_and_register = fake_download
    djaudio_service.validate_public_http_url_async = fake_validate
    djaudio_service.update_discord_message = fake_record
    djaudio_service.time = SimpleNamespace(monotonic=lambda: CLOCK[0])
    djaudio_service.DJAUDIO_DL_TIMEOUT = TIMEOUT
    djaudio_service.DJAUDIO_BASE_URL = BASE
    djaudio_service._user_cooldown = TTLCache(ttl=3600, max_entries=5000)
    djaudio_service._processing = set()
    djaudio_service._dl_semaphore = None


async def handle(bot, message, effects):
    """`handle_djaudio_message` を呼ぶ（例外が外へ抜けたら記録する）。"""
    try:
        await djaudio_service.handle_djaudio_message(bot, message)
    except Exception:
        effects.append(["raised"])


async def run(case):
    """例を 1 つ回して、したことの並びを返す。"""
    case["_effects"] = []
    case["_failures"] = Failures(case.get("fail", []))
    write_settings(case.get("settings", {"djaudio": {"watch_channel_id": CHANNEL, "cooldown": 30}}))
    install_fakes(case)
    bot = make_bot(case)
    for spec in case["messages"]:
        CLOCK[0] = spec.get("at", 1000.0)
        message = make_message(case, spec)
        if case.get("duplicate"):
            await asyncio.gather(handle(bot, message, case["_effects"]), handle(bot, message, case["_effects"]))
        else:
            await handle(bot, message, case["_effects"])
    effects = case.pop("_effects")
    case.pop("_failures")
    return effects


WATCH = {"djaudio": {"watch_channel_id": CHANNEL, "cooldown": 30}}
NO_COOLDOWN = {"djaudio": {"watch_channel_id": CHANNEL, "cooldown": 0}}
YT = "https://youtu.be/a"
YT2 = "https://youtu.be/b"
SC = "https://soundcloud.com/x/y"


def cases():
    """例の一覧。"""
    one = [{"content": YT}]
    out = [
        {"id": "ok", "messages": one},
        {"id": "ok-two-files", "messages": one, "downloads": {YT: {"results": [["A", "t1"], ["B" * 60, "t2"]]}}},
        {"id": "not-watched", "settings": {}, "messages": one},
        {"id": "other-channel", "messages": [{"content": YT, "channel": 99}]},
        {"id": "watch-legacy", "settings": {"djaudio_watch_channel": str(CHANNEL)}, "messages": one},
        {"id": "no-url", "messages": [{"content": "hello"}]},
        {"id": "spotify", "messages": [{"content": "https://open.spotify.com/track/1"}]},
        {"id": "apple-then-yt", "messages": [{"content": "https://music.apple.com/a " + YT}]},
        {"id": "unsupported-domain", "messages": [{"content": "https://example.com/a.mp3"}]},
        {"id": "unsafe", "messages": [{"content": "https://youtu.be/UNSAFE"}]},
        {"id": "unsafe-and-unsupported", "messages": [{"content": "https://example.com https://youtu.be/UNSAFE"}]},
        {"id": "spotify-and-unsupported", "messages": [{"content": "https://example.com https://open.spotify.com/x"}]},
        {"id": "two-urls", "messages": [{"content": f"{YT} {YT2}"}]},
        {"id": "dup-urls", "messages": [{"content": f"{YT} {YT} <{YT}>"}]},
        {
            "id": "max-urls",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "max_urls": 1}},
            "messages": [{"content": f"{YT} {YT2}"}],
        },
        {"id": "cooldown", "messages": [{"content": YT, "at": 1000.0}, {"content": YT2, "at": 1010.5}]},
        {"id": "cooldown-passed", "messages": [{"content": YT, "at": 1000.0}, {"content": YT2, "at": 1030.0}]},
        {"id": "cooldown-edge", "messages": [{"content": YT, "at": 1000.0}, {"content": YT2, "at": 1029.999}]},
        {
            "id": "cooldown-other-user",
            "messages": [{"content": YT, "at": 1000.0}, {"content": YT2, "at": 1001.0, "author": 43}],
        },
        {
            "id": "cooldown-zero",
            "settings": NO_COOLDOWN,
            "messages": [{"content": YT, "at": 1000.0}, {"content": YT2, "at": 1000.0}],
        },
        {
            "id": "cooldown-rejected-first",
            "messages": [{"content": "https://example.com", "at": 1000.0}, {"content": YT, "at": 1001.0}],
        },
        {"id": "duplicate", "settings": NO_COOLDOWN, "duplicate": True, "messages": one},
        {"id": "error", "messages": one, "downloads": {YT: {"error": "yt-dlp failed"}}},
        {"id": "timeout", "messages": one, "downloads": {YT: {"timeout": True}}},
        {"id": "one-ok-one-error", "messages": [{"content": f"{YT} {YT2}"}], "downloads": {YT2: {"error": "x"}}},
        {"id": "ttl", "settings": {"djaudio": {"watch_channel_id": CHANNEL, "cache_ttl": 7200}}, "messages": one},
        {"id": "name", "messages": [{"content": YT, "name": "表示 名"}]},
        {
            "id": "output",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "output_channel_id": 88}},
            "channels": {"88": "text"},
            "messages": one,
        },
        {
            "id": "output-missing",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "output_channel_id": 88}},
            "messages": one,
        },
        {
            "id": "output-same",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "output_channel_id": CHANNEL}},
            "channels": {str(CHANNEL): "text"},
            "messages": one,
        },
        {
            "id": "output-category",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "output_channel_id": 88}},
            "channels": {"88": "category"},
            "messages": one,
        },
        {
            "id": "output-category-same",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "output_channel_id": CHANNEL}},
            "channels": {str(CHANNEL): "category"},
            "messages": one,
        },
        {"id": "react-refused", "messages": one, "fail": ["react:⏳"]},
        {"id": "react-broken", "messages": one, "fail": ["react:⏳!"]},
        {"id": "unreact-refused", "messages": one, "fail": ["unreact:⏳"]},
        {"id": "unreact-broken", "messages": one, "fail": ["unreact:⏳!"]},
        {"id": "done-react-refused", "messages": one, "fail": ["react:✅"]},
        {"id": "reply-refused", "messages": one, "fail": ["reply:1"]},
        {"id": "reply-broken", "messages": one, "fail": ["reply:1!"]},
        {"id": "reply-refused-then-notice-refused", "messages": one, "fail": ["reply:1", "reply:2"]},
        {"id": "reply-refused-then-notice-broken", "messages": one, "fail": ["reply:1", "reply:2!"]},
        {"id": "error-notice-refused", "messages": one, "downloads": {YT: {"error": "x"}}, "fail": ["reply:1"]},
        {"id": "error-unreact-broken", "messages": one, "downloads": {YT: {"error": "x"}}, "fail": ["unreact:⏳!"]},
        {"id": "error-fail-mark-refused", "messages": one, "downloads": {YT: {"error": "x"}}, "fail": ["react:❌"]},
        {"id": "timeout-notice-refused", "messages": one, "downloads": {YT: {"timeout": True}}, "fail": ["reply:1"]},
        {"id": "rejection-reply-refused", "messages": [{"content": "https://example.com"}], "fail": ["reply:1"]},
        {"id": "rejection-reply-broken", "messages": [{"content": "https://example.com"}], "fail": ["reply:1!"]},
        {
            "id": "cooldown-reply-broken",
            "messages": [{"content": YT, "at": 1000.0}, {"content": YT2, "at": 1001.0}],
            "fail": ["reply:2!"],
        },
        {
            "id": "send-refused",
            "settings": {"djaudio": {"watch_channel_id": CHANNEL, "output_channel_id": 88}},
            "channels": {"88": "text"},
            "messages": one,
            "fail": ["send"],
        },
        {"id": "soundcloud", "messages": [{"content": SC}]},
        {"id": "angle", "messages": [{"content": f"<{YT}>"}]},
    ]
    return out


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in cases():
        effects = await run(case)
        print(json.dumps([case, effects], ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
