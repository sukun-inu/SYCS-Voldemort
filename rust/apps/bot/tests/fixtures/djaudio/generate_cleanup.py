"""DJAudio の期限切れの掃除（`djaudio_cache._cleanup_expired`）の基準（cleanup_expected.jsonl）を、本物の Python から
作る。

置き場に例のファイルを置き（期限の時刻と一時ファイルの古さは、いまの時刻からの秒数で書く）、記録するだけの偽物の
Bot（チャンネルを引く・メッセージを取りに行く・消す）を渡して、本物の掃除を 1 回回す。

1 行に 1 例。``[例, Discord にしたこと, 残ったファイル]``。したことは ``["fetch", チャンネル, メッセージ]`` と
``["delete", チャンネル, メッセージ]``（並べ替えたもの。Python は置き場を読んだ順に回るので、順は決まらない）。

台本（例の鍵）:

- ``files``: 名前 → 中身。中身が辞書なら情報の JSON（``expires_in`` を、いまの時刻 + その秒数の ``expires_at`` に
  する）、文字ならそのまま書く
- ``tmp``: 一時ファイルの名前 → いまから何秒前に書かれたか
- ``channels``: Bot から見えるチャンネル（ID → ``text``〔取りに行ける〕・``category``〔取りに行けない〕）
- メッセージの ID が 4040 なら取りに行くと断られ（404）、4030 なら消すと断られる（403）

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_cleanup.py > cleanup_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

CACHE_DIR = Path(tempfile.mkdtemp())
os.environ["DJAUDIO_CACHE_DIR"] = str(CACHE_DIR)
sys.path.insert(0, "/app")
import discord  # noqa: E402

from services import djaudio_cache  # noqa: E402

T1 = "a" * 32
T2 = "b" * 32
T3 = "c" * 32


def make_bot(case, effects):
    """記録するだけの偽物の Bot。"""
    channels = {}
    for key, kind in case.get("channels", {}).items():
        channel_id = int(key)
        if kind != "text":
            channels[channel_id] = SimpleNamespace(id=channel_id)
            continue

        async def fetch_message(message_id, _cid=channel_id):
            """メッセージを取りに行く（4040 は無い）。"""
            effects.append(["fetch", _cid, message_id])
            if message_id == 4040:
                raise discord.NotFound(MagicMock(status=404, reason="Not Found"), "Unknown Message")

            async def delete():
                """消す（4030 は断られる）。"""
                effects.append(["delete", _cid, message_id])
                if message_id == 4030:
                    raise discord.Forbidden(MagicMock(status=403, reason="Forbidden"), "Missing Permissions")

            return SimpleNamespace(id=message_id, delete=delete)

        channels[channel_id] = SimpleNamespace(id=channel_id, fetch_message=fetch_message)
    return SimpleNamespace(get_channel=channels.get)


def place_files(case):
    """置き場に例のファイルを置く。"""
    for path in CACHE_DIR.iterdir():
        path.unlink()
    now = datetime.now(timezone.utc).timestamp()
    for name, content in case.get("files", {}).items():
        if isinstance(content, dict):
            meta = dict(content)
            if "expires_in" in meta:
                meta["expires_at"] = now + meta.pop("expires_in")
            text = json.dumps(meta, ensure_ascii=False)
        else:
            text = content
        (CACHE_DIR / name).write_text(text, encoding="utf-8")
    for name, age in case.get("tmp", {}).items():
        path = CACHE_DIR / name
        path.write_text("{}", encoding="utf-8")
        stamp = time.time() - age
        os.utime(path, (stamp, stamp))


def cases():
    """例の一覧。"""
    text = {"123": "text", "124": "text", "200": "category"}
    old = {"token": T1, "expires_in": -10}
    return [
        {"id": "nothing", "files": {}},
        {"id": "fresh", "files": {f"{T1}.mp3": "x", f"{T1}.json": {"token": T1, "expires_in": 600}}},
        {"id": "expired", "files": {f"{T1}.mp3": "x", f"{T1}.json": old}},
        {
            "id": "expired-all-ext",
            "files": {
                f"{T1}.mp3": "x",
                f"{T1}.zip": "z",
                f"{T1}.wav": "w",
                f"{T1}.ogg": "o",
                f"{T1}.json": old,
                f"{T1}.txt": "t",
            },
        },
        {
            "id": "with-message",
            "channels": text,
            "files": {
                f"{T1}.mp3": "x",
                f"{T1}.json": {**old, "discord_channel_id": "123", "discord_message_id": "555"},
            },
        },
        {
            "id": "channel-unknown",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "999", "discord_message_id": "555"}},
        },
        {
            "id": "channel-not-number",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "abc", "discord_message_id": "555"}},
        },
        {
            "id": "message-not-number",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "123", "discord_message_id": "x5"}},
        },
        {
            "id": "message-not-number-unknown-channel",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "999", "discord_message_id": "x5"}},
        },
        {
            "id": "fullwidth-ids",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "１２３", "discord_message_id": " 556 "}},
        },
        {
            "id": "int-ids",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": 124, "discord_message_id": 557}},
        },
        {
            "id": "empty-channel-id",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "", "discord_message_id": "555"}},
        },
        {
            "id": "zero-message-id",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "123", "discord_message_id": 0}},
        },
        {"id": "only-channel", "channels": text, "files": {f"{T1}.json": {**old, "discord_channel_id": "123"}}},
        {
            "id": "fetch-404",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "123", "discord_message_id": "4040"}},
        },
        {
            "id": "delete-403",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "123", "discord_message_id": "4030"}},
        },
        {
            "id": "category",
            "channels": text,
            "files": {f"{T1}.json": {**old, "discord_channel_id": "200", "discord_message_id": "555"}},
        },
        {
            "id": "no-token",
            "files": {f"{T1}.json": {"expires_in": -10}, f"{T2}.json": {"token": T2, "expires_in": -10}},
        },
        {"id": "no-expires", "files": {f"{T1}.mp3": "x", f"{T1}.json": {"token": T1}}},
        {"id": "expires-true", "files": {f"{T1}.json": {"token": T1, "expires_at": True}}},
        {"id": "expires-zero", "files": {f"{T1}.json": {"token": T1, "expires_at": 0}}},
        {"id": "broken-json", "files": {f"{T1}.json": "{nope", f"{T2}.json": {"token": T2, "expires_in": -1}}},
        {
            "id": "token-mismatch",
            "files": {f"{T1}.json": {"token": T3, "expires_in": -1}, f"{T3}.mp3": "x", f"{T1}.mp3": "y"},
        },
        {
            "id": "many",
            "channels": text,
            "files": {
                f"{T1}.json": {**old, "discord_channel_id": "123", "discord_message_id": "601"},
                f"{T2}.json": {"token": T2, "expires_in": -5, "discord_channel_id": "124", "discord_message_id": "602"},
                f"{T3}.json": {
                    "token": T3,
                    "expires_in": 100,
                    "discord_channel_id": "123",
                    "discord_message_id": "603",
                },
            },
        },
        {"id": "tmp-files", "tmp": {f"{T1}.json.tmp": 1000, f"{T2}.json.tmp": 10, "x.tmp": 1000}},
        {"id": "info-json-name", "files": {"x.info.json": {"token": "x", "expires_in": -1}, "x.mp3": "x"}},
    ]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in cases():
        place_files(case)
        effects = []
        await djaudio_cache._cleanup_expired(make_bot(case, effects))
        left = sorted(p.name for p in CACHE_DIR.iterdir())
        print(json.dumps([case, sorted(effects), left], ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
