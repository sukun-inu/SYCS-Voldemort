"""VC の出入りに応じた読み上げの決め方の基準（voice_expected.jsonl）を、本物の Python から作る。

本物の `events/voice.py` の `_tts_vc_announce`（Bot を含む全員）と、人間のときだけ続く `_maybe_tts_auto_join`・
`_maybe_tts_auto_leave` を、`_dispatch_voice_state` と同じ順に呼ぶ。読み上げの係の働き（切る・入退室を読む・
先に入る）は記録するだけの偽物に差し替え、頼まれた順に書き出す。

設定の置き場は本物（settings_store のファイル版）を一時ディレクトリで使う。本番と同じ依存（requirements.txt）で、
リポジトリの直下を /app に置いて動かす:

    python generate_voice.py voice_cases.json > voice_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
sys.path.insert(0, "/app")
from events import voice  # noqa: E402
from services import settings_store, tts_service  # noqa: E402

GUILD = 1399617700363370556


def write_settings(tts):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): {"tts": tts}}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def channel(spec, humans):
    """VC（居る人の並び。人間の数だけ人間、ほかに Bot が 1 人）。無ければ None。"""
    if spec is None:
        return None
    members = [SimpleNamespace(bot=False) for _ in range(humans)] + [SimpleNamespace(bot=True)]
    return SimpleNamespace(id=spec, members=members)


async def run(case):
    """例を 1 つ回して、頼まれた働きを順に返す。"""
    write_settings(case["settings"])
    tts_service._temp_overrides.clear()
    if case.get("temp") is not None:
        tts_service._temp_overrides[GUILD] = {"vc_channel_id": case["temp"]}
    calls = []

    async def fake_disconnect(guild_id):
        """切る（記録するだけ）。"""
        calls.append(["disconnect"])

    async def fake_vc_event(bot, guild, member, event):
        """入退室を読む（記録するだけ）。"""
        calls.append(["announce", event])

    async def fake_auto_join(guild, vc_channel_id):
        """先に入る（記録するだけ）。"""
        calls.append(["auto_join", vc_channel_id])

    member = SimpleNamespace(bot=case["bot"], guild=SimpleNamespace(id=GUILD), display_name="a")
    before_ch = channel(case["before"], case.get("humans_before", 0))
    after_ch = channel(case["after"], 1)
    before = SimpleNamespace(channel=before_ch)
    after = SimpleNamespace(channel=after_ch)
    with (
        patch.object(tts_service, "disconnect", fake_disconnect),
        patch.object(tts_service, "enqueue_vc_event", fake_vc_event),
        patch.object(tts_service, "auto_join", fake_auto_join),
    ):
        await voice._tts_vc_announce(None, member, before, after)
        if not case["bot"]:
            is_join = before_ch is None and after_ch is not None
            is_leave = before_ch is not None and after_ch is None
            is_move = before_ch is not None and after_ch is not None and before_ch.id != after_ch.id
            await voice._maybe_tts_auto_join(member, after_ch, is_join)
            await voice._maybe_tts_auto_leave(member, before_ch, is_leave, is_move)
    return [case["id"], calls]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    for case in cases:
        print(json.dumps(await run(case), ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
