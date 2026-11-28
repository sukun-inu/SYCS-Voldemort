"""読み上げる文の作り方の基準（text_expected.json）を、本物の Python から作る。

本物の `services/tts_service.py` の関数を呼ぶ:

- clean: `_clean_text`（URL・メンション・絵文字の置き換え、前後の空白、長さの切り方）
- dictionary: `_apply_dictionary`（辞書の当て方）
- speak: `enqueue_message`（メッセージを読み上げるときの文・声・速度。合成の API は呼ばずに、渡されたものを覚える）
- vc_event: `enqueue_vc_event`（VC の入退室を読み上げるときの文・声・速度）

設定の置き場は本物（settings_store のファイル版）を一時ディレクトリで使う。本番と同じ依存（requirements.txt）で、
リポジトリの直下を /app に置いて動かす:

    python generate_text.py text_cases.json > text_expected.json
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
from services import settings_store, tts_service  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912


class Member:
    """読み上げる人（表示名と、`str(member)` の名前）。"""

    def __init__(self, display_name):
        """表示名を受け取る。`str()` は利用者名（nelly）。"""
        self.id = USER
        self.display_name = display_name

    def __str__(self):
        """discord.py の `str(member)`（利用者名）。"""
        return "nelly"


def write_settings(tts):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): {"tts": tts}}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


async def captured(run):
    """合成の API の代わりに、渡された文・声・速度を覚える。呼ばれなければ None。"""
    seen = []

    async def fake_synthesize(text, voice, rate):
        """渡されたものを覚えて、失敗として返す（キューには積まない）。"""
        seen.append([text, voice, rate])
        return None, 0

    with patch.object(tts_service, "_synthesize", fake_synthesize):
        await run()
    return seen[0] if seen else None


async def speak(case):
    """メッセージを読み上げるときの文・声・速度。"""
    tts = dict(case["settings"])
    tts["user_settings"] = {str(USER): case["user"]}
    write_settings(tts)
    guild = SimpleNamespace(id=GUILD)
    return await captured(lambda: tts_service.enqueue_message(None, guild, Member(case["name"]), case["text"]))


async def vc_event(case):
    """VC の入退室を読み上げるときの文・声・速度。"""
    write_settings(case["settings"])
    guild = SimpleNamespace(id=GUILD)
    return await captured(lambda: tts_service.enqueue_vc_event(None, guild, Member(case["name"]), case["event"]))


async def main():
    """全部の例を回して、種類ごとに結果を並べて書き出す。"""
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    out = {
        "clean": [tts_service._clean_text(c["text"], c["max"]) for c in cases["clean"]],
        "dictionary": [tts_service._apply_dictionary(c["text"], c["dict"]) for c in cases["dictionary"]],
        "speak": [await speak(c) for c in cases["speak"]],
        "vc_event": [await vc_event(c) for c in cases["vc_event"]],
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))


asyncio.run(main())
