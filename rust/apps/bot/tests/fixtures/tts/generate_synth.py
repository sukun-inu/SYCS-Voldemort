"""合成の API の呼び方の基準（synth_expected.jsonl）を、本物の Python（`tts_service._synthesize`）から作る。

このスクリプトの中に偽物の合成の API を立て、例ごとに決めた応答を返す。書き出すのは、API が受けた要求（場所・
本文の JSON）と、`_synthesize` が返した音声の場所（失敗なら null）。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_synth.py synth_cases.json > synth_expected.jsonl
"""

import asyncio
import json
import os
import sys

from aiohttp import web

os.environ["TTS_BASE_URL"] = "http://127.0.0.1:18090/"
sys.path.insert(0, "/app")
from services import tts_service  # noqa: E402


class FakeTts:
    """台本どおりに答える偽物の合成の API。受けた要求を覚える。"""

    def __init__(self):
        """台本と記録を空で始める。"""
        self.reply = {}
        self.seen = []

    async def handle(self, request):
        """合成の依頼を 1 つ受けて、台本の応答を返す。"""
        self.seen.append({"path": request.path_qs, "body": await request.json()})
        reply = self.reply
        if "json" in reply:
            body = json.dumps(reply["json"], ensure_ascii=False).encode()
        else:
            body = reply.get("body", "").encode()
        headers = {"Content-Type": reply.get("type", "application/json")}
        return web.Response(status=reply.get("status", 200), body=body, headers=headers)

    async def start(self):
        """決まった場所で待ち受ける。"""
        app = web.Application()
        app.router.add_post("/api/v1/synthesize", self.handle)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", 18090).start()


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    fake = FakeTts()
    await fake.start()
    for case in cases:
        fake.reply = case["reply"]
        fake.seen = []
        url, _ = await tts_service._synthesize(case["text"], case["voice"], case["rate"])
        line = [case["id"], fake.seen, url]
        print(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
