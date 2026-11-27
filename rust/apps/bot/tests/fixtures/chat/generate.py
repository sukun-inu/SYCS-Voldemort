"""AI の会話（応答チャンネルでの受け答え）の基準（expected.jsonl）を、本物の Python から作る。

3 つのことを書き出す（1 行に 1 例。`[種類, 例の名前, 結果]`）。最後の 1 行は、Groq に渡す最初の文（役どころの決まりと
現在の日時）。どの依頼でも同じなので、依頼の中では `<system>` と書く:

- talk: 本物の `ChatGPT.input_message` を、このスクリプトの中に立てた偽物の Groq につないで呼ぶ。届いた依頼の数と
  最後の依頼の中身、返事、履歴を書き出す（Groq の SDK の再試行・誤りの文の作り方まで本物を通る）。
- split: 本物の `send_large_message` が、長い文をどこで切って送るか。
- flow: 本物の `handle_chatgpt_message` を、記録するだけの偽物の message で呼ぶ。入力中の表示・送った文・
  ログ（`log_action` に渡したもの）を、起きた順に書き出す。

時刻は止める（システムの文に入る現在の日時と、古い会話を忘れる判定）。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate.py cases.json > expected.jsonl

もう 1 つ、Python の `repr()` が「印字できない」として書き換える文字の表を作る（Groq の誤りの文に、応答の中身の
`repr()` が入るため。`src/python_nonprintable.tsv`）:

    python generate.py nonprintable > python_nonprintable.tsv
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

FIXED_NOW = (2026, 11, 27, 21, 5, 9)
BOT_ID = 1
GUILD = 1
# これより長い文は、同じ文字の並びを数にまとめて書く（基準のファイルを小さく保つ）。
COMPACT_OVER = 200


def nonprintable_ranges():
    """Python が印字できないとみなす文字（`str.isprintable()` が偽）の範囲を、始めと終わりの組で返す。"""
    ranges = []
    start = None
    for code in range(0x110000):
        # サロゲートは Rust の文字列に入らないので、表に入れない。
        hidden = not (0xD800 <= code <= 0xDFFF) and not chr(code).isprintable()
        if hidden and start is None:
            start = code
        if not hidden and start is not None:
            ranges.append((start, code - 1))
            start = None
    if start is not None:
        ranges.append((start, 0x10FFFF))
    return ranges


def print_nonprintable():
    """印字できない文字の範囲を、1 行に 1 つ（16 進の始めと終わりをタブで区切って）書き出す。"""
    for start, end in nonprintable_ranges():
        print(f"{start:X}\t{end:X}")


if len(sys.argv) > 1 and sys.argv[1] == "nonprintable":
    print_nonprintable()
    sys.exit(0)


class FakeGroq(BaseHTTPRequestHandler):
    """台本どおりに答える偽物の Groq。届いた依頼を覚える。"""

    script: list = []
    seen: list = []

    def do_POST(self):
        """依頼を 1 つ受けて、台本の次の応答を返す（台本が尽きたら、最後の応答をくり返す）。"""
        length = int(self.headers.get("Content-Length", "0"))
        FakeGroq.seen.append(json.loads(self.rfile.read(length)))
        reply = FakeGroq.script.pop(0) if len(FakeGroq.script) > 1 else FakeGroq.script[0]
        status = reply.get("status", 200)
        body, content_type = reply_body(reply)
        self.send_response(status)
        if status >= 400:
            # 再試行の待ちを短くする（SDK は retry-after-ms、その外側の再試行は retry-after を読む）。
            self.send_header("retry-after-ms", "1")
            self.send_header("retry-after", "0")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """届いた依頼を標準エラーに書かない。"""


def text_of(parts):
    """`[["あ", 3], ["\\n", 1]]` のような作り方から、文を作る。"""
    return "".join(piece * count for piece, count in parts)


def reply_body(reply):
    """台本の応答 1 つから、送る中身と種類を作る。"""
    if "text" in reply:
        return reply["text"].encode("utf-8"), "text/plain; charset=utf-8"
    if "json" in reply:
        return json.dumps(reply["json"], ensure_ascii=False).encode("utf-8"), "application/json"
    content = text_of(reply["content_parts"]) if "content_parts" in reply else reply["content"]
    message = {"role": "assistant", "content": content}
    answer = {"id": "x", "object": "chat.completion", "created": 0, "model": "m"}
    answer["choices"] = [{"index": 0, "message": message, "finish_reason": "stop"}]
    return json.dumps(answer, ensure_ascii=False).encode("utf-8"), "application/json"


server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGroq)
threading.Thread(target=server.serve_forever, daemon=True).start()

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["GROQ_API_KEY"] = "test-key"
os.environ["GROQ_BASE_URL"] = f"http://127.0.0.1:{server.server_address[1]}"
os.environ["GROQ_MIN_REQUEST_INTERVAL_SECONDS"] = "0"
os.environ["GROQ_RETRY_BASE_DELAY_SECONDS"] = "0.5"
sys.path.insert(0, "/app")
import discord  # noqa: E402

from commands import chat_commands  # noqa: E402
from services import chatgpt_service, settings_store  # noqa: E402
from services.discord_utils import send_large_message  # noqa: E402


class FixedDatetime(datetime):
    """いつ聞いても同じ時刻を答える `datetime`。"""

    @classmethod
    def now(cls, tz=None):
        """止めた時刻を、聞かれた時間帯で返す。"""
        return cls(*FIXED_NOW, tzinfo=tz)


def run_length(text):
    """同じ文字の並びを `[文字, 数]` にまとめる。"""
    runs = []
    for ch in text:
        if runs and runs[-1][0] == ch:
            runs[-1][1] += 1
        else:
            runs.append([ch, 1])
    return runs


def compact(text):
    """長い文は、同じ文字の並びを数にまとめた形で書く。"""
    if text is not None and len(text) > COMPACT_OVER:
        return {"runs": run_length(text)}
    return text


SYSTEM_TEXT = []


def compact_message(message):
    """依頼の中の 1 件を、比べる形にする。最初の文（毎回同じ）は `<system>` と書く。"""
    role, content = message["role"], message["content"]
    if role == "system":
        if not SYSTEM_TEXT:
            SYSTEM_TEXT.append(content)
        if content == SYSTEM_TEXT[0]:
            return [role, "<system>"]
    return [role, compact(content)]


def compact_request(body):
    """届いた依頼を、比べる形にする（長い発言はまとめる）。"""
    if body is None:
        return None
    messages = [compact_message(m) for m in body["messages"]]
    rest = {key: value for key, value in body.items() if key != "messages"}
    return {"messages": messages, "rest": rest}


async def talk(case):
    """会話を 1 つ回して、発言ごとの依頼・返事・履歴を返す。"""
    chat = chatgpt_service.ChatGPT()
    turns = []
    key = "" if case.get("no_key") else "test-key"
    with patch.object(chatgpt_service, "GROQ_API_KEY", key):
        for turn in case["turns"]:
            FakeGroq.script = list(turn["replies"])
            FakeGroq.seen = []
            final = await chat.input_message(turn["text"])
            last = FakeGroq.seen[-1] if FakeGroq.seen else None
            history = [[m["role"], compact(m["content"])] for m in chat.history]
            sent = len(FakeGroq.seen)
            turns.append({"requests": sent, "last": compact_request(last), "final": final, "history": history})
    return turns


async def split(case):
    """長い文を本物の `send_large_message` に渡して、送られた文を順に返す。"""
    channel = SimpleNamespace(send=AsyncMock())
    await send_large_message(channel, text_of(case["parts"]))
    return [run_length(call.args[0]) for call in channel.send.call_args_list]


def write_settings(guild_settings):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    guilds = {str(GUILD): guild_settings, "2": guild_settings}
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": guilds}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def message_for(spec, bot_user, events):
    """例の 1 通から、記録するだけの偽物の message を作る。"""
    author = bot_user if spec.get("self") else SimpleNamespace(id=spec["user"], bot=False)
    typing = AsyncMock(side_effect=lambda channel_id: events.append(["typing", channel_id]))
    if spec.get("typing_fails"):
        failure = discord.HTTPException(SimpleNamespace(status=429, reason="Too Many Requests"), "rate limited")
        typing = AsyncMock(side_effect=failure)
    channel = SimpleNamespace(id=spec["channel"], mention=f"<#{spec['channel']}>")
    channel.send = AsyncMock(side_effect=lambda text: events.append(["send", compact(text)]))
    channel._state = SimpleNamespace(http=SimpleNamespace(send_typing=typing))
    guild = None if spec.get("dm") else SimpleNamespace(id=spec.get("guild", GUILD))
    content = text_of(spec["content_parts"]) if "content_parts" in spec else spec["content"]
    return SimpleNamespace(author=author, guild=guild, channel=channel, content=content)


async def one_message(spec, bot, clock):
    """1 通を本物の `handle_chatgpt_message` に渡して、起きたことを順に返す。"""
    events = []

    async def record_log(_bot, guild_id, level, title, *, user=None, fields=None):
        """ログに渡されたものを覚える。"""
        shown = [[name, compact(value)] for name, value in (fields or {}).items()]
        events.append(["log", guild_id, level, title, getattr(user, "id", None), shown])

    clock["now"] = spec.get("at", clock["now"])
    FakeGroq.script = list(spec["replies"])
    FakeGroq.seen = []
    with patch.object(chat_commands, "log_action", record_log):
        await chat_commands.handle_chatgpt_message(bot, message_for(spec, bot.user, events))
    asked = len(FakeGroq.seen[-1]["messages"]) if FakeGroq.seen else None
    return {"events": events, "asked_with": asked}


async def flow(case):
    """応答チャンネルへの投稿を順に流して、1 通ごとに起きたことを返す。"""
    write_settings(case["settings"])
    chat_commands.user_chatgpt.clear()
    chat_commands._user_last_used.clear()
    chat_commands._cleanup_counter = 0
    bot = SimpleNamespace(user=SimpleNamespace(id=BOT_ID, bot=True))
    clock = {"now": 0.0}
    results = []
    with patch.object(chat_commands, "time", SimpleNamespace(time=lambda: clock["now"])):
        for spec in case["messages"]:
            times = spec.get("repeat", 1)
            result = None
            for _ in range(times):
                result = await one_message(spec, bot, clock)
            # くり返した投稿は、最後の 1 回だけを書く。
            results.append({"times": times, "last": result})
    return results


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    runners = {"talk": talk, "split": split, "flow": flow}
    with patch.object(chatgpt_service, "datetime", FixedDatetime):
        for kind, run in runners.items():
            for case in cases[kind]:
                line = [kind, case["id"], await run(case)]
                print(json.dumps(line, ensure_ascii=False, separators=(",", ":")))
    print(json.dumps(["system", "text", SYSTEM_TEXT[0]], ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
