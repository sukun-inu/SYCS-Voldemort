"""読み上げの設定のコマンド（/tts・/voice・/dict）と声の補完の基準（commands_expected.jsonl）を、
本物の Python から作る。

- commands: 本物のコマンドの中身（commands/tts_commands.py）を、記録するだけの偽物の interaction で呼び、返事
  （本文・Embed・本人にだけ見せるか）と、書き換えたあとのそのサーバーの設定を書き出す。中で例外が出たら
  ``{"error": true}``（本物の Bot では、受け皿が「処理できなかった」と返す）
- voices: 本物の声の補完（`_voice_autocomplete`）を、このスクリプトの中に立てた偽物の合成の API につないで呼び、
  候補（名前と値）を書き出す

設定の置き場は本物（settings_store のファイル版）を一時ディレクトリで使う。本番と同じ依存（requirements.txt）で、
リポジトリの直下を /app に置いて動かす:

    python generate_commands.py commands_cases.json > commands_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from aiohttp import web

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["TTS_BASE_URL"] = "http://127.0.0.1:18089"
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands, tts_commands  # noqa: E402
from services import settings_store  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)


def expand(before):
    """例の中の印（長い辞書）を、決まった中身に広げる（Rust のテストも同じ広げ方をする）。"""
    tts = before.get("tts")
    if isinstance(tts, dict) and tts.get("dictionary") == "LONG":
        tts = dict(tts)
        tts["dictionary"] = {f"語{i:03d}" + "あ" * 40: "読み" * 40 for i in range(120)}
        before = dict(before)
        before["tts"] = tts
    return before


def many_voices(response):
    """例の中の印（たくさんの声）を、決まった中身に広げる。"""
    if response.get("json") == "MANY":
        response = dict(response)
        response["json"] = [{"name": f"voice{i:02d}"} for i in range(40)]
    return response


def write_settings(guild_settings):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): guild_settings}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def command_for(path):
    """`tts enable` のような道すじから、コマンドを引く。"""
    node = bot.tree.get_command(path.split()[0])
    for name in path.split()[1:]:
        node = node.get_command(name)
    return node


def guild_for(who, channels):
    """打たれたサーバー。チャンネルは、例が決めたものだけ引ける。"""
    if who == "dm":
        return None
    known = {cid: SimpleNamespace(id=cid, mention=f"<#{cid}>") for cid in channels}
    return SimpleNamespace(id=GUILD, get_member=lambda uid: None, get_channel=known.get)


def interaction_for(who, channels):
    """打った人の立場（admin・member・dm）ごとの、記録するだけの interaction。"""
    interaction = MagicMock()
    interaction.guild = guild_for(who, channels)
    member = MagicMock(spec=discord.Member)
    member.id = USER
    member.guild_permissions = SimpleNamespace(administrator=(who == "admin"))
    interaction.user = member
    interaction.response.is_done = MagicMock(return_value=False)
    interaction.response.send_message = AsyncMock()
    return interaction


def option_value(name, value):
    """引数を、Python のコマンドが受け取る形にする（チャンネルは ID とメンションを持つもの）。"""
    if name == "channel":
        return SimpleNamespace(id=value, mention=f"<#{value}>")
    return value


def embed_json(embed):
    """Embed から、比べる項目（題・本文・色・項目）だけを取り出す。"""
    d = embed.to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    return {"title": d.get("title"), "description": d.get("description"), "color": d.get("color"), "fields": fields}


def sent_reply(interaction):
    """最初の応答（send_message）に渡されたものを、比べる形にする。"""
    call = interaction.response.send_message.call_args
    content = call.args[0] if call.args else call.kwargs.get("content")
    embeds = [call.kwargs["embed"]] if call.kwargs.get("embed") is not None else []
    return {
        "content": content,
        "ephemeral": bool(call.kwargs.get("ephemeral")),
        "embeds": [embed_json(e) for e in embeds],
    }


async def run_command(case):
    """コマンドを 1 つ回して、返事と、書き換えたあとの設定を返す。"""
    write_settings(expand(case["before"]))
    interaction = interaction_for(case["who"], case.get("channels", []))
    kwargs = {name: option_value(name, value) for name, value in case.get("options", {}).items()}
    try:
        await command_for(case["path"]).callback(interaction, **kwargs)
        reply = sent_reply(interaction)
    except Exception:
        reply = {"error": True}
    after = settings_store.get_guild_settings(GUILD)
    # 書き換えの時刻は比べない（Rust では保存のときに押す）。
    after.pop("_updated_at", None)
    return ["commands", case["id"], reply, after]


class FakeTts:
    """台本どおりに答える偽物の合成の API（声の一覧）。"""

    def __init__(self):
        """答える中身を空で始める。"""
        self.response = {}

    async def handle(self, request):
        """声の一覧の問い合わせに、台本の応答を返す。"""
        reply = self.response
        if "json" in reply:
            body = json.dumps(reply["json"], ensure_ascii=False).encode()
        else:
            body = reply.get("body", "").encode()
        headers = {"Content-Type": reply.get("type", "application/json")}
        return web.Response(status=reply.get("status", 200), body=body, headers=headers)

    async def start(self):
        """決まった場所（TTS_BASE_URL）で待ち受ける。"""
        app = web.Application()
        app.router.add_get("/api/v1/voices", self.handle)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", 18089).start()


async def run_voices(fake, case):
    """声の補完を 1 つ回して、候補（名前と値）を返す。"""
    fake.response = many_voices(case["response"])
    interaction = interaction_for("member", [])
    choices = await tts_commands._voice_autocomplete(interaction, case["current"])
    return ["voices", case["id"], [[c.name, c.value] for c in choices]]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    fake = FakeTts()
    await fake.start()
    lines = [await run_command(c) for c in cases["commands"]]
    lines += [await run_voices(fake, c) for c in cases["voices"]]
    for line in lines:
        print(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
