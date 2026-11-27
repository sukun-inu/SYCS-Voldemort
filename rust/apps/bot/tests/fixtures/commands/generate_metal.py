"""貴金属のコマンド（/metal gold・silver・platinum・all）の基準（metal_expected.jsonl）を、本物の Python から作る。

本物のコマンドの中身（commands/metal_commands.py）を、記録するだけの偽物の interaction で呼ぶ。値段の API は、この
スクリプトの中に立てた偽物（例ごとに決めた応答を返す）に向ける。本物の metal_service が本物の aiohttp でそこへ
取りに行く。書き出すのは、外への働きかけの順番と中身（考え中・最初の応答・あとからの送信・ログチャンネルへの
記録）、API が受けた要求、コマンドが失敗で終わったか。

- Discord への送信とログの記録は、例が決めたとおりに失敗させられる（本物の discord.py の例外を投げる）
- コマンドの中で例外が出たら、本物の受け皿（commands/interaction_utils.py の _on_tree_error）に渡す
- Embed に書く時刻は固定する（services/discord_utils.py が見る時計を差し替える）

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_metal.py metal_cases.json > metal_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

os.environ["SETTINGS_DIR"] = tempfile.mkdtemp()
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["METALS_SITE_URL"] = "https://metals.example"
sys.path.insert(0, "/app")
import discord  # noqa: E402
from aiohttp import web  # noqa: E402
from discord import app_commands  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

import commands.metal_commands as metal_commands  # noqa: E402
import services.discord_utils as discord_utils  # noqa: E402
import services.metal_service as metal_service  # noqa: E402
from commands import register_all_commands  # noqa: E402
from commands.interaction_utils import install_global_app_command_error_handler  # noqa: E402

GUILD = 1399617700363370556
CHANNEL = 1505310388051251000
API_KEY = "test-key"
spec = json.load(open(sys.argv[1], encoding="utf-8"))
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)
install_global_app_command_error_handler(bot)


class FrozenDatetime(datetime):
    """いつ聞いても同じ時刻を返す時計（Embed の下に書く時刻を固定する）。"""

    @classmethod
    def now(cls, tz=None):
        """固定の時刻（2026-11-27 12:34:56）を、聞かれた時間帯で返す。"""
        return datetime(2026, 11, 27, 12, 34, 56, tzinfo=tz)


discord_utils.datetime = FrozenDatetime


class FakeApi:
    """偽物の値段の API。例ごとに決めた応答を返し、受けた要求を記録する。"""

    def __init__(self):
        """応答の表と、受けた要求の記録を空で始める。"""
        self.canned = {}
        self.hits = []

    async def handle(self, request):
        """要求を 1 つ受ける。金属ごとに決めた応答（無ければ既定の値段）を返す。"""
        self.hits.append(request.path_qs)
        code = request.query.get("currencies", "")
        canned = self.canned.get(code)
        if canned is None:
            canned = {"json": {"success": True, "base": "JPY", "rates": {f"JPY{code}": spec["default_rates"][code]}}}
        if "json" in canned:
            body = json.dumps(canned["json"], ensure_ascii=False).encode()
        else:
            body = canned.get("body", "").encode()
        headers = {}
        content_type = canned.get("type", "application/json")
        if content_type:
            headers["Content-Type"] = content_type
        return web.Response(status=canned.get("status", 200), body=body, headers=headers)

    async def start(self):
        """127.0.0.1 の空いているポートで待ち受け、その場所（URL）を返す。"""
        app = web.Application()
        app.router.add_get("/v1/latest", self.handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/v1/latest"


def embed_json(embed):
    """Embed から、比べる項目（題・本文・色・下の文・項目）だけを取り出す。"""
    d = embed.to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "color": d.get("color"),
        "footer": d.get("footer", {}).get("text"),
        "fields": fields,
    }


def components_json(view):
    """部品を、比べる項目だけにする（行ごと）。"""
    if view is None:
        return []
    rows = []
    for row in view.to_components():
        rows.append([{key: c.get(key) for key in ("type", "style", "label", "url")} for c in row["components"]])
    return rows


def reply_json(args, kwargs):
    """send_message・followup.send に渡されたものを、比べる形にする。"""
    content = args[0] if args else kwargs.get("content")
    embeds = [kwargs["embed"]] if kwargs.get("embed") is not None else []
    return {
        "content": content,
        "ephemeral": bool(kwargs.get("ephemeral")),
        "embeds": [embed_json(e) for e in embeds],
        "components": components_json(kwargs.get("view")),
    }


def http_error(parts):
    """例が決めた失敗（状態・理由・番号・文）から、本物の discord.py の例外を作る。"""
    status, reason, code, message = parts
    response = SimpleNamespace(status=status, reason=reason)
    return discord.HTTPException(response, {"code": code, "message": message})


class Recorder:
    """記録するだけの interaction と、ログの記録の差し替え。外への働きかけを順に覚える。"""

    def __init__(self, fail):
        """失敗させるところ（例が決めたもの）を受け取り、記録を空で始める。"""
        self.fail = fail
        self.events = []
        self.done = False
        self.followups = 0

    async def defer(self):
        """「考え中」を返す。成功したら、応答済みになる。"""
        failure = self.fail.get("defer")
        self.events.append(["defer", failure is None])
        if failure is not None:
            raise http_error(failure)
        self.done = True

    async def send_message(self, *args, **kwargs):
        """最初の応答として送る。成功したら、応答済みになる。"""
        failure = self.fail.get("respond")
        self.events.append(["respond", reply_json(args, kwargs), failure is None])
        if failure is not None:
            raise http_error(failure)
        self.done = True

    async def followup_send(self, *args, **kwargs):
        """応答のあとから送る。何回目を失敗させるかは例が決める。"""
        self.followups += 1
        failure = self.fail.get("followup", {}).get(str(self.followups))
        self.events.append(["followup", reply_json(args, kwargs), failure is None])
        if failure is not None:
            raise http_error(failure)

    async def log_action(self, _bot, _guild_id, level, message, *, user=None, fields=None, embed_color=None):
        """ログチャンネルへの記録（log_action）の代わり。レベルごとに失敗させられる。"""
        failure = self.fail.get("log", {}).get(level)
        pairs = [[name, value] for name, value in (fields or {}).items()]
        self.events.append(["log", level, message, pairs, failure is None])
        if failure is not None:
            raise http_error(failure)

    def interaction(self, who):
        """打った場所（guild・dm）ごとの、記録するだけの interaction。"""
        interaction = MagicMock()
        interaction.guild = None if who == "dm" else SimpleNamespace(id=GUILD)
        interaction.channel = SimpleNamespace(mention=f"<#{CHANNEL}>")
        interaction.response.is_done = lambda: self.done
        interaction.response.defer = self.defer
        interaction.response.send_message = self.send_message
        interaction.followup.send = self.followup_send
        return interaction


def command_for(kind):
    """`gold` のような名前から、/metal のコマンドを引く。"""
    return bot.tree.get_command("metal").get_command(kind)


async def run_command(command, who):
    """コマンドを 1 つ回して、外への働きかけと、失敗で終わったか（その文）を返す。"""
    recorder = Recorder(command.get("fail", {}))
    metal_commands.log_action = recorder.log_action
    interaction = recorder.interaction(who)
    node = command_for(command["kind"])
    error = None
    try:
        # discord.py は、数の引数を必ず小数にして渡す（app_commands/namespace.py の `float(value)`）。
        await node.callback(interaction, g=float(command["g"]))
    except Exception as e:
        error = str(e)
        # コマンドの中の失敗は、本物の受け皿が断りの文を返す。
        try:
            await bot.tree.on_error(interaction, app_commands.CommandInvokeError(node, e))
        except discord.HTTPException:
            pass
    return {"events": recorder.events, "error": error}


async def run(api, base_url, case):
    """例を 1 つ回す（続けて打つコマンドがあれば、覚えた値段を共有したまま回す）。"""
    api.canned = case.get("api", {})
    api.hits = []
    metal_service._price_cache.clear()
    metal_service.METALPRICE_BASE_URL = base_url
    metal_service.METALPRICE_API_KEY = None if case.get("no_key") else API_KEY
    who = case.get("who", "guild")
    outcomes = [await run_command(command, who) for command in [case, *case.get("then", [])]]
    if case.get("loose_error"):
        # JSON として読めない応答の文は、Python の json の文なので Rust と揃えられない。あることだけ比べる。
        for outcome in outcomes:
            for event in outcome["events"]:
                if event[0] == "log" and event[1] == "ERROR":
                    event[3] = [[name, "<読めない JSON の文>"] for name, _ in event[3]]
    return [case["id"], outcomes, api.hits]


async def main():
    """偽物の API を立て、全部の例を回して、1 行に 1 例ずつ書き出す。"""
    api = FakeApi()
    base_url = await api.start()
    for case in spec["cases"]:
        print(json.dumps(await run(api, base_url, case), ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
