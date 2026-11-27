"""サーバーの設定のコマンド（/greeting・/vcnotify・/sticky・/reactionrole・/news）の基準（server_expected.jsonl）を、
本物の Python から作る。

本物のコマンドの中身（commands/server/）を、記録するだけの偽物の interaction で呼び、次のものを書き出す。

- 返事（本文・Embed・部品・「本人にだけ見せるか」）。中で例外が出たら ``{"error": true}``
  （本物の Bot では、その受け皿が「処理できなかった」と返す）
- 返事を送った時点の、そのサーバーの設定
- 返事のあとにチャンネルへしたこと（/sticky の貼る・剥がす。古い固定メッセージを消す・新しく送る）
- すべて終わったあとの設定

補完（/reactionrole remove の message_id・emoji、/news remove の feed_id）は、本物の候補の関数に、本物の
`Namespace`（先に入れた引数の入れ物）を渡して呼び、候補（名前と値）を書き出す。

設定の置き場は本物（settings_store のファイル版）を一時ディレクトリで使う。打たれたチャンネルの種類が
discord.py のどのクラスになるかは、discord.py 自身に決めさせる（`_threaded_channel_factory`）。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_server.py server_cases.json > server_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["ADMIN_SITE_URL"] = "https://admin.example/login"
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord.app_commands.namespace import Namespace  # noqa: E402
from discord.channel import _threaded_channel_factory  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands  # noqa: E402
from commands.server import news as news_commands  # noqa: E402
from commands.server import sticky as sticky_commands  # noqa: E402
from services import settings_store  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
# コマンドが打たれたチャンネルと、Bot が新しく送った固定メッセージの ID。
CHANNEL = 1505310388051251000
NEW_MESSAGE = 900
# /news add が振る ID（本物は乱数。比べられるように決まった値にする）。
FEED_ID = "feedc0de"
cases = json.load(open(sys.argv[1], encoding="utf-8"))
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)
GUILD_OBJECT = SimpleNamespace(id=GUILD)
news_commands.uuid = SimpleNamespace(uuid4=lambda: uuid.UUID(hex=FEED_ID + "0" * 24))
# 返事のあとの仕事（/sticky の貼る・剥がす）のうち、呼ばれたもの。
AFTER_WORK = []


def recording(name, original):
    """返事のあとの仕事を、呼ばれたことを残してから本物へ渡すものに包む。"""

    async def wrapper(channel, guild_id):
        """呼ばれたことを残して、本物（services/sticky_service.py）を呼ぶ。"""
        AFTER_WORK.append(name)
        await original(channel, guild_id)

    return wrapper


sticky_commands.post_sticky = recording("post", sticky_commands.post_sticky)
sticky_commands.delete_sticky = recording("delete", sticky_commands.delete_sticky)


def write_settings(guild_settings):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): guild_settings}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def stored_settings():
    """いまのそのサーバーの設定。書き換えの時刻は比べない（Rust では保存のときに押す）。"""
    settings_store._cache = None
    settings_store._cache_sig = None
    current = settings_store.get_guild_settings(GUILD)
    current.pop("_updated_at", None)
    return current


def expand(value):
    """例の中の ``{"repeat": "1", "times": 4300, "suffix": ""}`` を、その長さの文字列に広げる。"""
    if isinstance(value, dict) and "repeat" in value:
        return value["repeat"] * value["times"] + value.get("suffix", "")
    return value


def command_for(path):
    """`sticky set` のような道すじから、コマンドを引く。"""
    node = bot.tree.get_command(path.split()[0])
    for name in path.split()[1:]:
        node = node.get_command(name)
    return node


def real_role(role_id):
    """本物の discord.Role（メンションの書き方を本物に決めさせる）。"""
    data = {"id": str(role_id), "name": f"r{role_id}", "permissions": "0", "position": 1, "color": 0}
    data.update({"hoist": False, "managed": False, "mentionable": False})
    return discord.Role(guild=GUILD_OBJECT, state=MagicMock(), data=data)


def real_text_channel(channel_id):
    """本物の discord.TextChannel（引数で選ばれたチャンネル。メンションの書き方を本物に決めさせる）。"""
    data = {"id": str(channel_id), "type": 0, "name": f"c{channel_id}", "position": 0}
    return discord.TextChannel(state=MagicMock(), guild=GUILD_OBJECT, data=data)


def named(table):
    """ID → 名前の表（例の ``roles``・``channels``）を、`get_role`・`get_channel` が引ける形にする。"""
    return {int(key): SimpleNamespace(name=name) for key, name in (table or {}).items()}


def guild_for(case):
    """打たれたサーバー。ロールとチャンネルは、例に書いたものだけ引ける（本物と同じく辞書から引く）。"""
    if case["who"] == "dm":
        return None
    roles = named(case.get("roles"))
    channels = named(case.get("channels"))
    return SimpleNamespace(id=GUILD, get_role=roles.get, get_channel=channels.get)


def invoked_channel(case, effects):
    """コマンドが打たれたチャンネル。種類の番号から、discord.py がどのクラスにするかを本物に決めさせる。

    したこと（古い固定メッセージを取りに行く・新しく送る）は `effects` に順に残す。
    """
    factory, _ = _threaded_channel_factory(case.get("channel_type", 0))
    if factory is None:
        return None
    channel = MagicMock(spec=factory)
    channel.id = CHANNEL

    async def fetch_message(message_id):
        """古い固定メッセージを取りに行く。Python はこのあと消す（無ければ、消さずに先へ進む）。"""
        effects.append(["delete_old", str(message_id)])
        if case.get("old_message") == "missing":
            raise discord.NotFound(MagicMock(status=404, reason="Not Found"), "Unknown Message")
        return SimpleNamespace(delete=AsyncMock())

    async def send(content):
        """新しい固定メッセージを送る。"""
        effects.append(["send", content])
        return SimpleNamespace(id=NEW_MESSAGE)

    channel.fetch_message = fetch_message
    channel.send = send
    return channel


def interaction_for(case, effects):
    """打った人の立場（admin・member・dm）ごとの、記録するだけの interaction。"""
    interaction = MagicMock()
    interaction.guild = guild_for(case)
    member = MagicMock(spec=discord.Member)
    member.id = USER
    member.guild_permissions = SimpleNamespace(administrator=(case["who"] == "admin"))
    interaction.user = member
    interaction.channel = invoked_channel(case, effects)
    interaction.response.is_done = MagicMock(return_value=False)
    return interaction


def option_value(name, value):
    """引数を、Python のコマンドが受け取る形にする（チャンネルとロールは本物のオブジェクト）。"""
    if name == "channel":
        return real_text_channel(value)
    if name == "role":
        return real_role(value)
    return expand(value)


def embed_json(embed):
    """Embed から、比べる項目（題・本文・色・項目）だけを取り出す。"""
    d = embed.to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    return {"title": d.get("title"), "description": d.get("description"), "color": d.get("color"), "fields": fields}


def components_json(view):
    """部品を、比べる項目だけにする。"""
    if view is None:
        return []
    rows = []
    for row in view.to_components():
        items = []
        for c in row["components"]:
            item = {key: c.get(key) for key in ("type", "style", "label", "url")}
            item["disabled"] = bool(c.get("disabled", False))
            items.append(item)
        rows.append(items)
    return rows


def sent_reply(call):
    """最初の応答（send_message）に渡されたものを、比べる形にする。"""
    content = call.args[0] if call.args else call.kwargs.get("content")
    embeds = list(call.kwargs.get("embeds") or [])
    if call.kwargs.get("embed") is not None:
        embeds.append(call.kwargs["embed"])
    return {
        "content": content,
        "ephemeral": bool(call.kwargs.get("ephemeral")),
        "embeds": [embed_json(e) for e in embeds],
        "components": components_json(call.kwargs.get("view")),
    }


async def run_command(case):
    """コマンドの例を 1 つ回して、次の順に返す。

    返事・返事の時点の設定・返事のあとの仕事（post・delete・無ければ null）・そのときチャンネルへしたこと・
    終わったあとの設定。
    """
    write_settings(case["before"])
    AFTER_WORK.clear()
    effects = []
    interaction = interaction_for(case, effects)
    at_reply = []

    async def send_message(*args, **kwargs):
        """返事を受け取った時点の設定を控える（返事のあとの仕事が、まだ始まっていないこと）。"""
        at_reply.append([stored_settings(), list(AFTER_WORK), list(effects)])

    interaction.response.send_message = AsyncMock(side_effect=send_message)
    kwargs = {name: option_value(name, value) for name, value in case.get("options", {}).items()}
    try:
        await command_for(case["path"]).callback(interaction, **kwargs)
    except Exception:
        assert not at_reply, "返事を送ったあとで例外になった（この基準では扱っていない）"
        return [case["id"], {"error": True}, None, None, [], stored_settings()]
    reply = sent_reply(interaction.response.send_message.call_args)
    settings_at_reply, work_before_reply, effects_before_reply = at_reply[0]
    assert len(at_reply) == 1, "返事を 2 回送っている"
    assert work_before_reply == [] and effects_before_reply == [], "返事より先に、あとの仕事を始めている"
    after_work = AFTER_WORK[0] if AFTER_WORK else None
    return [case["id"], reply, settings_at_reply, after_work, effects, stored_settings()]


async def run_autocomplete(case):
    """補完の例を 1 つ回して、候補（名前と値）を返す。中で例外が出たら ``{"error": true}``。"""
    write_settings(case["before"])
    interaction = interaction_for(case, [])
    options = [{"type": 3, "name": name, "value": value} for name, value in case.get("options", {}).items()]
    options.append({"type": 3, "name": case["focused"], "value": case["current"], "focused": True})
    interaction.namespace = Namespace(interaction, {}, options)
    choices_for = command_for(case["path"])._params[case["focused"]].autocomplete
    try:
        choices = await choices_for(interaction, case["current"])
    except Exception:
        return [case["id"], {"error": True}]
    return [case["id"], [[choice.name, choice.value] for choice in choices]]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in cases:
        run = run_autocomplete if "focused" in case else run_command
        print(json.dumps(await run(case), ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
