"""設定のコマンド（/log・/chat・/trusted・/bypass・/bot）の基準（settings_expected.jsonl）を、本物の Python から作る。

本物のコマンドの中身（commands/settings/）を、記録するだけの偽物の interaction で呼び、返事（本文・Embed・
部品・「本人にだけ見せるか」）と、書き換えたあとのそのサーバーの設定を書き出す。選択の画面（/trusted・/bypass
の追加と削除）は、選ぶ・確定を押す、の手順ごとの応答も書き出す。設定の置き場は本物（settings_store の
ファイル版）を一時ディレクトリで使う。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_settings.py settings_cases.json > settings_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["ADMIN_SITE_URL"] = "https://admin.example/login"
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands  # noqa: E402
from services import settings_store  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
OTHER = 4242
cases = json.load(open(sys.argv[1], encoding="utf-8"))
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)
GUILD_OBJECT = SimpleNamespace(id=GUILD)


def write_settings(guild_settings):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): guild_settings}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def command_for(path):
    """`log channel` のような道すじから、コマンドを引く。"""
    node = bot.tree.get_command(path.split()[0])
    for name in path.split()[1:]:
        node = node.get_command(name)
    return node


def real_role(role_id):
    """本物の discord.Role（メンションの書き方〔@everyone〕を本物に決めさせる）。"""
    data = {"id": str(role_id), "name": f"r{role_id}", "permissions": "0", "position": 1, "color": 0}
    data.update({"hoist": False, "managed": False, "mentionable": False})
    return discord.Role(guild=GUILD_OBJECT, state=MagicMock(), data=data)


def guild_for(who):
    """打たれたサーバー。ロールは、サーバーにあるもの（@everyone と 20）だけ引ける。"""
    if who == "dm":
        return None
    known = {GUILD: real_role(GUILD), 20: real_role(20)}
    return SimpleNamespace(id=GUILD, get_member=lambda uid: None, get_role=known.get)


def interaction_for(who, user_id=USER):
    """打った人の立場（admin・member・dm）ごとの、記録するだけの interaction。"""
    interaction = MagicMock()
    interaction.guild = guild_for(who)
    member = MagicMock(spec=discord.Member)
    member.id = user_id
    member.guild_permissions = SimpleNamespace(administrator=(who == "admin"))
    interaction.user = member
    interaction.response.is_done = MagicMock(return_value=False)
    interaction.response.send_message = AsyncMock()
    interaction.response.edit_message = AsyncMock()
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


def components_json(view):
    """部品を、比べる項目だけにする（ID は毎回違うので、あるかどうかだけ）。"""
    if view is None:
        return []
    rows = []
    for row in view.to_components():
        items = []
        for c in row["components"]:
            item = {key: c.get(key) for key in ("type", "style", "label")}
            item["disabled"] = bool(c.get("disabled", False))
            item.update({key: c.get(key) for key in ("placeholder", "min_values", "max_values", "url")})
            item["has_id"] = isinstance(c.get("custom_id"), str)
            items.append(item)
        rows.append(items)
    return rows


def sent_reply(interaction):
    """最初の応答（send_message）に渡されたものを、比べる形にする。view も返す。"""
    call = interaction.response.send_message.call_args
    content = call.args[0] if call.args else call.kwargs.get("content")
    embeds = list(call.kwargs.get("embeds") or [])
    if call.kwargs.get("embed") is not None:
        embeds.append(call.kwargs["embed"])
    view = call.kwargs.get("view")
    reply = {
        "content": content,
        "ephemeral": bool(call.kwargs.get("ephemeral")),
        "embeds": [embed_json(e) for e in embeds],
        "components": components_json(view),
    }
    return reply, view


def entities_for(path, ids):
    """選択の部品が返すもの（ユーザーかロール）を、ID から作る。"""
    if path.startswith("bypass"):
        return [real_role(i) for i in ids]
    return [SimpleNamespace(id=i, mention=f"<@{i}>") for i in ids]


async def take_step(path, view, step):
    """選択の画面の 1 手順（選ぶ・確定を押す）を回して、応答を比べる形にする。"""
    who = OTHER if step.get("by") == "other" else USER
    interaction = interaction_for("admin", who)
    if "select" in step:
        view.select_item._values = entities_for(path, step["select"])
        await view._on_select(interaction)
    else:
        await view._on_confirm(interaction)
    if interaction.response.send_message.called:
        call = interaction.response.send_message.call_args
        return {"kind": "message", "content": call.args[0], "ephemeral": bool(call.kwargs.get("ephemeral"))}
    call = interaction.response.edit_message.call_args
    kept = call.kwargs.get("view")
    return {"kind": "update", "content": call.kwargs.get("content"), "components": components_json(kept)}


async def run(case):
    """例を 1 つ回して、返事・手順ごとの応答・書き換えたあとの設定を返す。"""
    write_settings(case["before"])
    interaction = interaction_for(case["who"])
    kwargs = {name: option_value(name, value) for name, value in case.get("options", {}).items()}
    await command_for(case["path"]).callback(interaction, **kwargs)
    reply, view = sent_reply(interaction)
    steps = [await take_step(case["path"], view, step) for step in case.get("steps", [])]
    after = settings_store.get_guild_settings(GUILD)
    # 書き換えの時刻は比べない（Rust では保存のときに押す）。
    after.pop("_updated_at", None)
    return [case["id"], reply, steps, after]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in cases:
        print(json.dumps(await run(case), ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
