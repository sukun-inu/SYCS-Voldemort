"""設定のコマンド（/log・/chat）の基準（settings_expected.jsonl）を、本物の Python から作る。

本物のコマンドの中身（commands/settings/）を、記録するだけの偽物の interaction で呼び、返事（本文と
「本人にだけ見せるか」）と、書き換えたあとのそのサーバーの設定を書き出す。設定の置き場は本物
（settings_store のファイル版）を一時ディレクトリで使う。

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
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands  # noqa: E402
from services import settings_store  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
cases = json.load(open(sys.argv[1], encoding="utf-8"))
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)


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


def interaction_for(who):
    """打った人の立場（admin・member・dm）ごとの、記録するだけの interaction。"""
    interaction = MagicMock()
    interaction.guild = None if who == "dm" else SimpleNamespace(id=GUILD)
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


async def run(case):
    """例を 1 つ回して、返事と、書き換えたあとの設定を返す。"""
    write_settings(case["before"])
    interaction = interaction_for(case["who"])
    kwargs = {name: option_value(name, value) for name, value in case["options"].items()}
    await command_for(case["path"]).callback(interaction, **kwargs)
    call = interaction.response.send_message.call_args
    content = call.args[0] if call.args else call.kwargs.get("content")
    after = settings_store.get_guild_settings(GUILD)
    # 書き換えの時刻は比べない（Rust では保存のときに押す）。
    after.pop("_updated_at", None)
    return [case["id"], {"content": content, "ephemeral": bool(call.kwargs.get("ephemeral"))}, after]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in cases:
        print(json.dumps(await run(case), ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
