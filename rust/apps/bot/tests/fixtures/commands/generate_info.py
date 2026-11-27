"""情報のコマンド（/info server・/info user）の基準（info_expected.jsonl）を、本物の Python から作る。

サーバーとメンバーは、Discord から届く形の JSON（info_cases.json）を discord.py の本物の Guild・Role・Member に
読ませて作る（時刻の書き方・ロールの並び・色・アバターの URL を本物に決めさせる）。本物のコマンドの中身
（commands/server/info.py）を、記録するだけの偽物の interaction で呼び、返事（本文・Embed・部品・「本人にだけ
見せるか」）を書き出す。

引数で選んだ人がサーバーのメンバーでない例は、discord.py の本物の変換（MemberTransformer）に失敗させ、その失敗を
本物の受け皿（commands/interaction_utils.py の _on_tree_error）に渡して、返る文を書き出す。

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_info.py info_cases.json > info_expected.jsonl
"""

import asyncio
import copy
import json
import os
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock

os.environ["SETTINGS_DIR"] = tempfile.mkdtemp()
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["ADMIN_SITE_URL"] = "https://admin.example/login"
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord import app_commands  # noqa: E402
from discord.app_commands import transformers  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands  # noqa: E402
from commands.interaction_utils import install_global_app_command_error_handler  # noqa: E402

spec = json.load(open(sys.argv[1], encoding="utf-8"))
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)
install_global_app_command_error_handler(bot)


def new_state():
    """discord.py の中の状態の代わり（ユーザーを作るところだけ本物に回す）。"""
    state = MagicMock()
    state.store_user.side_effect = lambda data, *a, **k: discord.User(state=state, data=data)
    state.create_user.side_effect = lambda data: discord.User(state=state, data=data)
    return state


def member_payload(name):
    """名前で引いたメンバーの JSON（`user` は名前から中身に置き換える）。"""
    payload = copy.deepcopy(spec["members"][name])
    payload["user"] = copy.deepcopy(spec["users"][payload["user"]])
    return payload


def guild_payload(case):
    """その例のサーバーの JSON（共通のものに、例ごとの上書きを重ねる）。"""
    payload = copy.deepcopy(spec["guild"])
    payload.update(copy.deepcopy(case.get("guild_patch", {})))
    payload["members"] = [member_payload(name) for name in payload["members"]]
    return payload


def command_for(path):
    """`info server` のような道すじから、コマンドを引く。"""
    node = bot.tree.get_command(path.split()[0])
    for name in path.split()[1:]:
        node = node.get_command(name)
    return node


def embed_json(embed):
    """Embed から、比べる項目（題・本文・色・小さい画像・項目）だけを取り出す。"""
    d = embed.to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "color": d.get("color"),
        "thumbnail": d.get("thumbnail", {}).get("url"),
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


def sent_reply(interaction):
    """最初の応答（send_message）に渡されたものを、比べる形にする。"""
    call = interaction.response.send_message.call_args
    content = call.args[0] if call.args else call.kwargs.get("content")
    embeds = [call.kwargs["embed"]] if call.kwargs.get("embed") is not None else []
    return {
        "content": content,
        "ephemeral": bool(call.kwargs.get("ephemeral")),
        "embeds": [embed_json(e) for e in embeds],
        "components": components_json(call.kwargs.get("view")),
    }


def picked_target(case, state, guild):
    """引数で選んだ人を、discord.py と同じ作り方で作る（app_commands/namespace.py の _get_resolved_items）。

    サーバーにいる人は、届いたメンバーの情報から Member を作る。いない人は User になる。
    """
    if case.get("target") is not None:
        return discord.Member(state=state, guild=guild, data=member_payload(case["target"]))
    return state.create_user(copy.deepcopy(spec["users"][case["target_user"]]))


async def run(case):
    """例を 1 つ回して、返事を返す。"""
    state = new_state()
    interaction = MagicMock()
    interaction.response.is_done = MagicMock(return_value=False)
    interaction.response.send_message = AsyncMock()
    guild = None
    if case["who"] == "dm":
        interaction.guild = None
        interaction.user = state.create_user(copy.deepcopy(spec["users"][spec["members"][case["invoker"]]["user"]]))
    else:
        guild = discord.Guild(data=guild_payload(case), state=state)
        interaction.guild = guild
        # 打った人は、コマンドと一緒に届いたメンバーの情報から作る（discord.py の Interaction._from_data と同じ）。
        interaction.user = discord.Member(state=state, guild=guild, data=member_payload(case["invoker"]))
    command = command_for(case["path"])
    kwargs = {}
    if "target" in case or "target_user" in case:
        value = picked_target(case, state, guild)
        try:
            kwargs["member"] = await transformers.MemberTransformer().transform(interaction, value)
        except app_commands.AppCommandError as error:
            # メンバーでない人を選んだ。コマンドの中身は呼ばれず、失敗の受け皿が文を返す。
            await bot.tree.on_error(interaction, error)
            return [case["id"], sent_reply(interaction)]
    await command.callback(interaction, **kwargs)
    return [case["id"], sent_reply(interaction)]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in spec["cases"]:
        print(json.dumps(await run(case), ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
