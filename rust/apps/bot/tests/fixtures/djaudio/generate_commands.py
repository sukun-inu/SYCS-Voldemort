"""/djaudio channel・output・status の基準（commands_expected.jsonl）を、本物の Python から作る。

本物のコマンド（commands/djaudio_commands.py）を、discord.py と同じ順に動かす: コマンドの確かめ（`has_permissions`。
`_check_can_run`）→ 中身 → 例外ならコマンドの受け皿（`bind_permission_error_handler`）→ 全体の受け皿
（`install_global_app_command_error_handler`）。打った人への送信（最初の応答・あとからの送信）を順に記録する。

1 行に 1 例。``[id, 送ったもの, 終わったあとの設定]``。送ったものは ``[応答か, 本文, Embed, 部品, 本人にだけ見せるか]``
の並び。

- 例の ``who`` は admin・member・dm。``manage_channels`` は打った人がそのチャンネルで持つ「チャンネルの管理」の権限
- ``channels`` は、そのサーバーにあるチャンネルの ID（status の「チャンネル未検出」を決める）
- ``base_url``・``defaults`` で、配信のリンクの頭と、設定が無いときの値を変える
- ``fail`` は ``write``（設定を書けない）か ``send``（最初の返事を送れない）

設定の置き場は本物（settings_store のファイル版）を一時ディレクトリで使う。本番と同じ依存（requirements.txt）で、
リポジトリの直下を /app に置いて動かす:

    python generate_commands.py > commands_expected.jsonl
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
os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord import app_commands  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

import config  # noqa: E402
from commands import djaudio_commands, register_all_commands  # noqa: E402
from commands.interaction_utils import install_global_app_command_error_handler  # noqa: E402
from services import settings_store  # noqa: E402

GUILD = 1399617700363370556
USER = 80351110224678912
CHANNEL = 1505310388051251000
bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)
install_global_app_command_error_handler(bot)
GUILD_OBJECT = SimpleNamespace(id=GUILD)
REAL_AWRITE = djaudio_commands.awrite


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


def command_for(path):
    """`djaudio channel` のような道すじから、コマンドを引く。"""
    node = bot.tree.get_command(path.split()[0])
    for name in path.split()[1:]:
        node = node.get_command(name)
    return node


def real_text_channel(channel_id):
    """本物の discord.TextChannel（引数で選ばれたチャンネル。メンションの書き方を本物に決めさせる）。"""
    data = {"id": str(channel_id), "type": 0, "name": f"c{channel_id}", "position": 0}
    return discord.TextChannel(state=MagicMock(), guild=GUILD_OBJECT, data=data)


def embed_json(embed):
    """Embed から、比べる項目（題・本文・色・項目）だけを取り出す。"""
    if embed is None:
        return None
    d = embed.to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    return {"title": d.get("title"), "description": d.get("description"), "color": d.get("color"), "fields": fields}


def components_json(view):
    """部品を、比べる項目だけにする。"""
    if view is None:
        return []
    return [
        [{key: c.get(key) for key in ("type", "style", "label", "url")} for c in row["components"]]
        for row in view.to_components()
    ]


def interaction_for(case, sent):
    """記録するだけの interaction。送ったものは `sent` に順に残す。"""
    interaction = MagicMock()
    interaction.id = 1
    interaction.channel_id = CHANNEL
    if case["who"] == "dm":
        interaction.guild = None
        interaction.guild_id = None
    else:
        known = {int(c): real_text_channel(int(c)) for c in case.get("channels", [])}
        interaction.guild = SimpleNamespace(id=GUILD, get_channel=known.get)
        interaction.guild_id = GUILD
    member = MagicMock(spec=discord.Member)
    member.id = USER
    member.display_name = "u"
    member.guild_permissions = SimpleNamespace(administrator=(case["who"] == "admin"))
    interaction.user = member
    interaction.permissions = discord.Permissions(manage_channels=case.get("manage_channels", False))
    done = {"value": False}
    interaction.response.is_done = MagicMock(side_effect=lambda: done["value"])
    failures = {"send": case.get("fail") == "send"}

    def record(kind, kwargs):
        """送ったものを 1 つ残す。"""
        content = kwargs.get("content")
        sent.append(
            [
                kind,
                content,
                embed_json(kwargs.get("embed")),
                components_json(kwargs.get("view")),
                bool(kwargs.get("ephemeral")),
            ]
        )

    async def send_message(*args, **kwargs):
        """最初の応答。例によっては 1 回目だけ断られる（Discord が 400 を返したとき）。"""
        if args:
            kwargs["content"] = args[0]
        if failures["send"]:
            failures["send"] = False
            raise discord.HTTPException(MagicMock(status=400, reason="Bad Request"), "boom")
        record("response", kwargs)
        done["value"] = True

    async def followup_send(*args, **kwargs):
        """応答のあとからの送信。"""
        if args:
            kwargs["content"] = args[0]
        record("followup", kwargs)

    interaction.response.send_message = AsyncMock(side_effect=send_message)
    interaction.followup.send = AsyncMock(side_effect=followup_send)
    return interaction


async def invoke(command, interaction, kwargs):
    """discord.py の CommandTree._call と同じ順に動かす（確かめ → 中身 → 受け皿 2 つ）。"""
    interaction.command = command
    try:
        if not await command._check_can_run(interaction):
            raise app_commands.CheckFailure(f"The check functions for command {command.name!r} failed.")
        try:
            await command.callback(interaction, **kwargs)
        except app_commands.AppCommandError:
            raise
        except Exception as e:
            raise app_commands.CommandInvokeError(command, e) from e
    except app_commands.AppCommandError as e:
        await command._invoke_error_handlers(interaction, e)
        await bot.tree.on_error(interaction, e)


async def run(case):
    """例を 1 つ回して、送ったものと、終わったあとの設定を返す。"""
    write_settings(case.get("before", {}))
    base = case.get("base_url", "https://dl.example")
    djaudio_commands.DJAUDIO_BASE_URL = base
    config.DJAUDIO_CACHE_TTL, config.DJAUDIO_COOLDOWN, config.DJAUDIO_MAX_URLS = case.get("defaults", [600, 30, 3])

    async def failing_awrite(*args, **kwargs):
        """設定を書けない（DB の障害など）。"""
        raise RuntimeError("write failed")

    djaudio_commands.awrite = failing_awrite if case.get("fail") == "write" else REAL_AWRITE
    sent = []
    interaction = interaction_for(case, sent)
    kwargs = {}
    if "channel" in case:
        kwargs["channel"] = real_text_channel(case["channel"])
    await invoke(command_for(case["path"]), interaction, kwargs)
    return [case["id"], sent, stored_settings()]


def cases():
    """例の一覧。"""
    out = []
    settings_variants = [
        ("empty", {}),
        ("watch", {"djaudio": {"watch_channel_id": 11, "output_channel_id": 22, "cache_ttl": 1200, "cooldown": 5}}),
        ("legacy", {"djaudio_watch_channel_id": 11, "djaudio_watch_channel": 11, "djaudio_cache_ttl": 90, "x": 1}),
        ("broken", {"djaudio": "broken", "djaudio_max_urls": "７"}),
        ("huge", {"djaudio_watch_channel_id": "123456789012345678901234567890", "djaudio": {"output_channel_id": -4}}),
        ("nulls", {"djaudio": {"watch_channel_id": None, "cache_ttl": None}, "djaudio_cooldown": 0}),
    ]
    for name, before in settings_variants:
        for who in ("admin", "member", "dm"):
            out.append({"id": f"status-{name}-{who}", "path": "djaudio status", "who": who, "before": before})
        out.append(
            {
                "id": f"status-{name}-found",
                "path": "djaudio status",
                "who": "member",
                "before": before,
                "channels": [11, 22],
            }
        )
    out.append({"id": "status-local", "path": "djaudio status", "who": "admin", "base_url": "http://localhost:5001"})
    out.append({"id": "status-127", "path": "djaudio status", "who": "admin", "base_url": "http://127.0.0.1:9"})
    out.append({"id": "status-defaults", "path": "djaudio status", "who": "admin", "defaults": [59, 0, 1]})
    out.append({"id": "status-fail-send", "path": "djaudio status", "who": "admin", "fail": "send"})
    for path in ("djaudio channel", "djaudio output"):
        short = path.split()[1]
        for who in ("admin", "member", "dm"):
            out.append({"id": f"{short}-noperm-{who}", "path": path, "who": who, "channel": 33})
        out.append(
            {"id": f"{short}-perm-member", "path": path, "who": "member", "manage_channels": True, "channel": 33}
        )
        out.append({"id": f"{short}-perm-dm", "path": path, "who": "dm", "manage_channels": True, "channel": 33})
        for name, before in settings_variants:
            out.append(
                {
                    "id": f"{short}-set-{name}",
                    "path": path,
                    "who": "admin",
                    "manage_channels": True,
                    "channel": 33,
                    "before": before,
                }
            )
            out.append(
                {"id": f"{short}-clear-{name}", "path": path, "who": "admin", "manage_channels": True, "before": before}
            )
        common = {"path": path, "who": "admin", "manage_channels": True}
        out.append({"id": f"{short}-set-local", **common, "channel": 33, "base_url": "http://localhost:5001"})
        out.append({"id": f"{short}-set-defaults", **common, "channel": 33, "defaults": [3600, 7, 10]})
        out.append({"id": f"{short}-fail-write", **common, "channel": 33, "before": {"a": 1}, "fail": "write"})
        out.append({"id": f"{short}-fail-send", **common, "channel": 33, "before": {"a": 1}, "fail": "send"})
        out.append({"id": f"{short}-clear-fail-send", **common, "before": {"a": 1}, "fail": "send"})
    return out


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す（入力も並べて書く）。"""
    for case in cases():
        line = [case, *(await run(case))[1:]]
        print(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
