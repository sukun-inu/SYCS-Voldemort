"""地震の通知の基準（expected.jsonl）を、本物の Python から作る。

本物の services/earthquake_service.py に cases.json の例を 1 つずつ与え、結果を 1 行ずつ書き出す。
Discord・画像・気象庁の一覧は、記録するだけの偽物に差し替える（外へは何も送らない）。

    python generate.py cases.json > expected.jsonl

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす。

例外で終わる例は {"raises": 型の名前} と書く（Rust は形の崩れた電文でも読めるところだけで続けるので、
その例は比べない）。
"""

import asyncio
import io
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import discord  # noqa: E402
from services import earthquake_service as eq, settings_store  # noqa: E402
from services.ttl_cache import TTLCache  # noqa: E402
import events.background_tasks as background_tasks  # noqa: E402

G1 = 1399617700363370556
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
cases = json.load(open(sys.argv[1], encoding="utf-8"))


def norm(embed):
    """Embed から、比べるものだけを取り出す。"""
    d = embed.to_dict()
    ts = d.get("timestamp")
    footer = d.get("footer") or {}
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "color": d.get("color"),
        "timestamp": int(datetime.fromisoformat(ts).timestamp()) if ts else None,
        "fields": [[f["name"], f["value"], bool(f.get("inline"))] for f in d.get("fields", [])],
        "footer": [footer.get("text"), footer.get("icon_url")],
        "thumbnail": (d.get("thumbnail") or {}).get("url"),
        "image": (d.get("image") or {}).get("url"),
    }


def micros(dt):
    """時刻を 1970 年からのマイクロ秒にする（Rust と同じ単位で比べるため）。"""
    return None if dt is None else (dt - EPOCH) // timedelta(microseconds=1)


def fake_bot(guilds, sent):
    """サーバーとチャンネルの偽物。送ったものを sent に記録する。"""
    table = {}
    for gid_text, g in guilds.items():
        gid = int(gid_text)
        if not g.get("cached", True):
            table[gid] = None
            continue
        channels = {}
        for cid_text, kind in g.get("channels", {}).items():
            cid = int(cid_text)
            channel = MagicMock(spec=discord.TextChannel if kind in ("text", "news") else discord.VoiceChannel)
            channel.id = cid

            async def send(
                embed=None,
                files=discord.utils.MISSING,
                view=discord.utils.MISSING,
                _gid=gid,
                _cid=cid,
                _fails=cid in g.get("send_fails", []),
            ):
                """送られたものを記録する。失敗させる送り先なら、記録してから例外を投げる。"""
                button = None
                if view is not discord.utils.MISSING:
                    button = [view.children[0].label, view.children[0].url]
                names = [] if files is discord.utils.MISSING else [[f.filename, f.fp.read().decode()] for f in files]
                sent.append([_gid, _cid, not _fails, norm(embed), button, names])
                if _fails:
                    raise discord.HTTPException(MagicMock(status=403, reason="Forbidden"), "Missing Permissions")

            channel.send = send
            channels[cid] = channel
        table[gid] = SimpleNamespace(get_channel=lambda cid, channels=channels: channels.get(cid))
    return SimpleNamespace(get_guild=lambda gid: table.get(gid))


def settings_of(guilds):
    """例のサーバーの並びを、settings_store が読む形（guilds の辞書）にする。"""
    return {"guilds": {gid: g["settings"] for gid, g in guilds.items() if g.get("settings") is not None}}


async def notify(case):
    """通知の流れを 1 例回し、送ったもの・札と地図に渡したものを返す。"""
    sent, badge_calls, map_calls = [], [], []

    def badge(scale):
        """札の偽物。渡された震度を記録し、例の指定どおりに作る・作らない・落ちる。"""
        badge_calls.append(scale)
        if case["badge"] == "raise":
            raise RuntimeError("badge")
        return io.BytesIO(f"BADGE{scale}".encode()) if case["badge"] == "ok" else None

    async def intensity_map(session, lat, lon, points, title="", subtitle=""):
        """地図の偽物。渡されたものを記録し、例の指定どおりに作る・作らない・落ちる。"""
        map_calls.append([lat, lon, len(points), title, subtitle])
        if case["map"] == "raise":
            raise RuntimeError("map")
        return io.BytesIO(b"MAP") if case["map"] == "ok" else None

    async def jma_list():
        """気象庁の一覧の偽物（例の一覧をそのまま返す）。"""
        return case["jma"]

    bot = fake_bot(case["guilds"], sent)
    eq._jma_detail_url_cache = TTLCache(ttl=3600.0, max_entries=500)
    with (
        patch.object(settings_store, "_load_all", lambda: settings_of(case["guilds"])),
        patch.object(eq, "_generate_badge", badge),
        patch.object(eq, "_generate_intensity_map", intensity_map),
        patch.object(eq, "_get_jma_list", jma_list),
    ):
        kind = case["kind"]
        if kind == "quake":
            count = await eq._notify_all_guilds(
                bot,
                case["event"],
                only_guild_id=case.get("only_guild"),
                override_channel_id=case.get("override_channel"),
            )
        elif kind == "tsunami":
            count = await eq._notify_tsunami_guilds(bot, case["event"])
        else:
            count = await eq._notify_eew_guilds(bot, case["event"], kind)
    return {
        "count": count,
        "sent": sorted(sent, key=lambda s: (s[0], s[1])),
        "badge": badge_calls[0] if badge_calls else None,
        "map": map_calls[0] if map_calls else None,
    }


def evaluate(case):
    """1 つのサーバーが送り先かどうかの判定と、届かない理由の文を返す。"""
    guild = {"settings": case["settings"], "cached": case["guild"] == "cached", "channels": case["channels"]}
    bot = fake_bot({str(G1): guild}, [])
    kwargs = dict(notify_type=case["notify_type"], max_scale=case["max_scale"], apply_min_scale=case["apply_min_scale"])
    with patch.object(settings_store, "_load_all", lambda: settings_of({str(G1): guild})):
        try:
            channel, reason = eq._evaluate_guild(bot, G1, **kwargs)
            result = ["target", channel.id] if channel is not None else ["skip", reason]
        except Exception:
            result = ["broken"]
        diagnose = eq._diagnose_no_target(bot, G1, **kwargs)
    # 壊れた設定の理由は、例外の文（言語ごとに違う）を含むので、前置きだけを比べる。
    marker = "設定の読み取りに失敗しました（"
    if diagnose.startswith(marker):
        diagnose = marker
    return {"eval": result, "diagnose": diagnose}


async def replay(case):
    """リプレイの依頼を本物の受け口に渡し、通知に渡った電文・サーバー・チャンネルを返す。"""
    seen = []

    async def record(bot, event, *, only_guild_id=None, override_channel_id=None):
        """通知の代わりに、渡されたものを記録する。"""
        seen.append([event, only_guild_id, None if override_channel_id is None else int(override_channel_id)])
        return 0

    with patch.object(eq, "_notify_all_guilds", record), patch.object(background_tasks.logger, "info"):
        try:
            await background_tasks._signal_eq_replay(None, case["payload"])
        except Exception:
            return "error"
    return seen[0]


async def detail_url(case):
    """例の一覧から選ばれるリンクと、覚えておく鍵を返す。"""

    async def jma_list():
        """気象庁の一覧の偽物（例の一覧をそのまま返す）。"""
        return case["items"]

    eq._jma_detail_url_cache = TTLCache(ttl=3600.0, max_entries=500)
    scale = eq._max_scale(case["event"])
    with patch.object(eq, "_get_jma_list", jma_list):
        url = await eq._resolve_jma_detail_url(case["event"], scale)
    return {"url": url, "key": eq._cache_key_for_event(case["event"], scale)}


def score(case):
    """一覧の 1 件の点数（相手の時刻・名前・規模は、本物と同じ取り出し方をする）。"""
    event = case["event"]
    quake = event.get("earthquake", {})
    hypo = quake.get("hypocenter", {})
    return eq._score_jma_item(
        case["item"],
        eq._parse_any_time(quake.get("originTime") or quake.get("time", "")),
        str(hypo.get("name", "") or ""),
        eq._parse_magnitude_value(hypo.get("magnitude")),
        eq._max_scale(event),
    )


async def run(case):
    """例の op に合わせて、本物の関数を 1 つ呼ぶ。"""
    op = case["op"]
    if op == "max_scale":
        return eq._max_scale(case["event"])
    if op == "parse_coord":
        return eq._parse_coord(case["raw"])
    if op == "parse_depth":
        return eq._parse_depth(case["raw"])
    if op == "parse_magnitude":
        label, value = eq._parse_magnitude(case["raw"])
        # 無限大は JSON に書けないので、表示だけを比べる。
        return [label, value if value == value and abs(value) != float("inf") else None]
    if op == "format_time":
        label, dt = eq._format_time(case["text"])
        return [label, None if dt is None else int(dt.timestamp())]
    if op == "embed":
        return norm(eq._build_embed(case["event"], eq._max_scale(case["event"]), has_badge=case["has_badge"]))
    if op == "eew_embed":
        return norm(eq._build_eew_embed(case["event"]))
    if op == "tsunami_embed":
        return norm(eq._build_tsunami_embed(case["event"]))
    if op == "scale_from_text":
        return eq._scale_from_text(case["text"])
    if op == "magnitude_value":
        value = eq._parse_magnitude_value(case["raw"])
        return None if value is None or value != value or abs(value) == float("inf") else value
    if op == "any_time":
        return micros(eq._parse_any_time(case["raw"]))
    if op == "score":
        return score(case)
    if op == "detail_url":
        return await detail_url(case)
    if op == "evaluate":
        return evaluate(case)
    if op == "notify":
        return await notify(case)
    if op == "map_subtitle":
        return eq._map_subtitle(case["event"])
    if op == "replay":
        return await replay(case)
    raise ValueError(op)


async def main():
    """例を順に回して、結果を 1 行ずつ書き出す。"""
    for case in cases:
        try:
            result = await run(case)
        except Exception as e:  # noqa: BLE001
            result = {"raises": type(e).__name__}
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))


with (
    patch.object(eq.logger, "warning"),
    patch.object(eq.logger, "exception"),
    patch.object(eq.logger, "error"),
    patch.object(eq.logger, "info"),
):
    asyncio.run(main())
