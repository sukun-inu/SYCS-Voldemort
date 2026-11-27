"""ニュースの基準（pure_expected.json・flow_expected.jsonl・html5_entities.tsv）を、本物の Python から作る。

    python generate.py pure  <この置き場>      > pure_expected.json
    python generate.py flow  <この置き場>      > flow_expected.jsonl   # 偽物の配信元と Groq を立てておく
    python generate.py entities                > html5_entities.tsv    # src/ に置く（html.unescape の表）

本番と同じ依存（requirements.txt）の Python 3.13 で、リポジトリの直下を /app に置いて回す。TZ は UTC に固定する
（時刻帯の無い日付は「その場の時刻帯」として読まれるため）。

flow は、偽物の配信元（NEWS_FAKE_RSS、既定 http://fake-b8:8081）と偽物の Groq（NEWS_FAKE_GROQ、既定
http://fake-b8:8082）に本物の run_news_feeds を当て、Discord への送信と設定の書き戻しは記録するだけの偽物に
差し替える。偽物の決め方は Rust のテスト（tests/news_flow.rs）の中の偽物と同じ:

  配信元: GET /rss/search?q=… の q で決める。feed:<名前> は rss/<名前>.xml、status:<番号> はその状態、
          errfeed:<番号> はその状態で中身は rss/basic.xml、redirect:<名前> は feed:<名前> へ 302、
          close は何も返さずに切る、それ以外は rss/basic.xml
  Groq:   利用者の文に入っている印（G-500・G-NULL など）で決める。印が無ければ 1 行目を使った決まった文
  どちらも GET /_log で受けた要求を返し、POST /_reset で消す
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import urllib.request
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ["TZ"] = "UTC"
time.tzset()
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
FAKE_RSS = os.environ.get("NEWS_FAKE_RSS", "http://fake-b8:8081")
FAKE_GROQ = os.environ.get("NEWS_FAKE_GROQ", "http://fake-b8:8082")
os.environ["GROQ_API_KEY"] = "test-key"
os.environ["GROQ_BASE_URL"] = FAKE_GROQ
os.environ["GROQ_MIN_REQUEST_INTERVAL_SECONDS"] = "0"
os.environ.pop("NEWS_SUMMARY_MODEL", None)
sys.path.insert(0, "/app")

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
HERE = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(__file__))
# 巡回の時刻（UNIX 秒）。Rust のテストと同じ値にしてある。
NOW = 1795565100.25


def entities():
    """html.unescape が使う表を書き出す。E=名前つき、R=番号の置き換え、X=落とす番号。

    Rust は Python の表をそのまま使う（HTML5 の実体参照は 2231 個あり、手で写すと必ず食い違う）。
    """
    import html as _html
    from html.entities import html5

    out = []
    for name in sorted(html5):
        out.append("E\t%s\t%s" % (name, " ".join("%X" % ord(c) for c in html5[name])))
    for num in sorted(_html._invalid_charrefs):
        out.append("R\t%X\t%s" % (num, " ".join("%X" % ord(c) for c in _html._invalid_charrefs[num])))
    for num in sorted(_html._invalid_codepoints):
        out.append("X\t%X" % num)
    sys.stdout.write("\n".join(out) + "\n")


def pure():
    """部品（説明の整え方・日付・要約の整え方・favicon・RSS の読み方など）の結果を書き出す。

    入力は pure_cases.json と rss/*.xml。例外になるものは {"error": 型の名前} として残す
    （Rust 側は、例外になるところを「読めない」として扱うので、どこで例外になるかも基準に入れる）。
    """
    from urllib.parse import quote

    from services import news_service as ns
    from services.ttl_cache import TTLCache

    cases = json.load(open(os.path.join(HERE, "pure_cases.json"), encoding="utf-8"))

    def favicon(u):
        """favicon の URL。urlparse は壊れた URL で ValueError を投げる（その記事は送られない）。"""
        try:
            return ns._favicon_url(u)
        except Exception as e:
            return {"error": type(e).__name__}

    def parse(name):
        """RSS を読んだ結果。読めない文字コード（Shift_JIS など）では ValueError になる。"""
        raw = open(os.path.join(HERE, "rss", name + ".xml"), "rb").read()
        try:
            return ns._parse_rss(raw)
        except Exception as e:
            return {"error": type(e).__name__}

    def source_text(article):
        """本物の _summarize_article が Groq に渡す文（渡さなければ None）。

        文の組み立ては関数の中に直に書いてあるので、Groq の呼び出しを差し替えて、渡された文を取り出す。
        """
        seen = []

        async def fake_create(client, *, bucket, **kw):
            """Groq の呼び出しの代わり。渡された利用者の文を覚えて、決まった答えを返す。"""
            seen.append(kw["messages"][1]["content"])
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="x"))])

        with (
            patch.object(ns, "_summary_cache", TTLCache(ttl=60, max_entries=10)),
            patch.object(ns, "_get_groq_client", lambda: object()),
            patch.object(ns, "create_chat_completion", fake_create),
        ):
            asyncio.run(ns._summarize_article(dict(article)))
        return seen[0] if seen else None

    with patch.object(ns.logger, "exception"), patch.object(ns.logger, "warning"):
        out = {
            "strip_html": [ns._strip_html(x) for x in cases["strip_html"]],
            "pub_date": [ns._format_pub_date(x) for x in cases["pub_date"]],
            "normalize": [ns._normalize_summary_text(x) for x in cases["normalize"]],
            "favicon": [favicon(x) for x in cases["favicon"]],
            "hash": [ns._url_hash(x) for x in cases["hash"]],
            "quote": [quote(x) for x in cases["quote"]],
            "parse": [parse(x) for x in cases["parse"]],
            "source_text": [source_text(x) for x in cases["source_text"]],
        }
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")


def embed_dict(e):
    """Embed を辞書にする。中身に関わらない項目（種類は常に rich、flags は常に 0）は比べない。"""
    d = e.to_dict()
    d.pop("type", None)
    d.pop("flags", None)
    return d


def fake_log():
    """偽物が受けた要求（配信元の行き先と、Groq の本文）を取る。"""
    return json.load(urllib.request.urlopen(FAKE_RSS + "/_log"))


def fake_reset():
    """偽物が覚えている要求を消す（例ごとに数え直すため）。"""
    urllib.request.urlopen(urllib.request.Request(FAKE_RSS + "/_reset", data=b"", method="POST"))


async def run_flow(case):
    """1 つの例で本物の run_news_feeds を回し、送ったもの・書き戻したもの・偽物に届いたものをまとめる。

    Discord（ギルドとチャンネル）と設定の書き戻しは、記録するだけの偽物に差し替える。書き戻しは本物の
    _news_feed_state_mutator を手元の辞書に当てる（直近 100 件に切るところまで本物を通すため）。
    """
    import discord

    from services import news_service as ns
    from services import settings_store
    from services.ttl_cache import TTLCache

    data = {"guilds": json.loads(json.dumps(case["guilds"]))}
    sends, writes = [], []
    text_channels = {int(g): set(v) for g, v in case.get("text_channels", {}).items()}
    other_channels = {int(g): set(v) for g, v in case.get("other_channels", {}).items()}
    failing = set(case.get("send_fails", []))

    def get_guild(gid):
        """bot.get_guild の代わり。例に書いていないギルドは「見えない」（None）。"""
        if gid not in text_channels and gid not in other_channels:
            return None

        def get_channel(cid):
            """guild.get_channel の代わり。テキストチャンネル・ボイスチャンネル・無い、のどれか。"""
            if cid in text_channels.get(gid, ()):
                ch = MagicMock(spec=discord.TextChannel)

                async def send(embed=None):
                    """channel.send の代わり。送ろうとした Embed を記録し、失敗するチャンネルなら例外を投げる。"""
                    sends.append({"channel": cid, "embed": embed_dict(embed)})
                    if cid in failing:
                        raise discord.HTTPException(MagicMock(status=400, reason="Bad Request"), "Invalid Form Body")

                ch.send = send
                return ch
            if cid in other_channels.get(gid, ()):
                return MagicMock(spec=discord.VoiceChannel)
            return None

        return SimpleNamespace(get_channel=get_channel)

    async def update_state(guild_id, feed_id, last_run, seen_hashes):
        """aupdate_news_feed_state の代わり。本物の書き換えを手元の辞書に当てて、書いた行を記録する。"""
        before = json.dumps(data, sort_keys=True)
        settings_store._news_feed_state_mutator(guild_id, feed_id, last_run, seen_hashes)(data)
        row = data["guilds"].get(str(guild_id), {}).get("news_feeds", {})
        row = row.get(feed_id) if isinstance(row, dict) else None
        changed = json.dumps(data, sort_keys=True) != before
        writes.append({"guild": guild_id, "feed": feed_id, "changed": changed, "row": row})

    guild_ids = [int(k) for k in sorted(data["guilds"]) if k.lstrip("-").isdigit()]
    fake_reset()
    with (
        patch.object(ns, "_RSS_BASE", FAKE_RSS + "/rss/search?q={query}&hl=ja&gl=JP&ceid=JP:ja"),
        patch.object(ns, "GROQ_API_KEY", None if case.get("no_key") else "test-key"),
        patch.object(ns, "_summary_cache", TTLCache(ttl=6 * 3600, max_entries=1000)),
        patch.object(ns, "time", SimpleNamespace(time=lambda: NOW)),
        patch.object(ns, "get_all_guild_ids", lambda: guild_ids),
        patch.object(settings_store, "get_guild_settings", lambda gid: data["guilds"].get(str(gid), {})),
        patch.object(ns, "aupdate_news_feed_state", update_state),
    ):
        error = None
        try:
            await ns.run_news_feeds(SimpleNamespace(get_guild=get_guild))
        except Exception as e:
            # 壊れた設定で巡回ごと止まる（Rust は止めずに、そのフィードだけ飛ばす）。
            error = type(e).__name__
    log = fake_log()
    return {
        "id": case["id"],
        "sends": sends,
        "writes": writes,
        # `'` は Python が生で、Rust が %27 で送る（意味は同じ）。比べるときはそろえる。
        "rss": [r["target"].replace("%27", "'") for r in log["rss"]],
        "ua": sorted({r["ua"] for r in log["rss"]}),
        "groq": [g["body"] for g in log["groq"]],
        "groq_auth": sorted({g["auth"] for g in log["groq"]}),
        "aborted": error,
    }


async def flow():
    """巡回の流れの例（flow_cases.json）を順に回して、1 行に 1 例ずつ書き出す。"""
    from services import news_service as ns

    cases = json.load(open(os.path.join(HERE, "flow_cases.json"), encoding="utf-8"))
    with patch.object(ns.logger, "exception"), patch.object(ns.logger, "warning"):
        for case in cases:
            print(json.dumps(await run_flow(case), ensure_ascii=False, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    if MODE == "entities":
        entities()
    elif MODE == "pure":
        pure()
    elif MODE == "flow":
        asyncio.run(flow())
    else:
        sys.exit("pure / flow / entities のどれかを指定してください")
