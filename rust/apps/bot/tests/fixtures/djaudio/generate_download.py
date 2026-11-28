"""DJAudio の「落として登録する」段（`_download_and_register`）の基準（download_expected.jsonl）を、本物の Python
から作る。

yt-dlp は、台本どおりに動く偽物（`fake-yt-dlp.sh`。Rust のテストも同じものを使う）を PATH の先頭に置いて呼ばせる。
置き場（`DJAUDIO_CACHE_DIR`）は本物の `register_file` が書く。SoundCloud の client_id のページから探す段は、例の
``scrape``（呼ばれるたびに順に返す ID。null は見つからない）を返す偽物に差し替え、yt-dlp の Python のライブラリから
取る段（Rust には持ち込まない）は「取れない」にする。メタデータの補い（Deezer）は B10b で比べるので、ここでは
何もしない（「見つからない」と同じ）。

1 行に 1 例。``[例, 答え]``。答えは:

- ``calls``: yt-dlp に渡した引数の並び（呼んだ回ごと。`-o` の置き場は ``<tmp>`` に置き換える）
- ``scrapes``: ページから探しに行った回数
- ``results``: 題と印（印は ``<token1>`` のように出た順に置き換える）。失敗なら ``error``（yt-dlp の失敗と MP3 が
  無いときは文も、それ以外は null）
- ``cache``: 置き場のファイルの名前（印は置き換え）と中身（情報の JSON は文字そのまま。期限の時刻は ``<expires>``
  に置き換える。MP3 は中身の文字）

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_download.py > download_expected.jsonl
"""

import asyncio
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE_DIR = Path(tempfile.mkdtemp())
os.environ["DJAUDIO_CACHE_DIR"] = str(CACHE_DIR)
os.environ["SETTINGS_DIR"] = tempfile.mkdtemp()
os.environ["SETTINGS_BACKEND"] = "file"
sys.path.insert(0, "/app")
from services import djaudio_service  # noqa: E402

GUILD = 1399617700363370556
FFMPEG = "/usr/bin/ffmpeg"
CLIENT_ID_ERROR = "ERROR: [soundcloud] x: Unable to extract client id; please report this issue\n"


def make_plan(case):
    """偽物の yt-dlp の置き場を作る（bin/yt-dlp と、回ごとの台本）。"""
    root = Path(tempfile.mkdtemp())
    (root / "bin").mkdir()
    script = root / "bin" / "yt-dlp"
    shutil.copy(HERE / "fake-yt-dlp.sh", script)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    for i, step in enumerate(case.get("steps", []), start=1):
        d = root / "steps" / str(i)
        (d / "out").mkdir(parents=True)
        for name, content in step.get("files", {}).items():
            data = bytes.fromhex(content["hex"]) if isinstance(content, dict) else content.encode()
            (d / "out" / name).write_bytes(data)
        if "stderr" in step:
            err = step["stderr"]
            (d / "stderr").write_bytes(bytes.fromhex(err["hex"]) if isinstance(err, dict) else err.encode())
        (d / "exit").write_text(str(step.get("exit", 0)))
    return root


def read_calls(root):
    """偽物の yt-dlp が記録した引数を、呼んだ回ごとに分ける（-o の置き場は <tmp> にする）。"""
    path = root / "args.log"
    if not path.exists():
        return []
    calls = []
    current = []
    for line in path.read_text(encoding="utf-8").split("\n")[:-1]:
        if line == "----":
            calls.append(current)
            current = []
        else:
            current.append(line)
    for call in calls:
        for i, arg in enumerate(call):
            if i > 0 and call[i - 1] == "-o":
                call[i] = "<tmp>/" + arg.rsplit("/", 1)[1]
    return calls


def normalize(text, tokens):
    """印を <tokenN> に、期限の時刻を <expires> に置き換える。"""
    for i, token in enumerate(tokens, start=1):
        text = text.replace(token, f"<token{i}>")
    return re.sub(r'"expires_at": [0-9.e+-]+', '"expires_at": "<expires>"', text)


def cache_listing(tokens):
    """置き場のファイルの名前と中身（印を置き換えてから並べる。印は乱数なので、元の名前の順は毎回変わる）。"""
    out = []
    for path in CACHE_DIR.iterdir():
        content = path.read_text(encoding="utf-8", errors="replace")
        out.append([normalize(path.name, tokens), normalize(content, tokens)])
    return sorted(out)


async def run(case):
    """例を 1 つ回して、答えを返す。"""
    for path in CACHE_DIR.iterdir():
        path.unlink()
    root = make_plan(case)
    os.environ["PATH"] = f"{root / 'bin'}:{ORIGINAL_PATH}"
    djaudio_service.DJAUDIO_FFMPEG_PATH = FFMPEG
    djaudio_service._SC_ENV_CLIENT_ID = case.get("env_client_id", "")
    djaudio_service._sc_client_id = None
    djaudio_service._sc_client_id_fetched_at = -9999.0
    scrapes = list(case.get("scrape", []))
    count = [0]

    async def fake_scrape():
        """ページから探す段（台本の ID を順に返す）。"""
        count[0] += 1
        return scrapes.pop(0) if scrapes else None

    async def no_enrich(mp3_path, info):
        """メタデータの補い（ここでは比べない）。"""
        return False

    djaudio_service._scrape_sc_client_id_via_aiohttp = fake_scrape
    djaudio_service._sync_fetch_sc_client_id_via_ytdlp = lambda: None
    djaudio_service.enrich_metadata = no_enrich
    answers = []
    tokens = []
    for run_spec in case.get("runs", [{}]):
        url = run_spec.get("url", case.get("url", "https://youtu.be/a"))
        ttl = run_spec.get("ttl", case.get("ttl", 600))
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                results = await djaudio_service._download_and_register(url, GUILD, tmpdir, ttl)
            except Exception as e:
                text = str(e) if isinstance(e, RuntimeError) else None
                answers.append({"error": text})
                continue
        tokens.extend(token for _, token in results)
        answers.append({"results": [[title, normalize(token, tokens)] for title, token in results]})
    return {"calls": read_calls(root), "scrapes": count[0], "runs": answers, "cache": cache_listing(tokens)}


ORIGINAL_PATH = os.environ.get("PATH", "")
YT_INFO = {"extractor": "youtube", "title": "Song", "artist": "Artist", "track": "Track"}


def info(meta):
    """info.json の中身（yt-dlp と同じく ensure_ascii=False で書く）。"""
    return json.dumps(meta, ensure_ascii=False)


def cases():
    """例の一覧。"""
    sc = "https://soundcloud.com/a/b"
    sid = ["scid" + str(i) * 28 for i in range(1, 4)]
    fail_sc = {"exit": 1, "stderr": CLIENT_ID_ERROR}
    ok = {"files": {"Song.mp3": "MP3DATA", "Song.info.json": info(YT_INFO)}}
    return [
        {"id": "ok", "steps": [ok]},
        {"id": "ok-ttl", "ttl": 7200, "steps": [ok]},
        {"id": "ok-ttl-60", "ttl": 60, "steps": [ok]},
        {"id": "no-info", "steps": [{"files": {"曲 名.mp3": "x"}}]},
        {"id": "info-empty", "steps": [{"files": {"a.mp3": "x", "a.info.json": "{}"}}]},
        {"id": "info-list", "steps": [{"files": {"a.mp3": "x", "a.info.json": "[1]"}}]},
        {"id": "info-empty-list", "steps": [{"files": {"a.mp3": "x", "a.info.json": "[]"}}]},
        {"id": "info-string", "steps": [{"files": {"a.mp3": "x", "a.info.json": '"t"'}}]},
        {"id": "info-broken", "steps": [{"files": {"a.mp3": "x", "a.info.json": "{nope"}}]},
        {"id": "info-not-utf8", "steps": [{"files": {"a.mp3": "x", "a.info.json": {"hex": "7b2274223a22ff227d"}}}]},
        {"id": "info-bom", "steps": [{"files": {"a.mp3": "x", "a.info.json": "﻿{}"}}]},
        {
            "id": "info-sanitize",
            "steps": [{"files": {"a.mp3": "x", "a.info.json": info({"title": 'A/B\\C:"D"*?', "uploader": "<U>"})}}],
        },
        {"id": "info-long-title", "steps": [{"files": {"a.mp3": "x", "a.info.json": info({"title": "長" * 130})}}]},
        {"id": "info-symbols-only", "steps": [{"files": {"a.mp3": "x", "a.info.json": info({"title": "???"})}}]},
        {"id": "two-files", "steps": [{"files": {"b.mp3": "B", "a.mp3": "A", "a.info.json": info(YT_INFO)}}]},
        {"id": "other-files", "steps": [{"files": {"a.mp3": "A", "a.jpg": "J", "a.webm": "W", "x.mp3.part": "P"}}]},
        {"id": "upper-ext", "steps": [{"files": {"A.MP3": "A"}}]},
        {"id": "no-files", "steps": [{}]},
        {"id": "fail", "steps": [{"exit": 1, "stderr": "ERROR: [youtube] x: Video unavailable\n"}]},
        {"id": "fail-long", "steps": [{"exit": 2, "stderr": "エラー" * 300 + "\nEND"}]},
        {"id": "fail-not-utf8", "steps": [{"exit": 1, "stderr": {"hex": "626164ff0a"}}]},
        {"id": "fail-with-files", "steps": [{"exit": 1, "stderr": "partial", "files": {"a.mp3": "A"}}]},
        {"id": "youtube-client-id-error", "steps": [fail_sc]},
        {"id": "sc-retry-ok", "url": sc, "scrape": [sid[0]], "steps": [fail_sc, ok]},
        {"id": "sc-retry-force-ok", "url": sc, "scrape": [sid[0], sid[1]], "steps": [fail_sc, fail_sc, ok]},
        {"id": "sc-retry-force-same", "url": sc, "scrape": [sid[0], sid[0]], "steps": [fail_sc, fail_sc]},
        {"id": "sc-scrape-none", "url": sc, "scrape": [], "steps": [fail_sc]},
        {"id": "sc-scrape-none-then-id", "url": sc, "scrape": [None, sid[2]], "steps": [fail_sc, ok]},
        {
            "id": "sc-retry-other-error",
            "url": sc,
            "scrape": [sid[0]],
            "steps": [fail_sc, {"exit": 1, "stderr": "other"}],
        },
        {"id": "sc-env", "url": sc, "env_client_id": sid[2], "steps": [fail_sc, ok]},
        {"id": "sc-env-fails", "url": sc, "env_client_id": sid[2], "steps": [fail_sc, fail_sc]},
        {"id": "sc-other-error", "url": sc, "scrape": [sid[0]], "steps": [{"exit": 1, "stderr": "boom"}]},
        {"id": "sc-short-url", "url": "https://on.soundcloud.com/x", "scrape": [sid[0]], "steps": [fail_sc, ok]},
        {
            "id": "sc-cached",
            "url": sc,
            "scrape": [sid[0], sid[1]],
            "runs": [{}, {}],
            "steps": [fail_sc, ok, fail_sc, ok],
        },
        {
            "id": "sc-exit-0-with-error",
            "url": sc,
            "scrape": [sid[0]],
            "steps": [{"exit": 0, "stderr": CLIENT_ID_ERROR}],
        },
        {
            "id": "two-runs",
            "runs": [{"ttl": 600}, {"ttl": 900, "url": "https://youtu.be/b"}],
            "steps": [ok, {"files": {"c.mp3": "C"}}],
        },
    ]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for case in cases():
        answer = await run(case)
        print(json.dumps([case, answer], ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
