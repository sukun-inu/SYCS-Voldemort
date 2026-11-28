"""DJAudio の部品（Discord にも yt-dlp にも触らない関数）の基準（pure_expected.jsonl）を、本物の Python から作る。

1 行に 1 例。``[種類, 入力, 本物の Python の答え]``。種類ごとに呼ぶ関数:

- runtime: `settings_store.get_djaudio_runtime_settings`（設定の置き場は本物のファイル版を一時ディレクトリで使う。
  設定が無いときの値は `config` を書き換えて変える）
- site: `djaudio_site_detection.is_unsupported_url`・`is_djaudio_allowed_url`
- detect: `djaudio_site_detection.detect_site`
- soundcloud: `djaudio_service._is_soundcloud_url`
- extract: `djaudio_service._extract_urls`
- title: `djaudio_service._format_title_from_metadata`
- sanitize: `djaudio_cache._sanitize_filename`
- lower: `str.lower`
- stem: `pathlib.Path` の `stem` と `with_suffix(".info.json")` の名前
- client_id: `djaudio_service._SC_CLIENT_ID_PATTERNS` を順に `search` したもの
- scripts: `re.findall(r'src=["\\']([^"\\']+\\.js)["\\']', html)`
- embed: `djaudio_service._build_result_embed`（`DJAUDIO_BASE_URL` は例ごとに変える）

本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて動かす:

    python generate_pure.py > pure_expected.jsonl
"""

import json
import os
import random
import re
import sys
import tempfile
from pathlib import Path

SETTINGS_DIR = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = SETTINGS_DIR
os.environ["SETTINGS_BACKEND"] = "file"
os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, "/app")
import config  # noqa: E402
from services import djaudio_cache, djaudio_service, djaudio_site_detection, settings_store  # noqa: E402

GUILD = 1399617700363370556
OUT = []


def emit(kind, given, answer):
    """1 例を書き出す。"""
    OUT.append([kind, given, answer])


def write_settings(guild_settings):
    """設定のファイルを書き直し、読み込み済みの控えを捨てる。"""
    path = os.path.join(SETTINGS_DIR, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"guilds": {str(GUILD): guild_settings}}, f, ensure_ascii=False)
    settings_store._cache = None
    settings_store._cache_sig = None


def run_runtime(guild_settings, defaults):
    """設定と既定の値から、実行のときの設定を求める（チャンネルの ID は文字にする）。"""
    write_settings(guild_settings)
    config.DJAUDIO_CACHE_TTL, config.DJAUDIO_COOLDOWN, config.DJAUDIO_MAX_URLS = defaults
    r = settings_store.get_djaudio_runtime_settings(GUILD)
    output = None if r.output_channel_id is None else str(r.output_channel_id)
    return [str(r.watch_channel_id), r.cache_ttl, r.cooldown, r.max_urls, output]


RUNTIME = [
    {},
    {"djaudio": {"watch_channel_id": 123}},
    {"djaudio_watch_channel_id": 5, "djaudio": {"watch_channel_id": 6}},
    {"djaudio_watch_channel": "７７", "djaudio": {"channel_id": 9}},
    {"djaudio_watch_channel_id": 0, "djaudio_watch_channel": -3, "djaudio": {"watch_channel_id": "x", "channel_id": 4}},
    {"djaudio_watch_channel_id": " 1_234 ", "djaudio": "broken"},
    {"djaudio_watch_channel_id": True},
    {"djaudio_watch_channel_id": False, "djaudio": {"channel_id": 2.9}},
    {"djaudio_watch_channel_id": "123456789012345678901234567890"},
    {"djaudio_watch_channel_id": [1], "djaudio": {"watch_channel_id": {"a": 1}}},
    {"djaudio_watch_channel_id": None, "djaudio": {"watch_channel_id": None, "channel_id": "+8"}},
    {"djaudio_watch_channel_id": "1__2"},
    {"djaudio_watch_channel_id": "٣"},
    {"djaudio_watch_channel_id": "0x10"},
    {"djaudio": {"output_channel_id": 77}},
    {"djaudio": {"output_channel_id": "0"}},
    {"djaudio": {"output_channel_id": -1}},
    {"djaudio": {"output_channel_id": " 99 "}},
    {"djaudio": {"output_channel_id": 5.5}},
    {"djaudio_output_channel_id": 5},
    {"djaudio": {"cache_ttl": 5, "cooldown": -3, "max_urls": 50}},
    {"djaudio": {"cache_ttl": 3600, "cooldown": 0, "max_urls": 0}},
    {"djaudio": {"cache_ttl": None}, "djaudio_cache_ttl": 1200},
    {"djaudio_cache_ttl": "1_200", "cooldown": 30.9, "max_urls": "７"},
    {"cache_ttl": 100, "djaudio_cache_ttl": 200},
    {"cache_ttl": None, "djaudio_cache_ttl": 200},
    {"djaudio_cache_ttl": None, "djaudio_cooldown": None, "djaudio_max_urls": None},
    {"djaudio": {"cache_ttl": "abc", "cooldown": [], "max_urls": {}}},
    {"djaudio": {"cache_ttl": True, "cooldown": True, "max_urls": True}},
    {"djaudio": {"cache_ttl": 59.99, "cooldown": "  12  ", "max_urls": -5}},
    {"djaudio": {"cache_ttl": "1e3", "cooldown": "1.5", "max_urls": "3.0"}},
    {"djaudio": {"cache_ttl": 2592000, "cooldown": 3601, "max_urls": 10}},
    {"djaudio": {"cache_ttl": "-0", "cooldown": "-0", "max_urls": "-0"}},
    {"djaudio": []},
    {"djaudio": {"watch_channel_id": 10, "output_channel_id": 10, "cache_ttl": 61}},
]
DEFAULTS = [(600, 30, 3), (0, 0, 1), (59, 5, 10), (3600, 7, 2)]


SITES = [
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://youtube.com/shorts/abc",
    "https://YOUTU.BE/abc",
    "https://music.youtube.com/watch?v=x",
    "https://m.youtube.com/watch?v=x",
    "https://soundcloud.com/a/b",
    "https://on.soundcloud.com/xyz",
    "https://www.soundcloud.com/a",
    "https://m.soundcloud.com/a",
    "https://www.nicovideo.jp/watch/sm9",
    "https://nico.ms/sm9",
    "https://sp.nicovideo.jp/watch/sm9",
    "https://www.tiktok.com/@a/video/1",
    "https://vm.tiktok.com/ZM/",
    "https://vt.tiktok.com/ZS/",
    "https://bandcamp.com/x",
    "https://artist.bandcamp.com/track/song",
    "https://a.b.bandcamp.com/album/x",
    "https://bandcamp.com.evil.example/",
    "https://evilbandcamp.com/",
    "https://youtube.com.evil.example/",
    "https://www.www.youtube.com/",
    "https://user:pw@youtube.com:8443/x",
    "http://youtube.com/x",
    "https://youtube.com./x",
    "https://[::1]/x",
    "https://[abc/",
    "https://youtube.com]/",
    "https://youtube.com／x/",
    "https://ｙoutube.com/",
    "https://YouTube.COM/",
    "https://xn--youtube-.com/",
    "ftp://youtube.com/x",
    "youtube.com/x",
    "https://open.spotify.com/track/1",
    "https://OPEN.SPOTIFY.COM/track/1",
    "https://open.ſpotıfy.com/",
    "https://open.spotİfy.com/",
    "https://openXspotify.com/",
    "https://youtu.be/x?ref=open.spotify.com",
    "https://music.apple.com/jp/album/1",
    "https://Music.Apple.Com/",
    "https://music.apple.co/",
    "https://music.amazon.co.jp/albums/1",
    "https://music.amazon.com/albums/1",
    "https://music.amazon.de/albums/1",
    "https://music.amazon.co.uk/",
    "https://youtube.com/?q=music.amazon.com",
    "https://soundcloud.com/x?a=music.apple.com&b=open.spotify.com",
    "https://K.example/",
    "https://www.youtube.com:abc/",
    "https://@youtube.com/",
    "https://youtube.com@evil.example/",
    "https://evil.example@youtube.com/",
    "https://youtube.com%2F@evil/",
    "https://[v1.abc]/",
    "https://[1.2.3.4]/",
    "https://bandcamp.com:443/",
    "https://www.bandcamp.com/",
    "https://x.bandcamp.com.",
]


DETECT = [
    {"extractor": "youtube"},
    {"extractor": "Youtube:tab"},
    {"extractor": "", "extractor_key": "Youtube"},
    {"extractor_key": "SoundcloudIE"},
    {"extractor": "Bandcamp:album"},
    {"extractor": "niconico"},
    {"extractor": "NicovideoIE"},
    {"extractor": "TikTok"},
    {"extractor": "generic", "webpage_url": "https://www.youtube.com/watch?v=x"},
    {"extractor": "generic", "url": "https://youtu.be/x"},
    {"webpage_url": "", "url": "https://soundcloud.com/x"},
    {"webpage_url": "https://x.bandcamp.com/track/a"},
    {"webpage_url": "https://www.nicovideo.jp/watch/sm9"},
    {"webpage_url": "https://www.tiktok.com/@a"},
    {"webpage_url": "https://example.com/a.mp3"},
    {},
    {"extractor": 0, "extractor_key": "youtube"},
    {"extractor": None, "webpage_url": None, "url": "HTTPS://YOUTUBE.COM/"},
    {"extractor": 123},
    {"extractor": ["youtube"]},
    {"extractor": {"youtube": 1}},
    {"extractor": True},
    {"extractor": "KICK", "webpage_url": "https://tikKok.com/"},
    {"extractor": "TIKKOK"},
    {"extractor": "generic", "webpage_url": ["https://youtu.be/x"]},
    {"extractor": "soundcloud", "webpage_url": "https://youtube.com"},
    {"extractor": "nico"},
    {"extractor": "bandcamp", "webpage_url": "https://soundcloud.com"},
]


SOUNDCLOUD = [
    "https://soundcloud.com/a",
    "https://www.soundcloud.com/a",
    "https://on.soundcloud.com/a",
    "https://m.soundcloud.com/a",
    "https://SOUNDCLOUD.COM/a",
    "https://soundcloud.com:443/a",
    "https://user@soundcloud.com/a",
    "https://soundcloud.com.evil/",
    "https://youtube.com/?soundcloud.com",
    "https://www.on.soundcloud.com/",
]


EXTRACT = [
    ("見て https://youtu.be/a", 3),
    ("<https://youtu.be/a>", 3),
    ("(https://youtu.be/b).", 3),
    ("https://youtu.be/a https://youtu.be/a https://youtu.be/b", 3),
    ("https://a.b https://c.d https://e.f https://g.h", 2),
    ("https://a.b https://c.d https://e.f https://g.h", 10),
    ("HTTPS://upper.case", 3),
    ("http:// https://x.y/z!?", 3),
    ("https://x.y/z),.;:!?", 3),
    ("https://x.y/(a)", 3),
    ("https://x.y/<a>", 3),
    ("<<https://x.y>>", 3),
    ("https://x.y/a　https://x.y/b", 3),
    ("https://x.y/a\x1chttps://x.y/b", 3),
    ("https://x.y/a b", 3),
    ("https://x.y/a​b", 3),
    ("texthttps://x.y/a", 3),
    ("httphttps://x.y/a", 3),
    ("https://a.bhttps://c.d", 3),
    ("https://", 3),
    ("https://>", 3),
    ("https://.", 3),
    ("https://x.y/ https://x.y", 3),
    ("https://x.y/ https://x.y/", 3),
    ("", 3),
    ("no urls here", 3),
    ("https://x.y/\nhttps://z.w/\thttps://q.r/", 3),
    ("https://x.y/a😀b", 3),
    ("https://ｘ.y/a", 3),
    ("http://a.b/:)", 1),
]


TITLES = [
    {"extractor": "youtube", "title": "Song", "uploader": "Channel"},
    {"extractor": "youtube", "title": "Song", "artist": "Art", "track": "Trk"},
    {"extractor": "youtube", "title": "Song", "artist": "ABC", "track": "abc - Trk"},
    {"extractor": "youtube", "title": "Song", "artist": "Art"},
    {"extractor": "youtube", "title": "art - Song", "artist": "ART"},
    {"extractor": "youtube", "title": "Song", "artist": "   ", "uploader": "Up"},
    {"extractor": "youtube", "title": "Song", "creator": "Cr"},
    {"extractor": "youtube", "title": "Song"},
    {"extractor": "youtube", "title": "", "artist": "A", "track": "T"},
    {"extractor": "youtube", "title": "", "track": "T"},
    {"extractor": "youtube", "title": "  "},
    {"extractor": "soundcloud", "title": "Song", "uploader": "Up"},
    {"extractor": "soundcloud", "title": "Song"},
    {"extractor": "soundcloud", "title": "up - Song", "uploader": "UP"},
    {"extractor": "bandcamp", "title": "Song", "artist": "Ar", "track": "Tr"},
    {"extractor": "bandcamp", "title": "Song", "track": "Tr"},
    {"extractor": "bandcamp", "title": "Song"},
    {"extractor": "niconico", "title": "動画  タイトル", "artist": "x", "uploader": "y"},
    {"extractor": "tiktok", "title": "clip", "uploader": "user"},
    {"extractor": "tiktok", "title": "clip", "artist": "a"},
    {"extractor": "generic", "title": "T", "album_artist": "AA"},
    {"extractor": "generic", "title": "T", "alt_title": "Alt"},
    {"extractor": "generic", "title": "T", "release_title": "R"},
    {"extractor": "generic", "title": "T"},
    {},
    {"title": None, "artist": None},
    {"title": 123, "artist": 4.5},
    {"title": ["a", "b"], "uploader": {"k": "v"}},
    {"title": True, "artist": False, "track": 0},
    {"title": "a\tb\nc　d\x1ce", "artist": " x  y "},
    {"extractor": "youtube", "title": "ΟΔΟΣ", "artist": "οδοσ"},
    {"extractor": "youtube", "title": "x", "artist": "ΟΔΟΣ", "track": "οδος song"},
    {"extractor": "youtube", "title": "x", "artist": "İstanbul", "track": "i̇stanbul live"},
    {"extractor": "youtube", "title": "x", "artist": "istanbul", "track": "İstanbul"},
    {"extractor": "youtube", "title": "x", "artist": "Kelvin", "track": "kelvin x"},
    {"extractor": "youtube", "title": "x", "artist": "STRASSE", "track": "straße"},
    {"extractor": "youtube", "title": "x", "artist": "Ɤ", "track": "ɤ song"},
    {"extractor": "youtube", "title": "x", "artist": "\U00010d50", "track": "\U00010d70 z"},
    {"extractor": "generic", "title": "Same", "artist": "Same"},
    {"extractor": "generic", "title": "SAME", "artist": "same"},
    {"extractor": "generic", "title": "Song", "artist": "Song (Remix)"},
    {"extractor": "youtube", "title": "Song", "artist": "", "uploader": ""},
    {"extractor": "youtube", "title": "Song", "artist": "", "uploader": 0, "creator": "C"},
    {"extractor": "youtube", "title": "Song", "uploader": " "},
    {"extractor": "youtube", "title": "Song", "uploader": 7},
    {"webpage_url": "https://youtu.be/x", "title": "T", "uploader": "U"},
]


SANITIZE = [
    ("Song", "tok"),
    (" a/b\\c:d*e  f ", "tok"),
    ("曲名【公式】 (MV) [4K] {x} 😀", "tok"),
    ("???", "tok"),
    ("", "tok"),
    ("   ", "tok"),
    ("a_b-c.d", "tok"),
    ('<>:"|?*', "tok"),
    ("a　b\x1cc d", "tok"),
    ("é ü ß ﬁ", "tok"),
    ("́abć", "tok"),
    ("١٢٣ ½ ² Ⅻ", "tok"),
    ("a" * 130, "tok"),
    ("あ" * 121, "tok"),
    (("x " * 70), "tok"),
    ("  ..  ", "tok"),
    ("a/b/c", "tok"),
    ("a\\b", "tok"),
    ("#hash&amp;", "tok"),
    ("  (  )  ", "tok"),
    ("tab\there", "tok"),
    ("new\nline", "tok"),
    ("😀😀", "tok"),
    ("ｆｕｌｌ　ｗｉｄｔｈ", "tok"),
    ("​zero​width", "tok"),
    ("mix.ed_.-(1)[2]{3}", "tok"),
]


LOWER = [
    "ABC Ä",
    "İ",
    "K",
    "ΣΑΣ ΟΔΟΣ.",
    "Σ",
    "AΣ'b",
    "AΣ'",
    "AΣ'Σ",
    "1Σ",
    "ÁΣ",
    "AΣ́",
    "AΣ́B",
    "ΣͅΣ",
    "ΑΣ ΣΑ",
    "ǅ ǈ ǋ",
    "STRASSE ẞ",
    "Ɤ Ꟍ Ꟛ",
    "\U00010d50\U00010d70",
    "\U0001e900",
    "Ꭰ ꭰ",
    "Ⴀ",
    "ΑΣ.Σ",
    "ΑΣ:",
    "x" + "Σ" * 3,
    "",
    "日本語 English ÉCOLE",
]


STEMS = [
    "Song.mp3",
    "a.b.mp3",
    ".mp3",
    "noext",
    "trail.",
    "..mp3",
    "x.MP3",
    "曲.mp3",
    "a..mp3",
    ".hidden.mp3",
]


CLIENT_JS = [
    'x={client_id : "%s"}' % ("a" * 32),
    'client_id:"%s"' % ("A1" * 10),
    '"client_id":"%s"' % ("b" * 32),
    '"client_id" : "%s"' % ("b" * 32),
    'client_id = "%s"' % ("c" * 32),
    "client_id: '%s'" % ("d" * 32),
    "client_id='%s'" % ("d" * 32),
    'client_id:"%s"' % ("e" * 19),
    'client_id:"%s"' % ("e" * 20),
    'client_id:"%s"' % ("e" * 64),
    'client_id:"%s"' % ("e" * 65),
    'client_id:"%s-x"' % ("e" * 30),
    'client_id　:　"%s"' % ("f" * 32),
    'client_id\x1c:"%s"' % ("f" * 32),
    'client_id:"short" client_id:"%s"' % ("g" * 32),
    'client_id = "%s" client_id:"%s"' % ("h" * 32, "i" * 32),
    'client_id: \'%s\' "client_id":"%s"' % ("j" * 32, "k" * 32),
    'CLIENT_ID:"%s"' % ("l" * 32),
    'client_id:"ａ%s"' % ("m" * 31),
    "",
    'client_id:"%s"' % ("n" * 100),
    'xclient_id:"%s"' % ("o" * 32),
]


SCRIPTS_HTML = [
    "<script src=\"https://a/x.js\"></script><script src='/y.js'>",
    '<script src="https://a/x.js?v=1"></script>',
    '<script src=".js"></script>',
    "<script src=\"a.js'>",
    '<script src="a.jsx"></script><script src="b.js">',
    'src="a.js"src="b.js"',
    'src = "a.js"',
    'SRC="a.js"',
    "src='multi\nline.js'",
    'src="x.js.js"',
    "",
    'src="',
    'src="a.js" src="a.js"',
    '<img src="p.png"><script src="https://cdn/app-1a2b.js"></script>',
]


EMBEDS = [
    ([["Song", "0123456789abcdef0123456789abcdef"]], "http://localhost:5001", 600),
    ([["A" * 60, "t1"], ["B", "t2"]], "https://dl.example", 61),
    ([], "https://dl.example", 59),
    ([["曲😀" * 30, "t"]], "https://dl.example/base", 3600),
    ([["", "t"]], "", 120),
]


def client_id_of(js):
    """Python と同じ順に、4 つの形を search する。"""
    for pattern in djaudio_service._SC_CLIENT_ID_PATTERNS:
        m = pattern.search(js)
        if m:
            return m.group(1)
    return None


def embed_of(results, base, ttl):
    """結果の Embed を、比べる形（題・本文・色・項目）にする。"""
    djaudio_service.DJAUDIO_BASE_URL = base
    d = djaudio_service._build_result_embed([tuple(r) for r in results], GUILD, ttl).to_dict()
    fields = [[f["name"], f["value"], bool(f.get("inline", False))] for f in d.get("fields", [])]
    return {"title": d.get("title"), "description": d.get("description"), "color": d.get("color"), "fields": fields}


def random_titles():
    """乱数で作った題（記号・空白・全角・結合文字を混ぜる）。種は固定。"""
    rng = random.Random(20261128)
    alphabet = list('aAbBzZ09 _-.()[]{}<>:"|?*\\/\t　 \x1ćſıİKΣσςéÉ日本😀') + [" "]
    out = []
    for _ in range(80):
        out.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40))))
    return out


def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    for guild_settings in RUNTIME:
        for defaults in DEFAULTS:
            emit("runtime", [guild_settings, list(defaults)], run_runtime(guild_settings, defaults))
    for url in SITES:
        emit(
            "site",
            url,
            [djaudio_site_detection.is_unsupported_url(url), djaudio_site_detection.is_djaudio_allowed_url(url)],
        )
    for info in DETECT:
        emit("detect", info, djaudio_site_detection.detect_site(info))
    for url in SOUNDCLOUD:
        emit("soundcloud", url, djaudio_service._is_soundcloud_url(url))
    for content, limit in EXTRACT:
        emit("extract", [content, limit], djaudio_service._extract_urls(content, limit))
    for meta in TITLES:
        emit("title", meta, djaudio_service._format_title_from_metadata(meta))
    for text in random_titles():
        meta = {"extractor": "youtube", "title": text, "artist": text[:5], "track": text[3:]}
        emit("title", meta, djaudio_service._format_title_from_metadata(meta))
    for value, fallback in SANITIZE + [(t, "tok") for t in random_titles()]:
        emit("sanitize", [value, fallback], djaudio_cache._sanitize_filename(value, fallback))
    for text in LOWER + random_titles():
        emit("lower", text, text.lower())
    for name in STEMS:
        path = Path("/tmp/d") / name
        emit("stem", name, [path.stem, path.with_suffix(".info.json").name if path.stem else None])
    for js in CLIENT_JS:
        emit("client_id", js, client_id_of(js))
    for html in SCRIPTS_HTML:
        emit("scripts", html, re.findall(r'src=["\']([^"\']+\.js)["\']', html))
    for results, base, ttl in EMBEDS:
        emit("embed", [results, base, ttl], embed_of(results, base, ttl))
    for line in OUT:
        print(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


main()
