"""文の整え方・点の付け方・検索語の組み立ての基準を作る（`generate.py text`）。

本物の `services.djaudio_isrc_meta` の関数をそのまま呼ぶ。乱数で作る例は種を固定する（SEED）。
小数は IEEE 754 のビット（64 ビットの整数）で持つ（最後のビットまで比べる）。
"""

import asyncio
import random
import struct
import unicodedata

from services import djaudio_isrc_meta as meta

SEED = 20261128

REAL_TITLES = [
    "YOASOBI「アイドル」 Official Music Video",
    "YOASOBI - アイドル (Official Music Video)",
    "Ado - 唱 (Official Video)",
    "米津玄師 - Lemon (Official Music Video)",
    "Official髭男dism - Pretender［Official Video］",
    "King Gnu - 白日 [Official Video]",
    "Aimer - 残響散歌 (Official Music Video) [4K]",
    "Daft Punk - Get Lucky (Official Audio) ft. Pharrell Williams, Nile Rodgers",
    "Ed Sheeran - Shape of You (Official Music Video)",
    "The Weeknd - Blinding Lights (Official Audio)",
    "Billie Eilish - bad guy (Lyrics)",
    "Queen – Bohemian Rhapsody (Official Video Remastered)",
    "a-ha - Take On Me (Official Video) [Remastered in 4K]",
    "Rick Astley - Never Gonna Give You Up (Official Music Video)",
    "Avicii - Levels (Extended Mix)",
    "Calvin Harris - Summer (Radio Edit)",
    "Song Title feat. Someone",
    "Song Title ft Someone Else",
    "Song Title (feat. Someone) [Live]",
    'Song Title (from "Movie")',
    "Song Title【MV】",
    "Song Title [MV]",
    "Song Title (M/V)",
    "Song Title (PV)",
    "Song Title (2019 Remaster)",
    "Song Title (Remastered 2011)",
    "Song Title (Live ver.)",
    "Song Title (short ver.)",
    "Song Title (Ver. 2)",
    "Song Title (version)",
    "Song Title (TV size)",
    "Song Title (日本語字幕)",
    "Song Title (한국어 ver)",
    "Song Title (sub indo)",
    "Song Title (subtitles english)",
    "Song Title (visualiser)",
    "Song Title (Visualizer)",
    "Song Title (HD)",
    "Song Title (HQ Video)",
    "Song Title (8K)",
    "Song Title (Audio Only)",
    "Song Title (Full Album)",
    "Song Title (Full Version)",
    "Song Title (Original Mix)",
    "Song Title (Single Version)",
    "Song Title (Music Video)",
    "Song Title (Official Lyric Video)",
    "Song Title (Official Lyrics)",
    "Song Title (Official Clip)",
    "Song Title (Official MV)",
    "Song Title (Official Visualizer)",
    "Song Title - Topic",
    "Artist - Topic",
    "Artist / Topic",
    "【初音ミク】メルト【オリジナル】",
    "【MV】YOASOBI「夜に駆ける」",
    "【歌ってみた】千本桜 / 歌い手",
    "【東方】Bad Apple!! feat.nomico【PV】",
    "ハルジオン / YOASOBI",
    "original sound - user123",
    "Lofi Hip Hop Radio 📚 beats to relax/study to",
    "BTS (방탄소년단) 'Dynamite' Official MV",
    "BLACKPINK - 'How You Like That' M/V",
    "周杰倫 Jay Chou【告白氣球 Love Confession】Official MV",
    "Song (feat. A) (feat. B)",
    "(Official Video)",
    "[4K]",
    "feat. Someone",
    " ft. x",
    "Title -",
    "Title - ",
    "Title |",
    "Title //",
    "Title \\",
    "Title_",
    "  spaced   out   title  ",
    "tab\tseparated\ttitle",
    "line\nbreak feat. x",
    "line feat. x\n",
    "x feat  ",
    "x feat \n",
    "Ｆｕｌｌｗｉｄｔｈ　Ｔｉｔｌｅ",
    "ｶﾀｶﾅ ﾀｲﾄﾙ",
    "Café del Mar (Énergie mix)",
    "ΟΔΟΣ ΣΤΗ ΘΑΛΑΣΣΑ",
    "ΣΑΣ ΣΣ Σ ΑΣ",
    "İstanbul (Live)",
    "ıstanbul",
    "ſong (ſhort ſub ſ)",
    "Kelvin (K version)",
    "OFFİCİAL (Offıcıal Vıdeo)",
    "𝐁𝐨𝐥𝐝 𝐓𝐢𝐭𝐥𝐞",
    "① ② ③",
    "Ⅳ Ⅻ ⅷ",
    "ﬁne ﬂow",
    "",
    "-",
    "---",
    "Ⓐⓑ",
    "한국어 노래 제목",
    "A — B",
    "A – B",
    "A － B",
    "A-B",
    "A -B",
    "A - B - C",
    "Song (2020)",
    "Song (2020 version)",
    "Song (２０２０)",
    "Song (١٩٩٩)",
    "Song (live version)",
    "Song (Live Ver)",
    "Song (remastered)",
    "Song [Audio]",
    "Song [video only]",
    "Song (official   music   video)",
    "Song ( Official Video )",
    "Song (Official Video",
    "Song Official Video)",
    "Song (Official Video]",
    "Song 【Official Video)",
    "Song ((Official Video))",
    "Song (Official Video) (Official Audio)",
]

NOISE = [
    "Official Video",
    "official music video",
    "OFFICIAL AUDIO",
    "Official MV",
    "Official Visualizer",
    "Official Lyric Video",
    "Official Lyrics",
    "Official Clip",
    "HD",
    "4K",
    "8k video",
    "HQ",
    "Full Song",
    "Full Album",
    "Audio",
    "Video Only",
    "Remaster",
    "Remastered",
    "Remastered 2009",
    "Extended Mix",
    "Radio Edit",
    "Album Version",
    "Single Edit",
    "from Movie",
    "feat. Someone",
    "ft Someone",
    "Lyrics",
    "lyric",
    "MV",
    "M/V",
    "PV",
    "P/V",
    "2019",
    "2019 Version",
    "Live",
    "Live Ver",
    "Live Version",
    "ver.",
    "Ver. 2",
    "version",
    "Short Ver",
    "short version",
    "Music Video",
    "Visualiser",
    "visualizer",
    "Sub Indo",
    "Subtitles English",
    "subs 日本語",
    "日本語字幕",
    "英語ver",
    "한국어",
    "中文 字幕",
    "Acoustic",
    "Cover",
    "Instrumental",
    "TV Size",
    "Prod. X",
]

BASES = [
    "Song Title",
    "Artist - Song",
    "夜に駆ける",
    "Ado - 唱",
    "Bad Apple!!",
    "Lemon",
    "Shape of You",
    "Don't Stop Me Now",
    "A&B = C + D",
    "100% Pure",
    "Title / Subtitle",
    "What's Up? #1",
    "Σίσυφος",
    "Ünïcödé Sóng",
]

POOLS = [
    (0x20, 0x7E),
    (0xA0, 0xFF),
    (0x100, 0x24F),
    (0x300, 0x36F),
    (0x370, 0x3FF),
    (0x400, 0x4FF),
    (0x530, 0x58F),
    (0x10A0, 0x10FF),
    (0x13A0, 0x13FD),
    (0x1E00, 0x1EFF),
    (0x1F00, 0x1FFF),
    (0x2000, 0x206F),
    (0x2150, 0x218F),
    (0x2460, 0x24FF),
    (0x3000, 0x30FF),
    (0x3200, 0x33FF),
    (0x4E00, 0x4E80),
    (0xAC00, 0xAD00),
    (0x1100, 0x11FF),
    (0xFB00, 0xFB4F),
    (0xFE30, 0xFE4F),
    (0xFF00, 0xFFEF),
    (0x0600, 0x06FF),
    (0x0900, 0x097F),
    (0x0E00, 0x0E7F),
    (0x1D400, 0x1D7FF),
    (0x1F300, 0x1F6FF),
    (0x1CC00, 0x1CEBF),
    (0x10780, 0x107BF),
    (0xE0000, 0xE007F),
    (0x0370, 0x0380),
    (0x1C, 0x1F),
    (0x00, 0x1F),
]

SPACES = [" ", "  ", "\t", "　", "\xa0", "\n", " ", " 　 "]
OPENS = ["(", "[", "【", "（", "［"]
CLOSES = [")", "]", "】", "）", "］"]


def bits(value):
    """小数の IEEE 754 のビット。"""
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def odd_case(rnd, text):
    """大文字小文字をでたらめにし、ときどき IGNORECASE で当たる特別な文字（ſ・K・İ・ı）に変える。"""
    out = []
    for c in text:
        r = rnd.random()
        if c in "sS" and r < 0.1:
            out.append("ſ")
        elif c in "kK" and r < 0.2:
            out.append("K")
        elif c in "iI" and r < 0.1:
            out.append("İ" if r < 0.05 else "ı")
        elif r < 0.5:
            out.append(c.upper())
        else:
            out.append(c.lower())
    return "".join(out)


def decorated(rnd):
    """題に飾り（括弧の中の決まり文句・feat.・ダッシュ・空白）をでたらめに付ける。"""
    title = rnd.choice(BASES)
    for _ in range(rnd.randrange(4)):
        noise = odd_case(rnd, rnd.choice(NOISE))
        i = rnd.randrange(len(OPENS))
        close = CLOSES[i] if rnd.random() < 0.85 else rnd.choice(CLOSES)
        inner = rnd.choice(["", " ", "  ", "　"])
        piece = f"{OPENS[i]}{inner}{noise}{inner}{close}"
        sep = rnd.choice(SPACES + [""])
        title = f"{title}{sep}{piece}" if rnd.random() < 0.8 else f"{piece}{sep}{title}"
    if rnd.random() < 0.3:
        title += rnd.choice([" feat. X", " ft Y", " FEAT.  Z & W", " Ft. ", " feat.\tA", "feat. B"])
    if rnd.random() < 0.2:
        title += rnd.choice([" -", " - ", " | ", "_", " /", " \\", "  -  _ "])
    if rnd.random() < 0.2:
        title = rnd.choice(["Artist", "アーティスト", "A"]) + rnd.choice([" - ", " — ", " – ", " － ", "-"]) + title
    return title


def random_text(rnd, length):
    """いろいろな文字の並びから、でたらめな文を作る。"""
    out = []
    for _ in range(length):
        lo, hi = rnd.choice(POOLS)
        code = rnd.randint(lo, hi)
        if 0xD800 <= code <= 0xDFFF:
            code = 0x41
        out.append(chr(code))
    return "".join(out)


def clean_inputs(rnd):
    """整え方の例（実際の題・飾りを付けた題・でたらめな文・長い文）。"""
    inputs = list(REAL_TITLES)
    inputs += [decorated(rnd) for _ in range(1500)]
    inputs += [random_text(rnd, rnd.randrange(0, 40)) for _ in range(800)]
    inputs += [random_text(rnd, rnd.randrange(180, 260)) for _ in range(60)]
    inputs += [
        "".join(rnd.choice("ab (feat. x) - Official Video") for _ in range(rnd.randrange(190, 230))) for _ in range(30)
    ]
    return inputs


def check_strip_marks_concat(rnd):
    """NFKD して結合文字を除いたものが、1 文字ずつの結果をつないだものと同じであること（Rust の写し方の前提）。"""

    def strip(text):
        """`_normalize_for_compare` の前半。"""
        return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))

    for _ in range(3000):
        text = random_text(rnd, rnd.randrange(1, 30))
        assert strip(text) == "".join(strip(c) for c in text), repr(text)


def clean_cases(rnd):
    """[入力, _clean_title, _normalize_for_compare, _TOPIC_SUFFIX.sub, _DASH_SPLIT.search, split(maxsplit=1)]。"""
    cases = []
    for text in clean_inputs(rnd):
        has_dash = meta._DASH_SPLIT.search(text) is not None
        cases.append(
            [
                text,
                meta._clean_title(text),
                meta._normalize_for_compare(text),
                meta._TOPIC_SUFFIX.sub("", text),
                has_dash,
                meta._DASH_SPLIT.split(text, maxsplit=1),
            ]
        )
    return cases


def similarity_cases(rnd, cleaned):
    """[a, b, _similarity のビット]。"""
    pairs = [
        ("Lemon", "Lemon"),
        ("Lemon", "lemon"),
        ("アイドル", "アイドル"),
        ("ｱｲﾄﾞﾙ", "アイドル"),
        ("Bohemian Rhapsody", "Bohemian Rhapsody - Remastered 2011"),
        ("夜に駆ける", "夜に駆ける (Into The Night)"),
        ("", "x"),
        ("!!!", "x"),
        ("x", ""),
        ("ΟΔΟΣ", "οδος"),
        ("ΟΔΟΣ", "οδοσ"),
        ("a" * 300, "a" * 300),
        ("a" * 300, "ab" * 150),
        ("ab" * 150, "a" * 300),
        ("abc" * 70, "abc" * 70 + "d"),
        ("the quick brown fox " * 12, "the quick brown fox jumps " * 10),
    ]
    for _ in range(900):
        pairs.append((rnd.choice(cleaned), rnd.choice(cleaned)))
    for _ in range(300):
        a = rnd.choice(cleaned)
        b = "".join(c for c in a if rnd.random() < 0.8) + rnd.choice(["", " (Remix)", " - Live", "x"])
        pairs.append((a, b))
    for _ in range(120):
        alphabet = rnd.choice(["ab", "abc ", "aaab", "xyz12", "あい う"])
        a = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(150, 320)))
        b = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(150, 320)))
        pairs.append((a, b))
    return [[a, b, bits(meta._similarity(a, b))] for a, b in pairs]


def outcome(func):
    """関数を呼び、結果か例外の名前を返す。"""
    try:
        return {"ok": func()}
    except Exception as e:  # Python が外へ出す例外の種類そのものを基準にする
        return {"error": type(e).__name__}


def score_cases(rnd):
    """[item, ref_title, ref_artist, 結果（{"ok": ビット} か {"error": 例外の名前}）]。"""
    titles = ["Lemon", "Bad Apple!!", "アイドル", "", None, 5, ["x"], {"a": 1}, 0, "Lemon (Remastered)", "ﾚﾓﾝ"]
    artists = [
        {"name": "Kenshi Yonezu"},
        {"name": ""},
        {"name": None},
        {},
        None,
        "str",
        ["l"],
        {"name": 3},
        0,
        {"n": 1},
    ]
    refs = [None, "", "Kenshi Yonezu", "米津玄師", 5, ["a"], 0, "x", {"k": 1}]
    cases = []
    for t in titles:
        for a in artists:
            for r in refs:
                item = {"title": t, "artist": a}
                ref_title = rnd.choice(["Lemon", "アイドル", "Bad Apple!!", ""])
                result = outcome(lambda: bits(meta._score_result(item, ref_title, r)))
                cases.append([item, ref_title, r, result])
    for item in [{}, {"title": "Lemon"}, "str", 5, None, [1], {"artist": {"name": "x"}}]:
        for r in [None, "x"]:
            result = outcome(lambda: bits(meta._score_result(item, "Lemon", r)))
            cases.append([item, "Lemon", r, result])
    return cases


def query_cases(rnd, cleaned):
    """[title, artist, site, info, _build_search_queries の結果]。"""
    sites = ["youtube", "soundcloud", "bandcamp", "tiktok", "nicovideo", "generic", ""]
    artists = [None, "", "Artist", "米津玄師", 5, ["a", "b"], {"x": 1}, 0, 1.5, True, False, "Artist - Topic"]
    infos = [
        {},
        {"uploader": "Uploader - Topic"},
        {"uploader": "Uploader/Topic  "},
        {"uploader": "  Uploader  "},
        {"uploader": 5},
        {"uploader": ["u"]},
        {"uploader": "TOPIC - topic"},
        {"album": "Album"},
        {"album": "  "},
        {"album": [1, "x"]},
        {"music_title": "MT", "music_author": "MA"},
        {"music_title": " MT ", "music_author": ""},
        {"music_title": None, "music_author": "MA"},
        {"music_title": 7, "music_author": 8.5},
    ]
    titles = list(REAL_TITLES[:60]) + rnd.sample(cleaned, 60)
    titles = [t for t in titles if t]
    cases = []
    for _ in range(1200):
        title = rnd.choice(titles)
        artist = rnd.choice(artists)
        site = rnd.choice(sites)
        info = rnd.choice(infos)
        cases.append([title, artist, site, info, meta._build_search_queries(title, artist, site, info)])
    return cases


class _OneItem:
    """`_fetch_by_search` に渡す偽物の応答（検索結果 1 件）。"""

    status = 200

    async def json(self, content_type=None):
        """検索結果 1 件を返す。"""
        return {"data": [{"title": "x"}]}

    async def __aenter__(self):
        """async with で自分を返す。"""
        return self

    async def __aexit__(self, *exc):
        """何もしない。"""
        return False


class _Session:
    """`_fetch_by_search` に渡す偽物の ClientSession（ネットにはつながない）。"""

    def get(self, *args, **kwargs):
        """いつも検索結果 1 件を返す。"""
        return _OneItem()


def reference_cases(rnd, cleaned):
    """[title, artist, ref_title, ref_artist]。本物の `_fetch_by_search` が `_score_result` に渡す比べる相手。"""
    titles = [t for t in REAL_TITLES if t] + rnd.sample([c for c in cleaned if c], 150)
    artists = [None, "", "Info Artist", 5, ["a"], 0, "  "]
    captured = []
    real = meta._score_result

    def capture(item, ref_title, ref_artist):
        """比べる相手を覚えて、0 点を返す。"""
        captured.append([ref_title, ref_artist])
        return 0.0

    meta._score_result = capture
    cases = []
    try:
        for title in titles:
            artist = rnd.choice(artists)
            captured.clear()
            asyncio.run(meta._fetch_by_search(title, artist, _Session(), site="generic", info={}))
            cases.append([title, artist, *captured[0]])
    finally:
        meta._score_result = real
    return cases


def make():
    """全部の基準を返す。"""
    rnd = random.Random(SEED)
    check_strip_marks_concat(rnd)
    clean = clean_cases(rnd)
    cleaned = [c[1] for c in clean] + [c[0] for c in clean]
    return {
        "seed": SEED,
        "clean": clean,
        "similarity": similarity_cases(rnd, cleaned),
        "score": score_cases(rnd),
        "queries": query_cases(rnd, cleaned),
        "reference": reference_cases(rnd, cleaned),
    }
