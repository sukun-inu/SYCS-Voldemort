"""震度の地図の基準のうち、地図そのもの（範囲の決め方・部品・全体）の例と答えを作る。

generate.py から呼ばれる。本物の services/earthquake_service.py の関数をそのまま動かし、結果（画素の
ハッシュ・決めた範囲・文字を描く呼び出しの記録）を答えにする。外へは何も取りに行かない（タイルは
tiles/ に置いた見本を、決まった規則で配る偽物に差し替える）。

文字は、Rust の側では別の部品（earthquake_text）が描く。ここでは:

  - 文字を「描かずに記録するだけ」にした答え（文字以外の画素を比べるため）
  - 文字の幅（textlength）を控えたもの（Rust の偽物の文字描きが、同じ値を返すため）
  - 文字も描いた最終の画像の答え（文字の部品をつないだあとで比べるため）

を作る。小数は、最後の桁まで同じに伝えるために、ビットの並び（16 進 16 桁）で書く。
"""

import asyncio
import hashlib
import io
import math
import os
import random
import struct

import gen_shapes
import numpy as np
from PIL import Image, ImageDraw

# 文字を描く関数の本物（差し替える前に取っておく）。
REAL_TEXT = ImageDraw.ImageDraw.text
REAL_TEXTLENGTH = ImageDraw.ImageDraw.textlength

PREFS = [
    "北海道",
    "青森県",
    "岩手県",
    "宮城県",
    "秋田県",
    "山形県",
    "福島県",
    "茨城県",
    "栃木県",
    "群馬県",
    "埼玉県",
    "千葉県",
    "東京都",
    "神奈川県",
    "新潟県",
    "富山県",
    "石川県",
    "福井県",
    "山梨県",
    "長野県",
    "岐阜県",
    "静岡県",
    "愛知県",
    "三重県",
    "滋賀県",
    "京都府",
    "大阪府",
    "兵庫県",
    "奈良県",
    "和歌山県",
    "鳥取県",
    "島根県",
    "岡山県",
    "広島県",
    "山口県",
    "徳島県",
    "香川県",
    "愛媛県",
    "高知県",
    "福岡県",
    "佐賀県",
    "長崎県",
    "熊本県",
    "大分県",
    "宮崎県",
    "鹿児島県",
    "沖縄県",
]
SCALES = [10, 20, 30, 40, 45, 50, 55, 60, 70]


def bits(value: float) -> str:
    """小数を、ビットの並び（16 進 16 桁）にする。"""
    return struct.pack(">d", float(value)).hex()


def sha(data: bytes) -> str:
    """SHA-256（16 進）。"""
    return hashlib.sha256(data).hexdigest()


class TextSpy:
    """`ImageDraw` の文字の関数を差し替えて、呼び出しを記録する。`draw` が偽なら、文字は描かない。"""

    def __init__(self, draw: bool) -> None:
        """記録の入れ物を用意する。"""
        self.draw = draw
        self.calls: list[dict] = []
        self.lengths: dict[str, str] = {}

    @staticmethod
    def font_key(font: object) -> tuple[int, bool]:
        """フォントの大きさと、太字かどうか。"""
        return int(font.size), "Bold" in os.path.basename(font.path)

    def __enter__(self) -> "TextSpy":
        """差し替える。"""
        spy = self

        def text(draw, xy, text, fill=None, font=None, anchor=None, *args, **kwargs):
            """`ImageDraw.text` の代わり。呼び出しを記録し、必要なら本物も呼ぶ。"""
            size, bold = spy.font_key(font)
            spy.calls.append(
                {
                    "canvas": list(draw._image.size),
                    "xy": [bits(xy[0]), bits(xy[1])],
                    "text": text,
                    "size": size,
                    "bold": bold,
                    "fill": list(fill),
                    "anchor": anchor or "la",
                }
            )
            if spy.draw:
                REAL_TEXT(draw, xy, text, fill, font, anchor, *args, **kwargs)

        def textlength(draw, text, font=None, *args, **kwargs):
            """`ImageDraw.textlength` の代わり。本物の値を返し、控えておく。"""
            value = REAL_TEXTLENGTH(draw, text, font, *args, **kwargs)
            size, bold = spy.font_key(font)
            spy.lengths[f"{size}|{int(bold)}|{text}"] = bits(value)
            return value

        ImageDraw.ImageDraw.text = text
        ImageDraw.ImageDraw.textlength = textlength
        return self

    def __exit__(self, *exc: object) -> None:
        """元に戻す。"""
        ImageDraw.ImageDraw.text = REAL_TEXT
        ImageDraw.ImageDraw.textlength = REAL_TEXTLENGTH


# ── タイルの見本と、配る規則 ─────────────────────────────


def sample_tiles() -> list[bytes]:
    """タイルの見本（白い面に暗い線）を、色の形を変えて 6 枚。PNG のバイト列で返す。"""
    out = []
    for index, mode in enumerate(["L", "P", "RGB", "1", "RGBA", "LA"]):
        rng = random.Random(100 + index)
        img = Image.new("L", (256, 256), 255)
        pen = ImageDraw.Draw(img)
        for _ in range(7):
            x, y = rng.randrange(256), rng.randrange(256)
            line = [(x, y)]
            for _ in range(rng.randrange(4, 12)):
                x = min(255, max(0, x + rng.randrange(-70, 71)))
                y = min(255, max(0, y + rng.randrange(-70, 71)))
                line.append((x, y))
            pen.line(line, fill=rng.choice([0, 0, 40, 90, 150]), width=rng.choice([1, 1, 2]))
        if mode == "P":
            img = img.convert("RGB").quantize(8)
        elif mode == "RGBA":
            alpha = Image.frombytes("L", (256, 256), bytes((x + y) % 256 for y in range(256) for x in range(256)))
            img = Image.merge("RGBA", (img, img.point(lambda v: v * 3 // 4), img, alpha))
        elif mode == "LA":
            img = Image.merge("LA", (img, img.point(lambda v: 255 - v // 2)))
        else:
            img = img.convert(mode)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        out.append(buf.getvalue())
    return out


def tile_rule(mode: str, count: int, z: int, x: int, y: int) -> int | str | None:
    """そのタイルに何を返すか: 見本の番号・"broken"（PNG でないもの）・None（取れない）。

    Rust のテスト（earthquake_map_golden.rs の `tile_rule`）と同じ規則。
    """
    if mode == "none":
        return None
    if mode == "holes":
        hole = (x + 2 * y) % 5
        if hole == 0:
            return None
        if hole == 1:
            return "broken"
    return (x * 3 + y * 5 + z) % count


# ── 範囲の決め方（_generate_intensity_map の前半） ───────────────────


def point(pref: str, scale: object, addr: str = "") -> dict:
    """観測点（電文の points の 1 件）。"""
    return {"pref": pref, "addr": addr or f"{pref}のどこか", "isArea": False, "scale": scale}


def random_points(rng: random.Random, count: int) -> list[dict]:
    """でたらめな県・でたらめな震度の観測点。同じ県が何度か出る。"""
    prefs = rng.sample(PREFS, min(count, len(PREFS)))
    out = []
    for pref in prefs:
        for _ in range(rng.choice([1, 1, 2])):
            out.append(point(pref, rng.choice(SCALES)))
    rng.shuffle(out)
    return out


def nudged(value: float, steps: int) -> float:
    """浮動小数の目盛りで `steps` 個ぶん、上（正）か下（負）へずらす。"""
    for _ in range(abs(steps)):
        value = math.nextafter(value, math.inf if steps > 0 else -math.inf)
    return value


def flip_point(eq: object, make: object, guess: float) -> tuple[float, float] | None:
    """`make(値)` で作った例の答え（ズームと要るタイル）が切り替わる、隣り合う 2 つの浮動小数を二分探索で探す。

    `guess` は式から逆算した境のあたり。その前後（1e-7 度）で答えが変わらなければ None。
    """

    def key(value: float) -> object:
        """その値での答えのうち、比べるところ。"""
        plan = plan_of(eq, make(value))
        return plan["zoom"], plan["coords"]

    low, high = guess - 1e-7, guess + 1e-7
    low_key = key(low)
    if low_key == key(high):
        return None
    while True:
        middle = (low + high) / 2
        if middle <= low or middle >= high:
            return low, high
        if key(middle) == low_key:
            low = middle
        else:
            high = middle


def boundary_cases(eq: object) -> list[dict]:
    """タイルの番号・ズームが切り替わる、ちょうど境のところの例。

    境の値を式から逆算し、本物の Python で二分探索して「答えが切り替わる、隣り合う 2 つの浮動小数」を
    見つけ、その両側を 1 目盛りずつ 4 つまで並べる。最後の桁の違い（asinh・tan の実装の違い）があると、
    ここで Python と違う答えになる。
    """
    families: list[tuple[str, object, float]] = []
    zoom = 11
    n = 2**zoom
    for pref in ("長野県", "東京都", "北海道", "沖縄県", "鹿児島県"):
        lat_p, lon_p = eq._PREF_CENTERS[pref]
        px_p, py_p = (v * 256 for v in eq._latlon_to_tile_float(lat_p, lon_p, zoom))

        def by_lon(value: float, lat: float = lat_p, pref: str = pref) -> dict:
            """震源の経度だけを動かした例。"""
            return {"lat": bits(lat), "lon": bits(value), "points": [point(pref, 40)]}

        def by_lat(value: float, lon: float = lon_p, pref: str = pref) -> dict:
            """震源の緯度だけを動かした例。"""
            return {"lat": bits(value), "lon": bits(lon), "points": [point(pref, 40)]}

        for side, full in (("left", 0), ("right", 1200)):
            # 横: 左の端（origin_x）・右の端（origin_x + 1200）が、タイルの境（256 の倍数）に乗る震源の経度。
            origin = round((px_p - 600 + full) / 256) * 256 - full
            lon_c = (origin + 600) / 256 / n * 360 - 180
            families.append((f"edge-{side}-{pref}", by_lon, 2 * lon_c - lon_p))
        for side, full in (("top", 0), ("bottom", 720)):
            # 縦: 上の端・下の端が境に乗る震源の緯度（メルカトルを逆に解く）。
            origin = round((py_p - 360 + full) / 256) * 256 - full
            centre_y = (origin + 360) / 256
            lat_c = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * centre_y / n))))
            families.append((f"edge-{side}-{pref}", by_lat, 2 * lat_c - lat_p))
    lat_p, lon_p = eq._PREF_CENTERS["長野県"]
    for zoom in range(6, 12):
        n = 2**zoom
        # ズームの境: 横の幅がちょうど 1200 * 0.92、縦の幅がちょうど 720 * 0.84 になる震源。
        _, ty_p = eq._latlon_to_tile_float(lat_p, lon_p, zoom)
        ty_e = ty_p - (720 * 0.84) / 256
        lat_e = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * ty_e / n))))
        families.append(
            (
                f"zoom-wide-z{zoom}",
                lambda v: {"lat": bits(lat_p), "lon": bits(v), "points": [point("長野県", 40)]},
                lon_p + (1200 * 0.92) / 256 / n * 360,
            )
        )
        families.append(
            (
                f"zoom-tall-z{zoom}",
                lambda v: {"lat": bits(v), "lon": bits(lon_p), "points": [point("長野県", 40)]},
                lat_e,
            )
        )
    cases = []
    for name, make, guess in families:
        found = flip_point(eq, make, guess)
        if found is None:
            raise SystemExit(f"境が見つからない: {name}")
        low, high = found
        for step in range(-4, 0):
            cases.append({"name": f"{name}{step:+d}", **make(nudged(low, step + 1))})
        for step in range(1, 5):
            cases.append({"name": f"{name}{step:+d}", **make(nudged(high, step - 1))})
    return cases


def plan_inputs(eq: object) -> list[dict]:
    """範囲の決め方の例（でたらめなもの・形の崩れたもの・境のもの）。"""
    rng = random.Random(4649)
    cases = []
    for index in range(160):
        lat = round(rng.uniform(24.0, 46.0), rng.choice([1, 1, 2, 4]))
        lon = round(rng.uniform(123.0, 147.0), rng.choice([1, 1, 2, 4]))
        count = rng.choice([1, 1, 2, 3, 5, 8, 15, 47])
        cases.append(
            {"name": f"random-{index:03d}", "lat": bits(lat), "lon": bits(lon), "points": random_points(rng, count)}
        )
    for index in range(30):
        # 震源が遠い（千島・台湾・小笠原など）。
        lat = round(rng.uniform(-10.0, 62.0), 1)
        lon = round(rng.uniform(100.0, 179.0), 1)
        cases.append({"name": f"far-{index:02d}", "lat": bits(lat), "lon": bits(lon), "points": random_points(rng, 3)})
    odd = {
        "no-points": [],
        "all-weak": [point("東京都", 0), point("千葉県", 9), point("埼玉県", -1)],
        "no-scale": [{"pref": "東京都", "addr": "東京都"}],
        "unknown-pref": [point("どこか", 40)],
        "addr-fallback": [{"pref": "", "addr": "東京都", "scale": 40}, {"pref": "関東", "addr": "千葉県", "scale": 30}],
        "pref-missing": [{"addr": "大阪府", "scale": 50}],
        "pref-null": [{"pref": None, "addr": "京都府", "scale": 45}],
        "pref-number": [{"pref": 13, "addr": "東京都", "scale": 30}],
        "addr-number": [{"pref": "", "addr": 5, "scale": 30}, point("東京都", 20)],
        "addr-list": [{"pref": "", "addr": ["東京都"], "scale": 30}],
        "addr-list-known-pref": [{"pref": "東京都", "addr": ["東京都"], "scale": 30}],
        "float-scales": [point("東京都", 45.0), point("千葉県", 45.5), point("埼玉県", 9.99), point("茨城県", 46.0)],
        "unknown-scales": [point("東京都", 46), point("千葉県", 15), point("埼玉県", 99), point("茨城県", 1000)],
        "bool-scale": [point("東京都", True), point("千葉県", 40)],
        "null-scale": [point("東京都", None), point("千葉県", 40)],
        "text-scale": [point("東京都", "40")],
        "list-scale": [point("東京都", [40])],
        "not-a-dict": ["東京都", point("千葉県", 40)],
        "strongest-first": [point("東京都", 30), point("東京都", 50), point("東京都", 40)],
        "strongest-tie": [
            {"pref": "東京都", "addr": "a", "scale": 40},
            {"pref": "", "addr": "東京都", "scale": 40},
            {"pref": "東京都", "addr": "c", "scale": 30},
        ],
        "same-place-other-name": [
            {"pref": "", "addr": "東京都", "scale": 30},
            {"pref": "東京都", "addr": "x", "scale": 50},
        ],
        # 同じ場所・同じ震度で、名前（県の名前が表に無く addr で引いたもの）や字（47 と 47.0）だけが違う。先の方が残る。
        "strongest-tie-other-name": [
            {"pref": "東京都", "addr": "東京都", "scale": 40},
            {"pref": "東京", "addr": "東京都", "scale": 40},
        ],
        "strongest-tie-other-text": [point("東京都", 47), point("東京都", 47.0)],
    }
    for name, points in odd.items():
        cases.append({"name": f"odd-{name}", "lat": bits(35.7), "lon": bits(139.8), "points": points})
    return cases + boundary_cases(eq)


def plan_of(eq: object, case: dict) -> dict:
    """本物の `_generate_intensity_map` に例を与えて、決めた範囲を取り出す（描く手前で止める）。"""
    seen: dict = {}

    async def no_tile(session, z, x, y):
        """タイルは取らない。"""
        return None

    def capture(coords, tiles, origin_x, origin_y, zoom, plot, lat, lon, title, subtitle):
        """`_compose_intensity_map` の代わり。渡されたものを控えて、空の結果を返す。"""
        seen["plan"] = {
            "zoom": zoom,
            "origin": [bits(origin_x), bits(origin_y)],
            "coords": [list(c) for c in coords],
            "plot": [[bits(p[0]), bits(p[1]), scale_text(p[2]), p[3]] for p in plot],
        }
        return io.BytesIO(b"x")

    lat = struct.unpack(">d", bytes.fromhex(case["lat"]))[0]
    lon = struct.unpack(">d", bytes.fromhex(case["lon"]))[0]
    real = (eq._fetch_tile, eq._compose_intensity_map)
    eq._fetch_tile, eq._compose_intensity_map = no_tile, capture
    try:
        result = asyncio.run(eq._generate_intensity_map(None, lat, lon, case["points"], "題", "副題"))
    except Exception as e:
        return {"raises": type(e).__name__}
    finally:
        eq._fetch_tile, eq._compose_intensity_map = real
    if result is None:
        return {"none": True}
    return seen["plan"]


def scale_text(scale: object) -> list:
    """震度の値と、その `str()`（Rust は値を小数で持ち、表に無い震度の札にはこの字を書く）。"""
    return [bits(scale), str(scale)]


# ── 部品（札・震源・地名・帯と凡例・県の塗り） ─────────────────────


def blank(size: tuple[int, int], seed: int) -> Image.Image:
    """部品を載せる下地（でたらめな不透明の色。重ね合わせの計算が効くように）。Rust のテストも同じ式で作る。"""
    pixels = np.frombuffer(gen_shapes.noise(seed, size[0] * size[1] * 4), dtype=np.uint8).copy()
    pixels[3::4] = 255
    return Image.frombytes("RGBA", size, pixels.tobytes())


def piece_inputs() -> list[dict]:
    """部品の例。"""
    cases = []
    for scale in [*SCALES, 46, 15, 100, 45.5]:
        for size in sorted({eq_badge_size(scale) * 2, 36, 68}):
            cases.append({"name": f"badge-{scale}-{size}", "kind": "badge", "scale": scale_text(scale), "size": size})
    for size in (80, 40, 81, 12, 3):
        cases.append({"name": f"marker-{size}", "kind": "marker", "size": size})
    spots = [
        (150.0, 100.0),
        (150.5, 100.49),
        (0.0, 0.0),
        (-20.3, 55.9),
        (299.99, 199.99),
        (310.0, 230.0),
        (-200.0, 50.0),
    ]
    for index, (ex, ey) in enumerate(spots):
        cases.append(
            {
                "name": f"epicentre-{index}",
                "kind": "epicentre",
                "canvas": [300, 200],
                "seed": 30 + index,
                "at": [bits(ex), bits(ey)],
            }
        )
    names = ["東京都", "北海道", "神奈川県", "鹿児島県", "関東", "A", "Tokyo 23", "和歌山県"]
    for index, name in enumerate(names):
        left, top = [(20.0, 30.0), (20.5, 30.25), (-10.75, 5.5), (250.1, 180.9), (0.0, -19.0), (3.999, 7.001)][
            index % 6
        ]
        cases.append(
            {
                "name": f"label-{index}",
                "kind": "label",
                "canvas": [300, 200],
                "seed": 50 + index,
                "at": [bits(left), bits(top)],
                "text": name,
            }
        )
    chrome = [
        ("最大震度 5弱", "福島県沖  M5.2  深さ 40 km  2026年8月24日 12時54分ごろ", [10, 20, 30, 40, 45]),
        ("最大震度 7", "", SCALES),
        ("震度分布", "遠地", [30]),
        ("最大震度 3", "石川県能登地方  M4.1  ごく浅い", [10, 46, 30, 45.5]),
        ("最大震度 6強", "熊本県熊本地方  M7.3  深さ 10 km", [60, 55, 50, 45, 40, 30, 20, 10]),
    ]
    for index, (title, subtitle, scales) in enumerate(chrome):
        cases.append(
            {
                "name": f"chrome-{index}",
                "kind": "chrome",
                "canvas": [760, 420] if index % 2 else [900, 500],
                "seed": 70 + index,
                "title": title,
                "subtitle": subtitle,
                "scales": [scale_text(s) for s in sorted(scales)],
            }
        )
    fills = [
        (8, 139.0, 36.5, ["長野県", "群馬県", "新潟県", "埼玉県", "山梨県"]),
        (7, 141.0, 39.0, ["宮城県", "岩手県", "福島県", "山形県", "秋田県", "青森県"]),
        (9, 139.7, 35.6, ["東京都", "神奈川県", "千葉県"]),
        (6, 131.0, 33.0, ["熊本県", "大分県", "福岡県", "長崎県", "鹿児島県", "宮崎県", "佐賀県"]),
        (5, 138.0, 37.0, PREFS[::3]),
        (10, 127.7, 26.3, ["沖縄県"]),
        (8, 142.5, 43.2, ["北海道", "どこか"]),
    ]
    rng = random.Random(8)
    for index, (zoom, lon, lat, prefs) in enumerate(fills):
        cases.append(
            {
                "name": f"fill-{index}",
                "kind": "fill",
                "canvas": [640, 400],
                "seed": 90 + index,
                "zoom": zoom,
                "centre": [bits(lat), bits(lon)],
                "plot": [[pref, scale_text(rng.choice([*SCALES, 46]))] for pref in prefs],
            }
        )
    return cases


def eq_badge_size(scale: float) -> int:
    """札の一辺（`_badge_size` と同じ。例を作るためだけに使う）。"""
    for limit, size in ((55, 34), (45, 30), (40, 26), (30, 22)):
        if scale >= limit:
            return size
    return 18


def unbits(text: str) -> float:
    """ビットの並びを小数に戻す。"""
    return struct.unpack(">d", bytes.fromhex(text))[0]


def run_piece(eq: object, case: dict) -> Image.Image:
    """部品の例を 1 つ、本物の関数で描く。"""
    kind = case["kind"]
    if kind == "badge":
        value = unbits(case["scale"][0])
        scale = int(value) if value == int(value) and "." not in case["scale"][1] else value
        return eq._scale_badge(scale, case["size"])
    if kind == "marker":
        return eq._epicentre_marker(case["size"])
    canvas = blank(tuple(case["canvas"]), case["seed"])
    if kind == "epicentre":
        eq._draw_epicentre(canvas, unbits(case["at"][0]), unbits(case["at"][1]), eq._MAP_SS)
    elif kind == "label":
        eq._draw_place_label(canvas, unbits(case["at"][0]), unbits(case["at"][1]), case["text"])
    elif kind == "chrome":
        scales = []
        for raw, text in case["scales"]:
            value = unbits(raw)
            scales.append(int(value) if "." not in text else value)
        eq._draw_map_chrome(canvas, case["title"], case["subtitle"], scales)
    elif kind == "fill":
        lat, lon = unbits(case["centre"][0]), unbits(case["centre"][1])
        cx, cy = eq._latlon_to_tile_float(lat, lon, case["zoom"])
        origin_x, origin_y = cx * 256 - canvas.width / 4, cy * 256 - canvas.height / 4
        case["origin"] = [bits(origin_x), bits(origin_y)]
        plot = []
        for pref, (raw, text) in case["plot"]:
            value = unbits(raw)
            plot.append((0.0, 0.0, int(value) if "." not in text else value, pref))
        eq._fill_prefectures(canvas, plot, case["zoom"], origin_x, origin_y, eq._MAP_SS)
    else:
        raise SystemExit(f"知らない部品: {kind}")
    return canvas


def overlap_cases(eq: object) -> list[list]:
    """札・地名の重なりの判定（`_overlaps`）の例。辺が接するだけのものを多く含む（小さな格子の上で作る）。"""
    rng = random.Random(2718)

    def rect() -> list[float]:
        """格子（0.5 刻み）の上の四角（左・上・右・下）。"""
        x, y = rng.randrange(0, 6) / 2, rng.randrange(0, 6) / 2
        return [x, y, x + rng.randrange(1, 5) / 2, y + rng.randrange(1, 5) / 2]

    out = []
    for _ in range(400):
        box = rect()
        rects = [rect() for _ in range(rng.randrange(0, 4))]
        out.append([box, rects, eq._overlaps(tuple(box), [tuple(r) for r in rects])])
    return out


def piece_fixture(eq: object, dump: str | None) -> dict:
    """部品の例を全部描いて、答え（文字なしの画素のハッシュ・文字の呼び出し）を付ける。"""
    cases = piece_inputs()
    lengths: dict[str, str] = {}
    for case in cases:
        with TextSpy(draw=False) as spy:
            img = run_piece(eq, case)
        case["size_out"] = list(img.size)
        case["sha256"] = sha(img.tobytes())
        case["text_calls"] = spy.calls
        lengths.update(spy.lengths)
        with TextSpy(draw=True):
            case["sha256_with_text"] = sha(run_piece(eq, case).tobytes())
        if dump:
            with open(f"{dump}/piece-{case['name']}.rgba", "wb") as f:
                f.write(img.tobytes())
    return {
        "overlaps": overlap_cases(eq),
        "seat_alpha_sha256": sha(seat_alpha().tobytes()),
        "band_alpha": [int(215 * (1 - row / 148) ** 1.3) for row in range(148)],
        "lengths": lengths,
        "cases": cases,
    }


def seat_alpha() -> np.ndarray:
    """震源の座の濃さ（`_draw_epicentre` の中の式そのまま）。"""
    seat_r = 60
    yy, xx = np.mgrid[0 : seat_r * 2, 0 : seat_r * 2]
    dist = np.hypot(xx - seat_r + 0.5, yy - seat_r + 0.5) / seat_r
    return (120 * np.clip(1.0 - dist, 0.0, 1.0) ** 1.1).astype(np.uint8)


# ── 全体（本物の `_generate_intensity_map` を端から端まで） ──────────────


def map_inputs() -> list[dict]:
    """地図の全体の例（震源が陸・海・端、観測点が 1 つ／多数、震度いろいろ、タイルの取得失敗あり）。"""
    rng = random.Random(551)

    def many(prefs: list[str], low: int, high: int) -> list[dict]:
        """県の並びに、範囲の中のでたらめな震度を付ける。"""
        pool = [s for s in SCALES if low <= s <= high]
        return [point(pref, rng.choice(pool)) for pref in prefs]

    tohoku = [
        "宮城県",
        "福島県",
        "岩手県",
        "山形県",
        "秋田県",
        "青森県",
        "茨城県",
        "栃木県",
        "新潟県",
        "群馬県",
        "埼玉県",
        "千葉県",
    ]
    kanto = ["東京都", "神奈川県", "千葉県", "埼玉県", "茨城県", "栃木県", "群馬県", "山梨県", "静岡県"]
    kyushu = ["熊本県", "大分県", "福岡県", "佐賀県", "長崎県", "宮崎県", "鹿児島県", "愛媛県", "山口県"]
    cases = [
        {
            "name": "offshore-many",
            "lat": 37.7,
            "lon": 141.6,
            "title": "最大震度 6強",
            "subtitle": "福島県沖  M7.3  深さ 60 km  2026年3月16日 23時36分ごろ",
            "points": [point("宮城県", 60), point("福島県", 60), *many(tohoku[2:], 20, 50)],
            "tiles": "all",
        },
        {
            "name": "inland-kumamoto",
            "lat": 32.8,
            "lon": 130.7,
            "title": "最大震度 7",
            "subtitle": "熊本県熊本地方  M7.3  深さ 10 km  2026年4月16日 1時25分ごろ",
            "points": [point("熊本県", 70), point("大分県", 60), *many(kyushu[2:], 30, 55)],
            "tiles": "all",
        },
        {
            "name": "single-point",
            "lat": 37.5,
            "lon": 137.3,
            "title": "最大震度 3",
            "subtitle": "石川県能登地方  M4.1  ごく浅い",
            "points": [point("石川県", 30)],
            "tiles": "all",
        },
        {
            "name": "on-the-point",
            "lat": 35.689,
            "lon": 139.692,
            "title": "最大震度 4",
            "subtitle": "東京都23区  M4.8  深さ 80 km",
            "points": [point("東京都", 40)],
            "tiles": "all",
        },
        {
            "name": "whole-country",
            "lat": 33.1,
            "lon": 135.9,
            "title": "最大震度 7",
            "subtitle": "南海トラフ  M9.0  深さ 20 km",
            "points": many(PREFS, 10, 70),
            "tiles": "all",
        },
        {
            "name": "okinawa",
            "lat": 26.5,
            "lon": 128.4,
            "title": "最大震度 5弱",
            "subtitle": "沖縄本島近海  M6.0  深さ 30 km",
            "points": [point("沖縄県", 45), point("鹿児島県", 20)],
            "tiles": "all",
        },
        {
            "name": "far-epicentre",
            "lat": 52.0,
            "lon": 159.5,
            "title": "最大震度 3",
            "subtitle": "カムチャツカ半島付近  M8.2",
            "points": [point("北海道", 30), point("青森県", 20), point("岩手県", 10)],
            "tiles": "all",
        },
        {
            "name": "kanto-dense",
            "lat": 35.6,
            "lon": 140.1,
            "title": "最大震度 5強",
            "subtitle": "千葉県北西部  M6.1  深さ 70 km  2026年10月7日 22時41分ごろ",
            "points": [point("千葉県", 50), point("東京都", 50), *many(kanto[2:], 30, 45), point("東京都", 30)],
            "tiles": "all",
        },
        {
            "name": "odd-scales",
            "lat": 36.1,
            "lon": 133.2,
            "title": "震度分布",
            "subtitle": "",
            "points": [
                point("鳥取県", 46),
                point("島根県", 45.0),
                {"pref": "", "addr": "岡山県", "scale": 30},
                {"pref": "山陽", "addr": "広島県", "scale": 55},
                point("山口県", 5),
                {"pref": "香川県", "addr": "x"},
                point("どこか", 70),
            ],
            "tiles": "all",
        },
        {
            "name": "tiles-with-holes",
            "lat": 38.9,
            "lon": 142.1,
            "title": "最大震度 5弱",
            "subtitle": "宮城県沖  M5.9  深さ 50 km",
            "points": [point("宮城県", 45), point("岩手県", 40), point("福島県", 30), point("山形県", 20)],
            "tiles": "holes",
        },
        {
            "name": "no-tiles",
            "lat": 34.2,
            "lon": 135.2,
            "title": "最大震度 4",
            "subtitle": "和歌山県北部  M4.9  深さ 10 km",
            "points": [point("和歌山県", 40), point("大阪府", 30), point("奈良県", 30), point("兵庫県", 20)],
            "tiles": "none",
        },
        {
            "name": "hokkaido-east",
            "lat": 42.9,
            "lon": 145.6,
            "title": "最大震度 6弱",
            "subtitle": "根室半島南東沖  M7.0  深さ 40 km",
            "points": [point("北海道", 55), point("青森県", 30)],
            "tiles": "all",
        },
    ]
    return cases


def run_map(eq: object, case: dict, tiles: list[bytes], draw_text: bool) -> dict:
    """地図の例を 1 つ、本物の `_generate_intensity_map` に通して、段ごとの画素のハッシュを取る。"""
    stages: dict[str, str] = {}
    info: dict = {"requested": []}
    images: dict[str, bytes] = {}

    async def fetch(session, z, x, y):
        """タイルの偽物。規則どおりに見本を返す。"""
        info["requested"].append([z, x, y])
        what = tile_rule(case["tiles"], len(tiles), z, x, y)
        if what is None:
            return None
        return b"this is not a png" if what == "broken" else tiles[what]

    real = {
        name: getattr(eq, name)
        for name in (
            "_fetch_tile",
            "_paste_tiles",
            "_fill_prefectures",
            "_draw_epicentre",
            "_draw_place_labels",
            "_draw_map_chrome",
            "_compose_intensity_map",
        )
    }

    def paste(*args):
        """タイルを貼った面を控える。"""
        base = real["_paste_tiles"](*args)
        stages["base"] = sha(base.tobytes())
        images["base"] = base.convert("RGBA").tobytes()
        return base

    def fill(canvas, *args):
        """県の塗りの前（拡大した面）と後を控える。"""
        stages["upscaled"] = sha(canvas.tobytes())
        real["_fill_prefectures"](canvas, *args)
        stages["filled"] = sha(canvas.tobytes())
        images["filled"] = canvas.tobytes()

    def epicentre(canvas, *args):
        """震源を置いた後を控える。"""
        real["_draw_epicentre"](canvas, *args)
        stages["epicentre"] = sha(canvas.tobytes())

    def labels(canvas, *args):
        """地名の前（札を置いた後）と後を控える。"""
        stages["badges"] = sha(canvas.tobytes())
        real["_draw_place_labels"](canvas, *args)
        stages["labels"] = sha(canvas.tobytes())

    def chrome(canvas, *args):
        """帯・凡例・出典の後を控える。"""
        real["_draw_map_chrome"](canvas, *args)
        stages["chrome"] = sha(canvas.tobytes())
        images["chrome"] = canvas.tobytes()

    def compose(coords, tiles_, origin_x, origin_y, zoom, plot, *rest):
        """決めた範囲を控えてから、本物を呼ぶ。"""
        info["plan"] = {
            "zoom": zoom,
            "origin": [bits(origin_x), bits(origin_y)],
            "coords": [list(c) for c in coords],
            "plot": [[bits(p[0]), bits(p[1]), scale_text(p[2]), p[3]] for p in plot],
        }
        return real["_compose_intensity_map"](coords, tiles_, origin_x, origin_y, zoom, plot, *rest)

    eq._fetch_tile, eq._paste_tiles, eq._fill_prefectures = fetch, paste, fill
    eq._draw_epicentre, eq._draw_place_labels, eq._draw_map_chrome = epicentre, labels, chrome
    eq._compose_intensity_map = compose
    try:
        with TextSpy(draw=draw_text) as spy:
            png = asyncio.run(
                eq._generate_intensity_map(
                    None, case["lat"], case["lon"], case["points"], case["title"], case["subtitle"]
                )
            )
    finally:
        for name, fn in real.items():
            setattr(eq, name, fn)
    final = Image.open(io.BytesIO(png.getvalue()))
    assert final.mode == "RGB" and final.size == (1200, 720)
    stages["final"] = sha(final.tobytes())
    images["final"] = final.convert("RGBA").tobytes()
    return {
        "stages": stages,
        "plan": info["plan"],
        "requested": info["requested"],
        "text_calls": spy.calls,
        "lengths": spy.lengths,
        "png": png.getvalue(),
        "images": images,
    }


def map_fixture(eq: object, tiles: list[bytes], dump: str | None, with_text_dir: str | None) -> dict:
    """地図の全体の例を、文字なし・文字ありの両方で作る。"""
    cases = map_inputs()
    lengths: dict[str, str] = {}
    for case in cases:
        plain = run_map(eq, case, tiles, draw_text=False)
        full = run_map(eq, case, tiles, draw_text=True)
        assert plain["plan"] == full["plan"] and plain["text_calls"] == full["text_calls"]
        case["plan"] = plain["plan"]
        case["stages"] = plain["stages"]
        case["text_calls"] = plain["text_calls"]
        case["stages_with_text"] = full["stages"]
        case["png_bytes"] = len(full["png"])
        lengths.update(plain["lengths"])
        if dump:
            for stage, pixels in plain["images"].items():
                with open(f"{dump}/map-{case['name']}-{stage}.rgba", "wb") as f:
                    f.write(pixels)
        if with_text_dir:
            with open(f"{with_text_dir}/{case['name']}.png", "wb") as f:
                f.write(full["png"])
            with open(f"{with_text_dir}/{case['name']}.notext.png", "wb") as f:
                f.write(plain["png"])
    return {"lengths": lengths, "cases": cases}
