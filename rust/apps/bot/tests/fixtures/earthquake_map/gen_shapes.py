"""震度の地図の基準のうち、部品（図形・ぼかし・重ね合わせ・拡大縮小・タイルの塗り替え）の例と答えを作る。

generate.py から呼ばれる。例は乱数（種は固定）で作り、本物の Pillow に描かせて、出来た画像の画素
（RGBA の並び）の SHA-256 を答えにする。Rust のテスト（tests/earthquake_map_golden.rs）は同じ例を
Rust の写し（apps/bot/src/earthquake_map/draw.rs・raster.rs）で描いて、同じハッシュになることを確かめる。

例に書く小数は、桁の少ない 10 進の数だけにしてある（JSON を読む側の小数の読み方で値が変わらないように）。
"""

import hashlib
import io
import json
import random
import struct
import zlib

import numpy as np
from PIL import Image, ImageDraw, ImageFilter


def noise(seed: int, count: int) -> bytes:
    """決まった「でたらめ」のバイト列（Rust のテストも同じ式で作る）。"""
    i = np.arange(count, dtype=np.uint64)
    v = (i * np.uint64(2654435761) + np.uint64(seed * 40503)) & np.uint64(0xFFFFFFFF)
    v ^= v >> np.uint64(15)
    v = (v * np.uint64(2246822519)) & np.uint64(0xFFFFFFFF)
    v ^= v >> np.uint64(13)
    return (v & np.uint64(0xFF)).astype(np.uint8).tobytes()


def colour(rng: random.Random) -> list[int]:
    """でたらめな色（アルファも）。"""
    return [rng.randrange(256) for _ in range(4)]


def point(rng: random.Random, w: int, h: int, margin: float = 20.0) -> list[float]:
    """画像の少し外まで含む、でたらめな点（小数 2 桁）。"""
    return [round(rng.uniform(-margin, w + margin), 2), round(rng.uniform(-margin, h + margin), 2)]


def box(rng: random.Random, w: int, h: int, whole: bool = False) -> list[float]:
    """左上・右下の順の、でたらめな箱。"""
    xs = sorted(rng.uniform(-10, w + 10) for _ in range(2))
    ys = sorted(rng.uniform(-10, h + 10) for _ in range(2))
    values = [xs[0], ys[0], xs[1], ys[1]]
    return [int(v) for v in values] if whole else [round(v, 2) for v in values]


def polygon_cases(rng: random.Random, rings: list[list[list[float]]]) -> list[dict]:
    """多角形（`ImageDraw.polygon`）の例。"""
    cases = []
    for index in range(36):
        w, h = rng.choice([(64, 48), (120, 90), (200, 150), (33, 77)])
        ops = []
        for _ in range(rng.randrange(1, 4)):
            count = rng.randrange(3, 13)
            ops.append({"op": "polygon", "xy": [point(rng, w, h) for _ in range(count)], "fill": colour(rng)})
        cases.append({"name": f"polygon-random-{index:02d}", "size": [w, h], "base": [0, 0, 0, 0], "ops": ops})
    for index in range(20):
        # 格子の上の点（横の辺・同じ向きに続く横の辺・重なる点が多く出る）。
        w, h = 60, 40
        count = rng.randrange(3, 16)
        xy = [[rng.randrange(-4, 64, 4), rng.randrange(-4, 44, 4)] for _ in range(count)]
        cases.append(
            {
                "name": f"polygon-grid-{index:02d}",
                "size": [w, h],
                "base": [10, 20, 30, 40],
                "ops": [{"op": "polygon", "xy": xy, "fill": colour(rng)}],
            }
        )
    fixed = {
        "two-points": [[3, 4], [40, 30]],
        "one-point": [[5, 5]],
        "same-point": [[7, 7], [7, 7], [7, 7]],
        "flat": [[2, 9], [30, 9], [50, 9], [10, 9]],
        "runs-right": [[2, 5], [10, 5], [20, 5], [30, 5], [30, 20], [2, 20]],
        "runs-left": [[30, 5], [20, 5], [10, 5], [2, 5], [2, 20], [30, 20]],
        "closed": [[5, 5], [50, 8], [30, 30], [5, 5]],
        "collinear": [[5, 5], [20, 20], [35, 35]],
        "negative-fractions": [[-0.7, -0.2], [40.9, -0.9], [40.2, 30.99], [-0.99, 30.5]],
        "halves": [[10.5, 10.5], [40.5, 10.5], [40.5, 30.5], [10.5, 30.5]],
        "bow-tie": [[5, 5], [50, 35], [50, 5], [5, 35]],
        "spike": [[30, 2], [31, 38], [29, 38]],
        "far-outside": [[-500, -300], [700, -280], [650, 400], [-450, 380]],
    }
    for name, xy in fixed.items():
        cases.append(
            {
                "name": f"polygon-{name}",
                "size": [60, 40],
                "base": [0, 0, 0, 0],
                "ops": [{"op": "polygon", "xy": xy, "fill": [200, 100, 50, 180]}],
            }
        )
    for index, ring in enumerate(rings):
        # 本物の県の輪を、枠に収まるように置いたもの（小数 3 桁）。
        xs, ys = [p[0] for p in ring], [p[1] for p in ring]
        scale = 230 / max(max(xs) - min(xs), max(ys) - min(ys), 1e-9)
        xy = [[round((x - min(xs)) * scale - 8, 3), round((y - min(ys)) * scale - 8, 3)] for x, y in ring]
        cases.append(
            {
                "name": f"polygon-ring-{index:02d}",
                "size": [220, 220],
                "base": [0, 0, 0, 0],
                "ops": [{"op": "polygon", "xy": xy, "fill": colour(rng)}],
            }
        )
    return cases


def ellipse_cases(rng: random.Random) -> list[dict]:
    """楕円（`ImageDraw.ellipse`）の例。"""
    cases = []
    for index in range(48):
        w, h = rng.choice([(64, 48), (130, 100), (41, 41)])
        mode = index % 3
        op = {
            "op": "ellipse",
            "xy": box(rng, w, h, whole=index % 4 == 0),
            "fill": colour(rng) if mode != 0 else None,
            "outline": colour(rng) if mode != 1 else None,
            "width": rng.randrange(1, 12),
        }
        cases.append({"name": f"ellipse-random-{index:02d}", "size": [w, h], "base": [0, 0, 0, 0], "ops": [op]})
    for size in range(0, 14):
        # 小さい円（太さが半径を超えるものも）。
        op = {"op": "ellipse", "xy": [3, 3, 3 + size, 3 + size], "fill": None, "outline": [9, 8, 7, 255], "width": 3}
        cases.append({"name": f"ellipse-small-{size:02d}", "size": [20, 20], "base": [0, 0, 0, 0], "ops": [op]})
    # 輪郭をたどるとき、「縦に進む」と「斜めに進む」が同じ近さになる大きさ（Draw.c の quarter_next は縦を選ぶ）。
    # 塗りと、太さ 1・2 の輪（内側の輪郭は 2 * (太さ - 1) だけ小さい）で。
    for a, b in ((3, 6), (9, 18), (17, 34), (35, 56), (51, 48), (6, 3), (18, 9), (5, 8), (11, 20)):
        for style, fill, width in (("fill", [40, 50, 60, 255], 1), ("w1", None, 1), ("w2", None, 2)):
            op = {"op": "ellipse", "xy": [2, 2, 2 + a, 2 + b], "fill": fill, "outline": None, "width": width}
            if fill is None:
                op["outline"] = [200, 100, 50, 255]
            name = f"ellipse-tie-{a}x{b}-{style}"
            cases.append({"name": name, "size": [60, 64], "base": [0, 0, 0, 0], "ops": [op]})
    fixed = {
        # 震源の印（_epicentre_marker(80)）の 2 つの輪。
        "marker-outer": {"xy": [8.0, 8.0, 72.0, 72.0], "fill": None, "outline": [255, 72, 72, 255], "width": 6},
        "marker-inner": {"xy": [20.16, 20.16, 59.84, 59.84], "fill": None, "outline": [255, 72, 72, 210], "width": 5},
        "same-colours": {"xy": [5, 5, 60, 50], "fill": [1, 2, 3, 4], "outline": [1, 2, 3, 4], "width": 4},
        "zero-width": {"xy": [5, 5, 60, 50], "fill": None, "outline": [1, 2, 3, 4], "width": 0},
        "wrong-x": {"xy": [50, 5, 10, 50], "fill": [1, 2, 3, 4], "outline": None, "width": 1},
        "wrong-y": {"xy": [5, 50, 60, 10], "fill": None, "outline": [1, 2, 3, 4], "width": 1},
        "wide-flat": {"xy": [2.5, 30.2, 77.9, 36.6], "fill": [9, 9, 9, 99], "outline": [200, 0, 0, 255], "width": 2},
    }
    for name, op in fixed.items():
        cases.append(
            {"name": f"ellipse-{name}", "size": [80, 80], "base": [0, 0, 0, 0], "ops": [{"op": "ellipse", **op}]}
        )
    return cases


def line_cases(rng: random.Random) -> list[dict]:
    """線（`ImageDraw.line`）の例。"""
    cases = []
    for index in range(40):
        w, h = rng.choice([(64, 48), (130, 100)])
        count = 2 if index % 3 else rng.randrange(3, 7)
        op = {
            "op": "line",
            "xy": [point(rng, w, h, 8) for _ in range(count)],
            "fill": colour(rng),
            "width": 1 if index % 2 == 0 else rng.randrange(2, 10),
        }
        cases.append({"name": f"line-random-{index:02d}", "size": [w, h], "base": [0, 0, 0, 0], "ops": [op]})
    fixed = {
        # 震源の印の十字（太さ 6）。
        "marker-h": {"xy": [[2.88, 40.0], [77.12, 40.0]], "width": 6},
        "marker-v": {"xy": [[40.0, 2.88], [40.0, 77.12]], "width": 6},
        # 題の帯の 1 行（太さ 1 の横の線。終わりの点は画像の外）。
        "band-row": {"xy": [[0, 7], [80, 7]], "width": 1},
        "backwards": {"xy": [[70, 9], [3, 9]], "width": 1},
        "vertical": {"xy": [[9, 70], [9, 3]], "width": 1},
        "single-point": {"xy": [[9, 9], [9, 9]], "width": 1},
        "single-point-wide": {"xy": [[9, 9], [9, 9]], "width": 5},
        "diagonal": {"xy": [[2, 2], [70, 70]], "width": 4},
        "shallow": {"xy": [[2, 10], [75, 22]], "width": 7},
        "steep": {"xy": [[10, 2], [22, 75]], "width": 8},
        "zero-width": {"xy": [[2, 2], [70, 70]], "width": 0},
    }
    for name, op in fixed.items():
        cases.append(
            {
                "name": f"line-{name}",
                "size": [80, 80],
                "base": [0, 0, 0, 0],
                "ops": [{"op": "line", "fill": [255, 72, 72, 255], **op}],
            }
        )
    return cases


def rectangle_cases(rng: random.Random) -> list[dict]:
    """四角（`ImageDraw.rectangle`）の例。"""
    cases = []
    for index in range(30):
        w, h = rng.choice([(64, 48), (130, 100)])
        mode = index % 3
        op = {
            "op": "rectangle",
            "xy": box(rng, w, h, whole=index % 2 == 0),
            "fill": colour(rng) if mode != 0 else None,
            "outline": colour(rng) if mode != 1 else None,
            "width": rng.randrange(1, 7),
        }
        cases.append({"name": f"rectangle-random-{index:02d}", "size": [w, h], "base": [5, 6, 7, 8], "ops": [op]})
    fixed = {
        # 出典の座（下の端からはみ出す）。
        "attribution": {"xy": [0, 42, 51, 80], "fill": [8, 11, 17, 190], "outline": None, "width": 1},
        "wrong-x": {"xy": [50, 5, 10, 50], "fill": [1, 2, 3, 4], "outline": None, "width": 1},
        "wrong-y": {"xy": [5, 50, 60, 10], "fill": None, "outline": [1, 2, 3, 4], "width": 1},
        "thick-outline": {"xy": [5, 5, 12, 12], "fill": None, "outline": [1, 2, 3, 4], "width": 9},
        "below": {"xy": [5, 90, 60, 120], "fill": [1, 2, 3, 4], "outline": None, "width": 1},
    }
    for name, op in fixed.items():
        cases.append(
            {"name": f"rectangle-{name}", "size": [80, 80], "base": [0, 0, 0, 0], "ops": [{"op": "rectangle", **op}]}
        )
    return cases


def rounded_cases(rng: random.Random) -> list[dict]:
    """角丸の四角（`ImageDraw.rounded_rectangle`）の例。地図が使う大きさは全部入れる。"""
    cases = []
    for size in (36, 44, 52, 60, 68):
        # 震度の札（_scale_badge）: 影の形と、本体（枠つき）。
        pad = size // 3
        edge = size + pad * 2
        shade = {
            "op": "rounded_rectangle",
            "xy": [pad, pad + size // 10, pad + size, pad + size + size // 10],
            "radius": size // 4,
            "fill": [0, 0, 0, 165],
            "outline": None,
            "width": 1,
        }
        body = {
            "op": "rounded_rectangle",
            "xy": [pad, pad, pad + size, pad + size],
            "radius": size // 4,
            "fill": [226, 192, 62, 255],
            "outline": [255, 255, 255, 210],
            "width": max(1, size // 14),
        }
        cases.append(
            {"name": f"rounded-badge-shade-{size}", "size": [edge, edge], "base": [0, 0, 0, 0], "ops": [shade]}
        )
        cases.append({"name": f"rounded-badge-body-{size}", "size": [edge, edge], "base": [0, 0, 0, 0], "ops": [body]})
    for width in (50, 76, 102, 128, 154, 201):
        # 地名の札（_draw_place_label）。
        op = {
            "op": "rounded_rectangle",
            "xy": [0, 0, width - 1, 37],
            "radius": 10,
            "fill": [10, 14, 21, 214],
            "outline": [120, 140, 170, 110],
            "width": 1,
        }
        cases.append({"name": f"rounded-label-{width}", "size": [width, 38], "base": [0, 0, 0, 0], "ops": [op]})
    for count in range(1, 10):
        # 凡例の座（_draw_map_chrome）と、その上の色の札。
        box_w, box_h = 48 + count * 44 + (count - 1) * 14, 98
        ops = [
            {
                "op": "rounded_rectangle",
                "xy": [0, 0, box_w - 1, box_h - 1],
                "radius": 18,
                "fill": [12, 16, 24, 208],
                "outline": [120, 140, 170, 120],
                "width": 2,
            }
        ]
        for index in range(count):
            x, y = 24 + index * 58, 52
            ops.append(
                {
                    "op": "rounded_rectangle",
                    "xy": [x, y, x + 44, y + 44],
                    "radius": 10,
                    "fill": [*colour(rng)[:3], 255],
                    "outline": None,
                    "width": 1,
                }
            )
        cases.append({"name": f"rounded-legend-{count}", "size": [box_w, box_h], "base": [0, 0, 0, 0], "ops": ops})
    for index in range(60):
        w, h = rng.choice([(64, 48), (130, 100), (90, 90)])
        mode = index % 3
        whole = index % 2 == 0
        op = {
            "op": "rounded_rectangle",
            "xy": box(rng, w, h, whole=whole),
            "radius": rng.randrange(0, 40) if whole else round(rng.uniform(0, 40), 1),
            "fill": colour(rng) if mode != 0 else None,
            "outline": colour(rng) if mode != 1 else None,
            "width": rng.randrange(1, 7),
        }
        cases.append({"name": f"rounded-random-{index:02d}", "size": [w, h], "base": [0, 0, 0, 0], "ops": [op]})
    fixed = {
        "circle": {"xy": [10, 10, 50, 50], "radius": 30},
        "pill-wide": {"xy": [5, 20, 75, 40], "radius": 30},
        "pill-tall": {"xy": [20, 5, 40, 75], "radius": 30},
        "almost-pill": {"xy": [5, 20, 75, 41], "radius": 10},
        "square-corners": {"xy": [5, 5, 60, 50], "radius": 0},
        "tiny": {"xy": [5, 5, 6, 6], "radius": 3},
        "point": {"xy": [5, 5, 5, 5], "radius": 3},
        "one-wide": {"xy": [5, 5, 6, 40], "radius": 5},
        "wrong-x": {"xy": [50, 5, 10, 50], "radius": 5},
        "wrong-y": {"xy": [5, 50, 60, 10], "radius": 5},
        "halves": {"xy": [4.5, 5.5, 60.5, 49.5], "radius": 7.5},
        "outside": {"xy": [-20, -15, 30, 25], "radius": 12},
    }
    for name, op in fixed.items():
        for style, (fill, outline) in {
            "fill": ([40, 80, 120, 200], None),
            "outline": (None, [250, 250, 250, 210]),
            "both": ([40, 80, 120, 200], [250, 250, 250, 210]),
        }.items():
            cases.append(
                {
                    "name": f"rounded-{name}-{style}",
                    "size": [80, 80],
                    "base": [0, 0, 0, 0],
                    "ops": [{"op": "rounded_rectangle", **op, "fill": fill, "outline": outline, "width": 3}],
                }
            )
    return cases


def blur_cases(rng: random.Random) -> list[dict]:
    """ぼかし（`ImageFilter.GaussianBlur`）の例。"""
    cases = []
    for size in (36, 44, 52, 60, 68):
        # 震度の札の落ち影（影の形を描いてから、size / 8 でぼかす）。
        pad = size // 3
        edge = size + pad * 2
        ops = [
            {
                "op": "rounded_rectangle",
                "xy": [pad, pad + size // 10, pad + size, pad + size + size // 10],
                "radius": size // 4,
                "fill": [0, 0, 0, 165],
                "outline": None,
                "width": 1,
            },
            {"op": "blur", "radius": size / 8},
        ]
        cases.append({"name": f"blur-badge-shade-{size}", "size": [edge, edge], "base": [0, 0, 0, 0], "ops": ops})
    sizes = [(1, 1), (2, 3), (5, 1), (1, 7), (16, 9), (40, 40), (97, 31), (31, 97), (120, 120)]
    radii = [0, 0.3, 0.5, 1, 1.7, 2, 3.25, 4.5, 5.5, 6.5, 7.5, 8.5, 12, 30, 100]
    for index in range(40):
        w, h = sizes[index % len(sizes)]
        radius = radii[(index * 7) % len(radii)]
        cases.append(
            {
                "name": f"blur-noise-{index:02d}",
                "size": [w, h],
                "noise": rng.randrange(1, 1 << 20),
                "ops": [{"op": "blur", "radius": radius}],
            }
        )
    return cases


def composite_cases(rng: random.Random) -> list[dict]:
    """重ね合わせ（`Image.alpha_composite` の、置き場所つきの方）の例。"""
    cases = []
    for index in range(40):
        w, h = rng.choice([(64, 48), (130, 100), (30, 30)])
        ow, oh = rng.choice([(20, 20), (64, 48), (200, 10), (7, 150)])
        at = [rng.randrange(-ow - 5, w + 5), rng.randrange(-oh - 5, h + 5)]
        case = {
            "name": f"composite-{index:02d}",
            "size": [w, h],
            "ops": [{"op": "composite", "size": [ow, oh], "noise": rng.randrange(1, 1 << 20), "at": at}],
        }
        if index % 4 == 0:
            case["base"] = [0, 0, 0, 0]
        elif index % 4 == 1:
            case["base"] = [38, 47, 62, 255]
        else:
            case["noise"] = rng.randrange(1, 1 << 20)
        cases.append(case)
    return cases


def resize_cases(rng: random.Random) -> list[dict]:
    """LANCZOS の拡大縮小（`Image.resize`）の例。RGBA（アルファを掛けて戻す）と RGB。"""
    cases = []
    pairs = [
        ((200, 120), (100, 60)),
        ((201, 121), (100, 60)),
        ((64, 64), (128, 128)),
        ((100, 400), (90, 100)),
        ((300, 100), (300, 50)),
        ((300, 100), (150, 100)),
        ((50, 50), (50, 50)),
        ((37, 91), (100, 60)),
        ((7, 5), (3, 2)),
        ((240, 144), (120, 72)),
    ]
    for index, (src, dst) in enumerate(pairs):
        seed = rng.randrange(1, 1 << 20)
        cases.append(
            {
                "name": f"resize-rgba-{index:02d}",
                "size": list(src),
                "noise": seed,
                "ops": [{"op": "resize", "size": list(dst)}],
            }
        )
        cases.append(
            {
                "name": f"resize-rgb-{index:02d}",
                "mode": "RGB",
                "size": list(src),
                "noise": seed,
                "ops": [{"op": "resize", "size": list(dst)}],
            }
        )
    # 地図と同じ大きさ（拡大は RGB、縮小は RGBA）。
    cases.append(
        {
            "name": "resize-rgb-map",
            "mode": "RGB",
            "size": [1200, 720],
            "noise": 77,
            "ops": [{"op": "resize", "size": [2400, 1440]}],
        }
    )
    cases.append(
        {"name": "resize-rgba-map", "size": [2400, 1440], "noise": 78, "ops": [{"op": "resize", "size": [1200, 720]}]}
    )
    for index in range(10):
        # RGB の貼り付け（タイルを面に貼るところ）。
        w, h = rng.choice([(64, 48), (130, 100)])
        tw, th = rng.choice([(32, 32), (256, 256), (10, 200)])
        ops = [
            {
                "op": "paste",
                "size": [tw, th],
                "noise": rng.randrange(1, 1 << 20),
                "at": [rng.randrange(-tw, w + 3), rng.randrange(-th, h + 3)],
            }
            for _ in range(3)
        ]
        cases.append({"name": f"paste-rgb-{index:02d}", "mode": "RGB", "size": [w, h], "noise": 5 + index, "ops": ops})
    return cases


def run_shape(case: dict) -> bytes:
    """例を 1 つ、本物の Pillow で描いて、RGBA の並びを返す。Pillow が例外にしたら、そのまま投げる。"""
    w, h = case["size"]
    mode = case.get("mode", "RGBA")
    bands = len(mode)
    if "noise" in case:
        img = Image.frombytes(mode, (w, h), noise(case["noise"], w * h * bands))
    else:
        img = Image.new(mode, (w, h), tuple(case["base"]))
    for op in case["ops"]:
        kind = op["op"]
        draw = ImageDraw.Draw(img)
        fill = tuple(op["fill"]) if op.get("fill") else None
        outline = tuple(op["outline"]) if op.get("outline") else None
        if kind == "polygon":
            draw.polygon([tuple(p) for p in op["xy"]], fill=fill)
        elif kind == "ellipse":
            draw.ellipse(op["xy"], fill=fill, outline=outline, width=op["width"])
        elif kind == "line":
            draw.line([tuple(p) for p in op["xy"]], fill=fill, width=op["width"])
        elif kind == "rectangle":
            draw.rectangle(op["xy"], fill=fill, outline=outline, width=op["width"])
        elif kind == "rounded_rectangle":
            draw.rounded_rectangle(op["xy"], radius=op["radius"], fill=fill, outline=outline, width=op["width"])
        elif kind == "blur":
            img = img.filter(ImageFilter.GaussianBlur(op["radius"]))
        elif kind == "composite":
            ow, oh = op["size"]
            img.alpha_composite(Image.frombytes("RGBA", (ow, oh), noise(op["noise"], ow * oh * 4)), tuple(op["at"]))
        elif kind == "paste":
            tw, th = op["size"]
            img.paste(Image.frombytes("RGB", (tw, th), noise(op["noise"], tw * th * 3)), tuple(op["at"]))
        elif kind == "resize":
            img = img.resize(tuple(op["size"]), Image.LANCZOS)
        else:
            raise SystemExit(f"知らない操作: {kind}")
    return img.convert("RGBA").tobytes()


def shape_fixture(rings: list[list[list[float]]], dump: str | None) -> list[dict]:
    """部品の例を全部作って、答え（ハッシュ。Pillow が例外にするものは "error"）を付ける。"""
    rng = random.Random(20261127)
    cases = (
        polygon_cases(rng, rings)
        + ellipse_cases(rng)
        + line_cases(rng)
        + rectangle_cases(rng)
        + rounded_cases(rng)
        + blur_cases(rng)
        + composite_cases(rng)
        + resize_cases(rng)
    )
    for case in cases:
        try:
            pixels = run_shape(case)
        except (ValueError, TypeError):
            case["sha256"] = "error"
            continue
        case["sha256"] = hashlib.sha256(pixels).hexdigest()
        if dump:
            with open(f"{dump}/{case['name']}.rgba", "wb") as f:
                f.write(pixels)
    return cases


def png_chunk(kind: bytes, data: bytes) -> bytes:
    """PNG のかたまりを 1 つ作る。"""
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def raw_png(width: int, height: int, depth: int, colour_type: int, rows: list[bytes], extra: bytes = b"") -> bytes:
    """Pillow が書けない形（2・4 ビットのグレー、16 ビットの色など）の PNG を、手で組み立てる。"""
    header = struct.pack(">IIBBBBB", width, height, depth, colour_type, 0, 0, 0)
    body = zlib.compress(b"".join(b"\x00" + row for row in rows))
    signature = b"\x89PNG\r\n\x1a\n"
    return signature + png_chunk(b"IHDR", header) + extra + png_chunk(b"IDAT", body) + png_chunk(b"IEND", b"")


def tile_pngs() -> dict[str, bytes]:
    """タイルとして届きうる PNG を、色の形ごとに 1 枚ずつ（白地図らしい「白い面に黒い線」も）。"""
    out: dict[str, bytes] = {}

    def save(name: str, img: Image.Image, **options: object) -> None:
        """Pillow で PNG にして覚える。"""
        buf = io.BytesIO()
        img.save(buf, format="PNG", **options)
        out[name] = buf.getvalue()

    size = 32
    rng = random.Random(7)
    blank = Image.new("L", (size, size), 255)
    pen = ImageDraw.Draw(blank)
    for _ in range(12):
        pen.line([rng.randrange(size) for _ in range(4)], fill=rng.choice([0, 0, 60, 128]), width=1)
    ramp = Image.frombytes("L", (size, size), bytes((x * 8 + y) % 256 for y in range(size) for x in range(size)))
    rgb = Image.frombytes("RGB", (size, size), noise(11, size * size * 3))
    rgba = Image.frombytes("RGBA", (size, size), noise(12, size * size * 4))
    save("l8-blank", blank)
    save("l8-ramp", ramp)
    save("bilevel", blank.convert("1"))
    save("la8", Image.merge("LA", (ramp, ramp.point(lambda v: 255 - v))))
    save("rgb8", rgb)
    save("rgba8", rgba)
    save("palette-256", rgb.quantize(256))
    save("palette-16", rgb.quantize(16))
    save("palette-4", blank.convert("RGB").quantize(4))
    save("palette-2", blank.convert("RGB").quantize(2))
    save("palette-trns", rgb.quantize(16), transparency=3)
    save("l8-trns", ramp, transparency=200)
    save("rgb8-trns", rgb, transparency=(1, 2, 3))
    save("i16", Image.frombytes("I;16", (size, size), noise(13, size * size * 2)))
    save("not-256", Image.frombytes("L", (40, 90), noise(14, 40 * 90)))
    # 2・4 ビットのグレー、16 ビットの色・グレー＋アルファは Pillow では書けないので手で作る。
    two = [bytes(noise(20 + y, size // 4)) for y in range(size)]
    four = [bytes(noise(90 + y, size // 2)) for y in range(size)]
    out["l2"] = raw_png(size, size, 2, 0, two)
    out["l4"] = raw_png(size, size, 4, 0, four)
    out["rgb16"] = raw_png(size, size, 16, 2, [bytes(noise(200 + y, size * 6)) for y in range(size)])
    out["rgba16"] = raw_png(size, size, 16, 6, [bytes(noise(300 + y, size * 8)) for y in range(size)])
    out["la16"] = raw_png(size, size, 16, 4, [bytes(noise(400 + y, size * 4)) for y in range(size)])
    out["l16-low"] = raw_png(size, size, 16, 0, [bytes([0, v]) * size for v in range(size)])
    palette = png_chunk(b"PLTE", bytes(noise(500, 4 * 3)))
    out["palette-2bit"] = raw_png(size, size, 2, 3, two, palette)
    out["palette-short"] = raw_png(
        size, size, 8, 3, [bytes(v % 6 for v in noise(600 + y, size)) for y in range(size)], palette
    )
    out["l16-trns"] = raw_png(
        size, size, 16, 0, [bytes(noise(700 + y, size * 2)) for y in range(size)], png_chunk(b"tRNS", b"\x00\x05")
    )
    # 読めないもの。
    out["broken-truncated"] = out["rgb8"][:200]
    out["broken-not-png"] = b"<html>503 Service Unavailable</html>"
    out["broken-empty"] = b""
    return out


def tile_fixture(recolour: object, dump: str | None) -> list[dict]:
    """タイルの例: PNG（16 進）と、「明るさにして塗り替えた」結果（RGB の並びのハッシュ。読めなければ "error"）。"""
    cases = []
    for name, data in tile_pngs().items():
        case = {"name": name, "png": data.hex()}
        try:
            gray = Image.open(io.BytesIO(data)).convert("L")
            pixels = recolour(gray).tobytes()
        except Exception:  # Python の _paste_tiles と同じく、何が出ても「読めない」にする
            case["sha256"] = "error"
        else:
            case["size"] = list(gray.size)
            case["gray_sha256"] = hashlib.sha256(gray.tobytes()).hexdigest()
            case["sha256"] = hashlib.sha256(pixels).hexdigest()
            if dump:
                with open(f"{dump}/tile-{name}.rgb", "wb") as f:
                    f.write(pixels)
                with open(f"{dump}/tile-{name}.gray", "wb") as f:
                    f.write(gray.tobytes())
        cases.append(case)
    return cases


def dumps(value: object) -> str:
    """JSON にする。例の並びは 1 例 1 行（差分が読め、ファイルも膨らまない）。それ以外は字下げして整える。"""
    if isinstance(value, list):
        rows = [json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in value]
        return "[\n" + ",\n".join(rows) + "\n]\n"
    if isinstance(value, dict) and isinstance(value.get("cases"), list):
        head = {key: item for key, item in value.items() if key != "cases"}
        text = json.dumps(head, ensure_ascii=False, indent=1)
        return text[:-2] + ',\n "cases": ' + dumps(value["cases"]).rstrip("\n").replace("\n", "\n ") + "\n}\n"
    return json.dumps(value, ensure_ascii=False, indent=1) + "\n"
