"""colorthief の基準の画像と答えを作る（rust/apps/bot/tests/colorthief_golden.rs が読む）。

答え（expected.txt）は Python の colorthief 0.2.1 の get_color(quality=10) が出したもの。
Rust の移植（apps/bot/src/colorthief.rs）がこれと同じ色を出すことを CI で確かめる。

作り直すとき（画像を足すときなど）は、本番と同じ requirements.txt を入れた Python で:

    python rust/apps/bot/tests/fixtures/colorthief/generate.py

乱数は種を固定してあるので、同じ Pillow なら同じ画像になる。画像は小さく保つこと
（リポジトリに入る）。
"""

import os
import random
from io import BytesIO

from colorthief import ColorThief
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))


def images() -> dict[str, tuple[Image.Image, dict]]:
    """名前 → (画像, save に渡す引数)。種類ごとに 1 枚（透過・パレット・グレー・GIF など）。"""
    out: dict[str, tuple[Image.Image, dict]] = {}
    out["01_solid.png"] = (Image.new("RGB", (16, 16), (200, 40, 10)), {})
    two = Image.new("RGB", (40, 40), (0, 0, 200))
    ImageDraw.Draw(two).rectangle([0, 0, 39, 3], fill=(200, 0, 0))
    out["02_two.png"] = (two, {})
    g = Image.new("RGB", (64, 64))
    g.putdata([(x * 4, y * 4, 128) for y in range(64) for x in range(64)])
    out["03_gradient.png"] = (g, {})
    r = random.Random(1)
    n = Image.new("RGB", (48, 48))
    n.putdata([(r.randrange(256), r.randrange(256), r.randrange(256)) for _ in range(48 * 48)])
    out["04_noise.png"] = (n, {})
    r = random.Random(2)
    a = Image.new("RGBA", (48, 48))
    a.putdata([(r.randrange(256), r.randrange(256), r.randrange(256), r.randrange(256)) for _ in range(48 * 48)])
    out["05_noise_alpha.png"] = (a, {})
    p = n.quantize(16)
    out["06_palette_trns.png"] = (p, {"transparency": 3})
    gray = Image.new("L", (48, 48))
    gray.putdata([(x * 5) % 256 for y in range(48) for x in range(48)])
    out["07_gray.png"] = (gray, {})
    out["08_gray_alpha.png"] = (Image.merge("LA", (gray, gray.point(lambda v: 255 - v))), {})
    out["09_palette.gif"] = (p, {"transparency": 5})
    w = Image.new("RGB", (40, 40), (255, 255, 255))
    ImageDraw.Draw(w).ellipse([15, 15, 25, 25], fill=(30, 160, 90))
    out["10_mostly_white.png"] = (w, {})
    out["11_all_white.png"] = (Image.new("RGB", (8, 8), (255, 255, 255)), {})
    out["12_all_transparent.png"] = (Image.new("RGBA", (8, 8), (10, 200, 10, 0)), {})
    r = random.Random(3)
    av = Image.new("RGB", (128, 128), (54, 57, 63))
    d = ImageDraw.Draw(av)
    for _ in range(25):
        x, y, s = r.randrange(128), r.randrange(128), r.randrange(4, 40)
        d.ellipse([x, y, x + s, y + s], fill=(r.randrange(256), r.randrange(256), r.randrange(256)))
    out["13_avatar_like.png"] = (av, {})
    r = random.Random(4)
    few = Image.new("RGB", (40, 40))
    few.putdata([r.choice([(10, 10, 10), (240, 240, 0), (0, 128, 255), (128, 0, 128)]) for _ in range(40 * 40)])
    out["15_few_colours.png"] = (few, {})
    edge = Image.new("RGBA", (16, 16), (100, 150, 200, 124))
    ImageDraw.Draw(edge).rectangle([0, 0, 7, 15], fill=(250, 100, 0, 125))
    out["16_alpha_edge.png"] = (edge, {})
    return out


def main() -> None:
    """画像を書き、colorthief の答えを expected.txt に書く。"""
    lines = []
    for name, (img, kw) in images().items():
        img.save(os.path.join(HERE, name), **kw)
    # 動く GIF（最初のコマが使われること）。
    f1 = Image.new("P", (16, 16))
    f1.putpalette([255, 0, 0, 0, 0, 255] + [0] * 762)
    f2 = f1.copy()
    ImageDraw.Draw(f2).rectangle([0, 0, 15, 15], fill=1)
    f1.save(os.path.join(HERE, "14_animated.gif"), save_all=True, append_images=[f2], duration=100, loop=0)
    for name in sorted(n for n in os.listdir(HERE) if n.endswith((".png", ".gif"))):
        with open(os.path.join(HERE, name), "rb") as f:
            data = f.read()
        try:
            red, green, blue = ColorThief(BytesIO(data)).get_color(quality=10)
            lines.append(f"{name} {(red << 16) + (green << 8) + blue:06x}")
        except Exception:
            lines.append(f"{name} none")
    with open(os.path.join(HERE, "expected.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
