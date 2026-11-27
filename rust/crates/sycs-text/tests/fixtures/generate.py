"""文字の描画と震度の札の基準（expected.json）を、本物の Python（Pillow・numpy）から作り直す。

Rust の Bot は、地震の画像の文字を Pillow と同じ画素で描く（rust/crates/sycs-text）。その「同じ」を CI で毎回
確かめるための基準を作る。Rust のテスト（rust/crates/sycs-text/tests/golden.rs）が、同じ文字・同じ文を描いて、
ここで作ったハッシュと比べる。

**本番と同じ環境で動かすこと**（Dockerfile と同じ apt のパッケージ〔ffmpeg・fonts-noto-cjk〕と requirements.txt）。

- `ffmpeg` を入れると libfribidi が入り、Pillow の文字の並べ方が raqm（HarfBuzz）になる。本番はこちら。
  無いと Pillow は別の並べ方（basic）に落ち、字の送りが変わる。この道具は raqm でなければ止まる。
- フォントは `fonts-noto-cjk` の NotoSansCJK-Regular.ttc と NotoSansCJK-Bold.ttc。ハッシュを基準に書き込み、
  Rust のテストは「同じファイルか」を先に確かめる。

使い方（リポジトリの直下を /app に置いて）:

    python rust/crates/sycs-text/tests/fixtures/generate.py rust/crates/sycs-text/tests/fixtures/expected.json

ハッシュにするバイト列の並び（リトルエンディアン。Rust のテストと合わせる）:

- 濃さの絵（`font.getmask2`）: u32 幅・u32 高さ・i32 ずれ x・i32 ずれ y・画素
- 1 文字ごと（chars）: 文字ごとに u32 文字の番号・i64 長さ（1/64 画素）・濃さの絵（anchor は la）
- 文ごと（strings）: lengths は i64 を文の順に。boxes は文ごと・anchor ごとに i32×4。
  masks は文ごと・anchor ごと・始点の小数ごとに濃さの絵
- 画像に描く（draws）: RGBA の画素
- 札（badges）: RGBA の画素（base は文字を置く前の 720x720、small はそれを縮めた 240x240、text は文字だけの層の
  720x720、full はできあがりの 240x240）
"""

import hashlib
import io
import json
import os
import random
import struct
import sys
import tempfile

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import numpy as np  # noqa: E402
import PIL  # noqa: E402
from PIL import Image, ImageDraw, ImageFont, features  # noqa: E402

from services import earthquake_service as eq  # noqa: E402

SCALES = [10, 20, 30, 40, 45, 50, 55, 60, 70]

# Python が実際に使う大きさ（services/earthquake_service.py）。
#   札（太字）: 見出し 70・数字 403・添え字 169
#   地図（通常、倍率 2）: 札の数字 21・26・31・36・40（1 字）と 15・19・22・26・29（2 字）、地名 26、題 46、副題 28、
#   「震度」と出典 22、凡例 27・20
SIZES = {True: [70, 169, 403], False: [15, 19, 20, 21, 22, 26, 27, 28, 29, 31, 36, 40, 46]}
# 漢字を全部（JIS 第 1・第 2 水準）見る大きさ。地名（26）と副題（28）は、どの字が来るか決まっていない。
KANJI_SIZES = {True: [70], False: [26, 28]}
# それ以外の大きさで見る漢字の数（第 1・第 2 水準から無作為に選ぶ）。
KANJI_SAMPLE = 300

ANCHORS = [h + v for h in "lmr" for v in "atmsbd"]
MASK_ANCHORS = ["la", "ls", "lm", "mm"]
STARTS = [(0.0, 0.0), (0.5, 0.5), (0.3, 0.8)]

PREFECTURES = (
    "北海道 青森県 岩手県 宮城県 秋田県 山形県 福島県 茨城県 栃木県 群馬県 埼玉県 千葉県 東京都 神奈川県 "
    "新潟県 富山県 石川県 福井県 山梨県 長野県 岐阜県 静岡県 愛知県 三重県 滋賀県 京都府 大阪府 兵庫県 "
    "奈良県 和歌山県 鳥取県 島根県 岡山県 広島県 山口県 徳島県 香川県 愛媛県 高知県 福岡県 佐賀県 長崎県 "
    "熊本県 大分県 宮崎県 鹿児島県 沖縄県"
).split()

# 震源の名前（気象庁の震央地名から）。
HYPOCENTERS = (
    "茨城県沖 福島県沖 宮城県沖 岩手県沖 三陸沖 青森県東方沖 十勝沖 釧路沖 根室半島南東沖 北海道東方沖 "
    "千葉県東方沖 千葉県北西部 東京湾 神奈川県西部 伊豆大島近海 新島・神津島近海 八丈島東方沖 父島近海 "
    "駿河湾 遠州灘 紀伊水道 能登半島沖 石川県能登地方 新潟県中越地方 長野県北部 岐阜県飛騨地方 "
    "京都府南部 大阪府北部 淡路島付近 鳥取県中部 安芸灘 伊予灘 豊後水道 日向灘 熊本県熊本地方 "
    "薩摩半島西方沖 トカラ列島近海 奄美大島近海 沖縄本島近海 与那国島近海 台湾付近 南太平洋 "
    "カムチャツカ半島付近 千島列島 胆振地方中東部 山梨県東部・富士五湖 フィリピン付近 チリ中部沖"
).split()

TEXTS = [
    # 札
    "最大震度",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "弱",
    "強",
    "5-",
    "5+",
    "6-",
    "6+",
    # 地図の題・副題・凡例・出典
    "震度分布",
    "最大震度 1",
    "最大震度 4",
    "最大震度 5弱",
    "最大震度 6強",
    "最大震度 7",
    "震度",
    eq._TILE_ATTRIBUTION,
    "M5.2",
    "M7.1",
    "40 km",
    "ごく浅い",
    "不明",
    "24日 12時54分ごろ",
    "茨城県沖  M5.2  40 km  24日 12時54分ごろ",
    "石川県能登地方  M7.6  ごく浅い  1日 16時10分ごろ",
    "新島・神津島近海  M4.3  10 km  3日 4時05分ごろ",
    "2026/08/24 12:54:41ごろ",
    "2026年8月24日 12時54分ごろ",
    "深さ 40 km",
    "M9.0  ごく浅い  31日 23時59分ごろ",
    # 並べ方（カーニング・合字・記号・空白・用字の変わり目）を確かめる文
    "AVATAR Wave To. Ty LT fi fl ffi ff",
    "The quick brown fox jumps over the lazy dog.",
    "0123456789 +-*/=()[]{}<>!?#$%&'\"@^_`|~\\;:,.",
    "km/h 3.5km VoldermortBot/1.0",
    "あいうえお がぎぐげご ぱぴぷぺぽ っゃゅょー",
    "アイウエオ ガギグゲゴ パピプペポ ッャュョー ヴ",
    "ｱｲｳｴｵ ｶﾞｷﾞ ﾊﾟﾋﾟ",
    "全角ＡＢＣ１２３！？（）「」『』【】、。・…―〜",
    "がき゚ヴ",
    "é à ü ñ ç ß é à",
    "→←↑↓ ○●◎△▲□■◆☆★ ※ 〒 ℃ ①②③",
    "東京都千代田区、大阪府大阪市。福岡県北九州市！",
    "日本「カナ」を(a「b)c",
    " 茨城県沖 ",
    "  ",
    " ",
    "",
]
TEXTS += PREFECTURES + HYPOCENTERS

MULTILINE = ["震度\n分布", "a\nbb\nccc", "最大震度 5弱\n茨城県沖  M5.2", "\nA", "あ\n\nい"]
BACKGROUNDS = [(0, 0, 0, 0), (38, 47, 62, 255), (10, 14, 21, 214), (255, 255, 255, 255), (226, 192, 62, 255)]
BACKGROUNDS += [(120, 140, 170, 110), (200, 100, 0, 1), (0, 0, 0, 255)]
FILLS = [(255, 255, 255, 255), (16, 20, 26, 255), (16, 20, 26, 170), (255, 255, 255, 170), (232, 238, 246, 255)]
FILLS += [(178, 192, 210, 255), (170, 186, 206, 255), (150, 165, 185, 255), (255, 72, 72, 128), (1, 2, 3, 0)]

FONT_PATHS = {False: eq._font_path(False), True: eq._font_path(True)}


def jis_kanji(first_row, last_row):
    """JIS X 0208 の区 first_row〜last_row の漢字（EUC-JP で引く）。"""
    out = []
    for row in range(first_row, last_row + 1):
        for cell in range(1, 95):
            try:
                out.append(bytes([0xA0 + row, 0xA0 + cell]).decode("euc_jp"))
            except UnicodeDecodeError:
                continue
    return out


def char_blocks():
    """1 文字ごとに確かめる文字を、種類ごとに分けて返す（名前 → 文字を並べた文）。"""
    ascii_chars = [chr(c) for c in range(0x20, 0x7F)]
    kana = [chr(c) for c in range(0x3041, 0x3097)] + [chr(c) for c in range(0x30A1, 0x30FD)]
    kana += list("、。・「」『』（）〜…")
    kanji = jis_kanji(16, 47) + jis_kanji(48, 84)
    seen = set(ascii_chars) | set(kana) | set(kanji)
    used = sorted({ch for text in TEXTS for ch in text} - seen)
    # 全部の漢字を見ない大きさでは、無作為に選んだ漢字（第 1・第 2 水準から）を見る。
    sample = random.Random(20261128).sample(kanji, KANJI_SAMPLE)
    return {
        "ascii": "".join(ascii_chars),
        "kana": "".join(kana),
        "used": "".join(used),
        "kanji": "".join(kanji),
        "kanji_sample": "".join(sample),
    }


def font_for(bold, size):
    """`_get_font(size, bold)`（Python の地震の画像と同じ開き方）。"""
    return eq._get_font(size, bold=bold)


def max_chars(size):
    """その大きさで濃さの絵まで作る文の、文字数の上限（大きい字で長い文を描くと絵が大きくなりすぎる）。"""
    if size >= 100:
        return 4
    if size >= 60:
        return 16
    return 1000


def mask_bytes(font, text, anchor, start):
    """`font.getmask2` の結果を、ハッシュにするバイト列にする。"""
    mask, offset = font.getmask2(text, "L", anchor=anchor, start=start)
    width, height = mask.size
    pixels = Image.new("L", (1, 1))._new(mask).tobytes() if width and height else b""
    return struct.pack("<IIii", width, height, offset[0], offset[1]) + pixels


def length_26_6(font, text):
    """`font.getlength` を 1/64 画素の整数で。"""
    return int(font.getlength(text) * 64)


def chars_entries(blocks):
    """1 文字ごとの基準（太さ・大きさ・文字の種類ごとにハッシュ 1 つ）。"""
    entries = []
    for bold in (False, True):
        for size in SIZES[bold]:
            font = font_for(bold, size)
            for name, chars in blocks.items():
                if name == "kanji" and size not in KANJI_SIZES[bold]:
                    continue
                if name == "kanji_sample" and size in KANJI_SIZES[bold]:
                    continue
                digest = hashlib.sha256()
                for ch in chars:
                    digest.update(struct.pack("<Iq", ord(ch), length_26_6(font, ch)))
                    digest.update(mask_bytes(font, ch, "la", (0.0, 0.0)))
                entries.append({"bold": bold, "size": size, "block": name, "sha256": digest.hexdigest()})
    return entries


def strings_entries():
    """文ごとの基準（太さ・大きさごとに、長さ・箱・濃さの絵のハッシュ）。"""
    entries = []
    for bold in (False, True):
        for size in SIZES[bold]:
            font = font_for(bold, size)
            lengths, boxes, masks = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
            for text in TEXTS:
                lengths.update(struct.pack("<q", length_26_6(font, text)))
                for anchor in ANCHORS:
                    boxes.update(struct.pack("<4i", *font.getbbox(text, "L", anchor=anchor)))
                if len(text) > max_chars(size):
                    continue
                for anchor in MASK_ANCHORS:
                    for start in STARTS:
                        masks.update(mask_bytes(font, text, anchor, start))
            entries.append(
                {
                    "bold": bold,
                    "size": size,
                    "max_chars": max_chars(size),
                    "lengths": lengths.hexdigest(),
                    "boxes": boxes.hexdigest(),
                    "masks": masks.hexdigest(),
                }
            )
    return entries


def draw_entries():
    """画像に描く基準（1 件ずつ。下地・座標・色・anchor を無作為に選ぶ）。"""
    rng = random.Random(20261127)
    entries = []
    for bold in (False, True):
        for size in SIZES[bold]:
            font = font_for(bold, size)
            texts = [text for text in TEXTS if len(text) <= max_chars(size)]
            if size < 60:
                texts += MULTILINE
            for _ in range(24):
                text = rng.choice(texts)
                anchor = rng.choice(ANCHORS if "\n" not in text else ["la", "ma", "rs", "ld", "mm"])
                width = min(int(size * (len(text) * 0.7 + 2)), 1400) + rng.randrange(0, 40)
                height = int(size * (2.2 + 1.5 * text.count("\n"))) + rng.randrange(0, 30)
                # 座標は 1/8 画素か 1/1000 画素の刻み（JSON にしても値が変わらない桁数にする）。
                grid = rng.choice([1, 2, 4, 8, 1000])
                xy = (
                    rng.randrange(-size * grid, width * grid) / grid,
                    rng.randrange(-size // 2 * grid, height * grid) / grid,
                )
                fill = rng.choice(FILLS + [tuple(rng.randrange(256) for _ in range(4))])
                background = rng.choice(BACKGROUNDS + [tuple(rng.randrange(256) for _ in range(4))])
                image = Image.new("RGBA", (width, height), background)
                ImageDraw.Draw(image).text(xy, text, font=font, fill=fill, anchor=anchor)
                entries.append(
                    {
                        "bold": bold,
                        "size": size,
                        "text": text,
                        "anchor": anchor,
                        "xy": list(xy),
                        "fill": list(fill),
                        "background": list(background),
                        "canvas": [width, height],
                        "sha256": hashlib.sha256(image.tobytes()).hexdigest(),
                    }
                )
    return entries


def badge_entries():
    """札の基準（震度の値ごとに、段ごとの画素のハッシュ）。"""
    entries = {}
    for scale in SCALES:
        ss, size = 3, 240
        w = h = size * ss
        # 文字を置く前の段を、_generate_badge と同じ手順で作る。
        mask = eq._squircle(w, h)
        base = eq._badge_ground(w, h, eq._MAP_FILL_RGB[scale])
        base.putalpha(Image.fromarray((mask * 255).astype(np.uint8), "L"))
        base.alpha_composite(eq._badge_rim(w, h, mask))
        small = base.resize((size, size), Image.LANCZOS)

        # 文字だけの層: _generate_badge が作る透明の画像を横から覗く。
        holder = {}
        real_new = Image.new

        def spy_new(mode, sz, color=0, _holder=holder, _real=real_new, _size=(w, h)):
            """`Image.new` の代わり。文字の層だけ控える。"""
            image = _real(mode, sz, color)
            if mode == "RGBA" and sz == _size and color == (0, 0, 0, 0):
                _holder["text"] = image
            return image

        Image.new = spy_new
        try:
            png = eq._generate_badge(scale).getvalue()
        finally:
            Image.new = real_new
        full = Image.open(io.BytesIO(png)).convert("RGBA")
        entries[str(scale)] = {
            name: hashlib.sha256(image.tobytes()).hexdigest()
            for name, image in (("base", base), ("small", small), ("text", holder["text"]), ("full", full))
        }
    return entries


def file_sha256(path):
    """ファイルの SHA-256。"""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main(out):
    """基準を作って書き出す。"""
    if not eq._has_cjk_font() or FONT_PATHS[True] is None:
        raise SystemExit("和字のフォント（fonts-noto-cjk）がありません。本番と同じ環境で動かしてください。")
    if not features.check_feature("raqm"):
        raise SystemExit("raqm が無効です（libfribidi が無い）。本番と同じ apt（ffmpeg）を入れて動かしてください。")
    if any(font_for(bold, 20).layout_engine != ImageFont.Layout.RAQM for bold in (False, True)):
        raise SystemExit("フォントの並べ方が raqm になっていません。")
    blocks = char_blocks()
    expected = {
        "environment": {
            "pillow": PIL.__version__,
            "numpy": np.__version__,
            "freetype": features.version("freetype2"),
            "raqm": features.version("raqm"),
            "harfbuzz": features.version("harfbuzz"),
        },
        "fonts": {
            "regular": {"path": FONT_PATHS[False], "sha256": file_sha256(FONT_PATHS[False])},
            "bold": {"path": FONT_PATHS[True], "sha256": file_sha256(FONT_PATHS[True])},
        },
        "anchors": ANCHORS,
        "mask_anchors": MASK_ANCHORS,
        "starts": [list(start) for start in STARTS],
        "texts": TEXTS,
        "char_blocks": blocks,
        "chars": chars_entries(blocks),
        "strings": strings_entries(),
        "draws": draw_entries(),
        "badges": badge_entries(),
    }
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(expected, f, ensure_ascii=False, indent=1)
        f.write("\n")
    counts = {name: len(chars) for name, chars in blocks.items()}
    print(f"書いた: {out}（文 {len(TEXTS)}・文字 {counts}・描く {len(expected['draws'])} 件）")
    print(json.dumps(expected["environment"], ensure_ascii=False), expected["fonts"])


if __name__ == "__main__":
    main(sys.argv[1])
