import asyncio
import io
import json
import logging
import math
import os
import re
import time
from collections import deque
from datetime import datetime

import aiohttp
import discord
from discord.ext.commands import Bot

try:
    # ImageFilter は落ち影のぼかし、numpy は白地図の塗り替えと暈の生成に使う。
    # numpy は requirements にあり、PIL と同じく画像生成にだけ要る。
    import numpy as np
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
    _PIL = True
except ImportError:
    _PIL = False

from config import BOT_ICON_URL, JST as _JST, SCALE_LABELS as _SCALE_DISPLAY
from services.ttl_cache import TTLCache
from services.settings_store import (
    get_all_guild_ids,
    get_earthquake_notify_types,
    get_earthquake_settings,
)

logger = logging.getLogger(__name__)

_WS_URL  = "wss://api.p2pquake.net/v2/ws"
_SEEN_ID_LIMIT = 500  # 重複排除で覚えておくイベントIDの数
# 地図のタイル。
#
# 以前は CARTO の dark_all を使っていたが、鍵が要るようになり、届く画像に
# 「API KEY REQUIRED」が斜めに刷り込まれるようになった。それをそのまま
# Discord へ流していた。
#
# 地理院タイルの白地図（blank）に替える。鍵は要らず、出典を書けば自由に
# 使える（政府標準利用規約）。白地図なので文字も色も入っておらず、こちらで
# 暗色へ塗り替えられる。1枚 13KB と軽い（標準地図は 117KB）。
_TILE_URL = "https://cyberjapandata.gsi.go.jp/xyz/blank/{z}/{x}/{y}.png"
_TILE_ATTRIBUTION = "地理院タイル（国土地理院）"
_TILE_UA  = "VoldermortBot/1.0 (earthquake alert; contact: github)"
_TILE_SZ  = 256

# 都道府県中心座標（エリア座標APIが存在しないため都道府県単位でフォールバック）
_PREF_CENTERS: dict[str, tuple[float, float]] = {
    "北海道": (43.064, 141.347), "青森県": (40.824, 140.740), "岩手県": (39.703, 141.153),
    "宮城県": (38.268, 140.872), "秋田県": (39.718, 140.102), "山形県": (38.240, 140.363),
    "福島県": (37.750, 140.468), "茨城県": (36.341, 140.447), "栃木県": (36.565, 139.883),
    "群馬県": (36.391, 139.060), "埼玉県": (35.857, 139.649), "千葉県": (35.605, 140.123),
    "東京都": (35.689, 139.692), "神奈川県": (35.447, 139.642), "新潟県": (37.902, 139.023),
    "富山県": (36.695, 137.211), "石川県": (36.594, 136.626), "福井県": (36.065, 136.222),
    "山梨県": (35.664, 138.568), "長野県": (36.651, 138.181), "岐阜県": (35.391, 136.722),
    "静岡県": (34.977, 138.383), "愛知県": (35.180, 136.906), "三重県": (34.730, 136.509),
    "滋賀県": (35.004, 135.869), "京都府": (35.021, 135.756), "大阪府": (34.686, 135.520),
    "兵庫県": (34.691, 135.183), "奈良県": (34.685, 135.833), "和歌山県": (34.226, 135.167),
    "鳥取県": (35.503, 134.238), "島根県": (35.472, 133.051), "岡山県": (34.661, 133.934),
    "広島県": (34.396, 132.460), "山口県": (34.186, 131.471), "徳島県": (34.066, 134.559),
    "香川県": (34.340, 134.043), "愛媛県": (33.842, 132.766), "高知県": (33.560, 133.531),
    "福岡県": (33.606, 130.418), "佐賀県": (33.249, 130.299), "長崎県": (32.745, 129.874),
    "熊本県": (32.789, 130.742), "大分県": (33.238, 131.613), "宮崎県": (31.911, 131.424),
    "鹿児島県": (31.560, 130.558), "沖縄県": (26.212, 127.681),
}

# マップ上の震度圏塗り色 — Kiwi Monitor V2 準拠
# 震度の色。気象庁の並びに沿いつつ、暗い地図の上で沈まないよう明度を上げ、
# 原色のままだと安っぽく見えるので彩度を少し落としてある。
_MAP_FILL_RGB = {
    10: ( 58, 122, 216), 20: ( 46, 158, 214), 30: ( 44, 176, 154),
    40: (226, 192,  62), 45: (232, 152,  48),
    50: (233, 119,  43), 55: (226,  78,  44),
    60: (206,  47,  62), 70: (132,  44, 128),
}

# 地図の面と線の色（暗い埋め込みに合わせる）。白地図を塗り替えるときに使う。
_MAP_SEA = (11, 15, 22)
_MAP_LAND = (38, 47, 62)
_MAP_LINE = (96, 114, 142)

# 出力の大きさと、描画時の倍率。
#
# PIL の ellipse / line はアンチエイリアスしないので、等倍で描くと円も×印も
# 階段状になる（これが「チープに見える」いちばんの原因だった）。倍で描いて
# から縮小すると、縮小の平均化がそのままアンチエイリアスになる。
# 幅を 900 から広げた。観測点は県庁所在地に丸めてあるので札の数は最大47枚だが、
# 900 幅では東北のように県が密なところで札が重なり、重なり避けで消えていた。
_MAP_W, _MAP_H = 1200, 720
_MAP_SS = 2

# 凡例・ログ用（全角）
# 全角表記（凡例・ログ用）。対応は config.SCALE_LABELS と同じ仕様に従う。
_SCALE_MAP = {
    10: "１", 20: "２", 30: "３", 40: "４", 45: "５弱",
    50: "５強", 55: "６弱", 60: "６強", 70: "７",
}

# バッジ画像用（ASCII のみ・CJK フォント不要）
_SCALE_BADGE_LABEL = {
    10: "1", 20: "2", 30: "3", 40: "4", 45: "5-",
    50: "5+", 55: "6-", 60: "6+", 70: "7",
}

# EEW予報 (556) の forecastMaxInt 文字列 → 内部スケール値
_FORECAST_INT_TO_SCALE: dict[str, int] = {
    "1": 10, "2": 20, "3": 30, "4": 40,
    "5-": 45, "5+": 50, "6-": 55, "6+": 60, "7": 70,
}

# 震度別 RGB — Kiwi Monitor カラースキーム 第2版
_SCALE_RGB = {
    10: (  0,  64, 255), 20: (  0, 148, 255), 30: (  0, 200, 200),
    40: (250, 230,  20), 45: (255, 175,   0),
    50: (255, 120,   0), 55: (255,  60,   0),
    60: (220,   0,   0), 70: (110,   0, 130),
}

_SCALE_COLORS = {k: discord.Color.from_rgb(*v) for k, v in _SCALE_RGB.items()}

# タイトル絵文字（震度別）
_SCALE_TITLE_EMOJI = {
    10: "🔵", 20: "🔵", 30: "🔵",
    40: "🟡", 45: "🟠",
    50: "🟠", 55: "🔴",
    60: "🔴", 70: "🔴",
}

_TSUNAMI_TEXT = {
    "None":         "この地震による津波の心配はありません。",
    "Unknown":      "津波の有無を調査中です。",
    "Checking":     "津波の有無を調査中です。",
    "NonEffective": "この地震による津波の心配はありません。",
    "Watch":        "⚠️ 津波注意報が発令されています。",
    "Warning":      "🚨 津波警報が発令されています！",
}

_TSUNAMI_GRADE_LABELS: dict[str, str] = {
    "MajorWarning": "🔴 大津波警報",
    "Warning":      "🟠 津波警報",
    "Watch":        "🟡 津波注意報",
    "Unknown":      "❓ 不明",
}

_TSUNAMI_GRADE_ORDER: dict[str, int] = {
    "MajorWarning": 3, "Warning": 2, "Watch": 1, "Unknown": 0,
}

_ISSUE_LABELS = {
    "ScalePrompt":         "気象庁 震度速報",
    "Destination":         "気象庁 震源に関する情報",
    "ScaleAndDestination": "気象庁 震度・震源に関する情報",
    "DetailScale":         "気象庁 各地の震度に関する情報",
    "Foreign":             "気象庁 遠地地震に関する情報",
    "Other":               "気象庁",
}


# ── フォントローダー ───────────────────────────────────────

_FONT_SEARCH_PATHS = [
    # Debian/Ubuntu: fonts-noto-cjk パッケージ
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKjp-Regular.otf",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
    # Windows
    "C:/Windows/Fonts/meiryo.ttc",
    "C:/Windows/Fonts/msgothic.ttc",
    "C:/Windows/Fonts/YuGothR.ttc",
]
_FONT_PATH: str | None = None
_FONT_CACHE: dict[int, "ImageFont.ImageFont"] = {}


def _get_font(size: int) -> "ImageFont.ImageFont":
    global _FONT_PATH
    if size in _FONT_CACHE:
        return _FONT_CACHE[size]

    if _FONT_PATH is None:
        for p in _FONT_SEARCH_PATHS:
            if os.path.exists(p):
                _FONT_PATH = p
                break

    font = None
    if _FONT_PATH:
        try:
            font = ImageFont.truetype(_FONT_PATH, size)
        except Exception as e:
            # サイズごとに _FONT_CACHE へ結果を残すため、ここは初回の一度しか
            # 通らない。既定フォントへ切り替わったこと自体は害が無いが、
            # 理由を残さないと「なぜ見た目のフォントが違うか」が追えない。
            logger.warning("[earthquake] フォント %s の読み込みに失敗: %s", _FONT_PATH, e)

    if font is None:
        try:
            font = ImageFont.load_default(size=size)
        except TypeError:
            font = ImageFont.load_default()

    _FONT_CACHE[size] = font
    return font


# ── データ解析ヘルパー ─────────────────────────────────────

def _max_scale(event: dict) -> int:
    points = event.get("points", [])
    if points:
        return max((p.get("scale", -1) for p in points), default=-1)
    # EEW予報 (556) は points ではなく areas に地域ごとの予想震度レンジ
    # (scaleFrom/scaleTo) が入る。以前は intensity.forecastMaxInt.to を
    # 見ていたが、実際のペイロードにその形は現れず（P2PQuake の実データで
    # 確認済み）、556 の予想最大震度が常に「不明」になっていた。
    areas = event.get("areas", [])
    if areas:
        return max((a.get("scaleTo", a.get("scaleFrom", -1)) for a in areas), default=-1)
    eq_scale = event.get("earthquake", {}).get("maxScale", -1)
    if eq_scale >= 0:
        return eq_scale
    # 保険: 上記のどれにも当てはまらない別形式のペイロード用
    to_str = event.get("intensity", {}).get("forecastMaxInt", {}).get("to", "")
    return _FORECAST_INT_TO_SCALE.get(to_str, -1)


def _parse_coord(raw) -> float | None:
    """'N35.8' / 'E137.7' / float → float。0・±200 (P2PQuake 無効値) は None。"""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        v = float(raw)
        return v if v != 0 and abs(v) <= 180 else None
    s = str(raw).strip()
    sign = -1 if s[:1] in ("S", "W") else 1
    try:
        v = sign * float(re.sub(r"^[NSEWnsew]", "", s))
        return v if v != 0 and abs(v) <= 180 else None
    except ValueError:
        return None


def _parse_depth(raw) -> str:
    if raw is None:
        return "不明"
    if isinstance(raw, str):
        if "浅" in raw:
            return "ごく浅い"
        try:
            v = int(float(raw))
            if v < 0:
                return "不明"
            return "ごく浅い" if v == 0 else f"{v} km"
        except ValueError:
            return raw or "不明"
    try:
        v = int(raw)
        if v < 0:
            return "不明"
        return "ごく浅い" if v == 0 else f"{v} km"
    except (TypeError, ValueError):
        return "不明"


def _parse_magnitude(raw) -> tuple[str, float]:
    try:
        v = float(raw)
        return (f"M{v}", v) if v >= 0 else ("不明", -1.0)
    except (TypeError, ValueError):
        return "不明", -1.0


def _format_time(time_str: str) -> tuple[str, datetime | None]:
    if not time_str:
        return "不明", None
    try:
        dt = datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=_JST)
        return f"{dt.day}日 {dt.hour}時{dt.minute:02d}分ごろ", dt
    except ValueError:
        return f"{time_str}ごろ", None


# ── バッジ画像生成 ─────────────────────────────────────────

def _generate_badge(scale: int) -> io.BytesIO | None:
    """震度バッジを生成して BytesIO で返す。

    以前は等倍で角丸と文字を描いていたため、角が階段状に出て安っぽかった
    （PIL はアンチエイリアスしない）。倍で描いてから縮めると、縮小の平均化が
    そのままアンチエイリアスになる。
    """
    if not _PIL:
        return None

    rgb = _MAP_FILL_RGB.get(scale, (120, 130, 150))
    label = _SCALE_BADGE_LABEL.get(scale, str(scale))

    ss = 3
    size = 180
    w = h = size * ss
    header_h = 44 * ss
    radius = 22 * ss

    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 本体。上から下へわずかに沈ませて、平らな板に見えないようにする。
    draw.rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, fill=(*rgb, 255))
    shade = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    shade_draw = ImageDraw.Draw(shade)
    for row in range(header_h, h):
        t = (row - header_h) / max(1, h - header_h)
        shade_draw.line([(0, row), (w, row)], fill=(0, 0, 0, int(46 * t ** 1.4)))
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, fill=255)
    img.alpha_composite(Image.composite(shade, Image.new("RGBA", (w, h), (0, 0, 0, 0)), mask))

    # 見出しの帯。角丸は上だけなので、下側は四角で埋める。
    header = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    hd = ImageDraw.Draw(header)
    hd.rounded_rectangle([0, 0, w - 1, header_h + radius], radius=radius, fill=(9, 13, 21, 255))
    hd.rectangle([0, header_h, w - 1, header_h + radius], fill=(9, 13, 21, 255))
    img.alpha_composite(Image.composite(header, Image.new("RGBA", (w, h), (0, 0, 0, 0)), mask))
    draw.rectangle([0, header_h - ss, w - 1, header_h], fill=(255, 255, 255, 38))

    draw.text((w / 2, header_h / 2), "最大震度", font=_get_font(int(21 * ss)),
              fill=(226, 234, 244, 255), anchor="mm")

    # 数字。明るい震度では白が沈むので黒に切り替える。
    body_cy = header_h + (h - header_h) / 2
    draw.text((w / 2, body_cy), label,
              font=_get_font(int(size * ss * (0.50 if len(label) == 1 else 0.34))),
              fill=_ink_for(rgb), anchor="mm")

    # 縁の光。板の厚みに見せる。
    draw.rounded_rectangle([0, 0, w - 1, h - 1], radius=radius,
                           outline=(255, 255, 255, 46), width=max(1, ss))

    buf = io.BytesIO()
    img.resize((size, size), Image.LANCZOS).save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf


# ── 地図生成ヘルパー ───────────────────────────────────────

def _latlon_to_tile_float(lat: float, lon: float, zoom: int) -> tuple[float, float]:
    n = 2 ** zoom
    tx = (lon + 180) / 360 * n
    lat_r = math.radians(lat)
    ty = (1 - math.asinh(math.tan(lat_r)) / math.pi) / 2 * n
    return tx, ty



def _resolve_point_coord(addr: str, pref: str) -> tuple[float, float] | None:
    """pref / addr → (lat, lon)。都道府県中心座標を使用。"""
    return _PREF_CENTERS.get(pref) or _PREF_CENTERS.get(addr)


async def _fetch_tile(session: aiohttp.ClientSession, z: int, x: int, y: int):
    url = _TILE_URL.format(z=z, x=x, y=y)
    try:
        async with session.get(
            url,
            headers={"User-Agent": _TILE_UA},
            timeout=aiohttp.ClientTimeout(total=3),
        ) as resp:
            if resp.status == 200:
                data = await resp.read()
                # 白地図は「白い面に細い黒線」。明るさだけ使うので L で受ける。
                return Image.open(io.BytesIO(data)).convert("L")
    except Exception as e:
        logger.debug("[earthquake] tile %d/%d/%d fetch error: %s", z, x, y, e)
    return None


def _recolour_tile(gray: "Image.Image") -> "Image.Image":
    """白地図を暗色の地図へ塗り替える。

    白地図は白い面に細い黒線なので、明るさをそのまま「線の濃さ」として読み、
    陸の色から線の色へ混ぜる。こうすると配信元の見た目に縛られず、埋め込みの
    暗い背景に合う地図を自前で作れる。
    """
    values = np.asarray(gray, dtype=np.float32) / 255.0
    ink = np.clip(1.0 - values, 0.0, 1.0)[..., None]
    land = np.array(_MAP_LAND, dtype=np.float32)
    line = np.array(_MAP_LINE, dtype=np.float32)
    return Image.fromarray((land * (1 - ink) + line * ink).astype(np.uint8), "RGB")



def _ink_for(rgb: tuple[int, int, int]) -> tuple[int, int, int, int]:
    """その色の上に置く文字の色。明るい震度では白が沈む。"""
    luma = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]
    return (16, 20, 26, 255) if luma > 150 else (255, 255, 255, 255)


def _badge_size(scale: int) -> int:
    """震度の札の一辺（ss を掛ける前）。強いほど大きく。

    全部同じ大きさにすると、震度1の海のなかから震度5弱を探すことになる。
    大小を付けておくと、色が読めなくても視線が強い方へ落ちる。
    """
    if scale >= 55:      # 6弱以上
        return 34
    if scale >= 45:      # 5弱・5強
        return 30
    if scale >= 40:      # 4
        return 26
    if scale >= 30:      # 3
        return 22
    return 18            # 1・2


def _scale_badge(scale: int, size: int) -> "Image.Image":
    """観測点の札。角丸の座に震度の数字を入れる。

    以前は「全点は色だけの小さな丸、上位6点だけ数字の札」だった。丸は色しか
    情報を持たないので、震度4(黄)と5弱(橙)を並べても一目では分からない。
    凡例と同じ角丸＋数字に揃え、地図の上でも凡例と同じ読み方ができるようにする。
    """
    rgb = _MAP_FILL_RGB.get(scale, (120, 130, 150))
    label = _SCALE_BADGE_LABEL.get(scale, str(scale))
    pad = size // 3
    img = Image.new("RGBA", (size + pad * 2, size + pad * 2), (0, 0, 0, 0))

    # 落ち影。暗い地図の上で札の縁が溶けないよう、下に薄く敷く。
    shade = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(shade).rounded_rectangle(
        [pad, pad + size // 10, pad + size, pad + size + size // 10],
        radius=size // 4, fill=(0, 0, 0, 165))
    img.alpha_composite(shade.filter(ImageFilter.GaussianBlur(size / 8)))

    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([pad, pad, pad + size, pad + size], radius=size // 4,
                           fill=(*rgb, 255), outline=(255, 255, 255, 210),
                           width=max(1, size // 14))
    # 「5-」のような2文字は1文字より小さく組む。同じ字送りだと札からはみ出す。
    font = _get_font(int(size * (0.60 if len(label) == 1 else 0.44)))
    draw.text((pad + size / 2, pad + size / 2 + size // 28), label, font=font,
              fill=_ink_for(rgb), anchor="mm")
    return img


def _epicentre_marker(size: int) -> "Image.Image":
    """震源。二重の輪と十字にして、震度の札と見分けられるようにする。

    以前は赤い × 印だけで、観測点の四角と紛れていた。
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    centre, radius = size / 2, size / 2 - size // 10
    for r, width, alpha in ((radius, max(1, size // 12), 255),
                            (radius * 0.62, max(1, size // 14), 210)):
        draw.ellipse([centre - r, centre - r, centre + r, centre + r],
                     outline=(255, 72, 72, alpha), width=width)
    arm = radius * 1.16
    for dx, dy in ((1, 0), (0, 1)):
        draw.line([centre - arm * dx, centre - arm * dy,
                   centre + arm * dx, centre + arm * dy],
                  fill=(255, 72, 72, 255), width=max(1, size // 12))
    return img


def _label_box(canvas: "Image.Image", text: str) -> tuple[int, int]:
    """地名ラベルの大きさ。"""
    ss = _MAP_SS
    width = int(ImageDraw.Draw(canvas).textlength(text, font=_get_font(13 * ss)))
    return width + 12 * ss, 19 * ss


def _draw_place_label(canvas: "Image.Image", left: float, top: float, text: str) -> None:
    """地名ラベルを1枚置く。

    震度の丸と数字だけでは、地図に詳しくないと「どこの話か」が読み取れない。
    暗い座を敷いてから字を置く（地図の上にそのまま置くと、陸の模様に紛れる）。
    """
    ss = _MAP_SS
    width, height = _label_box(canvas, text)
    box = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    ImageDraw.Draw(box).rounded_rectangle(
        [0, 0, width - 1, height - 1], radius=5 * ss,
        fill=(10, 14, 21, 214), outline=(120, 140, 170, 110), width=max(1, ss // 2))
    canvas.alpha_composite(box, (int(left), int(top)))
    ImageDraw.Draw(canvas).text((left + 6 * ss, top + height / 2), text,
                                font=_get_font(13 * ss), fill=(232, 238, 246, 255), anchor="lm")


def _draw_map_chrome(canvas: "Image.Image", title: str, subtitle: str,
                     scales: list[int]) -> None:
    """見出しの帯・凡例・出典。画像だけを見ても意味が通るようにする。

    以前は地図と円だけで、色が何の震度を指すのか画像からは分からなかった。
    """
    ss = _MAP_SS
    width, height = canvas.size
    draw = ImageDraw.Draw(canvas)

    band_h = 74 * ss
    band = Image.new("RGBA", (width, band_h), (0, 0, 0, 0))
    band_draw = ImageDraw.Draw(band)
    for row in range(band_h):
        band_draw.line([(0, row), (width, row)],
                       fill=(10, 13, 20, int(215 * (1 - row / band_h) ** 1.3)))
    canvas.alpha_composite(band, (0, 0))
    draw.text((22 * ss, 20 * ss), title, font=_get_font(23 * ss), fill=(255, 255, 255, 255))
    if subtitle:
        draw.text((22 * ss, 47 * ss), subtitle, font=_get_font(14 * ss),
                  fill=(178, 192, 210, 255))

    # 最大震度は帯の右端に、その震度の色で大きく置く。
    #
    # 見出しの文字列にも「最大震度6強」とは書いてあるが、地図に落ちた札を
    # 目で追って最大値を探すのと、数字が1つ大きく出ているのとでは、読み取りに
    # かかる時間が違う。速報として最初に伝わるべき値なので、色と大きさを与える。
    if scales:
        top = max(scales)
        rgb = _MAP_FILL_RGB.get(top, (120, 130, 150))
        label = _SCALE_BADGE_LABEL.get(top, str(top))
        box_w, box_h = 96 * ss, 58 * ss
        bx = width - box_w - 20 * ss
        by = 12 * ss
        seat = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        ImageDraw.Draw(seat).rounded_rectangle(
            [0, 0, box_w - 1, box_h - 1], radius=10 * ss, fill=(*rgb, 255))
        canvas.alpha_composite(seat, (int(bx), int(by)))
        ink = _ink_for(rgb)
        draw.text((bx + box_w / 2, by + 13 * ss), "最大震度", font=_get_font(12 * ss),
                  fill=(*ink[:3], 215), anchor="mm")
        draw.text((bx + box_w / 2, by + 38 * ss), label,
                  font=_get_font(int(34 * ss * (1.0 if len(label) == 1 else 0.78))),
                  fill=ink, anchor="mm")

    chip, gap, pad = 22 * ss, 7 * ss, 12 * ss
    box_w = pad * 2 + len(scales) * chip + max(0, len(scales) - 1) * gap
    box_h = pad * 2 + chip + 15 * ss
    bx, by = width - box_w - 16 * ss, height - box_h - 16 * ss
    panel = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
    ImageDraw.Draw(panel).rounded_rectangle(
        [0, 0, box_w - 1, box_h - 1], radius=9 * ss,
        fill=(12, 16, 24, 208), outline=(120, 140, 170, 120), width=max(1, ss))
    canvas.alpha_composite(panel, (int(bx), int(by)))
    draw.text((bx + pad, by + pad - ss), "震度", font=_get_font(11 * ss),
              fill=(170, 186, 206, 255))
    for index, scale in enumerate(scales):
        x = bx + pad + index * (chip + gap)
        y = by + pad + 14 * ss
        rgb = _MAP_FILL_RGB.get(scale, (120, 130, 150))
        label = _SCALE_BADGE_LABEL.get(scale, str(scale))
        draw.rounded_rectangle([x, y, x + chip, y + chip], radius=5 * ss, fill=(*rgb, 255))
        draw.text((x + chip / 2, y + chip / 2), label,
                  font=_get_font(int(chip * (0.62 if len(label) == 1 else 0.46))),
                  fill=_ink_for(rgb), anchor="mm")

    font = _get_font(11 * ss)
    text_w = int(draw.textlength(_TILE_ATTRIBUTION, font=font))
    draw.rectangle([0, height - 19 * ss, text_w + 16 * ss, height], fill=(8, 11, 17, 190))
    draw.text((8 * ss, height - 16 * ss), _TILE_ATTRIBUTION, font=font,
              fill=(150, 165, 185, 255))


async def _generate_intensity_map(
    session: aiohttp.ClientSession,
    lat: float,
    lon: float,
    points: list[dict],
    title: str = "震度分布",
    subtitle: str = "",
) -> io.BytesIO | None:
    """観測点の震度を地図に落として BytesIO で返す。"""
    if not _PIL:
        return None

    # (緯度, 経度, 震度, 地名)。地名まで持つのは、画像だけを見て「どこの話か」が
    # 分かるようにするため。震度の丸だけでは、地図に詳しくないと読み取れない。
    plot: list[tuple[float, float, int, str]] = []
    for point in points:
        scale = point.get("scale", -1)
        if scale < 10:
            continue
        pref = str(point.get("pref", "") or "")
        coord = _resolve_point_coord(point.get("addr", ""), pref)
        if coord:
            plot.append((*coord, scale, pref or str(point.get("addr", "") or "")))

    if not plot:
        return None

    # 観測点の座標は県庁所在地に丸めている（_resolve_point_coord）。同じ県の
    # 観測点は全部ひとつの座標に重なるので、いちばん強い震度だけ残す。
    # 残さないと、同じ場所に何枚も丸を描いたうえ、札の重なり避けで肝心の
    # 最大震度が弾かれる。
    strongest: dict[tuple[float, float], tuple[int, str]] = {}
    for point_lat, point_lon, scale, name in plot:
        key = (point_lat, point_lon)
        if scale > strongest.get(key, (-1, ""))[0]:
            strongest[key] = (scale, name)
    plot = [(k[0], k[1], v[0], v[1]) for k, v in strongest.items()]

    lats = [p[0] for p in plot] + [lat]
    lons = [p[1] for p in plot] + [lon]

    # 全部が入り、かつ余白が残る一番大きなズームを選ぶ。
    zoom = 5
    for candidate in range(11, 4, -1):
        x0, _ = _latlon_to_tile_float(max(lats), min(lons), candidate)
        x1, _ = _latlon_to_tile_float(min(lats), max(lons), candidate)
        _, y0 = _latlon_to_tile_float(max(lats), min(lons), candidate)
        _, y1 = _latlon_to_tile_float(min(lats), max(lons), candidate)
        # 収まる範囲でできるだけ大きく。0.80/0.70 のころは海ばかりが写り、
        # 肝心の札が画面の 1/3 に押し込められていた。上の帯と凡例の分だけ
        # 縦を控えめにする。
        if (abs(x1 - x0) * _TILE_SZ < _MAP_W * 0.92
                and abs(y1 - y0) * _TILE_SZ < _MAP_H * 0.84):
            zoom = candidate
            break

    centre_x, centre_y = _latlon_to_tile_float(
        (max(lats) + min(lats)) / 2, (max(lons) + min(lons)) / 2, zoom)
    origin_x = centre_x * _TILE_SZ - _MAP_W / 2
    origin_y = centre_y * _TILE_SZ - _MAP_H / 2

    tx0, ty0 = int(origin_x // _TILE_SZ), int(origin_y // _TILE_SZ)
    tx1 = int((origin_x + _MAP_W) // _TILE_SZ)
    ty1 = int((origin_y + _MAP_H) // _TILE_SZ)
    coords = [(tx, ty) for ty in range(ty0, ty1 + 1) for tx in range(tx0, tx1 + 1)]
    tiles = await asyncio.gather(
        *(_fetch_tile(session, zoom, tx, ty) for tx, ty in coords),
        return_exceptions=True,
    )

    # ここから先は PIL の同期処理（塗り替え・合成・描画・PNG の保存）。倍で
    # 描いてから縮小するので、直に実行すると Bot のイベントループが数百ミリ秒
    # 止まる——緊急地震速報を全ギルドへ配信しようとしている、まさにその瞬間に。
    # 余震が続けば短時間に何度も起きる。スレッドへ逃がす。
    return await asyncio.to_thread(
        _compose_intensity_map, coords, tiles, origin_x, origin_y,
        zoom, plot, lat, lon, title, subtitle,
    )


def _compose_intensity_map(
    coords: list[tuple[int, int]],
    tiles: list,
    origin_x: float, origin_y: float,
    zoom: int,
    plot: list[tuple[float, float, int]],
    lat: float, lon: float,
    title: str, subtitle: str,
) -> io.BytesIO:
    """取り込んだタイルから地図を組み立てる（同期。呼ぶ側がスレッドへ逃がす）。"""
    ss = _MAP_SS

    # 地図の面。白地図を暗色へ塗り替えてから貼る。
    base = Image.new("RGB", (_MAP_W, _MAP_H), _MAP_SEA)
    for (tx, ty), tile in zip(coords, tiles):
        if not isinstance(tile, Image.Image):
            continue
        base.paste(_recolour_tile(tile),
                   (int(tx * _TILE_SZ - origin_x), int(ty * _TILE_SZ - origin_y)))

    # 倍に伸ばしてから描き、最後に縮める。PIL は円も線もアンチエイリアス
    # しないので、これが輪郭のなめらかさをそのまま決める。
    canvas = base.resize((_MAP_W * ss, _MAP_H * ss), Image.LANCZOS).convert("RGBA")

    def to_px(point_lat: float, point_lon: float) -> tuple[float, float]:
        px, py = _latlon_to_tile_float(point_lat, point_lon, zoom)
        return ((px * _TILE_SZ - origin_x) * ss, (py * _TILE_SZ - origin_y) * ss)

    # 暈（最大震度のまわりの淡い円）は置かない。
    # 札が色だけの丸だったころは視線を導く役に立っていたが、札に数字と大小が
    # 入った今は、最大震度の札そのものを赤くにじませて読みにくくするだけ。
    def overlaps(box: tuple[float, float, float, float],
                 rects: list[tuple[float, float, float, float]]) -> bool:
        return any(not (box[2] <= r[0] or box[0] >= r[2]
                        or box[3] <= r[1] or box[1] >= r[3]) for r in rects)

    # 観測点。全部の札に震度の数字を入れる。
    #
    # 以前は「全点を色だけの丸で打ち、上位6点にだけ数字の札」という二段構えで、
    # 地図の大半は色しか情報を持っていなかった。震度4と5弱は黄と橙で隣同士
    # なので、縮小されて届く Discord の埋め込みでは一目で見分けられない。
    #
    # 数字を全部に入れると密集地で重なるので、強い順に置いて、既に置いた札と
    # 重なるものは落とす。落とすのは常に弱い方（速報として消してよいのは
    # 弱い方だけ）。距離ではなく実際の矩形で見るので、札の大小を変えても
    # 間隔の定数を調整し直さなくてよい。
    #
    # 震源の位置は「空けておく枠」に入れない。入れていたときは、震源のすぐ
    # 隣にある最大震度の札が弾かれて地図から消えていた（青森県沖の地震で
    # 6強と6弱の札が両方とも出なかった）。速報で最初に見るべき札を、
    # 重なり避けの都合で消してはいけない。震源は最後に上から描く。
    taken: list[tuple[float, float, float, float]] = []
    badges: list[tuple[float, float, int]] = []
    placed_at: set[tuple[float, float]] = set()
    for index, (point_lat, point_lon, scale, _name) in enumerate(
            sorted(plot, key=lambda p: -p[2])):
        x, y = to_px(point_lat, point_lon)
        half = _badge_size(scale) * ss / 2
        box = (x - half, y - half, x + half, y + half)
        # 先頭＝最大震度は無条件で置く。見出しに出す震度が地図に無いと、
        # 画像と本文が食い違って見える。
        if index and overlaps(box, taken):
            continue
        taken.append(box)
        badges.append((x, y, scale))
        placed_at.add((point_lat, point_lon))

    # 震源は札より先に描く。
    #
    # 以前は最後に上から描いていた。震央と最寄りの観測点がほぼ同じ場所になる
    # 内陸の地震（熊本県熊本地方など）では、震源印が最大震度の札にそのまま
    # 重なって数字が読めなくなっていた。震源印は輪と十字なので、札を上に
    # 置いても輪は外にはみ出して見える。速報として消してよいのは震源印の
    # 中心であって、震度の数字ではない。
    ex, ey = to_px(lat, lon)
    seat_r = 24 * ss
    seat = Image.new("RGBA", (seat_r * 2, seat_r * 2), (0, 0, 0, 0))
    ImageDraw.Draw(seat).ellipse([0, 0, seat_r * 2 - 1, seat_r * 2 - 1], fill=(8, 11, 17, 130))
    canvas.alpha_composite(seat.filter(ImageFilter.GaussianBlur(seat_r / 3)),
                           (int(ex - seat_r), int(ey - seat_r)))
    marker = _epicentre_marker(40 * ss)
    canvas.alpha_composite(marker, (int(ex - marker.width / 2), int(ey - marker.height / 2)))

    # 描くのは弱い順。落ち影が強い札の上に乗らないようにする。
    for x, y, scale in sorted(badges, key=lambda b: b[2]):
        badge = _scale_badge(scale, _badge_size(scale) * ss)
        canvas.alpha_composite(badge, (int(x - badge.width / 2), int(y - badge.height / 2)))

    # 地名は強い方から数点だけ。全部に付けると読めない。
    # 札そのものは既に置いてあるので、ここで探すのはラベルの置き場所だけ。
    #
    # 震源の座はここで初めて予約する。地名が震源印に重なると字が読めないが、
    # 札を消してよい理由にはならない（上の placed_at を参照）。
    ex_pre, ey_pre = to_px(lat, lon)
    taken.append((ex_pre - 20 * ss, ey_pre - 20 * ss, ex_pre + 20 * ss, ey_pre + 20 * ss))

    for point_lat, point_lon, scale, name in sorted(plot, key=lambda p: -p[2])[:5]:
        # 札が置けなかった点に地名だけ出すと、何も無い場所を指す札になる。
        if not name or (point_lat, point_lon) not in placed_at:
            continue
        x, y = to_px(point_lat, point_lon)
        half = _badge_size(scale) * ss / 2
        label_w, label_h = _label_box(canvas, name)
        # 右→左→上→下の順に空きを探す。左右だけを見ていたころは、震源印の
        # そばにある最大震度の地名がどちらにも置けず、名前なしで出ていた。
        for dx, dy in ((half + 5 * ss, 0), (-half - 5 * ss - label_w, 0),
                       (-label_w / 2, -half - label_h / 2 - 3 * ss),
                       (-label_w / 2, half + label_h / 2 + 3 * ss)):
            lx, ly = x + dx, y + dy - label_h / 2
            label = (lx, ly, lx + label_w, ly + label_h)
            if 0 <= label[0] and label[2] <= canvas.width and not overlaps(label, taken):
                taken.append(label)
                _draw_place_label(canvas, label[0], label[1], name)
                break

    _draw_map_chrome(canvas, title, subtitle, sorted({point[2] for point in plot}))

    buf = io.BytesIO()
    canvas.resize((_MAP_W, _MAP_H), Image.LANCZOS).convert("RGB").save(
        buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf


# ── Embed 生成 ────────────────────────────────────────────

def _build_embed(event: dict, max_scale: int, has_badge: bool = False) -> discord.Embed:
    eq    = event.get("earthquake", {})
    hypo  = eq.get("hypocenter", {})
    issue = event.get("issue", {})

    time_label, _  = _format_time(eq.get("time", ""))
    _, issue_dt    = _format_time(issue.get("time", ""))
    tsunami_text   = _TSUNAMI_TEXT.get(eq.get("domesticTsunami", "None"), "津波情報は不明です。")
    footer_label   = _ISSUE_LABELS.get(issue.get("type", ""), "気象庁")
    color          = _SCALE_COLORS.get(max_scale, discord.Color.red())

    name      = hypo.get("name") or "不明"
    mag_str,_ = _parse_magnitude(hypo.get("magnitude"))
    depth_str = _parse_depth(hypo.get("depth"))

    emoji = _SCALE_TITLE_EMOJI.get(max_scale, "⚪")
    # 分からない情報は「不明」と書くのではなく行ごと出さない
    # （震源・規模・深さのフィールドは元からそうしていた。日時・震度も揃える）。
    lines = []
    if time_label != "不明":
        lines.append(f"{time_label}、")
    if max_scale in _SCALE_DISPLAY:
        lines.append(f"最大震度 {_SCALE_DISPLAY[max_scale]} の地震がありました。")
    else:
        lines.append("地震がありました。")
    lines.append(tsunami_text)

    embed = discord.Embed(
        title=f"{emoji} 地震情報",
        description="\n".join(lines),
        color=color,
        timestamp=issue_dt,
    )
    if name != "不明":
        embed.add_field(name="震源", value=name,      inline=True)
    if mag_str != "不明":
        embed.add_field(name="規模", value=mag_str,   inline=True)
    if depth_str != "不明":
        embed.add_field(name="深さ", value=depth_str, inline=True)
    embed.set_footer(text=footer_label, icon_url=BOT_ICON_URL)

    if has_badge:
        embed.set_thumbnail(url="attachment://intensity_badge.png")

    return embed


def _build_eew_embed(event: dict) -> discord.Embed:
    """556 (EEW予報, 震源・規模あり) / 554 (EEWDetection, チャイム検出のみ) から Embed を生成。

    P2PQuake の実データで確認したところ、554 は
    {"code": 554, "id": ..., "time": ..., "type": "Full"} という形で
    earthquake オブジェクトを一切持たない（気象庁のチャイムが鳴ったことを
    検出しただけの通知）。以前はここで 556 と同じ地震情報が来る前提で
    組んでいたため、震源・規模・震度がすべて「不明」の埋まった Embed に
    なっていた。震源データが無いときは、無い情報を埋めずに検出だけを伝える。

    cancelled=True（取り消し）は 556 側で実際に立つことを確認済み。以前は
    WS 側で cancelled を丸ごと弾いていたため、取り消しが来ても誰にも
    伝わらなかった（最初の警報だけ届いて、外れだったことは分からないまま）。
    """
    code      = event.get("code", 554)
    is_forecast = code == 556
    cancelled = bool(event.get("cancelled"))

    eq   = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    has_quake_data = bool(hypo.get("name"))

    # 続報番号は、公式の実データでは serialNo ではなく issue.serial に入る。
    # `or "1"` にすると serial の値がそのまま偽になる場合（"0" 等）に既定値へ
    # すり替わってしまうため、キーの有無で判定する。
    issue = event.get("issue") or {}
    serial = str(issue["serial"]) if issue.get("serial") is not None else "1"

    if cancelled:
        embed = discord.Embed(
            title="✅ 緊急地震速報は取り消されました",
            description=(
                f"**{hypo.get('name')}** 付近を震源とする緊急地震速報は取り消されました。"
                if has_quake_data else
                "直前の緊急地震速報は取り消されました。"
            ),
            color=discord.Color.green(),
        )
        footer = "気象庁 緊急地震速報（予報）" if is_forecast else "気象庁 緊急地震速報"
        embed.set_footer(text=footer, icon_url=BOT_ICON_URL)
        return embed

    if not has_quake_data:
        embed = discord.Embed(
            title="🚨 緊急地震速報を検出しました",
            description="緊急地震速報の受信を検出しました。震源・規模の詳細は、後続の情報でご確認ください。",
            color=discord.Color.orange(),
        )
        embed.set_footer(text="気象庁 緊急地震速報", icon_url=BOT_ICON_URL)
        return embed

    title_base = "⚠️ 緊急地震速報（予報）" if is_forecast else "🚨 緊急地震速報（警報）"
    # has_quake_data の時点判定により、ここでは name は必ず実在の文字列。
    name       = hypo.get("name") or "不明"
    # 556 は originTime、554 は time を使用
    time_raw   = eq.get("originTime") or eq.get("time", "")
    time_label, ts = _format_time(time_raw)
    mag_str, _ = _parse_magnitude(hypo.get("magnitude"))
    max_scale  = _max_scale(event)
    color      = _SCALE_COLORS.get(max_scale, discord.Color.orange())

    # 震源はあっても震度だけ分からない（areas が空 等）ことがあるので、
    # その行だけ出さない。「不明」と書くより、無いなら黙って省く。
    lines = []
    if time_label != "不明":
        lines.append(f"{time_label}、")
    lines.append(f"**{name}** 付近を震源とする地震が発生しました。")
    if max_scale in _SCALE_DISPLAY:
        lines.append(f"予想最大震度 **{_SCALE_DISPLAY[max_scale]}**")

    embed = discord.Embed(
        title=f"{title_base}（第{serial}報）",
        description="\n".join(lines),
        color=color,
        timestamp=ts,
    )
    if name != "不明":
        embed.add_field(name="予想震源", value=name,    inline=True)
    if mag_str != "不明":
        embed.add_field(name="予想規模", value=mag_str, inline=True)
    footer = "気象庁 緊急地震速報（予報）" if is_forecast else "気象庁 緊急地震速報（警報）"
    embed.set_footer(text=footer, icon_url=BOT_ICON_URL)
    return embed


def _build_tsunami_embed(event: dict) -> discord.Embed:
    """P2PQuake code 552 津波予報データから Discord Embed を生成。"""
    areas     = event.get("areas", [])
    issue     = event.get("issue", {})
    cancelled = event.get("cancelled", False)
    _, issue_dt = _format_time(issue.get("time", ""))

    if cancelled:
        embed = discord.Embed(
            title="津波予報（解除）",
            description="すべての津波予報が解除されました。",
            color=discord.Color.green(),
            timestamp=issue_dt,
        )
        embed.set_footer(text="気象庁 津波情報", icon_url=BOT_ICON_URL)
        return embed

    max_grade = max(
        areas,
        key=lambda a: _TSUNAMI_GRADE_ORDER.get(a.get("grade", "Unknown"), 0),
        default={},
    ).get("grade", "Unknown") if areas else "Unknown"

    color       = discord.Color.red() if max_grade == "MajorWarning" else (
                  discord.Color.orange() if max_grade == "Warning" else
                  discord.Color.yellow() if max_grade == "Watch" else
                  discord.Color.greyple())
    grade_label = _TSUNAMI_GRADE_LABELS.get(max_grade, "津波情報")

    embed = discord.Embed(
        title="津波情報",
        description=f"{grade_label}が発令されています。",
        color=color,
        timestamp=issue_dt,
    )

    by_grade: dict[str, list[str]] = {}
    for area in areas:
        grade = area.get("grade", "Unknown")
        name  = area.get("name", "不明")
        by_grade.setdefault(grade, []).append(name)

    for grade in ("MajorWarning", "Warning", "Watch", "Unknown"):
        if grade not in by_grade:
            continue
        label   = _TSUNAMI_GRADE_LABELS.get(grade, grade)
        names   = by_grade[grade]
        regions = "、".join(names[:10])
        if len(names) > 10:
            regions += f" 他{len(names) - 10}地域"
        embed.add_field(name=label, value=regions, inline=False)

    embed.set_footer(text="気象庁 津波情報", icon_url=BOT_ICON_URL)
    return embed


# ── 詳細リンクボタン ──────────────────────────────────────

class _EqView(discord.ui.View):
    def __init__(self, url: str):
        super().__init__(timeout=None)
        self.add_item(discord.ui.Button(
            label="詳細（気象庁）",
            url=url,
            style=discord.ButtonStyle.link,
        ))


# ── JMA URL ヘルパー ──────────────────────────────────────

_JMA_QUAKE_LIST_URL = "https://www.jma.go.jp/bosai/quake/data/list.json"
# 気象庁の統合地図ページ。?contents=earthquake_map&id=<eid> を付けると、
# その地震の震源にセンタリングされた状態で開く（実データの eid で、
# 別々の地震を指定して座標が正しく切り替わることを確認済み）。
_JMA_QUAKE_DETAIL_BASE = "https://www.jma.go.jp/bosai/map.html"
_JMA_QUAKE_FALLBACK_URL = "https://www.jma.go.jp/bosai/map.html#contents=earthquake_map"
_JMA_LIST_TTL_SEC = 30.0
_JMA_DETAIL_CACHE_TTL_SEC = 3600.0

_jma_list_cache: tuple[list[dict], float] | None = None
# 地震1件ごとに鍵が増えるので、件数にも上限を置く（従来は追い出しが無かった）
_jma_detail_url_cache: TTLCache[str, str] = TTLCache(
    ttl=_JMA_DETAIL_CACHE_TTL_SEC, max_entries=500,
)
_jma_list_lock = asyncio.Lock()


def _normalize_scale_text(text: str) -> str:
    return (
        str(text or "")
        .translate(str.maketrans("０１２３４５６７", "01234567"))
        .replace("最大", "")
        .replace("震度", "")
        .replace(" ", "")
        .replace("　", "")
    )


def _scale_from_text(text: str) -> int:
    norm = _normalize_scale_text(text)
    m = re.search(r"([1-7])(弱|強)?", norm)
    if not m:
        return -1
    base = int(m.group(1))
    mod = m.group(2) or ""
    if base == 4 and mod == "強":
        return 45
    if base == 5:
        if mod == "弱":
            return 50
        if mod == "強":
            return 55
    if base == 6:
        if mod == "弱":
            return 60
        if mod == "強":
            return 65
    if base == 7:
        return 70
    return base * 10


def _parse_magnitude_value(raw) -> float | None:
    if raw is None:
        return None
    s = str(raw).strip().upper().replace("M", "")
    try:
        v = float(s)
        return v if v >= 0 else None
    except ValueError:
        return None


def _parse_any_time(raw) -> datetime | None:
    if not raw:
        return None
    s = str(raw).strip()
    if not s:
        return None

    try:
        dt = datetime.strptime(s, "%Y/%m/%d %H:%M:%S")
        return dt.replace(tzinfo=_JST)
    except ValueError:
        pass

    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_JST)
        return dt.astimezone(_JST)
    except ValueError:
        return None


def _item_area_name(item: dict) -> str:
    for key in ("anm", "name", "epicenter"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _item_detail_url(item: dict) -> str | None:
    """list.json の1件から、人が読める気象庁のページへのリンクを作る。

    実データで list.json の各要素を確認したところ、"detail"/"url"/"link"/"uri"
    というキーは存在しない。あるのは "json"（生の JSON データファイル名、例
    "20260824125723_20260824125441_VXSE5k_1.json"）と "eid"（イベントID）。
    以前は存在しないキーの前に "json" を探していたため、常にそこへマッチし、
    リンク先が JSON ファイルそのもの（ブラウザで開くとパーサーの値がそのまま
    出るだけのページ）になっていた。eid から統合地図ページを組み立てる。
    """
    eid = item.get("eid")
    if isinstance(eid, str) and eid.strip():
        return f"{_JMA_QUAKE_DETAIL_BASE}?contents=earthquake_map&id={eid.strip()}"
    return None


def _cache_key_for_event(event: dict, max_scale: int) -> str:
    eq = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    eq_time = eq.get("originTime") or eq.get("time", "")
    return "|".join([
        str(event.get("code", "")),
        str(eq_time),
        str(max_scale),
        str(hypo.get("name", "")),
    ])


def _score_jma_item(
    item: dict,
    target_dt: datetime | None,
    target_name: str,
    target_mag: float | None,
    target_scale: int,
) -> float:
    score = 0.0

    item_dt = _parse_any_time(item.get("at") or item.get("time") or item.get("datetime"))
    if target_dt and item_dt:
        delta = abs((item_dt - target_dt).total_seconds())
        if delta > 900:
            return -1e9
        score += max(0.0, 110.0 - delta / 6.0)
    elif target_dt:
        score -= 30.0

    item_name = _item_area_name(item)
    if target_name and item_name:
        if item_name == target_name:
            score += 30.0
        elif target_name in item_name or item_name in target_name:
            score += 15.0

    if target_mag is not None:
        item_mag = _parse_magnitude_value(item.get("mag"))
        if item_mag is not None:
            diff = abs(item_mag - target_mag)
            if diff <= 0.1:
                score += 18.0
            elif diff <= 0.3:
                score += 10.0
            elif diff <= 0.6:
                score += 4.0

    if target_scale >= 0:
        item_scale = _scale_from_text(item.get("ttl", ""))
        if item_scale >= 0:
            if item_scale == target_scale:
                score += 18.0
            elif abs(item_scale - target_scale) <= 10:
                score += 8.0

    return score


async def _get_jma_list() -> list[dict]:
    global _jma_list_cache
    now = time.time()
    if _jma_list_cache and now - _jma_list_cache[1] < _JMA_LIST_TTL_SEC:
        return _jma_list_cache[0]

    async with _jma_list_lock:
        now = time.time()
        if _jma_list_cache and now - _jma_list_cache[1] < _JMA_LIST_TTL_SEC:
            return _jma_list_cache[0]
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(_JMA_QUAKE_LIST_URL) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    data = await resp.json(content_type=None)
            if isinstance(data, list):
                _jma_list_cache = (data, now)
                return data
        except Exception as e:
            logger.debug("[earthquake] JMA list fetch failed: %s", e)

        if _jma_list_cache:
            return _jma_list_cache[0]
        return []


async def _resolve_jma_detail_url(event: dict, max_scale: int) -> str:
    key = _cache_key_for_event(event, max_scale)
    cached = _jma_detail_url_cache.get(key)
    if cached is not None:
        return cached

    eq = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    target_dt = _parse_any_time(eq.get("originTime") or eq.get("time", ""))
    target_name = str(hypo.get("name", "") or "")
    target_mag = _parse_magnitude_value(hypo.get("magnitude"))

    items = await _get_jma_list()
    best_url = _JMA_QUAKE_FALLBACK_URL
    best_score = -1e9
    for item in items[:400]:
        if not isinstance(item, dict):
            continue
        detail_url = _item_detail_url(item)
        if not detail_url:
            continue
        score = _score_jma_item(item, target_dt, target_name, target_mag, max_scale)
        if score > best_score:
            best_score = score
            best_url = detail_url

    if best_score < 10:
        best_url = _JMA_QUAKE_FALLBACK_URL

    _jma_detail_url_cache.set(key, best_url)
    return best_url


# ── 通知送信（確定地震情報 551） ──────────────────────────

_NOTIFY_TYPE_LABELS: dict[str, str] = {
    "quake_info":   "地震情報",
    "tsunami":      "津波情報",
    "eew_warning":  "緊急地震速報（警報）",
    "eew_forecast": "緊急地震速報（予報）",
}


def _evaluate_guild(
    bot: Bot,
    guild_id: int,
    *,
    notify_type: str,
    max_scale: int,
    apply_min_scale: bool,
) -> tuple[discord.TextChannel | None, str]:
    """1ギルドが通知対象かを判定する。

    以前は地震(551)・津波(552)・EEW(554/556) の3経路と「0件だった理由の説明」が
    同じ判定をそれぞれ別に書いていた。条件を1つ直しても片方にしか反映されない、
    という取りこぼしが実際に何度も起きたため、判定順も理由の文言もここへ集約する。

    戻り値は (送信先チャンネル, 対象外の理由)。対象なら理由は空文字、対象外なら
    チャンネルは None で、最初に引っかかった理由だけが入る（候補を並べても
    どれが本当の原因か分からないため、必ず1つに絞る）。
    """
    s = get_earthquake_settings(guild_id)

    ch_id = s.get("channel_id")
    if not ch_id:
        return None, "「アラートを送るチャンネル」が未設定です"

    if apply_min_scale:
        try:
            min_scale = int(s.get("min_scale", 30))
        except (TypeError, ValueError):
            min_scale = 30
        if max_scale < min_scale:
            return None, f"「通知する最小震度」が {min_scale} で、今回の震度 {max_scale} は届いていません"

    if not get_earthquake_notify_types(guild_id).get(notify_type, True):
        label = _NOTIFY_TYPE_LABELS.get(notify_type, notify_type)
        return None, f"通知タイプ「{label}」がオフになっています"

    guild = bot.get_guild(guild_id)
    if guild is None:
        return None, "bot がこのギルドをまだキャッシュしていません（未参加、または再起動直後）"

    channel = guild.get_channel(int(ch_id))
    if not isinstance(channel, discord.TextChannel):
        return None, f"設定されているチャンネル（{ch_id}）が見つからないか、テキストチャンネルではありません"

    return channel, ""


def _collect_targets(
    bot: Bot,
    *,
    notify_type: str,
    max_scale: int,
    apply_min_scale: bool = True,
    only_guild_id: int | None = None,
) -> list[tuple[int, discord.TextChannel]]:
    """送信対象の (guild_id, チャンネル) を集める。

    1ギルドの設定不正（例: min_scale が壊れた値）で他の全ギルドへの通知まで
    巻き添えで止まらないよう、ギルドごとに例外を閉じ込める。
    """
    guild_ids = [only_guild_id] if only_guild_id is not None else get_all_guild_ids()
    targets: list[tuple[int, discord.TextChannel]] = []
    for guild_id in guild_ids:
        try:
            channel, _ = _evaluate_guild(
                bot, guild_id,
                notify_type=notify_type, max_scale=max_scale, apply_min_scale=apply_min_scale,
            )
            if channel is not None:
                targets.append((guild_id, channel))
        except Exception:
            logger.exception("[earthquake] guild=%s の対象判定に失敗", guild_id)
    return targets


def _diagnose_no_target(
    bot: Bot,
    guild_id: int,
    *,
    notify_type: str,
    max_scale: int,
    apply_min_scale: bool = True,
) -> str:
    """1ギルドに絞ったのに送信先が0件だったときの理由を1文で返す。

    判定は _evaluate_guild と同じものを使う（説明用に条件を書き写すと、
    実際のフィルタとずれて嘘の理由を出すため）。
    """
    try:
        _, reason = _evaluate_guild(
            bot, guild_id,
            notify_type=notify_type, max_scale=max_scale, apply_min_scale=apply_min_scale,
        )
    except Exception as exc:
        return f"設定の読み取りに失敗しました（{exc}）"
    return reason or "条件はすべて満たしていますが、送信の直前で対象から外れました（一時的な状態変化の可能性）"


def _override_target(
    bot: Bot, guild_id: int, channel_id: int,
) -> list[tuple[int, discord.TextChannel]]:
    """DEV専用: 地震アラート設定を一切見ず、指定チャンネルへ直接送る。

    本番用の設定が無いギルドでも中身を確認できるようにするための逃げ道。
    0件になったときは、ここで理由を出しきる（呼び出し側で重ねて出さない）。
    """
    guild = bot.get_guild(guild_id)
    if guild is None:
        logger.warning(
            "[earthquake] guild=%s: bot がこのギルドをまだキャッシュしていません"
            "（未参加、または再起動直後）", guild_id,
        )
        return []
    channel = guild.get_channel(int(channel_id))
    if not isinstance(channel, discord.TextChannel):
        logger.warning(
            "[earthquake] guild=%s: 指定チャンネル（%s）が見つからないか、"
            "テキストチャンネルではありません", guild_id, channel_id,
        )
        return []
    return [(guild_id, channel)]


async def _dispatch(
    targets: list[tuple[int, discord.TextChannel]],
    *,
    tag: str,
    embed: discord.Embed,
    view: discord.ui.View | None = None,
    attachments: list[tuple[str, bytes]] | None = None,
) -> int:
    """対象へ一斉送信し、成功した数を返す。

    discord.File は送信で消費されるため使い回せない。チャンネルごとに bytes から
    作り直す。
    """
    async def _send(channel: discord.TextChannel) -> None:
        files = [discord.File(io.BytesIO(data), filename=name) for name, data in (attachments or [])]
        await channel.send(
            embed=embed,
            files=files or discord.utils.MISSING,
            view=view or discord.utils.MISSING,
        )

    results = await asyncio.gather(*(_send(ch) for _, ch in targets), return_exceptions=True)
    ok_count = 0
    for (guild_id, channel), result in zip(targets, results):
        if isinstance(result, BaseException):
            # ここは except の外なので exc_info を明示する。logger.exception は
            # sys.exc_info() を見るため、例外が有効でない場所では
            # トレースが "NoneType: None" になり、どこで落ちたか残らない。
            logger.error(
                "[%s] send error guild=%s ch=%s: %s",
                tag, guild_id, channel.id, result, exc_info=result,
            )
        else:
            ok_count += 1
    return ok_count


async def _notify_all_guilds(
    bot: Bot,
    event: dict,
    *,
    only_guild_id: int | None = None,
    override_channel_id: int | None = None,
) -> int:
    """通知する。only_guild_id を渡すと、そのギルドだけに絞る
    （開発者パネルのリプレイが全サーバーへ誤爆しないようにするため）。
    絞り込んだ場合も、そのギルドの min_scale・通知タイプ・チャンネル設定は
    そのまま適用する（本番で実際に届く内容をそのまま確認できるように）。

    override_channel_id を only_guild_id とセットで渡すと、そのギルドの
    地震アラート設定（チャンネル・min_scale・通知タイプ）を一切見ずに、
    指定したチャンネルへ直接送る。開発者パネルでの動作確認専用の経路で、
    本番用の「地震アラート」設定が無いギルドでも中身を確認できるようにする。

    戻り値は実際に送信を試みたチャンネル数。0 のとき「対象ギルドの設定が
    無い／閾値で弾かれた／bot がギルドをキャッシュしていない」のどれかで
    静かに何も起きない状態になるため、呼び出し側（開発者パネルのリプレイ等）
    がログを残せるように返す。"""
    max_scale = _max_scale(event)

    # 先に送信先を決める。以前は JMA 詳細リンクの取得・バッジ生成・震度マップ
    # 生成（タイル25枚のHTTP取得）を対象判定より先に走らせていたため、誰も
    # 受け取らない地震でも毎回そのぶんの通信と描画が発生していた。
    if override_channel_id is not None and only_guild_id is not None:
        targets = _override_target(bot, only_guild_id, override_channel_id)
    else:
        targets = _collect_targets(
            bot, notify_type="quake_info", max_scale=max_scale, only_guild_id=only_guild_id,
        )
        # only_guild_id 指定（開発者パネルのリプレイ）で 0 件だと、押した側は
        # 「受信・完了」のログしか見えず、何も届かない理由が分からない。
        # 全ギルド一斉送信（本番の WS 経由）では毎回ほぼ全ギルドが対象外に
        # なるのが通常なので、そちらでは出さない。override 経路は
        # _override_target 側で理由を出しきっている。
        if not targets and only_guild_id is not None:
            logger.warning(
                "[earthquake] guild=%s: 送信先が0件でした（理由: %s）",
                only_guild_id,
                _diagnose_no_target(bot, only_guild_id, notify_type="quake_info", max_scale=max_scale),
            )

    if not targets:
        return 0

    points = event.get("points", [])
    eq     = event.get("earthquake", {})
    hypo   = eq.get("hypocenter", {})
    lat    = _parse_coord(hypo.get("latitude"))
    lon    = _parse_coord(hypo.get("longitude"))

    detail_url = await _resolve_jma_detail_url(event, max_scale)

    is_minor = max_scale <= 20  # 震度1-2 はコンパクト表示

    # 震度が取れないイベント（遠地地震など、points も areas も maxScale も無い）
    # では max_scale が -1 になる。そのままバッジを作ると「最大震度 -1」と
    # 大書きした画像を貼ってしまうため、分からないときは作らない。
    badge_buf: io.BytesIO | None = None
    if max_scale >= 0:
        try:
            # PIL の描画と PNG 保存。地図ほど重くはないが、同じ理由で
            # イベントループの上では回さない。
            badge_buf = await asyncio.to_thread(_generate_badge, max_scale)
        except Exception as e:
            logger.exception("[earthquake] badge generation error: %s", e)

    map_buf: io.BytesIO | None = None
    if not is_minor and lat is not None and lon is not None and points:
        try:
            # 画像だけを見ても意味が通るよう、見出しに震度と震源を入れる。
            # Discord の埋め込みは本文が折り畳まれることがあり、画像だけが
            # 目に入る場面がある。
            eq_info = event.get("earthquake", {})
            hypo_info = eq_info.get("hypocenter", {})
            map_title = (f"最大震度 {_SCALE_DISPLAY[max_scale]}"
                         if max_scale in _SCALE_DISPLAY else "震度分布")
            time_label, _ = _format_time(eq_info.get("time", ""))
            mag_label, _ = _parse_magnitude(hypo_info.get("magnitude"))
            parts = [hypo_info.get("name") or "", mag_label,
                     _parse_depth(hypo_info.get("depth")),
                     time_label if time_label != "不明" else ""]
            map_subtitle = "  ".join(part for part in parts if part)

            # タイル取得は専用セッションで実施（WS セッションを汚染しない）
            async with aiohttp.ClientSession() as tile_session:
                map_buf = await _generate_intensity_map(
                    tile_session, lat, lon, points, map_title, map_subtitle)
        except Exception as e:
            logger.exception("[earthquake] map generation error: %s", e)

    embed = _build_embed(event, max_scale, has_badge=bool(badge_buf))
    if map_buf:
        embed.set_image(url="attachment://earthquake_map.png")

    attachments: list[tuple[str, bytes]] = []
    if badge_buf:
        attachments.append(("intensity_badge.png", badge_buf.getvalue()))
    if map_buf:
        attachments.append(("earthquake_map.png", map_buf.getvalue()))

    return await _dispatch(
        targets, tag="earthquake", embed=embed,
        view=_EqView(detail_url), attachments=attachments,
    )


# ── 津波情報通知（552） ───────────────────────────────────

async def _notify_tsunami_guilds(bot: Bot, event: dict) -> int:
    """津波情報 (code 552) を全対象ギルドへ送信。

    津波は震度を持たないので、最小震度のしきい値は適用しない。
    """
    targets = _collect_targets(
        bot, notify_type="tsunami", max_scale=-1, apply_min_scale=False,
    )
    if not targets:
        return 0
    return await _dispatch(targets, tag="tsunami", embed=_build_tsunami_embed(event))


# ── EEW 通知（554 警報 / 556 予報） ──────────────────────

async def _notify_eew_guilds(bot: Bot, event: dict, notify_type: str) -> int:
    """EEW を全対象ギルドへ送信。notify_type: 'eew_warning' or 'eew_forecast'"""
    max_scale = _max_scale(event)
    cancelled = bool(event.get("cancelled"))

    # 震度が分からない（554 の検出通知・取り消し）ときは、閾値で弾かず必ず
    # 届ける。EEW は安全に倒すほうが良いという判断。
    targets = _collect_targets(
        bot, notify_type=notify_type, max_scale=max_scale, apply_min_scale=max_scale >= 0,
    )
    if not targets:
        return 0

    detail_url = await _resolve_jma_detail_url(event, max_scale)

    # 554 (EEWDetection) は震度が分からない（max_scale == -1）。
    # 分からない震度を「-1」のバッジ画像にして貼るのは避ける。
    # 取り消し（cancelled）も、外れた震度をバッジで見せると紛らわしいので作らない。
    badge_buf: io.BytesIO | None = None
    if max_scale >= 0 and not cancelled:
        try:
            # PIL の描画と PNG 保存。地図ほど重くはないが、同じ理由で
            # イベントループの上では回さない。
            badge_buf = await asyncio.to_thread(_generate_badge, max_scale)
        except Exception:
            logger.exception("[eew] badge generation error")

    embed = _build_eew_embed(event)
    if badge_buf:
        embed.set_thumbnail(url="attachment://intensity_badge.png")

    attachments = [("intensity_badge.png", badge_buf.getvalue())] if badge_buf else []
    return await _dispatch(
        targets, tag="eew", embed=embed,
        view=_EqView(detail_url), attachments=attachments,
    )


# ── WebSocket ループ ──────────────────────────────────────

# 起動した通知タスクへの参照。create_task の戻り値を保持しないと、実行中に
# GC でタスクごと消えることがある（CPython の既知の挙動）。
_running_tasks: set[asyncio.Task] = set()


def _on_task_done(task: asyncio.Task) -> None:
    _running_tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        # done_callback は except の外なので exc_info を明示する。
        # logger.exception だとトレースが "NoneType: None" になる。
        logger.error("[earthquake] task error: %s", exc, exc_info=exc)


def _spawn(coro) -> asyncio.Task:
    """通知タスクをバックグラウンドで起動し、未捕捉例外をログに記録する。"""
    task = asyncio.create_task(coro)
    _running_tasks.add(task)
    task.add_done_callback(_on_task_done)
    return task


async def run_earthquake_ws(bot: Bot) -> None:
    """P2PQuake WS 1本で地震情報 (551)・津波情報 (552)・EEW検出 (554)・EEW予報 (556) を受信する。

    554 (EEWDetection) は震源データを持たない「チャイムが鳴ったことの検出」のみの
    通知で、実際の震源・規模・震度は 556 (EEW予報) 側にしか入っていない。

    P2PQuake は同一の情報を複数回配信することがあるため、公式が推奨するとおり
    id で重複だけを弾く（https://www.p2pquake.net/develop/json_api_v2/ ）。
    以前は EEW だけ自前の eq_time + serialNo + isFinal の合成キーで組んで
    いたが、実際のペイロードには serialNo・isFinal がトップレベルに存在せず
    （556 の続報番号は issue.serial、554 には earthquake すら無い）常に
    既定値へ落ちてキーが固定化し、起動後の最初の1件を送った後は同じ震度
    階級の通知が二度と送られない不具合になっていた。551・552 にはそもそも
    重複排除自体が無く、P2PQuake が再配信すればそのまま二重に通知していた。

    通知処理はすべて asyncio.create_task() でバックグラウンド起動するため、
    WS 受信ループはタイル取得や Discord API 送信をブロックせず常に即応する。
    """
    # 重複排除。以前は上限を超えたら clear() で全消ししていたため、消した直後に
    # 同じ id が再配信されると二重通知になりえた。古い順に1件ずつ捨てる。
    _seen_ids: set[str] = set()
    _seen_order: deque[str] = deque()

    while True:
        try:
            # WS 専用セッション（タイル HTTP と共有しない）
            async with aiohttp.ClientSession() as ws_session:
                async with ws_session.ws_connect(_WS_URL, heartbeat=20) as ws:
                    logger.info("[earthquake] P2PQuake WS 接続確立")
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                            except json.JSONDecodeError:
                                continue

                            code = data.get("code")
                            if code not in (551, 552, 554, 556):
                                continue

                            event_id = data.get("id")
                            if event_id:
                                if event_id in _seen_ids:
                                    continue
                                _seen_ids.add(event_id)
                                _seen_order.append(event_id)
                                while len(_seen_order) > _SEEN_ID_LIMIT:
                                    _seen_ids.discard(_seen_order.popleft())

                            if code == 551:
                                # タイル生成を含むためバックグラウンド実行
                                _spawn(_notify_all_guilds(bot, data))

                            elif code == 552:
                                _spawn(_notify_tsunami_guilds(bot, data))

                            elif code in (554, 556):
                                # cancelled（取り消し）も届ける。以前はここで
                                # 丸ごと弾いていたため、緊急地震速報が
                                # 外れたことを誰にも伝えられなかった。
                                notify_type = "eew_forecast" if code == 556 else "eew_warning"
                                # EEW は最優先でバックグラウンド起動
                                _spawn(_notify_eew_guilds(bot, data, notify_type))

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            logger.warning("[earthquake] WS 切断: %s", msg.type)
                            break
        except Exception as e:
            logger.exception("[earthquake] WS エラー: %s", e)
        logger.info("[earthquake] 10秒後に再接続")
        await asyncio.sleep(10)
