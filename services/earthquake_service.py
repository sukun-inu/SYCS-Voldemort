import asyncio
import io
import json
import logging
import math
import os
import re
import time
from datetime import datetime

import aiohttp
import discord
from discord.ext.commands import Bot

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL = True
except ImportError:
    _PIL = False

from config import BOT_ICON_URL, JST as _JST, SCALE_LABELS as _SCALE_DISPLAY
from services.settings_store import (
    get_all_guild_ids,
    get_earthquake_notify_types,
    get_earthquake_settings,
)

logger = logging.getLogger(__name__)

_WS_URL  = "wss://api.p2pquake.net/v2/ws"
_TILE_URL = "https://cartodb-basemaps-a.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png"
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
_MAP_FILL_RGB = {
    10: (  0,  55, 220), 20: (  0, 130, 230), 30: (  0, 180, 180),
    40: (220, 200,  10), 45: (230, 150,   0),
    50: (230, 100,   0), 55: (230,  45,   0),
    60: (200,   0,   0), 65: (150,   0, 150), 70: ( 95,   0, 115),
}

# 凡例・ログ用（全角）
_SCALE_MAP = {
    10: "１", 20: "２", 30: "３", 40: "４", 45: "４強",
    50: "５弱", 55: "５強", 60: "６弱", 65: "６強", 70: "７",
}

# バッジ画像用（ASCII のみ・CJK フォント不要）
_SCALE_BADGE_LABEL = {
    10: "1", 20: "2", 30: "3", 40: "4", 45: "4+",
    50: "5-", 55: "5+", 60: "6-", 65: "6+", 70: "7",
}

# EEW予報 (556) の forecastMaxInt 文字列 → 内部スケール値
_FORECAST_INT_TO_SCALE: dict[str, int] = {
    "1": 10, "2": 20, "3": 30, "4": 40, "4+": 45,
    "5-": 50, "5+": 55, "6-": 60, "6+": 65, "7": 70,
}

# 震度別 RGB — Kiwi Monitor カラースキーム 第2版
_SCALE_RGB = {
    10: (  0,  64, 255), 20: (  0, 148, 255), 30: (  0, 200, 200),
    40: (250, 230,  20), 45: (255, 175,   0),
    50: (255, 120,   0), 55: (255,  60,   0),
    60: (220,   0,   0), 65: (170,   0, 170), 70: (110,   0, 130),
}

_SCALE_COLORS = {k: discord.Color.from_rgb(*v) for k, v in _SCALE_RGB.items()}

# タイトル絵文字（震度別）
_SCALE_TITLE_EMOJI = {
    10: "🔵", 20: "🔵", 30: "🔵",
    40: "🟡", 45: "🟡",
    50: "🟠", 55: "🟠",
    60: "🔴", 65: "🔴", 70: "🔴",
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
        except Exception:
            pass

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
    """震度バッジ（160×160）を生成して BytesIO で返す。
    上部ダークヘッダーに「最大震度」、下部に大きな震度数字。"""
    if not _PIL:
        return None

    r, g, b = _SCALE_RGB.get(scale, (100, 100, 100))
    label   = _SCALE_BADGE_LABEL.get(scale, str(scale))

    w, h       = 160, 160
    header_h   = 38          # ヘッダー帯の高さ
    radius     = 16
    header_bg  = (10, 18, 30, 255)

    img  = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 全体背景（角丸、震度カラー）
    draw.rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, fill=(r, g, b, 255))

    # ヘッダー帯（上部、角丸はみ出しを矩形で塗りつぶし）
    draw.rounded_rectangle([0, 0, w - 1, header_h + radius], radius=radius, fill=header_bg)
    draw.rectangle([0, header_h, w - 1, header_h + radius], fill=header_bg)

    # ヘッダーと本体の区切り線
    draw.rectangle([0, header_h, w - 1, header_h + 1], fill=(255, 255, 255, 30))

    # 「最大震度」テキスト
    font_hd = _get_font(20)
    draw.text((w // 2, header_h // 2 + 1), "最大震度",
              fill=(255, 255, 255, 240), font=font_hd, anchor="mm")

    # 震度数字（下部中央）
    body_cy = header_h + (h - header_h) // 2
    font_lg = _get_font(88 if len(label) == 1 else 60)
    draw.text((w // 2, body_cy + 4), label,
              fill=(255, 255, 255, 255), font=font_lg, anchor="mm")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


# ── 地図生成ヘルパー ───────────────────────────────────────

def _latlon_to_tile_float(lat: float, lon: float, zoom: int) -> tuple[float, float]:
    n = 2 ** zoom
    tx = (lon + 180) / 360 * n
    lat_r = math.radians(lat)
    ty = (1 - math.asinh(math.tan(lat_r)) / math.pi) / 2 * n
    return tx, ty


def _km_to_px(km: float, lat: float, zoom: int) -> float:
    tile_km = (40075.017 * math.cos(math.radians(lat))) / (2 ** zoom)
    return km * _TILE_SZ / tile_km


def _resolve_point_coord(addr: str, pref: str) -> tuple[float, float] | None:
    """pref / addr → (lat, lon)。都道府県中心座標を使用。"""
    return _PREF_CENTERS.get(pref) or _PREF_CENTERS.get(addr)


def _auto_zoom(
    lats: list[float], lons: list[float],
    img_w: int, img_h: int,
) -> int:
    """点群が画像の 65% 以内に収まる最大ズームを返す。"""
    clat = (max(lats) + min(lats)) / 2
    span_km = max(
        (max(lats) - min(lats)) * 111,
        (max(lons) - min(lons)) * 111 * math.cos(math.radians(clat)),
    ) * 1.5
    target = min(img_w, img_h) * 0.65
    for zoom in range(9, 3, -1):
        if _km_to_px(max(span_km / 2, 1.0), clat, zoom) <= target / 2:
            return zoom
    return 4


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
                return Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception as e:
        logger.debug("[earthquake] tile %d/%d/%d fetch error: %s", z, x, y, e)
    return None


def _draw_x_marker(draw: "ImageDraw.ImageDraw", cx: int, cy: int, r: int) -> None:
    """赤い × 印（震源マーカー）を描画。"""
    d = int(r * 0.78)
    w = max(3, r // 3)
    draw.line([cx - d, cy - d, cx + d, cy + d], fill=(110, 0, 0, 255), width=w + 3)
    draw.line([cx - d, cy + d, cx + d, cy - d], fill=(110, 0, 0, 255), width=w + 3)
    draw.line([cx - d, cy - d, cx + d, cy + d], fill=(255, 45, 45, 255), width=w)
    draw.line([cx - d, cy + d, cx + d, cy - d], fill=(255, 45, 45, 255), width=w)


def _draw_point_badge(
    draw: "ImageDraw.ImageDraw",
    px: int, py: int,
    label: str,
    rgb: tuple[int, int, int],
) -> None:
    """各観測点に震度バッジ（暗背景の四角ボックス）を描画。"""
    font = _get_font(13)
    pad  = 5
    try:
        tw = int(draw.textlength(label, font=font))
    except AttributeError:
        tw = len(label) * 8
    bw, bh = tw + pad * 2, 22
    x0, y0 = px - bw // 2, py - bh // 2
    draw.rectangle([x0 - 1, y0 - 1, x0 + bw + 1, y0 + bh + 1], fill=(5, 15, 35, 220))
    draw.rectangle([x0, y0, x0 + bw, y0 + bh], fill=(*rgb, 235))
    draw.text((px, py + 1), label, fill=(255, 255, 255, 255), font=font, anchor="mm")


def _draw_attribution(img: "Image.Image") -> None:
    """左下に地図帰属表示。"""
    draw = ImageDraw.Draw(img)
    font = _get_font(9)
    text = "© OpenStreetMap contributors"
    draw.rectangle([0, img.height - 14, len(text) * 6, img.height],
                   fill=(0, 0, 0, 160))
    draw.text((2, img.height - 13), text, fill=(180, 180, 180), font=font)


async def _generate_intensity_map(
    session: aiohttp.ClientSession,
    lat: float,
    lon: float,
    points: list[dict],
) -> io.BytesIO | None:
    """P2PQuake 点震度データを使ったダーク地図を生成し BytesIO で返す。"""
    if not _PIL:
        return None

    plot: list[tuple[float, float, int]] = []
    for p in points:
        scale = p.get("scale", -1)
        if scale < 10:
            continue
        coord = _resolve_point_coord(p.get("addr", ""), p.get("pref", ""))
        if coord:
            plot.append((*coord, scale))

    if not plot:
        return None

    img_w, img_h = 600, 360
    all_lats = [p[0] for p in plot] + [lat]
    all_lons = [p[1] for p in plot] + [lon]
    zoom = _auto_zoom(all_lats, all_lons, img_w, img_h)

    clat = (max(all_lats) + min(all_lats)) / 2
    clon = (max(all_lons) + min(all_lons)) / 2
    cx_f, cy_f = _latlon_to_tile_float(clat, clon, zoom)
    pad = 2
    tx0, ty0 = int(cx_f) - pad, int(cy_f) - pad
    tx1, ty1 = int(cx_f) + pad, int(cy_f) + pad

    coords = [(tx, ty) for ty in range(ty0, ty1 + 1) for tx in range(tx0, tx1 + 1)]
    tile_imgs = await asyncio.gather(
        *(_fetch_tile(session, zoom, tx, ty) for tx, ty in coords),
        return_exceptions=True,
    )

    map_w = (tx1 - tx0 + 1) * _TILE_SZ
    map_h = (ty1 - ty0 + 1) * _TILE_SZ
    base = Image.new("RGBA", (map_w, map_h), (20, 22, 30, 255))
    for (tx, ty), tile in zip(coords, tile_imgs):
        if isinstance(tile, Image.Image):
            base.paste(tile, ((tx - tx0) * _TILE_SZ, (ty - ty0) * _TILE_SZ))

    overlay = Image.new("RGBA", (map_w, map_h), (0, 0, 0, 0))
    draw    = ImageDraw.Draw(overlay)
    circle_r_km = 55.0
    badge_positions: list[tuple[int, int, str, tuple[int, int, int]]] = []

    for pt_lat, pt_lon, scale in sorted(plot, key=lambda x: x[2]):
        pxf, pyf = _latlon_to_tile_float(pt_lat, pt_lon, zoom)
        px = int((pxf - tx0) * _TILE_SZ)
        py = int((pyf - ty0) * _TILE_SZ)
        rp  = max(20, int(_km_to_px(circle_r_km, pt_lat, zoom)))
        rgb = _MAP_FILL_RGB.get(scale, (30, 80, 150))
        draw.ellipse(
            [px - rp, py - rp, px + rp, py + rp],
            fill=(*rgb, 185), outline=(*rgb, 255), width=2,
        )
        badge_positions.append((px, py, _SCALE_BADGE_LABEL.get(scale, str(scale)), rgb))

    epi_xf, epi_yf = _latlon_to_tile_float(lat, lon, zoom)
    epi_x = int((epi_xf - tx0) * _TILE_SZ)
    epi_y = int((epi_yf - ty0) * _TILE_SZ)
    _draw_x_marker(draw, epi_x, epi_y, 14)

    composite = Image.alpha_composite(base, overlay)

    cx0 = max(0, min(epi_x - img_w // 2, map_w - img_w))
    cy0 = max(0, min(epi_y - img_h // 2, map_h - img_h))
    cropped = composite.crop((cx0, cy0, cx0 + img_w, cy0 + img_h))

    bdraw = ImageDraw.Draw(cropped)
    for px, py, label, rgb in badge_positions:
        _draw_point_badge(bdraw, px - cx0, py - cy0, label, rgb)

    _draw_attribution(cropped)

    buf = io.BytesIO()
    cropped.convert("RGB").save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf


# ── Embed 生成 ────────────────────────────────────────────

def _build_embed(event: dict, max_scale: int, has_badge: bool = False) -> discord.Embed:
    eq    = event.get("earthquake", {})
    hypo  = eq.get("hypocenter", {})
    issue = event.get("issue", {})

    time_label, _  = _format_time(eq.get("time", ""))
    _, issue_dt    = _format_time(issue.get("time", ""))
    scale_disp     = _SCALE_DISPLAY.get(max_scale, f"不明({max_scale})")
    tsunami_text   = _TSUNAMI_TEXT.get(eq.get("domesticTsunami", "None"), "津波情報は不明です。")
    footer_label   = _ISSUE_LABELS.get(issue.get("type", ""), "気象庁")
    color          = _SCALE_COLORS.get(max_scale, discord.Color.red())

    name      = hypo.get("name") or "不明"
    mag_str,_ = _parse_magnitude(hypo.get("magnitude"))
    depth_str = _parse_depth(hypo.get("depth"))

    emoji = _SCALE_TITLE_EMOJI.get(max_scale, "⚪")
    embed = discord.Embed(
        title=f"{emoji} 地震情報",
        description="\n".join([
            f"{time_label}、",
            f"最大震度 {scale_disp} の地震がありました。",
            tsunami_text,
        ]),
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
    """
    code = event.get("code", 554)
    is_forecast = code == 556

    eq   = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    has_quake_data = bool(hypo.get("name"))

    # 続報番号は、公式の実データでは serialNo ではなく issue.serial に入る。
    serial = str((event.get("issue") or {}).get("serial") or "1")

    if not has_quake_data:
        embed = discord.Embed(
            title="🚨 緊急地震速報を検出しました",
            description="緊急地震速報の受信を検出しました。震源・規模の詳細は、後続の情報でご確認ください。",
            color=discord.Color.orange(),
        )
        embed.set_footer(text="気象庁 緊急地震速報", icon_url=BOT_ICON_URL)
        return embed

    title_base = "⚠️ 緊急地震速報（予報）" if is_forecast else "🚨 緊急地震速報（警報）"
    name       = hypo.get("name") or "不明"
    # 556 は originTime、554 は time を使用
    time_raw   = eq.get("originTime") or eq.get("time", "")
    time_label, ts = _format_time(time_raw)
    mag_str, _ = _parse_magnitude(hypo.get("magnitude"))
    max_scale  = _max_scale(event)
    scale_disp = _SCALE_DISPLAY.get(max_scale, "不明") if max_scale > 0 else "不明"
    color      = _SCALE_COLORS.get(max_scale, discord.Color.orange())

    embed = discord.Embed(
        title=f"{title_base}（第{serial}報）",
        description="\n".join([
            f"{time_label}、",
            f"**{name}** 付近を震源とする地震が発生しました。",
            f"予想最大震度 **{scale_disp}**",
        ]),
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
_JMA_QUAKE_DETAIL_BASE = "https://www.jma.go.jp/bosai/quake/data/"
_JMA_QUAKE_FALLBACK_URL = "https://www.jma.go.jp/bosai/map.html#contents=earthquake_map"
_JMA_LIST_TTL_SEC = 30.0
_JMA_DETAIL_CACHE_TTL_SEC = 3600.0

_jma_list_cache: tuple[list[dict], float] | None = None
_jma_detail_url_cache: dict[str, tuple[str, float]] = {}
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
    for key in ("json", "detail", "url", "link", "uri"):
        value = item.get(key)
        if not isinstance(value, str):
            continue
        val = value.strip()
        if not val:
            continue
        if val.startswith(("http://", "https://")):
            return val
        return f"{_JMA_QUAKE_DETAIL_BASE}{val.lstrip('/')}"
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
    now = time.time()
    cached = _jma_detail_url_cache.get(key)
    if cached and now - cached[1] < _JMA_DETAIL_CACHE_TTL_SEC:
        return cached[0]

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

    _jma_detail_url_cache[key] = (best_url, now)
    return best_url


# ── 通知送信（確定地震情報 551） ──────────────────────────

async def _notify_all_guilds(bot: Bot, event: dict) -> None:
    max_scale = _max_scale(event)
    points    = event.get("points", [])

    eq   = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    lat  = _parse_coord(hypo.get("latitude"))
    lon  = _parse_coord(hypo.get("longitude"))

    detail_url = await _resolve_jma_detail_url(event, max_scale)

    is_minor = max_scale <= 20  # 震度1-2 はコンパクト表示

    badge_buf: io.BytesIO | None = None
    try:
        badge_buf = _generate_badge(max_scale)
    except Exception as e:
        logger.exception("[earthquake] badge generation error: %s", e)

    map_buf: io.BytesIO | None = None
    if not is_minor and lat is not None and lon is not None and points:
        try:
            # タイル取得は専用セッションで実施（WS セッションを汚染しない）
            async with aiohttp.ClientSession() as tile_session:
                map_buf = await _generate_intensity_map(tile_session, lat, lon, points)
        except Exception as e:
            logger.exception("[earthquake] map generation error: %s", e)

    embed = _build_embed(event, max_scale, has_badge=bool(badge_buf))
    if map_buf:
        embed.set_image(url="attachment://earthquake_map.png")

    view = _EqView(detail_url)

    targets: list[tuple[int, discord.TextChannel]] = []
    for guild_id in get_all_guild_ids():
        s = get_earthquake_settings(guild_id)
        ch_id = s.get("channel_id")
        if not ch_id:
            continue
        if max_scale < int(s.get("min_scale", 30)):
            continue
        if not get_earthquake_notify_types(guild_id).get("quake_info", True):
            continue
        guild = bot.get_guild(guild_id)
        if guild is None:
            continue
        channel = guild.get_channel(int(ch_id))
        if not isinstance(channel, discord.TextChannel):
            continue
        targets.append((guild_id, channel))

    if not targets:
        return

    badge_data = badge_buf.getvalue() if badge_buf else None
    map_data   = map_buf.getvalue()   if map_buf   else None

    async def _send(channel: discord.TextChannel) -> None:
        files: list[discord.File] = []
        if badge_data:
            files.append(discord.File(io.BytesIO(badge_data), filename="intensity_badge.png"))
        if map_data:
            files.append(discord.File(io.BytesIO(map_data), filename="earthquake_map.png"))
        await channel.send(embed=embed, files=files or discord.utils.MISSING, view=view)

    results = await asyncio.gather(
        *(_send(ch) for _, ch in targets),
        return_exceptions=True,
    )
    for (guild_id, _), result in zip(targets, results):
        if isinstance(result, Exception):
            logger.exception("[earthquake] send error guild=%s: %s", guild_id, result)


# ── 津波情報通知（552） ───────────────────────────────────

async def _notify_tsunami_guilds(bot: Bot, event: dict) -> None:
    """津波情報 (code 552) を全対象ギルドへ送信。"""
    embed = _build_tsunami_embed(event)

    targets: list[discord.TextChannel] = []
    for guild_id in get_all_guild_ids():
        s = get_earthquake_settings(guild_id)
        ch_id = s.get("channel_id")
        if not ch_id:
            continue
        if not get_earthquake_notify_types(guild_id).get("tsunami", True):
            continue
        guild = bot.get_guild(guild_id)
        if guild is None:
            continue
        channel = guild.get_channel(int(ch_id))
        if isinstance(channel, discord.TextChannel):
            targets.append(channel)

    if not targets:
        return

    results = await asyncio.gather(
        *(ch.send(embed=embed) for ch in targets),
        return_exceptions=True,
    )
    for ch, result in zip(targets, results):
        if isinstance(result, Exception):
            logger.exception("[tsunami] send error ch=%s: %s", ch.id, result)


# ── EEW 通知（554 警報 / 556 予報） ──────────────────────

async def _notify_eew_guilds(bot: Bot, event: dict, notify_type: str) -> None:
    """EEW を全対象ギルドへ送信。notify_type: 'eew_warning' or 'eew_forecast'"""
    max_scale  = _max_scale(event)
    detail_url = await _resolve_jma_detail_url(event, max_scale)

    # 554 (EEWDetection) は震度が分からない（max_scale == -1）。
    # 分からない震度を「-1」のバッジ画像にして貼るのは避ける。
    badge_buf: io.BytesIO | None = None
    if max_scale >= 0:
        try:
            badge_buf = _generate_badge(max_scale)
        except Exception:
            pass

    embed = _build_eew_embed(event)
    if badge_buf:
        embed.set_thumbnail(url="attachment://intensity_badge.png")

    view = _EqView(detail_url)

    targets: list[discord.TextChannel] = []
    for guild_id in get_all_guild_ids():
        s = get_earthquake_settings(guild_id)
        ch_id = s.get("channel_id")
        if not ch_id:
            continue
        # 震度が分からない（554 の検出通知）ときは、閾値で弾かず必ず届ける。
        # EEW は安全に倒すほうが良いという判断。
        if max_scale >= 0 and max_scale < int(s.get("min_scale", 30)):
            continue
        if not get_earthquake_notify_types(guild_id).get(notify_type, True):
            continue
        guild = bot.get_guild(guild_id)
        if guild is None:
            continue
        channel = guild.get_channel(int(ch_id))
        if isinstance(channel, discord.TextChannel):
            targets.append(channel)

    if not targets:
        return

    badge_data = badge_buf.getvalue() if badge_buf else None

    async def _send(channel: discord.TextChannel) -> None:
        files = ([discord.File(io.BytesIO(badge_data), filename="intensity_badge.png")]
                 if badge_data else discord.utils.MISSING)
        await channel.send(embed=embed, files=files, view=view)

    results = await asyncio.gather(*(_send(ch) for ch in targets), return_exceptions=True)
    for ch, result in zip(targets, results):
        if isinstance(result, Exception):
            logger.exception("[eew] send error ch=%s: %s", ch.id, result)


# ── WebSocket ループ ──────────────────────────────────────

def _spawn(coro) -> asyncio.Task:
    """通知タスクをバックグラウンドで起動し、未捕捉例外をログに記録する。"""
    task = asyncio.create_task(coro)
    task.add_done_callback(
        lambda t: logger.exception("[earthquake] task error: %s", t.exception())
        if not t.cancelled() and t.exception() else None
    )
    return task


async def run_earthquake_ws(bot: Bot) -> None:
    """P2PQuake WS 1本で地震情報 (551)・津波情報 (552)・EEW検出 (554)・EEW予報 (556) を受信する。

    554 (EEWDetection) は震源データを持たない「チャイムが鳴ったことの検出」のみの
    通知で、実際の震源・規模・震度は 556 (EEW予報) 側にしか入っていない。

    通知処理はすべて asyncio.create_task() でバックグラウンド起動するため、
    WS 受信ループはタイル取得や Discord API 送信をブロックせず常に即応する。
    """
    _eew_seen: set[str] = set()

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

                            if code == 551:
                                # タイル生成を含むためバックグラウンド実行
                                _spawn(_notify_all_guilds(bot, data))

                            elif code == 552:
                                _spawn(_notify_tsunami_guilds(bot, data))

                            elif code in (554, 556) and not data.get("cancelled"):
                                notify_type = "eew_forecast" if code == 556 else "eew_warning"
                                # P2PQuake は同じ情報を複数回配信することがあるため、
                                # 公式が推奨するとおり id で重複だけを弾く
                                # （https://www.p2pquake.net/develop/json_api_v2/ ）。
                                # 以前はここを自前の eq_time + serialNo + isFinal の
                                # 合成キーで組んでいたが、実際のペイロードには
                                # serialNo・isFinal はトップレベルに存在せず
                                # （556 の続報番号は issue.serial、554 には
                                # earthquake すら無い）常に既定値へ落ちてキーが固定化し、
                                # 起動後の最初の1件を送った後は同じ震度階級の通知が
                                # 二度と送られない不具合になっていた。
                                event_id = data.get("id")
                                if event_id and event_id not in _eew_seen:
                                    _eew_seen.add(event_id)
                                    if len(_eew_seen) > 200:
                                        _eew_seen.clear()
                                    # EEW は最優先でバックグラウンド起動
                                    _spawn(_notify_eew_guilds(bot, data, notify_type))

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            logger.warning("[earthquake] WS 切断: %s", msg.type)
                            break
        except Exception as e:
            logger.exception("[earthquake] WS エラー: %s", e)
        logger.info("[earthquake] 10秒後に再接続")
        await asyncio.sleep(10)
