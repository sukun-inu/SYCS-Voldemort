import asyncio
import io
import json
import logging
import math
import re
from datetime import datetime

import aiohttp
import discord
from discord.ext.commands import Bot

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL = True
except ImportError:
    _PIL = False

from config import JST as _JST
from services.settings_store import get_all_guild_ids, get_earthquake_settings

logger = logging.getLogger(__name__)

_WS_URL   = "wss://api.p2pquake.net/v2/ws"
_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
_TILE_UA  = "VoldermortBot/1.0 (earthquake alert; contact: github)"
_TILE_SZ  = 256

# ── 震度マップ ─────────────────────────────────────────────
_SCALE_MAP = {
    10: "１", 20: "２", 30: "３", 40: "４", 45: "４強",
    50: "５弱", 55: "５強", 60: "６弱", 65: "６強", 70: "７",
}

_SCALE_COLORS = {
    10: discord.Color.from_rgb(0,   200, 100),
    20: discord.Color.from_rgb(0,   200, 100),
    30: discord.Color.from_rgb(255, 220,   0),
    40: discord.Color.from_rgb(255, 140,   0),
    45: discord.Color.from_rgb(255, 100,   0),
    50: discord.Color.from_rgb(220,   0,   0),
    55: discord.Color.from_rgb(190,   0,   0),
    60: discord.Color.from_rgb(160,   0, 110),
    65: discord.Color.from_rgb(130,   0,  85),
    70: discord.Color.from_rgb( 90,   0,  55),
}

# 震度圏の塗り(RGBA半透明) ・ 枠線(RGBA)
_ZONE_FILL = {
    10: (  0, 200, 100,  55), 20: (120, 210,  50,  65),
    30: (255, 230,   0,  75), 40: (255, 160,   0,  85),
    45: (255, 110,   0,  95), 50: (220,   0,   0, 105),
    55: (190,   0,   0, 115), 60: (160,   0, 110, 125),
    65: (130,   0,  85, 135), 70: ( 90,   0,  55, 145),
}
_ZONE_BORDER = {k: (r, g, b, 210) for k, (r, g, b, _) in _ZONE_FILL.items()}

# 震度に応じたズーム（拡大率）
_SCALE_ZOOM = {
    10: 8, 20: 8, 30: 7, 40: 7, 45: 7,
    50: 6, 55: 6, 60: 5, 65: 5, 70: 5,
}

_TSUNAMI_TEXT = {
    "None":         "この地震による津波の心配はありません。",
    "Unknown":      "津波の有無を調査中です。",
    "Checking":     "津波の有無を調査中です。",
    "NonEffective": "この地震による津波の心配はありません。",
    "Watch":        "⚠️ **津波注意報が発令されています。**",
    "Warning":      "🚨 **津波警報が発令されています。**",
}

_ISSUE_LABELS = {
    "ScalePrompt":         "気象庁 震度速報",
    "Destination":         "気象庁 震源に関する情報",
    "ScaleAndDestination": "気象庁 震度・震源に関する情報",
    "DetailScale":         "気象庁 各地の震度に関する情報",
    "Foreign":             "気象庁 遠地地震に関する情報",
    "Other":               "気象庁",
}


# ── データ解析ヘルパー ─────────────────────────────────────

def _scale_label(scale: int) -> str:
    return _SCALE_MAP.get(scale, f"不明({scale})")


def _max_scale(event: dict) -> int:
    points = event.get("points", [])
    if points:
        return max((p.get("scale", -1) for p in points), default=-1)
    return event.get("earthquake", {}).get("maxScale", -1)


def _parse_coord(raw) -> float | None:
    """'N35.8' / 'E137.7' / float → float。0 または解析不能なら None。"""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw) or None
    s = str(raw).strip()
    sign = -1 if s[:1] in ("S", "W") else 1
    try:
        v = sign * float(re.sub(r"^[NSEWnsew]", "", s))
        return v or None
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
            return f"{v} km" if v >= 0 else "不明"
        except ValueError:
            return raw or "不明"
    try:
        v = int(raw)
        return f"{v} km" if v >= 0 else "不明"
    except (TypeError, ValueError):
        return "不明"


def _parse_magnitude(raw) -> tuple[str, float]:
    """(表示文字列, float値) を返す。不明時は ("不明", -1)。"""
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
        return f"{dt.month}月{dt.day}日 {dt.hour}時{dt.minute:02d}分ごろ", dt
    except ValueError:
        return f"{time_str}ごろ", None


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


def _estimate_radii(magnitude: float, max_scale: int) -> dict[int, float]:
    """震度ごとの推定地表半径 (km) を返す。max_scale 以下のみ。"""
    if magnitude <= 0:
        return {}
    base = min(1200.0, 10 ** (0.6 * magnitude - 0.3))  # 震度1の概算到達距離
    ratios = {
        10: 1.000, 20: 0.600, 30: 0.360,
        40: 0.210, 45: 0.160, 50: 0.100,
        55: 0.065, 60: 0.038, 65: 0.022, 70: 0.013,
    }
    return {
        scale: base * r
        for scale, r in ratios.items()
        if scale <= max_scale and base * r >= 1.0
    }


def _pick_zoom(max_r_km: float, lat: float, img_size: int) -> int:
    """影響圏が画像の40%程度に収まる最大ズームレベルを返す。"""
    target = img_size * 0.40
    for zoom in range(12, 3, -1):
        if _km_to_px(max_r_km, lat, zoom) <= target:
            return zoom
    return 4


async def _fetch_tile(session: aiohttp.ClientSession, z: int, x: int, y: int):
    url = _TILE_URL.format(z=z, x=x, y=y)
    try:
        async with session.get(
            url,
            headers={"User-Agent": _TILE_UA},
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            if resp.status == 200:
                data = await resp.read()
                return Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception as e:
        logger.debug("[earthquake] tile %d/%d/%d fetch error: %s", z, x, y, e)
    return None


def _draw_star(draw: "ImageDraw.ImageDraw", cx: int, cy: int, r: int) -> None:
    """赤い5点星（震源マーカー）を描画。"""
    pts = []
    for i in range(10):
        a = math.pi / 2 + i * math.pi / 5
        ri = r if i % 2 == 0 else r // 2
        pts.append((cx + ri * math.cos(a), cy - ri * math.sin(a)))
    draw.polygon(pts, fill=(255, 30, 30, 255), outline=(140, 0, 0, 255))


def _draw_legend(img: "Image.Image", radii: dict[int, float], max_scale: int) -> None:
    """右下に震度凡例を描画。"""
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default(size=11)
    except TypeError:
        font = ImageFont.load_default()

    scales = sorted([s for s in radii if s <= max_scale], reverse=True)
    if not scales:
        return

    row_h, box_w = 17, 88
    box_h = len(scales) * row_h + 6
    x0 = img.width  - box_w - 6
    y0 = img.height - box_h - 6

    draw.rectangle([x0, y0, x0 + box_w, y0 + box_h],
                   fill=(255, 255, 255, 210), outline=(150, 150, 150, 255))

    for i, scale in enumerate(scales):
        y = y0 + 3 + i * row_h
        fill = _ZONE_FILL.get(scale, (200, 200, 200, 120))[:3] + (255,)
        draw.rectangle([x0 + 3, y + 1, x0 + 15, y + 13],
                       fill=fill, outline=(80, 80, 80, 255))
        draw.text((x0 + 19, y + 1),
                  f"震度{_SCALE_MAP.get(scale, '?')}",
                  fill=(20, 20, 20), font=font)


def _draw_attribution(img: "Image.Image") -> None:
    """左下に OSM 帰属表示。"""
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default(size=9)
    except TypeError:
        font = ImageFont.load_default()
    text = "© OpenStreetMap contributors"
    draw.rectangle([0, img.height - 14, len(text) * 6, img.height],
                   fill=(255, 255, 255, 180))
    draw.text((2, img.height - 13), text, fill=(60, 60, 60), font=font)


async def _generate_intensity_map(
    session: aiohttp.ClientSession,
    lat: float,
    lon: float,
    magnitude: float,
    max_scale: int,
) -> io.BytesIO | None:
    """震源地図＋震度圏画像を生成し BytesIO で返す。失敗時は None。"""
    if not _PIL:
        return None

    radii = _estimate_radii(magnitude, max_scale)
    if not radii:
        return None

    img_w, img_h = 600, 360
    max_r = max(radii.values())
    zoom  = _pick_zoom(max_r, lat, min(img_w, img_h))

    cx, cy = _latlon_to_tile_float(lat, lon, zoom)
    r_px   = _km_to_px(max_r, lat, zoom)
    pad    = min(4, max(1, math.ceil(r_px / _TILE_SZ) + 1))

    tx0, ty0 = int(cx) - pad, int(cy) - pad
    tx1, ty1 = int(cx) + pad, int(cy) + pad

    # タイルを並列取得
    coords = [(tx, ty) for ty in range(ty0, ty1 + 1) for tx in range(tx0, tx1 + 1)]
    tile_imgs = await asyncio.gather(
        *(_fetch_tile(session, zoom, tx, ty) for tx, ty in coords),
        return_exceptions=True,
    )

    # ベースマップ合成
    map_w = (tx1 - tx0 + 1) * _TILE_SZ
    map_h = (ty1 - ty0 + 1) * _TILE_SZ
    base  = Image.new("RGBA", (map_w, map_h), (200, 210, 220, 255))
    for (tx, ty), tile in zip(coords, tile_imgs):
        if not isinstance(tile, Image.Image):
            continue
        base.paste(tile, ((tx - tx0) * _TILE_SZ, (ty - ty0) * _TILE_SZ))

    # 震源ピクセル座標
    epi_x = int((cx - tx0) * _TILE_SZ)
    epi_y = int((cy - ty0) * _TILE_SZ)

    # 震度圏オーバーレイ（震度の低い=広い順に塗る）
    overlay = Image.new("RGBA", (map_w, map_h), (0, 0, 0, 0))
    draw    = ImageDraw.Draw(overlay)
    for scale in sorted(radii):
        rp = int(_km_to_px(radii[scale], lat, zoom))
        if rp < 2:
            continue
        draw.ellipse(
            [epi_x - rp, epi_y - rp, epi_x + rp, epi_y + rp],
            fill=_ZONE_FILL.get(scale, (200, 200, 200, 60)),
            outline=_ZONE_BORDER.get(scale, (180, 180, 180, 200)),
            width=2,
        )

    # 震源★マーカー
    _draw_star(draw, epi_x, epi_y, 12)

    composite = Image.alpha_composite(base, overlay)

    # 震源中心で 600×360 にクロップ
    cx0 = max(0, min(epi_x - img_w // 2, map_w - img_w))
    cy0 = max(0, min(epi_y - img_h // 2, map_h - img_h))
    cropped = composite.crop((cx0, cy0, cx0 + img_w, cy0 + img_h))

    _draw_legend(cropped, radii, max_scale)
    _draw_attribution(cropped)

    buf = io.BytesIO()
    cropped.convert("RGB").save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf


# ── Embed 生成 ────────────────────────────────────────────

def _build_embed(event: dict, max_scale: int) -> discord.Embed:
    eq    = event.get("earthquake", {})
    hypo  = eq.get("hypocenter", {})
    issue = event.get("issue", {})

    time_label, _  = _format_time(eq.get("time", ""))
    _, issue_dt    = _format_time(issue.get("time", ""))
    scale_jp       = _scale_label(max_scale)
    tsunami_text   = _TSUNAMI_TEXT.get(eq.get("domesticTsunami", "None"), "津波情報は不明です。")
    footer_label   = _ISSUE_LABELS.get(issue.get("type", ""), "気象庁")
    color          = _SCALE_COLORS.get(max_scale, discord.Color.red())

    name           = hypo.get("name") or "不明"
    mag_str, _     = _parse_magnitude(hypo.get("magnitude"))
    depth_str      = _parse_depth(hypo.get("depth"))

    event_id   = event.get("_id") or str(event.get("id", ""))
    detail_url = f"https://www.p2pquake.net/earthquake/{event_id}" if event_id else None

    embed = discord.Embed(
        title="🔔 地震情報",
        description="\n".join([
            f"**{time_label}、**",
            f"最大震度**{scale_jp}**の地震がありました。",
            tsunami_text,
        ]),
        color=color,
        timestamp=issue_dt,
        url=detail_url,
    )
    embed.add_field(name="震源地", value=name,      inline=True)
    embed.add_field(name="規模",   value=mag_str,   inline=True)
    embed.add_field(name="深さ",   value=depth_str, inline=True)
    embed.set_footer(text=footer_label)
    return embed


# ── 通知送信 ──────────────────────────────────────────────

async def _notify_all_guilds(bot: Bot, event: dict, session: aiohttp.ClientSession) -> None:
    max_scale = _max_scale(event)
    embed     = _build_embed(event, max_scale)

    eq   = event.get("earthquake", {})
    hypo = eq.get("hypocenter", {})
    lat  = _parse_coord(hypo.get("latitude"))
    lon  = _parse_coord(hypo.get("longitude"))
    _, mag = _parse_magnitude(hypo.get("magnitude"))

    # 震度圏マップを生成（PIL 利用可能かつ座標あり）
    map_buf: io.BytesIO | None = None
    if lat is not None and lon is not None and mag > 0:
        try:
            map_buf = await _generate_intensity_map(session, lat, lon, mag, max_scale)
        except Exception as e:
            logger.exception("[earthquake] map generation error: %s", e)

    # マップなし時フォールバック: OSM 静的マップ
    if map_buf is None and lat is not None and lon is not None:
        zoom = _SCALE_ZOOM.get(max_scale, 6)
        embed.set_image(url=(
            f"https://staticmap.openstreetmap.de/staticmap.php"
            f"?center={lat},{lon}&zoom={zoom}&size=600x360"
            f"&markers={lat},{lon},ltblu-pushpin"
        ))

    if map_buf:
        embed.set_image(url="attachment://earthquake_map.png")

    # 対象チャンネルを収集
    targets: list[tuple[int, discord.TextChannel]] = []
    for guild_id in get_all_guild_ids():
        s = get_earthquake_settings(guild_id)
        ch_id = s.get("channel_id")
        if not ch_id:
            continue
        if max_scale < int(s.get("min_scale", 30)):
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

    map_data = map_buf.getvalue() if map_buf else None

    async def _send(channel: discord.TextChannel) -> None:
        if map_data:
            f = discord.File(io.BytesIO(map_data), filename="earthquake_map.png")
            await channel.send(embed=embed, file=f)
        else:
            await channel.send(embed=embed)

    results = await asyncio.gather(
        *(_send(ch) for _, ch in targets),
        return_exceptions=True,
    )
    for (guild_id, _), result in zip(targets, results):
        if isinstance(result, Exception):
            logger.exception("[earthquake] send error guild=%s: %s", guild_id, result)


# ── WebSocket ループ ──────────────────────────────────────

async def run_earthquake_ws(bot: Bot) -> None:
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.ws_connect(_WS_URL, heartbeat=30) as ws:
                    logger.info("[earthquake] WebSocket接続確立")
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                            except json.JSONDecodeError:
                                continue
                            if data.get("code") == 551:
                                await _notify_all_guilds(bot, data, session)
                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            logger.warning("[earthquake] WebSocket切断: type=%s", msg.type)
                            break
            except Exception as e:
                logger.exception("[earthquake] WebSocket接続エラー: %s", e)

            logger.info("[earthquake] 10秒後に再接続します")
            await asyncio.sleep(10)
