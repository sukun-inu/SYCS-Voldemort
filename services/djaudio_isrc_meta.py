"""
Deezer API を使って MP3 のメタデータを補完するモジュール。
1. ISRC が取れている場合 → /track/isrc:{isrc} で完全一致検索
2. ISRC がない場合       → 媒体別クエリ最適化＋フォールバックリトライで検索
いずれも認証不要の公開エンドポイントを使用。
"""

import asyncio
import logging
import re
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
from typing import cast

import aiohttp
from mutagen.id3 import APIC, ID3, TALB, TDRC, TIT2, TPOS, TPE1, TRCK
from mutagen.mp3 import MP3

from services.djaudio_site_detection import detect_site

logger = logging.getLogger(__name__)

_DEEZER_ISRC = "https://api.deezer.com/track/isrc:{}"
_DEEZER_SEARCH = "https://api.deezer.com/search"

_HIGH_SCORE = 0.80
_MIN_SCORE = 0.45

_NOISE_BRACKET = re.compile(
    r"""
    [\(\[\【]
    \s*
    (?:
        official\s+(?:music\s+)?(?:video|audio|mv|visualizer|lyric[s]?|clip)|
        (?:hd|4k|8k|hq)\s*(?:video)?|
        full\s+(?:song|album|version)|
        (?:audio|video)\s*(?:only)?|
        remaster(?:ed)?(?:\s+\d{4})?|
        (?:extended|original|radio|album|single)\s+(?:mix|edit|version)|
        from\s+[^\)\]\】]+|
        (?:feat|ft)\.?\s+[^\)\]\】]+|
        lyric[s]?|
        (?:m/?v|p/?v)|
        \d{4}(?:\s+version)?|
        live(?:\s+ver(?:sion)?)?|
        ver(?:sion)?\.?\s*\w*|
        short\s+ver(?:sion)?|
        music\s+video|
        visuali[sz]er|
        sub(?:title)?[s]?\s+(?:indo|english|日本語)|
        (?:日本語|英語|한국어|中文)\s*(?:字幕|ver)?
    )
    \s*
    [\)\]\】]
    """,
    re.IGNORECASE | re.VERBOSE,
)

_FEAT_BARE = re.compile(r"\s+(?:feat|ft)\.?\s+.+$", re.IGNORECASE)
_TOPIC_SUFFIX = re.compile(r"\s*[-/]\s*Topic\s*$", re.IGNORECASE)
_DASH_SPLIT = re.compile(r"\s+[-－—–]\s+")


def _clean_title(title: str) -> str:
    t = _FEAT_BARE.sub("", title)
    t = _NOISE_BRACKET.sub("", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    t = re.sub(r"[\s\-_|/\\]+$", "", t).strip()
    return t or title


def _normalize_for_compare(text: str) -> str:
    t = unicodedata.normalize("NFKD", text)
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = t.lower()
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _similarity(a: str, b: str) -> float:
    na, nb = _normalize_for_compare(a), _normalize_for_compare(b)
    if not na or not nb:
        return 0.0
    return SequenceMatcher(None, na, nb).ratio()


def _score_result(item: dict, ref_title: str, ref_artist: str | None) -> float:
    dz_title = item.get("title") or ""
    dz_artist = (item.get("artist") or {}).get("name") or ""
    title_sim = _similarity(ref_title, dz_title)
    if ref_artist:
        return title_sim * 0.65 + _similarity(ref_artist, dz_artist) * 0.35
    return title_sim


def _build_search_queries(title: str, artist: str | None, site: str, info: dict) -> list[str]:
    clean = _clean_title(title)
    queries: list[str] = []

    if site == "youtube":
        uploader = _TOPIC_SUFFIX.sub("", str(info.get("uploader") or "")).strip()
        if _DASH_SPLIT.search(clean):
            parts = _DASH_SPLIT.split(clean, maxsplit=1)
            queries.append(f'artist:"{parts[0].strip()}" track:"{parts[1].strip()}"')
            queries.append(f'track:"{parts[1].strip()}"')
        if artist:
            queries.append(f'artist:"{artist}" track:"{clean}"')
        elif uploader:
            queries.append(f'artist:"{uploader}" track:"{clean}"')
        queries.append(f'track:"{clean}"')
        if clean != title:
            raw_clean = _clean_title(_DASH_SPLIT.split(title, 1)[-1]) if _DASH_SPLIT.search(title) else clean
            if raw_clean and raw_clean not in queries:
                queries.append(f'track:"{raw_clean}"')

    elif site == "soundcloud":
        if artist:
            queries.append(f'artist:"{artist}" track:"{clean}"')
        queries.append(f'track:"{clean}"')
        if artist:
            queries.append(f'"{artist}" "{clean}"')

    elif site == "bandcamp":
        album = str(info.get("album") or "").strip()
        if artist and clean:
            queries.append(f'artist:"{artist}" track:"{clean}"')
        if artist and album:
            queries.append(f'artist:"{artist}" album:"{album}"')
        queries.append(f'track:"{clean}"')

    elif site == "tiktok":
        music_title = str(info.get("music_title") or "").strip()
        music_artist = str(info.get("music_author") or "").strip()
        if music_artist and music_title:
            queries.append(f'artist:"{music_artist}" track:"{music_title}"')
        if music_title:
            queries.append(f'track:"{music_title}"')
        if artist and clean:
            queries.append(f'artist:"{artist}" track:"{clean}"')
        queries.append(f'track:"{clean}"')

    elif site == "nicovideo":
        queries.append(f'track:"{clean}"')
        if clean != title:
            queries.append(f'track:"{title}"')

    else:
        if artist:
            queries.append(f'artist:"{artist}" track:"{clean}"')
        queries.append(f'track:"{clean}"')

    bare = clean if clean else title
    if bare not in queries:
        queries.append(bare)

    seen: set[str] = set()
    deduped: list[str] = []
    for q in queries:
        if q and q not in seen:
            seen.add(q)
            deduped.append(q)
    return deduped


async def _fetch_by_isrc(isrc: str, session: aiohttp.ClientSession) -> dict | None:
    try:
        async with session.get(
            _DEEZER_ISRC.format(isrc),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                logger.warning("Deezer: ISRC=%s の検索で HTTP %d エラー", isrc, resp.status)
                return None
            data: dict = await resp.json(content_type=None)
            if "error" in data:
                logger.info("Deezer: ISRC=%s 未登録", isrc)
                return None
            return data
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.warning("Deezer ISRC 検索エラー: %s", e)
        return None


async def _fetch_by_search(
    title: str,
    artist: str | None,
    session: aiohttp.ClientSession,
    site: str = "generic",
    info: dict | None = None,
) -> dict | None:
    clean = _clean_title(title)
    ref_title = clean
    ref_artist = artist
    if _DASH_SPLIT.search(clean):
        parts = _DASH_SPLIT.split(clean, maxsplit=1)
        ref_artist = ref_artist or parts[0].strip()
        ref_title = parts[1].strip()

    queries = _build_search_queries(title, artist, site, info or {})
    best_item: dict | None = None
    best_score: float = 0.0

    for q in queries:
        try:
            async with session.get(
                _DEEZER_SEARCH,
                params={"q": q, "limit": 5},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    logger.warning("Deezer テキスト検索 HTTP %d エラー (q=%r)", resp.status, q)
                    continue
                data = await resp.json(content_type=None)
                items: list[dict] = data.get("data") or []

            for item in items:
                score = _score_result(item, ref_title, ref_artist)
                if score > best_score:
                    best_score = score
                    best_item = item
                if score >= _HIGH_SCORE:
                    logger.info("Deezer 高精度ヒット (score=%.2f): q=%r → %r", score, q, item.get("title"))
                    return item
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning("Deezer テキスト検索エラー (q=%r): %s", q, e)

    if best_item and best_score >= _MIN_SCORE:
        logger.info("Deezer ベストマッチ採用 (score=%.2f): %r", best_score, best_item.get("title"))
        return best_item
    return None


async def _download_bytes(url: str, session: aiohttp.ClientSession) -> bytes | None:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.read()
            logger.warning("カバー画像取得エラー: URL=%s, HTTP %d", url, resp.status)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.warning("カバー画像取得エラー: URL=%s, %s", url, e)
    return None


def _write_tags(mp3_path: Path, data: dict, cover: bytes | None) -> None:
    audio = MP3(mp3_path, ID3=ID3)
    if audio.tags is None:
        audio.add_tags()
    tags = cast(ID3, audio.tags)

    if title := data.get("title"):
        tags["TIT2"] = TIT2(encoding=3, text=title)
    if artist_name := (data.get("artist") or {}).get("name"):
        tags["TPE1"] = TPE1(encoding=3, text=artist_name)
    album_data = data.get("album") or {}
    if album_title := album_data.get("title"):
        tags["TALB"] = TALB(encoding=3, text=album_title)
    if release_date := data.get("release_date"):
        tags["TDRC"] = TDRC(encoding=3, text=release_date[:4])
    if track_pos := data.get("track_position"):
        tags["TRCK"] = TRCK(encoding=3, text=str(track_pos))
    if disk_num := data.get("disk_number"):
        tags["TPOS"] = TPOS(encoding=3, text=str(disk_num))
    if cover and cover[:3] == b"\xff\xd8\xff":
        tags.delall("APIC")
        tags.add(APIC(encoding=3, mime="image/jpeg", type=3, desc="Cover", data=cover))

    tags.save(mp3_path)


def _cover_url(data: dict) -> str | None:
    album = data.get("album") or {}
    return album.get("cover_xl") or album.get("cover_big") or album.get("cover")


async def enrich_metadata(mp3_path: Path, info: dict) -> bool:
    """
    Deezer からメタデータを取得して MP3 タグを上書きする。
    成功したら True、スキップ・失敗なら False を返す。
    """
    isrc = info.get("isrc")
    title = info.get("track") or info.get("title") or info.get("alt_title")
    artist = info.get("artist") or info.get("album_artist") or info.get("creator") or info.get("uploader")
    site = detect_site(info)

    if not isrc and not title:
        return False

    async with aiohttp.ClientSession() as session:
        data = None
        if isrc:
            data = await _fetch_by_isrc(isrc, session)
        if data is None and title:
            data = await _fetch_by_search(title, artist, session, site=site, info=info)
        if not data:
            logger.info("Deezer: 該当なし (%s)", mp3_path.name)
            return False
        cover_url = _cover_url(data)
        cover = await _download_bytes(cover_url, session) if cover_url else None

    try:
        await asyncio.to_thread(_write_tags, mp3_path, data, cover)
        logger.info("Deezer メタデータ適用完了: %s", mp3_path.name)
        return True
    except Exception as e:
        logger.warning("タグ書き込みエラー (%s): %s", mp3_path.name, e)
        return False
