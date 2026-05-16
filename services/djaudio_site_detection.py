"""yt-dlp の info.json からソース媒体を判定するユーティリティ。"""

import re
from urllib.parse import urlparse

SUPPORTED_SITES: frozenset[str] = frozenset({
    "youtube",
    "soundcloud",
    "bandcamp",
    "nicovideo",
    "tiktok",
})

# DJ-Audio が処理を受け付けるドメインの許可リスト
_DJAUDIO_ALLOWED_HOSTS: frozenset[str] = frozenset({
    "youtube.com",
    "youtu.be",
    "music.youtube.com",
    "soundcloud.com",
    "on.soundcloud.com",
    "nicovideo.jp",
    "nico.ms",
    "tiktok.com",
    "vm.tiktok.com",
    "vt.tiktok.com",
    "bandcamp.com",
})


def is_djaudio_allowed_url(url: str) -> bool:
    """DJ-Audio が処理できるドメインであれば True を返す（許可リスト方式）。

    bandcamp はアーティストサブドメイン（*.bandcamp.com）も許可する。
    """
    try:
        hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
    except Exception:
        return False
    if hostname in _DJAUDIO_ALLOWED_HOSTS:
        return True
    if hostname.endswith(".bandcamp.com"):
        return True
    return False


_UNSUPPORTED_URL_RULES: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"open\.spotify\.com", re.IGNORECASE),
        "Spotify は著作権保護のため音声をダウンロードできません。"
        "YouTube Music などの代替 URL をお試しください。",
    ),
    (
        re.compile(r"music\.apple\.com", re.IGNORECASE),
        "Apple Music は著作権保護のため音声をダウンロードできません。",
    ),
    (
        re.compile(r"music\.amazon\.(co\.jp|com)", re.IGNORECASE),
        "Amazon Music は著作権保護のため音声をダウンロードできません。",
    ),
]


def is_unsupported_url(url: str) -> str | None:
    """ダウンロード非対応サービスの URL であれば理由メッセージを返す。対応サービスなら None。"""
    for pattern, reason in _UNSUPPORTED_URL_RULES:
        if pattern.search(url):
            return reason
    return None


def detect_site(info: dict) -> str:
    """extractor フィールドと URL から媒体識別子を返す。"""
    extractor = str(info.get("extractor") or info.get("extractor_key") or "").lower()
    if "youtube" in extractor:
        return "youtube"
    if "soundcloud" in extractor:
        return "soundcloud"
    if "bandcamp" in extractor:
        return "bandcamp"
    if "nicovideo" in extractor or "nico" in extractor:
        return "nicovideo"
    if "tiktok" in extractor:
        return "tiktok"

    url = str(info.get("webpage_url") or info.get("url") or "").lower()
    if "youtube.com" in url or "youtu.be" in url:
        return "youtube"
    if "soundcloud.com" in url:
        return "soundcloud"
    if "bandcamp.com" in url:
        return "bandcamp"
    if "nicovideo.jp" in url:
        return "nicovideo"
    if "tiktok.com" in url:
        return "tiktok"

    return "generic"
