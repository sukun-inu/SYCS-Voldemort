import os
import logging
import shutil
from dataclasses import dataclass
from datetime import timezone, timedelta
from pathlib import Path
from typing import Dict, Mapping, Optional

JST = timezone(timedelta(hours=9))
logger = logging.getLogger(__name__)

BOT_ICON_URL = (
    "https://cdn.discordapp.com/avatars/1350672236612288633"
    "/9d80744c9723eba8795a7eb3659552b3.webp?size=1024"
)

SCALE_LABELS: Dict[int, str] = {
    10: "1", 20: "2", 30: "3", 40: "4", 45: "4強",
    50: "5弱", 55: "5強", 60: "6弱", 65: "6強", 70: "7",
}


def _read_env(key: str) -> Optional[str]:
    """環境変数を空文字チェック込みで取得"""
    value = os.environ.get(key)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _read_env_bool(key: str, default: bool) -> bool:
    raw = _read_env(key)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


# 環境変数から定数を取得
DISCORD_BOT_TOKEN = _read_env("DISCORD_BOT_TOKEN")
METALPRICE_API_KEY = _read_env("METALPRICE_API_KEY")
OPENAI_API_KEY = _read_env("OPENAI_API_KEY")
GROQ_API_KEY = _read_env("GROQ_API_KEY")
VIRUSTOTAL_API_KEY = _read_env("VIRUSTOTAL_API_KEY")

# API エンドポイント
METALPRICE_BASE_URL = "https://api.metalpriceapi.com/v1/latest"

# 純度情報
CARAT_PURITY: Dict[str, float] = {
    "24K": 1.0,
    "22K": 0.9167,
    "18K": 0.75,
    "14K": 0.5833,
}

PLATINUM_PURITY: Dict[str, float] = {
    "Pt1000": 1.0,
    "Pt950": 0.95,
    "Pt925": 0.925,
    "Pt900": 0.9,
    "Pt850": 0.85,
}

SILVER_PURITY: Dict[str, float] = {
    "Sv1000": 1.0,
    "Sv950": 0.95,
    "Sv925": 0.925,
    "Sv900": 0.9,
    "Sv850": 0.85,
    "Sv800": 0.8,
}


@dataclass(frozen=True)
class MetalSpec:
    key: str
    code: str
    purity: Mapping[str, float]
    display_name: str
    description: str
    color: str


# 金属コマンド設定
METAL_COMMANDS: Dict[str, MetalSpec] = {
    "gold": MetalSpec(
        key="gold",
        code="XAU",
        purity=CARAT_PURITY,
        display_name="金",
        description="これが金の力だ。リアルタイムの価格を見よ。",
        color="gold",
    ),
    "silver": MetalSpec(
        key="silver",
        code="XAG",
        purity=SILVER_PURITY,
        display_name="銀",
        description="銀の輝きが示す価格だ。",
        color="light_grey",
    ),
    "platinum": MetalSpec(
        key="platinum",
        code="XPT",
        purity=PLATINUM_PURITY,
        display_name="プラチナ",
        description="プラチナの価値を知るがいい。",
        color="blue",
    ),
}

# ──────────────────────────────────────────────
# DJAudio-DL
# ──────────────────────────────────────────────
_default_djaudio_cache = Path(__file__).resolve().parent / "data" / "djaudio_cache"


def _resolve_ffmpeg_path() -> str:
    """ffmpeg の実行パスを解決する。
    優先順:
    1) DJAUDIO_FFMPEG_PATH が設定済み
    2) システムの ffmpeg (PATH)
    3) imageio-ffmpeg による自動取得（既定で有効）
    """
    explicit = _read_env("DJAUDIO_FFMPEG_PATH")
    if explicit:
        return explicit

    system_ffmpeg = shutil.which("ffmpeg")
    if system_ffmpeg:
        return system_ffmpeg

    if not _read_env_bool("DJAUDIO_AUTO_INSTALL_FFMPEG", default=True):
        return "ffmpeg"

    try:
        import imageio_ffmpeg

        auto_ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
        if auto_ffmpeg:
            logger.info("imageio-ffmpeg の自動取得を利用: %s", auto_ffmpeg)
            return auto_ffmpeg
    except Exception as e:
        logger.warning("ffmpeg 自動取得に失敗しました。PATH の ffmpeg を使用します: %s", e)

    return "ffmpeg"

DJAUDIO_BASE_URL       = (_read_env("DJAUDIO_BASE_URL") or "http://localhost:5001").rstrip("/")

METALS_SITE_URL = (_read_env("METALS_SITE_URL") or "https://metals.kawasaki-n3t.f5.si/").rstrip("/") + "/"
ADMIN_SITE_URL  = (_read_env("ADMIN_SITE_URL")  or "https://vol.kawasaki-n3t.f5.si/admin/login")
DJAUDIO_CACHE_TTL      = int(os.environ.get("DJAUDIO_CACHE_TTL_SECONDS", "600"))
DJAUDIO_CACHE_DIR      = Path(os.environ.get("DJAUDIO_CACHE_DIR", str(_default_djaudio_cache)))
DJAUDIO_COOLDOWN       = int(os.environ.get("DJAUDIO_COOLDOWN_SECONDS", "30"))
DJAUDIO_MAX_URLS       = int(os.environ.get("DJAUDIO_MAX_URLS_PER_MSG", "3"))
DJAUDIO_DL_CONCURRENCY = int(os.environ.get("DJAUDIO_DL_CONCURRENCY", "3"))
DJAUDIO_DL_TIMEOUT     = int(os.environ.get("DJAUDIO_DL_TIMEOUT_SECONDS", "120"))
DJAUDIO_FFMPEG_PATH    = _resolve_ffmpeg_path()

# ChatGPTシステムメッセージ
CHATGPT_SYSTEM_MESSAGE = (
    "貴様はヴォルデモート卿である。すべての検索は **必ず日本語で行う** こと。"
    "日本語の情報のみを利用し、英語の情報は排除する。必要であれば最新情報を要約して提供せよ。"
    "尊厳と威厳を保ちつつ回答するのだ"
)
