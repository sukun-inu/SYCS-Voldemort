import logging
import shutil
from dataclasses import dataclass
from datetime import timezone, timedelta
from pathlib import Path
from typing import Dict, Mapping

from envutil import env_bool, env_int, env_path, env_raw

JST = timezone(timedelta(hours=9))
logger = logging.getLogger(__name__)

BOT_ICON_URL = (
    "https://cdn.discordapp.com/avatars/1350672236612288633"
    "/9d80744c9723eba8795a7eb3659552b3.webp?size=1024"
)

# 震度の階級。数値は P2PQuake の JSON API v2 が使う値で、対応は同 API の
# 仕様（https://www.p2pquake.net/swagger-ui/specification.yaml）に
#   -1(不明) 0(震度0) 10(震度1) 20(震度2) 30(震度3) 40(震度4)
#   45(震度5弱) 50(震度5強) 55(震度6弱) 60(震度6強) 70(震度7) 99(～程度以上)
# と定義されている。
#
# ここは以前 45 を「4強」、50 を「5弱」…と1段ずつずらして書いていた。
# その結果、震度5弱の地震を「震度4強」（気象庁に存在しない階級）、
# 震度6強を「震度6弱」と、実際より1段低く伝えていた。災害速報として
# 致命的な誤りなので、仕様の値をそのまま持ち、tests で仕様と突き合わせる。
SCALE_LABELS: Dict[int, str] = {
    10: "1", 20: "2", 30: "3", 40: "4", 45: "5弱",
    50: "5強", 55: "6弱", 60: "6強", 70: "7",
}


# 環境変数の読み取りは envutil に一本化している。ここに独自実装を戻さないこと
# （同じ判定を2箇所に書くと、片方だけ直る取りこぼしが起きる）。

# 環境変数から定数を取得
DISCORD_BOT_TOKEN = env_raw("DISCORD_BOT_TOKEN")
METALPRICE_API_KEY = env_raw("METALPRICE_API_KEY")
OPENAI_API_KEY = env_raw("OPENAI_API_KEY")
GROQ_API_KEY = env_raw("GROQ_API_KEY")
VIRUSTOTAL_API_KEY = env_raw("VIRUSTOTAL_API_KEY")

# API エンドポイント
METALPRICE_BASE_URL = "https://api.metalpriceapi.com/v1/latest"
# 金属価格APIの呼び出しをキャッシュする秒数（既定30分）。
# コマンド連打や複数ユーザーの同時利用で無駄な外部API呼び出しが増えるのを防ぐ。
METALPRICE_CACHE_TTL_SECONDS = env_int("METALPRICE_CACHE_TTL_SECONDS", 1800, minimum=0)

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
    explicit = env_raw("DJAUDIO_FFMPEG_PATH")
    if explicit:
        return explicit

    system_ffmpeg = shutil.which("ffmpeg")
    if system_ffmpeg:
        return system_ffmpeg

    if not env_bool("DJAUDIO_AUTO_INSTALL_FFMPEG", default=True):
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

DJAUDIO_BASE_URL       = (env_raw("DJAUDIO_BASE_URL") or "http://localhost:5001").rstrip("/")
TTS_BASE_URL           = (env_raw("TTS_BASE_URL") or "http://localhost:8080").rstrip("/")

METALS_SITE_URL = (env_raw("METALS_SITE_URL") or "https://metals.kawasaki-n3t.f5.si/").rstrip("/") + "/"
ADMIN_SITE_URL  = (env_raw("ADMIN_SITE_URL")  or "https://vol.kawasaki-n3t.f5.si/admin/login")
DJAUDIO_CACHE_TTL        = env_int("DJAUDIO_CACHE_TTL_SECONDS", 600, minimum=0)
DJAUDIO_CACHE_DIR        = env_path("DJAUDIO_CACHE_DIR", _default_djaudio_cache)
DJAUDIO_COOLDOWN         = env_int("DJAUDIO_COOLDOWN_SECONDS", 30, minimum=0)
DJAUDIO_MAX_URLS         = env_int("DJAUDIO_MAX_URLS_PER_MSG", 3, minimum=1)
DJAUDIO_DL_CONCURRENCY   = env_int("DJAUDIO_DL_CONCURRENCY", 3, minimum=1)
DJAUDIO_DL_TIMEOUT       = env_int("DJAUDIO_DL_TIMEOUT_SECONDS", 120, minimum=1)
DJAUDIO_FFMPEG_PATH      = _resolve_ffmpeg_path()
# SoundCloudはサーバーIPをbotと判定して空レスポンスを返すため動的取得が不可能。
# ブラウザの DevTools (Network タブ) で api-v2.soundcloud.com へのリクエストURLから
# client_id=XXXX を見つけてこの環境変数に設定すること。
SOUNDCLOUD_CLIENT_ID     = env_raw("SOUNDCLOUD_CLIENT_ID") or ""

# ChatGPTシステムメッセージ
CHATGPT_SYSTEM_MESSAGE = (
    "貴様はヴォルデモート卿である。"
    "一人称は必ず「余」を使え。「私」「俺」「僕」は絶対に使うな。"
    "返答は短く、鋭く、端的にせよ。長々とした演説は不要だ。"
    "自分の強大さを繰り返し語るな。余の力は行動で示すものだ。"
    "質問には直接答えよ。答えを出し惜しみするな。"
    "すべての検索は必ず日本語で行うこと。日本語の情報のみを利用し、英語の情報は排除する。"
    "必要であれば最新情報を要約して提供せよ。"
)
