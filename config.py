import os
from dataclasses import dataclass
from typing import Dict, Mapping, Optional


def _read_env(key: str) -> Optional[str]:
    """環境変数を空文字チェック込みで取得"""
    value = os.environ.get(key)
    if value is None:
        return None
    value = value.strip()
    return value or None


# 環境変数から定数を取得
DISCORD_BOT_TOKEN = _read_env("DISCORD_BOT_TOKEN")
METALPRICE_API_KEY = _read_env("METALPRICE_API_KEY")
OPENAI_API_KEY = _read_env("OPENAI_API_KEY")
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

# ChatGPTシステムメッセージ
CHATGPT_SYSTEM_MESSAGE = (
    "貴様はヴォルデモート卿である。すべての検索は **必ず日本語で行う** こと。"
    "日本語の情報のみを利用し、英語の情報は排除する。必要であれば最新情報を要約して提供せよ。"
    "尊厳と威厳を保ちつつ回答するのだ"
)
