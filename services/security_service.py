import asyncio
import time
import base64
import re
import hashlib
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional, TypedDict

import aiohttp
import discord
import unicodedata
import datetime

from config import OPENAI_API_KEY, VIRUSTOTAL_API_KEY
from services.logging_service import log_action
from services.settings_store import get_trusted_user_ids, get_bypass_role_ids

# ===============================
# 型
# ===============================
class ModerationResult(TypedDict):
    danger: bool
    reason: str
    category: str

# ===============================
# グローバル
# ===============================
_message_timestamps: Dict[Tuple[int, int], Deque[float]] = defaultdict(lambda: deque(maxlen=10))
_voice_joins: Dict[Tuple[int, int], Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=50))
_hash_cache: Dict[str, dict] = {}
_last_vt_request = 0.0

# ===============================
# 定数
# ===============================
MAX_MESSAGES_PER_SEC = 2
VOICE_SIMILAR_JOIN_THRESHOLD = 3
VOICE_JOIN_WINDOW_SEC = 20

DANGEROUS_EXTENSIONS = {".exe", ".lnk", ".iso"}

VT_FILE_LOOKUP = "https://www.virustotal.com/api/v3/files"
VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls"
VT_INTERVAL = 20  # 無料API制限

URL_REGEX = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

# ===============================
# ユーティリティ
# ===============================
def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _encode_vt_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

async def vt_rate_limit():
    global _last_vt_request
    delta = time.time() - _last_vt_request
    if delta < VT_INTERVAL:
        await asyncio.sleep(VT_INTERVAL - delta)
    _last_vt_request = time.time()

# ===============================
# VirusTotal
# ===============================
async def vt_check_hash(file_hash: str) -> Optional[dict]:
    if file_hash in _hash_cache:
        return _hash_cache[file_hash]

    if not VIRUSTOTAL_API_KEY:
        return None

    await vt_rate_limit()
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as s:
        async with s.get(f"{VT_FILE_LOOKUP}/{file_hash}", headers=headers) as r:
            if r.status != 200:
                return None
            j = await r.json()
            stats = j["data"]["attributes"]["last_analysis_stats"]
            _hash_cache[file_hash] = stats
            return stats

async def vt_check_url(url: str) -> Optional[dict]:
    await vt_rate_limit()
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = _encode_vt_url(url)

    async with aiohttp.ClientSession() as s:
        async with s.get(f"{VT_URL_LOOKUP}/{url_id}", headers=headers) as r:
            if r.status != 200:
                return None
            j = await r.json()
            return j["data"]["attributes"]["last_analysis_stats"]

# ===============================
# GPT 補助評価
# ===============================
async def gpt_moderation(content: str) -> ModerationResult:
    if not OPENAI_API_KEY:
        return {"danger": False, "reason": "disabled", "category": "none"}

    data = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": "Discordセキュリティ監査役として危険性を評価せよ。JSONのみ出力。"},
            {"role": "user", "content": content},
        ],
    }

    async with aiohttp.ClientSession() as s:
        async with s.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=data,
        ) as r:
            j = await r.json()
            import json as _j
            return _j.loads(j["choices"][0]["message"]["content"])

# ===============================
# 荒らし検知
# ===============================
def register_message_rate(guild_id: int, user_id: int) -> bool:
    now = time.time()
    dq = _message_timestamps[(guild_id, user_id)]
    dq.append(now)
    while dq and now - dq[0] > 1:
        dq.popleft()
    return len(dq) >= MAX_MESSAGES_PER_SEC

def is_suspicious_unicode(text: str) -> bool:
    weird = sum(
        1 for c in text
        if unicodedata.category(c).startswith("C")
    )
    return weird >= 16

def _name_similarity(a: str, b: str) -> float:
    match = sum(1 for x, y in zip(a, b) if x == y)
    return match / max(len(a), len(b), 1)

def register_voice_join(guild_id: int, channel_id: int, name: str) -> bool:
    now = time.time()
    dq = _voice_joins[(guild_id, channel_id)]
    dq.append((now, name))
    while dq and now - dq[0][0] > VOICE_JOIN_WINDOW_SEC:
        dq.popleft()
    return sum(1 for _, n in dq if _name_similarity(name, n) >= 0.7) >= VOICE_SIMILAR_JOIN_THRESHOLD

# ===============================
# メイン処理
# ===============================
async def handle_security_for_message(message: discord.Message, bot: discord.Client):
    if not message.guild or not isinstance(message.author, discord.Member):
        return

    guild = message.guild
    member = message.author

    if member.id in get_trusted_user_ids(guild.id):
        return

    reasons = []

    # 荒らし
    if register_message_rate(guild.id, member.id):
        reasons.append("スパム投稿")

    if is_suspicious_unicode(message.content):
        reasons.append("Unicode異常")

    # 添付ファイル
    for a in message.attachments:
        ext = "." + a.filename.split(".")[-1].lower()
        if ext in DANGEROUS_EXTENSIONS:
            data = await a.read()
            h = sha256(data)
            vt = await vt_check_hash(h)
            if vt and vt.get("malicious", 0) > 0:
                await guild.ban(member, reason="VirusTotal検出")
                return

    # URL
    for url in extract_links(message.content):
        vt = await vt_check_url(url)
        if vt and vt.get("malicious", 0) > 0:
            reasons.append("悪性URL検出")

    # GPT（補助）
    if reasons:
        gpt = await gpt_moderation(message.content)
        reasons.append(f"GPT補助判定: {gpt['reason']}")

    if reasons:
        await log_action(
            bot,
            guild.id,
            "WARN",
            "セキュリティ検知",
            user=member,
            fields={"理由": " | ".join(reasons)},
            embed_color=discord.Color.orange(),
        )
