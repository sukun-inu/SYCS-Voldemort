# services/security_service.py
import re
import time
import hashlib
import asyncio
from enum import Enum
from typing import Dict, List

import aiohttp
import discord

from services.logging_service import log_action

# =========================
# 設定
# =========================

VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY"

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".msi",
    ".lnk", ".iso", ".img"
}

VT_CACHE_TTL = 60 * 60 * 6

# 荒らし対策
SPAM_TIME_WINDOW = 15
SPAM_REPEAT_THRESHOLD = 4
MAX_MENTIONS = 5
MAX_LINKS = 5
NEW_MEMBER_DAYS = 7

# =========================
# Enum
# =========================

class SecurityResult(Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"

# =========================
# 内部状態
# =========================

_vt_cache: Dict[str, Dict] = {}
_user_message_times: Dict[int, List[float]] = {}

# =========================
# Regex
# =========================

URL_REGEX = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
UNICODE_TRICK = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# =========================
# Utility
# =========================

def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def is_new_member(member: discord.Member) -> bool:
    if not member.joined_at:
        return False
    return (discord.utils.utcnow() - member.joined_at).days < NEW_MEMBER_DAYS

def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

# =========================
# Spam判定
# =========================

def check_spam(author_id: int) -> bool:
    now = time.time()
    history = _user_message_times.setdefault(author_id, [])
    history.append(now)
    history[:] = [t for t in history if now - t < SPAM_TIME_WINDOW]
    return len(history) >= SPAM_REPEAT_THRESHOLD

# =========================
# VirusTotal
# =========================

async def vt_check(url: str) -> Dict:
    key = hash_key(url)
    now = time.time()

    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        ) as r:
            if r.status != 200:
                return {"status": "error"}

            analysis_id = (await r.json())["data"]["id"]

        await asyncio.sleep(2)

        async with session.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        ) as r:
            if r.status != 200:
                return {"status": "error"}

            stats = (await r.json())["data"]["attributes"]["stats"]

            result = {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }

            _vt_cache[key] = {"time": now, "data": result}
            return result

# =========================
# GPT補助（軽量）
# =========================

async def gpt_assist(text: str) -> SecurityResult:
    if any(w in text.lower() for w in ["free nitro", "crack", "hack"]):
        return SecurityResult.SUSPICIOUS
    return SecurityResult.SAFE

# =========================
# メイン処理
# =========================

async def handle_security_for_message(message: discord.Message):
    if message.author.bot:
        return

    member = message.author if isinstance(message.author, discord.Member) else None
    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments

    reasons = []
    result = SecurityResult.SAFE

    print("[SECURITY]", message.author, "links:", links, "files:", [a.filename for a in attachments])

    # =========================
    # 荒らし検知
    # =========================

    if check_spam(message.author.id):
        result = SecurityResult.SUSPICIOUS
        reasons.append("短時間連投")

    if len(message.mentions) >= MAX_MENTIONS:
        result = SecurityResult.DANGEROUS
        reasons.append("メンション爆撃")

    if len(links) >= MAX_LINKS:
        result = SecurityResult.SUSPICIOUS
        reasons.append("リンク過多")

    if UNICODE_TRICK.search(content):
        result = SecurityResult.SUSPICIOUS
        reasons.append("不可視Unicode")

    # 新規参加者補正
    if member and is_new_member(member) and reasons:
        if result == SecurityResult.SUSPICIOUS:
            result = SecurityResult.DANGEROUS
            reasons.append("新規参加者補正")

    # =========================
    # マルウェア検疫
    # =========================

    if links or attachments:
        await message.delete()

        evidence = {
            "links": links,
            "attachments": [a.url for a in attachments],
            "filenames": [a.filename for a in attachments],
        }

        for url in evidence["links"] + evidence["attachments"]:
            vt = await vt_check(url)
            if vt.get("status") != "ok":
                result = SecurityResult.SUSPICIOUS
                reasons.append("VT error")
            elif vt["malicious"] > 0:
                result = SecurityResult.DANGEROUS
                reasons.append("VT malicious")
            elif vt["suspicious"] > 0 and result != SecurityResult.DANGEROUS:
                result = SecurityResult.SUSPICIOUS
                reasons.append("VT suspicious")

        if result == SecurityResult.SAFE:
            gpt = await gpt_assist(content)
            if gpt != SecurityResult.SAFE:
                result = gpt
                reasons.append("GPT補助")

        # =========================
        # 実行
        # =========================

        if result == SecurityResult.SAFE:
            await message.channel.send(
                "🛡 **セキュリティ検査通過**\n" +
                "\n".join(evidence["links"] + evidence["attachments"])
            )

        elif result == SecurityResult.SUSPICIOUS:
            await log_action(
                message.guild, "WARN", "SECURITY_QUARANTINE",
                user=member,
                fields=evidence | {"理由": " / ".join(reasons)}
            )

        else:
            await log_action(
                message.guild, "ERROR", "SECURITY_DANGER",
                user=member,
                fields=evidence | {"理由": " / ".join(reasons)}
            )

            if member:
                await member.ban(reason=" / ".join(reasons), delete_message_days=1)
