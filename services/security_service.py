import re
import asyncio
import time
import hashlib
from typing import List, Dict

import aiohttp
import discord

# =========================
# 設定
# =========================

VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY"
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY"

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".msi",
    ".lnk", ".iso", ".img"
}

NEW_MEMBER_THRESHOLD_DAYS = 7

MAX_MENTIONS = 5
MAX_LINKS = 5
SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15

VT_CACHE_TTL = 60 * 60 * 6  # 6時間

# =========================
# 内部キャッシュ
# =========================

_vt_cache: Dict[str, Dict] = {}
_user_message_history: Dict[int, List[float]] = {}

# =========================
# 正規表現
# =========================

URL_REGEX = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
SUSPICIOUS_UNICODE_REGEX = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# =========================
# ユーティリティ
# =========================

def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def is_new_member(member: discord.Member) -> bool:
    if not member.joined_at:
        return False
    delta = discord.utils.utcnow() - member.joined_at
    return delta.days < NEW_MEMBER_THRESHOLD_DAYS

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

# =========================
# VirusTotal
# =========================

async def check_url_virustotal(url: str) -> Dict:
    key = sha256(url)
    now = time.time()

    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        ) as resp:
            if resp.status != 200:
                return {"status": "error"}

            data = await resp.json()
            analysis_id = data["data"]["id"]

        await asyncio.sleep(2)

        async with session.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        ) as resp:
            if resp.status != 200:
                return {"status": "error"}

            result = await resp.json()
            stats = result["data"]["attributes"]["stats"]

            parsed = {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }

            _vt_cache[key] = {"time": now, "data": parsed}
            return parsed

# =========================
# GPT 補助判定
# =========================

async def gpt_risk_assessment(text: str) -> str:
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a security moderation AI."},
            {
                "role": "user",
                "content": f"""
次の投稿がマルウェア配布・詐欺・荒らしの可能性があるか判定してください。
SAFE / SUSPICIOUS / DANGEROUS のどれか一語で答えてください。

{text}
"""
            },
        ],
        "temperature": 0,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
        ) as resp:
            if resp.status != 200:
                return "SUSPICIOUS"

            data = await resp.json()
            return data["choices"][0]["message"]["content"].strip().upper()

# =========================
# 荒らし検知
# =========================

def check_spam(author_id: int) -> bool:
    now = time.time()
    history = _user_message_history.setdefault(author_id, [])
    history.append(now)
    history[:] = [t for t in history if now - t < SPAM_TIME_WINDOW]
    return len(history) >= SPAM_REPEAT_THRESHOLD

# =========================
# メイン処理
# =========================

async def handle_security_for_message(message: discord.Message):
    if message.author.bot:
        return

    member = message.author if isinstance(message.author, discord.Member) else None
    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments or []

    reasons = []
    level = "CLEAN"  # CLEAN / UNVERIFIED / BLOCKED

    print(
        "[SECURITY]",
        "author:", message.author,
        "links:", links,
        "attachments:", [a.filename for a in attachments],
    )

    # ===== 荒らし =====
    if check_spam(message.author.id):
        level = "BLOCKED"
        reasons.append("スパム連投")

    if len(message.mentions) >= MAX_MENTIONS:
        level = "BLOCKED"
        reasons.append("過剰メンション")

    if len(links) >= MAX_LINKS:
        level = "BLOCKED"
        reasons.append("過剰リンク")

    # ===== Unicode =====
    if SUSPICIOUS_UNICODE_REGEX.search(content):
        level = max(level, "UNVERIFIED")
        reasons.append("不可視Unicode")

    # ===== 添付 =====
    dangerous_files = [
        a for a in attachments
        if any(a.filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    ]

    for a in dangerous_files:
        vt = await check_url_virustotal(a.url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            level = "BLOCKED"
            reasons.append(f"危険ファイル: {a.filename}")
        else:
            level = max(level, "UNVERIFIED")
            reasons.append(f"未検証ファイル: {a.filename}")

    # ===== URL =====
    for url in links:
        vt = await check_url_virustotal(url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            level = "BLOCKED"
            reasons.append(f"危険URL: {url}")
        else:
            level = max(level, "UNVERIFIED")
            reasons.append("未検証URL")

    # ===== GPT 補助 =====
    if level != "BLOCKED" and (links or dangerous_files):
        gpt = await gpt_risk_assessment(content)
        if gpt == "DANGEROUS":
            level = "BLOCKED"
            reasons.append("GPT危険判定")

    # ===== 新規参加者 =====
    if member and is_new_member(member) and (links or dangerous_files):
        level = "BLOCKED"
        reasons.append("新規参加者 + 実行形式")

    # ===== 実行 =====
    if level == "BLOCKED":
        await message.delete()
        if member:
            await member.ban(reason=" / ".join(reasons), delete_message_days=1)
        print("[SECURITY] BLOCKED:", reasons)

    elif level == "UNVERIFIED":
        await message.delete()
        print("[SECURITY] UNVERIFIED:", reasons)

    else:
        print("[SECURITY] CLEAN")
