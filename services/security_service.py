# Security_Service.py
import re
import asyncio
import time
import hashlib
from typing import List, Dict

import aiohttp
import discord

# =========================
# 設定値
# =========================

VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY"
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY"

# 危険とみなす拡張子
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".msi",
    ".lnk", ".iso", ".img"
}

# 新規参加者とみなす日数
NEW_MEMBER_THRESHOLD_DAYS = 7

# 荒らし検知用
MAX_MENTIONS = 5
MAX_LINKS = 5
SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15  # 秒

# キャッシュ（VT/API負荷対策）
VT_CACHE_TTL = 60 * 60 * 6  # 6時間

# =========================
# 内部キャッシュ
# =========================

_vt_cache: Dict[str, Dict] = {}
_user_message_history: Dict[int, List[float]] = {}

# =========================
# 正規表現
# =========================

URL_REGEX = re.compile(
    r"(https?://[^\s]+)",
    re.IGNORECASE
)

SUSPICIOUS_UNICODE_REGEX = re.compile(
    r"[\u202A-\u202E\u2066-\u2069]"
)

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

def hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

# =========================
# VirusTotal
# =========================

async def check_url_virustotal(url: str) -> Dict:
    key = hash_url(url)
    now = time.time()

    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

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
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

            _vt_cache[key] = {
                "time": now,
                "data": parsed
            }

            return parsed

# =========================
# GPT 評価（軽量）
# =========================

async def gpt_risk_assessment(text: str) -> str:
    """
    戻り値: SAFE / SUSPICIOUS / DANGEROUS
    """
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": "You are a security moderation AI."
            },
            {
                "role": "user",
                "content": f"""
次のメッセージは荒らし・詐欺・マルウェア配布の可能性があるか判定してください。
SAFE / SUSPICIOUS / DANGEROUS のどれか一語で答えてください。

{text}
"""
            }
        ],
        "temperature": 0
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload
        ) as resp:
            if resp.status != 200:
                return "SUSPICIOUS"

            data = await resp.json()
            content = data["choices"][0]["message"]["content"].strip().upper()

            if "DANGEROUS" in content:
                return "DANGEROUS"
            if "SUSPICIOUS" in content:
                return "SUSPICIOUS"
            return "SAFE"

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

async def handle_security_for_message(
    message: discord.Message,
    *,
    ban_on_malware: bool = True
):
    # BOT無視
    if message.author.bot:
        return

    member = message.author if isinstance(message.author, discord.Member) else None
    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments or []

    reasons = []
    is_danger = False

    # ===== デバッグログ =====
    print(
        "[SECURITY]",
        "author:", message.author,
        "content_len:", len(content),
        "links:", links,
        "attachments:", [a.filename for a in attachments]
    )

    # =========================
    # ① 荒らし（スパム）
    # =========================
    if check_spam(message.author.id):
        is_danger = True
        reasons.append("短時間での連投（スパム）")

    if message.mentions and len(message.mentions) >= MAX_MENTIONS:
        is_danger = True
        reasons.append("過剰メンション")

    if len(links) >= MAX_LINKS:
        is_danger = True
        reasons.append("過剰リンク")

    # =========================
    # ② Unicode トリック
    # =========================
    if SUSPICIOUS_UNICODE_REGEX.search(content):
        reasons.append("不可視Unicode検出")

    # =========================
    # ③ 添付ファイル検査
    # =========================
    dangerous_files = []

    for a in attachments:
        filename = (a.filename or "").lower()
        if any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            dangerous_files.append(a)

    if dangerous_files:
        for a in dangerous_files:
            vt = await check_url_virustotal(a.url)
            if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
                is_danger = True
                reasons.append(
                    f"危険ファイル: {a.filename} (malicious={vt['malicious']})"
                )

    # =========================
    # ④ URL検査
    # =========================
    for url in links:
        vt = await check_url_virustotal(url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            is_danger = True
            reasons.append(
                f"危険URL: {url} (malicious={vt['malicious']})"
            )

    # =========================
    # ⑤ GPT評価（補助）
    # =========================
    if not is_danger and (links or dangerous_files):
        gpt_result = await gpt_risk_assessment(content)
        if gpt_result == "DANGEROUS":
            is_danger = True
            reasons.append("GPT危険判定")
        elif gpt_result == "SUSPICIOUS":
            reasons.append("GPT要注意判定")

    # =========================
    # ⑥ 新規参加者補正
    # =========================
    if member and is_new_member(member) and (links or dangerous_files):
        is_danger = True
        reasons.append("新規参加者によるリンク/ファイル投稿")

    # =========================
    # ⑦ 実行
    # =========================
    if is_danger:
        await message.delete()

        if ban_on_malware and member:
            await member.ban(
                reason=" / ".join(reasons),
                delete_message_days=1
            )

        print("[SECURITY] BLOCKED:", reasons)

    else:
        print("[SECURITY] OK")
