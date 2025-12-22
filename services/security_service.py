import asyncio
import time
import base64
import hashlib
import re
import unicodedata
import datetime
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional, Union, TypedDict

import aiohttp
import discord

from config import OPENAI_API_KEY, VIRUSTOTAL_API_KEY
from services.logging_service import log_action
from services.settings_store import get_trusted_user_ids, get_bypass_role_ids

# ============================================================
# 型定義
# ============================================================
class ModerationResult(TypedDict):
    danger: bool
    reason: str
    category: str

# ============================================================
# グローバル状態
# ============================================================
_message_timestamps: Dict[Tuple[int, int], Deque[float]] = defaultdict(lambda: deque(maxlen=10))
_voice_joins: Dict[Tuple[int, int], Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=50))

# hashキャッシュ (sha256 -> vt_result)
_HASH_CACHE: Dict[str, Dict] = {}

# ============================================================
# 定数
# ============================================================
MAX_MESSAGES_PER_SEC = 2
VOICE_SIMILAR_JOIN_THRESHOLD = 3
VOICE_JOIN_WINDOW_SEC = 20

MAX_MESSAGE_LENGTH_SUSPICIOUS = 4000
MAX_REPEATED_CHAR_RUN = 100
MAX_WEIRD_CHAR_COUNT = 16
MAX_WEIRD_CHAR_RATIO = 0.15

NEW_MEMBER_LINK_SEC = 3600

DANGEROUS_EXTENSIONS = {".exe", ".lnk", ".iso"}

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls"
VT_FILE_LOOKUP = "https://www.virustotal.com/api/v3/files"

# ============================================================
# ユーティリティ
# ============================================================
def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def _encode_vt_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def _file_extension(filename: str) -> str:
    return "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

# ============================================================
# VirusTotal URL チェック
# ============================================================
async def check_url_virustotal(url: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "disabled"}

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json",
    }

    url_id = _encode_vt_url(url)
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{VT_URL_LOOKUP}/{url_id}", headers=headers) as resp:
            if resp.status == 404:
                return {"status": "unknown"}
            if resp.status != 200:
                return {"status": "error"}
            data = await resp.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
    }

# ============================================================
# VirusTotal FILE(hash) チェック
# ============================================================
async def check_file_hash_virustotal(sha256: str) -> Dict:
    if sha256 in _HASH_CACHE:
        return _HASH_CACHE[sha256]

    if not VIRUSTOTAL_API_KEY:
        return {"status": "disabled"}

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json",
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(f"{VT_FILE_LOOKUP}/{sha256}", headers=headers) as resp:
            if resp.status == 404:
                result = {"status": "unknown"}
            elif resp.status != 200:
                result = {"status": "error"}
            else:
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                result = {
                    "status": "ok",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

    _HASH_CACHE[sha256] = result
    return result

# ============================================================
# GPT補助評価（BAN不可）
# ============================================================
async def gpt_risk_assessment(name: str, context: str) -> ModerationResult:
    system = (
        "貴様はDiscordサーバーのセキュリティ分析官だ。"
        "以下の情報が危険な兆候を持つかを判定せよ。"
        "出力はJSONのみ:"
        '{"danger":true/false,"reason":"理由","category":"type"}'
    )

    user = f"対象: {name}\n内容:\n{context}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                },
                json={
                    "model": "gpt-5-mini",
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            ) as resp:
                j = await resp.json()
                raw = j["choices"][0]["message"]["content"]

        import json
        result = json.loads(raw)
        result["danger"] = bool(result.get("danger"))
        return result
    except Exception:
        return {"danger": False, "reason": "gpt_error", "category": "error"}

# ============================================================
# 荒らし対策
# ============================================================
def register_message_rate(guild_id: int, user_id: int) -> bool:
    now = time.time()
    dq = _message_timestamps[(guild_id, user_id)]
    dq.append(now)
    while dq and now - dq[0] > 1.0:
        dq.popleft()
    return len(dq) >= MAX_MESSAGES_PER_SEC

def is_suspicious_unicode(text: str) -> Tuple[bool, str]:
    if not text:
        return False, ""

    if len(text) >= MAX_MESSAGE_LENGTH_SUSPICIOUS:
        run = longest = 1
        prev = None
        for ch in text:
            run = run + 1 if ch == prev else 1
            longest = max(longest, run)
            prev = ch
        if longest >= MAX_REPEATED_CHAR_RUN:
            return True, "同一文字の大量連続"

    weird = sum(
        1 for ch in text
        if unicodedata.category(ch).startswith("C")
    )
    if weird >= MAX_WEIRD_CHAR_COUNT and weird / max(len(text), 1) >= MAX_WEIRD_CHAR_RATIO:
        return True, "制御文字異常"

    return False, ""

# ============================================================
# 信頼判定（※処罰免除のみ）
# ============================================================
def _is_trusted_member(guild_id: int, member_id: int) -> bool:
    return member_id in set(get_trusted_user_ids(guild_id))

def _has_bypass_role(guild: discord.Guild, member: discord.Member) -> bool:
    return any(r.id in set(get_bypass_role_ids(guild.id)) for r in member.roles)

# ============================================================
# 処罰
# ============================================================
async def punish_member(
    bot: discord.Client,
    guild: discord.Guild,
    member: discord.Member,
    channel: discord.abc.Messageable,
    reason: str,
) -> None:
    roles = [r for r in member.roles if r.name != "@everyone"]
    if roles:
        await member.remove_roles(*roles, reason=reason)

    await log_action(
        bot,
        guild.id,
        "ERROR",
        "危険行為検出",
        user=member,
        fields={"理由": reason},
        embed_color=discord.Color.red(),
    )

    try:
        await channel.send(
            f"⚠️ {member.mention} による危険な行為を検出。\nリンクやファイルを開かないでください。"
        )
    except Exception:
        pass

# ============================================================
# メッセージ処理（核心）
# ============================================================
async def handle_security_for_message(message: discord.Message, bot: discord.Client) -> None:
    if not message.guild or not isinstance(message.author, discord.Member):
        return

    guild = message.guild
    member = message.author
    trusted = _is_trusted_member(guild.id, member.id) or _has_bypass_role(guild, member)

    reasons: List[str] = []
    ban = False

    # ---------- 添付ファイル検査 ----------
    for att in message.attachments:
        ext = _file_extension(att.filename)
        if ext in DANGEROUS_EXTENSIONS:
            async with aiohttp.ClientSession() as session:
                async with session.get(att.url) as resp:
                    data = await resp.read()

            sha256 = hashlib.sha256(data).hexdigest()
            vt = await check_file_hash_virustotal(sha256)

            if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
                ban = True
                reasons.append(f"VT FILE検出 {att.filename}")
            elif vt.get("status") == "unknown":
                gpt = await gpt_risk_assessment(att.filename, "Executable attachment")
                if gpt["danger"]:
                    reasons.append(f"GPT警告: {gpt['reason']}")

    # ---------- URL検査 ----------
    for url in extract_links(message.content or ""):
        vt = await check_url_virustotal(url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            ban = True
            reasons.append(f"VT URL検出 {url}")

    # ---------- 荒らし ----------
    if register_message_rate(guild.id, member.id):
        reasons.append("高頻度メッセージ")

    suspicious, u_reason = is_suspicious_unicode(message.content or "")
    if suspicious:
        reasons.append(f"Unicode異常: {u_reason}")

    # ---------- 実行 ----------
    if ban and not trusted:
        await punish_member(bot, guild, member, message.channel, " | ".join(reasons))
    elif reasons:
        await log_action(
            bot,
            guild.id,
            "WARN",
            "セキュリティ警告",
            user=member,
            fields={"詳細": " | ".join(reasons)},
            embed_color=discord.Color.orange(),
        )

# ============================================================
# VCレイド対策
# ============================================================
def _name_similarity(a: str, b: str) -> float:
    a = a.lower()
    b = b.lower()
    m = max(len(a), len(b)) or 1
    return sum(1 for x, y in zip(a, b) if x == y) / m

async def handle_security_for_voice_join(
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
    bot: discord.Client,
) -> None:
    if not member.guild:
        return

    if before.channel is None and after.channel is not None:
        dq = _voice_joins[(member.guild.id, after.channel.id)]
        now = time.time()
        dq.append((now, member.display_name))
        while dq and now - dq[0][0] > VOICE_JOIN_WINDOW_SEC:
            dq.popleft()

        similar = sum(1 for _, n in dq if _name_similarity(member.display_name, n) >= 0.7)
        if similar >= VOICE_SIMILAR_JOIN_THRESHOLD:
            if not _is_trusted_member(member.guild.id, member.id):
                await punish_member(
                    bot,
                    member.guild,
                    member,
                    after.channel,
                    "VCレイド検出",
                )
