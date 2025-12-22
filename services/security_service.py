import asyncio
import time
import base64
import re
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional, Union, TypedDict

import aiohttp
import discord
import unicodedata
import datetime

from config import OPENAI_API_KEY, VIRUSTOTAL_API_KEY
from services.logging_service import log_action
from services.settings_store import get_trusted_user_ids, get_bypass_role_ids

# -------------------------------
# 型定義
# -------------------------------
class ModerationResult(TypedDict):
    danger: bool
    reason: str
    category: str

# -------------------------------
# グローバル変数
# -------------------------------
_message_timestamps: Dict[Tuple[int, int], Deque[float]] = defaultdict(lambda: deque(maxlen=10))
_voice_joins: Dict[Tuple[int, int], Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=50))

# -------------------------------
# 定数
# -------------------------------
MAX_MESSAGES_PER_SEC = 2
VOICE_SIMILAR_JOIN_THRESHOLD = 3
VOICE_JOIN_WINDOW_SEC = 20

MAX_MESSAGE_LENGTH_SUSPICIOUS = 4000
MAX_REPEATED_CHAR_RUN = 100
MAX_WEIRD_CHAR_COUNT = 16
MAX_WEIRD_CHAR_RATIO = 0.15

VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls"
MAX_VT_URLS_PER_MESSAGE = 3
NEW_MEMBER_LINK_SEC = 3600

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

# -------------------------------
# ユーティリティ
# -------------------------------
def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def _encode_vt_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

# -------------------------------
# VirusTotal URL チェック
# -------------------------------
async def check_url_virustotal(url: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "disabled"}

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json",
    }

    url_id = _encode_vt_url(url)
    lookup_url = f"{VT_URL_LOOKUP}/{url_id}"

    async with aiohttp.ClientSession() as session:
        async with session.get(lookup_url, headers=headers) as resp:
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
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

# -------------------------------
# メッセージレート監視
# -------------------------------
def register_message_rate(guild_id: int, user_id: int) -> bool:
    now = time.time()
    dq = _message_timestamps[(guild_id, user_id)]
    dq.append(now)
    while dq and now - dq[0] > 1.0:
        dq.popleft()
    return len(dq) >= MAX_MESSAGES_PER_SEC

# -------------------------------
# 名前類似度
# -------------------------------
def _name_similarity(a: str, b: str) -> float:
    a = a.lower()
    b = b.lower()
    max_len = max(len(a), len(b)) or 1
    prefix = 0
    for ca, cb in zip(a, b):
        if ca == cb:
            prefix += 1
        else:
            break
    return prefix / max_len

# -------------------------------
# VC参加監視
# -------------------------------
def register_voice_join(guild_id: int, channel_id: int, member_name: str) -> bool:
    now = time.time()
    dq = _voice_joins[(guild_id, channel_id)]
    dq.append((now, member_name))

    while dq and now - dq[0][0] > VOICE_JOIN_WINDOW_SEC:
        dq.popleft()

    similar = sum(1 for _, name in dq if _name_similarity(member_name, name) >= 0.7)
    return similar >= VOICE_SIMILAR_JOIN_THRESHOLD

# -------------------------------
# GPTによるメッセージ判定
# -------------------------------
async def moderate_message_content(
    content: str,
    joined_at: Optional[discord.utils.snowflake_time] = None,
) -> ModerationResult:
    system_prompt = (
        "貴様はDiscordサーバーのセキュリティ監査役だ。"
        "投稿内容が危険かどうか(フィッシング、マルウェア、詐欺、荒らし、スパム等)を判定せよ。"
        "出力は必ずJSON一行のみ:"
        "{""danger"":true/false,""reason"":""理由"",""category"":""カテゴリ""}"
    )

    joined_info = ""
    if joined_at:
        joined_info = f"\n参加日時(UTC): {joined_at.isoformat()}"

    user_prompt = (
        "以下のメッセージを審査せよ。\n"
        f"{joined_info}\n\n本文:\n{content}"
    )

    data = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                },
                json=data,
            ) as resp:
                j = await resp.json()
                raw = j["choices"][0]["message"]["content"]
    except Exception:
        return {"danger": False, "reason": "moderation_error", "category": "error"}

    try:
        import json
        result = json.loads(raw)
    except Exception:
        return {"danger": False, "reason": "parse_error", "category": "error"}

    result["danger"] = (
        result["danger"].lower() == "true"
        if isinstance(result.get("danger"), str)
        else bool(result.get("danger"))
    )
    return result  # type: ignore

# -------------------------------
# 信頼済み判定
# -------------------------------
def _is_trusted_member(guild_id: int, member_id: int) -> bool:
    return member_id in set(get_trusted_user_ids(guild_id))

def _has_bypass_role(guild: discord.Guild, member: discord.Member) -> bool:
    bypass_ids = set(get_bypass_role_ids(guild.id))
    return any(r.id in bypass_ids for r in member.roles)

# -------------------------------
# Unicode異常判定
# -------------------------------
def is_suspicious_unicode(text: str) -> tuple[bool, str]:
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
            return True, "同一文字の異常連続"

    weird = sum(
        1 for ch in text
        if ord(ch) in {0x200B,0x200C,0x200D,0x2060,0xFEFF,0x202A,0x202B,0x202D,0x202E,0x202C}
        or unicodedata.category(ch).startswith("C")
    )

    if weird >= MAX_WEIRD_CHAR_COUNT and weird / max(len(text), 1) >= MAX_WEIRD_CHAR_RATIO:
        return True, "制御文字が異常に多い"

    return False, ""

# -------------------------------
# ロール剥奪 + 警告
# -------------------------------
async def strip_all_roles_and_warn(
    bot: discord.Client,
    guild: discord.Guild,
    member: discord.Member,
    channel: discord.abc.Messageable,
    reason: str,
) -> None:
    from datetime import timezone, timedelta
    JST = timezone(timedelta(hours=9))
    now = datetime.datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")

    roles = [r for r in member.roles if r.name != "@everyone"]
    if roles:
        await member.remove_roles(*roles, reason=reason)

    await log_action(
        bot,
        guild.id,
        "ERROR",
        "危険行為検出",
        user=member,
        fields={
            "理由": reason,
            "時刻": now,
        },
        embed_color=discord.Color.red(),
    )

    try:
        await channel.send(
            f"⚠️ {member.mention} による危険なリンク/コンテンツを検出。\n"
            "リンクを開かないよう注意してください。"
        )
    except Exception:
        pass

# -------------------------------
# メッセージセキュリティ処理
# -------------------------------
async def handle_security_for_message(message: discord.Message, bot: discord.Client) -> None:
    if not message.guild or not isinstance(message.author, discord.Member):
        return

    guild = message.guild
    member = message.author

    if _is_trusted_member(guild.id, member.id) or _has_bypass_role(guild, member):
        return

    content = message.content or ""
    links = extract_links(content)

    is_spam = register_message_rate(guild.id, member.id)
    suspicious_unicode, unicode_reason = is_suspicious_unicode(content)

    joined_at = member.joined_at
    is_danger = False
    reasons = []

    # VirusTotal 検問
    vt_unknown = False
    for url in links[:MAX_VT_URLS_PER_MESSAGE]:
        vt = await check_url_virustotal(url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            is_danger = True
            reasons.append(
                f"VirusTotal検出 {url} (malicious={vt['malicious']}, suspicious={vt['suspicious']})"
            )
        elif vt.get("status") == "unknown":
            vt_unknown = True

    # VT 未判定のみ GPT
    if links and not is_danger and vt_unknown:
        moderation = await moderate_message_content(content, joined_at)
        if moderation["danger"]:
            is_danger = True
            reasons.append(f"GPT判定: {moderation['reason']}")

    # 新規参加者リンク
    if links and joined_at:
        age = (datetime.datetime.utcnow() - joined_at.replace(tzinfo=None)).total_seconds()
        if age < NEW_MEMBER_LINK_SEC:
            is_danger = True
            reasons.append("新規参加ユーザーのリンク投稿")

    if is_spam:
        reasons.append("高頻度メッセージ")
    if suspicious_unicode:
        reasons.append(f"Unicode異常: {unicode_reason}")

    if is_danger or is_spam or suspicious_unicode:
        await strip_all_roles_and_warn(
            bot, guild, member, message.channel, " | ".join(reasons)
        )

# -------------------------------
# VC参加時セキュリティ処理
# -------------------------------
async def handle_security_for_voice_join(
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
    bot: discord.Client,
) -> None:
    if not member.guild:
        return

    if _is_trusted_member(member.guild.id, member.id) or _has_bypass_role(member.guild, member):
        return

    if before.channel is None and after.channel is not None:
        if register_voice_join(member.guild.id, after.channel.id, member.display_name):
            await strip_all_roles_and_warn(
                bot,
                member.guild,
                member,
                after.channel,
                "VCレイド検出（類似名大量参加）",
            )
