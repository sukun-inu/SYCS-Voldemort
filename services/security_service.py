import asyncio
import hashlib
import logging
import time
import os
import re
import tempfile
from typing import List, Dict, Tuple, Optional

import aiohttp
import discord
import vt

from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY
from services.settings_store import get_trusted_user_ids, get_bypass_role_ids

# ==================================================
# 設定
# ==================================================
NEW_MEMBER_THRESHOLD_DAYS = 7

MAX_LINKS = 5
SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15

VT_CACHE_TTL = 60 * 60 * 6

VC_RAID_WINDOW_SEC = 20
VC_RAID_SIMILAR_PREFIX = 4
VC_RAID_THRESHOLD = 5

# ==================================================
# 内部キャッシュ
# ==================================================
_vt_cache: Dict[str, Dict] = {}
_user_message_times: Dict[int, List[float]] = {}
_vc_join_history: Dict[int, List[Tuple[float, str, int]]] = {}

# ==================================================
# 正規表現
# ==================================================
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
UNICODE_TRICK_REGEX = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# ==================================================
# ロガー
# ==================================================
logger = logging.getLogger("security_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = True

# ==================================================
# ユーティリティ
# ==================================================
def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def is_new_member(member: discord.Member) -> bool:
    if not member.joined_at:
        return False
    return (discord.utils.utcnow() - member.joined_at).days < NEW_MEMBER_THRESHOLD_DAYS

def is_spam(user_id: int) -> bool:
    now = time.time()
    history = _user_message_times.setdefault(user_id, [])
    history.append(now)
    history[:] = [t for t in history if now - t < SPAM_TIME_WINDOW]
    return len(history) >= SPAM_REPEAT_THRESHOLD

def is_security_bypassed(member: discord.Member) -> Tuple[bool, str]:
    try:
        trusted = get_trusted_user_ids(member.guild.id)
        if member.id in trusted:
            return True, "trusted_user"

        bypass_roles = set(get_bypass_role_ids(member.guild.id))
        if any(r.id in bypass_roles for r in member.roles):
            return True, "bypass_role"
    except Exception as e:
        logger.error("[SECURITY] bypass check failed: %s", e)

    return False, ""

async def strip_roles(member: discord.Member) -> Tuple[bool, str]:
    try:
        roles = [r for r in member.roles if not r.is_default()]
        if not roles:
            return True, "no_roles"

        await member.remove_roles(*roles, reason="セキュリティ違反")
        return True, "removed"

    except discord.Forbidden:
        return False, "forbidden"
    except Exception as e:
        logger.error("[SECURITY] strip roles failed: %s", e)
        return False, str(e)

# ==================================================
# Content-Type 判定
# ==================================================
async def fetch_content_type(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.head(url, allow_redirects=True, timeout=10) as r:
            if r.status < 400:
                return r.headers.get("Content-Type", "")
    except Exception:
        pass

    try:
        async with session.get(url, allow_redirects=True, timeout=10) as r:
            return r.headers.get("Content-Type", "")
    except Exception:
        return ""

def is_file_content_type(content_type: str) -> bool:
    if not content_type:
        return False

    ct = content_type.lower()
    if ct.startswith("application/"):
        return True
    if ct in ("binary/octet-stream", "application/octet-stream"):
        return True
    return False

# ==================================================
# VirusTotal URL チェック（vt-py 0.22.0）
# ==================================================
async def vt_check_url(url: str) -> Dict:
    key = hash_text(url)
    now = time.time()

    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "url", "malicious": 0, "suspicious": 0}

    try:
        def sync():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                analysis = client.urls.scan(url, wait_for_completion=True)
                stats = analysis.stats
                return {
                    "status": "ok",
                    "type": "url",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

        result = await asyncio.to_thread(sync)
        _vt_cache[key] = {"time": now, "data": result}
        return result

    except Exception as e:
        logger.error("[VT] URL scan exception: %s", e)
        return {"status": "error", "type": "url", "reason": str(e), "malicious": 0, "suspicious": 0}

# ==================================================
# VirusTotal FILE チェック（vt-py 0.22.0）
# ==================================================
async def vt_check_file(content: bytes) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "file", "malicious": 0, "suspicious": 0}

    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        def sync():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                with open(tmp_path, "rb") as f:
                    analysis = client.files.scan(f, wait_for_completion=True)
                stats = analysis.stats
                return {
                    "status": "ok",
                    "type": "file",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

        return await asyncio.to_thread(sync)

    except Exception as e:
        logger.error("[VT] File scan exception: %s", e)
        return {"status": "error", "type": "file", "reason": str(e), "malicious": 0, "suspicious": 0}

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

# ==================================================
# VT 自動振り分け
# ==================================================
async def vt_scan_target(session: aiohttp.ClientSession, url: str) -> Dict:
    content_type = await fetch_content_type(session, url)
    logger.info("[VT] Content-Type %s -> %s", url, content_type)

    if is_file_content_type(content_type):
        async with session.get(url, timeout=20) as r:
            data = await r.read()
        return await vt_check_file(data)

    return await vt_check_url(url)

# ==================================================
# VT 結果 Embed
# ==================================================
def build_vt_embed(results: List[Dict]) -> discord.Embed:
    embed = discord.Embed(
        title="🛡 VirusTotal Scan Result",
        color=discord.Color.red()
    )

    for idx, r in enumerate(results, 1):
        embed.add_field(
            name=f"Target {idx} ({r.get('type')})",
            value=(
                f"Status: `{r.get('status')}`\n"
                f"Malicious: `{r.get('malicious')}`\n"
                f"Suspicious: `{r.get('suspicious')}`"
            ),
            inline=False
        )

    return embed

# ==================================================
# GPT 補助判定
# ==================================================
async def gpt_assess(text: str, vt_results: List[Dict]) -> str:
    for r in vt_results:
        if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0:
            return "DANGEROUS"

    if not OPENAI_API_KEY:
        return "SAFE"

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": "You are a security moderation AI."},
            {"role": "user", "content": f"以下の投稿を判定してください:\n{text}"}
        ],
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload
        ) as r:
            data = await r.json()
            reply = data["choices"][0]["message"]["content"].upper()

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply:
        return "SUSPICIOUS"
    return "SAFE"

# ==================================================
# メッセージセキュリティ
# ==================================================
async def handle_security_for_message(bot: discord.Client, message: discord.Message):
    if message.author.bot or message.guild is None:
        return

    member = message.author
    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments or []

    bypassed, _ = is_security_bypassed(member)
    if bypassed:
        return

    danger = False
    reasons: List[str] = []

    if is_spam(member.id):
        danger = True
        reasons.append("SPAM")

    if len(links) >= MAX_LINKS:
        danger = True
        reasons.append("TOO_MANY_LINKS")

    if UNICODE_TRICK_REGEX.search(content):
        reasons.append("UNICODE_TRICK")

    vt_results: List[Dict] = []
    async with aiohttp.ClientSession() as session:
        for url in links + [a.url for a in attachments]:
            res = await vt_scan_target(session, url)
            vt_results.append(res)
            if res.get("malicious", 0) > 0 or res.get("suspicious", 0) > 0:
                danger = True
                reasons.append("VT_DETECTED")

    gpt_result = await gpt_assess(content, vt_results)
    if gpt_result == "DANGEROUS":
        danger = True
        reasons.append("GPT")

    if is_new_member(member):
        danger = True
        reasons.append("NEW_MEMBER")

    if danger:
        try:
            await message.delete()
        except Exception:
            pass

        await strip_roles(member)

        try:
            embed = build_vt_embed(vt_results)
            await message.channel.send(
                "🚨 **危険な投稿をブロックしました**\n理由: " + " / ".join(reasons),
                embed=embed
            )
        except Exception as e:
            logger.error("[SECURITY] notify failed: %s", e)

    else:
        logger.info("[SECURITY] SAFE")

# ==================================================
# VC レイド検知（bot_setup.py 対応）
# ==================================================
async def handle_security_for_voice_join(
    bot: discord.Client,
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
):
    if member.bot or member.guild is None:
        return

    if before.channel == after.channel or after.channel is None:
        return

    now = time.time()
    gid = member.guild.id
    vc_id = after.channel.id

    history = _vc_join_history.setdefault(gid, [])
    history.append((now, member.display_name, vc_id))
    history[:] = [h for h in history if now - h[0] <= VC_RAID_WINDOW_SEC]

    same_vc = [n for (_, n, v) in history if v == vc_id]
    if len(same_vc) < VC_RAID_THRESHOLD:
        return

    prefix = same_vc[0][:VC_RAID_SIMILAR_PREFIX]
    similar = [n for n in same_vc if n.startswith(prefix)]

    if len(similar) < VC_RAID_THRESHOLD:
        return

    logger.warning("[SECURITY] VC RAID DETECTED")

    try:
        await after.channel.edit(user_limit=0)
    except Exception:
        pass

    if member.guild.system_channel:
        await member.guild.system_channel.send(
            f"🚨 **VCレイド検出**\n{after.channel.mention}"
        )
