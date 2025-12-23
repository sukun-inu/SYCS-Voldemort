import asyncio
import hashlib
import logging
import time
import os
import re
import tempfile
import datetime
from typing import List, Dict, Tuple

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
# VirusTotal URL / FILE チェック
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
                analysis = client.scan_url(url, wait_for_completion=True)
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
        return {"status": "error", "type": "url", "reason": str(e), "malicious": -1, "suspicious": -1}

async def vt_check_file(content: bytes) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "file", "malicious": 0, "suspicious": 0}

    sha256 = hashlib.sha256(content).hexdigest()
    tmp_path = None

    try:
        def sync_lookup():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                try:
                    obj = client.get_object(f"/files/{sha256}")
                    stats = obj.last_analysis_stats
                    return {"status": "cached", "type": "file", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
                except vt.error.APIError:
                    return None

        cached = await asyncio.to_thread(sync_lookup)
        if cached:
            return cached

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        def sync_scan():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                with open(tmp_path, "rb") as f:
                    analysis = client.scan_file(f, wait_for_completion=True)
                stats = analysis.stats
                return {"status": "ok", "type": "file", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}

        return await asyncio.to_thread(sync_scan)

    except vt.error.ConflictError:
        try:
            def sync_fallback():
                with vt.Client(VIRUSTOTAL_API_KEY) as client:
                    obj = client.get_object(f"/files/{sha256}")
                    stats = obj.last_analysis_stats
                    return {"status": "conflict_fallback", "type": "file", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}

            return await asyncio.to_thread(sync_fallback)
        except Exception as e:
            raise e

    except Exception as e:
        logger.error("[VT] File scan exception: %s", e)
        return {"status": "error", "type": "file", "reason": str(e), "malicious": -1, "suspicious": -1}

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

async def vt_scan_target(session: aiohttp.ClientSession, url: str) -> Dict:
    content_type = await fetch_content_type(session, url)
    logger.info("[VT] Content-Type %s -> %s", url, content_type)

    if content_type.startswith("image/"):
        return {"status": "skip", "type": "image", "malicious": 0, "suspicious": 0}

    if is_file_content_type(content_type):
        async with session.get(url, timeout=20) as r:
            data = await r.read()
        return await vt_check_file(data)

    return await vt_check_url(url)

# ==================================================
# GPT 判定
# ==================================================
async def gpt_assess(text: str, vt_results: List[Dict]) -> str:
    for r in vt_results:
        if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0:
            return "DANGEROUS"

    if not OPENAI_API_KEY:
        return "SAFE"

    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": "You are a security moderation AI."},
            {"role": "user", "content": f"以下の投稿を判定してください:\n{text}"}
        ],
    }

    async with aiohttp.ClientSession() as session:
        async with session.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload) as r:
            data = await r.json()
            reply = data["choices"][0]["message"]["content"].upper()

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply:
        return "SUSPICIOUS"
    return "SAFE"

# ==================================================
# Embedユーティリティ
# ==================================================
def now_jst() -> str:
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")

def build_progress_bar(current: int, total: int, length: int = 10) -> str:
    filled_len = int(length * current / total)
    bar = "█" * filled_len + "░" * (length - filled_len)
    return f"[{bar}] {current}/{total}"

def vt_icon(malicious: int, suspicious: int) -> str:
    if malicious > 0:
        return "🔴"
    if suspicious > 0:
        return "🟡"
    return "🟢"

def gpt_icon(result: str) -> str:
    if result == "DANGEROUS":
        return "🔴"
    if result == "SUSPICIOUS":
        return "🟡"
    return "🟢"

def reason_icon(reason: str) -> str:
    mapping = {
        "SPAM": "⚠️",
        "TOO_MANY_LINKS": "⚠️",
        "UNICODE_TRICK": "⚠️",
        "NEW_MEMBER": "🆕",
        "GPT": "🤖",
        "VT_DETECTED": "🛡",
        "VC_RAID": "🎵",
    }
    return mapping.get(reason, "ℹ️")

def build_final_embed(vt_results: List[Dict], gpt_result: str, reasons: List[str], logs: List[str]) -> discord.Embed:
    if "DANGEROUS" in reasons or gpt_result == "DANGEROUS":
        color = discord.Color.red()
        title = "🚨 危険な投稿を検出"
    elif "SUSPICIOUS" in reasons or gpt_result == "SUSPICIOUS":
        color = discord.Color.orange()
        title = "⚠️ 注意：投稿に問題の可能性"
    else:
        color = discord.Color.green()
        title = "✅ 検査完了：問題なし"

    embed = discord.Embed(title=title, description="\n".join(logs), color=color)

    for idx, r in enumerate(vt_results, 1):
        icon = vt_icon(r.get("malicious", 0), r.get("suspicious", 0))
        embed.add_field(name=f"{icon} ターゲット {idx} ({r.get('type')})",
                        value=f"Status: `{r.get('status')}` | Malicious: `{r.get('malicious')}` | Suspicious: `{r.get('suspicious')}`",
                        inline=False)

    embed.add_field(name=f"{gpt_icon(gpt_result)} GPT判定", value=f"結果: `{gpt_result}`", inline=False)

    if reasons:
        icons = " / ".join([reason_icon(r) + r for r in reasons])
        embed.add_field(name="判定理由", value=icons, inline=False)

    embed.set_footer(text=f"実行時間: {now_jst()}")
    return embed

# ==================================================
# VCレイド検知
# ==================================================
def check_vc_raid(member: discord.Member, channel_id: int) -> bool:
    now = time.time()
    history = _vc_join_history.setdefault(channel_id, [])
    history.append((now, member.display_name[:VC_RAID_SIMILAR_PREFIX], member.id))
    history[:] = [h for h in history if now - h[0] < VC_RAID_WINDOW_SEC]

    name_counter = {}
    for _, prefix, _ in history:
        name_counter[prefix] = name_counter.get(prefix, 0) + 1
        if name_counter[prefix] >= VC_RAID_THRESHOLD:
            return True
    return False

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

    logs: List[str] = [f"🔍 {now_jst()} にスキャン開始"]
    reasons: List[str] = []
    danger = False

    bypassed, _ = is_security_bypassed(member)
    if bypassed:
        logs.append("🔹 信頼済みユーザー / バイパスロール検出")
        embed = build_final_embed([], "SAFE", [], logs)
        await message.channel.send(embed=embed)
        return

    # SPAM判定
    if is_spam(member.id):
        danger = True
        reasons.append("SPAM")
        logs.append("⚠️ スパム検出")

    # リンク数過多
    if len(links) >= MAX_LINKS:
        danger = True
        reasons.append("TOO_MANY_LINKS")
        logs.append("⚠️ リンク数過多")

    # Unicode trick
    if UNICODE_TRICK_REGEX.search(content):
        reasons.append("UNICODE_TRICK")
        logs.append("⚠️ ユニコードトリック検出")

    progress_msg = None
    vt_results: List[Dict] = []

    # VT解析
    if links or attachments:
        progress_msg = await message.channel.send(
            embed=discord.Embed(title="🔍 セキュリティ検査中", description="VirusTotal解析中…", color=discord.Color.blurple())
        )
        async with aiohttp.ClientSession() as session:
            targets = links + [a.url for a in attachments]
            for idx, url in enumerate(targets, 1):
                res = await vt_scan_target(session, url)
                vt_results.append(res)
                icon = vt_icon(res.get("malicious", 0), res.get("suspicious", 0))
                logs.append(f"{icon} {url} をスキャン: Malicious={res.get('malicious')} Suspicious={res.get('suspicious')}")
                if res.get("malicious", 0) > 0 or res.get("suspicious", 0) > 0:
                    danger = True
                    reasons.append("VT_DETECTED")
                if progress_msg:
                    bar = build_progress_bar(idx, len(targets))
                    await progress_msg.edit(embed=discord.Embed(
                        title="🔍 セキュリティ検査中",
                        description="\n".join(logs) + f"\n{bar}",
                        color=discord.Color.blurple()
                    ))

    # GPT判定
    gpt_result = await gpt_assess(content, vt_results)
    if gpt_result == "DANGEROUS":
        danger = True
        reasons.append("GPT")
        logs.append("⚠️ GPT判定: DANGEROUS")
    elif gpt_result == "SUSPICIOUS":
        reasons.append("GPT")
        logs.append("⚠️ GPT判定: SUSPICIOUS")
    else:
        logs.append("🤖 GPT判定: SAFE")

    # 新規メンバー
    if is_new_member(member):
        danger = True
        reasons.append("NEW_MEMBER")
        logs.append("🆕 新規メンバー")

    # VCレイド判定
    if message.author.voice and message.author.voice.channel:
        channel_id = message.author.voice.channel.id
        if check_vc_raid(member, channel_id):
            danger = True
            reasons.append("VC_RAID")
            logs.append("🎵 VCレイド検出")

    # 削除・役職除去
    if danger:
        try:
            await message.delete()
        except Exception:
            pass
        await strip_roles(member)

    # 最終結果Embed送信
    embed = build_final_embed(vt_results, gpt_result, reasons, logs)
    if progress_msg:
        try:
            await progress_msg.edit(embed=embed)
        except Exception:
            await message.channel.send(embed=embed)
    else:
        await message.channel.send(embed=embed)

    logger.info("[SECURITY] SAFE" if not danger else "[SECURITY] DANGER")
