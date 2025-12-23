import asyncio
import hashlib
import logging
import time
import os
import re
from typing import List, Dict, Tuple, Optional

import aiohttp
import discord
import vt

from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY
from services.settings_store import get_trusted_user_ids, get_bypass_role_ids

# =========================
# 設定
# =========================
NEW_MEMBER_THRESHOLD_DAYS = 7
MAX_LINKS = 5
SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15
VT_CACHE_TTL = 60 * 60 * 6

VC_RAID_WINDOW_SEC = 20
VC_RAID_SIMILAR_PREFIX = 4
VC_RAID_THRESHOLD = 5

# =========================
# 内部キャッシュ
# =========================
_vt_cache: Dict[str, Dict] = {}
_user_message_times: Dict[int, List[float]] = {}
_vc_join_history: Dict[int, List[Tuple[float, str, int]]] = {}

# =========================
# 正規表現
# =========================
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
UNICODE_TRICK_REGEX = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# =========================
# ロガー
# =========================
logger = logging.getLogger("security_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = True

# =========================
# ユーティリティ
# =========================
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

async def _strip_roles(member: discord.Member) -> Tuple[bool, str]:
    try:
        roles = [r for r in member.roles if not r.is_default()]
        if not roles:
            return True, "no_roles"

        await member.remove_roles(
            *roles,
            reason="セキュリティ違反: 危険コンテンツ検出"
        )
        return True, "removed"

    except discord.Forbidden:
        return False, "forbidden"
    except Exception as e:
        logger.error("[SECURITY] strip roles failed: %s", e)
        return False, str(e)

# =========================
# Content-Type 判定
# =========================
async def fetch_content_type(
    session: aiohttp.ClientSession,
    url: str,
) -> str:
    try:
        async with session.head(
            url,
            allow_redirects=True,
            timeout=10
        ) as r:
            if r.status < 400:
                return r.headers.get("Content-Type", "")
    except Exception:
        pass

    try:
        async with session.get(
            url,
            allow_redirects=True,
            timeout=10
        ) as r:
            return r.headers.get("Content-Type", "")
    except Exception:
        return ""

def is_file_content_type(content_type: str) -> bool:
    if not content_type:
        return False

    ct = content_type.lower()
    if ct.startswith("application/"):
        return True
    if ct == "binary/octet-stream":
        return True

    return False

# =========================
# VirusTotal URL チェック（修正版）
# =========================
async def vt_check_url(url: str) -> Dict:
    key = hash_text(url)
    now = time.time()

    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "malicious": 0, "suspicious": 0}

    try:
        def sync_scan():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                logger.info(f"[VT] URL scan: {url}")
                analysis = client.scan_url(
                    url,
                    wait_for_completion=True
                )
                stats = analysis.last_analysis_stats
                return {
                    "status": "ok",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

        result = await asyncio.to_thread(sync_scan)
        _vt_cache[key] = {"time": now, "data": result}
        return result

    except Exception as e:
        logger.error(f"[VT] URL scan exception: {e}")
        return {
            "status": "error",
            "reason": str(e),
            "malicious": 0,
            "suspicious": 0,
        }

# =========================
# VirusTotal FILE チェック（修正版）
# =========================
async def vt_check_file_from_content(content: bytes) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "malicious": 0, "suspicious": 0}

    tmp_path: Optional[str] = None

    try:
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        def sync_scan():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                with open(tmp_path, "rb") as f:
                    analysis = client.scan_file(
                        f,
                        wait_for_completion=True
                    )
                stats = analysis.last_analysis_stats
                return {
                    "status": "ok",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

        return await asyncio.to_thread(sync_scan)

    except Exception as e:
        logger.error(f"[VT] File scan exception: {e}")
        return {
            "status": "error",
            "reason": str(e),
            "malicious": 0,
            "suspicious": 0,
        }

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

# =========================
# VT 自動振り分け
# =========================
async def vt_scan_target(
    session: aiohttp.ClientSession,
    url: str,
) -> Dict:
    content_type = await fetch_content_type(session, url)
    logger.info(f"[VT] Content-Type {url} -> {content_type}")

    if is_file_content_type(content_type):
        try:
            async with session.get(url, timeout=20) as r:
                file_bytes = await r.read()
            return await vt_check_file_from_content(file_bytes)
        except Exception as e:
            logger.error(f"[VT] File fetch error: {e}")
            return {
                "status": "error",
                "reason": str(e),
                "malicious": 0,
                "suspicious": 0,
            }

    return await vt_check_url(url)

# =========================
# GPT 補助判定
# =========================
async def gpt_assess(text: str, vt_results: List[Dict]) -> str:
    for vt_res in vt_results:
        if vt_res.get("malicious", 0) > 0 or vt_res.get("suspicious", 0) > 0:
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
            {
                "role": "user",
                "content": (
                    "以下の投稿が危険か判定してください。\n"
                    "SAFE / SUSPICIOUS / DANGEROUS のいずれか一語で答えてください。\n\n"
                    f"{text}"
                ),
            },
        ],
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            ) as r:
                data = await r.json()
                reply = data["choices"][0]["message"]["content"].upper()
        except Exception as e:
            logger.error(f"[GPT] Exception: {e}")
            return "SUSPICIOUS"

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply:
        return "SUSPICIOUS"
    return "SAFE"

# =========================
# メイン処理
# =========================
async def handle_security_for_message(
    bot: discord.Client,
    message: discord.Message,
):
    if message.author.bot or message.guild is None:
        return

    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments or []
    member = message.author

    bypassed, bypass_reason = is_security_bypassed(member)
    if bypassed:
        logger.info("[SECURITY] bypassed: %s (%s)", member, bypass_reason)
        return

    targets = links + [a.url for a in attachments]
    target_list = "\n".join(links + [a.filename for a in attachments])

    try:
        wait_msg = await message.channel.send(
            "🔍 **セキュリティ検査中**\n"
            "以下のリンク・ファイルを確認しています。\n"
            "**完了までクリック・ダウンロードしないでください**\n"
            f"{target_list or '(対象なし)'}"
        )
    except Exception:
        wait_msg = None

    danger = False
    reasons: List[str] = []
    vt_results: List[Dict] = []

    if is_spam(member.id):
        danger = True
        reasons.append("スパム行為")

    if len(links) >= MAX_LINKS:
        danger = True
        reasons.append("過剰リンク")

    if UNICODE_TRICK_REGEX.search(content):
        reasons.append("不可視Unicode検出")

    async with aiohttp.ClientSession() as session:
        for url in targets:
            vt_res = await vt_scan_target(session, url)
            vt_results.append(vt_res)

            if vt_res.get("malicious", 0) > 0 or vt_res.get("suspicious", 0) > 0:
                danger = True
                reasons.append(f"VT検出 ({url})")
            elif vt_res.get("status") == "error":
                reasons.append("VTエラー")

    gpt_result = await gpt_assess(content, vt_results)
    if gpt_result == "DANGEROUS":
        danger = True
        reasons.append("GPT危険判定")
    elif gpt_result == "SUSPICIOUS":
        reasons.append("GPT要注意")

    if is_new_member(member):
        danger = True
        reasons.append("新規参加者による投稿")

    try:
        from services.logging_service import log_action
    except Exception:
        log_action = None

    async def _log(level: str, title: str, fields: Dict[str, str]):
        if log_action is None:
            return
        await log_action(
            bot,
            message.guild.id,
            level,
            title,
            user=member,
            fields=fields,
        )

    if danger:
        try:
            await message.delete()
        except Exception:
            pass

        if wait_msg:
            await wait_msg.edit(
                content=(
                    "🚨 **危険なコンテンツを検出しました**\n"
                    "セキュリティ上の理由により削除されました。"
                )
            )

        stripped, strip_reason = await _strip_roles(member)

        await _log(
            "ERROR",
            "危険コンテンツをブロック",
            {
                "理由": " / ".join(reasons),
                "検査対象": target_list or "(なし)",
                "VT結果": str(vt_results),
                "GPT判定": gpt_result,
                "ロール剥奪": strip_reason,
            },
        )

        logger.info("[SECURITY] BLOCKED: %s", reasons)

    else:
        if wait_msg:
            await wait_msg.edit(
                content="✅ **セキュリティ検査完了: 問題なし**"
            )

        await _log(
            "INFO",
            "セキュリティ検査：安全",
            {
                "検査対象": target_list or "(なし)",
                "VT結果": str(vt_results),
                "GPT判定": gpt_result,
            },
        )

        logger.info("[SECURITY] SAFE")
