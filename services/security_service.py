# services/security_service.py
import asyncio
import hashlib
import logging
import time
from typing import List, Dict, Tuple, Optional

import aiohttp
import discord
from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY
from services.settings_store import get_trusted_user_ids, get_bypass_role_ids
import re
import vt

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
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
UNICODE_TRICK_REGEX = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# =========================
# ロガー
logger = logging.getLogger("security_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = True
logger.disabled = False

# =========================
# ユーティリティ
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

def _normalize_name(name: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9ぁ-んァ-ヴー一-龥]", "", name).lower()
    return base[:VC_RAID_SIMILAR_PREFIX] if base else name.lower()[:VC_RAID_SIMILAR_PREFIX]

async def _strip_roles(member: discord.Member) -> Tuple[bool, str]:
    try:
        roles = [r for r in member.roles if not r.is_default()]
        if not roles:
            return True, "no_roles"
        await member.remove_roles(*roles, reason="セキュリティ違反: 危険コンテンツ検出")
        return True, "removed"
    except discord.Forbidden:
        return False, "forbidden"
    except Exception as e:
        logger.error("[SECURITY] strip roles failed: %s", e)
        return False, str(e)

# =========================
# VirusTotal チェック
# =========================
async def vt_check_url(url: str) -> Dict:
    key = hash_text(url)
    now = time.time()
    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]
    if not VIRUSTOTAL_API_KEY:
        logger.warning("[VT] API key missing. Skipping VT scan.")
        return {"status": "skip", "reason": "no_api_key", "malicious": 0, "suspicious": 0}

    try:
        def sync_scan():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                logger.info(f"[VT] Sending URL to VT: {url}")
                analysis = client.scan_url(url, wait_for_completion=True)
                stats = getattr(analysis, "last_analysis_stats", {"malicious": 0, "suspicious": 0})
                return {"status": "ok", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        result = await asyncio.to_thread(sync_scan)
        _vt_cache[key] = {"time": now, "data": result}
        return result
    except Exception as e:
        logger.error(f"[VT] Exception: {e}")
        return {"status": "error", "reason": str(e), "malicious": 0, "suspicious": 0}

async def vt_check_file_from_content(content: bytes) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        logger.warning("[VT] API key missing. Skipping VT scan.")
        return {"status": "skip", "reason": "no_api_key", "malicious": 0, "suspicious": 0}
    import tempfile
    try:
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(content)
            tmp.flush()
            def sync_scan():
                with vt.Client(VIRUSTOTAL_API_KEY) as client:
                    analysis = client.scan_file(tmp.name, wait_for_completion=True)
                    stats = getattr(analysis, "last_analysis_stats", {"malicious": 0, "suspicious": 0})
                    return {"status": "ok", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
            result = await asyncio.to_thread(sync_scan)
        return result
    except Exception as e:
        logger.error(f"[VT] File scan exception: {e}")
        return {"status": "error", "reason": str(e), "malicious": 0, "suspicious": 0}

# =========================
# GPT 補助判定
# =========================
async def gpt_assess(text: str, vt_results: List[Dict]) -> str:
    for vt in vt_results:
        if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
            return "DANGEROUS"

    if not OPENAI_API_KEY:
        logger.warning("[GPT] OPENAI_API_KEY missing. Skipping GPT assess.")
        return "SAFE"

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": "You are a security moderation AI."},
            {"role": "user", "content": f"以下の投稿が危険か判定してください。\nSAFE / SUSPICIOUS / DANGEROUS のいずれか一語で答えてください。\n\n{text}"}
        ],
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload
            ) as r:
                resp_json = await r.json()
                logger.info(f"[GPT] API call response: {r.status} {resp_json}")
                if r.status != 200:
                    return "SUSPICIOUS"
                reply = resp_json["choices"][0]["message"]["content"].upper()
        except Exception as e:
            logger.error(f"[GPT] Exception: {e}")
            return "SUSPICIOUS"

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply:
        return "SUSPICIOUS"
    return "SAFE"

# =========================
# メイン処理（Content-Type 判定 + 削除/通知/ロール剥奪/ログ統合版）
# =========================
async def handle_security_for_message(bot: discord.Client, message: discord.Message):
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

    # 🔍 検査中メッセージ
    target_list = "\n".join(links + [a.filename for a in attachments])
    try:
        wait_msg = await message.channel.send(
            "🔍 **セキュリティ検査中**\n"
            f"以下のファイル・リンクを確認しています。\n**検査が完了するまでクリック・ダウンロードしないでください**\n"
            f"{target_list or '(対象取得失敗)'}"
        )
    except Exception:
        wait_msg = None

    reasons: List[str] = []
    danger = False
    vt_results = []

    # 荒らし判定
    if is_spam(member.id):
        danger = True
        reasons.append("スパム行為")
    if len(links) >= MAX_LINKS:
        danger = True
        reasons.append("過剰リンク")
    if UNICODE_TRICK_REGEX.search(content):
        reasons.append("不可視Unicode検出")

    # Content-Type 判定 & VT スキャン
    scan_targets = links + [a.url for a in attachments]
    async with aiohttp.ClientSession() as session:
        for url in scan_targets:
            try:
                async with session.head(url, timeout=10) as resp:
                    ctype = resp.headers.get("Content-Type", "")
            except Exception:
                ctype = ""

            if ctype.startswith("application/"):
                try:
                    async with session.get(url) as resp:
                        file_content = await resp.read()
                    vt = await vt_check_file_from_content(file_content)
                except Exception as e:
                    vt = {"status": "error", "reason": str(e), "malicious": 0, "suspicious": 0}
            else:
                vt = await vt_check_url(url)

            vt_results.append(vt)
            if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
                danger = True
                reasons.append(f"VT検出 ({url})")
            elif vt.get("status") == "error":
                reasons.append("VTエラー")

    # GPT 判定
    gpt = await gpt_assess(content, vt_results)
    if gpt == "DANGEROUS":
        danger = True
        reasons.append("GPT危険判定")
    elif gpt == "SUSPICIOUS":
        reasons.append("GPT要注意")

    if is_new_member(member):
        danger = True
        reasons.append("新規参加者による投稿")

    # ログ関数
    try:
        from services.logging_service import log_action
    except Exception:
        log_action = None  # type: ignore

    async def _log(level: str, title: str, extra_fields: Optional[Dict[str, str]] = None):
        if log_action is None:
            return
        fields = {
            "チャンネル": message.channel.mention,
            "本文プレビュー": (content[:1800] + "...") if len(content) > 1800 else content or "(なし)",
        }
        if extra_fields:
            fields.update(extra_fields)
        await log_action(
            bot,
            message.guild.id,
            level,
            title,
            user=member,
            fields=fields,
        )

    # 結果処理
    if danger:
        try:
            await message.delete()
        except discord.Forbidden:
            logger.error("[SECURITY] Delete failed: %s", message.id)
        except Exception as e:
            logger.error("[SECURITY] Delete failed (other): %s", e)

        if wait_msg:
            try:
                await wait_msg.edit(
                    content="🚨 **危険なコンテンツを検出しました**\n"
                            "セキュリティ上の理由により隔離・削除されました。\n"
                            "ファイルのダウンロードは推奨されません。"
                )
            except Exception as e:
                logger.error("[SECURITY] failed to edit wait message: %s", e)
        else:
            try:
                wait_msg = await message.channel.send(
                    "🚨 **危険なコンテンツを検出しました**\n"
                    "セキュリティ上の理由により隔離・削除されました。\n"
                    "ファイルのダウンロードは推奨されません。"
                )
            except Exception as e:
                logger.error("[SECURITY] failed to send danger message: %s", e)

        ban_reason = " / ".join(reasons) or "危険なコンテンツ"
        stripped, reason = await _strip_roles(member)
        if not stripped:
            logger.error("[SECURITY] Role strip failed: %s (%s)", member, reason)

        await _log(
            "ERROR",
            "危険なコンテンツをブロック（ロール剥奪）",
            {
                "理由": ban_reason,
                "検査対象": target_list or "(なし)",
                "VT結果": str(vt_results),
                "GPT判定": gpt,
                "ロール剥奪結果": reason if not stripped else "success",
            },
        )
        logger.info("[SECURITY] BLOCKED: %s", reasons)
    else:
        if wait_msg:
            try:
                await wait_msg.edit(
                    content="✅ **セキュリティ検査完了: 問題なし**\n"
                            "ご利用を続けてください。"
                )
            except Exception as e:
                logger.error("[SECURITY] failed to edit safe message: %s", e)
        else:
            try:
                await message.channel.send("✅ **セキュリティ検査完了: 問題なし**")
            except Exception as e:
                logger.error("[SECURITY] failed to send safe message: %s", e)

        await _log(
            "INFO",
            "セキュリティ検査：安全",
            {
                "検査対象": target_list or "(なし)",
                "VT結果": str(vt_results),
                "GPT判定": gpt,
            },
        )
        logger.info("[SECURITY] SAFE")
