# services/security_service.py
import asyncio
import hashlib
import logging
import time
from typing import List, Dict, Tuple, Optional

import aiohttp
import discord
from vt import AsyncClient
from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY
from services.settings_store import (
    get_trusted_user_ids,
    get_bypass_role_ids,
)

# =========================
# 設定
# =========================
NEW_MEMBER_THRESHOLD_DAYS = 7
MAX_LINKS = 5
SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15
VT_CACHE_TTL = 60 * 60 * 6  # 6時間
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
import re
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
logger.disabled = False

# =========================
# ユーティリティ
# =========================
def extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")


def is_new_member(member: discord.Member) -> bool:
    if not member.joined_at:
        return False
    return (discord.utils.utcnow() - member.joined_at).days < NEW_MEMBER_THRESHOLD_DAYS


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def is_spam(user_id: int) -> bool:
    now = time.time()
    history = _user_message_times.setdefault(user_id, [])
    history.append(now)
    history[:] = [t for t in history if now - t < SPAM_TIME_WINDOW]
    return len(history) >= SPAM_REPEAT_THRESHOLD


def is_security_bypassed(member: discord.Member) -> Tuple[bool, str]:
    """信頼済みユーザー・バイパスロール判定をまとめて行う。"""
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
    """@everyone 以外のロールを全て剥奪する。戻り値: (成功可否, 失敗理由)"""
    try:
        roles = [r for r in member.roles if r.is_default() is False]
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
# VirusTotal URL チェック (非同期 vt-py)
# =========================
async def vt_check_url(url: str) -> Dict:
    """VirusTotal で URL をスキャン（キャッシュ付き）。"""
    key = hash_text(url)
    now = time.time()
    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    if not VIRUSTOTAL_API_KEY:
        logger.warning("[VT] API key missing. Skipping VT scan.")
        return {"status": "skip", "reason": "no_api_key", "malicious": 0, "suspicious": 0}

    try:
        async with AsyncClient(VIRUSTOTAL_API_KEY) as client:
            logger.info(f"[VT] Sending URL to VT: {url}")
            analysis = await client.async_scan_url(url)
            # VT からの結果反映を待機（非同期）。失敗時は後続で例外へ。
            await asyncio.sleep(2)
            await analysis.async_update()
            stats = analysis.last_analysis_stats
            result = {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
            _vt_cache[key] = {"time": now, "data": result}
            return result
    except Exception as e:
        logger.error(f"[VT] Exception: {e}")
        return {"status": "error", "reason": str(e), "malicious": 0, "suspicious": 0}

# =========================
# GPT 補助判定
# =========================
async def gpt_assess(text: str, vt_results: List[Dict]) -> str:
    # VT 検出がある場合は即 DANGEROUS
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
# メイン処理
# =========================
async def handle_security_for_message(bot: discord.Client, message: discord.Message):
    """メッセージに含まれる URL/添付ファイルをスキャンして対処する。"""
    if message.author.bot or message.guild is None:
        return

    print("[SECURITY] entered handle_security_for_message", flush=True)

    # ログが無効化されている環境でも目視できるよう print を併用
    print(
        f"[SECURITY] recv message author={message.author} ch={getattr(message.channel, 'id', 'unknown')} "
        f"attachments={len(message.attachments or [])} links={len(extract_links(message.content or ''))}"
    , flush=True)
    logger.info(
        "[SECURITY] recv message: author=%s channel=%s attachments=%s links=%s",
        message.author,
        getattr(message.channel, "id", "unknown"),
        len(message.attachments or []),
        len(extract_links(message.content or "")),
    )

    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments or []
    member = message.author

    bypassed, bypass_reason = is_security_bypassed(member)
    if bypassed:
        print(f"[SECURITY] bypassed: {member} ({bypass_reason})", flush=True)
        logger.info("[SECURITY] bypassed: %s (%s)", member, bypass_reason)
        return

    logger.info(
        "[SECURITY] start scan member=%s links=%s files=%s",
        member,
        links,
        [a.filename for a in attachments],
    )

    if not links and not attachments:
        logger.info("[SECURITY] CLEAN(no url/attachment)")
        return

    # 🔍 検査中メッセージ
    target_list = "\n".join(links + [a.filename for a in attachments])
    try:
        wait_msg = await message.channel.send(
            "🔍 **セキュリティ検査中**\n"
            "以下のファイル・リンクを確認しています。\n"
            "**検査が完了するまでクリック・ダウンロードしないでください**\n"
            f"{target_list or '(対象取得失敗)'}"
        )
    except Exception as e:
        logger.error("[SECURITY] failed to send wait message: %s", e)
        wait_msg = None
    else:
        logger.info("[SECURITY] wait message sent: %s", getattr(wait_msg, "id", "unknown"))

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

    # URL VT検査（リンク＆添付URL両方）
    scan_targets = links + [a.url for a in attachments]
    for url in scan_targets:
        vt = await vt_check_url(url)
        vt_results.append(vt)
        if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
            danger = True
            reasons.append(f"VT検出 ({url})")
        elif vt.get("status") == "error":
            reasons.append("VTエラー")

    # GPT 補助判定
    gpt = await gpt_assess(content, vt_results)
    if gpt == "DANGEROUS":
        danger = True
        reasons.append("GPT危険判定")
    elif gpt == "SUSPICIOUS":
        reasons.append("GPT要注意")

    # 新規参加者補正
    if is_new_member(member):
        danger = True
        reasons.append("新規参加者による投稿")

    # Discord Embed ログ
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


async def handle_security_for_voice_join(
    bot: discord.Client,
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
):
    """VC 参加の簡易レイド検知。"""
    if member.bot or member.guild is None:
        return

    bypassed, _ = is_security_bypassed(member)
    if bypassed:
        return

    # Join detection: before None -> after channel
    if before.channel is not None or after.channel is None:
        return

    gid = member.guild.id
    now = time.time()
    name_key = _normalize_name(member.display_name or member.name)
    history = _vc_join_history.setdefault(gid, [])
    history.append((now, name_key, member.id))
    history[:] = [h for h in history if now - h[0] < VC_RAID_WINDOW_SEC]

    # 同一 prefix の人数を計測
    similar = [h for h in history if h[1] == name_key]
    if len(similar) < VC_RAID_THRESHOLD:
        return

    # レイドと判断
    try:
        from services.logging_service import log_action
    except Exception:
        log_action = None  # type: ignore

    warning = (
        "🚨 **ボイスレイドを検知**\n"
        f"{VC_RAID_WINDOW_SEC} 秒以内に似た名前の参加が {len(similar)} 件ありました。\n"
        "運営は確認してください。"
    )
    try:
        await after.channel.send(warning)
    except Exception:
        logger.warning("[SECURITY] Failed to send VC raid warning to channel.")

    if log_action:
        joiners = ", ".join(f"<@{mid}>" for _, _, mid in similar)
        await log_action(
            bot,
            gid,
            "ERROR",
            "VCレイド検知",
            user=member,
            fields={
                "チャンネル": after.channel.mention,
                "人数": str(len(similar)),
                "参加者": joiners,
            },
            embed_color=discord.Color.red(),
        )
