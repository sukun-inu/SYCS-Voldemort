# services/security_service.py
import re
import asyncio
import time
import hashlib
from typing import List, Dict
from urllib.parse import urlparse, urlunparse

import aiohttp
import discord
from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY

# =========================
# 設定
# =========================
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
_user_message_times: Dict[int, List[float]] = {}

# =========================
# 正規表現
# =========================
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
UNICODE_TRICK_REGEX = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

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

def normalize_discord_url(url: str) -> str:
    """
    Discord 添付 URL の余計なクエリを削除
    """
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=""))

# =========================
# VirusTotal
# =========================
async def vt_check(target: str) -> Dict:
    key = hash_text(target)
    now = time.time()
    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        try:
            print(f"[VT] Sending file URL to VT: {target}")
            # URL スキャンで送る
            data = {"url": target}
            async with session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=data,
            ) as r:
                resp_json = await r.json()
                print(f"[VT] URL submission response: {r.status} {resp_json}")
                if r.status != 200:
                    return {"status": "error"}
                analysis_id = resp_json["data"]["id"]

            # 少し待って分析結果を取得
            await asyncio.sleep(2)
            async with session.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            ) as r:
                resp_json = await r.json()
                print(f"[VT] Analysis fetch response: {r.status} {resp_json}")
                if r.status != 200:
                    return {"status": "error"}
                stats = resp_json["data"]["attributes"]["stats"]

            result = {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
            _vt_cache[key] = {"time": now, "data": result}
            return result
        except Exception as e:
            print(f"[VT] Exception: {e}")
            return {"status": "error"}

# =========================
# GPT 補助判定
# =========================
async def gpt_assess(text: str) -> str:
    if not text.strip():
        text = "(内容なし)"
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
                print(f"[GPT] API call response: {r.status} {resp_json}")
                if r.status != 200:
                    return "SUSPICIOUS"
                reply = resp_json["choices"][0]["message"]["content"].upper()
        except Exception as e:
            print(f"[GPT] Exception: {e}")
            return "SUSPICIOUS"

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply:
        return "SUSPICIOUS"
    return "SAFE"

# =========================
# メイン処理
# =========================
async def handle_security_for_message(message: discord.Message):
    if message.author.bot or message.guild is None:
        return

    content = message.content or ""
    links = extract_links(content)
    attachments = message.attachments or []
    member = message.author

    print("[SECURITY]", member, "links:", links, "files:", [a.filename for a in attachments])

    if not links and not attachments:
        print("[SECURITY] CLEAN")
        return

    # 🔍 検査中メッセージ
    attach_list = "\n".join([a.filename for a in attachments])
    wait_msg = await message.channel.send(
        "🔍 **セキュリティ検査中**\n"
        "以下のファイル・リンクを確認しています。\n"
        "**検査が完了するまでクリック・ダウンロードしないでください**\n"
        f"{attach_list}"
    )

    reasons = []
    danger = False

    # 荒らし判定
    if is_spam(member.id):
        danger = True
        reasons.append("スパム行為")
    if len(links) >= MAX_LINKS:
        danger = True
        reasons.append("過剰リンク")
    if UNICODE_TRICK_REGEX.search(content):
        reasons.append("不可視Unicode検出")

    # URL VT検査
    for url in links:
        vt = await vt_check(url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            danger = True
            reasons.append(f"VT検出 ({url})")

    # 添付ファイルも URL スキャン
    for a in attachments:
        normalized_url = normalize_discord_url(a.url)
        vt = await vt_check(normalized_url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            danger = True
            reasons.append(f"VT検出 ({a.filename})")

    # GPT補助判定
    if not danger:
        gpt = await gpt_assess(content)
        if gpt == "DANGEROUS":
            danger = True
            reasons.append("GPT危険判定")
        elif gpt == "SUSPICIOUS":
            reasons.append("GPT要注意")

    # 新規参加者補正
    if is_new_member(member):
        danger = True
        reasons.append("新規参加者による投稿")

    # 結果処理
    if danger:
        try:
            await message.delete()
        except discord.Forbidden:
            print("[SECURITY] Delete failed:", message.id)
        await wait_msg.edit(
            content="🚨 **危険なコンテンツを検出しました**\n"
                    "セキュリティ上の理由により隔離・削除されました。\n"
                    "ファイルのダウンロードは推奨されません。"
        )
        try:
            await member.ban(reason=" / ".join(reasons), delete_message_days=1)
        except discord.Forbidden:
            print("[SECURITY] Ban failed:", member)
        print("[SECURITY] BLOCKED:", reasons)
    else:
        await wait_msg.delete()
        print("[SECURITY] SAFE")
