import asyncio
import time
from typing import List, Dict

import discord
from vt import Client as VTClient
from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY
import aiohttp

# =========================
# 設定
# =========================
NEW_MEMBER_THRESHOLD_DAYS = 7
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
# ユーティリティ
# =========================
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

# =========================
# VirusTotal
# =========================
async def vt_check_url(url: str) -> Dict:
    """URLをVirusTotalに送信し、結果を返す"""
    key = url
    now = time.time()
    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    print(f"[VT] Sending URL to VT: {url}")
    try:
        async with VTClient(VIRUSTOTAL_API_KEY) as client:
            analysis = await client.url(url)
            stats = analysis.last_analysis_stats
            result = {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
            _vt_cache[key] = {"time": now, "data": result}
            print(f"[VT] VT result: {result}")
            return result
    except Exception as e:
        print(f"[VT] Exception: {e}")
        return {"status": "error"}

# =========================
# GPT 補助判定
# =========================
async def gpt_assess(text: str) -> str:
    import aiohttp

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": "You are a security moderation AI."},
            {"role": "user", "content": text}
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

    member = message.author
    content = message.content or ""
    attachments = message.attachments or []

    print("[SECURITY]", member, "files:", [a.filename for a in attachments])

    if not attachments:
        print("[SECURITY] CLEAN")
        return

    wait_msg = await message.channel.send(
        "🔍 **セキュリティ検査中**\n"
        "以下のファイルを確認しています。\n"
        "**検査が完了するまでクリック・ダウンロードしないでください**\n"
        + "\n".join([a.filename for a in attachments])
    )

    danger = False
    reasons = []

    # 荒らし判定
    if is_spam(member.id):
        danger = True
        reasons.append("スパム行為")
    if is_new_member(member):
        danger = True
        reasons.append("新規参加者による投稿")

    # VT URL 検査
    for a in attachments:
        vt = await vt_check_url(a.url)
        if vt.get("status") == "ok" and (vt["malicious"] > 0 or vt["suspicious"] > 0):
            danger = True
            reasons.append(f"VT検出 ({a.filename})")

    # GPT 補助判定
    if not danger:
        vt_summary = ", ".join([f"{a.filename}: {vt_check_url(a.url)}" for a in attachments])
        gpt_text = f"以下の投稿が危険か判定してください。\n投稿: {content}\nVT結果: {vt_summary}\nSAFE / SUSPICIOUS / DANGEROUS のいずれかで答えてください。"
        gpt = await gpt_assess(gpt_text)
        if gpt == "DANGEROUS":
            danger = True
            reasons.append("GPT危険判定")
        elif gpt == "SUSPICIOUS":
            reasons.append("GPT要注意")

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
