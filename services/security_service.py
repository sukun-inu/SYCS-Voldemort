# services/security_service.py
import re
import asyncio
import time
import hashlib
from typing import List, Dict

import aiohttp
import discord
from config import OPENAI_API_KEY, VIRUSTOTAL_API_KEY

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".lnk", ".iso", ".img"}
NEW_MEMBER_THRESHOLD_DAYS = 7
MAX_MENTIONS = 5
MAX_LINKS = 5
SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15
VT_CACHE_TTL = 60 * 60 * 6  # 6時間

_vt_cache: Dict[str, Dict] = {}
_user_message_times: Dict[int, List[float]] = {}

URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
UNICODE_TRICK_REGEX = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

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

# =========================
# VirusTotal チェック（非同期最適化）
# =========================
async def vt_check(target: str, is_file: bool = False) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        print("[VT] APIキー未設定")
        return {"status": "error"}

    key = hash_text(target)
    now = time.time()
    if key in _vt_cache and now - _vt_cache[key]["time"] < VT_CACHE_TTL:
        return _vt_cache[key]["data"]

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        try:
            if is_file:
                # ファイルを Discord から取得
                print(f"[VT] Downloading file: {target}")
                async with session.get(target) as r:
                    if r.status != 200:
                        print(f"[VT] File download failed ({r.status})")
                        return {"status": "error"}
                    file_bytes = await r.read()

                data = aiohttp.FormData()
                data.add_field("file", file_bytes, filename="upload")
                print(f"[VT] Uploading file to VT")
                async with session.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    data=data,
                ) as r:
                    if r.status != 200:
                        print(f"[VT] File submission failed ({r.status})")
                        return {"status": "error"}
                    analysis_id = (await r.json())["data"]["id"]

            else:
                print(f"[VT] Sending URL to VT: {target}")
                async with session.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": target},
                ) as r:
                    if r.status != 200:
                        print(f"[VT] URL submission failed ({r.status})")
                        return {"status": "error"}
                    analysis_id = (await r.json())["data"]["id"]

            # ===== 非同期ポーリング =====
            for _ in range(15):  # 最大 15 回ポーリング (~15秒)
                async with session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers) as r:
                    if r.status != 200:
                        await asyncio.sleep(1)
                        continue
                    data = await r.json()
                    status = data["data"]["attributes"]["status"]
                    if status == "completed":
                        stats = data["data"]["attributes"]["stats"]
                        break
                    await asyncio.sleep(1)
            else:
                print("[VT] Analysis timeout")
                return {"status": "error"}

        except Exception as e:
            print(f"[VT] Exception: {e}")
            return {"status": "error"}

    result = {"status": "ok", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    _vt_cache[key] = {"time": now, "data": result}
    return result

# =========================
# GPT 判定は同じ
# =========================
async def gpt_assess(text: str) -> str:
    if not OPENAI_API_KEY:
        print("[GPT] APIキー未設定")
        return "SUSPICIOUS"

    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "system", "content": "You are a security moderation AI."},
                     {"role": "user", "content": f"以下の投稿が危険か判定してください。SAFE / SUSPICIOUS / DANGEROUS のいずれか一語で答えてください。\n{text}"}],
        "temperature": 0,
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers, json=payload
            ) as r:
                if r.status != 200:
                    print(f"[GPT] API call failed ({r.status})")
                    return "SUSPICIOUS"
                reply = (await r.json())["choices"][0]["message"]["content"].upper()
        except Exception as e:
            print(f"[GPT] Exception: {e}")
            return "SUSPICIOUS"

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply:
        return "SUSPICIOUS"
    return "SAFE"

# =========================
# メイン処理（非同期タスクで VT 並列）
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

    # 検査中メッセージ
    attach_list = "\n".join([a.filename for a in attachments])
    wait_msg = await message.channel.send(
        "🔍 **セキュリティ検査中**\n"
        "以下のファイル・リンクを確認しています。\n"
        "**検査が完了するまでクリック・ダウンロードしないでください**。\n"
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

    # VT チェックを非同期タスクでまとめて実行
    tasks = []
    for url in links:
        tasks.append(vt_check(url, is_file=False))
    for att in attachments:
        if any(att.filename.lower().endswith(e) for e in DANGEROUS_EXTENSIONS):
            tasks.append(vt_check(att.url, is_file=True))

    vt_results = await asyncio.gather(*tasks)
    for res, obj in zip(vt_results, links + [a.filename for a in attachments if any(a.filename.lower().endswith(e) for e in DANGEROUS_EXTENSIONS)]):
        if res.get("status") == "ok" and (res["malicious"] > 0 or res["suspicious"] > 0):
            danger = True
            reasons.append(f"VT検出 ({obj})")

    # GPT 判定
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
        return

    # SAFE の場合
    await wait_msg.delete()
    print("[SECURITY] SAFE")
