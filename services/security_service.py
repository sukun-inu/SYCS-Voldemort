import asyncio
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional, Union, TypedDict

import aiohttp
import discord
import unicodedata

from config import OPENAI_API_KEY
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
# メッセージレート監視用: { (guild_id, user_id): deque[timestamps_sec] }
_message_timestamps: Dict[Tuple[int, int], Deque[float]] = defaultdict(lambda: deque(maxlen=10))

# VCレイド検知用: { (guild_id, channel_id): deque[(joined_at, member_name)] }
_voice_joins: Dict[Tuple[int, int], Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=50))

# レートリミット閾値
MAX_MESSAGES_PER_SEC = 2  # 1秒間に3件以上
VOICE_SIMILAR_JOIN_THRESHOLD = 3  # 似た名前のユーザーが5人以上
VOICE_JOIN_WINDOW_SEC = 20  # 何秒間の窓で見るか

# Unicode 的に怪しいとみなす閾値
MAX_MESSAGE_LENGTH_SUSPICIOUS = 4000
MAX_REPEATED_CHAR_RUN = 100
MAX_WEIRD_CHAR_COUNT = 16
MAX_WEIRD_CHAR_RATIO = 0.15  # 全体の15%を超えると怪しい

# -------------------------------
# メッセージレート監視
# -------------------------------
def register_message_rate(guild_id: int, user_id: int) -> bool:
    """メッセージレートを記録し、スパム閾値を超えたかどうかを返す。"""
    now = time.time()
    key = (guild_id, user_id)
    dq = _message_timestamps[key]
    dq.append(now)
    # 1秒より前のものを削除
    while dq and now - dq[0] > 1.0:
        dq.popleft()
    return len(dq) >= MAX_MESSAGES_PER_SEC

# -------------------------------
# 名前類似度
# -------------------------------
def _name_similarity(a: str, b: str) -> float:
    """非常に簡易的な名前類似度（共通プレフィックス長 / 長い方の長さ）。"""
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
    """VC参加イベントを記録し、短時間に似た名前が5人以上かどうかを返す。"""
    now = time.time()
    key = (guild_id, channel_id)
    dq = _voice_joins[key]
    dq.append((now, member_name))

    # 古いものを消す
    while dq and now - dq[0][0] > VOICE_JOIN_WINDOW_SEC:
        dq.popleft()

    # 類似名のカウント
    similar_count = 0
    for _, name in dq:
        if _name_similarity(member_name, name) >= 0.7:
            similar_count += 1
    return similar_count >= VOICE_SIMILAR_JOIN_THRESHOLD

# -------------------------------
# GPTによるメッセージ判定
# -------------------------------
async def moderate_message_content(
    content: str,
    joined_at: Optional[discord.utils.snowflake_time] = None,
) -> ModerationResult:
    """メッセージ内容をGPTに投げて安全性を判定してもらう。"""
    system_prompt = (
        "貴様はDiscordサーバーのセキュリティ監査役だ。"
        "ユーザーの投稿内容が危険かどうか(フィッシング、マルウェアリンク、詐欺、荒らし、スパム等)を判定せよ。"
        "出力は必ず次のJSON一行のみとする: "
        "{""danger"": ""true"" または ""false"", ""reason"": ""理由"", ""category"": ""カテゴリ""}"
    )

    joined_info = ""
    if joined_at is not None:
        joined_info = f"\nサーバー参加日時(UTC): {joined_at.isoformat()}"

    user_prompt = (
        "以下のメッセージが安全かどうか判定せよ。\n"
        "危険な場合はdanger=trueとし、安全ならfalseとする。\n"
        f"メッセージ本文:\n{content}\n"
        f"{joined_info}"
    )

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }
    data = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        # "temperature": 0,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=data) as resp:
                j = await resp.json()
                message = j["choices"][0]["message"]["content"]
    except Exception:
        # 解析に失敗した場合は安全側に倒す
        return {"danger": False, "reason": "moderation_error", "category": "error"}

    message = message.strip()
    result: Dict[str, Union[str, bool]] = {"danger": False, "reason": "", "category": ""}

    try:
        import json as _json
        result.update(_json.loads(message))
    except Exception:
        result["danger"] = False
        result["reason"] = "parse_error"
        result["category"] = "error"

    # --- danger を必ず bool に正規化 ---
    danger_raw = result.get("danger", False)
    if isinstance(danger_raw, str):
        result["danger"] = danger_raw.strip().lower() == "true"
    else:
        result["danger"] = bool(danger_raw)

    return result  # type: ignore

# -------------------------------
# 信頼済み判定
# -------------------------------
def _is_trusted_member(guild_id: int, member_id: int) -> bool:
    trusted = set(get_trusted_user_ids(guild_id))
    return member_id in trusted

def _has_bypass_role(guild: discord.Guild, member: discord.Member) -> bool:
    bypass_ids = set(get_bypass_role_ids(guild.id))
    if not bypass_ids:
        return False
    return any(r.id in bypass_ids for r in member.roles)

# -------------------------------
# Unicode異常判定
# -------------------------------
def is_suspicious_unicode(text: str) -> tuple[bool, str]:
    if not text:
        return False, ""

    if len(text) >= MAX_MESSAGE_LENGTH_SUSPICIOUS:
        longest_run = 0
        current_run = 1
        prev_char = None
        for ch in text:
            if ch == prev_char:
                current_run += 1
            else:
                longest_run = max(longest_run, current_run)
                current_run = 1
                prev_char = ch
        longest_run = max(longest_run, current_run)
        if longest_run >= MAX_REPEATED_CHAR_RUN:
            return True, "極端に長いメッセージと同一文字の大量連続"

    dangerous_codepoints = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202A, 0x202B, 0x202D, 0x202E, 0x202C}

    weird_count = 0
    for ch in text:
        cp = ord(ch)
        cat = unicodedata.category(ch)
        if cp in dangerous_codepoints or cat.startswith("C"):
            weird_count += 1

    if weird_count >= MAX_WEIRD_CHAR_COUNT and weird_count / max(len(text), 1) >= MAX_WEIRD_CHAR_RATIO:
        return True, "制御文字やゼロ幅文字が異常に多い"

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
    from datetime import datetime, timezone, timedelta
    _JST = timezone(timedelta(hours=9))
    now_jst = datetime.now(_JST).strftime("%Y-%m-%d %H:%M:%S")

    before_roles = [r.name for r in member.roles if r.name != "@everyone"]
    roles_to_remove = [r for r in member.roles if r.name != "@everyone"]
    after_roles = []

    channel_name = getattr(channel, "name", str(channel))
    channel_mention = getattr(channel, "mention", channel_name)
    executor = bot.user.name if hasattr(bot, "user") and bot.user else "Bot"
    guild_name = guild.name if hasattr(guild, "name") else str(guild.id)
    guild_id = guild.id
    joined_at = member.joined_at.astimezone(_JST).strftime("%Y-%m-%d %H:%M:%S") if member.joined_at else "(不明)"
    created_at = member.created_at.astimezone(_JST).strftime("%Y-%m-%d %H:%M:%S") if hasattr(member, "created_at") else "(不明)"

    danger_detail = reason

    if roles_to_remove:
        try:
            await member.remove_roles(*roles_to_remove, reason=f"Security action: {reason}")
            after_roles = [r.name for r in member.roles if r.name != "@everyone"]
        except Exception as e:
            await log_action(
                bot,
                guild.id,
                "ERROR",
                "ロール剥奪中にエラー",
                user=member,
                fields={
                    "対象ユーザー": f"{member.mention}（ID: {member.id})",
                    "実行者": executor,
                    "対象チャンネル": channel_mention,
                    "サーバー": f"{guild_name}（ID: {guild_id})",
                    "参加日時": joined_at,
                    "アカウント作成日時": created_at,
                    "剥奪前ロール": ", ".join(before_roles) if before_roles else "(なし)",
                    "剥奪後ロール": ", ".join(after_roles) if after_roles else "(なし)",
                    "エラー": str(e),
                    "剥奪理由": reason,
                    "危険内容": danger_detail,
                    "実行時刻": now_jst,
                },
                embed_color=discord.Color.red(),
            )

    await log_action(
        bot,
        guild.id,
        "ERROR",
        "危険ユーザー検出。ロール剥奪を実行",
        user=member,
        fields={
            "対象ユーザー": f"{member.mention}（ID: {member.id})",
            "実行者": executor,
            "対象チャンネル": channel_mention,
            "サーバー": f"{guild_name}（ID: {guild_id})",
            "参加日時": joined_at,
            "アカウント作成日時": created_at,
            "剥奪前ロール": ", ".join(before_roles) if before_roles else "(なし)",
            "剥奪後ロール": ", ".join(after_roles) if after_roles else "(なし)",
            "理由": reason,
            "危険内容": danger_detail,
            "実行時刻": now_jst,
        },
        embed_color=discord.Color.red(),
    )

    try:
        warning = (
            f"⚠️ {member.mention} による危険なコンテンツ/リンクが検出された。\n"
            "絶対にリンクや添付ファイルを開かないように。サーバー管理者は状況を確認せよ。"
        )
        await channel.send(warning)
    except Exception:
        pass

# -------------------------------
# メッセージ単体のセキュリティ処理
# -------------------------------
async def handle_security_for_message(message: discord.Message, bot: discord.Client) -> None:
    if message.guild is None or not isinstance(message.author, discord.Member):
        return

    guild = message.guild
    member: discord.Member = message.author

    if _is_trusted_member(guild.id, member.id) or _has_bypass_role(guild, member):
        return

    is_spam_rate = register_message_rate(guild.id, member.id)
    suspicious_unicode, unicode_reason = is_suspicious_unicode(message.content or "")
    joined_at = getattr(member, "joined_at", None)
    moderation = await moderate_message_content(message.content or "", joined_at)
    if not isinstance(moderation, dict):
        moderation = {"danger": False, "reason": "moderation_error", "category": "error"}

    is_danger: bool = moderation["danger"]

    if is_danger or is_spam_rate or suspicious_unicode:
        reason_parts = []
        if is_danger:
            reason_parts.append(f"GPT判定: {moderation.get('category', '')}: {moderation.get('reason', '')}")
        if is_spam_rate:
            reason_parts.append("高頻度メッセージ")
        if suspicious_unicode:
            reason_parts.append(f"Unicode異常: {unicode_reason}")
        reason = " | ".join(reason_parts) or "不明"

        await strip_all_roles_and_warn(bot, guild, member, message.channel, reason)

# -------------------------------
# VC参加時のセキュリティ処理
# -------------------------------
async def handle_security_for_voice_join(
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
    bot: discord.Client,
) -> None:
    guild = member.guild
    if guild is None:
        return

    if _is_trusted_member(guild.id, member.id) or _has_bypass_role(guild, member):
        return

    before_ch = before.channel
    after_ch = after.channel

    if before_ch is None and after_ch is not None:
        suspicious = register_voice_join(guild.id, after_ch.id, member.display_name)
        if suspicious:
            await strip_all_roles_and_warn(
                bot,
                guild,
                member,
                after_ch,
                "VCレイドと判断 (短時間に似た名前のユーザーが多数参加)",
            )
