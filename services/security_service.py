import datetime
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import aiohttp
import discord

from services.content_moderation import gpt_assess
from services.logging_service import log_action, send_log_embed
from services.raid_detection import check_vc_raid
from services.settings_store import get_bypass_role_ids, get_response_channel_id, get_trusted_user_ids
from services.spam_detection import SPAM_TIME_WINDOW, check_spam
from services.virustotal_service import MALICIOUS_THRESHOLD, vt_scan_target

NEW_MEMBER_THRESHOLD_DAYS = 7
MAX_LINKS = 5

URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
UNICODE_TRICK_REGEX = re.compile(r"[‪-‮⁦-⁩]")

logger = logging.getLogger(__name__)


# ==================================================
# ユーティリティ
# ==================================================
def now_jst() -> str:
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(url: str) -> str:
    if not url:
        return ""
    u = url.strip()
    if u.startswith("<") and u.endswith(">"):
        u = u[1:-1].strip()
    u = u.strip("<>")
    u = u.rstrip(".,!?;:")
    return u


def extract_links(text: str) -> List[str]:
    raw = URL_REGEX.findall(text or "")
    links: List[str] = []
    seen: set[str] = set()
    for u in raw:
        u = normalize_url(u)
        if not u or u in seen:
            continue
        seen.add(u)
        links.append(u)
    return links


def is_new_member(member: discord.Member) -> bool:
    if not member.joined_at:
        return False
    return (discord.utils.utcnow() - member.joined_at).days < NEW_MEMBER_THRESHOLD_DAYS


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
# Embedユーティリティ
# ==================================================
SAFE_ICON = "[SAFE]"
WARN_ICON = "[WARN]"
ALERT_ICON = "[ALERT]"
REASON_ICONS = {
    "SPAM": "[SPAM]",
    "TOO_MANY_LINKS": "[LINKS]",
    "UNICODE_TRICK": "[UNICODE]",
    "NEW_MEMBER": "[NEW]",
    "GPT": "[GPT]",
    "VT_DANGEROUS": "[VT]",
    "VT_SUSPICIOUS": "[VT]",
    "VC_RAID": "[VC]",
}


def build_progress_bar(current: int, total: int, length: int = 10) -> str:
    filled_len = int(length * current / total)
    bar = "#" * filled_len + "-" * (length - filled_len)
    return f"[{bar}] {current}/{total}"


def vt_icon(malicious: int, suspicious: int, status: Optional[str] = None) -> str:
    if status in ("error", "skip"):
        return WARN_ICON
    if malicious > 0:
        return ALERT_ICON
    if suspicious > 0:
        return WARN_ICON
    return SAFE_ICON


def gpt_icon(result: str) -> str:
    if result == "DANGEROUS":
        return ALERT_ICON
    if result == "SUSPICIOUS":
        return WARN_ICON
    return SAFE_ICON


def reason_icon(reason: str) -> str:
    base = reason.split(":")[0]
    return REASON_ICONS.get(base, "[INFO]")


def build_final_embed(
    vt_results: List[Dict[str, Any]],
    gpt_result: str,
    reasons: List[str],
    logs: List[str],
) -> discord.Embed:
    is_vt_dangerous = "VT_DANGEROUS" in reasons
    is_vc_raid = "VC_RAID" in reasons
    is_spam = "SPAM" in reasons
    is_vt_suspicious = "VT_SUSPICIOUS" in reasons

    if is_vt_dangerous or gpt_result == "DANGEROUS" or is_vc_raid:
        color = discord.Color.red()
        title = "危険な投稿を検出"
    elif is_vt_suspicious or gpt_result == "SUSPICIOUS" or is_spam:
        color = discord.Color.orange()
        title = "注意：スパム/不審な投稿の可能性"
    else:
        color = discord.Color.green()
        title = "検査完了：問題なし"

    embed = discord.Embed(title=title, description="\n".join(logs), color=color)

    for idx, r in enumerate(vt_results, 1):
        icon = vt_icon(r.get("malicious", 0), r.get("suspicious", 0), r.get("status"))
        embed.add_field(
            name=f"{icon} ターゲット {idx} ({r.get('type')})",
            value=f"Status: `{r.get('status')}` | Malicious: `{r.get('malicious')}` | Suspicious: `{r.get('suspicious')}`",
            inline=False,
        )

    embed.add_field(name=f"{gpt_icon(gpt_result)} GPT判定", value=f"結果: `{gpt_result}`", inline=False)

    if reasons:
        icons = " / ".join([reason_icon(r) + r for r in reasons])
        embed.add_field(name="判定理由", value=icons, inline=False)

    embed.set_footer(text=f"実行時間: {now_jst()}")
    return embed


# ==================================================
# メッセージセキュリティの各ステップ
# ==================================================
def _check_content_flags(
    member: discord.Member,
    content: str,
    links: List[str],
) -> Tuple[List[str], List[str], int, float]:
    """(reason_flags, logs, spam_count, min_interval) を返す。"""
    reason_flags: List[str] = []
    logs: List[str] = []

    spam_detected, spam_count, min_interval = check_spam(member.guild.id, member.id)
    if spam_detected:
        reason_flags.append("SPAM")
        logs.append(f"スパム検出（{spam_count}回/{SPAM_TIME_WINDOW}秒、最短間隔{min_interval:.1f}秒）")

    if len(links) >= MAX_LINKS:
        reason_flags.append("TOO_MANY_LINKS")
        logs.append("リンク数過多")

    if UNICODE_TRICK_REGEX.search(content):
        reason_flags.append("UNICODE_TRICK")
        logs.append("ユニコードトリック検出")

    return reason_flags, logs, spam_count, min_interval


async def _run_vt_scans(
    bot: discord.Client,
    guild_id: int,
    links: List[str],
    attachments: Sequence,
    logs: List[str],
) -> Tuple[List[Dict[str, Any]], Optional[discord.Message], List[str], bool]:
    vt_results: List[Dict[str, Any]] = []
    vt_malicious_max = 0
    vt_suspicious_max = 0
    extra_flags: List[str] = []
    danger = False
    progress_msg: Optional[discord.Message] = None

    if not links and not attachments:
        return vt_results, progress_msg, extra_flags, danger

    progress_msg = await send_log_embed(
        bot,
        guild_id,
        "INFO",
        embed=discord.Embed(title="セキュリティ検査中", description="VirusTotal解析中…", color=discord.Color.blurple()),
    )
    timeout = aiohttp.ClientTimeout(total=25)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        targets = links + [a.url for a in attachments]
        for idx, url in enumerate(targets, 1):
            res = await vt_scan_target(session, url)
            vt_results.append(res)
            mal = int(res.get("malicious", 0) or 0)
            sus = int(res.get("suspicious", 0) or 0)
            status = res.get("status") or "unknown"
            icon = vt_icon(mal, sus, status)
            vt_malicious_max = max(vt_malicious_max, mal)
            vt_suspicious_max = max(vt_suspicious_max, sus)
            log_line = f"{icon} {url} をスキャン: status={status} Malicious={mal} Suspicious={sus}"
            if res.get("reason"):
                log_line += f" reason={res.get('reason')}"
            logs.append(log_line)

            if progress_msg:
                bar = build_progress_bar(idx, len(targets))
                try:
                    await progress_msg.edit(
                        embed=discord.Embed(
                            title="セキュリティ検査中",
                            description="\n".join(logs) + f"\n{bar}",
                            color=discord.Color.blurple(),
                        )
                    )
                except Exception:
                    logger.debug("[SECURITY] プログレスメッセージ更新に失敗", exc_info=True)
                    progress_msg = None

    if vt_malicious_max >= MALICIOUS_THRESHOLD:
        danger = True
        extra_flags.append("VT_DANGEROUS")
    elif vt_malicious_max > 0 or vt_suspicious_max > 0:
        extra_flags.append("VT_SUSPICIOUS")

    return vt_results, progress_msg, extra_flags, danger


# ==================================================
# メッセージセキュリティ
# ==================================================
async def handle_security_for_message(bot: discord.Client, message: discord.Message):
    if message.author.bot or message.guild is None:
        return

    member = message.author
    content = message.content or ""
    links = extract_links(content)
    attachments: Sequence[discord.Attachment] = message.attachments or []

    try:
        resp_ch_id = get_response_channel_id(message.guild.id)
        is_chat_channel = bool(resp_ch_id and message.channel.id == resp_ch_id)
        if is_chat_channel and not links and not attachments:
            return
    except Exception:
        logger.debug("failed to check response_channel_id", exc_info=True)

    logs: List[str] = [f"[{now_jst()}] スキャン開始"]
    danger = False

    bypassed, bypass_reason = is_security_bypassed(member)
    if bypassed:
        logs.append(f"バイパス適用: {bypass_reason}")
        try:
            await log_action(
                bot, message.guild.id, "INFO", "セキュリティ検査スキップ",
                user=member, fields={"理由": bypass_reason or "bypass"},
            )
        except Exception:
            logger.debug("log_action failed", exc_info=True)
        return

    member_is_new = is_new_member(member)
    reason_flags, flag_logs, spam_count, min_interval = _check_content_flags(member, content, links)
    logs.extend(flag_logs)

    # スパム単体でも SUSPICIOUS 扱い（危険判定の引き上げは gpt_assess に委ねる）
    if "SPAM" in reason_flags:
        danger = True

    vt_results, progress_msg, vt_flags, vt_danger = await _run_vt_scans(
        bot, message.guild.id, links, attachments, logs
    )
    reason_flags.extend(vt_flags)
    if vt_danger:
        danger = True

    gpt_result = await gpt_assess(
        content, vt_results,
        spam_count=spam_count,
        min_interval=min_interval,
        is_new_member=member_is_new,
    )
    reason_flags.append(f"GPT:{gpt_result}")
    logs.append(f"GPT判定: {gpt_result}")
    if gpt_result == "DANGEROUS":
        danger = True

    if member_is_new:
        reason_flags.append("NEW_MEMBER")
        logs.append("新規メンバー")

    if message.author.voice and message.author.voice.channel:
        channel_id = message.author.voice.channel.id
        if check_vc_raid(member, channel_id):
            danger = True
            reason_flags.append("VC_RAID")
            logs.append("VCレイド検出")

    if danger:
        try:
            await message.delete()
        except discord.HTTPException as e:
            logger.warning("[security] message delete failed: %s", e)
        await strip_roles(member)

    embed = build_final_embed(vt_results, gpt_result, reason_flags, logs)

    # 検査結果はログチャンネルのみに送信（テキストチャンネルには送らない）
    if links or attachments:
        if progress_msg:
            try:
                await progress_msg.edit(embed=embed)
            except discord.HTTPException as e:
                logger.warning("[security] progress_msg edit failed: %s", e)
        else:
            await send_log_embed(bot, message.guild.id, "ERROR" if danger else "INFO", embed)
    elif danger:
        await send_log_embed(bot, message.guild.id, "ERROR", embed)

    try:
        await log_action(
            bot, message.guild.id,
            "ERROR" if danger else "INFO",
            "メッセージセキュリティ検査",
            user=member,
            fields={
                "理由": ", ".join(reason_flags) or "なし",
                "GPT判定": gpt_result,
                "リンク数": str(len(links)),
                "スパム回数": str(spam_count) if spam_count > 1 else "なし",
            },
            embed_color=discord.Color.red() if danger else discord.Color.green(),
        )
    except Exception:
        logger.debug("log_action failed", exc_info=True)

    logger.info("[SECURITY] SAFE" if not danger else "[SECURITY] DANGER")


# ==================================================
# VCセキュリティ
# ==================================================
async def handle_security_for_voice_join(
    bot: discord.Client,
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
) -> None:
    if member.bot or member.guild is None:
        return

    if before.channel == after.channel or after.channel is None:
        return

    bypassed, _ = is_security_bypassed(member)
    if bypassed:
        return

    channel = after.channel
    if channel and check_vc_raid(member, channel.id):
        logs = [f"[{now_jst()}] VCレイド検出", f"チャンネル: {channel.name}"]
        await strip_roles(member)

        try:
            await log_action(
                bot, member.guild.id, "ERROR", "VCレイド検出",
                user=member, fields={"チャンネル": channel.mention},
                embed_color=discord.Color.red(),
            )
        except Exception:
            logger.debug("log_action failed on VC raid", exc_info=True)
