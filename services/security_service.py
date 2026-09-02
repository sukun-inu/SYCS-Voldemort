import asyncio
import datetime
import logging
import re
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple, cast

import aiohttp
import discord

from envutil import env_int
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

# VirusTotal を同時に何本まで走らせるか。
#
# 1リンクずつ待つと、5本貼られただけで待ち時間も5倍になる。到達できない
# ときは1本あたり制限いっぱい（30秒）かかるため、リンクを並べるだけで
# security ハンドラが返らなくなる。
#
# 一方で無制限にもできない。スキャンは asyncio.to_thread の中で走り、
# 既定のスレッドプールは「CPU数 + 4、最大32本」しかない。ここを埋めると
# 設定の書き込み（settings_store.awrite）など、他の to_thread が全部
# 後ろに並ぶ。**速くするために別のものを詰まらせない**ための上限。
VT_SCAN_CONCURRENCY = env_int("VT_SCAN_CONCURRENCY", 4, minimum=1)


# ==================================================
# ユーティリティ
# ==================================================
def now_jst() -> str:
    """現在時刻をJST・ログ表示用の書式で返す。"""
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(url: str) -> str:
    """抽出したURLの前後に付いた記号を取り除く。

    Discordの <https://example.com> というリンク無効化記法や、
    "https://example.com." のように文の一部として書かれたURLでも、
    実際のURLだけを取り出せるようにする。
    """
    if not url:
        return ""
    u = url.strip()
    if u.startswith("<") and u.endswith(">"):
        u = u[1:-1].strip()
    u = u.strip("<>")
    u = u.rstrip(".,!?;:")
    return u


def extract_links(text: str) -> List[str]:
    """本文からURLを重複無しで抜き出す。normalize_url を通したあとの
    文字列で重複判定するので、記号の付き方が違うだけの同じURLを
    二重にスキャンしない。
    """
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
    """参加してから NEW_MEMBER_THRESHOLD_DAYS 日未満のメンバーかどうか。
    joined_at が取れない場合は「新規ではない」扱いにする（無害側に倒す）。
    """
    if not member.joined_at:
        return False
    return (discord.utils.utcnow() - member.joined_at).days < NEW_MEMBER_THRESHOLD_DAYS


class BypassResult(NamedTuple):
    """バイパス判定の結果。

    「判定できなかった」を「バイパスなし」と同じ扱いにすると、設定を読めなかった
    だけで全ロール剥奪（元に戻せない）まで進んでしまう。3つの状態を区別する。
    """

    bypassed: bool
    reason: str = ""
    check_failed: bool = False


def is_security_bypassed(member: discord.Member) -> BypassResult:
    """信頼ユーザー／バイパスロールのどちらかに該当するか判定する。

    設定の読み取りに失敗した場合は bypassed=False ではなく
    check_failed=True を立てて返す。呼び出し側はこれを「バイパスなし」と
    区別し、強制措置を見送る材料にする（設定を読めなかっただけで
    ロールを剥がされる事故を防ぐ）。
    """
    try:
        trusted = get_trusted_user_ids(member.guild.id)
        if member.id in trusted:
            return BypassResult(True, "trusted_user")

        bypass_roles = set(get_bypass_role_ids(member.guild.id))
        if any(r.id in bypass_roles for r in member.roles):
            return BypassResult(True, "bypass_role")
    except Exception as e:
        # 信頼済みかどうかが分からない状態。ここで「バイパスなし」と答えると、
        # 設定の読み取りに失敗しただけの管理者からロールを剥がしかねない。
        logger.error(
            "[SECURITY] バイパス判定に失敗しました guild=%s user=%s: %s" "（この検査では強制措置を行いません）",
            member.guild.id,
            member.id,
            e,
            exc_info=True,
        )
        return BypassResult(False, "check_failed", True)

    return BypassResult(False)


async def strip_roles(member: discord.Member) -> Tuple[bool, str]:
    """@everyone 以外の全ロールを剥奪する。

    剥奪対象が無ければ何もせず成功扱い（"no_roles"）。権限不足
    （discord.Forbidden）は個別に区別して返し、呼び出し側でログの
    出し分けができるようにする。
    """
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
    """VirusTotal 走査の進捗をテキストのプログレスバーにする。"""
    filled_len = int(length * current / total)
    bar = "#" * filled_len + "-" * (length - filled_len)
    return f"[{bar}] {current}/{total}"


def vt_icon(malicious: int, suspicious: int, status: Optional[str] = None) -> str:
    """VirusTotal の結果をアイコンへ変換する。status が error/skip
    （＝走査できなかった）のときは SAFE ではなく WARN を返す。
    判定できなかったことを「安全」と混同させないため。
    """
    if status in ("error", "skip"):
        return WARN_ICON
    if malicious > 0:
        return ALERT_ICON
    if suspicious > 0:
        return WARN_ICON
    return SAFE_ICON


def gpt_icon(result: str) -> str:
    """ChatGPT判定の結果をアイコンへ変換する。UNKNOWN（Groq呼び出し失敗）は
    SUSPICIOUS と同じ WARN 扱いにする。「判定できなかった」ことが
    埋め込みの上で「問題なし」に化けないようにするため。
    """
    if result == "DANGEROUS":
        return ALERT_ICON
    if result in ("SUSPICIOUS", "UNKNOWN"):
        # UNKNOWN は gpt_assess が Groq 呼び出しに失敗したときの値で、
        # 「安全と判定した」わけではない。SAFE と同じ扱いにすると、
        # 判定できなかったことが埋め込みの上では「問題なし」に化けてしまう。
        return WARN_ICON
    return SAFE_ICON


def reason_icon(reason: str) -> str:
    """reason 文字列（"GPT:DANGEROUS" のように ":" で付加情報が付くことがある）
    から種別だけを取り出し、対応するアイコンを返す。未知の種別は
    [INFO] にフォールバックする。
    """
    base = reason.split(":")[0]
    return REASON_ICONS.get(base, "[INFO]")


def build_final_embed(
    vt_results: List[Dict[str, Any]],
    gpt_result: str,
    reasons: List[str],
    logs: List[str],
) -> discord.Embed:
    """検査結果の総括 embed を組み立てる。

    危険度に応じて色とタイトルを決める際、GPT判定の UNKNOWN（判定失敗）
    を安全側と混同しないよう独立した分岐にしてある。
    """
    is_vt_dangerous = "VT_DANGEROUS" in reasons
    is_vc_raid = "VC_RAID" in reasons
    is_spam = "SPAM" in reasons
    is_vt_suspicious = "VT_SUSPICIOUS" in reasons

    # gpt_result == "UNKNOWN" は Groq 呼び出し自体が失敗した合図であり、
    # 「GPTが安全と判定した」のではない。ここで無視すると、判定できなかった
    # 投稿がそのまま緑色の「問題なし」として報告されてしまう。
    is_gpt_unknown = gpt_result == "UNKNOWN"

    if is_vt_dangerous or gpt_result == "DANGEROUS" or is_vc_raid:
        color = discord.Color.red()
        title = "危険な投稿を検出"
    elif is_vt_suspicious or gpt_result == "SUSPICIOUS" or is_spam:
        color = discord.Color.orange()
        title = "注意：スパム/不審な投稿の可能性"
    elif is_gpt_unknown:
        color = discord.Color.orange()
        title = "注意：GPT判定に失敗しました"
    else:
        color = discord.Color.green()
        title = "検査完了：問題なし"

    embed = discord.Embed(title=title, description="\n".join(logs), color=color)

    for idx, r in enumerate(vt_results, 1):
        icon = vt_icon(r.get("malicious", 0), r.get("suspicious", 0), r.get("status"))
        embed.add_field(
            name=f"{icon} ターゲット {idx} ({r.get('type')})",
            value=(
                f"Status: `{r.get('status')}` | Malicious: `{r.get('malicious')}` | "
                f"Suspicious: `{r.get('suspicious')}`"
            ),
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
    """リンク・添付ファイルを順にVirusTotalへ回し、結果と危険フラグを
    まとめる。

    走査対象が無ければ何もせず空の結果を返す。走査中は進捗メッセージを
    都度編集するが、編集自体が失敗した場合は以降の更新を諦める
    （進捗表示の失敗で検査そのものを止めない）。
    """
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
        gate = asyncio.Semaphore(VT_SCAN_CONCURRENCY)
        done = 0

        async def scan_one(url: str) -> Dict[str, Any]:
            """1件スキャンして、終わるたびに進捗を1つ進める。"""
            nonlocal done, progress_msg
            async with gate:
                res = await vt_scan_target(session, url)
            done += 1
            if progress_msg:
                # 「何本終わったか」だけを出す。並列に走るので、どの行まで
                # 進んだかは終わってからでないと分からない。
                bar = build_progress_bar(done, len(targets))
                try:
                    await progress_msg.edit(
                        embed=discord.Embed(
                            title="セキュリティ検査中",
                            description="VirusTotal解析中… " + bar,
                            color=discord.Color.blurple(),
                        )
                    )
                except Exception:
                    logger.debug("[SECURITY] プログレスメッセージ更新に失敗", exc_info=True)
                    progress_msg = None
            return res

        # gather は**渡した順**で結果を返す。終わった順に並べると、ログの行と
        # 結果の対応が崩れて「どのURLがどの結果か」が読めなくなる。
        vt_results = list(await asyncio.gather(*(scan_one(url) for url in targets)))

    for url, res in zip(targets, vt_results):
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

    if vt_malicious_max >= MALICIOUS_THRESHOLD:
        danger = True
        extra_flags.append("VT_DANGEROUS")
    elif vt_malicious_max > 0 or vt_suspicious_max > 0:
        extra_flags.append("VT_SUSPICIOUS")

    return vt_results, progress_msg, extra_flags, danger


# ==================================================
# メッセージセキュリティ
# ==================================================
class _Findings(NamedTuple):
    """1件のメッセージを見て集まった判定材料。

    危険かどうかの結論（danger）と、その根拠になった印（reason_flags）を
    一緒に持つ。片方だけ渡すと、「危険だが理由が空」という報告が作れて
    しまう。
    """

    danger: bool
    reason_flags: List[str]
    vt_results: List[Dict[str, Any]]
    progress_msg: Optional[discord.Message]
    gpt_result: str
    spam_count: int


def _is_examinable(message: discord.Message) -> bool:
    """検査の対象になるメッセージか。

    ボット自身の発言とDMは対象外。author が Member でない場合も外すが、
    **黙って戻らないこと。** ここは危険な投稿を見つけるための経路で、
    素通りしたことに気づけないのがいちばん困る。
    """
    if message.author.bot or message.guild is None:
        return False

    if not isinstance(message.author, discord.Member):
        # 型を絞り込むために要る。以下でロールや参加日時（Member にしか無い）を
        # 見るため、User のままだと AttributeError になる。
        #
        # ここへ来ることは通常無い。on_message で投稿しているのだから、その人は
        # まだギルドに居る。ただし discord.py は「ギルドを抜けたあとの投稿」など
        # いくつかの場合に User を返す仕様なので、絶対に来ないとは言い切れない。
        logger.warning(
            "[security] author が Member ではないため検査を飛ばします " "guild=%s channel=%s author=%s(%s)",
            message.guild.id,
            getattr(message.channel, "id", None),
            message.author,
            type(message.author).__name__,
        )
        return False
    return True


def _is_plain_chat_post(message: discord.Message, guild_id: int, links: List[str], attachments: Sequence) -> bool:
    """AI応答チャンネルへの、リンクも添付も無い発言か。

    会話用のチャンネルは投稿が多いので、走査するものが何も無いなら見ない。
    設定を読めなかったときは「普通のチャンネル」として扱う（検査する側へ
    倒す）。
    """
    try:
        resp_ch_id = get_response_channel_id(guild_id)
    except Exception:
        logger.debug("failed to check response_channel_id", exc_info=True)
        return False
    return bool(resp_ch_id and message.channel.id == resp_ch_id) and not links and not attachments


async def _announce_bypass(bot: discord.Client, guild_id: int, member: discord.Member, reason: str) -> None:
    """バイパスで検査を飛ばしたことをログへ残す。"""
    try:
        await log_action(
            bot,
            guild_id,
            "INFO",
            "セキュリティ検査スキップ",
            user=member,
            fields={"理由": reason or "bypass"},
        )
    except Exception:
        logger.debug("log_action failed", exc_info=True)


async def _collect_findings(
    bot: discord.Client,
    guild_id: int,
    member: discord.Member,
    content: str,
    links: List[str],
    attachments: Sequence,
    logs: List[str],
) -> _Findings:
    """スパム・リンク・VirusTotal・GPT・VCレイドを順に見て、材料をそろえる。

    ここでは**判定するだけで、何も実行しない。** 消すか剥がすかを決めるのは
    _enforce_or_withhold の仕事で、分けてあるのは「判定は正しいのに措置の
    条件だけ壊れている」状態をテストで切り分けられるようにするため。
    """
    member_is_new = is_new_member(member)
    reason_flags, flag_logs, spam_count, min_interval = _check_content_flags(member, content, links)
    logs.extend(flag_logs)

    # スパム単体でも SUSPICIOUS 扱い（危険判定の引き上げは gpt_assess に委ねる）
    danger = "SPAM" in reason_flags

    vt_results, progress_msg, vt_flags, vt_danger = await _run_vt_scans(bot, guild_id, links, attachments, logs)
    reason_flags.extend(vt_flags)
    danger = danger or vt_danger

    gpt_result = await gpt_assess(
        content,
        vt_results,
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

    if member.voice and member.voice.channel:
        if check_vc_raid(member, member.voice.channel.id):
            danger = True
            reason_flags.append("VC_RAID")
            logs.append("VCレイド検出")

    return _Findings(
        danger=danger,
        reason_flags=reason_flags,
        vt_results=vt_results,
        progress_msg=progress_msg,
        gpt_result=gpt_result,
        spam_count=spam_count,
    )


async def _withhold_enforcement(
    bot: discord.Client,
    guild_id: int,
    member: discord.Member,
    findings: _Findings,
    logs: List[str],
) -> None:
    """危険と判定したが、バイパス判定に失敗しているので何もしない。

    信頼済みかどうかが分からないまま消したり剥がしたりしない。見逃すより
    取り返しがつかないほうを避け、人が判断できるよう大きく残す。
    """
    logs.append("強制措置は見送った（バイパス判定に失敗しているため）")
    logger.error(
        "[SECURITY] guild=%s user=%s 危険と判定しましたが、バイパス判定に失敗している"
        "ため強制措置（メッセージ削除・ロール剥奪）を見送りました。手動で確認してください。",
        guild_id,
        member.id,
    )
    try:
        await log_action(
            bot,
            guild_id,
            "ERROR",
            "⚠️ 要確認: 強制措置を見送りました",
            user=member,
            fields={
                "理由": "バイパス判定に失敗（設定を読めませんでした）",
                "検出": "、".join(findings.reason_flags) or "不明",
                "対応": "内容を確認し、必要なら手動で対処してください。",
            },
            embed_color=discord.Color.orange(),
        )
    except Exception:
        logger.debug("log_action failed", exc_info=True)


async def _enforce_or_withhold(
    bot: discord.Client,
    message: discord.Message,
    guild_id: int,
    member: discord.Member,
    findings: _Findings,
    bypass: BypassResult,
    logs: List[str],
) -> None:
    """危険なら消して剥がす。ただしバイパス判定に失敗しているなら見送る。

    **見送りの判定を、削除・剥奪より先に置くこと。** 順序を入れ替えると、
    設定を読めなかっただけでロールが消える。元に戻せない操作なので、
    ここは「分からないなら触らない」に倒す。
    """
    if findings.danger and bypass.check_failed:
        await _withhold_enforcement(bot, guild_id, member, findings, logs)
    elif findings.danger:
        try:
            await message.delete()
        except discord.HTTPException as e:
            logger.warning("[security] message delete failed: %s", e)
        await strip_roles(member)


async def _report_result(
    bot: discord.Client,
    guild_id: int,
    member: discord.Member,
    findings: _Findings,
    links: List[str],
    attachments: Sequence,
    logs: List[str],
) -> None:
    """検査結果を、ログチャンネルへだけ送る（テキストチャンネルには送らない）。"""
    embed = build_final_embed(findings.vt_results, findings.gpt_result, findings.reason_flags, logs)

    if links or attachments:
        if findings.progress_msg:
            try:
                await findings.progress_msg.edit(embed=embed)
            except discord.HTTPException as e:
                logger.warning("[security] progress_msg edit failed: %s", e)
        else:
            await send_log_embed(bot, guild_id, "ERROR" if findings.danger else "INFO", embed)
    elif findings.danger:
        await send_log_embed(bot, guild_id, "ERROR", embed)

    try:
        await log_action(
            bot,
            guild_id,
            "ERROR" if findings.danger else "INFO",
            "メッセージセキュリティ検査",
            user=member,
            fields={
                "理由": ", ".join(findings.reason_flags) or "なし",
                "GPT判定": findings.gpt_result,
                "リンク数": str(len(links)),
                "スパム回数": str(findings.spam_count) if findings.spam_count > 1 else "なし",
            },
            embed_color=discord.Color.red() if findings.danger else discord.Color.green(),
        )
    except Exception:
        logger.debug("log_action failed", exc_info=True)

    logger.info("[SECURITY] SAFE" if not findings.danger else "[SECURITY] DANGER")


async def handle_security_for_message(bot: discord.Client, message: discord.Message):
    """メッセージ1件に対する検査の入口。

    スパム・リンク過多・ユニコードトリック・VirusTotal・GPT判定・VC
    レイドを順に確認し、危険と判定したら削除とロール剥奪を行う。
    バイパス判定に失敗した場合は、危険と判定していても強制措置を
    見送り、人が確認できるようログに大きく残す（信頼済みかどうか
    分からないまま取り返しのつかない操作をしないため）。

    判定（_collect_findings）と措置（_enforce_or_withhold）と報告
    （_report_result）を分けてある。結末は tests の
    MessageSecurityOutcomeTests が4通り固定している。
    """
    if not _is_examinable(message):
        return

    # _is_examinable が Member であることを確認済み。assert は使わない
    # （実行時に例外を投げうる文を、型検査のためだけに足さない）。
    member = cast(discord.Member, message.author)
    # message.guild も同様。関数をまたぐと mypy は絞り込みを引き継げないので、
    # ここで一度だけ束ねて、以降は guild_id を配る。
    guild_id = cast(discord.Guild, message.guild).id
    content = message.content or ""
    links = extract_links(content)
    attachments: Sequence[discord.Attachment] = message.attachments or []
    if _is_plain_chat_post(message, guild_id, links, attachments):
        return

    logs: List[str] = [f"[{now_jst()}] スキャン開始"]

    bypass = is_security_bypassed(member)
    if bypass.bypassed:
        logs.append(f"バイパス適用: {bypass.reason}")
        await _announce_bypass(bot, guild_id, member, bypass.reason or "")
        return
    if bypass.check_failed:
        logs.append("⚠️ バイパス判定に失敗（強制措置は行わない）")

    findings = await _collect_findings(bot, guild_id, member, content, links, attachments, logs)
    await _enforce_or_withhold(bot, message, guild_id, member, findings, bypass, logs)
    await _report_result(bot, guild_id, member, findings, links, attachments, logs)


# ==================================================
# VCセキュリティ
# ==================================================
async def handle_security_for_voice_join(
    bot: discord.Client,
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
) -> None:
    """VC参加時にレイド検出だけを行う入口（メッセージ検査とは別経路）。
    バイパス判定に失敗した場合はロール剥奪を見送り、人が確認できる
    よう大きくログに残す（handle_security_for_message と同じ方針）。
    """
    if member.bot or member.guild is None:
        return

    if before.channel == after.channel or after.channel is None:
        return

    bypass = is_security_bypassed(member)
    if bypass.bypassed:
        return

    channel = after.channel
    if channel and check_vc_raid(member, channel.id):
        if bypass.check_failed:
            # メッセージ側と同じ扱い。判定できないまま剥がさない。
            logger.error(
                "[SECURITY] guild=%s user=%s VCレイドを検出しましたが、バイパス判定に"
                "失敗しているためロール剥奪を見送りました。手動で確認してください。",
                member.guild.id,
                member.id,
            )
            try:
                await log_action(
                    bot,
                    member.guild.id,
                    "ERROR",
                    "⚠️ 要確認: VCレイドの措置を見送りました",
                    user=member,
                    fields={
                        "チャンネル": channel.mention,
                        "理由": "バイパス判定に失敗（設定を読めませんでした）",
                        "対応": "内容を確認し、必要なら手動で対処してください。",
                    },
                    embed_color=discord.Color.orange(),
                )
            except Exception:
                logger.debug("log_action failed on VC raid", exc_info=True)
            return

        await strip_roles(member)

        try:
            await log_action(
                bot,
                member.guild.id,
                "ERROR",
                "VCレイド検出",
                user=member,
                fields={"チャンネル": channel.mention},
                embed_color=discord.Color.red(),
            )
        except Exception:
            logger.debug("log_action failed on VC raid", exc_info=True)
