import asyncio
import datetime
import logging
import re
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple, cast

import discord

from envutil import env_int
from services import content_moderation, raid_detection, spam_detection
from services.content_moderation import gpt_assess
from services.http_client import get_session
from services.logging_service import log_action, send_log_embed
from services.raid_detection import check_vc_raid, is_vc_raid_ongoing, was_enforced
from services.settings_store import get_bypass_role_ids, get_response_channel_id, get_trusted_user_ids
from services.spam_detection import SpamCheck, check_spam
from services.virustotal_service import MALICIOUS_THRESHOLD, vt_scan_target

NEW_MEMBER_THRESHOLD_DAYS = 7
MAX_LINKS = 5

# 措置のタイムアウトの長さ（秒。rust-09 の S1・S2）。危険なもの（VirusTotal の危険・AI の DANGEROUS・VC の荒らし）は
# 24 時間、スパムだけなら 10 分。上限は Discord が受け付ける 28 日。
TIMEOUT_MAX_SECONDS = 28 * 24 * 3600
SECURITY_TIMEOUT_DANGER_SECONDS = env_int(
    "SECURITY_TIMEOUT_DANGER_SECONDS", 86400, minimum=60, maximum=TIMEOUT_MAX_SECONDS
)
SECURITY_TIMEOUT_SPAM_SECONDS = env_int("SECURITY_TIMEOUT_SPAM_SECONDS", 600, minimum=60, maximum=TIMEOUT_MAX_SECONDS)
# タイムアウト・ロールの剥奪の理由（監査ログに出る）。
ENFORCEMENT_REASON = "セキュリティ違反"

URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
# 隠しリンク [文](https://…)（S6）。括弧の中の URL だけを取る。URL の中の対になった括弧は 1 段まで
# （https://ja.wikipedia.org/wiki/X_(曖昧さ回避) など）。<> で囲んだもの（埋め込みを出さない書き方）も読む。
MASKED_LINK_REGEX = re.compile(
    r"\[[^\[\]]*\]\(\s*<?(https?://(?:[^\s()<>]|\([^\s()<>]*\))+)>?\s*\)",
    re.IGNORECASE,
)
# https:// の無い招待（discord.gg/コード・discord.com/invite/コード・discordapp.com/invite/コード。大文字小文字は
# 問わない）。コードは英数字とハイフン。大文字小文字は文字の組で書く（IGNORECASE だと Python と Rust で、
# 英字に重ねる文字〔İ・ı など〕が食い違う）。
INVITE_REGEX = re.compile(
    r"[Dd][Ii][Ss][Cc][Oo][Rr][Dd]"
    r"(?:\.[Gg][Gg]|(?:[Aa][Pp][Pp])?\.[Cc][Oo][Mm]/[Ii][Nn][Vv][Ii][Tt][Ee])"
    r"/[A-Za-z0-9-]+"
)
# 招待の直前にこれがあれば、別のドメインや道すじの一部（evil-discord.gg/… など）なので拾わない。
_INVITE_GLUE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/@")
# URL の末尾から落とす句読点と、Discord の飾りの記号（|| ネタバレ・~~ 打ち消し・** __ * _ 強調・` コード）。
_TRAILING_PUNCT = ".,!?;:"
_TRAILING_PAIRS = ("||", "~~")
_TRAILING_SINGLES = ("*", "_", "`")
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


def _trim_once(u: str) -> str:
    """URL の末尾から、記号を 1 回ぶん落とす（normalize_url が、変わらなくなるまで繰り返す）。

    前後の <>・末尾の句読点を落とし、そのあと末尾の Discord の飾りの記号（|| ~~ は 2 文字、* _ ` は 1 文字）か、
    URL の中の ( [ と対にならない ) ] を 1 つ落とす。
    """
    u = u.strip("<>").rstrip(_TRAILING_PUNCT)
    if u.endswith(_TRAILING_PAIRS):
        return u[:-2]
    if u.endswith(_TRAILING_SINGLES):
        return u[:-1]
    if u.endswith(")") and u.count("(") < u.count(")"):
        return u[:-1]
    if u.endswith("]") and u.count("[") < u.count("]"):
        return u[:-1]
    return u


def normalize_url(url: str) -> str:
    """抽出したURLの前後に付いた記号を取り除く。

    Discordの <https://example.com> というリンク無効化記法や、
    "https://example.com." のように文の一部として書かれたURLでも、
    実際のURLだけを取り出せるようにする。

    末尾の Discord の飾りの記号（||https://例|| のネタバレ・**太字** など）と、URL の中の括弧と対にならない
    末尾の ) ] も落とす（(https://例) の ) は落とし、https://ja.wikipedia.org/wiki/X_(曖昧さ回避) の ) は残す。
    S6）。句読点と組み合わさっても（https://例||. など）落ちきるよう、変わらなくなるまで繰り返す。
    """
    if not url:
        return ""
    u = url.strip()
    if u.startswith("<") and u.endswith(">"):
        u = u[1:-1].strip()
    while True:
        trimmed = _trim_once(u)
        if trimmed == u:
            return u
        u = trimmed


def _blank(text: str, start: int, end: int) -> str:
    """text の start〜end を空白で塗る（長さは変えない。位置で並べ直すため）。"""
    return text[:start] + " " * (end - start) + text[end:]


def extract_links(text: str) -> List[str]:
    """本文からURLを重複無しで抜き出す。normalize_url を通したあとの
    文字列で重複判定するので、記号の付き方が違うだけの同じURLを
    二重にスキャンしない。

    Discord の書き方を読み解く（S6）。隠しリンク [文](https://例) は括弧の中の URL だけを取る（文の中は見ない）。
    https:// の無い招待（discord.gg/コード など）は https:// を付けた形にする（https:// 付きの URL の中のものは
    拾い直さない）。www. で始まるもの・ドメインらしい文字列は拾わない（拾いすぎて VirusTotal の枠を食う）。
    並びは本文に出た順。
    """
    text = text or ""
    found: List[Tuple[int, str]] = []
    rest = text
    for m in MASKED_LINK_REGEX.finditer(text):
        found.append((m.start(), m.group(1)))
        rest = _blank(rest, m.start(), m.end())
    plain = rest
    for m in URL_REGEX.finditer(plain):
        found.append((m.start(), m.group(0)))
        rest = _blank(rest, m.start(), m.end())
    for m in INVITE_REGEX.finditer(rest):
        if m.start() > 0 and rest[m.start() - 1] in _INVITE_GLUE:
            continue
        found.append((m.start(), "https://" + m.group(0)))

    links: List[str] = []
    seen: set[str] = set()
    for _, raw in sorted(found, key=lambda f: f[0]):
        u = normalize_url(raw)
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


def is_new_account(member: discord.Member) -> bool:
    """アカウントを作ってから NEW_ACCOUNT_THRESHOLD_DAYS 日未満か（rust-09 の S5）。

    作った日時は ID（snowflake）から取る（discord.py の member.created_at と同じ計算。ID から直に取るので、
    いつでも分かる）。日数の数え方は is_new_member と同じ（切り捨て）。
    """
    created = discord.utils.snowflake_time(member.id)
    return (discord.utils.utcnow() - created).days < content_moderation.NEW_ACCOUNT_THRESHOLD_DAYS


def is_fresh_joiner(member: discord.Member) -> bool:
    """VC の荒らしに数える「入って間もない人」か（rust-09 の S4）。

    サーバーに入って VC_RAID_NEW_JOIN_HOURS 時間未満か、アカウントを作って NEW_ACCOUNT_THRESHOLD_DAYS 日未満の人。
    joined_at が取れない人は「入って間もない人ではない」（is_new_member と同じく無害側に倒す）。
    """
    if not member.joined_at:
        return False
    joined = discord.utils.utcnow() - member.joined_at
    return joined < datetime.timedelta(hours=raid_detection.VC_RAID_NEW_JOIN_HOURS) or is_new_account(member)


class BypassResult(NamedTuple):
    """バイパス判定の結果。

    「判定できなかった」を「バイパスなし」と同じ扱いにすると、設定を読めなかった
    だけで全ロール剥奪（元に戻せない）まで進んでしまう。3つの状態を区別する。
    """

    bypassed: bool
    reason: str = ""
    check_failed: bool = False


def _is_administrator(member: discord.Member) -> bool:
    """サーバーの管理者（administrator の権限。オーナーも discord.py では管理者）か（rust-09 の S7）。

    真偽の値として真のときだけ管理者にする。読めないとき（例外・真偽でない値）は管理者でない（検査する側に倒す）。
    MANAGE_GUILD・MANAGE_MESSAGES の人は管理者に入れない（乗っ取られたときに素通りする範囲を広げない）。
    """
    try:
        return getattr(member.guild_permissions, "administrator", False) is True
    except Exception:
        logger.debug("[SECURITY] 管理者かどうかを読めませんでした", exc_info=True)
        return False


def is_security_bypassed(member: discord.Member) -> BypassResult:
    """管理者／信頼ユーザー／バイパスロールのどれかに該当するか判定する。

    管理者は、設定を読む前に見る（設定が読めなくても管理者は飛ばす。理由は administrator。S7）。

    設定の読み取りに失敗した場合は bypassed=False ではなく
    check_failed=True を立てて返す。呼び出し側はこれを「バイパスなし」と
    区別し、強制措置を見送る材料にする（設定を読めなかっただけで
    ロールを剥がされる事故を防ぐ）。
    """
    if _is_administrator(member):
        return BypassResult(True, "administrator")
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


class StripResult(NamedTuple):
    """ロールの剥奪の結果。

    ok と reason は以前の戻り値（(bool, str)）と同じ。reason は "removed"・
    "no_roles"・"forbidden"・ほかの失敗の文。removed と kept で、どのロールを
    剥がせて、どのロールが残ったかを持つ（ログチャンネルの報告に出す。rust-09 の (i)）。
    """

    ok: bool
    reason: str
    removed: Tuple[Any, ...] = ()
    kept: Tuple[Any, ...] = ()


async def strip_roles(member: discord.Member) -> StripResult:
    """@everyone 以外の全ロールを剥奪する。

    剥奪対象が無ければ何もせず成功扱い（"no_roles"）。権限不足
    （discord.Forbidden）は個別に区別して返し、呼び出し側でログの
    出し分けができるようにする。

    1 つずつ外し、失敗したらそこで止める。discord.py の remove_roles（atomic）も
    1 つずつ送って失敗で止まるので、Discord へ送るものは以前と同じ。1 つずつ
    呼ぶのは、どこまで剥がせたか（removed）と、何が残ったか（kept: 失敗した
    ロールと、そのあと試さなかったロール）を知るため。
    """
    roles: List[Any] = []
    removed: List[Any] = []
    try:
        roles = [r for r in member.roles if not r.is_default()]
        if not roles:
            return StripResult(True, "no_roles")

        for role in roles:
            await member.remove_roles(role, reason=ENFORCEMENT_REASON)
            removed.append(role)
        return StripResult(True, "removed", tuple(removed))

    except discord.Forbidden:
        return StripResult(False, "forbidden", tuple(removed), tuple(roles[len(removed) :]))
    except Exception as e:
        logger.error("[SECURITY] strip roles failed: %s", e)
        return StripResult(False, str(e), tuple(removed), tuple(roles[len(removed) :]))


def can_timeout(guild: Any) -> bool:
    """Bot がそのサーバーで「メンバーをタイムアウト」（moderate_members）の権限を持っているか（rust-09 の S1）。

    discord.py の guild.me.guild_permissions（オーナー・管理者なら全部の権限）。Bot のメンバーが分からない・
    真偽の値でないときは持っていない扱い（いまどおり全ロールを外す側に倒す）。
    """
    me = getattr(guild, "me", None)
    permissions = getattr(me, "guild_permissions", None)
    return getattr(permissions, "moderate_members", False) is True


class TimeoutResult(NamedTuple):
    """タイムアウトの結果（rust-09 の S1）。reason は "timed_out"・"forbidden"・ほかの失敗の文。"""

    ok: bool
    reason: str
    seconds: int


async def timeout_member(member: discord.Member, seconds: int) -> TimeoutResult:
    """メンバーを seconds 秒タイムアウトする（理由は「セキュリティ違反」。discord.py の member.timeout）。

    断られたとき（相手のロールが Bot より上など）は失敗として返す。ロールを外すことは試さない（同じ理由で
    失敗する）。権限不足（discord.Forbidden）は個別に区別する（ログの出し分けは strip_roles と同じ）。
    """
    try:
        await member.timeout(datetime.timedelta(seconds=seconds), reason=ENFORCEMENT_REASON)
    except discord.Forbidden:
        return TimeoutResult(False, "forbidden", seconds)
    except Exception as e:
        logger.error("[SECURITY] timeout failed: %s", e)
        return TimeoutResult(False, str(e), seconds)
    return TimeoutResult(True, "timed_out", seconds)


def _fold(items: Sequence[str], *, budget: int, unit: str, joiner: str) -> str:
    """一覧を文字数の予算に収める。はみ出す分は「…他N{unit}」の形で畳む。

    commands/interaction_utils.cap_list_for_message（header・limit なし）と同じ畳み方。
    services から commands を読まないので、同じ決まりでここに置く。省略の行の長さも
    予算に含め、収まるまで後ろから削る。
    """
    fitted: List[str] = []
    for item in items:
        if len(joiner.join(fitted + [item])) > budget:
            break
        fitted.append(item)
    omitted = len(items) - len(fitted)
    while True:
        if omitted <= 0:
            return joiner.join(fitted)
        omission = f"…他{omitted}{unit}"
        text = joiner.join(fitted)
        candidate = f"{text}{joiner}{omission}" if text else omission
        if len(candidate) <= budget or not fitted:
            return candidate
        fitted.pop()
        omitted += 1


EMBED_FIELD_VALUE_LIMIT = 1024


def strip_fields(result: StripResult) -> Dict[str, str]:
    """剥がした結果を、ログチャンネルの報告に足す項目にする（rust-09 の (i)）。

    「剥がしたロール」は必ず出す（無ければ「なし」）。残ったロールがあれば
    「剥がせなかったロール（権限不足）」か「剥がせなかったロール（失敗）」を足す
    （失敗の文は Discord の誤りの文なので、項目には出さずログにだけ残す）。
    ロールはメンションで並べ、1 つの項目の上限（1024 文字）に収める。
    """

    def mentions(roles: Tuple[Any, ...]) -> str:
        """ロールのメンションを並べ、項目の上限に収める（はみ出す分は「…他N個」）。"""
        return _fold([f"<@&{r.id}>" for r in roles], budget=EMBED_FIELD_VALUE_LIMIT, unit="個", joiner=" ")

    fields = {"剥がしたロール": mentions(result.removed) if result.removed else "なし"}
    if result.kept:
        why = "権限不足" if result.reason == "forbidden" else "失敗"
        fields[f"剥がせなかったロール（{why}）"] = mentions(result.kept)
    return fields


def duration_text(seconds: int) -> str:
    """タイムアウトの長さの書き方（86400 → 「24 時間」、600 → 「10 分」、割り切れなければ秒）。"""
    if seconds % 3600 == 0:
        return f"{seconds // 3600} 時間"
    if seconds % 60 == 0:
        return f"{seconds // 60} 分"
    return f"{seconds} 秒"


def timeout_fields(result: TimeoutResult) -> Dict[str, str]:
    """タイムアウトの結果を、ログチャンネルの報告に足す項目にする（strip_fields と同じ作法）。

    できたら「タイムアウト」に長さ。断られたら「タイムアウトできなかった（権限不足）」か「…（失敗）」に、
    かけようとした長さ（失敗の文は項目には出さずログにだけ残す）。
    """
    length = duration_text(result.seconds)
    if result.ok:
        return {"タイムアウト": length}
    refused = "権限不足" if result.reason == "forbidden" else "失敗"
    return {f"タイムアウトできなかった（{refused}）": length}


class Enforcement(NamedTuple):
    """取った措置（rust-09 の S1・S2）。報告の見出し・色・項目は、これで決める（S8）。

    - action: "danger"（危険で措置した）・"spam"（スパムだけで措置した）・"withheld"（バイパスの判定に失敗して
      見送った）・"none"（措置なし）
    - deleted・delete_failed: 消した投稿（既に消えていたものも含む）と、消せなかった投稿の数
    - timeout: タイムアウトを試した結果（タイムアウトの権限が無ければ None）
    - stripped: ロールを外した結果（危険で、タイムアウトの権限が無いサーバー）
    - vc_done: 危険だが、VC の荒らしの経路で措置済みなので、人への措置はしなかった（二重に措置しない。S4）
    """

    action: str = "none"
    deleted: int = 0
    delete_failed: int = 0
    timeout: Optional[TimeoutResult] = None
    stripped: Optional[StripResult] = None
    vc_done: bool = False


def enforcement_fields(enforcement: Enforcement) -> Dict[str, str]:
    """取った措置を、ログチャンネルの報告に足す項目にする（消した投稿・タイムアウト・剥がしたロール）。

    消そうとしなかったときは消した投稿の項目を出さない。消せなかった投稿があれば「消せなかった投稿」を足す。
    """
    fields: Dict[str, str] = {}
    if enforcement.deleted or enforcement.delete_failed:
        fields["消した投稿"] = f"{enforcement.deleted}件"
        if enforcement.delete_failed:
            fields["消せなかった投稿"] = f"{enforcement.delete_failed}件"
    if enforcement.timeout is not None:
        fields.update(timeout_fields(enforcement.timeout))
    if enforcement.stripped is not None:
        fields.update(strip_fields(enforcement.stripped))
    return fields


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
    "NEW_ACCOUNT": "[ACCOUNT]",
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


# Discord の Embed の上限。超えると Discord が送信（書き換え）ごと断り、報告が届かない。
EMBED_DESCRIPTION_LIMIT = 4096
EMBED_FIELD_COUNT_LIMIT = 25
EMBED_TOTAL_LIMIT = 6000
# 畳んだ走査の結果の印は、隠れたものの中でいちばん重いもの（危険 > 注意 > 安全）。
_ICON_WEIGHT = {ALERT_ICON: 2, WARN_ICON: 1, SAFE_ICON: 0}


def _target_fields(vt_results: List[Dict[str, Any]], room: int) -> List[Tuple[str, str]]:
    """走査の結果を 1 件 1 項目にする。room 個を超えるなら、最後の 1 項目に残りを畳む。

    畳んだ項目は「{印} ターゲット {最初}〜{最後}」と「…他N件」。印は隠れた結果の
    中でいちばん重いもの（隠れた中に危険があれば、畳んでも危険の印が見える）。
    """
    fields = []
    for idx, r in enumerate(vt_results, 1):
        icon = vt_icon(r.get("malicious", 0), r.get("suspicious", 0), r.get("status"))
        fields.append(
            (
                f"{icon} ターゲット {idx} ({r.get('type')})",
                f"Status: `{r.get('status')}` | Malicious: `{r.get('malicious')}` | "
                f"Suspicious: `{r.get('suspicious')}`",
            )
        )
    if len(fields) <= room:
        return fields
    shown = room - 1
    hidden = vt_results[shown:]
    icons = [vt_icon(r.get("malicious", 0), r.get("suspicious", 0), r.get("status")) for r in hidden]
    worst = max(icons, key=lambda i: _ICON_WEIGHT[i])
    fold = (f"{worst} ターゲット {shown + 1}〜{len(vt_results)}", f"…他{len(hidden)}件")
    return fields[:shown] + [fold]


# 措置しなかったときに「注意の材料あり」（黄）にする印（S8）。AI の SUSPICIOUS・UNKNOWN も入る。
_CAUTION_FLAGS = ("VT_SUSPICIOUS", "TOO_MANY_LINKS", "UNICODE_TRICK")


def has_caution(reasons: Sequence[str], gpt_result: str) -> bool:
    """注意の材料（VirusTotal の疑わしい・AI の SUSPICIOUS/UNKNOWN・リンク過多・ユニコードトリック）があるか。

    gpt_result == "UNKNOWN" は Groq 呼び出し自体が失敗した合図であり、「GPTが安全と判定した」のではない。
    ここで外すと、判定できなかった投稿がそのまま緑色の「問題なし」として報告されてしまう。
    """
    return gpt_result in ("SUSPICIOUS", "UNKNOWN") or any(flag in reasons for flag in _CAUTION_FLAGS)


def _partly_failed(enforcement: Enforcement) -> bool:
    """措置の一部が失敗したか（消せなかった投稿がある・タイムアウトが断られた・外せないロールが残った）。"""
    timeout, stripped = enforcement.timeout, enforcement.stripped
    if enforcement.delete_failed:
        return True
    if timeout is not None and not timeout.ok:
        return True
    return stripped is not None and not stripped.ok


def outcome_heading(enforcement: Enforcement, caution: bool) -> Tuple[str, discord.Color]:
    """報告の見出しと色を、実際に取った措置から決める（rust-09 の S8）。

    危険で措置した → 赤「消して 24 時間のタイムアウト」（ロールを外したときは「消してロールを外した」）。
    スパムだけで措置した → 橙「消して 10 分のタイムアウト」（権限が無いときは「消した」）。見送った → 橙
    「措置を見送った（要確認）」。措置なしで注意の材料あり → 黄「記録だけ（注意の材料あり）」。何も無ければ緑。
    措置の一部が失敗したら、見出しに「（一部失敗）」を足す（中身は報告の項目に出す）。
    """
    if enforcement.action == "withheld":
        return "措置を見送った（要確認）", discord.Color.orange()
    if enforcement.action not in ("danger", "spam"):
        if caution:
            return "記録だけ（注意の材料あり）", discord.Color.gold()
        return "記録だけ（問題なし）", discord.Color.green()
    if enforcement.timeout is not None:
        title = f"消して {duration_text(enforcement.timeout.seconds)}のタイムアウト"
    elif enforcement.stripped is not None:
        title = "消してロールを外した"
    elif enforcement.vc_done:
        title = "消した（VC の荒らしで措置済み）"
    else:
        title = "消した"
    if _partly_failed(enforcement):
        title += "（一部失敗）"
    return title, discord.Color.red() if enforcement.action == "danger" else discord.Color.orange()


def build_final_embed(
    vt_results: List[Dict[str, Any]],
    gpt_result: str,
    reasons: List[str],
    logs: List[str],
    enforcement: Optional[Enforcement] = None,
) -> discord.Embed:
    """検査結果の総括 embed を組み立てる。

    色と見出しは、実際に取った措置（enforcement。無ければ措置なし）から決める（rust-09 の S8。outcome_heading）。
    判定の材料（VirusTotal・AI・スパム・新規・新しいアカウント）は、これまでどおり項目に並べる。

    Discord の上限（項目 25 個・説明 4096 文字・全体 6000 文字）に収める（rust-09 の (c)）。
    リンクの多い投稿は全部を走査するので、そのままだと上限を超え、Discord が送信ごと
    断って報告が届かなかった。走査の結果の項目は、GPT 判定と判定理由の項目を残して
    入るだけ並べ、残りは最後の 1 項目に「…他N件」で畳む。説明（ログの行）は、題・
    項目・足元を引いた残り（4096 文字まで）に収め、はみ出す行を「…他N行」で畳む。
    走査する数そのものは変えない。
    """
    title, color = outcome_heading(enforcement or Enforcement(), has_caution(reasons, gpt_result))

    tail = [(f"{gpt_icon(gpt_result)} GPT判定", f"結果: `{gpt_result}`")]
    if reasons:
        tail.append(("判定理由", " / ".join([reason_icon(r) + r for r in reasons])))
    fields = _target_fields(vt_results, EMBED_FIELD_COUNT_LIMIT - len(tail)) + tail
    footer = f"実行時間: {now_jst()}"

    # 説明に使えるのは、題・項目・足元を引いた残り（説明そのものの上限 4096 文字まで）。
    used = len(title) + len(footer) + sum(len(name) + len(value) for name, value in fields)
    budget = min(EMBED_DESCRIPTION_LIMIT, EMBED_TOTAL_LIMIT - used)
    description = _fold(logs, budget=budget, unit="行", joiner="\n")

    embed = discord.Embed(title=title, description=description, color=color)
    for name, value in fields:
        embed.add_field(name=name, value=value, inline=False)
    embed.set_footer(text=footer)
    return embed


# ==================================================
# メッセージセキュリティの各ステップ
# ==================================================
def _spam_logs(spam: SpamCheck) -> List[str]:
    """スパムのログの行（当たった条件ごとに 1 行。何の条件で・何回か。繰り返しはチャンネルの数も。S3）。"""
    logs: List[str] = []
    if spam.repeat:
        logs.append(
            f"スパム検出（同じ内容を{spam.repeat_count}回/{spam_detection.SPAM_REPEAT_WINDOW_SECONDS}秒、"
            f"{spam.repeat_channels}チャンネル）"
        )
    if spam.flood:
        logs.append(
            f"スパム検出（{spam.flood_count}回/{spam_detection.SPAM_FLOOD_WINDOW_SECONDS}秒、"
            f"最短間隔{spam.min_interval:.1f}秒）"
        )
    return logs


def _check_content_flags(spam: SpamCheck, content: str, links: List[str]) -> Tuple[List[str], List[str]]:
    """(reason_flags, logs) を返す（スパム・リンク数過多・ユニコードトリック）。"""
    reason_flags: List[str] = []
    logs = _spam_logs(spam)
    if spam.is_spam:
        reason_flags.append("SPAM")

    if len(links) >= MAX_LINKS:
        reason_flags.append("TOO_MANY_LINKS")
        logs.append("リンク数過多")

    if UNICODE_TRICK_REGEX.search(content):
        reason_flags.append("UNICODE_TRICK")
        logs.append("ユニコードトリック検出")

    return reason_flags, logs


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
    # セッションは使い回す（services/http_client.py）。制限時間はリクエストごとに
    # 渡す形へ移した（セッションへ焼き付けると使い回せない）。
    session = get_session()
    targets = links + [a.url for a in attachments]
    gate = asyncio.Semaphore(VT_SCAN_CONCURRENCY)
    done = 0

    async def scan_one(url: str) -> Dict[str, Any]:
        """1件スキャンして、終わるたびに進捗を1つ進める。"""
        nonlocal done, progress_msg
        async with gate:
            try:
                res = await vt_scan_target(session, url)
            except Exception as e:
                # 1件の予期しない失敗で、検査全体（GPT の判定・削除・剥奪・報告）を止めない。
                # 止めると、危険な投稿に「走査で落ちる URL」を混ぜるだけで素通りできてしまう
                # （壊れた URL で url_safety が ValueError を投げていたときに実際にそうなった）。
                # 走査できなかった件として扱い、印は「注意」になる（安全とは数えない）。
                logger.exception("[SECURITY] VirusTotal の走査で予期しない失敗 url=%s", url)
                res = {
                    "status": "error",
                    "type": "url",
                    "reason": f"scan_failed:{type(e).__name__}",
                    "malicious": 0,
                    "suspicious": 0,
                }
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

    スパムは danger に入れず spam に持つ（スパムだけなら消して 10 分のタイムアウト、危険なら 24 時間。S1・S2）。
    spam_posts はスパムと数えた投稿（チャンネル, メッセージ。消すもの）。vc_enforced は、VC の荒らしの経路で
    この人に措置済みか（二重に措置しない。S4）。
    """

    danger: bool
    reason_flags: List[str]
    vt_results: List[Dict[str, Any]]
    progress_msg: Optional[discord.Message]
    gpt_result: str
    spam_count: int
    spam: bool = False
    spam_posts: Tuple[Tuple[int, int], ...] = ()
    vc_enforced: bool = False


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


def _log_bypass(guild_id: int, member: discord.Member, reason: str, route: str) -> None:
    """バイパスで検査を飛ばしたことを、ログファイルに 1 行書く（rust-09 の S7）。

    以前はログチャンネルへ「セキュリティ検査スキップ」を出していた（管理者・信頼ユーザーの発言のたびに出て、
    ログチャンネルが埋まる）。いまはログファイル（security のカテゴリ）にだけ書く。理由は trusted_user・
    bypass_role・administrator。route は経路（メッセージか VC か）。
    """
    logger.info(
        "[SECURITY] 検査を飛ばしました（%s） 経路=%s guild=%s user=%s", reason or "bypass", route, guild_id, member.id
    )


async def _collect_findings(
    bot: discord.Client,
    guild_id: int,
    member: discord.Member,
    content: str,
    links: List[str],
    attachments: Sequence,
    logs: List[str],
    channel_id: int = 0,
    message_id: int = 0,
) -> _Findings:
    """スパム・リンク・VirusTotal・GPT・新規・新しいアカウント・VCレイドを順に見て、材料をそろえる。

    ここでは**判定するだけで、何も実行しない。** 消すかタイムアウトするかを決めるのは
    _enforce_or_withhold の仕事で、分けてあるのは「判定は正しいのに措置の
    条件だけ壊れている」状態をテストで切り分けられるようにするため。

    channel_id・message_id は、この投稿の場所（スパムと数えた投稿を、あとで消すために記録する）。
    """
    member_is_new = is_new_member(member)
    account_is_new = is_new_account(member)
    files = [(a.filename, a.size) for a in attachments]
    spam = check_spam(guild_id, member.id, channel_id, message_id, content, files)
    reason_flags, flag_logs = _check_content_flags(spam, content, links)
    logs.extend(flag_logs)

    # スパムは danger に入れない。スパムだけなら「消して 10 分のタイムアウト」（S2）、ここから下の危険な材料
    # （VirusTotal・GPT・VC の荒らし）があれば、そちらの「24 時間のタイムアウト」が勝つ（S1。重いほう）。
    vt_results, progress_msg, vt_flags, danger = await _run_vt_scans(bot, guild_id, links, attachments, logs)
    reason_flags.extend(vt_flags)

    gpt_result = await gpt_assess(
        content,
        vt_results,
        spam=spam,
        is_new_member=member_is_new,
        is_new_account=account_is_new,
    )
    reason_flags.append(f"GPT:{gpt_result}")
    logs.append(f"GPT判定: {gpt_result}")
    if gpt_result == "DANGEROUS":
        danger = True

    if member_is_new:
        reason_flags.append("NEW_MEMBER")
        logs.append("新規メンバー")
    if account_is_new:
        reason_flags.append("NEW_ACCOUNT")
        logs.append("新しいアカウント")

    # VC にいる人の発言は、VC の荒らしの記録に入れない（数えるのは VC への参加だけ。rust-09 の (e)）。
    # VC_RAID の印を付けるのは、その人自身が荒らしの数に入っている（入って間もない人として記録にある）ときだけ
    # （同じ VC にいるだけの常連は巻き込まない。S4）。VC の経路で措置済みなら、人への措置は二重にしない。
    vc_enforced = False
    if member.voice and member.voice.channel:
        voice_id = member.voice.channel.id
        if is_vc_raid_ongoing(voice_id, member.id):
            danger = True
            reason_flags.append("VC_RAID")
            logs.append("VCレイド検出")
            vc_enforced = was_enforced(voice_id, member.id)

    return _Findings(
        danger=danger,
        reason_flags=reason_flags,
        vt_results=vt_results,
        progress_msg=progress_msg,
        gpt_result=gpt_result,
        spam_count=spam.counted if spam.is_spam else spam.flood_count,
        spam=spam.is_spam,
        spam_posts=spam.posts,
        vc_enforced=vc_enforced,
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


async def delete_message(bot: discord.Client, channel_id: int, message_id: int) -> None:
    """投稿を ID で 1 件消す（スパムと数えた、前の投稿。discord.py の PartialMessage.delete）。"""
    await bot.get_partial_messageable(channel_id).get_partial_message(message_id).delete()


async def _delete_posts(
    bot: discord.Client, message: discord.Message, posts: Sequence[Tuple[int, int]]
) -> Tuple[int, int]:
    """投稿を 1 件ずつ消し、(消した数, 消せなかった数) を返す（S2）。

    検査している投稿は message.delete()（いまの作法）、前の投稿は ID で消す。既に消えていた（NotFound）なら
    消した数に入れて先へ進む（止めない）。ほかの失敗は記録して先へ進み、消せなかった数に入れる。
    """
    deleted = failed = 0
    for channel_id, message_id in posts:
        try:
            if (channel_id, message_id) == (message.channel.id, message.id):
                await message.delete()
            else:
                await delete_message(bot, channel_id, message_id)
        except discord.NotFound:
            logger.debug("[security] message already gone: %s/%s", channel_id, message_id)
        except discord.HTTPException as e:
            logger.warning("[security] message delete failed: %s", e)
            failed += 1
            continue
        deleted += 1
    return deleted, failed


async def _punish(member: discord.Member, seconds: int) -> Tuple[Optional[TimeoutResult], Optional[StripResult]]:
    """危険なときの、人への措置（S1）。タイムアウトの権限があれば seconds 秒のタイムアウト、無ければ全ロールを外す。

    タイムアウトが断られても、ロールを外すことは試さない（同じ理由で失敗する。失敗として報告する）。
    """
    if can_timeout(member.guild):
        return await timeout_member(member, seconds), None
    return None, await strip_roles(member)


async def _enforce_or_withhold(
    bot: discord.Client,
    message: discord.Message,
    guild_id: int,
    member: discord.Member,
    findings: _Findings,
    bypass: BypassResult,
    logs: List[str],
) -> Enforcement:
    """危険・スパムなら措置する。ただしバイパス判定に失敗しているなら見送る。取った措置を返す（報告に出す）。

    **見送りの判定を、削除・タイムアウト・剥奪より先に置くこと。** 順序を入れ替えると、
    設定を読めなかっただけでロールが消える。元に戻せない操作なので、
    ここは「分からないなら触らない」に倒す。

    危険（S1）: この投稿（とスパムと数えた投稿）を消し、24 時間のタイムアウト（権限が無ければ全ロールを外す）。
    VC の荒らしの経路で措置済みの人には、人への措置を二重にしない（消すだけ。S4）。
    スパムだけ（S2）: スパムと数えた投稿を消し、10 分のタイムアウト（権限が無ければ消すだけ）。
    """
    if not (findings.danger or findings.spam):
        return Enforcement()
    if bypass.check_failed:
        await _withhold_enforcement(bot, guild_id, member, findings, logs)
        return Enforcement("withheld")
    posts = list(findings.spam_posts)
    current = (message.channel.id, message.id)
    if current not in posts:
        posts.append(current)
    deleted, failed = await _delete_posts(bot, message, posts)
    if not findings.danger:
        timeout = await timeout_member(member, SECURITY_TIMEOUT_SPAM_SECONDS) if can_timeout(member.guild) else None
        return Enforcement("spam", deleted, failed, timeout)
    if findings.vc_enforced:
        return Enforcement("danger", deleted, failed, vc_done=True)
    timeout, stripped = await _punish(member, SECURITY_TIMEOUT_DANGER_SECONDS)
    return Enforcement("danger", deleted, failed, timeout, stripped)


async def _report_result(
    bot: discord.Client,
    guild_id: int,
    member: discord.Member,
    findings: _Findings,
    links: List[str],
    attachments: Sequence,
    logs: List[str],
    enforcement: Optional[Enforcement] = None,
) -> None:
    """検査結果を、ログチャンネルへだけ送る（テキストチャンネルには送らない）。

    最後の「メッセージセキュリティ検査」のログは、途中の送信・書き換えが
    どう失敗しても必ず出す。見出し・色・水準は取った措置から決め（措置したら ERROR。S8）、
    取った措置（見出し・消した投稿・タイムアウト・剥がしたロール）の項目を足す。
    """
    enforcement = enforcement or Enforcement()
    acted = enforcement.action != "none"
    level = "ERROR" if acted else "INFO"
    embed = build_final_embed(findings.vt_results, findings.gpt_result, findings.reason_flags, logs, enforcement)

    if links or attachments:
        if findings.progress_msg:
            try:
                await findings.progress_msg.edit(embed=embed)
            except Exception as e:
                # Discord の応答（HTTPException）だけでなく、通信の失敗（aiohttp の
                # ClientError・時間切れ）も受け止める。以前は HTTPException だけで、
                # 通信の失敗だとここで抜け、最後のログを出さずに終わっていた
                # （rust-09 の (h)。Rust は出していた）。
                logger.warning("[security] progress_msg edit failed: %s", e)
        else:
            await send_log_embed(bot, guild_id, level, embed)
    elif acted:
        await send_log_embed(bot, guild_id, "ERROR", embed)

    title, color = outcome_heading(enforcement, has_caution(findings.reason_flags, findings.gpt_result))
    fields = {
        "理由": ", ".join(findings.reason_flags) or "なし",
        "GPT判定": findings.gpt_result,
        "リンク数": str(len(links)),
        "スパム回数": str(findings.spam_count) if findings.spam_count > 1 else "なし",
        "措置": title,
    }
    fields.update(enforcement_fields(enforcement))
    try:
        await log_action(
            bot,
            guild_id,
            level,
            "メッセージセキュリティ検査",
            user=member,
            fields=fields,
            embed_color=color,
        )
    except Exception:
        logger.debug("log_action failed", exc_info=True)

    logger.info("[SECURITY] DANGER" if acted else "[SECURITY] SAFE")


async def handle_security_for_message(bot: discord.Client, message: discord.Message):
    """メッセージ1件に対する検査の入口。

    スパム・リンク過多・ユニコードトリック・VirusTotal・GPT判定・新規・
    新しいアカウント・VCレイドを順に確認し、危険と判定したら投稿を消して
    24 時間のタイムアウト（権限が無ければロール剥奪）、スパムだけなら消して
    10 分のタイムアウトを行う（rust-09 の S1・S2）。
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
        _log_bypass(guild_id, member, bypass.reason, "メッセージ")
        return
    if bypass.check_failed:
        logs.append("⚠️ バイパス判定に失敗（強制措置は行わない）")

    findings = await _collect_findings(
        bot, guild_id, member, content, links, attachments, logs, channel_id=message.channel.id, message_id=message.id
    )
    enforcement = await _enforce_or_withhold(bot, message, guild_id, member, findings, bypass, logs)
    await _report_result(bot, guild_id, member, findings, links, attachments, logs, enforcement)


# ==================================================
# VCセキュリティ
# ==================================================
async def _withhold_vc_raid(bot: discord.Client, member: discord.Member, channel: Any) -> None:
    """VC の荒らしの数に入ったが、その人のバイパス判定に失敗しているので措置しない（大きくログに残す）。

    メッセージ側と同じ扱い。判定できないまま、タイムアウトもロールの剥奪もしない。
    """
    logger.error(
        "[SECURITY] guild=%s user=%s VCレイドを検出しましたが、バイパス判定に"
        "失敗しているため措置を見送りました。手動で確認してください。",
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


async def _enforce_vc_raid(bot: discord.Client, member: discord.Member, channel: Any) -> None:
    """VC の荒らしの数に入った 1 人に、24 時間のタイムアウト（権限が無ければ全ロールを外す）をして報告する（S1）。"""
    timeout, stripped = await _punish(member, SECURITY_TIMEOUT_DANGER_SECONDS)
    # タイムアウトの結果・剥がした結果も出す（rust-09 の (i)・S1）。
    measure = enforcement_fields(Enforcement("danger", timeout=timeout, stripped=stripped))
    try:
        await log_action(
            bot,
            member.guild.id,
            "ERROR",
            "VCレイド検出",
            user=member,
            fields={"チャンネル": channel.mention, **measure},
            embed_color=discord.Color.red(),
        )
    except Exception:
        logger.debug("log_action failed on VC raid", exc_info=True)


async def handle_security_for_voice_join(
    bot: discord.Client,
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState,
) -> None:
    """VC参加時にレイド検出だけを行う入口（メッセージ検査とは別経路）。

    入って間もない人（is_fresh_joiner）の参加だけを数える（S4）。荒らしなら、数に入った全員（まだ措置して
    いない人。後から入った人も）に、最初に入った順で 24 時間のタイムアウト（権限が無ければロール剥奪）。
    バイパスの人は数えない（飛ばしたことはログファイルにだけ書く。S7）。
    バイパス判定に失敗した人は措置を見送り、人が確認できるよう大きくログに残す
    （handle_security_for_message と同じ方針。ほかの人への措置は止めない）。
    """
    if member.bot or member.guild is None:
        return

    if before.channel == after.channel or after.channel is None:
        return

    bypass = is_security_bypassed(member)
    if bypass.bypassed:
        _log_bypass(member.guild.id, member, bypass.reason, "VC")
        return

    channel = after.channel
    if not channel or not is_fresh_joiner(member):
        return
    for target, check_failed in check_vc_raid(member, channel.id, bypass.check_failed):
        if check_failed:
            await _withhold_vc_raid(bot, target, channel)
        else:
            await _enforce_vc_raid(bot, target, channel)
