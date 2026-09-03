"""ユーザー状態（user_state_service）の同期・自動修復まわり。

setup_events(bot) の巨大クロージャから、監査ログ照会・メンバー/BAN取得・
ギルド横断の同期・定期修復ループを切り出したもの。ここに集めた関数は
guild 単位のもの（_find_recent_audit_entry / _fetch_guild_*）を除いて
bot を明示引数に取る形にしてあり、nonlocal で書き換えていた「同期が
1回でも走ったか」のフラグと排他ロックだけが呼び出し側（events.state.EventState）
に残っている。
"""

from __future__ import annotations

import asyncio
import logging

import discord
from discord.ext.commands import Bot
from envutil import env_bool, env_float, env_int
from services.user_state_service import repair_user_state_integrity, sync_guild_user_states

logger = logging.getLogger(__name__)

# 環境変数の読み取りは envutil に一本化している（config.py と同じ方針）。
# 以前は int(os.getenv(...)) を直書きしていたため、値が空文字や数値以外だと
# インポート時に ValueError で bot 全体が起動しなかった。
_USER_STATE_SYNC_ON_READY = env_bool("USER_STATE_SYNC_ON_READY", True)
_USER_STATE_SYNC_DELAY_SECONDS = env_int("USER_STATE_SYNC_DELAY_SECONDS", 20, minimum=0)
_USER_STATE_SYNC_GUILD_PAUSE_SECONDS = env_float(
    "USER_STATE_SYNC_GUILD_PAUSE_SECONDS",
    1.0,
    minimum=0.0,
)
_USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD = env_int(
    "USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD",
    0,
    minimum=0,
)
_USER_STATE_AUTO_REPAIR_ENABLED = env_bool("USER_STATE_AUTO_REPAIR_ENABLED", True)
_USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS = env_int(
    "USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS",
    1800,
    minimum=300,
)
_USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS = env_int(
    "USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS",
    180,
    minimum=0,
)
_USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD = env_int(
    "USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD",
    50000,
    minimum=100,
)
_USER_STATE_AUTO_REPAIR_WRITE_EVENTS = env_bool("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", False)


async def _find_recent_audit_entry(
    guild: discord.Guild,
    *,
    action: discord.AuditLogAction,
    target_user_id: int,
    window_seconds: int = 20,
    retries: int = 2,
    retry_delay: float = 0.6,
) -> discord.AuditLogEntry | None:
    """BAN/kick等の実行者を、対象アクションの監査ログから追跡する。

    view_audit_log 権限が無ければ即Noneを返す。guild.audit_logsの呼び出し
    自体は権限が無くても403を投げるだけなので、事前にガードして無駄な
    例外送出とログ汚染を避ける。監査ログへの反映はDiscord側で数百ms〜数秒
    遅れることがあるため、初回で見つからなくても retry_delay を挟んで
    数回リトライする。window_seconds は、対象イベントとは無関係な、
    たまたま近い時刻に起きた別の同種アクションを取り違えないための枠。
    """
    me = guild.me
    if me is None or not me.guild_permissions.view_audit_log:
        return None

    for attempt in range(retries + 1):
        try:
            now_utc = discord.utils.utcnow()
            async for entry in guild.audit_logs(limit=10, action=action):
                target = getattr(entry, "target", None)
                if getattr(target, "id", None) != target_user_id:
                    continue

                created_at = getattr(entry, "created_at", None)
                if created_at is None:
                    continue

                age = (now_utc - created_at).total_seconds()
                if 0 <= age <= window_seconds:
                    return entry
        except Exception as e:
            logger.debug(
                "[BOT_SETUP] audit log lookup failed action=%s target=%s err=%s",
                action,
                target_user_id,
                e,
            )

        if attempt < retries:
            await asyncio.sleep(retry_delay)
    return None


async def _fetch_guild_members_for_sync(guild: discord.Guild) -> tuple[list[discord.Member], bool]:
    """fetch_membersはメンバー一覧を取るIntentが必要で、無いとForbiddenに
    なる。その場合はキャッシュ(guild.members)にフォールバックするが、
    キャッシュが全メンバーを含む保証は無いためfetched_all=Falseを返す。
    呼び出し側(_sync_user_state_all_guilds)はこのフラグでreconcile_missing
    （退出者の突き合わせ）を行うかどうかを決める——不完全な一覧のまま
    突き合わせると、実際にはまだいるメンバーを「退出した」と誤判定しかねない。
    """
    members: list[discord.Member] = []
    fetched_all = False
    fetch_limit = _USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD or None

    try:
        async for member in guild.fetch_members(limit=fetch_limit):
            members.append(member)
        fetched_all = fetch_limit is None
    except discord.Forbidden:
        logger.warning(
            "[BOT_SETUP] user_state sync: fetch_members forbidden guild=%s. Fallback to cache.",
            guild.id,
        )
        members = list(guild.members)
        fetched_all = False
    except Exception as e:
        logger.exception(
            "[BOT_SETUP] user_state sync: fetch_members error guild=%s err=%s",
            guild.id,
            e,
        )
        members = list(guild.members)
        fetched_all = False

    return members, fetched_all


async def _fetch_guild_bans_for_sync(guild: discord.Guild) -> list[discord.abc.User]:
    """_fetch_guild_members_for_syncと違い、Forbiddenでもキャッシュ代替が
    無い（BAN一覧はDiscord側にしか無く、ローカルキャッシュという概念が
    存在しないため）。取得できなければ空リストのまま諦め、そのギルドの
    BAN同期だけをスキップする。
    """
    users: list[discord.abc.User] = []
    try:
        async for entry in guild.bans(limit=None):
            users.append(entry.user)
    except discord.Forbidden:
        logger.warning(
            "[BOT_SETUP] user_state sync: bans forbidden guild=%s. Skip ban sync.",
            guild.id,
        )
    except Exception as e:
        logger.exception(
            "[BOT_SETUP] user_state sync: bans fetch error guild=%s err=%s",
            guild.id,
            e,
        )
    return users


_SYNC_TOTALS = ("members_seen", "bans_seen", "created", "updated", "left_reconciled", "events_written")


async def _sync_one_guild(
    guild,
    *,
    source: str,
    write_events_on_sync: bool,
    run_integrity_repair: bool,
) -> dict[str, int]:
    """1ギルドぶんを同期し、そのギルドの数を返す。

    整合性の修復は頼まれたときだけ回す。全行を走査するので、毎回の同期で
    回すと重い（逆に頼んだのに呼ばないと、壊れた行が何日も残る）。
    """
    members, fetched_all = await _fetch_guild_members_for_sync(guild)
    banned_users = await _fetch_guild_bans_for_sync(guild)

    stats = await sync_guild_user_states(
        guild_id=guild.id,
        members=members,
        banned_users=banned_users,
        source=source,
        reconcile_missing=fetched_all,
        write_events_on_sync=write_events_on_sync,
    )

    repair_stats: dict[str, int] = {}
    if run_integrity_repair:
        repair_stats = await repair_user_state_integrity(
            guild_id=guild.id,
            max_rows=_USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD,
        )

    logger.info(
        "[BOT_SETUP] user_state sync guild=%s source=%s members=%s bans=%s "
        "created=%s updated=%s left=%s events=%s fetched_all=%s "
        "repaired_rows=%s repaired_fixed=%s",
        guild.id,
        source,
        stats.get("members_seen", 0),
        stats.get("bans_seen", 0),
        stats.get("created", 0),
        stats.get("updated", 0),
        stats.get("left_reconciled", 0),
        stats.get("events_written", 0),
        fetched_all,
        repair_stats.get("rows_scanned", 0),
        repair_stats.get("rows_fixed", 0),
    )

    counted = {key: int(stats.get(key, 0)) for key in _SYNC_TOTALS}
    counted["repair_rows"] = int(repair_stats.get("rows_scanned", 0))
    counted["repair_fixed"] = int(repair_stats.get("rows_fixed", 0))
    return counted


def _log_sync_completed(source: str, totals: dict[str, int]) -> None:
    """終わりの1行。無人で回るので、あとから読めるのはここだけ。"""
    logger.info(
        "[BOT_SETUP] user_state sync completed source=%s members=%s bans=%s "
        "created=%s updated=%s left=%s events=%s repaired_rows=%s repaired_fixed=%s",
        source,
        totals["members_seen"],
        totals["bans_seen"],
        totals["created"],
        totals["updated"],
        totals["left_reconciled"],
        totals["events_written"],
        totals["repair_rows"],
        totals["repair_fixed"],
    )


async def _sync_user_state_all_guilds(
    bot: Bot,
    *,
    source: str,
    write_events_on_sync: bool,
    run_integrity_repair: bool,
    lock: asyncio.Lock,
) -> None:
    """全ギルドのメンバー/BAN状態を1つずつ順番に同期する。

    並行にせずギルドを1つずつ処理し、間に
    _USER_STATE_SYNC_GUILD_PAUSE_SECONDS の待機を挟むのは、
    fetch_members/bansのレート制限を避けるため。1ギルドの処理で例外が
    出ても他ギルドを止めないよう、ギルド単位でtry/exceptしている。
    lockで全体を囲むのは、on_ready起点の同期(_sync_user_state_on_ready)と
    定期修復ループ(_user_state_auto_repair_loop)が同時に走って同じDBへ
    二重に書き込むのを防ぐため。

    **待機は try の外**に置く。失敗したときだけ待たずに次へ行くと、調子が
    悪いときに限って最速で叩き続けることになる（レート制限に当たっている
    最中がまさにそれ）。
    """
    async with lock:
        logger.info(
            "[BOT_SETUP] user_state sync started source=%s guilds=%s",
            source,
            len(bot.guilds),
        )
        totals = dict.fromkeys((*_SYNC_TOTALS, "repair_rows", "repair_fixed"), 0)

        for guild in bot.guilds:
            try:
                counted = await _sync_one_guild(
                    guild,
                    source=source,
                    write_events_on_sync=write_events_on_sync,
                    run_integrity_repair=run_integrity_repair,
                )
                for key, value in counted.items():
                    totals[key] += value
            except Exception as e:
                logger.exception(
                    "[BOT_SETUP] user_state sync failed guild=%s source=%s err=%s",
                    guild.id,
                    source,
                    e,
                )

            if _USER_STATE_SYNC_GUILD_PAUSE_SECONDS > 0:
                await asyncio.sleep(_USER_STATE_SYNC_GUILD_PAUSE_SECONDS)

        _log_sync_completed(source, totals)


async def _sync_user_state_on_ready(bot: Bot, lock: asyncio.Lock) -> None:
    """起動直後は他の初期化処理と競合しやすいため、
    _USER_STATE_SYNC_DELAY_SECONDS だけ遅らせてから同期する。ここで例外を
    握りつぶす（re-raiseしない）のは、on_readyのasyncio.create_taskとして
    起動されるため、放置すると例外が「処理されなかったタスク例外」として
    ログに埋もれるだけで誰も拾わないため。
    """
    try:
        if _USER_STATE_SYNC_DELAY_SECONDS > 0:
            await asyncio.sleep(_USER_STATE_SYNC_DELAY_SECONDS)
        await _sync_user_state_all_guilds(
            bot,
            source="on_ready",
            write_events_on_sync=True,
            run_integrity_repair=True,
            lock=lock,
        )
    except Exception as e:
        logger.exception("[BOT_SETUP] user_state sync fatal error: %s", e)


async def _purge_abandoned_guild_settings(bot: Bot) -> None:
    """放棄されたギルドの設定を掃除する。失敗しても修復ループは止めない。

    消してよいのは「Bot がもう居ない」かつ「長く触られていない」ものだけ
    （判断は services/guild_retention.py）。**居るギルドは1つも渡さない**
    ——ここで渡す集合が空になると、現役のサーバーまで対象になる。

    掃除の失敗で定期修復ごと止めない。掃除は付随処理で、本筋は同期と修復の
    ほうである。
    """
    from services.guild_retention import purge_abandoned_guilds

    try:
        await purge_abandoned_guilds({guild.id for guild in bot.guilds})
    except Exception as e:
        logger.exception("[BOT_SETUP] 放棄ギルドの設定掃除に失敗: %s", e)


async def _user_state_auto_repair_loop(bot: Bot, lock: asyncio.Lock) -> None:
    """@tasks.loopではなく手書きのwhileループにしているのは、開始遅延
    (_USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS)を挟んでから無限ループに
    入る形が必要だったため。bot.is_closed()を見て自然に抜けるので、切断
    時は明示的なキャンセルをしなくても止まる。CancelledErrorだけは
    re-raiseし、後段のexcept Exceptionで「修復ループが異常終了した」扱いに
    しない——タスクをキャンセルする経路（プロセス終了時のイベントループの
    片付け等）が正しく機能するよう、キャンセル要求は必ず伝播させる。
    """
    try:
        if _USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS > 0:
            await asyncio.sleep(_USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS)
        while not bot.is_closed():
            await _sync_user_state_all_guilds(
                bot,
                source="auto_repair",
                write_events_on_sync=_USER_STATE_AUTO_REPAIR_WRITE_EVENTS,
                run_integrity_repair=True,
                lock=lock,
            )
            await _purge_abandoned_guild_settings(bot)
            await asyncio.sleep(_USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        logger.info("[BOT_SETUP] user_state auto_repair loop cancelled")
        raise
    except Exception as e:
        logger.exception("[BOT_SETUP] user_state auto_repair fatal error: %s", e)
