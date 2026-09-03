"""ギルドのデータをいつ消すか。

■ 方針

**消すのは利用者が決める。** 管理画面の「このサーバーのデータを削除」で、
設定と監査履歴をまとめて消す。使っている限り、何年経っても勝手には消えない。

自動で消すのは**放棄されたものだけ**である。

    Bot がもう そのギルドに居ない   かつ   最終更新から10年

片方だけでは足りない。Bot が居ないだけなら「一時的に外して戻す」運用で
設定が消えるし、10年経っただけなら「設定して放置しているが現役」の
サーバーが初期化される。

■ 触られた時刻が無い設定

この仕組みを入れる前から在る設定には時刻が無い。**無いものを「ずっと前」
と読んではいけない**——読むと、既存の設定が条件を満たした瞬間に一斉に
消える。時刻が無いものは消さず、次に何か書き換えられた時点で時刻が入る。

■ まとめて消す、の範囲

利用者が消すときは、そのギルドについて残っているものを全部消す。

    settings.json のギルド設定
    ユーザー状態の監査履歴（UserStateEvent / UserStateCurrent）

監査履歴だけを別に消す口は作らない。「このサーバーのデータを消したい」と
思った人に、消し残しがあることを覚えていてもらう作りにしないため。
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from envutil import env_int
from services.settings_store import awrite, delete_guild_settings, known_guild_ids, touched_at

logger = logging.getLogger(__name__)

# 放棄と見なすまでの日数。ユーザー状態の履歴（USER_STATE_RETENTION_DAYS）と
# 同じ既定にしてある。
ABANDONED_AFTER_DAYS = env_int("GUILD_SETTINGS_ABANDONED_AFTER_DAYS", 3650, minimum=1)


def _parse(stamp: str | None) -> datetime | None:
    """ISO 8601 の時刻を読む。読めなければ None（＝消さない側へ倒す）。"""
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_abandoned(guild_id: int, *, present: bool, now: datetime | None = None) -> bool:
    """そのギルドの設定を自動で消してよいか。

    present は「Bot がいまそのギルドに居るか」。居るなら何年経っていても
    消さない（設定して放置しているだけの現役サーバーがある）。

    時刻が読めないものも消さない。**無いものを「ずっと前」と読むと、
    既存の設定が一斉に消える。**
    """
    if present:
        return False
    stamp = _parse(touched_at(guild_id))
    if stamp is None:
        return False
    limit = (now or datetime.now(timezone.utc)) - timedelta(days=ABANDONED_AFTER_DAYS)
    return stamp < limit


async def delete_guild_data(guild_id: int) -> dict[str, int]:
    """1ギルドぶんのデータを、残っているところ全部から消す。

    利用者が自分で消すための口。**監査履歴も一緒に消す**——別々の口に
    すると、消したつもりの人に消し残しを覚えていてもらうことになる。

    監査履歴の削除に失敗しても設定は消す（逆にすると、設定を消せない
    かぎり履歴も消せなくなる）。何をいくつ消したかを返し、呼び出し側が
    画面とログに出せるようにしてある。
    """
    from services.user_state_service import delete_guild_user_states

    removed = {"settings": 0, "events": 0, "states": 0}
    try:
        counts = await delete_guild_user_states(guild_id)
        removed["events"] = counts.get("events", 0)
        removed["states"] = counts.get("states", 0)
    except Exception:
        logger.exception("[retention] 監査履歴を消せませんでした guild=%s（設定は消します）", guild_id)

    # 設定の書き込みはファイルロックを取る。async から直に呼ぶと、待つあいだ
    # このプロセスのイベントループ全体が止まる（awrite の docstring 参照）。
    removed["settings"] = 1 if await awrite(delete_guild_settings, guild_id) else 0
    logger.warning(
        "[retention] ギルドのデータを削除 guild=%s 設定=%d 履歴=%d 現在状態=%d",
        guild_id,
        removed["settings"],
        removed["events"],
        removed["states"],
    )
    return removed


async def purge_abandoned_guilds(present_guild_ids: set[int]) -> list[int]:
    """放棄されたギルドの設定を掃除する。消したギルドIDを返す。

    present_guild_ids は Bot がいま居るギルド。**居るものは1つも消さない。**
    掃除は設定だけを対象にする——監査履歴には別の保管期間があり
    （USER_STATE_RETENTION_DAYS）、そちらの掃除が持っている。
    """
    now = datetime.now(timezone.utc)
    removed: list[int] = []
    for guild_id in known_guild_ids():
        if not is_abandoned(guild_id, present=guild_id in present_guild_ids, now=now):
            continue
        if await awrite(delete_guild_settings, guild_id):
            removed.append(guild_id)

    if removed:
        logger.warning(
            "[retention] %d年以上触られていない退出済みギルドの設定を削除 guilds=%s",
            ABANDONED_AFTER_DAYS // 365,
            removed,
        )
    return removed
