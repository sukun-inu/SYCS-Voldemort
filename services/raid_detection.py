"""VC の荒らし（入って間もない人が、続けて同じ VC に入る）を数える（rust-09 の S4。本人の決定 2026-11-28）。

以前は、チャンネルごとに 20 秒に表示名の先頭 4 文字が同じ参加が 5 回で荒らしにしていた（同じ人の入り直しも、
同じ VC にいるだけの常連も数えた）。いまは名前を見ず、「入って間もない人」（security_service.is_fresh_joiner。
呼ぶ側が決める）の参加だけを記録する。同じ VC に VC_RAID_WINDOW_SECONDS 秒（既定 20）の間に、入って間もない人が
VC_RAID_THRESHOLD 人（既定 5）入ったら荒らし。同じ人は何度入り直しても 1 人。

当たったら、数に入った全員に措置する（措置は呼ぶ側）。同じ窓の中で後から入った人にも措置し、同じ人に二度は
措置しない（措置した人を、措置してから VC_RAID_WINDOW_SECONDS 秒覚える）。

**記録に入れるのは VC への参加だけ**（rust-09 の (e)）。メッセージの検査（VC にいる人の発言）は、記録を足さずに
is_vc_raid_ongoing・was_enforced で見る。
"""

import time
from typing import Any, Dict, List, Tuple

from envutil import env_int

VC_RAID_WINDOW_SECONDS = env_int("VC_RAID_WINDOW_SECONDS", 20, minimum=1)
VC_RAID_THRESHOLD = env_int("VC_RAID_THRESHOLD", 5, minimum=2)
# 「入って間もない人」とみなす、サーバーに入ってからの時間（もう 1 つの条件は、アカウントを作ってからの日数。
# content_moderation.NEW_ACCOUNT_THRESHOLD_DAYS）。
VC_RAID_NEW_JOIN_HOURS = env_int("VC_RAID_NEW_JOIN_HOURS", 24, minimum=1)

# チャンネル → (参加の時刻, ユーザー ID, メンバー, バイパスの判定に失敗したか)。入って間もない人の参加だけ。
_vc_join_history: Dict[int, List[Tuple[float, int, Any, bool]]] = {}
# チャンネル → {ユーザー ID: 措置した時刻}（同じ人に二度措置しない）。
_vc_enforced: Dict[int, Dict[int, float]] = {}
_cleanup_counter = 0
_CLEANUP_INTERVAL = 50


def _maybe_cleanup() -> None:
    """呼び出し _CLEANUP_INTERVAL 回に1回だけ、直近ウィンドウ内に参加の記録も措置の覚えも無い
    チャンネルを間引く。毎回の参加のたびに全チャンネルを見るのは無駄なので頻度を落としている。
    """
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter < _CLEANUP_INTERVAL:
        return
    _cleanup_counter = 0
    now = time.time()
    for cid, history in list(_vc_join_history.items()):
        if not any(now - h[0] < VC_RAID_WINDOW_SECONDS for h in history):
            _vc_join_history.pop(cid, None)
    for cid, done in list(_vc_enforced.items()):
        if not any(now - at < VC_RAID_WINDOW_SECONDS for at in done.values()):
            _vc_enforced.pop(cid, None)


def _counted(history: List[Tuple[float, int, Any, bool]], now: float) -> Dict[int, Tuple[Any, bool]]:
    """直近 VC_RAID_WINDOW_SECONDS 秒の記録で数に入る人（ユーザー ID → (メンバー, バイパスの判定に失敗したか)）。

    同じ人は 1 人（並びは最初に入った順、中身はいちばん新しい参加のもの）。
    """
    people: Dict[int, Tuple[Any, bool]] = {}
    for at, user_id, member, check_failed in history:
        if now - at < VC_RAID_WINDOW_SECONDS:
            people[user_id] = (member, check_failed)
    return people


def check_vc_raid(member: Any, channel_id: int, check_failed: bool = False) -> List[Tuple[Any, bool]]:
    """入って間もない人の VC への参加を 1 回記録して判定する。

    荒らし（直近 VC_RAID_WINDOW_SECONDS 秒に、入って間もない人が VC_RAID_THRESHOLD 人以上）なら、数に入った
    人のうち、まだ措置していない人を、最初に入った順に (メンバー, バイパスの判定に失敗したか) で返す（返した人は
    措置済みとして覚える）。荒らしでなければ空。

    **VC への参加のとき（handle_security_for_voice_join）だけ、入って間もない人について呼ぶこと。**
    メッセージの検査は、記録を足さない is_vc_raid_ongoing・was_enforced を使う。
    """
    now = time.time()
    history = _vc_join_history.setdefault(channel_id, [])
    history.append((now, member.id, member, check_failed))
    history[:] = [h for h in history if now - h[0] < VC_RAID_WINDOW_SECONDS]
    _maybe_cleanup()
    people = _counted(history, now)
    if len(people) < VC_RAID_THRESHOLD:
        return []
    done = _vc_enforced.setdefault(channel_id, {})
    for user_id in [u for u, at in done.items() if now - at >= VC_RAID_WINDOW_SECONDS]:
        del done[user_id]
    targets = [entry for user_id, entry in people.items() if user_id not in done]
    for user_id in people:
        done.setdefault(user_id, now)
    return targets


def is_vc_raid_ongoing(channel_id: int, user_id: int) -> bool:
    """記録を足さずに、そのチャンネルがいま荒らしの形で、その人自身が数に入っているかを見る。

    数え方は check_vc_raid と同じ。メッセージの検査（VC にいる人の発言）から呼ぶ。発言は数えない。
    同じ VC にいるだけの、入って間もなくない人は数に入らないので、ここで偽になる（S4）。
    """
    people = _counted(_vc_join_history.get(channel_id, []), time.time())
    return len(people) >= VC_RAID_THRESHOLD and user_id in people


def was_enforced(channel_id: int, user_id: int) -> bool:
    """その人に、VC の荒らしの経路で措置済みか（措置してから VC_RAID_WINDOW_SECONDS 秒の間）。"""
    at = _vc_enforced.get(channel_id, {}).get(user_id)
    return at is not None and time.time() - at < VC_RAID_WINDOW_SECONDS
