import time
from typing import Dict, List, Tuple

import discord

VC_RAID_WINDOW_SEC = 20
VC_RAID_SIMILAR_PREFIX = 4
VC_RAID_THRESHOLD = 5

# チャンネル → (参加の時刻, 表示名の先頭, ユーザー ID)。**VC への参加だけを入れる。**
# VC にいる人の発言は入れない（rust-09 の (e)。以前はメッセージの検査も check_vc_raid
# を呼んで発言を参加と同じ記録に積んでいたので、VC の中で 20 秒に 5 回発言すると
# VC の荒らし扱いになり、消して剥がしていた）。
_vc_join_history: Dict[int, List[Tuple[float, str, int]]] = {}
_cleanup_counter = 0
_CLEANUP_INTERVAL = 50


def _maybe_cleanup() -> None:
    """呼び出し _CLEANUP_INTERVAL 回に1回だけ、直近ウィンドウ内に参加履歴が
    無いチャンネルのエントリを間引く。毎回の参加のたびに全チャンネルを
    スキャンするのは無駄なので頻度を落としている。
    """
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter < _CLEANUP_INTERVAL:
        return
    _cleanup_counter = 0
    now = time.time()
    stale = [
        cid
        for cid, history in list(_vc_join_history.items())
        if not any(now - h[0] < VC_RAID_WINDOW_SEC for h in history)
    ]
    for cid in stale:
        _vc_join_history.pop(cid, None)


def _has_raid(history: List[Tuple[float, str, int]], now: float) -> bool:
    """直近 VC_RAID_WINDOW_SEC 秒以内の記録に、先頭が同じ名前が VC_RAID_THRESHOLD 回以上あるか。"""
    name_counter: Dict[str, int] = {}
    for at, prefix, _ in history:
        if now - at >= VC_RAID_WINDOW_SEC:
            continue
        name_counter[prefix] = name_counter.get(prefix, 0) + 1
        if name_counter[prefix] >= VC_RAID_THRESHOLD:
            return True
    return False


def check_vc_raid(member: discord.Member, channel_id: int) -> bool:
    """VC への参加を 1 回記録して判定する。直近 VC_RAID_WINDOW_SEC 秒以内に、表示名の先頭
    VC_RAID_SIMILAR_PREFIX 文字が同じユーザーが VC_RAID_THRESHOLD 人
    以上参加していたら True（レイド荒らしはボットアカウントで似た
    名前を連番にすることが多いため、完全一致ではなく先頭一致で見る）。

    **VC への参加のとき（handle_security_for_voice_join）だけ呼ぶこと。**
    メッセージの検査は記録を足さない is_vc_raid_ongoing を使う。
    """
    now = time.time()
    history = _vc_join_history.setdefault(channel_id, [])
    history.append((now, member.display_name[:VC_RAID_SIMILAR_PREFIX], member.id))
    history[:] = [h for h in history if now - h[0] < VC_RAID_WINDOW_SEC]
    _maybe_cleanup()
    return _has_raid(history, now)


def is_vc_raid_ongoing(channel_id: int) -> bool:
    """記録を足さずに、そのチャンネルへの参加の記録が、いま荒らしの形になっているかを見る。

    数え方は check_vc_raid と同じ（直近 VC_RAID_WINDOW_SEC 秒・先頭
    VC_RAID_SIMILAR_PREFIX 文字・VC_RAID_THRESHOLD 回）。メッセージの検査
    （VC にいる人の発言）から呼ぶ。発言は数えない。
    """
    return _has_raid(_vc_join_history.get(channel_id, []), time.time())
