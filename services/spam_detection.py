import time
from typing import Dict, List, Tuple

SPAM_REPEAT_THRESHOLD = 4
SPAM_TIME_WINDOW = 15

_user_message_times: Dict[tuple[int, int], List[float]] = {}
_cleanup_counter = 0
_CLEANUP_INTERVAL = 100


def _maybe_cleanup() -> None:
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter < _CLEANUP_INTERVAL:
        return
    _cleanup_counter = 0
    now = time.time()
    stale = [
        key for key, times in list(_user_message_times.items())
        if not any(now - t < SPAM_TIME_WINDOW for t in times)
    ]
    for key in stale:
        _user_message_times.pop(key, None)


def check_spam(guild_id: int, user_id: int) -> Tuple[bool, int, float]:
    """スパム判定。(スパムか, ウィンドウ内メッセージ数, 最短メッセージ間隔秒) を返す。"""
    now = time.time()
    key = (guild_id, user_id)
    history = _user_message_times.setdefault(key, [])
    history.append(now)
    history[:] = [t for t in history if now - t < SPAM_TIME_WINDOW]
    _maybe_cleanup()
    count = len(history)

    if len(history) >= 2:
        sorted_times = sorted(history)
        min_interval = min(
            sorted_times[i + 1] - sorted_times[i] for i in range(len(sorted_times) - 1)
        )
    else:
        min_interval = float("inf")

    return count >= SPAM_REPEAT_THRESHOLD, count, min_interval


def is_spam(guild_id: int, user_id: int) -> bool:
    result, _, _ = check_spam(guild_id, user_id)
    return result
