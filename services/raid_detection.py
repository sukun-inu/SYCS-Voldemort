import time
from typing import Dict, List, Tuple

import discord

VC_RAID_WINDOW_SEC = 20
VC_RAID_SIMILAR_PREFIX = 4
VC_RAID_THRESHOLD = 5

_vc_join_history: Dict[int, List[Tuple[float, str, int]]] = {}
_cleanup_counter = 0
_CLEANUP_INTERVAL = 50


def _maybe_cleanup() -> None:
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter < _CLEANUP_INTERVAL:
        return
    _cleanup_counter = 0
    now = time.time()
    stale = [
        cid for cid, history in list(_vc_join_history.items())
        if not any(now - h[0] < VC_RAID_WINDOW_SEC for h in history)
    ]
    for cid in stale:
        _vc_join_history.pop(cid, None)


def check_vc_raid(member: discord.Member, channel_id: int) -> bool:
    now = time.time()
    history = _vc_join_history.setdefault(channel_id, [])
    history.append((now, member.display_name[:VC_RAID_SIMILAR_PREFIX], member.id))
    history[:] = [h for h in history if now - h[0] < VC_RAID_WINDOW_SEC]
    _maybe_cleanup()

    name_counter: Dict[str, int] = {}
    for _, prefix, _ in history:
        name_counter[prefix] = name_counter.get(prefix, 0) + 1
        if name_counter[prefix] >= VC_RAID_THRESHOLD:
            return True
    return False
