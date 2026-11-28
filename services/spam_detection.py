"""同じ人の投稿を数えて、スパムかどうかを決める（rust-09 の S3。本人の決定 2026-11-28）。

以前は、同じ人の投稿を内容を見ずに、サーバー全体で 15 秒に 4 回でスパムにしていた。いまは 2 つの条件に分ける:

- 繰り返し: 同じ内容を SPAM_REPEAT_WINDOW_SECONDS 秒（既定 60）に SPAM_REPEAT_COUNT 回（既定 3）。チャンネルを
  またいでも数える（3 つのチャンネルに 1 回ずつでも 3 回）。何チャンネルにまたがったかも返す
- 量: 内容が違っても SPAM_FLOOD_WINDOW_SECONDS 秒（既定 10）に SPAM_FLOOD_COUNT 回（既定 8）

数える単位は、いまどおり（サーバー, 人）。「同じ内容」は content_key で比べる。本文も添付も空（スタンプだけなど）の
投稿は、繰り返しには数えず、量にだけ数える。

スパムと数えた投稿（チャンネル, メッセージ）は SpamCheck.posts で返す（呼ぶ側が 1 件ずつ消す。S2）。一度返した
投稿は二度返さない（消し直さない。消えた投稿を何度も消しに行くと、Discord に無効な要求として数えられる）が、
回数には数え続ける（スパムを続ける人の次の投稿を、すぐスパムにするため）。
"""

import time
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from envutil import env_int

# 繰り返し: 同じ内容を、この秒数の中でこの回数（この投稿を含む）。
SPAM_REPEAT_COUNT = env_int("SPAM_REPEAT_COUNT", 3, minimum=2)
SPAM_REPEAT_WINDOW_SECONDS = env_int("SPAM_REPEAT_WINDOW_SECONDS", 60, minimum=1)
# 量: 内容を問わず、この秒数の中でこの回数（この投稿を含む）。
SPAM_FLOOD_COUNT = env_int("SPAM_FLOOD_COUNT", 8, minimum=2)
SPAM_FLOOD_WINDOW_SECONDS = env_int("SPAM_FLOOD_WINDOW_SECONDS", 10, minimum=1)

# 同じ内容かを比べる鍵（揃えた本文, （ファイル名, 大きさ）の並び）。
ContentKey = Tuple[str, Tuple[Tuple[str, int], ...]]


@dataclass
class _Post:
    """記録した投稿 1 件。taken は、スパムと数えて一度返したか（二度は返さない）。"""

    at: float
    channel_id: int
    message_id: int
    key: Optional[ContentKey]
    taken: bool = False


class SpamCheck(NamedTuple):
    """スパムの判定の結果。既定の値は「スパムではない、この投稿 1 件だけ」。

    - repeat・repeat_count・repeat_channels: 繰り返しの条件に当たったか、同じ内容の回数（この投稿を含む。
      本文も添付も空なら 0）、またがったチャンネルの数
    - flood・flood_count: 量の条件に当たったか、量の窓の中の回数（この投稿を含む）
    - min_interval: 量の窓の中の、いちばん短い間隔（秒。1 回だけなら無限大）
    - counted: スパムと数えた投稿の数（当たった条件の投稿を合わせたもの。スパムでなければ 0）
    - posts: 今回はじめてスパムと数えた投稿（チャンネル, メッセージ）。記録の順（この投稿は最後）
    """

    repeat: bool = False
    flood: bool = False
    repeat_count: int = 0
    repeat_channels: int = 0
    flood_count: int = 1
    min_interval: float = float("inf")
    counted: int = 0
    posts: Tuple[Tuple[int, int], ...] = ()

    @property
    def is_spam(self) -> bool:
        """どちらかの条件に当たったか。"""
        return self.repeat or self.flood


_user_posts: Dict[Tuple[int, int], List[_Post]] = {}
_cleanup_counter = 0
_CLEANUP_INTERVAL = 100


def _keep_seconds() -> int:
    """記録を覚えておく秒数（2 つの窓の長いほう）。"""
    return max(SPAM_REPEAT_WINDOW_SECONDS, SPAM_FLOOD_WINDOW_SECONDS)


def _maybe_cleanup() -> None:
    """呼び出し _CLEANUP_INTERVAL 回に1回だけ、覚えておく秒数の中に投稿が無い人の記録を間引く。
    投稿のたびに全員を見るのは無駄なので頻度を落としている。
    """
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter < _CLEANUP_INTERVAL:
        return
    _cleanup_counter = 0
    now = time.time()
    keep = _keep_seconds()
    stale = [key for key, posts in list(_user_posts.items()) if not any(now - p.at < keep for p in posts)]
    for key in stale:
        _user_posts.pop(key, None)


def content_key(content: str, attachments: Sequence[Tuple[str, int]]) -> Optional[ContentKey]:
    """同じ内容かを比べる鍵。本文も添付も空なら None（繰り返しには数えない）。

    本文は NFKC にして casefold し、空白の並びを 1 つに縮めて前後を落とす（全角と半角・大文字と小文字・
    空白の打ち方だけが違う投稿を同じ内容にする）。添付は（ファイル名, 大きさ）の並び。本文と添付の
    両方が同じなら同じ内容。
    """
    text = " ".join(unicodedata.normalize("NFKC", content or "").casefold().split())
    files = tuple((str(name), int(size)) for name, size in attachments)
    if not text and not files:
        return None
    return text, files


def check_spam(
    guild_id: int,
    user_id: int,
    channel_id: int,
    message_id: int,
    content: str,
    attachments: Sequence[Tuple[str, int]],
) -> SpamCheck:
    """投稿を 1 件記録して、スパムかどうかを返す（繰り返しと量の 2 つの条件。モジュールの説明を参照）。

    attachments は（ファイル名, 大きさ）の並び。スパムと数えた投稿のうち、まだ返していないものを posts で返す。
    """
    now = time.time()
    key = content_key(content, attachments)
    history = _user_posts.setdefault((guild_id, user_id), [])
    history.append(_Post(now, channel_id, message_id, key))
    keep = _keep_seconds()
    history[:] = [p for p in history if now - p.at < keep]
    _maybe_cleanup()

    flood = [p for p in history if now - p.at < SPAM_FLOOD_WINDOW_SECONDS]
    same = [p for p in history if key is not None and p.key == key and now - p.at < SPAM_REPEAT_WINDOW_SECONDS]
    is_flood = len(flood) >= SPAM_FLOOD_COUNT
    is_repeat = len(same) >= SPAM_REPEAT_COUNT
    chosen = {id(p) for p in flood} if is_flood else set()
    if is_repeat:
        chosen |= {id(p) for p in same}
    counted = [p for p in history if id(p) in chosen]
    fresh = [p for p in counted if not p.taken]
    for p in fresh:
        p.taken = True

    times = sorted(p.at for p in flood)
    min_interval = min((b - a for a, b in zip(times, times[1:])), default=float("inf"))
    return SpamCheck(
        repeat=is_repeat,
        flood=is_flood,
        repeat_count=len(same),
        repeat_channels=len({p.channel_id for p in same}),
        flood_count=len(flood),
        min_interval=min_interval,
        counted=len(counted),
        posts=tuple((p.channel_id, p.message_id) for p in fresh),
    )
