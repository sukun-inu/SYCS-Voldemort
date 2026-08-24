"""期限つきキャッシュ。

読み出し時に期限を見るだけで追い出しを行わないキャッシュが各所にあり、鍵の空間が
広いもの（地震のイベント単位、ニュース記事の URL 単位、利用者単位）はプロセスを
動かし続けるほど増え続けていた。1つずつ場当たりに直すと同じ抜けが再発するので、
この小さな入れ物に寄せる。

スレッド安全ではない。イベントループ上からの利用を想定している。
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Generic, TypeVar

_K = TypeVar("_K")
_V = TypeVar("_V")


class TTLCache(Generic[_K, _V]):
    """期限と件数の両方に上限があるキャッシュ。

    件数の上限を超えたら、最後に使われたのが古いものから捨てる。
    期限切れは読み出し時にも取り除くので、放置しても膨らまない。
    """

    def __init__(self, *, ttl: float, max_entries: int) -> None:
        if ttl <= 0:
            raise ValueError("ttl は正の秒数で指定してください。")
        if max_entries <= 0:
            raise ValueError("max_entries は 1 以上で指定してください。")
        self.ttl = float(ttl)
        self.max_entries = int(max_entries)
        self._items: OrderedDict[_K, tuple[_V, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: _K) -> bool:
        return self.get(key) is not None

    def get(self, key: _K) -> _V | None:
        entry = self._items.get(key)
        if entry is None:
            return None
        value, stored_at = entry
        if time.time() - stored_at >= self.ttl:
            self._items.pop(key, None)
            return None
        self._items.move_to_end(key)
        return value

    def set(self, key: _K, value: _V) -> None:
        self._items[key] = (value, time.time())
        self._items.move_to_end(key)
        self._evict()

    def pop(self, key: _K) -> _V | None:
        entry = self._items.pop(key, None)
        return None if entry is None else entry[0]

    def clear(self) -> None:
        self._items.clear()

    def _evict(self) -> None:
        now = time.time()
        # 期限切れをまとめて落とす（古い順に並んでいるとは限らないので全体を見る）
        expired = [k for k, (_, at) in self._items.items() if now - at >= self.ttl]
        for key in expired:
            self._items.pop(key, None)
        # それでも多いときは、使われていない順に捨てる
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)
