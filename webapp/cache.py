import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass
class _CacheItem(Generic[T]):
    value: T
    expires_at: float


class TTLCache(Generic[T]):
    def __init__(self, *, default_ttl_seconds: int, max_items: int = 256):
        """0以下の ttl / 上限を1へ切り上げる。

        0 を許すと set() 直後の get() が必ず None になり、設定ミス
        （環境変数の解析漏れなど）でキャッシュが常に空のまま動き続け、
        気づきにくい。
        """
        self.default_ttl_seconds = max(1, default_ttl_seconds)
        self.max_items = max(1, max_items)
        self._data: OrderedDict[str, _CacheItem[T]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> T | None:
        """期限切れは呼ばれたときに初めて掃除する（背景タイマーは無い）。

        アクセスされないまま期限切れになったキーはメモリに残り続ける。
        それを上限で刈るのが max_items の役目なので、ここでの遅延削除は
        max_items とセットで初めて安全になる。
        """
        now = time.monotonic()
        async with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            if item.expires_at <= now:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return item.value

    async def set(self, key: str, value: T, ttl_seconds: int | None = None) -> None:
        """上限を超えたら、期限切れかどうかに関わらず最も古いアクセスから捨てる。

        LRU での間引きなので、まだ有効なキーでも溢れれば消える。
        """
        ttl = self.default_ttl_seconds if ttl_seconds is None else max(1, ttl_seconds)
        expires_at = time.monotonic() + ttl
        async with self._lock:
            self._data[key] = _CacheItem(value=value, expires_at=expires_at)
            self._data.move_to_end(key)
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)

    async def clear(self) -> None:
        """全件を破棄する。TTL を待たず即座に古い値を見せたくない場面向け。"""
        async with self._lock:
            self._data.clear()
