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
        self.default_ttl_seconds = max(1, default_ttl_seconds)
        self.max_items = max(1, max_items)
        self._data: OrderedDict[str, _CacheItem[T]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> T | None:
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
        ttl = self.default_ttl_seconds if ttl_seconds is None else max(1, ttl_seconds)
        expires_at = time.monotonic() + ttl
        async with self._lock:
            self._data[key] = _CacheItem(value=value, expires_at=expires_at)
            self._data.move_to_end(key)
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

