"""API 応答のキャッシュ。プロセス内（一次）と Valkey（二次）の2段。

■ なぜ2段なのか

WEB_WORKERS の既定は 2 で、ワーカーごとに別のプロセスが動く。一次だけだと同じ
問い合わせに対して**同じ DB クエリと同じ予測計算がワーカーの数だけ走り、期限が
切れる時刻もそれぞれずれる。** 二次を足すと、片方のワーカーが作った結果をもう
片方が使えるようになり、再起動をまたいでも残る。

一次を捨てて二次だけにしなかったのは、Valkey が落ちたときに「今までと同じ速さで
動き続ける」ようにするため。二次は無くても正しく動く層として足してある
（services/shared_cache.py の冒頭に、そこを守るための3つの決まりがある）。

■ 名前空間を渡さないと二次は使われない

namespace を省略した TTLCache は、今までと完全に同じプロセス内キャッシュとして
動く。二次に載せてよいかどうかは値の性質によるので（JSON にできるか、他の
ワーカーと共有して意味があるか）、既定で載せない側に倒してある。
"""

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

from services.shared_cache import SharedCache, shared_cache

T = TypeVar("T")


@dataclass
class _CacheItem(Generic[T]):
    value: T
    expires_at: float


class TTLCache(Generic[T]):
    def __init__(
        self,
        *,
        default_ttl_seconds: int,
        max_items: int = 256,
        namespace: Optional[str] = None,
        shared: Optional[SharedCache] = None,
    ):
        """0以下の ttl / 上限を1へ切り上げる。

        0 を許すと set() 直後の get() が必ず None になり、設定ミス
        （環境変数の解析漏れなど）でキャッシュが常に空のまま動き続け、
        気づきにくい。

        namespace を渡すと二次（Valkey）にも載せる。省略すると今までと同じ
        プロセス内だけのキャッシュになる。shared はテストのための差し替え口で、
        省略すると環境変数から作られた共有キャッシュを使う。
        """
        self.default_ttl_seconds = max(1, default_ttl_seconds)
        self.max_items = max(1, max_items)
        self.namespace = namespace
        self._data: OrderedDict[str, _CacheItem[T]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._shared = shared

    @property
    def shared(self) -> Optional[SharedCache]:
        """二次キャッシュ。namespace が無いときは None（一次だけで動く）。

        shared_cache() をコンストラクタで呼ばず、ここまで遅らせている。
        TTLCache は webapp/app.py の import 時に作られるので、そこで環境変数を
        読むと、テストが環境変数を差し替える前に確定してしまう。
        """
        if self.namespace is None:
            return None
        if self._shared is None:
            self._shared = shared_cache()
        return self._shared

    async def get(self, key: str) -> T | None:
        """期限切れは呼ばれたときに初めて掃除する（背景タイマーは無い）。

        アクセスされないまま期限切れになったキーはメモリに残り続ける。
        それを上限で刈るのが max_items の役目なので、ここでの遅延削除は
        max_items とセットで初めて安全になる。

        一次に無ければ二次を見る。二次で見つかったら一次へ書き戻す
        （同じワーカーが続けて同じ鍵を引くとき、毎回 Valkey へ行かせない）。
        """
        hit = await self._get_local(key)
        if hit is not None:
            return hit

        shared = self.shared
        if shared is None:
            return None
        value = await shared.get_json(self.namespace or "", key)
        if value is None:
            return None
        # 二次の残り時間は分からないので、一次には既定の TTL で入れる。
        # 二次より長く持つことはありうるが、どちらも「古い値を出しうる」
        # 前提の入れ物なので、ここを厳密にしても得るものが無い。
        await self._set_local(key, value, self.default_ttl_seconds)
        return value  # type: ignore[no-any-return]  # JSON から戻る値の型は保証できない

    async def set(self, key: str, value: T, ttl_seconds: int | None = None) -> None:
        """上限を超えたら、期限切れかどうかに関わらず最も古いアクセスから捨てる。

        LRU での間引きなので、まだ有効なキーでも溢れれば消える。

        一次へ書いてから二次へ書く。順番に意味がある。二次を先にすると、
        Valkey が固まっているあいだ一次にも入らないまま返ることになり、
        「キャッシュが無い場合より遅い」状態になる。
        """
        ttl = self.default_ttl_seconds if ttl_seconds is None else max(1, ttl_seconds)
        await self._set_local(key, value, ttl)
        shared = self.shared
        if shared is not None:
            await shared.set_json(self.namespace or "", key, value, ttl)

    async def clear(self) -> None:
        """全件を破棄する。TTL を待たず即座に古い値を見せたくない場面向け。

        二次も消す。**ここで二次を消し忘れると、価格を取り直したのに他の
        ワーカーが古い値を返し続ける。** clear() が呼ばれるのは日次の取得と
        予測の更新の直後で、まさに全ワーカーに新しい値を見せたい場面。
        """
        async with self._lock:
            self._data.clear()
        shared = self.shared
        if shared is not None:
            await shared.clear_namespace(self.namespace or "")

    async def _get_local(self, key: str) -> T | None:
        """一次キャッシュだけを見る。期限切れはその場で取り除く。"""
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

    async def _set_local(self, key: str, value: T, ttl: int) -> None:
        """一次キャッシュへ書き、上限を超えたぶんを古いアクセスから捨てる。"""
        expires_at = time.monotonic() + ttl
        async with self._lock:
            self._data[key] = _CacheItem(value=value, expires_at=expires_at)
            self._data.move_to_end(key)
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)
