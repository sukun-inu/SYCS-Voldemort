"""公開 API のレート制限を全ワーカーで共有する部分のテスト。

    python -m unittest tests.test_shared_rate_limit -v

■ なぜこのファイルがあるか

`WEB_WORKERS` の既定は 2 で、ワーカーごとに別プロセスが動く。レート制限を
プロセス内の deque で数えていたので、**上限が実質2倍通っていた。** 数え場所を
Valkey へ移したが、レート制限は緩めても気づかない（誰も 429 を報告してこない）
種類の機能なので、ここで固定しておく以外に守る方法が無い。

■ 何を守っているか

  1. 別のワーカー（別インスタンス）が数えた件数が合算されること
  2. 上限を超えたら 429、超えていなければ通ること（境界の1件ずれが無いこと）
  3. **断ったリクエストを窓に残さないこと**（残すと、叩き続けている相手が
     いつまでも解除されない）
  4. Valkey が落ちたらプロセス内の計数へ落ちること（＝制限が消えないこと）
  5. 移動窓であること（固定窓だと、窓の切り替わりで上限の2倍通せる）
  6. `/api/` 以外は数えないこと
  7. calculate だけ別枠であること

実 Valkey へは接続しない。tests/test_shared_cache.py の FakeValkey を使う。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # noqa: E402

from services import shared_cache as shared_cache_module  # noqa: E402
from tests.test_shared_cache import FakeValkey, QuietSharedCacheLog, make_cache  # noqa: E402
from webapp.security import RateLimitMiddleware  # noqa: E402


class _FakeRequest:
    """レート制限が見るところだけを持つ、最小の偽リクエスト。"""

    def __init__(self, path: str, host: str = "203.0.113.10") -> None:
        """パスと接続元を持つ。"""
        self.url = type("URL", (), {"path": path})()
        self.client = type("Client", (), {"host": host})()
        self.headers: dict[str, str] = {}


async def _pass_through(_request):
    """次のミドルウェアの代わり。200 を返したことにする。"""
    return type("Response", (), {"status_code": 200})()


def make_middleware(**kwargs) -> RateLimitMiddleware:
    """レート制限ミドルウェアを作る。上限を小さくして境界を試しやすくする。"""
    defaults = {
        "requests_per_window": 3,
        "calculate_requests_per_window": 2,
        "window_seconds": 60,
        "trust_cf_headers": False,
    }
    defaults.update(kwargs)
    return RateLimitMiddleware(None, **defaults)  # type: ignore[arg-type]  # app は使わない


class SharedRateLimitTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """Valkey で数えるときの振る舞い。"""

    def setUp(self) -> None:
        """偽 Valkey を共有キャッシュとして差し込む。"""
        super().setUp()
        self.fake = FakeValkey()
        shared_cache_module.set_shared_cache(make_cache(self.fake))

    def tearDown(self) -> None:
        """差し込みを戻す（他のテストへ持ち越さない）。"""
        shared_cache_module.set_shared_cache(None)
        super().tearDown()

    async def _hit(self, middleware, path="/api/prices", host="203.0.113.10"):
        """1リクエスト分だけ通して、返ってきた status_code を返す。"""
        response = await middleware.dispatch(_FakeRequest(path, host), _pass_through)
        return response.status_code

    async def test_requests_up_to_the_limit_pass(self):
        """上限ぴったりまでは通ること。

        ここが1件ずれると、上限3のはずが2件で断られる（利用者から見ると
        「使えない」）。
        """
        middleware = make_middleware(requests_per_window=3)
        for i in range(3):
            self.assertEqual(await self._hit(middleware), 200, f"{i + 1} 件目")

    async def test_one_over_the_limit_is_refused(self):
        """上限を1つ超えたら 429 になること。"""
        middleware = make_middleware(requests_per_window=3)
        for _ in range(3):
            await self._hit(middleware)
        self.assertEqual(await self._hit(middleware), 429)

    async def test_two_workers_share_the_count(self):
        """**別インスタンス（＝別ワーカー）の件数が合算されること。**

        これがこの変更の目的そのもの。プロセス内で数えていたときは、
        WEB_WORKERS=2 なら上限3が実質6件通っていた。
        """
        worker_a = make_middleware(requests_per_window=3)
        worker_b = make_middleware(requests_per_window=3)
        self.assertEqual(await self._hit(worker_a), 200)
        self.assertEqual(await self._hit(worker_b), 200)
        self.assertEqual(await self._hit(worker_a), 200)
        # ここまでで3件。4件目はどちらのワーカーから来ても断られる。
        self.assertEqual(await self._hit(worker_b), 429)
        self.assertEqual(await self._hit(worker_a), 429)

    async def test_a_refused_request_is_not_kept_in_the_window(self):
        """**断ったリクエストを窓に残さないこと。**

        残すと「断られたリクエストが窓を押し続ける」形になり、叩いている相手が
        いつまでも解除されない。元のプロセス内実装は上限に達した時点で deque へ
        積まずに返していたので、そこと振る舞いを揃える。
        """
        middleware = make_middleware(requests_per_window=2)
        await self._hit(middleware)
        await self._hit(middleware)
        key = "sycs:ratelimit:api:default:203.0.113.10"
        before = len(self.fake.zsets[key])
        for _ in range(5):
            self.assertEqual(await self._hit(middleware), 429)
        self.assertEqual(len(self.fake.zsets[key]), before, "断ったぶんが窓に残っている")

    async def test_the_window_slides(self):
        """古い件数が窓から外れて、また通るようになること。

        固定窓にすると、窓の切り替わりをまたいで上限の2倍まで通せる
        （窓の末尾で上限ぶん、切り替わった直後にもう一度上限ぶん）。
        """
        middleware = make_middleware(requests_per_window=2, window_seconds=60)
        with patch("webapp.security.time.monotonic", return_value=1000.0):
            self.assertEqual(await self._hit(middleware), 200)
            self.assertEqual(await self._hit(middleware), 200)
            self.assertEqual(await self._hit(middleware), 429)
        # 窓を過ぎたところ
        with patch("webapp.security.time.monotonic", return_value=1061.0):
            self.assertEqual(await self._hit(middleware), 200)

    async def test_different_ips_are_counted_separately(self):
        """送信元ごとに別で数えること（1人が使い切って全員止まらないこと）。"""
        middleware = make_middleware(requests_per_window=1)
        self.assertEqual(await self._hit(middleware, host="203.0.113.10"), 200)
        self.assertEqual(await self._hit(middleware, host="203.0.113.11"), 200)
        self.assertEqual(await self._hit(middleware, host="203.0.113.10"), 429)

    async def test_calculate_has_its_own_smaller_budget(self):
        """calculate だけ別枠で、しかも枠が小さいこと。

        他の read 系より重い（DB アクセス＋計算）ため、共通の上限にすると
        連打を軽い API と同じ回数まで許してしまう。
        """
        middleware = make_middleware(requests_per_window=3, calculate_requests_per_window=1)
        self.assertEqual(await self._hit(middleware, path="/api/prices/calculate"), 200)
        self.assertEqual(await self._hit(middleware, path="/api/prices/calculate"), 429)
        # 別枠なので、通常の API はまだ通る
        self.assertEqual(await self._hit(middleware, path="/api/prices"), 200)

    async def test_non_api_paths_are_not_counted(self):
        """/api/ 以外は数えないこと（静的ファイルで枠を使い切らせない）。"""
        middleware = make_middleware(requests_per_window=1)
        for _ in range(10):
            self.assertEqual(await self._hit(middleware, path="/static/app.js"), 200)
        self.assertEqual(await self._hit(middleware, path="/api/prices"), 200)

    async def test_it_uses_a_pipeline_not_separate_round_trips(self):
        """1リクエストにつき Valkey への往復が1回で済んでいること。

        古いものを落とす・数える・足す・期限を付けるを別々に await すると、
        1リクエストで4往復する。レート制限は全リクエストが通る道なので、
        ここの往復数がそのまま全体の遅さになる。
        """
        middleware = make_middleware()
        self.fake.calls.clear()
        await self._hit(middleware)
        self.assertEqual(self.fake.calls.count("pipeline.execute"), 1)
        for op in ("zcard", "zadd", "zremrangebyscore"):
            self.assertNotIn(op, self.fake.calls, f"{op} を個別に呼んでいる")


class LocalFallbackTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """Valkey が使えないときにプロセス内で数えること。"""

    def tearDown(self) -> None:
        """差し込みを戻す。"""
        shared_cache_module.set_shared_cache(None)
        super().tearDown()

    async def _hit(self, middleware, path="/api/prices"):
        """1リクエスト分だけ通して status_code を返す。"""
        response = await middleware.dispatch(_FakeRequest(path), _pass_through)
        return response.status_code

    async def test_without_valkey_the_limit_still_applies(self):
        """**Valkey が設定されていなくても制限が効くこと。**

        ここが抜けると、VALKEY_URL を設定していない環境（手元・単一ワーカー）で
        公開 API のレート制限が丸ごと無くなる。
        """
        shared_cache_module.set_shared_cache(shared_cache_module.SharedCache(""))
        middleware = make_middleware(requests_per_window=2)
        self.assertEqual(await self._hit(middleware), 200)
        self.assertEqual(await self._hit(middleware), 200)
        self.assertEqual(await self._hit(middleware), 429)

    async def test_a_broken_valkey_falls_back_instead_of_failing_open(self):
        """**Valkey が落ちても制限が消えないこと。**

        「落ちたら制限なし」と「落ちたら API が 500」のどちらも取らない。
        緩くはなるが効いている状態（ワーカーごとの計数）へ落ちる。
        """
        shared_cache_module.set_shared_cache(make_cache(FakeValkey(fail_on={"pipeline.execute"})))
        middleware = make_middleware(requests_per_window=2)
        self.assertEqual(await self._hit(middleware), 200)
        self.assertEqual(await self._hit(middleware), 200)
        self.assertEqual(await self._hit(middleware), 429, "Valkey が落ちたら制限が消えている")

    async def test_a_broken_valkey_does_not_turn_into_a_500(self):
        """Valkey の失敗が例外として外へ出ないこと。"""
        shared_cache_module.set_shared_cache(make_cache(FakeValkey(fail_on={"pipeline"})))
        middleware = make_middleware()
        self.assertEqual(await self._hit(middleware), 200)


class CloudflareGuardTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """CF-Connecting-IP が要求される構成で、すり抜けを許さないこと。"""

    def tearDown(self) -> None:
        """差し込みを戻す。"""
        shared_cache_module.set_shared_cache(None)
        super().tearDown()

    async def test_a_direct_request_is_refused_with_403(self):
        """CF 経由でないリクエストは 403 で弾くこと（429 ではない）。

        レート制限をすり抜けさせないための門。**共有化で数え場所を変えたときに
        この分岐より後ろへ動かすと、直アクセスが数えられて通ってしまう。**
        """
        shared_cache_module.set_shared_cache(make_cache(FakeValkey()))
        middleware = make_middleware(require_cf_connecting_ip=True, trust_cf_headers=True)
        response = await middleware.dispatch(_FakeRequest("/api/prices"), _pass_through)
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
