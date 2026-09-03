"""プロセス間で共有するキャッシュ（services/shared_cache.py）と、それを二次として
使う webapp/cache.py の2段キャッシュのテスト。

    python -m unittest tests.test_shared_cache -v

■ このファイルが守っているもの

共有キャッシュは「無くても正しく動く層」として足した。つまり守るべき性質の
大半は**正常系ではなく、壊れたときに何が起きないか**である。

  - Valkey が例外を投げても、例外が呼び出し側へ出ない
  - 一度失敗したら、決めた時間だけ相手に触らない（死んだ相手を毎回待たない）
  - 壊れた値・JSON にできない値でも落ちない
  - clear() が二次まで消す（消し忘れると他のワーカーが古い価格を返し続ける）

正常系だけ通しても、これらは1つも検証できない。壊れたときに落ちるかどうかが、
この層を入れたことで障害が増えるか減るかを決める。

実 Valkey へは接続しない。SharedCache の client_factory を差し替える。
"""

from __future__ import annotations

import json
import logging
import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # noqa: E402

from services import shared_cache as shared_cache_module  # noqa: E402
from services.shared_cache import SharedCache  # noqa: E402
from webapp import cache as cache_module  # noqa: E402


class FakeValkey:
    """Valkey の代わり。使った操作を記録し、指定した操作で例外を投げる。

    実物を相手にすると、テストが Valkey の起動を要求するようになる
    （CONTRIBUTING 5. の「出てはいけない先」）。ここで記録を取っているのは、
    「触っていないこと」を検証したいテストがあるため（遮断器）。
    """

    def __init__(self, *, fail_on: set[str] | None = None) -> None:
        """fail_on に入れた操作名を呼ぶと RuntimeError を投げる。"""
        self.data: dict[str, str] = {}
        self.calls: list[str] = []
        self.fail_on = fail_on or set()
        self.closed = False
        self._scan_snapshot: list[str] = []
        # 鍵 → 付けられた期限（秒）。期限切れは模していない（時間を進める
        # テストは書いていない）。「期限が付いたかどうか」の検証にだけ使う。
        self.expires: dict[str, int] = {}

    def _record(self, name: str) -> None:
        """呼ばれた操作を記録し、fail_on に入っていれば投げる。"""
        self.calls.append(name)
        if name in self.fail_on:
            raise RuntimeError(f"擬似的な失敗: {name}")

    async def get(self, key: str) -> str | None:
        """記録して値を返す。"""
        self._record("get")
        return self.data.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        """記録して値を書く（ex は受け取るだけ。期限切れは検証対象にしない）。"""
        self._record("set")
        self.data[key] = value

    async def scan(self, cursor: int = 0, match: str = "*", count: int = 10) -> tuple[int, list[str]]:
        """1回に1件だけ返す。ページングを最後まで回すかを検証したいので、
        あえて小分けにする（1回で全部返す偽物だと、cursor を無視した実装でも通る）。

        cursor=0 の時点の鍵一覧を控えて、それを cursor で辿る。**その場で
        self.data を数え直す作りにすると、呼び出し側が消しながら回ったときに
        添字がずれて、実装が正しくても取りこぼす。** 実物の SCAN は反復の
        あいだ存在し続けた鍵を必ず1回は返すので、こちらのほうが実物に近い。
        """
        self._record("scan")
        prefix = match.rstrip("*")
        if cursor == 0:
            self._scan_snapshot = sorted(k for k in self.data if k.startswith(prefix))
        keys = self._scan_snapshot
        if cursor >= len(keys):
            return 0, []
        next_cursor = cursor + 1
        return (0 if next_cursor >= len(keys) else next_cursor), [keys[cursor]]

    async def mget(self, keys: list[str]) -> list[str | None]:
        """複数の鍵をまとめて取る。scan_values が使う。"""
        self._record("mget")
        return [self.data.get(key) for key in keys]

    async def incrby(self, key: str, amount: int) -> int:
        """原子的に増やす。実物と同じく、無い鍵は 0 から始める。"""
        self._record("incrby")
        current = int(self.data.get(key, "0")) + amount
        self.data[key] = str(current)
        return current

    async def expire(self, key: str, seconds: int) -> bool:
        """期限を付ける。**付いたことを記録に残す。** カウンタに期限が付いて
        いないことを検証したいテストがあるため（付くと読む側が「減った」と
        解釈して差分が壊れる）。
        """
        self._record("expire")
        self.expires[key] = seconds
        return key in self.data

    async def delete(self, *keys: str) -> int:
        """記録して消す。"""
        self._record("delete")
        removed = 0
        for key in keys:
            if self.data.pop(key, None) is not None:
                removed += 1
        return removed

    async def aclose(self) -> None:
        """記録して閉じる。"""
        self._record("aclose")
        self.closed = True


def make_cache(fake: FakeValkey | None = None, **kwargs: Any) -> SharedCache:
    """FakeValkey を繋いだ SharedCache を作る。"""
    fake = fake or FakeValkey()
    return SharedCache("redis://test/0", client_factory=lambda: fake, **kwargs)


class QuietSharedCacheLog:
    """わざと壊すテストの警告ログを、CI の出力に出さないための土台。

    この層は「壊れたら警告を1行出して degrade する」のが正しい振る舞いなので、
    壊す試験をすると必ずログが出る。素通しにすると CI のログがその警告で埋まり、
    本当に見たい失敗が読めなくなる（CONTRIBUTING 5. の print を残さないのと
    同じ理由）。

    ログの内容そのものを検証したいテストは assertLogs を使う。assertLogs は
    その場でレベルを上げ直すので、ここで CRITICAL にしていても効く。
    """

    def setUp(self) -> None:
        """services.shared_cache のログを一時的に黙らせる。"""
        super().setUp()  # type: ignore[misc]  # ミックスインとして TestCase と併用する
        self._previous_level = shared_cache_module.logger.level
        shared_cache_module.logger.setLevel(logging.CRITICAL)

    def tearDown(self) -> None:
        """元のレベルへ戻す（他のテストへ持ち越さない）。"""
        shared_cache_module.logger.setLevel(self._previous_level)
        super().tearDown()  # type: ignore[misc]  # ミックスインとして TestCase と併用する


class SharedCacheDisabledTests(unittest.IsolatedAsyncioTestCase):
    """URL が空のときは、何もしない入れ物として振る舞うこと。

    VALKEY_URL を設定しない運用（単一ワーカー、手元での実行、テスト）を
    そのまま続けられることが前提。ここが崩れると、環境変数を1つ足すまで
    アプリが動かなくなる。
    """

    async def test_an_empty_url_is_not_configured(self):
        """空文字は「設定されていない」として扱うこと。

        env_str は未設定でも空文字でも空文字を返すので、ここを None 判定に
        すると「宣言だけされている」場合に有効扱いになる。
        """
        cache = SharedCache("")
        self.assertFalse(cache.configured)
        self.assertFalse(cache.available)

    async def test_disabled_cache_never_touches_a_client(self):
        """無効なら、クライアントを作りにも行かないこと。

        作りに行くと、redis が入っていない環境で import エラーになる。
        """

        def explode() -> Any:
            raise AssertionError("無効なのにクライアントを作ろうとした")

        cache = SharedCache("", client_factory=explode)
        self.assertIsNone(await cache.get_json("ns", "k"))
        await cache.set_json("ns", "k", {"a": 1}, 60)
        await cache.clear_namespace("ns")
        await cache.close()


class SharedCacheRoundTripTests(unittest.IsolatedAsyncioTestCase):
    """正常系。値が JSON として往復し、鍵に接頭辞が付くこと。"""

    async def test_set_then_get_returns_the_same_value(self):
        """書いたものが読めること。"""
        cache = make_cache()
        await cache.set_json("web:latest", "gold", {"price": "12.34"}, 60)
        self.assertEqual(await cache.get_json("web:latest", "gold"), {"price": "12.34"})

    async def test_keys_carry_the_prefix_and_namespace(self):
        """鍵が sycs:<名前空間>:<鍵> の形になること。

        接頭辞が無いと、同じ Valkey を別の用途と相乗りさせたときに
        clear_namespace の走査が他人の鍵を巻き込む。
        """
        fake = FakeValkey()
        cache = make_cache(fake)
        await cache.set_json("web:latest", "gold", 1, 60)
        self.assertEqual(list(fake.data), ["sycs:web:latest:gold"])

    async def test_a_missing_key_returns_none(self):
        """無い鍵は None。"""
        cache = make_cache()
        self.assertIsNone(await cache.get_json("ns", "nope"))

    async def test_the_ttl_is_passed_through_and_clamped_to_at_least_one(self):
        """0 以下の TTL を渡しても 1 秒へ切り上げること。

        0 を渡せると、書いた直後に消える（＝キャッシュが常に空）状態を
        設定ミスで作れてしまい、気づきにくい。
        """
        recorded: list[int | None] = []

        class RecordingValkey(FakeValkey):
            async def set(self, key: str, value: str, ex: int | None = None) -> None:
                """ex を記録する。"""
                recorded.append(ex)
                await super().set(key, value, ex)

        cache = make_cache(RecordingValkey())
        await cache.set_json("ns", "k", 1, 0)
        await cache.set_json("ns", "k", 1, -5)
        await cache.set_json("ns", "k", 1, 30)
        self.assertEqual(recorded, [1, 1, 30])


class SharedCacheFailureTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """**このクラスがこのファイルの主目的。** 壊れたときに落ちないこと。"""

    async def test_a_failing_get_returns_none_instead_of_raising(self):
        """get が失敗しても例外を外へ出さないこと。

        ここが漏れると、Valkey が落ちた瞬間に価格 API が 500 を返す。
        キャッシュの故障が、キャッシュが無ければ起きなかった障害を作る。
        """
        cache = make_cache(FakeValkey(fail_on={"get"}))
        self.assertIsNone(await cache.get_json("ns", "k"))

    async def test_a_failing_set_does_not_raise(self):
        """set が失敗しても例外を外へ出さないこと。"""
        cache = make_cache(FakeValkey(fail_on={"set"}))
        await cache.set_json("ns", "k", {"a": 1}, 60)

    async def test_a_failing_scan_does_not_raise(self):
        """clear_namespace が失敗しても例外を外へ出さないこと。"""
        cache = make_cache(FakeValkey(fail_on={"scan"}))
        await cache.clear_namespace("ns")

    async def test_a_client_factory_that_raises_is_absorbed(self):
        """接続そのものを作れない場合も落ちないこと。

        redis が入っていない・URL が壊れている場合がここに来る。
        """

        def boom() -> Any:
            raise RuntimeError("接続を作れない")

        cache = SharedCache("redis://test/0", client_factory=boom)
        self.assertIsNone(await cache.get_json("ns", "k"))
        await cache.set_json("ns", "k", 1, 60)

    async def test_a_value_that_is_not_json_is_dropped_not_raised(self):
        """壊れた値が入っていても None を返すこと。

        別の版の自分が書いた値や、他人が同じ鍵を使った場合に起きる。
        作り直せるので捨ててよいが、例外にすると中身1つで API が落ちる。
        """
        fake = FakeValkey()
        cache = make_cache(fake)
        fake.data["sycs:ns:k"] = "{これはJSONではない"
        self.assertIsNone(await cache.get_json("ns", "k"))

    async def test_a_value_that_cannot_be_serialised_is_skipped(self):
        """JSON にできない値を渡されても落ちないこと。

        一次キャッシュには既に入っている段階でここへ来るので、諦めて続ける
        以外の選択肢が無い。
        """
        fake = FakeValkey()
        cache = make_cache(fake)
        await cache.set_json("ns", "k", {1, 2, 3}, 60)  # set は JSON にできない
        self.assertEqual(fake.data, {})

    async def test_a_failure_opens_the_breaker_and_stops_touching_valkey(self):
        """一度失敗したら、クールダウンの間はクライアントに触らないこと。

        **これが無いと、Valkey が落ちている間 1リクエストごとに接続の
        タイムアウトぶん待たされ、キャッシュが無い場合よりむしろ遅くなる。**
        """
        fake = FakeValkey(fail_on={"get"})
        cache = make_cache(fake, breaker_cooldown_seconds=300.0)

        self.assertIsNone(await cache.get_json("ns", "k"))
        calls_after_first = len(fake.calls)
        self.assertFalse(cache.available, "失敗のあとは遮断器が開いていること")

        for _ in range(5):
            self.assertIsNone(await cache.get_json("ns", "k"))
        self.assertEqual(
            len(fake.calls),
            calls_after_first,
            "遮断器が開いているあいだ、Valkey へ1回も行っていないこと",
        )

    async def test_the_breaker_closes_again_after_the_cooldown(self):
        """クールダウンが過ぎたら、また試すこと。

        開いたままにすると、Valkey が復旧してもプロセスを再起動するまで
        共有キャッシュが死んだままになる。
        """
        fake = FakeValkey(fail_on={"get"})
        cache = make_cache(fake, breaker_cooldown_seconds=1.0)
        await cache.get_json("ns", "k")
        self.assertFalse(cache.available)

        # 時間を進める代わりに、遮断器の期限を過去へ動かす（sleep はしない）。
        cache._blocked_until = 0.0
        fake.fail_on = set()
        fake.data["sycs:ns:k"] = json.dumps({"ok": True})
        self.assertTrue(cache.available)
        self.assertEqual(await cache.get_json("ns", "k"), {"ok": True})

    async def test_a_failed_operation_drops_the_connection(self):
        """失敗した接続は捨てること。

        壊れた接続を使い回すと、Valkey が復旧しても失敗し続ける。
        """
        fake = FakeValkey(fail_on={"get"})
        cache = make_cache(fake)
        await cache.get_json("ns", "k")
        self.assertIsNone(cache._client, "失敗した接続が残っていないこと")

    async def test_the_breaker_logs_once_not_every_call(self):
        """遮断器が開くときだけログを出すこと（開いている間は出さない）。

        毎回出すと、落ちている間ログが同じ行で埋まって本当の原因が埋もれる。
        """
        fake = FakeValkey(fail_on={"get"})
        cache = make_cache(fake, breaker_cooldown_seconds=300.0)
        with self.assertLogs(shared_cache_module.logger, level="WARNING") as logs:
            await cache.get_json("ns", "k")
            for _ in range(5):
                await cache.get_json("ns", "k")
        self.assertEqual(len(logs.records), 1, f"1行だけであること: {[r.message for r in logs.records]}")


class SharedCacheClearTests(unittest.IsolatedAsyncioTestCase):
    """名前空間の消去。SCAN を最後まで回し、他の名前空間を巻き込まないこと。"""

    async def test_clear_removes_every_key_in_the_namespace(self):
        """ページングされても全件消すこと。

        FakeValkey.scan は1回に1件しか返さないので、cursor を無視した実装だと
        1件しか消えずにここで落ちる。
        """
        fake = FakeValkey()
        cache = make_cache(fake)
        for key in ("a", "b", "c"):
            await cache.set_json("web:history", key, key, 60)
        await cache.clear_namespace("web:history")
        self.assertEqual(fake.data, {})

    async def test_clear_does_not_touch_other_namespaces(self):
        """別の名前空間の鍵は残ること。

        価格のキャッシュを消したいだけのときに予測のキャッシュまで消えると、
        LLM を使う重い計算がやり直しになる。
        """
        fake = FakeValkey()
        cache = make_cache(fake)
        await cache.set_json("web:history", "a", 1, 60)
        await cache.set_json("web:forecast", "b", 2, 60)
        await cache.clear_namespace("web:history")
        self.assertEqual(list(fake.data), ["sycs:web:forecast:b"])


class SharedCacheSingletonTests(unittest.TestCase):
    """shared_cache() が環境変数から1つだけ作り、差し替えられること。"""

    def tearDown(self) -> None:
        """他のテストへ状態を持ち越さない。"""
        shared_cache_module.set_shared_cache(None)

    def test_it_returns_the_same_instance(self):
        """毎回作り直さないこと（接続が増え続けるのを避ける）。"""
        shared_cache_module.set_shared_cache(None)
        first = shared_cache_module.shared_cache()
        self.assertIs(shared_cache_module.shared_cache(), first)

    def test_set_shared_cache_replaces_the_instance(self):
        """差し替えが効くこと（これが無いとテストが実 Valkey を要求する）。"""
        replacement = make_cache()
        shared_cache_module.set_shared_cache(replacement)
        self.assertIs(shared_cache_module.shared_cache(), replacement)


class TwoLayerCacheTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """webapp/cache.py の2段構成。一次と二次の役割分担を検証する。"""

    async def test_without_a_namespace_the_shared_layer_is_never_used(self):
        """namespace を渡さない TTLCache は、今までと完全に同じ動きをすること。

        二次に載せてよいかは値の性質による（JSON にできるか、共有して意味が
        あるか）ので、既定で載せない側に倒してある。ここが崩れると、
        namespace を書き忘れた箇所が黙って Valkey を触り始める。
        """
        fake = FakeValkey()
        cache = cache_module.TTLCache(default_ttl_seconds=60, shared=make_cache(fake))
        self.assertIsNone(cache.shared)
        await cache.set("k", {"a": 1})
        self.assertEqual(await cache.get("k"), {"a": 1})
        await cache.clear()
        self.assertEqual(fake.calls, [], "共有層へ1回も行っていないこと")

    async def test_a_local_hit_does_not_go_to_the_shared_layer(self):
        """一次で当たったら二次を見ないこと。

        毎回 Valkey へ行くと、プロセス内キャッシュを残した意味が無くなる。
        """
        fake = FakeValkey()
        cache = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=make_cache(fake))
        await cache.set("k", {"a": 1})
        fake.calls.clear()
        self.assertEqual(await cache.get("k"), {"a": 1})
        self.assertEqual(fake.calls, [], "一次で当たったのに二次へ行っている")

    async def test_a_local_miss_falls_back_to_the_shared_layer(self):
        """一次に無ければ二次を見て、見つかったら一次へ書き戻すこと。

        書き戻さないと、同じワーカーが同じ鍵を引くたびに Valkey へ行く。
        """
        fake = FakeValkey()
        shared = make_cache(fake)
        writer = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=shared)
        reader = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=shared)

        # 別ワーカーが書いた状況を、別インスタンスで作る
        await writer.set("k", {"a": 1})

        self.assertEqual(await reader.get("k"), {"a": 1})
        fake.calls.clear()
        self.assertEqual(await reader.get("k"), {"a": 1})
        self.assertEqual(fake.calls, [], "一次へ書き戻せていない（毎回二次へ行っている）")

    async def test_set_writes_to_both_layers(self):
        """set が一次と二次の両方へ書くこと。"""
        fake = FakeValkey()
        cache = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=make_cache(fake))
        await cache.set("k", {"a": 1})
        self.assertIn("sycs:ns:k", fake.data)
        self.assertEqual(await cache._get_local("k"), {"a": 1})

    async def test_clear_also_clears_the_shared_layer(self):
        """**clear が二次まで消すこと。**

        消し忘れると、価格を取り直したのに他のワーカーが古い値を返し続ける。
        clear() が呼ばれるのは日次の取得と予測の更新の直後で、まさに全ワーカーへ
        新しい値を見せたい場面。
        """
        fake = FakeValkey()
        cache = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=make_cache(fake))
        await cache.set("k", {"a": 1})
        await cache.clear()
        self.assertEqual(fake.data, {}, "二次に古い値が残っている")

    async def test_a_broken_shared_layer_does_not_break_the_cache(self):
        """二次が全操作で失敗しても、一次だけで正しく動くこと。

        これが「Valkey が落ちても今までと同じ速さで動き続ける」の実体。
        """
        fake = FakeValkey(fail_on={"get", "set", "scan"})
        cache = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=make_cache(fake))
        await cache.set("k", {"a": 1})
        self.assertEqual(await cache.get("k"), {"a": 1})
        await cache.clear()
        self.assertIsNone(await cache.get("k"))

    async def test_the_local_layer_is_written_before_the_shared_one(self):
        """一次へ書いてから二次へ行くこと。

        逆にすると、Valkey が固まっているあいだ一次にも入らないまま返るので、
        キャッシュが無い場合より遅くなる。
        """
        order: list[str] = []

        class SlowValkey(FakeValkey):
            async def set(self, key: str, value: str, ex: int | None = None) -> None:
                """二次へ書いた時点を記録する。"""
                order.append("shared")
                await super().set(key, value, ex)

        cache = cache_module.TTLCache(default_ttl_seconds=60, namespace="ns", shared=make_cache(SlowValkey()))
        original = cache._set_local

        async def spy(key: str, value: Any, ttl: int) -> None:
            """一次へ書いた時点を記録する。"""
            order.append("local")
            await original(key, value, ttl)

        cache._set_local = spy  # type: ignore[method-assign]  # テスト用の差し替え
        await cache.set("k", {"a": 1})
        self.assertEqual(order, ["local", "shared"])


if __name__ == "__main__":
    unittest.main()
