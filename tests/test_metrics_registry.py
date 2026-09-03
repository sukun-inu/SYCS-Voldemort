"""Netdata へ出すメトリクス（services/metrics_registry.py・metrics_reporter.py・
webapp_admin/prometheus_view.py）のテスト。

    python -m unittest tests.test_metrics_registry -v

■ このファイルが守っているもの

  1. **接続元の制限が本当に効くこと。** /metrics には認証が無い。ここが緩いと、
     アプリの内部状態を誰でも読めるようになる。転送ヘッダを見ていないことも
     含めて固定する。
  2. Prometheus の形式として壊れていないこと。HELP/TYPE が1メトリクス1回、
     ラベル値がエスケープされていること。**形式が壊れると Netdata 側からは
     「メトリクスが1つ欠けた」ではなく「読めない」に見える**ので、原因を追い
     にくい。
  3. 生存が「消える」ではなく 0/1 で出ること。
  4. 報告に失敗したときにカウンタを捨てないこと。
  5. カウンタに期限が付かないこと（付くと、読む側が「減った」と解釈する）。

実 Valkey へは接続しない。tests/test_shared_cache.py の FakeValkey を使う。
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # noqa: E402

from services import metrics_registry as registry_module  # noqa: E402
from services import metrics_reporter as reporter_module  # noqa: E402
from services.metrics_registry import CounterBuffer, MetricsRegistry  # noqa: E402
from tests.test_shared_cache import FakeValkey, QuietSharedCacheLog, make_cache  # noqa: E402
from webapp_admin import prometheus_view  # noqa: E402


def make_registry(fake: FakeValkey | None = None, **kwargs) -> MetricsRegistry:
    """FakeValkey を繋いだ登録簿を作る。"""
    return MetricsRegistry(make_cache(fake or FakeValkey()), **kwargs)


class LabelFormattingTests(unittest.TestCase):
    """Prometheus の形式として壊れないこと。"""

    def test_label_values_are_escaped(self):
        """ラベル値の " と改行とバックスラッシュが逃がされること。

        **逃がさないと、値に " が混ざった時点でその行以降の出力全体が壊れる。**
        例外の型名をラベルにしているので、外から来た文字列が入る余地がある。
        """
        got = registry_module._format_labels({"type": 'Odd"Name'})
        self.assertEqual(got, '{type="Odd\\"Name"}')
        self.assertEqual(registry_module._format_labels({"a": "x\ny"}), '{a="x\\ny"}')
        self.assertEqual(registry_module._format_labels({"a": "b\\c"}), '{a="b\\\\c"}')

    def test_labels_are_sorted_so_output_is_stable(self):
        """並びが固定されること。固定しないと同じ内容でも出力が毎回変わる。"""
        self.assertEqual(
            registry_module._format_labels({"b": "2", "a": "1"}),
            '{a="1",b="2"}',
        )

    def test_integers_are_not_printed_in_exponent_form(self):
        """大きな整数が 1e+06 のような形にならないこと。

        指数表記になると、カウンタの値を目で追えなくなる。
        """
        self.assertEqual(registry_module._format_value(1000000.0), "1000000")
        self.assertEqual(registry_module._format_value(3), "3")

    def test_counter_keys_are_stable_regardless_of_label_order(self):
        """ラベルの順番が違っても同じ鍵になること。

        **ここが揺れると、同じカウンタが2つに分かれて数えられる。**
        """
        first = registry_module._encode_counter_key("x", {"a": "1", "b": "2"})
        second = registry_module._encode_counter_key("x", {"b": "2", "a": "1"})
        self.assertEqual(first, second)

    def test_counter_keys_round_trip(self):
        """鍵を作って読み戻せること。"""
        key = registry_module._encode_counter_key("http_responses_total", {"app": "admin", "code": "500"})
        name, labels = registry_module._decode_counter_key(key)
        self.assertEqual(name, "http_responses_total")
        self.assertEqual(labels, {"app": "admin", "code": "500"})

    def test_a_broken_counter_key_is_treated_as_unlabelled(self):
        """壊れた鍵でも例外にしないこと。

        Valkey に1つ変な鍵が入っているだけで /metrics 全体が 500 になるのは困る。
        """
        name, labels = registry_module._decode_counter_key("weird|=,,=")
        self.assertEqual(name, "weird")
        self.assertEqual(labels, {})

    def test_help_and_type_appear_once_per_metric(self):
        """同じメトリクス名について HELP と TYPE が1回だけ出ること。

        複数回出すと Prometheus の形式として不正で、収集器が行を捨てる。
        """
        lines = registry_module._block("x", "gauge", "説明", [({"a": "1"}, 1.0), ({"a": "2"}, 2.0)])
        self.assertEqual(len([line for line in lines if line.startswith("# HELP")]), 1)
        self.assertEqual(len([line for line in lines if line.startswith("# TYPE")]), 1)
        self.assertEqual(len([line for line in lines if not line.startswith("#")]), 2)


class RenderTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """Valkey に置かれた値が Prometheus 形式で出ること。"""

    async def test_a_fresh_heartbeat_reports_up_as_one(self):
        """心拍が新しければ sycs_up が 1 になること。"""
        reg = make_registry(stale_after_seconds=90.0)
        await reg.heartbeat("bot")
        text = await reg.render()
        self.assertIn('sycs_up{app="bot"} 1', text)

    async def test_a_stale_heartbeat_reports_up_as_zero_not_missing(self):
        """古い心拍は、系列を消すのではなく 0 で出すこと。

        **消える形にすると、Netdata 側で「無くなったこと」を条件に書く必要が
        あり、値を見るより難しくなる。** ここが 0 で出ることが、死活監視が
        成立する条件そのもの。
        """
        fake = FakeValkey()
        reg = make_registry(fake, stale_after_seconds=10.0)
        await reg.heartbeat("bot")
        # 心拍を 1000 秒前に書き換える
        with patch.object(registry_module.time, "time", return_value=0.0):
            await reg.heartbeat("bot")
        text = await reg.render()
        self.assertIn('sycs_up{app="bot"} 0', text)
        self.assertIn('sycs_heartbeat_age_seconds{app="bot"}', text)

    async def test_gauges_and_counters_are_labelled_by_app(self):
        """ゲージはアプリ名のラベルが付き、カウンタは書いたラベルで出ること。"""
        reg = make_registry()
        await reg.set_gauge("bot", "bot_guilds", 3)
        await reg.incr_counter("exceptions_total", {"app": "admin", "type": "ValueError"}, 2)
        text = await reg.render()
        self.assertIn('sycs_bot_guilds{app="bot"} 3', text)
        self.assertIn('sycs_exceptions_total{app="admin",type="ValueError"} 2', text)
        self.assertIn("# TYPE sycs_exceptions_total counter", text)
        self.assertIn("# TYPE sycs_bot_guilds gauge", text)

    async def test_counters_have_no_expiry(self):
        """カウンタに期限が付かないこと。

        **付くと、読む側は途中で値が減ったように見えて差分がおかしくなる。**
        Prometheus のカウンタは単調増加でなければならない。
        """
        fake = FakeValkey()
        reg = make_registry(fake)
        await reg.incr_counter("requests_total", {"app": "admin"})
        self.assertEqual(fake.expires, {}, "カウンタに期限が付いている")
        self.assertNotIn("expire", fake.calls, "EXPIRE が呼ばれている")

    async def test_gauges_do_expire(self):
        """ゲージには期限が付くこと。

        付けないと、死んだプロセスの最後の値が生きているように見え続ける。
        """
        recorded: list[tuple[str, object]] = []

        class Recording(FakeValkey):
            async def set(self, key, value, ex=None):
                """ex を記録する。"""
                recorded.append((key, ex))
                await super().set(key, value, ex)

        reg = make_registry(Recording(), gauge_ttl_seconds=120)
        await reg.set_gauge("bot", "bot_guilds", 1)
        self.assertEqual([ex for _, ex in recorded], [120])

    async def test_heartbeat_has_no_expiry(self):
        """心拍に期限が付かないこと（付くと sycs_up が 0 でなく消える）。"""
        recorded: list[tuple[str, object]] = []

        class Recording(FakeValkey):
            async def set(self, key, value, ex=None):
                """ex を記録する。"""
                recorded.append((key, ex))
                await super().set(key, value, ex)

        reg = make_registry(Recording())
        await reg.heartbeat("bot")
        self.assertEqual([ex for _, ex in recorded], [None])

    async def test_shared_cache_health_is_always_reported(self):
        """共有キャッシュが生きているかを必ず出すこと。

        **これが無いと、「Valkey が落ちてメトリクスが空になった」のか
        「本当に静かだった」のかを区別できない。**
        """
        reg = make_registry()
        text = await reg.render()
        self.assertIn("sycs_shared_cache_available 1", text)

    async def test_render_is_not_empty_when_valkey_is_down(self):
        """Valkey が落ちていても本文が空にならないこと。

        空を返すと Netdata は「収集器が壊れた」と扱い、「Valkey が落ちている」
        という本当の情報が伝わらない。
        """
        reg = MetricsRegistry(make_cache(FakeValkey(fail_on={"scan"})))
        text = await reg.render(extra=[("x", None, 1.0, "gauge", "説明")])
        self.assertIn("sycs_x 1", text)
        self.assertIn("sycs_shared_cache_available 0", text)

    async def test_a_non_numeric_value_is_skipped_not_fatal(self):
        """数値として読めない値が入っていても、他のメトリクスは出ること。"""
        fake = FakeValkey()
        reg = make_registry(fake)
        await reg.set_gauge("bot", "ok", 1)
        fake.data["sycs:metrics:g:bot:broken"] = "これは数値ではない"
        text = await reg.render()
        self.assertIn('sycs_ok{app="bot"} 1', text)
        self.assertNotIn("broken", text)


class CounterBufferTests(unittest.TestCase):
    """プロセス内に溜める入れ物。"""

    def test_counts_accumulate_per_label_set(self):
        """名前とラベルの組ごとに足されること。"""
        buffer = CounterBuffer()
        buffer.add("x", {"a": "1"})
        buffer.add("x", {"a": "1"}, 2)
        buffer.add("x", {"a": "2"})
        drained = dict(((name, tuple(sorted(labels.items()))), count) for name, labels, count in buffer.drain())
        self.assertEqual(drained[("x", (("a", "1"),))], 3)
        self.assertEqual(drained[("x", (("a", "2"),))], 1)

    def test_label_order_does_not_split_the_count(self):
        """ラベルの順番が違っても1つに数えられること。"""
        buffer = CounterBuffer()
        buffer.add("x", {"a": "1", "b": "2"})
        buffer.add("x", {"b": "2", "a": "1"})
        self.assertEqual(len(buffer.drain()), 1)

    def test_drain_empties_the_buffer(self):
        """取り出したら空になること（2回送られないこと）。"""
        buffer = CounterBuffer()
        buffer.add("x")
        self.assertEqual(len(buffer.drain()), 1)
        self.assertEqual(buffer.drain(), [])

    def test_restore_puts_the_counts_back(self):
        """戻したぶんが次の drain で出ること。"""
        buffer = CounterBuffer()
        buffer.add("x", None, 5)
        drained = buffer.drain()
        buffer.restore(drained)
        self.assertEqual(buffer.drain(), [("x", {}, 5)])


class ReporterTests(unittest.IsolatedAsyncioTestCase):
    """報告ループ。失敗したときに数を捨てないこと。"""

    def setUp(self) -> None:
        """報告の失敗ログで CI の出力を汚さない。"""
        self._level = reporter_module.logger.level
        reporter_module.logger.setLevel(logging.CRITICAL)

    def tearDown(self) -> None:
        """ログのレベルを戻す。"""
        reporter_module.logger.setLevel(self._level)

    async def test_it_writes_heartbeat_gauges_and_counters(self):
        """心拍・ゲージ・カウンタが1回の報告で全部出ること。"""
        fake = FakeValkey()
        buffer = CounterBuffer()
        buffer.add("requests_total", {"app": "admin"}, 7)
        await reporter_module.report_once(
            "admin",
            registry=make_registry(fake),
            buffer=buffer,
            gauges={"admin_x": 2.0},
        )
        self.assertIn("sycs:metrics:hb:admin", fake.data)
        self.assertEqual(fake.data["sycs:metrics:g:admin:admin_x"], "2")
        self.assertEqual(fake.data["sycs:metrics:c:requests_total|app=admin"], "7")

    async def test_a_failed_report_does_not_lose_the_counts(self):
        """**報告に失敗したら、drain したぶんを必ず戻すこと。**

        戻さないと、Valkey が一時的に落ちている間の計数が全部捨てられる。
        遮断器が開いている 30 秒ぶんが毎回消える形になる。
        """
        buffer = CounterBuffer()
        buffer.add("requests_total", {"app": "admin"}, 4)

        class Exploding(MetricsRegistry):
            async def heartbeat(self, app: str) -> None:
                """必ず失敗する。"""
                raise RuntimeError("擬似的な失敗")

        await reporter_module.report_once("admin", registry=Exploding(make_cache()), buffer=buffer)
        self.assertEqual(buffer.drain(), [("requests_total", {"app": "admin"}, 4)])

    async def test_report_once_never_raises(self):
        """例外を外へ出さないこと。

        これを呼ぶのは背景タスクで、discord.ext.tasks の loop は中で例外が
        飛ぶとその回で停止し、再始動しない限り二度と走らない。**メトリクスの
        報告が失敗したせいで他の背景処理まで止まるのが最悪。**
        """

        class Exploding(MetricsRegistry):
            async def heartbeat(self, app: str) -> None:
                """必ず失敗する。"""
                raise RuntimeError("擬似的な失敗")

        await reporter_module.report_once("bot", registry=Exploding(make_cache()), buffer=CounterBuffer())


class MetricsAccessTests(unittest.TestCase):
    """**/metrics の接続元制限。** 認証が無い経路なので、ここが唯一の守り。"""

    @staticmethod
    def _request(host: str | None, headers: dict[str, str] | None = None):
        """接続元とヘッダだけを持つ、最小の偽リクエスト。"""
        return SimpleNamespace(
            client=None if host is None else SimpleNamespace(host=host),
            headers=headers or {},
        )

    def test_loopback_and_docker_bridge_are_allowed(self):
        """既定でループバックと Docker のブリッジ帯から読めること。

        Netdata はホスト上で動き、公開ポート経由で来るので、コンテナから見た
        接続元はブリッジのゲートウェイになる。ここを落とすと何も測れない。
        """
        with patch.dict("os.environ", {}, clear=False):
            for host in ("127.0.0.1", "::1", "172.18.0.1"):
                self.assertTrue(prometheus_view.client_allowed(self._request(host)), host)

    def test_the_public_internet_is_refused(self):
        """外部からは読めないこと。"""
        for host in ("203.0.113.10", "8.8.8.8", "192.168.1.10"):
            self.assertFalse(prometheus_view.client_allowed(self._request(host)), host)

    def test_forwarded_headers_cannot_grant_access(self):
        """**転送ヘッダを付けても通れないこと。**

        ここが最も危ない失敗。X-Forwarded-For を見る作りにすると、ヘッダを1つ
        付けてリクエストするだけで誰でもアプリの内部状態を読める。管理画面の
        他の経路は TRUSTED_PROXY_CIDRS を見て転送ヘッダを信じるので、その作法を
        真似てしまいやすい。
        """
        spoofed = self._request(
            "203.0.113.10",
            {
                "x-forwarded-for": "127.0.0.1",
                "x-real-ip": "127.0.0.1",
                "cf-connecting-ip": "127.0.0.1",
            },
        )
        self.assertFalse(prometheus_view.client_allowed(spoofed))

    def test_a_missing_client_is_refused(self):
        """接続元が取れない場合は拒否すること。

        通すと、判定を空振りさせるだけで通れる道になる。
        """
        self.assertFalse(prometheus_view.client_allowed(self._request(None)))
        self.assertFalse(prometheus_view.client_allowed(self._request("")))

    def test_a_non_ip_host_is_refused(self):
        """IP として読めない接続元は拒否すること。"""
        self.assertFalse(prometheus_view.client_allowed(self._request("not-an-ip")))

    def test_the_allowed_range_can_be_narrowed(self):
        """環境変数で範囲を絞れること。"""
        with patch.dict("os.environ", {"METRICS_ALLOWED_CIDRS": "10.1.2.3/32"}, clear=False):
            self.assertTrue(prometheus_view.client_allowed(self._request("10.1.2.3")))
            self.assertFalse(prometheus_view.client_allowed(self._request("127.0.0.1")))

    def test_a_broken_cidr_is_ignored_and_the_rest_still_work(self):
        """書式が壊れた1件を無視して、他は活かすこと。

        例外を上げると、設定の書式ミス1つで管理画面が起動しなくなる。
        """
        with patch.dict("os.environ", {"METRICS_ALLOWED_CIDRS": "これは壊れている,10.1.2.3/32"}, clear=False):
            with self.assertLogs(prometheus_view.logger, level="WARNING"):
                self.assertTrue(prometheus_view.client_allowed(self._request("10.1.2.3")))


class BackupAgeTests(unittest.TestCase):
    """バックアップの経過時間。失敗した回を「成功」と読まないこと。"""

    def _with_status(self, payload: object) -> float | None:
        """status.json を一時ファイルに書いて読ませる。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.dict("os.environ", {"BACKUP_STATUS_FILE": str(path)}, clear=False):
                return prometheus_view.backup_age_seconds()

    def test_a_successful_backup_reports_its_age(self):
        """成功した回なら経過秒数が出ること。"""
        import time

        age = self._with_status({"result": "ok", "finished_at_epoch": time.time() - 100})
        self.assertIsNotNone(age)
        assert age is not None
        self.assertGreater(age, 90)
        self.assertLess(age, 200)

    def test_a_failed_backup_reports_nothing(self):
        """**失敗した回の時刻を返さないこと。**

        返すと「バックアップは最近動いている」ように見える。動いてはいるが
        成功していない、という最も気づきにくい状態を隠してしまう。
        """
        import time

        self.assertIsNone(self._with_status({"result": "error", "finished_at_epoch": time.time()}))

    def test_a_missing_file_reports_nothing(self):
        """ファイルが無ければ None（マウントしない構成でも落ちない）。"""
        with patch.dict("os.environ", {"BACKUP_STATUS_FILE": "/does/not/exist.json"}, clear=False):
            self.assertIsNone(prometheus_view.backup_age_seconds())

    def test_a_broken_file_reports_nothing(self):
        """壊れた JSON でも落ちないこと。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text("{壊れている", encoding="utf-8")
            with patch.dict("os.environ", {"BACKUP_STATUS_FILE": str(path)}, clear=False):
                self.assertIsNone(prometheus_view.backup_age_seconds())

    def test_a_non_numeric_epoch_reports_nothing(self):
        """時刻が数値でなければ None。"""
        self.assertIsNone(self._with_status({"result": "ok", "finished_at_epoch": "きのう"}))


class MetricsEndpointTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """/metrics のハンドラそのもの。403 と 200 の両方を通す。"""

    @staticmethod
    def _request(host: str):
        """接続元だけを持つ最小の偽リクエスト。"""
        return SimpleNamespace(client=SimpleNamespace(host=host), headers={})

    async def test_a_refused_client_gets_403_without_the_body(self):
        """許可されない接続元には本文を返さないこと。

        **何が許可されているかを返さないこと。** 返すと、外から許可範囲を
        探れる（403 の本文で「172.16.0.0/12 のみ」と教えるのは、鍵の場所を
        書いた札を玄関に貼るのと同じ）。
        """
        response = await prometheus_view.render_metrics(self._request("203.0.113.10"))
        self.assertEqual(response.status_code, 403)
        body = response.body.decode("utf-8")
        self.assertNotIn("sycs_", body)
        self.assertNotIn("172.16", body)

    async def test_an_allowed_client_gets_the_prometheus_content_type(self):
        """Content-Type が Prometheus のテキスト形式になること。

        付けないと、収集器が HTML として扱って何も読まないことがある。
        """
        registry_module.set_metrics_registry(make_registry())
        try:
            response = await prometheus_view.render_metrics(self._request("127.0.0.1"))
        finally:
            registry_module.set_metrics_registry(None)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.headers["content-type"])
        self.assertIn("version=0.0.4", response.headers["content-type"])

    async def test_the_body_always_carries_the_in_process_values(self):
        """Valkey が落ちていても、このプロセスで測れる値は出ること。"""
        registry_module.set_metrics_registry(MetricsRegistry(make_cache(FakeValkey(fail_on={"scan"}))))
        try:
            response = await prometheus_view.render_metrics(self._request("127.0.0.1"))
        finally:
            registry_module.set_metrics_registry(None)
        body = response.body.decode("utf-8")
        self.assertIn("sycs_admin_request_tps", body)
        self.assertIn("sycs_admin_uptime_seconds", body)
        self.assertIn("sycs_shared_cache_available 0", body)


class ReportForeverTests(QuietSharedCacheLog, unittest.IsolatedAsyncioTestCase):
    """報告ループが実際に回ること。"""

    def setUp(self) -> None:
        """わざと壊すので、報告側のログも黙らせる。"""
        super().setUp()
        self._reporter_level = reporter_module.logger.level
        reporter_module.logger.setLevel(logging.CRITICAL)

    def tearDown(self) -> None:
        """レベルを戻す。"""
        reporter_module.logger.setLevel(self._reporter_level)
        super().tearDown()

    async def test_it_reports_and_keeps_going(self):
        """1周して次の待ちに入ること。

        sleep を差し替えて2周目で抜ける。実時間を待つと、テストが間隔の秒数
        ぶん止まる（30秒）。
        """
        fake = FakeValkey()
        rounds = {"n": 0}

        async def fake_sleep(_seconds):
            """2周目で CancelledError を出してループを抜けさせる。"""
            rounds["n"] += 1
            if rounds["n"] >= 2:
                raise asyncio.CancelledError()

        with patch.object(reporter_module.asyncio, "sleep", fake_sleep):
            with self.assertRaises(asyncio.CancelledError):
                await reporter_module.report_forever(
                    "admin",
                    interval_seconds=1.0,
                    registry=make_registry(fake),
                    buffer=CounterBuffer(),
                    gauge_source=lambda: {"x": 1.0},
                )
        self.assertIn("sycs:metrics:hb:admin", fake.data)
        self.assertEqual(fake.data["sycs:metrics:g:admin:x"], "1")

    async def test_a_broken_gauge_source_does_not_stop_the_loop(self):
        """ゲージの収集が壊れていても、心拍は届くこと。

        ここで止まると、アプリは生きているのに sycs_up が 0 になる。
        """
        fake = FakeValkey()

        async def fake_sleep(_seconds):
            """1周で抜ける。"""
            raise asyncio.CancelledError()

        def boom():
            """必ず失敗するゲージ収集。"""
            raise RuntimeError("擬似的な失敗")

        with patch.object(reporter_module.asyncio, "sleep", fake_sleep):
            with self.assertRaises(asyncio.CancelledError):
                await reporter_module.report_forever(
                    "bot",
                    interval_seconds=1.0,
                    registry=make_registry(fake),
                    buffer=CounterBuffer(),
                    gauge_source=boom,
                )
        self.assertIn("sycs:metrics:hb:bot", fake.data)


if __name__ == "__main__":
    unittest.main()
