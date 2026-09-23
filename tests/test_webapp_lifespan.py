"""webapp/app.py の lifespan が「何をどの順で組み立てるか」を固定する不変条件テスト。

    python -m unittest tests.test_webapp_lifespan -v

■ なぜこのファイルがあるか

lifespan を割る前に、外から見た振る舞いを押さえるために書いた
（CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。**割ったあとに
書いたテストは、割った形に合わせたテストになるので「割る前と同じか」については
何も言えない。**

lifespan は性質としては「組み立て」なので、固定するのは
**何がどの順で登録されたかの一覧**（CONTRIBUTING 5. の表）。順序に意味がある。

  起動時ジョブ    日次取得 → 自動修復 → Push 通知 → 起動時テスト。
                  取得の前に通知すると、その日のぶんが無い状態で送る。
  スケジューラ    id・トリガの種類とその引数・misfire_grace_time。
                  **id を書き間違えても replace_existing=True なので黙って
                  別のジョブとして増える。** 誰も気づかない。
  後始末          メトリクス報告を止める → スケジューラを止める → ロックを外す
                  → DB を閉じる。DB を先に閉じるとゲージの収集が例外になる。

■ 触らせないもの

DB・ネットワーク・APScheduler の実物には出ない。差し替えるのは lifespan が
呼ぶ名前だけで、lifespan 自身は本物を動かす。
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # noqa: E402

from webapp import app as app_module  # noqa: E402


class FakeScheduler:
    """AsyncIOScheduler の代わり。add_job / start / shutdown を記録する。"""

    instances: list["FakeScheduler"] = []

    def __init__(self, *, timezone: Any = None) -> None:
        """作られたことを記録し、以降の add_job を溜める。"""
        self.timezone = timezone
        self.jobs: list[dict[str, Any]] = []
        self.started = False
        self.shutdown_called = False
        FakeScheduler.instances.append(self)

    def add_job(self, func: Any, trigger: Any, **kwargs: Any) -> None:
        """登録された1件を、あとで突き合わせられる形にして溜める。"""
        self.jobs.append(
            {
                "func": getattr(func, "__name__", repr(func)),
                "trigger": type(trigger).__name__,
                "trigger_args": getattr(trigger, "_recorded", None),
                "id": kwargs.get("id"),
                "kwargs": kwargs.get("kwargs"),
                "misfire_grace_time": kwargs.get("misfire_grace_time"),
                "coalesce": kwargs.get("coalesce"),
                "max_instances": kwargs.get("max_instances"),
                "replace_existing": kwargs.get("replace_existing"),
            }
        )

    def start(self) -> None:
        """起動されたことを記録する。"""
        self.started = True

    def shutdown(self, wait: bool = True) -> None:
        """止められたことを記録する。"""
        self.shutdown_called = True


def _fake_trigger(name: str):
    """CronTrigger / IntervalTrigger の代わり。渡された引数をそのまま覚える。

    実物を使うと、トリガの中身を外から読み出す形が版に依存する。ここで
    覚えておけば「どんな時刻指定で登録したか」をそのまま突き合わせられる。
    """

    class _Trigger:
        def __init__(self, **kwargs: Any) -> None:
            """引数を _recorded へ控える（timezone は除く）。"""
            self._recorded = {k: v for k, v in kwargs.items() if k != "timezone"}

    _Trigger.__name__ = name
    return _Trigger


class LifespanShapeTests(unittest.IsolatedAsyncioTestCase):
    """lifespan が組み立てるものを、順序ごと固定する。"""

    async def _run_lifespan(self, **flags: Any) -> dict[str, Any]:
        """lifespan を1周させて、外へ出た作用を集めて返す。"""
        FakeScheduler.instances.clear()
        order: list[str] = []

        def note(label: str, result: Any = None, name: str | None = None):
            """呼ばれた順を記録する AsyncMock を作る。

            __name__ を付けているのは、スケジューラへ登録された関数を名前で
            突き合わせているため。付けないと差し替えた分が全部 "AsyncMock" に
            なり、**どのジョブにどの関数を登録したかを検証できなくなる。**
            """

            async def _call(*args: Any, **kwargs: Any):
                order.append(label)
                return result

            mock = AsyncMock(side_effect=_call)
            mock.__name__ = name or label
            return mock

        defaults = {
            "WEB_SCHEDULER_ENABLED": True,
            "METAL_AUTO_REPAIR_ENABLED": True,
            "FORECAST_REFRESH_EXTRA_HOURS_JST": ["6", "12", "18"],
        }
        defaults.update(flags)

        reported: list[str] = []

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """報告ループの代わり。名前を記録して、止められるまで待つ。"""
            reported.append(app_name)
            await asyncio.Event().wait()

        with (
            patch.object(app_module, "init_db", note("init_db")),
            patch.object(app_module, "refresh_vapid_config", lambda: order.append("refresh_vapid_config")),
            patch.object(app_module, "_try_acquire_scheduler_lock", note("acquire_lock", result=True)),
            patch.object(app_module, "collect_daily_data", note("collect_daily_data")),
            patch.object(
                app_module, "auto_repair_metalprice_data", note("auto_repair", name="auto_repair_metalprice_data")
            ),
            patch.object(
                app_module,
                "dispatch_top_delta_notification",
                note("dispatch_push", name="dispatch_top_delta_notification"),
            ),
            patch.object(app_module, "_run_startup_test_jobs", note("startup_tests")),
            patch.object(app_module, "_release_scheduler_lock", note("release_lock")),
            patch.object(app_module, "close_db", note("close_db")),
            patch.object(app_module, "AsyncIOScheduler", FakeScheduler),
            patch.object(app_module, "CronTrigger", _fake_trigger("CronTrigger")),
            patch.object(app_module, "IntervalTrigger", _fake_trigger("IntervalTrigger")),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.multiple(app_module, **defaults),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                order.append("--- yield ---")
                # 報告タスクが実際に走り出すところまで進める
                await asyncio.sleep(0)

        scheduler = FakeScheduler.instances[0] if FakeScheduler.instances else None
        return {"order": order, "scheduler": scheduler, "reported": reported}

    async def test_the_startup_jobs_run_in_this_order(self):
        """起動時の作用が、この順で1回ずつ走ること。

        **順序に意味がある。** 日次取得より先に Push 通知を送ると、その日のぶんが
        まだ無い状態で配信する。取得と修復の順が入れ替わると、修復が古い行を見る。
        """
        got = await self._run_lifespan()
        self.assertEqual(
            got["order"],
            [
                "init_db",
                "refresh_vapid_config",
                "acquire_lock",
                "collect_daily_data",
                "auto_repair",
                "dispatch_push",
                "startup_tests",
                "--- yield ---",
                "release_lock",
                "close_db",
            ],
        )

    async def test_every_scheduled_job_keeps_its_id_and_trigger(self):
        """4本のジョブが、同じ id・同じトリガ・同じ猶予で登録されること。

        **id を書き間違えても replace_existing=True なので例外は出ず、黙って
        別のジョブとして増える。** トリガの時刻を間違えても、動かして丸一日
        待つまで分からない。ここで字面ごと固定する。
        """
        got = await self._run_lifespan()
        scheduler = got["scheduler"]
        self.assertIsNotNone(scheduler)
        assert scheduler is not None
        self.assertEqual(
            [(j["id"], j["func"], j["trigger"], j["trigger_args"], j["misfire_grace_time"]) for j in scheduler.jobs],
            [
                (
                    "jst_daily_metal_snapshot_and_forecast",
                    "collect_daily_data",
                    "CronTrigger",
                    {"hour": 0, "minute": 0},
                    3600,
                ),
                (
                    "jst_intraday_forecast_refresh",
                    "collect_weekly_forecast_cache",
                    "CronTrigger",
                    {"hour": "6,12,18", "minute": app_module.FORECAST_REFRESH_MINUTE_JST},
                    1800,
                ),
                (
                    "jst_daily_top_delta_push_notify",
                    "dispatch_top_delta_notification",
                    "CronTrigger",
                    {
                        "hour": app_module.PUSH_NOTIFY_HOUR_JST,
                        "minute": app_module.PUSH_NOTIFY_MINUTE_JST,
                    },
                    7200,
                ),
                (
                    "jst_metalprice_auto_repair",
                    "auto_repair_metalprice_data",
                    "IntervalTrigger",
                    {"minutes": app_module.METAL_AUTO_REPAIR_INTERVAL_MINUTES},
                    max(300, app_module.METAL_AUTO_REPAIR_INTERVAL_MINUTES * 60),
                ),
            ],
        )
        self.assertTrue(scheduler.started, "スケジューラを start していない")
        self.assertTrue(scheduler.shutdown_called, "終了時に shutdown していない")

    async def test_every_job_is_guarded_against_pile_up(self):
        """4本すべてに coalesce と max_instances=1 が付いていること。

        付いていないと、遅れて溜まった実行がまとめて走る。金属価格の取得は
        MetalpriceAPI の無料枠（月100回）を消費するので、二重に走ると枠を食う。
        """
        got = await self._run_lifespan()
        scheduler = got["scheduler"]
        assert scheduler is not None
        for job in scheduler.jobs:
            self.assertTrue(job["coalesce"], f"{job['id']} に coalesce が無い")
            self.assertEqual(job["max_instances"], 1, f"{job['id']} の max_instances が 1 でない")
            self.assertTrue(job["replace_existing"], f"{job['id']} に replace_existing が無い")

    async def test_the_intraday_refresh_forces_a_recompute(self):
        """日中の追加更新だけ force_refresh=True で登録されること。

        JST 0時のぶんは日次取得が済ませているので、日中の回は強制更新でないと
        キャッシュを読んで終わる（＝何もしない）。
        """
        got = await self._run_lifespan()
        scheduler = got["scheduler"]
        assert scheduler is not None
        intraday = [j for j in scheduler.jobs if j["id"] == "jst_intraday_forecast_refresh"][0]
        self.assertEqual(intraday["kwargs"], {"force_refresh": True})

    async def test_without_the_lock_no_scheduler_and_no_startup_jobs(self):
        """ロックを取れなかったワーカーは、起動時ジョブもスケジューラも持たないこと。

        **ここが崩れると、全ワーカーが日次取得を走らせて MetalpriceAPI の無料枠を
        ワーカー数ぶん消費する。** 枠を使い切ってから気づく形になる。
        """
        FakeScheduler.instances.clear()
        order: list[str] = []

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """報告ループの代わり。"""
            await asyncio.Event().wait()

        with (
            patch.object(app_module, "init_db", AsyncMock()),
            patch.object(app_module, "refresh_vapid_config", lambda: None),
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=False)),
            patch.object(app_module, "collect_daily_data", AsyncMock(side_effect=lambda: order.append("collect"))),
            patch.object(app_module, "_release_scheduler_lock", AsyncMock(side_effect=lambda: order.append("release"))),
            patch.object(app_module, "close_db", AsyncMock()),
            patch.object(app_module, "AsyncIOScheduler", FakeScheduler),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.multiple(app_module, WEB_SCHEDULER_ENABLED=True),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                await asyncio.sleep(0)

        self.assertEqual(FakeScheduler.instances, [], "ロック無しでスケジューラを作っている")
        self.assertEqual(order, [], "ロック無しで起動時ジョブを走らせている / 持っていないロックを外している")

    async def test_the_metrics_reporter_runs_regardless_of_the_lock(self):
        """メトリクスの報告は、ロックを取れなくても走ること。

        **スケジューラ担当だけにすると、担当でないワーカーが死んでも Netdata から
        見えない。** ワーカーごとに別のアプリ名（web-<PID>）で報告する。
        """
        reported: list[str] = []

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """報告ループの代わり。名前を記録する。"""
            reported.append(app_name)
            await asyncio.Event().wait()

        FakeScheduler.instances.clear()
        with (
            patch.object(app_module, "init_db", AsyncMock()),
            patch.object(app_module, "refresh_vapid_config", lambda: None),
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=False)),
            patch.object(app_module, "close_db", AsyncMock()),
            patch.object(app_module, "AsyncIOScheduler", FakeScheduler),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.multiple(app_module, WEB_SCHEDULER_ENABLED=True),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                await asyncio.sleep(0)

        self.assertEqual(len(reported), 1)
        self.assertTrue(reported[0].startswith("web-"), f"アプリ名が web-<PID> でない: {reported[0]}")

    async def test_the_reporter_is_stopped_before_the_database_is_closed(self):
        """後始末の順が、報告の停止 → DB を閉じる であること。

        逆にすると、閉じた DB に対してゲージの収集が走って例外になる。
        """
        order: list[str] = []
        stopped = asyncio.Event()

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """止められた時点を記録する。"""
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                order.append("reporter_stopped")
                stopped.set()
                raise

        async def fake_close_db() -> None:
            """閉じた時点を記録する。"""
            order.append("close_db")

        FakeScheduler.instances.clear()
        with (
            patch.object(app_module, "init_db", AsyncMock()),
            patch.object(app_module, "refresh_vapid_config", lambda: None),
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=False)),
            patch.object(app_module, "close_db", fake_close_db),
            patch.object(app_module, "AsyncIOScheduler", FakeScheduler),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.multiple(app_module, WEB_SCHEDULER_ENABLED=True),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                await asyncio.sleep(0)

        self.assertEqual(order, ["reporter_stopped", "close_db"])

    async def test_the_scheduler_is_disabled_entirely_when_turned_off(self):
        """WEB_SCHEDULER_ENABLED=false ならロックも取りに行かないこと。"""
        FakeScheduler.instances.clear()
        touched: list[str] = []

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """報告ループの代わり。"""
            await asyncio.Event().wait()

        with (
            patch.object(app_module, "init_db", AsyncMock()),
            patch.object(app_module, "refresh_vapid_config", lambda: None),
            patch.object(
                app_module,
                "_try_acquire_scheduler_lock",
                AsyncMock(side_effect=lambda: touched.append("acquire") or False),
            ),
            patch.object(app_module, "close_db", AsyncMock()),
            patch.object(app_module, "AsyncIOScheduler", FakeScheduler),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.multiple(app_module, WEB_SCHEDULER_ENABLED=False),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                await asyncio.sleep(0)

        self.assertEqual(touched, [], "無効なのにロックを取りに行っている")
        self.assertEqual(FakeScheduler.instances, [])


class _FakeLockConn:
    """ロックを持つ接続の代わり。execute が失敗するかどうかと、捨て方を記録する。"""

    def __init__(self, *, alive: bool = True, fail_with: BaseException | None = None) -> None:
        """alive=False なら execute が失敗する（接続が切れている）。"""
        self.alive = alive
        self.fail_with = fail_with
        self.calls: list[str] = []

    async def execute(self, statement: Any, params: Any = None) -> None:
        """実行した文を記録する。切れていれば例外を投げる。"""
        self.calls.append(str(statement))
        if self.fail_with is not None:
            raise self.fail_with
        if not self.alive:
            raise ConnectionError("connection is closed")

    async def invalidate(self) -> None:
        """プールへ戻さずに捨てたことを記録する。"""
        self.calls.append("invalidate")

    async def close(self) -> None:
        """閉じた（プールへ返した）ことを記録する。"""
        self.calls.append("close")


class SchedulerLockWatchTests(unittest.IsolatedAsyncioTestCase):
    """スケジューラのロックを持つ接続が切れたとき、担当を降りて取り直すこと。

    ロックは起動時に取った接続を開きっぱなしにして保っている。以前はその接続が
    途中で切れても誰も気づかず、**切れたワーカーはスケジューラを動かし続け、
    外れたロックは次に起動したワーカーが取った。** 日次の価格取得が2本並んで走り、
    MetalpriceAPI の無料枠（月100回）を倍の速さで使う。本番では停止のたびに
    「advisory lock解放に失敗した（connection is closed）」が出ていた。
    """

    def setUp(self) -> None:
        """ロック用接続の置き場を空にし、スケジューラは偽物にする。"""
        FakeScheduler.instances.clear()
        self._conn_patch = patch.object(app_module, "_scheduler_lock_conn", None)
        self._conn_patch.start()
        self.addCleanup(self._conn_patch.stop)
        self._stack = [
            patch.object(app_module, "AsyncIOScheduler", FakeScheduler),
            patch.object(app_module, "CronTrigger", _fake_trigger("CronTrigger")),
            patch.object(app_module, "IntervalTrigger", _fake_trigger("IntervalTrigger")),
        ]
        for item in self._stack:
            item.start()
            self.addCleanup(item.stop)

    def _holding(self, conn: _FakeLockConn) -> Any:
        """conn でロックを持ち、スケジューラが動いている担当を作る。"""
        app_module._scheduler_lock_conn = conn  # type: ignore[assignment]  # 偽の接続
        duty = app_module._SchedulerDuty()
        duty.holds_lock = True
        duty.start_scheduler()
        return duty

    async def test_a_live_connection_keeps_the_duty_as_it_is(self):
        """接続が生きていれば、何も変えず、取り直しにも行かないこと。"""
        duty = self._holding(_FakeLockConn(alive=True))
        scheduler = duty.scheduler
        acquire = AsyncMock(return_value=True)

        with patch.object(app_module, "_try_acquire_scheduler_lock", acquire):
            await duty.check()

        acquire.assert_not_called()
        self.assertIs(duty.scheduler, scheduler)
        self.assertFalse(scheduler.shutdown_called)

    async def test_a_dead_connection_stops_the_scheduler_before_trying_again(self):
        """切れていたら、取り直しに行く**前に**スケジューラを止めること。

        先に取り直しへ進むと、他のワーカーが引き継いでいた場合に、止め損ねた
        こちらのスケジューラと向こうのスケジューラが同時に日次ジョブを走らせる。
        """
        duty = self._holding(_FakeLockConn(alive=False))
        old = duty.scheduler
        seen: list[bool] = []

        async def acquire() -> bool:
            """呼ばれた時点で古いスケジューラが止まっていたかを控える。"""
            seen.append(old.shutdown_called)
            return False

        with (
            patch.object(app_module, "_try_acquire_scheduler_lock", acquire),
            self.assertLogs(app_module.logger, level="WARNING"),
        ):
            await duty.check()

        self.assertEqual(seen, [True], "スケジューラを止める前に取り直しへ進んでいる")
        self.assertFalse(duty.holds_lock)
        self.assertIsNone(duty.scheduler)

    async def test_it_takes_the_lock_again_without_rerunning_the_startup_jobs(self):
        """取り直せたら新しいスケジューラで担当に戻り、起動時ジョブは走らせないこと。

        起動時ジョブは「起動した日のぶんを作る」処理で、担当が入れ替わるたびに
        走らせると同じ日の取得が重なる。
        """
        duty = self._holding(_FakeLockConn(alive=False))
        startup = AsyncMock()

        with (
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=True)),
            patch.object(app_module, "_run_startup_jobs", startup),
            self.assertLogs(app_module.logger, level="WARNING") as logs,
        ):
            await duty.check()

        self.assertTrue(duty.holds_lock)
        self.assertEqual(len(FakeScheduler.instances), 2, "新しいスケジューラが作られていない")
        self.assertTrue(duty.scheduler.started)
        startup.assert_not_called()
        self.assertTrue(any("取り直した" in r.getMessage() for r in logs.records))

    async def test_the_dead_connection_is_thrown_away_not_returned_to_the_pool(self):
        """切れた接続は invalidate で捨てること（close だけでプールへ返さない）。

        SELECT 1 が一時的に失敗しただけでセッションが生きていた場合、プールへ
        返すとロックを抱えたセッションが別のリクエストに使い回され、誰も
        ロックを取れなくなる。
        """
        conn = _FakeLockConn(alive=False)
        duty = self._holding(conn)

        with (
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=False)),
            self.assertLogs(app_module.logger, level="WARNING"),
        ):
            await duty.check()

        self.assertIn("invalidate", conn.calls)
        self.assertLess(conn.calls.index("invalidate"), conn.calls.index("close"))
        self.assertIsNone(app_module._scheduler_lock_conn)

    async def test_a_worker_without_the_lock_takes_over(self):
        """ロックを持っていなかったワーカーが、空いたロックを引き継ぐこと。

        担当が死んだとき、引き継ぐのは残ったワーカーである。以前は起動時の1回しか
        取りに行かなかったので、担当が死ぬと再起動まで誰も定期ジョブを走らせなかった。
        """
        duty = app_module._SchedulerDuty()

        with (
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=True)),
            self.assertLogs(app_module.logger, level="WARNING") as logs,
        ):
            await duty.check()

        self.assertTrue(duty.holds_lock)
        self.assertTrue(duty.scheduler.started)
        self.assertTrue(any("引き継いだ" in r.getMessage() for r in logs.records))

    async def test_a_worker_without_the_lock_stays_quiet_while_someone_else_holds_it(self):
        """他が持っている間は、何も作らず、何も出さないこと（毎分ログが出るのを避ける）。"""
        duty = app_module._SchedulerDuty()

        with (
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=False)),
            self.assertNoLogs(app_module.logger, level="INFO"),
        ):
            await duty.check()

        self.assertFalse(duty.holds_lock)
        self.assertEqual(FakeScheduler.instances, [])

    async def test_a_database_that_is_down_does_not_break_the_watch(self):
        """取りに行く処理が例外を出しても、check() は例外を外へ出さないこと。"""
        duty = app_module._SchedulerDuty()

        with (
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(side_effect=OSError("db down"))),
            self.assertLogs(app_module.logger, level="WARNING"),
        ):
            await duty.check()

        self.assertFalse(duty.holds_lock)

    async def test_the_watch_keeps_going_after_an_unexpected_failure(self):
        """check() が想定外に落ちても、見張りのループは止まらないこと。

        ここが止まると、ロックを失ったワーカーが担当を名乗り続ける元の状態へ黙って戻る。
        """
        calls: list[int] = []

        async def check() -> None:
            """1回目だけ落ち、3回目で見張りを終わらせる。"""
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            if len(calls) == 3:
                raise asyncio.CancelledError

        duty = app_module._SchedulerDuty()
        duty.check = check  # type: ignore[method-assign]  # 呼ばれた回数だけ見たい
        with (
            patch.object(app_module, "SCHEDULER_LOCK_CHECK_SECONDS", 0),
            self.assertLogs(app_module.logger, level="ERROR"),
            self.assertRaises(asyncio.CancelledError),
        ):
            await app_module._watch_scheduler_lock(duty)

        self.assertEqual(len(calls), 3)

    async def test_releasing_a_lock_whose_connection_is_gone_is_not_an_error(self):
        """停止時に接続が既に切れていたら、例外の全文ではなく1行で済ませること。

        切れた時点で Postgres がロックを外しているので、外すものは残っていない。
        以前は停止のたびに100行近いトレースバックが ERROR で出ていた。
        """
        from sqlalchemy.exc import InterfaceError

        conn = _FakeLockConn(fail_with=InterfaceError("SELECT pg_advisory_unlock($1)", {}, Exception("closed")))
        app_module._scheduler_lock_conn = conn  # type: ignore[assignment]  # 偽の接続

        with self.assertLogs(app_module.logger, level="INFO") as logs:
            await app_module._release_scheduler_lock()

        self.assertEqual([r.levelname for r in logs.records], ["INFO"])
        self.assertIn("close", conn.calls)
        self.assertIsNone(app_module._scheduler_lock_conn)

    async def test_the_lifespan_stops_the_watch_before_the_scheduler(self):
        """後始末で、見張りを止めてからスケジューラを止めること。

        逆だと、止めたばかりのスケジューラを見張りが「担当が居ない」と読んで
        取り直しに行く。
        """
        order: list[str] = []
        started = asyncio.Event()

        async def fake_watch(duty: Any) -> None:
            """止められた時点を記録する。"""
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                order.append("watch_stopped")
                raise

        class RecordingScheduler(FakeScheduler):
            """止められた時点を記録するスケジューラ。"""

            def shutdown(self, wait: bool = True) -> None:
                """止められたことを order へ記録する。"""
                order.append("scheduler_stopped")
                super().shutdown(wait)

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """報告ループの代わり。"""
            await asyncio.Event().wait()

        with (
            patch.object(app_module, "init_db", AsyncMock()),
            patch.object(app_module, "refresh_vapid_config", lambda: None),
            patch.object(app_module, "_try_acquire_scheduler_lock", AsyncMock(return_value=True)),
            patch.object(app_module, "_run_startup_jobs", AsyncMock()),
            patch.object(app_module, "_release_scheduler_lock", AsyncMock(side_effect=lambda: order.append("release"))),
            patch.object(app_module, "close_db", AsyncMock()),
            patch.object(app_module, "AsyncIOScheduler", RecordingScheduler),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.object(app_module, "_watch_scheduler_lock", fake_watch),
            patch.multiple(app_module, WEB_SCHEDULER_ENABLED=True),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                await asyncio.wait_for(started.wait(), 1)

        self.assertEqual(order, ["watch_stopped", "scheduler_stopped", "release"])

    async def test_the_watch_is_not_started_when_the_scheduler_is_off(self):
        """WEB_SCHEDULER_ENABLED=false なら、見張りも動かさないこと。"""
        watch = AsyncMock()

        async def fake_report_forever(app_name: str, **kwargs: Any) -> None:
            """報告ループの代わり。"""
            await asyncio.Event().wait()

        with (
            patch.object(app_module, "init_db", AsyncMock()),
            patch.object(app_module, "refresh_vapid_config", lambda: None),
            patch.object(app_module, "close_db", AsyncMock()),
            patch.object(app_module, "report_forever", fake_report_forever),
            patch.object(app_module, "_watch_scheduler_lock", watch),
            patch.multiple(app_module, WEB_SCHEDULER_ENABLED=False),
        ):
            async with app_module.lifespan(None):  # type: ignore[arg-type]  # 引数は使われない
                await asyncio.sleep(0)

        watch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
