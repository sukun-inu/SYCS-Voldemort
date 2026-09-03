"""services/user_state_service.py のテスト。

    python -m unittest discover -s tests -t .

このサービス層はユーザー状態の長期監査 DB（Postgres 想定）を直接操作する。
CI に Postgres は無いため、`services.user_state_service.SessionLocal` を
差し替えて検証する（tests/test_admin_api.py 冒頭のコメントと同じ方針:
「DB を必要とするユーザー状態監査は services 層を差し替えて検証する」）。

差し替え先は本物の SQLAlchemy ORM をインメモリ SQLite に向けた薄いラッパー。
select/where/order_by/limit/offset/delete/func.count など、本番と同じ
SQLAlchemy Core の式を本物の SQL として実行するので、フィルタ条件や
並び順、件数の打ち切りまで本物の挙動で確認できる。実 DB（Postgres）にも
ネットワークにも一切出ない。
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

# services/* は読み込み時に SETTINGS_DIR を解決するため、import より前に差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="user-state-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
# 配信キャッシュは SETTINGS_DIR とは別の設定なので、明示的に隔離する。
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="user-state-test-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import services.user_state_service as uss  # noqa: E402
from webapp.models import UserStateCurrent, UserStateEvent  # noqa: E402


# ---------------------------------------------------------------------------
# インメモリ SQLite を services.user_state_service.SessionLocal の代わりに使うための細工。
# ---------------------------------------------------------------------------


class _FakeAsyncSession:
    """本物の同期 Session を、await できる薄い皮だけ被せて包む。

    本番の SessionLocal は asyncpg 前提の async_sessionmaker で Postgres が
    無いと動かせない。ここでは同じ ORM モデル・同じ SQL 文をインメモリ
    SQLite の同期セッションで実際に実行し、`async with` / `await` の形だけ
    本番コードに合わせる。
    """

    def __init__(self, sync_session):
        self._session = sync_session

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._session.close()
        return False

    def add(self, obj):
        self._session.add(obj)

    async def scalars(self, stmt):
        return self._session.scalars(stmt)

    async def scalar(self, stmt):
        return self._session.scalar(stmt)

    async def execute(self, stmt):
        return self._session.execute(stmt)

    async def commit(self):
        self._session.commit()

    async def rollback(self):
        self._session.rollback()


class _FailureController:
    """指定回数だけ DB エラーを起こす細工。自己修復リトライの経路を確かめるために使う。"""

    def __init__(self, fail_times: int):
        self.fail_times = fail_times
        self.calls = 0

    def maybe_raise(self) -> None:
        if self.calls < self.fail_times:
            self.calls += 1
            raise OperationalError("SELECT 1", {}, Exception("fake db error"))


class _FlakyFakeAsyncSession(_FakeAsyncSession):
    """commit（または scalars）の直前に _FailureController でエラーを起こせるセッション。"""

    def __init__(self, sync_session, controller: _FailureController, op: str):
        super().__init__(sync_session)
        self._controller = controller
        self._op = op

    async def commit(self):
        if self._op == "commit":
            self._controller.maybe_raise()
        await super().commit()

    async def scalars(self, stmt):
        if self._op == "scalars":
            self._controller.maybe_raise()
        return await super().scalars(stmt)

    async def scalar(self, stmt):
        if self._op == "scalar":
            self._controller.maybe_raise()
        return await super().scalar(stmt)


def _make_engine():
    engine = create_engine("sqlite://")
    UserStateCurrent.__table__.create(bind=engine, checkfirst=True)
    UserStateEvent.__table__.create(bind=engine, checkfirst=True)
    return engine


def _make_session_local(engine):
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    def factory():
        return _FakeAsyncSession(maker())

    return factory


def _make_flaky_session_local(engine, controller: _FailureController, op: str = "commit"):
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    def factory():
        return _FlakyFakeAsyncSession(maker(), controller, op)

    return factory


def _run(coro):
    return asyncio.run(coro)


def _member(
    *,
    id: int = 10,
    name: str = "taro",
    display_name: str | None = "Taro",
    bot: bool = False,
    roles=(),
    administrator: bool = False,
    timed_out_until=None,
):
    permissions = SimpleNamespace(
        administrator=administrator,
        manage_guild=False,
        kick_members=False,
        ban_members=False,
        moderate_members=False,
        manage_roles=False,
    )
    return SimpleNamespace(
        id=id,
        name=name,
        display_name=display_name,
        bot=bot,
        roles=list(roles),
        guild_permissions=permissions,
        timed_out_until=timed_out_until,
    )


def _role(role_id: int, name: str, position: int, *, is_default: bool = False):
    return SimpleNamespace(id=role_id, name=name, position=position, is_default=lambda: is_default)


class _DbBackedTestCase(unittest.TestCase):
    """DB を要するテストの共通セットアップ：インメモリ SQLite へ差し替える。"""

    def setUp(self):
        self.engine = _make_engine()
        self._patchers = [
            patch.object(uss, "SessionLocal", _make_session_local(self.engine)),
            patch.object(uss, "ensure_user_state_db", AsyncMock(return_value=None)),
        ]
        for p in self._patchers:
            p.start()
        self.addCleanup(self._stop_patchers)
        # 保持期間クリーンアップの間隔制御はモジュールグローバルなので、
        # テスト間で汚染されないようにリセットする。
        uss._last_cleanup_at = None

    def _stop_patchers(self):
        for p in reversed(self._patchers):
            p.stop()
        self.engine.dispose()

    def _sync_session(self):
        maker = sessionmaker(bind=self.engine, expire_on_commit=False)
        return maker()


# ---------------------------------------------------------------------------
# 純粋関数（DB 不要）: 正規化ロジックそのもの
# ---------------------------------------------------------------------------


class SanitizeStatusTests(unittest.TestCase):
    """_sanitize_status: 前後空白除去・小文字化・空文字は unknown・長さ制限を確認する。"""

    def test_strips_and_lowercases(self):
        self.assertEqual(uss._sanitize_status("  Active  "), "active")

    def test_empty_or_none_becomes_unknown(self):
        self.assertEqual(uss._sanitize_status(""), "unknown")
        self.assertEqual(uss._sanitize_status("   "), "unknown")
        self.assertEqual(uss._sanitize_status(None), "unknown")

    def test_truncated_to_32_chars(self):
        long_status = "x" * 100
        result = uss._sanitize_status(long_status)
        self.assertEqual(len(result), 32)
        self.assertEqual(result, "x" * 32)


class ExtractUserFieldsTests(unittest.TestCase):
    """_extract_user_fields: username/display_name/avatar_url の抽出と欠損時の扱いを確認する。"""

    def test_none_user_returns_all_none(self):
        self.assertEqual(
            uss._extract_user_fields(None),
            {"username": None, "display_name": None, "avatar_url": None},
        )

    def test_display_name_falls_back_to_username(self):
        user = SimpleNamespace(name="jiro")
        fields = uss._extract_user_fields(user)
        self.assertEqual(fields["display_name"], "jiro")

    def test_names_are_truncated_to_128_chars(self):
        user = SimpleNamespace(name="a" * 200, display_name="b" * 200)
        fields = uss._extract_user_fields(user)
        self.assertEqual(len(fields["username"]), 128)
        self.assertEqual(len(fields["display_name"]), 128)

    def test_avatar_url_prefers_display_avatar(self):
        user = SimpleNamespace(
            name="taro",
            display_name="Taro",
            display_avatar=SimpleNamespace(url="https://cdn.example/display.png"),
            avatar=SimpleNamespace(url="https://cdn.example/avatar.png"),
        )
        fields = uss._extract_user_fields(user)
        self.assertEqual(fields["avatar_url"], "https://cdn.example/display.png")

    def test_avatar_url_falls_back_to_avatar_when_display_avatar_missing(self):
        user = SimpleNamespace(
            name="taro", display_name="Taro", avatar=SimpleNamespace(url="https://cdn.example/a.png")
        )
        fields = uss._extract_user_fields(user)
        self.assertEqual(fields["avatar_url"], "https://cdn.example/a.png")

    def test_avatar_url_is_none_when_both_accessors_fail(self):
        user = SimpleNamespace(name="taro", display_name="Taro")
        fields = uss._extract_user_fields(user)
        self.assertIsNone(fields["avatar_url"])


class ExtractRoleSnapshotTests(unittest.TestCase):
    """_extract_role_snapshot: @everyone の除外・position 降順ソート・壊れた role の無視を確認する。"""

    def test_none_member_returns_empty_list(self):
        self.assertEqual(uss._extract_role_snapshot(None), [])

    def test_non_list_roles_returns_empty_list(self):
        member = SimpleNamespace(roles="not-a-list")
        self.assertEqual(uss._extract_role_snapshot(member), [])

    def test_default_role_is_skipped_and_others_sorted_by_position_desc(self):
        low = _role(1, "低位ロール", 1)
        high = _role(2, "高位ロール", 5)
        everyone = _role(0, "@everyone", 0, is_default=True)
        member = SimpleNamespace(roles=[low, everyone, high])

        result = uss._extract_role_snapshot(member)

        self.assertEqual([r["id"] for r in result], [2, 1])
        self.assertEqual(result[0]["name"], "高位ロール")

    def test_role_raising_exception_is_skipped(self):
        class _Broken:
            def is_default(self):
                raise RuntimeError("boom")

        member = SimpleNamespace(roles=[_Broken(), _role(3, "ok", 2)])
        result = uss._extract_role_snapshot(member)
        self.assertEqual([r["id"] for r in result], [3])


class ExtractAbilitySnapshotTests(unittest.TestCase):
    """_extract_ability_snapshot: 権限フラグ・信頼ユーザー・バイパスロールの反映を確認する。"""

    def test_none_member_returns_empty_dict(self):
        self.assertEqual(uss._extract_ability_snapshot(None, 1), {})

    def test_permission_flags_are_copied(self):
        member = _member(id=1, administrator=True)
        with (
            patch.object(uss, "get_trusted_user_ids", return_value=[]),
            patch.object(uss, "get_bypass_role_ids", return_value=[]),
        ):
            abilities = uss._extract_ability_snapshot(member, guild_id=1)
        self.assertTrue(abilities["administrator"])
        self.assertFalse(abilities["is_bot"])

    def test_trusted_user_flag_reflects_settings_store(self):
        member = _member(id=42)
        with (
            patch.object(uss, "get_trusted_user_ids", return_value=[42]),
            patch.object(uss, "get_bypass_role_ids", return_value=[]),
        ):
            abilities = uss._extract_ability_snapshot(member, guild_id=1)
        self.assertTrue(abilities["trusted_user"])

    def test_bypass_role_flag_reflects_role_membership(self):
        member = _member(id=1, roles=[_role(777, "bypass", 1)])
        with (
            patch.object(uss, "get_trusted_user_ids", return_value=[]),
            patch.object(uss, "get_bypass_role_ids", return_value=[777]),
        ):
            abilities = uss._extract_ability_snapshot(member, guild_id=1)
        self.assertTrue(abilities["bypass_role"])

    def test_settings_store_exceptions_are_swallowed_as_no_special_role(self):
        """設定を読めなくても記録そのものは続ける。

        ここで例外を上へ投げると、ユーザー状態の記録が丸ごと止まる。扱いが
        外れるだけに留めるのが正しい。ただし黙って倒れるのではないことは
        下のテストで確認する。
        """
        member = _member(id=1)
        uss._warned_ability_lookup.clear()
        with (
            patch.object(uss, "get_trusted_user_ids", side_effect=RuntimeError("boom")),
            patch.object(uss, "get_bypass_role_ids", side_effect=RuntimeError("boom")),
        ):
            abilities = uss._extract_ability_snapshot(member, guild_id=1)
        self.assertFalse(abilities["trusted_user"])
        self.assertFalse(abilities["bypass_role"])

    def test_settings_store_failure_is_logged_with_the_reason(self):
        """読めなかった理由をログに残す。

        以前はこの2つの例外だけ無言で握りつぶしていた。同じファイルの他の
        失敗（自己修復・保持期間の掃除）は必ず理由を残す方針なのに、ここだけ
        設定ストアが恒常的に壊れていても誰も気づけない構造だった。
        """
        member = _member(id=1)
        uss._warned_ability_lookup.clear()
        with (
            patch.object(uss, "get_trusted_user_ids", side_effect=RuntimeError("boom")),
            patch.object(uss, "get_bypass_role_ids", side_effect=RuntimeError("boom")),
        ):
            with self.assertLogs(uss.logger, level="WARNING") as captured:
                uss._extract_ability_snapshot(member, guild_id=1)
        self.assertEqual(len(captured.records), 2)  # 信頼ユーザーとバイパスロールで1件ずつ
        self.assertTrue(any("信頼ユーザー" in line for line in captured.output))
        self.assertTrue(any("バイパスロール" in line for line in captured.output))

    def test_the_failure_is_logged_once_not_for_every_member(self):
        """同期はメンバー1人ずつこの関数を呼ぶ。毎回出すとログが埋まる。"""
        uss._warned_ability_lookup.clear()
        with (
            patch.object(uss, "get_trusted_user_ids", side_effect=RuntimeError("boom")),
            patch.object(uss, "get_bypass_role_ids", side_effect=RuntimeError("boom")),
        ):
            with self.assertLogs(uss.logger, level="WARNING") as captured:
                for user_id in range(5):
                    uss._extract_ability_snapshot(_member(id=user_id), guild_id=1)
        self.assertEqual(len(captured.records), 2)  # 5人ぶん回しても最初の1周ぶんだけ

    def test_the_warning_returns_after_the_setting_recovers_and_breaks_again(self):
        """一度知らせたら黙るが、直って再発したらまた知らせる。"""
        member = _member(id=1)
        uss._warned_ability_lookup.clear()
        broken = {"side_effect": RuntimeError("boom")}
        with patch.object(uss, "get_bypass_role_ids", return_value=[]):
            with patch.object(uss, "get_trusted_user_ids", **broken):
                with self.assertLogs(uss.logger, level="WARNING"):
                    uss._extract_ability_snapshot(member, guild_id=1)
            # 読めるようになれば覚えていた印が消える
            with patch.object(uss, "get_trusted_user_ids", return_value=[]):
                uss._extract_ability_snapshot(member, guild_id=1)
            with patch.object(uss, "get_trusted_user_ids", **broken):
                with self.assertLogs(uss.logger, level="WARNING") as again:
                    uss._extract_ability_snapshot(member, guild_id=1)
        self.assertEqual(len(again.records), 1)


class ToAwareUtcTests(unittest.TestCase):
    """_to_aware_utc: None は現在時刻、naive datetime には UTC を付与することを確認する。"""

    def test_none_returns_a_recent_aware_datetime(self):
        before = datetime.now(timezone.utc)
        result = uss._to_aware_utc(None)
        after = datetime.now(timezone.utc)
        self.assertIsNotNone(result.tzinfo)
        self.assertLessEqual(before, result)
        self.assertLessEqual(result, after)

    def test_naive_datetime_gets_utc_attached_without_shifting_value(self):
        naive = datetime(2024, 1, 1, 12, 0, 0)
        result = uss._to_aware_utc(naive)
        self.assertEqual(result, datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc))

    def test_aware_datetime_in_other_timezone_is_converted_to_utc(self):
        from datetime import timezone as tz

        jst = tz(timedelta(hours=9))
        aware = datetime(2024, 1, 1, 21, 0, 0, tzinfo=jst)
        result = uss._to_aware_utc(aware)
        self.assertEqual(result, datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc))


class SafeJsonTests(unittest.TestCase):
    """_safe_json_dumps / _safe_json_loads: シリアライズ失敗時に既定値へ倒れることを確認する。"""

    def test_round_trip(self):
        data = {"a": 1, "日本語": "テスト"}
        dumped = uss._safe_json_dumps(data, "{}")
        self.assertEqual(uss._safe_json_loads(dumped, {}), data)

    def test_dumps_falls_back_when_not_serializable(self):
        # set は json.dumps できないため既定値へ倒れる。
        result = uss._safe_json_dumps({1, 2, 3}, "FALLBACK")
        self.assertEqual(result, "FALLBACK")

    def test_loads_falls_back_on_malformed_json(self):
        self.assertEqual(uss._safe_json_loads("{not-json", {"x": 1}), {"x": 1})

    def test_loads_falls_back_on_empty_or_none(self):
        self.assertEqual(uss._safe_json_loads(None, []), [])
        self.assertEqual(uss._safe_json_loads("", []), [])


class IsTimedOutUntilTests(unittest.TestCase):
    """_is_timed_out_until: タイムアウト終了時刻が未来かどうかの単純な比較を確認する。"""

    def test_none_is_not_timed_out(self):
        self.assertFalse(uss._is_timed_out_until(None, datetime.now(timezone.utc)))

    def test_future_is_timed_out(self):
        now = datetime.now(timezone.utc)
        self.assertTrue(uss._is_timed_out_until(now + timedelta(hours=1), now))

    def test_past_is_not_timed_out(self):
        now = datetime.now(timezone.utc)
        self.assertFalse(uss._is_timed_out_until(now - timedelta(hours=1), now))


class TryDbSelfHealTests(unittest.TestCase):
    """_try_db_self_heal: 再試行してよいエラー種別の判定と、修復失敗時の扱いを確認する。"""

    def test_non_repairable_error_does_not_attempt_heal(self):
        ensure = AsyncMock(return_value=None)
        with patch.object(uss, "ensure_user_state_db", ensure):
            healed = _run(uss._try_db_self_heal(context="test", exc=ValueError("not a db error")))
        self.assertFalse(healed)
        ensure.assert_not_called()

    def test_repairable_error_triggers_heal_and_reports_success(self):
        ensure = AsyncMock(return_value=None)
        with patch.object(uss, "ensure_user_state_db", ensure):
            healed = _run(uss._try_db_self_heal(context="test", exc=OperationalError("SELECT 1", {}, Exception("x"))))
        self.assertTrue(healed)
        ensure.assert_called_once_with(force=True)

    def test_heal_failure_is_reported_as_false_not_raised(self):
        ensure = AsyncMock(side_effect=RuntimeError("still broken"))
        with patch.object(uss, "ensure_user_state_db", ensure):
            healed = _run(uss._try_db_self_heal(context="test", exc=OperationalError("SELECT 1", {}, Exception("x"))))
        self.assertFalse(healed)


# ---------------------------------------------------------------------------
# record_user_state_event: イベント記録の正規化と upsert
# ---------------------------------------------------------------------------


class RecordUserStateEventTests(_DbBackedTestCase):
    def test_event_type_and_status_are_normalized(self):
        """event_type / status_after が小文字化・trim・長さ制限されて保存されることを確認する。"""
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="  Member_Join  ",
                status_after="  ACTIVE  ",
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertEqual(detail["events"][0]["event_type"], "member_join")
        self.assertEqual(detail["current"]["status"], "active")

    def test_member_context_adds_roles_and_abilities_to_payload(self):
        """discord.Member 相当（roles / guild_permissions を持つ）の場合だけ
        payload に roles/abilities が入ることを確認する。"""
        member = _member(id=10, roles=[_role(5, "モデレーター", 3)])
        with (
            patch.object(uss, "get_trusted_user_ids", return_value=[]),
            patch.object(uss, "get_bypass_role_ids", return_value=[]),
        ):
            _run(
                uss.record_user_state_event(
                    guild_id=1,
                    user_id=10,
                    event_type="member_join",
                    status_after="active",
                    user=member,
                )
            )
        detail = _run(uss.get_user_state_detail(1, 10))
        payload = detail["events"][0]["payload"]
        self.assertIn("roles", payload)
        self.assertIn("abilities", payload)
        self.assertEqual(payload["roles"][0]["id"], 5)
        self.assertEqual(detail["current"]["roles"][0]["id"], 5)

    def test_plain_user_without_member_context_has_no_roles_or_abilities_in_payload(self):
        """discord.User 相当（roles を持たない）の場合は roles/abilities を payload に書かないことを確認する。"""
        plain_user = SimpleNamespace(id=10, name="taro", display_name="Taro")
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="member_leave",
                status_after="left",
                user=plain_user,
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        payload = detail["events"][0]["payload"]
        self.assertNotIn("roles", payload)
        self.assertNotIn("abilities", payload)

    def test_second_event_updates_existing_row_instead_of_creating_a_duplicate(self):
        """同一 guild_id/user_id への2回目の記録は UserStateCurrent を1行のまま更新することを確認する（upsert）。"""
        _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_join", status_after="active"))
        _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_leave", status_after="left"))

        rows = _run(uss.list_recent_user_states(1))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "left")

        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertEqual(len(detail["events"]), 2)

    def test_status_active_infers_in_guild_true_and_banned_false_when_not_specified(self):
        """in_guild / is_banned を明示しない場合、status_after から妥当な値へ推定されることを確認する。"""
        _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_join", status_after="active"))
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertTrue(detail["current"]["is_in_guild"])
        self.assertFalse(detail["current"]["is_banned"])

    def test_status_banned_infers_in_guild_false_and_banned_true(self):
        _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_ban", status_after="banned"))
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertFalse(detail["current"]["is_in_guild"])
        self.assertTrue(detail["current"]["is_banned"])

    def test_explicit_in_guild_and_is_banned_override_inference(self):
        """明示的に渡した in_guild/is_banned は status からの推定より優先されることを確認する。"""
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="odd_event",
                status_after="active",
                in_guild=False,
                is_banned=True,
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertFalse(detail["current"]["is_in_guild"])
        self.assertTrue(detail["current"]["is_banned"])

    def test_member_timeout_cleared_resets_timeout_fields(self):
        """member_timeout_cleared イベントは timed_out_until を明示的に None へ戻すことを確認する。"""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="member_timeout",
                status_after="active",
                timed_out_until=future,
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertTrue(detail["current"]["is_timed_out"])

        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="member_timeout_cleared",
                status_after="active",
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertFalse(detail["current"]["is_timed_out"])
        self.assertIsNone(detail["current"]["timed_out_until"])

    def test_actor_with_zero_id_is_recorded_as_none(self):
        """actor.id が 0/falsy の場合、actor_user_id は 0 ではなく None として保存されることを確認する。"""
        actor = SimpleNamespace(id=0, name="system", display_name="System")
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="member_kick",
                status_after="kicked",
                actor=actor,
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertIsNone(detail["events"][0]["actor_user_id"])

    def test_reason_is_truncated_to_2000_chars(self):
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="member_ban",
                status_after="banned",
                reason="x" * 3000,
            )
        )
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertEqual(len(detail["events"][0]["reason"]), 2000)

    def test_a_failing_retention_cleanup_does_not_lose_the_event(self):
        """保持期間の掃除が失敗しても、イベントは記録すること。

        掃除は「古い履歴を捨てる」だけの付随処理で、本筋は目の前のイベントを
        残すこと。ここで例外が抜けると、**掃除が失敗している間じゅう
        BAN も入退室も1件も残らない。** 掃除が壊れるのは DB が不調なときだけ
        なので、平常時のテストでは再現しない。

        109行あるこの関数を割る前に押さえる
        （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
        """
        with (
            patch.object(uss, "_cleanup_old_events_if_needed", AsyncMock(side_effect=RuntimeError("掃除が落ちた"))),
            self.assertLogs(uss.logger, level="ERROR"),
        ):
            _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_join", status_after="active"))

        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertEqual(len(detail["events"]), 1)

    def test_the_timeout_deadline_is_kept_in_the_event_payload(self):
        """タイムアウトの期限を、履歴の payload にも残すこと。

        最新状態（UserStateCurrent）にも入るが、そちらは**次のイベントで
        上書きされる**。「いつまでの制限だったか」を後から辿れるのは履歴側
        だけなので、ここが抜けると解除後に何も分からなくなる。
        """
        until = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
        _run(
            uss.record_user_state_event(
                guild_id=1,
                user_id=10,
                event_type="member_timeout",
                status_after="timeout",
                timed_out_until=until,
            )
        )

        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertEqual(detail["events"][0]["payload"]["timed_out_until"], until.isoformat())

    def test_a_user_with_only_one_member_attribute_is_not_treated_as_a_member(self):
        """roles と guild_permissions の**両方**が揃ってはじめて Member 扱いにすること。

        片方だけで通すと、権限を持たない相手に対して権限の一覧を組み立てに
        行き、payload に空の abilities が入る。**役職が無いのか、調べられ
        なかったのかが区別できなくなる。** webhook 経由の投稿者など、
        属性が欠けた相手は実際に来る。
        """
        half = SimpleNamespace(id=10, name="taro", display_name="Taro", bot=False, roles=[])
        _run(
            uss.record_user_state_event(
                guild_id=1, user_id=10, event_type="member_join", status_after="active", user=half
            )
        )

        payload = _run(uss.get_user_state_detail(1, 10))["events"][0]["payload"]
        self.assertNotIn("roles", payload)
        self.assertNotIn("abilities", payload)

    def test_the_history_and_the_current_state_are_written_together(self):
        """履歴と最新状態は、同じトランザクションで書くこと。

        別々にコミットすると、あいだで落ちたときに**履歴には残っているのに
        最新状態が古いまま**という食い違いが残る。管理画面はこの2つを並べて
        出すので、見た人はどちらを信じるか分からない。

        最新状態の更新だけを落として、履歴も残っていないことを見る。
        """
        with (
            patch.object(uss, "_update_current_state_fields", Mock(side_effect=RuntimeError("更新が落ちた"))),
            self.assertLogs(uss.logger, level="ERROR"),
        ):
            _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_join", status_after="active"))

        self.assertIsNone(_run(uss.get_user_state_detail(1, 10)), "履歴だけが残っている")

    def test_transient_db_error_is_retried_after_self_heal_and_event_is_recorded(self):
        """コミット時に1回だけ DB エラーが起きても、自己修復してリトライし記録が完了することを確認する。

        保持期間クリーンアップ（_cleanup_old_events_if_needed）も同じ
        SessionLocal を使って commit するため、対象を record 本体の
        リトライ経路だけに絞るためクリーンアップは no-op にしておく。
        """
        controller = _FailureController(fail_times=1)
        ensure_mock = AsyncMock(return_value=None)
        with (
            patch.object(uss, "SessionLocal", _make_flaky_session_local(self.engine, controller, op="commit")),
            patch.object(uss, "ensure_user_state_db", ensure_mock),
            patch.object(uss, "_cleanup_old_events_if_needed", AsyncMock(return_value=None)),
        ):
            _run(uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_join", status_after="active"))

        self.assertEqual(controller.calls, 1)
        ensure_mock.assert_any_call(force=True)

        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertIsNotNone(detail)
        self.assertEqual(len(detail["events"]), 1)

    def test_permanent_db_error_is_swallowed_without_raising_and_nothing_is_written(self):
        """自己修復してもなお失敗する場合、例外を外へ投げず静かに諦めることを確認する（呼び出し元のイベント処理を落とさないため）。"""
        controller = _FailureController(fail_times=99)
        with (
            patch.object(uss, "SessionLocal", _make_flaky_session_local(self.engine, controller, op="commit")),
            patch.object(uss, "ensure_user_state_db", AsyncMock(return_value=None)),
            patch.object(uss, "_cleanup_old_events_if_needed", AsyncMock(return_value=None)),
        ):
            try:
                _run(
                    uss.record_user_state_event(guild_id=1, user_id=10, event_type="member_join", status_after="active")
                )
            except Exception as e:  # pragma: no cover - 失敗したらテストを落とす
                self.fail(f"record_user_state_event が例外を外へ漏らした: {e!r}")

        self.assertEqual(controller.calls, 2)  # 2回とも試行はされている
        detail = _run(uss.get_user_state_detail(1, 10))
        self.assertIsNone(detail)


# ---------------------------------------------------------------------------
# sync_guild_user_states: 同期の作成/更新/整合、失敗時も継続すること
# ---------------------------------------------------------------------------


class SyncGuildUserStatesTests(_DbBackedTestCase):
    def test_new_members_are_created_and_marked_active(self):
        members = [_member(id=1, name="a"), _member(id=2, name="b")]
        stats = _run(uss.sync_guild_user_states(guild_id=1, members=members, banned_users=[]))

        self.assertEqual(stats["members_seen"], 2)
        self.assertEqual(stats["created"], 2)
        self.assertEqual(stats["updated"], 0)

        rows = _run(uss.list_recent_user_states(1))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["status"] == "active" for r in rows))

    def test_existing_members_are_updated_not_duplicated(self):
        member = _member(id=1, name="a")
        _run(uss.sync_guild_user_states(guild_id=1, members=[member], banned_users=[]))
        stats = _run(uss.sync_guild_user_states(guild_id=1, members=[member], banned_users=[]))

        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["updated"], 1)
        rows = _run(uss.list_recent_user_states(1))
        self.assertEqual(len(rows), 1)

    def test_banned_user_overrides_active_status(self):
        """同じ user_id が members にも banned_users にも入っていた場合、banned が最終的に勝つことを確認する。"""
        target = SimpleNamespace(id=1)
        members = [_member(id=1, name="a")]
        stats = _run(uss.sync_guild_user_states(guild_id=1, members=members, banned_users=[target]))

        self.assertEqual(stats["bans_seen"], 1)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertEqual(detail["current"]["status"], "banned")
        self.assertTrue(detail["current"]["is_banned"])

    def test_reconcile_missing_marks_absent_active_users_as_left(self):
        """前回は active だったが今回の members/bans に居ないユーザーは left へ整合されることを確認する。"""
        m1 = _member(id=1, name="a")
        m2 = _member(id=2, name="b")
        _run(uss.sync_guild_user_states(guild_id=1, members=[m1, m2], banned_users=[]))

        stats = _run(uss.sync_guild_user_states(guild_id=1, members=[m1], banned_users=[], reconcile_missing=True))

        self.assertEqual(stats["left_reconciled"], 1)
        detail = _run(uss.get_user_state_detail(1, 2))
        self.assertEqual(detail["current"]["status"], "left")
        self.assertFalse(detail["current"]["is_in_guild"])

    def test_reconcile_missing_false_leaves_absent_users_untouched(self):
        m1 = _member(id=1, name="a")
        m2 = _member(id=2, name="b")
        _run(uss.sync_guild_user_states(guild_id=1, members=[m1, m2], banned_users=[]))

        stats = _run(uss.sync_guild_user_states(guild_id=1, members=[m1], banned_users=[], reconcile_missing=False))

        self.assertEqual(stats["left_reconciled"], 0)
        detail = _run(uss.get_user_state_detail(1, 2))
        self.assertEqual(detail["current"]["status"], "active")

    def test_reconcile_missing_skips_users_already_banned(self):
        """BAN 済みユーザーは members/bans どちらにも出て来なくなっても left で上書きしないことを確認する。"""
        target = SimpleNamespace(id=1)
        _run(uss.sync_guild_user_states(guild_id=1, members=[], banned_users=[target]))

        stats = _run(uss.sync_guild_user_states(guild_id=1, members=[], banned_users=[], reconcile_missing=True))

        self.assertEqual(stats["left_reconciled"], 0)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertEqual(detail["current"]["status"], "banned")

    def test_write_events_on_sync_false_suppresses_event_rows(self):
        member = _member(id=1, name="a")
        stats = _run(
            uss.sync_guild_user_states(guild_id=1, members=[member], banned_users=[], write_events_on_sync=False)
        )
        self.assertEqual(stats["events_written"], 0)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertEqual(detail["events"], [])

    def test_source_label_is_truncated_to_32_chars(self):
        """source は32文字に切られ、last_event_type とイベント payload の両方に反映されることを確認する。"""
        member = _member(id=1, name="a")
        long_source = "s" * 100
        _run(uss.sync_guild_user_states(guild_id=1, members=[member], banned_users=[], source=long_source))
        detail = _run(uss.get_user_state_detail(1, 1))

        truncated_source = "s" * 32
        self.assertEqual(detail["current"]["last_event_type"], f"sync_member_{truncated_source}")
        self.assertEqual(detail["events"][0]["payload"]["source"], truncated_source)

    def test_permanent_db_failure_returns_without_raising_and_persists_nothing(self):
        """1ギルドの同期が最終的に失敗しても例外を投げず戻ることを確認する。

        events/user_state_sync 側はギルドごとにこの関数を呼び出しており、
        ここで例外が漏れると他ギルドの同期まで巻き込んで止めてしまう。

        あわせて、戻り値の件数が 0 になることも確認する。stats はループの中で
        加算していくので、失敗して rollback したときに加算済みの値をそのまま
        返すと、DB には1行も無いのに created: 1 が返る。呼び出し元がこれを
        成功件数としてログや監視へ出すと、まるごと失敗した同期が「一部成功」
        に見えてしまう。
        """
        controller = _FailureController(fail_times=99)
        member = _member(id=1, name="a")
        with (
            patch.object(uss, "SessionLocal", _make_flaky_session_local(self.engine, controller, op="commit")),
            patch.object(uss, "ensure_user_state_db", AsyncMock(return_value=None)),
            patch.object(uss, "_cleanup_old_events_if_needed", AsyncMock(return_value=None)),
        ):
            try:
                stats = _run(uss.sync_guild_user_states(guild_id=1, members=[member], banned_users=[]))
            except Exception as e:  # pragma: no cover
                self.fail(f"sync_guild_user_states が例外を外へ漏らした: {e!r}")

        # 例外は外へ漏れず、stats は返る（＝呼び出し元の継続は保証されている）。
        self.assertIsInstance(stats, dict)
        # 何も保存されていない。
        rows = _run(uss.list_recent_user_states(1))
        self.assertEqual(rows, [])
        # 件数も 0。保存できていないものを「作成した」と数えない。
        self.assertEqual(
            stats,
            {
                "members_seen": 0,
                "bans_seen": 0,
                "created": 0,
                "updated": 0,
                "left_reconciled": 0,
                "events_written": 0,
            },
        )

    def test_transient_db_failure_is_retried_after_self_heal(self):
        controller = _FailureController(fail_times=1)
        member = _member(id=1, name="a")
        with (
            patch.object(uss, "SessionLocal", _make_flaky_session_local(self.engine, controller, op="commit")),
            patch.object(uss, "ensure_user_state_db", AsyncMock(return_value=None)),
            patch.object(uss, "_cleanup_old_events_if_needed", AsyncMock(return_value=None)),
        ):
            stats = _run(uss.sync_guild_user_states(guild_id=1, members=[member], banned_users=[]))

        self.assertEqual(stats["created"], 1)
        self.assertEqual(controller.calls, 1)
        rows = _run(uss.list_recent_user_states(1))
        self.assertEqual(len(rows), 1)


# ---------------------------------------------------------------------------
# repair_user_state_integrity: 整合性の修復
# ---------------------------------------------------------------------------


class SyncGuildUserStatesWholeRunTests(_DbBackedTestCase):
    """1回の同期で、3つの段が同時に動いたときの結果を丸ごと固定する。

    215行ある `sync_guild_user_states` を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    上の SyncGuildUserStatesTests は「新規は created が増える」「BAN が勝つ」
    のように**1つずつ**確かめている。割るときに怖いのはそこではなく、
    **段どうしの噛み合わせ**である。

      - 同じ人が members と bans の両方に居ると、updated が2回数えられないか
      - BAN された人が、その後の「居ないので left」に巻き込まれないか
      - イベント行が、必要なぶんだけ書かれているか（多くても少なくてもだめ）

    数え間違いは例外を出さない。**監査ログの件数が静かにずれるだけ**で、
    見ているのは後から数字を読む人だけになる。
    """

    def test_one_pass_over_members_bans_and_absentees_is_unchanged(self):
        """メンバー・BAN・不在者が同時に出てくる同期の、統計と最終状態。

        2回目の同期で次が同時に起きる。

            user 1 … 居続けている（updated）
            user 2 … 居なくなった（left へ整合）
            user 3 … BAN された（members からも消えている）
            user 4 … 新しく現れた（created）
        """
        first = [_member(id=1, name="a"), _member(id=2, name="b"), _member(id=3, name="c")]
        _run(uss.sync_guild_user_states(guild_id=1, members=first, banned_users=[]))

        stats = _run(
            uss.sync_guild_user_states(
                guild_id=1,
                members=[_member(id=1, name="a"), _member(id=4, name="d")],
                banned_users=[SimpleNamespace(id=3)],
                source="mixed_sync",
            )
        )

        self.assertEqual(
            stats,
            {
                "members_seen": 2,
                "bans_seen": 1,
                "created": 1,
                "updated": 2,
                "left_reconciled": 1,
                "events_written": 3,
            },
        )

        actual = []
        for user_id in (1, 2, 3, 4):
            current = _run(uss.get_user_state_detail(1, user_id))["current"]
            actual.append((user_id, current["status"], bool(current["is_in_guild"]), bool(current["is_banned"])))
        self.assertEqual(
            actual,
            [
                (1, "active", True, False),
                (2, "left", False, False),
                (3, "banned", False, True),
                (4, "active", True, False),
            ],
        )

    def test_re_syncing_the_same_ban_does_not_write_a_second_event(self):
        """既に banned の人をもう一度 BAN 一覧で見ても、イベント行を増やさないこと。

        監査履歴は「状態が変わったとき」に1行入る。同期のたびに1行入ると、
        起動のたびに同じ BAN が積み上がり、**履歴を読んでも何回 BAN された
        のか分からなくなる**。件数がずれるだけで例外は出ない。
        """
        _run(uss.sync_guild_user_states(guild_id=1, members=[_member(id=3, name="c")], banned_users=[]))
        first = _run(uss.sync_guild_user_states(guild_id=1, members=[], banned_users=[SimpleNamespace(id=3)]))
        again = _run(
            uss.sync_guild_user_states(guild_id=1, members=[], banned_users=[SimpleNamespace(id=3)], source="again")
        )

        self.assertEqual(first["events_written"], 1, "BAN になった回はイベントを書く")
        self.assertEqual(again["events_written"], 0, "同じ BAN でもう1行書いている")
        self.assertEqual(again["updated"], 1)


class RepairUserStateIntegrityTests(_DbBackedTestCase):
    def _insert_raw(self, **overrides):
        base = dict(
            guild_id=1,
            user_id=1,
            username="taro",
            status="unknown",
            is_in_guild=False,
            is_banned=False,
            is_timed_out=False,
            roles_json="[]",
            abilities_json="{}",
        )
        base.update(overrides)
        with self._sync_session() as session:
            row = UserStateCurrent(**base)
            session.add(row)
            session.commit()

    def test_status_whitespace_and_case_are_normalized(self):
        self._insert_raw(status="  ACTIVE  ")
        stats = _run(uss.repair_user_state_integrity(guild_id=1))
        self.assertEqual(stats["status_fixed"], 1)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertEqual(detail["current"]["status"], "active")

    def test_invalid_roles_json_is_reset_to_empty_list(self):
        self._insert_raw(roles_json='"not-a-list"')
        stats = _run(uss.repair_user_state_integrity(guild_id=1))
        self.assertEqual(stats["json_fixed"], 1)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertEqual(detail["current"]["roles"], [])

    def test_invalid_abilities_json_is_reset_to_empty_dict(self):
        self._insert_raw(abilities_json="[1,2,3]")
        stats = _run(uss.repair_user_state_integrity(guild_id=1))
        self.assertEqual(stats["json_fixed"], 1)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertEqual(detail["current"]["abilities"], {})

    def test_banned_status_forces_banned_true_and_in_guild_false(self):
        self._insert_raw(status="banned", is_banned=False, is_in_guild=True)
        stats = _run(uss.repair_user_state_integrity(guild_id=1))
        self.assertEqual(stats["flag_fixed"], 2)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertTrue(detail["current"]["is_banned"])
        self.assertFalse(detail["current"]["is_in_guild"])

    def test_left_status_forces_in_guild_false(self):
        self._insert_raw(status="left", is_in_guild=True)
        stats = _run(uss.repair_user_state_integrity(guild_id=1))
        self.assertEqual(stats["flag_fixed"], 1)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertFalse(detail["current"]["is_in_guild"])

    def test_timed_out_flag_is_recalculated_from_timestamp(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        self._insert_raw(is_timed_out=True, timed_out_until=past)
        stats = _run(uss.repair_user_state_integrity(guild_id=1))
        self.assertEqual(stats["timeout_fixed"], 1)
        detail = _run(uss.get_user_state_detail(1, 1))
        self.assertFalse(detail["current"]["is_timed_out"])

    def test_only_target_guild_rows_are_touched(self):
        """guild_id を指定した場合、他ギルドの壊れた行には手を出さないことを確認する。"""
        self._insert_raw(guild_id=1, user_id=1, status="  ACTIVE  ")
        self._insert_raw(guild_id=2, user_id=1, status="  ACTIVE  ")

        stats = _run(uss.repair_user_state_integrity(guild_id=1))

        self.assertEqual(stats["rows_scanned"], 1)
        detail_g2 = _run(uss.get_user_state_detail(2, 1))
        self.assertEqual(detail_g2["current"]["status"], "  ACTIVE  ")

    def test_max_rows_is_clamped_to_a_minimum_of_100(self):
        """max_rows に極端に小さい値を渡しても、下限100へ引き上げられて全行が対象になることを確認する。"""
        for i in range(3):
            self._insert_raw(guild_id=1, user_id=i, status="  ACTIVE  ")

        stats = _run(uss.repair_user_state_integrity(guild_id=1, max_rows=1))

        self.assertEqual(stats["rows_scanned"], 3)


# ---------------------------------------------------------------------------
# list_recent_user_states / count_user_states / get_user_state_detail: 一覧・検索・件数の打ち切り
# ---------------------------------------------------------------------------


class ListingAndDetailTests(_DbBackedTestCase):
    def setUp(self):
        super().setUp()
        members = [
            _member(id=100, name="alice", display_name="Alice"),
            _member(id=200, name="bob", display_name="Bob"),
            _member(id=1002, name="carol", display_name="Carol"),
        ]
        _run(uss.sync_guild_user_states(guild_id=1, members=members, banned_users=[]))

    def test_filter_by_exact_numeric_user_id(self):
        rows = _run(uss.list_recent_user_states(1, query="100"))
        user_ids = {r["user_id"] for r in rows}
        # "100" は 100 と完全一致、かつ 1002 のような前方一致にもマッチする。
        self.assertIn(100, user_ids)
        self.assertIn(1002, user_ids)
        self.assertNotIn(200, user_ids)

    def test_filter_by_name_substring_is_case_insensitive(self):
        rows = _run(uss.list_recent_user_states(1, query="ALI"))
        self.assertEqual([r["user_id"] for r in rows], [100])

    def test_no_query_returns_all_rows_in_guild(self):
        rows = _run(uss.list_recent_user_states(1))
        self.assertEqual(len(rows), 3)

    def test_count_user_states_matches_filtered_rows(self):
        total = _run(uss.count_user_states(1))
        self.assertEqual(total, 3)
        filtered = _run(uss.count_user_states(1, query="bob"))
        self.assertEqual(filtered, 1)

    def test_limit_is_clamped_to_a_minimum_of_1(self):
        """limit=0 のような値でも、下限1へ引き上げられて0件応答にならないことを確認する。"""
        rows = _run(uss.list_recent_user_states(1, limit=0))
        self.assertEqual(len(rows), 1)

    def test_negative_offset_is_clamped_to_0(self):
        rows_a = _run(uss.list_recent_user_states(1, offset=0))
        rows_b = _run(uss.list_recent_user_states(1, offset=-5))
        self.assertEqual([r["user_id"] for r in rows_a], [r["user_id"] for r in rows_b])

    def test_get_user_state_detail_returns_none_when_nothing_found(self):
        detail = _run(uss.get_user_state_detail(1, 999999))
        self.assertIsNone(detail)

    def test_get_user_state_detail_combines_current_and_events(self):
        detail = _run(uss.get_user_state_detail(1, 100))
        self.assertIsNotNone(detail["current"])
        self.assertGreaterEqual(len(detail["events"]), 1)

    def test_event_limit_is_clamped_to_a_minimum_of_1(self):
        for _ in range(3):
            _run(uss.record_user_state_event(guild_id=1, user_id=100, event_type="note", status_after="active"))
        detail = _run(uss.get_user_state_detail(1, 100, event_limit=0))
        self.assertEqual(len(detail["events"]), 1)


# ---------------------------------------------------------------------------
# 保持期間による掃除
# ---------------------------------------------------------------------------


class RetentionCleanupTests(_DbBackedTestCase):
    def test_events_older_than_retention_cutoff_are_deleted(self):
        """USER_STATE_RETENTION_DAYS より古いイベントが掃除で削除されることを確認する。"""
        now = datetime.now(timezone.utc)
        with self._sync_session() as session:
            old_event = UserStateEvent(
                guild_id=1,
                user_id=1,
                event_type="old",
                status_after="active",
                payload_json="{}",
                event_at=now - timedelta(days=10),
            )
            recent_event = UserStateEvent(
                guild_id=1,
                user_id=1,
                event_type="recent",
                status_after="active",
                payload_json="{}",
                event_at=now - timedelta(hours=1),
            )
            session.add_all([old_event, recent_event])
            session.commit()

        with patch.object(uss, "USER_STATE_RETENTION_DAYS", 5):
            _run(uss._cleanup_old_events_if_needed(now))

        with self._sync_session() as session:
            remaining = [e.event_type for e in session.query(UserStateEvent).all()]
        self.assertEqual(remaining, ["recent"])

    def test_cleanup_is_skipped_within_the_interval(self):
        """直前に掃除したばかりなら、間隔内の再呼び出しは何もしないことを確認する。"""
        now = datetime.now(timezone.utc)
        with self._sync_session() as session:
            session.add(
                UserStateEvent(
                    guild_id=1,
                    user_id=1,
                    event_type="old",
                    status_after="active",
                    payload_json="{}",
                    event_at=now - timedelta(days=10),
                )
            )
            session.commit()

        with (
            patch.object(uss, "USER_STATE_RETENTION_DAYS", 5),
            patch.object(uss, "USER_STATE_CLEANUP_INTERVAL_SECONDS", 3600),
        ):
            _run(uss._cleanup_old_events_if_needed(now))
            # 直後に呼んでも間隔内なので掃除は走らない。ここで新しく古いイベントを
            # 足しても消えないはず。
            with self._sync_session() as session:
                session.add(
                    UserStateEvent(
                        guild_id=1,
                        user_id=2,
                        event_type="old2",
                        status_after="active",
                        payload_json="{}",
                        event_at=now - timedelta(days=10),
                    )
                )
                session.commit()
            _run(uss._cleanup_old_events_if_needed(now + timedelta(seconds=1)))

        with self._sync_session() as session:
            remaining = {e.event_type for e in session.query(UserStateEvent).all()}
        self.assertIn("old2", remaining)

    def test_cleanup_runs_again_after_the_interval_has_elapsed(self):
        now = datetime.now(timezone.utc)
        with (
            patch.object(uss, "USER_STATE_RETENTION_DAYS", 5),
            patch.object(uss, "USER_STATE_CLEANUP_INTERVAL_SECONDS", 300),
        ):
            _run(uss._cleanup_old_events_if_needed(now))
            with self._sync_session() as session:
                session.add(
                    UserStateEvent(
                        guild_id=1,
                        user_id=3,
                        event_type="old3",
                        status_after="active",
                        payload_json="{}",
                        event_at=now - timedelta(days=10),
                    )
                )
                session.commit()
            later = now + timedelta(seconds=301)
            _run(uss._cleanup_old_events_if_needed(later))

        with self._sync_session() as session:
            remaining = {e.event_type for e in session.query(UserStateEvent).all()}
        self.assertNotIn("old3", remaining)


# ---------------------------------------------------------------------------
# USER_STATE_* 環境変数が実際にモジュール定数へ反映されること
# ---------------------------------------------------------------------------


class EnvVarsAffectModuleConstantsTests(unittest.TestCase):
    """USER_STATE_RETENTION_DAYS / USER_STATE_CLEANUP_INTERVAL_SECONDS が
    実際に環境変数から読まれ、下限でクランプされることを確認する。

    値はモジュール読み込み時に env_int で1度だけ決まるため、
    importlib.reload で読み直して確認し、終了後は必ず元の環境・
    モジュール状態へ戻す。
    """

    def _reload_with_env(self, **env_overrides):
        with patch.dict(os.environ, env_overrides):
            importlib.reload(uss)
        return uss

    def tearDown(self):
        # 環境変数はテスト内の with を抜けた時点で元に戻っているので、
        # 最後にもう一度読み直せばモジュール定数も既定の状態へ戻る。
        importlib.reload(uss)

    def test_retention_days_reflects_env_when_above_minimum(self):
        reloaded = self._reload_with_env(USER_STATE_RETENTION_DAYS="4000")
        self.assertEqual(reloaded.USER_STATE_RETENTION_DAYS, 4000)

    def test_retention_days_below_minimum_is_clamped_to_3650(self):
        """3650日未満を env で指定しても、監査要件の下限より短くはならないことを確認する。"""
        reloaded = self._reload_with_env(USER_STATE_RETENTION_DAYS="10")
        self.assertEqual(reloaded.USER_STATE_RETENTION_DAYS, 3650)

    def test_cleanup_interval_reflects_env_when_above_minimum(self):
        reloaded = self._reload_with_env(USER_STATE_CLEANUP_INTERVAL_SECONDS="7200")
        self.assertEqual(reloaded.USER_STATE_CLEANUP_INTERVAL_SECONDS, 7200)

    def test_cleanup_interval_below_minimum_is_clamped_to_300(self):
        reloaded = self._reload_with_env(USER_STATE_CLEANUP_INTERVAL_SECONDS="1")
        self.assertEqual(reloaded.USER_STATE_CLEANUP_INTERVAL_SECONDS, 300)


if __name__ == "__main__":
    unittest.main()
