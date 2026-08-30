"""events/ パッケージ（bot_setup.setup_events の分割先）のテスト。

    python -m unittest discover -s tests -t .

setup_events(bot) は元々1,210行の単一クロージャで、Discord/DB に依存しない
純粋な判定ロジックまで含めて一切テストされていなかった。events/ へ分割した
際に切り出した「bot を経由しない・依存を注入できる」関数だけを狙って、
分割の副産物としてカバレッジを上げる。

test_services.py と同じ方針: Discord とネットワークには一切触らない。
discord.py の型は SimpleNamespace / Mock(spec=...) で最小限だけ用意し、
DB を触るサービス関数は unittest.mock.patch で差し替える。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

# services/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# events.*（経由で services）の import より前に一時ディレクトリへ差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="events-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="events-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import events.background_tasks as bg  # noqa: E402
import events.user_state_sync as uss  # noqa: E402
import events.voice as voice  # noqa: E402


def _async_gen_from(items):
    """呼ぶたびに items を1件ずつ返す async generator 関数を作る。

    discord.py の guild.fetch_members() / guild.bans() / guild.audit_logs()
    はどれも async generator を返す API なので、テスト用の guild にも
    同じ形（呼び出し可能で、呼ぶと async for できるもの）を持たせる。
    """

    async def gen(*_args, **_kwargs):
        for it in items:
            yield it

    return gen


def _raising_agen(exc: Exception):
    """呼ぶと async for に入った瞬間に exc を送出する async generator 関数。

    discord.Forbidden 等は HTTP 応答が返ってから分かる（呼び出し時点では
    分からない）ので、関数呼び出し自体ではなく最初の __anext__ で例外を
    出す必要がある。
    """

    async def gen(*_args, **_kwargs):
        raise exc
        yield  # pragma: no cover - 型を async generator にするためだけの到達不能コード

    return gen


class FindRecentAuditEntryTests(unittest.TestCase):
    """_find_recent_audit_entry の絞り込み条件（権限/対象ID/時間窓）を固定する。

    on_member_remove などがこの関数の結果でログ種別（退出 vs kick）を
    切り替えるため、絞り込みを誤ると監査ログの理由が本人の意思による退出に
    見えてしまう。
    """

    def _guild(self, *, can_view_audit_log=True, entries=()):
        me = SimpleNamespace(guild_permissions=SimpleNamespace(view_audit_log=can_view_audit_log))
        return SimpleNamespace(me=me, audit_logs=_async_gen_from(list(entries)))

    def _entry(self, *, user_id, created_at, user=None, reason=None):
        return SimpleNamespace(target=SimpleNamespace(id=user_id), created_at=created_at, user=user, reason=reason)

    def test_guild_me_is_none_returns_none_without_calling_the_api(self):
        def _must_not_call(*_a, **_kw):
            raise AssertionError("me が無い時点で audit_logs は呼ばれてはいけない")

        guild = SimpleNamespace(me=None, audit_logs=_must_not_call)
        result = asyncio.run(
            uss._find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.kick,
                target_user_id=1,
            )
        )
        self.assertIsNone(result)

    def test_no_view_audit_log_permission_returns_none_without_calling_the_api(self):
        def _must_not_call(*_a, **_kw):
            raise AssertionError("権限が無い時点で audit_logs は呼ばれてはいけない")

        guild = SimpleNamespace(
            me=SimpleNamespace(guild_permissions=SimpleNamespace(view_audit_log=False)),
            audit_logs=_must_not_call,
        )
        result = asyncio.run(
            uss._find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.kick,
                target_user_id=1,
            )
        )
        self.assertIsNone(result)

    def test_matching_recent_entry_is_returned(self):
        now = discord.utils.utcnow()
        entry = self._entry(user_id=42, created_at=now - timedelta(seconds=3))
        guild = self._guild(entries=[entry])
        result = asyncio.run(
            uss._find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.kick,
                target_user_id=42,
                retries=0,
            )
        )
        self.assertIs(result, entry)

    def test_entry_for_a_different_user_is_ignored(self):
        now = discord.utils.utcnow()
        entry = self._entry(user_id=999, created_at=now - timedelta(seconds=3))
        guild = self._guild(entries=[entry])
        result = asyncio.run(
            uss._find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.kick,
                target_user_id=42,
                retries=0,
            )
        )
        self.assertIsNone(result)

    def test_entry_outside_the_time_window_is_ignored(self):
        """window_seconds より前の操作は、今回の参加/退出とは無関係とみなして拾わない。"""
        now = discord.utils.utcnow()
        entry = self._entry(user_id=42, created_at=now - timedelta(seconds=120))
        guild = self._guild(entries=[entry])
        result = asyncio.run(
            uss._find_recent_audit_entry(
                guild,
                action=discord.AuditLogAction.kick,
                target_user_id=42,
                window_seconds=20,
                retries=0,
            )
        )
        self.assertIsNone(result)


class FetchGuildMembersForSyncTests(unittest.TestCase):
    """_USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD による打ち切りまわりを固定する。"""

    def test_default_zero_means_unlimited_and_fetched_all_is_true(self):
        guild = SimpleNamespace(id=1, fetch_members=_async_gen_from([SimpleNamespace(id=1), SimpleNamespace(id=2)]))
        with patch("events.user_state_sync._USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", 0):
            members, fetched_all = asyncio.run(uss._fetch_guild_members_for_sync(guild))
        self.assertEqual(len(members), 2)
        self.assertTrue(fetched_all)

    def test_a_positive_limit_marks_fetched_all_false(self):
        """limit を切って取得した場合、全員取れた保証が無いので fetched_all=False。

        呼び出し元（_sync_user_state_all_guilds）はこれで
        reconcile_missing（居なくなった扱いへの倒し込み）の可否を決める。
        limit 未満しか実際には来ていなくても、指定した時点で判定は変わらない。
        """
        guild = SimpleNamespace(id=1, fetch_members=_async_gen_from([SimpleNamespace(id=1)]))
        with patch("events.user_state_sync._USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", 500):
            members, fetched_all = asyncio.run(uss._fetch_guild_members_for_sync(guild))
        self.assertEqual(len(members), 1)
        self.assertFalse(fetched_all)

    def test_forbidden_falls_back_to_the_cached_member_list(self):
        exc = discord.Forbidden(Mock(status=403, reason="Forbidden"), "missing permission")
        guild = SimpleNamespace(
            id=1,
            fetch_members=_raising_agen(exc),
            members=[SimpleNamespace(id=7)],
        )
        with patch("events.user_state_sync._USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", 0):
            members, fetched_all = asyncio.run(uss._fetch_guild_members_for_sync(guild))
        self.assertEqual([m.id for m in members], [7])
        self.assertFalse(fetched_all)


class SyncUserStateAllGuildsTests(unittest.TestCase):
    """_sync_user_state_all_guilds のギルド横断オーケストレーションを固定する。

    DB本体（services.user_state_service.sync_guild_user_states）は
    services 層の責務なのでここでは差し替え、「どのギルドに何を渡して
    何回呼ぶか」だけを見る。
    """

    def _guild(self, guild_id, *, members=(), bans=()):
        ban_entries = [SimpleNamespace(user=u) for u in bans]
        return SimpleNamespace(
            id=guild_id,
            fetch_members=_async_gen_from(list(members)),
            bans=_async_gen_from(ban_entries),
            members=list(members),
        )

    def test_syncs_each_guild_once_with_its_own_members_and_bans(self):
        g1 = self._guild(1, members=[SimpleNamespace(id=10)])
        g2 = self._guild(2, bans=[SimpleNamespace(id=20)])
        bot = SimpleNamespace(guilds=[g1, g2])
        calls = []

        async def _fake_sync(**kwargs):
            calls.append(kwargs)
            return {
                "members_seen": len(kwargs["members"]),
                "bans_seen": len(kwargs["banned_users"]),
                "created": 0,
                "updated": 0,
                "left_reconciled": 0,
                "events_written": 0,
            }

        with (
            patch("events.user_state_sync.sync_guild_user_states", side_effect=_fake_sync),
            patch("events.user_state_sync._USER_STATE_SYNC_GUILD_PAUSE_SECONDS", 0),
        ):
            asyncio.run(
                uss._sync_user_state_all_guilds(
                    bot,
                    source="test",
                    write_events_on_sync=False,
                    run_integrity_repair=False,
                    lock=asyncio.Lock(),
                )
            )

        self.assertEqual([c["guild_id"] for c in calls], [1, 2])
        self.assertEqual(len(calls[0]["members"]), 1)
        self.assertEqual(len(calls[0]["banned_users"]), 0)
        self.assertEqual(len(calls[1]["banned_users"]), 1)

    def test_one_guild_failing_does_not_stop_the_others(self):
        """1ギルドの同期失敗が他ギルドまで止めないこと。

        実運用ではBotが蹴られた/権限を失ったサーバーが1つあるだけで
        全ギルドの定期同期が止まると被害が大きい。
        """
        g1 = self._guild(1)
        g2 = self._guild(2, members=[SimpleNamespace(id=99)])
        bot = SimpleNamespace(guilds=[g1, g2])
        seen_guild_ids = []

        async def _fake_sync(**kwargs):
            if kwargs["guild_id"] == 1:
                raise RuntimeError("boom")
            seen_guild_ids.append(kwargs["guild_id"])
            return {
                "members_seen": 0,
                "bans_seen": 0,
                "created": 0,
                "updated": 0,
                "left_reconciled": 0,
                "events_written": 0,
            }

        with (
            patch("events.user_state_sync.sync_guild_user_states", side_effect=_fake_sync),
            patch("events.user_state_sync._USER_STATE_SYNC_GUILD_PAUSE_SECONDS", 0),
        ):
            asyncio.run(
                uss._sync_user_state_all_guilds(
                    bot,
                    source="test",
                    write_events_on_sync=False,
                    run_integrity_repair=False,
                    lock=asyncio.Lock(),
                )
            )

        self.assertEqual(seen_guild_ids, [2])


class TtsVcBecameEmptyTests(unittest.TestCase):
    """_tts_vc_became_empty の判定（監視VCと一致 + 人間ゼロ）を固定する。

    以前は on_voice_state_update の冒頭と末尾で少し違う条件を別々に
    書いていたため、退出時に切断されたりされなかったりが分かりにくかった。
    """

    def test_channel_none_is_false(self):
        self.assertFalse(voice._tts_vc_became_empty(1, None))

    def test_channel_not_watched_is_false(self):
        channel = SimpleNamespace(id=555, members=[])
        with (
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(999, [])),
        ):
            self.assertFalse(voice._tts_vc_became_empty(1, channel))

    def test_watched_channel_with_only_bots_is_true(self):
        channel = SimpleNamespace(id=555, members=[SimpleNamespace(bot=True)])
        with (
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(555, [])),
        ):
            self.assertTrue(voice._tts_vc_became_empty(1, channel))

    def test_watched_channel_with_a_human_present_is_false(self):
        channel = SimpleNamespace(id=555, members=[SimpleNamespace(bot=False)])
        with (
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(555, [])),
        ):
            self.assertFalse(voice._tts_vc_became_empty(1, channel))


class ComputeVcTransitionTests(unittest.TestCase):
    """join/leave/move の判定と、退出時の滞在時間の算出を固定する。

    vc_join_times は on_voice_state_update の呼び出しをまたいで register()
    側が持ち続ける辞書で、この関数が直接書き換える。
    """

    def test_join_records_the_time_and_reports_no_duration(self):
        times: dict = {}
        ch = SimpleNamespace(id=1)
        is_join, is_leave, is_move, dur_s, dur_str = voice._compute_vc_transition(
            (1, 2),
            1000.0,
            None,
            ch,
            times,
        )
        self.assertTrue(is_join)
        self.assertFalse(is_leave or is_move)
        self.assertEqual(times[(1, 2)], 1000.0)
        self.assertIsNone(dur_s)
        self.assertEqual(dur_str, "")

    def test_leave_computes_duration_from_the_recorded_join(self):
        times = {(1, 2): 1000.0}
        ch = SimpleNamespace(id=1)
        is_join, is_leave, is_move, dur_s, dur_str = voice._compute_vc_transition(
            (1, 2),
            1000.0 + 3661,
            ch,
            None,
            times,
        )
        self.assertTrue(is_leave)
        self.assertEqual(dur_s, 3661)
        self.assertEqual(dur_str, "01:01:01")
        self.assertNotIn((1, 2), times, "退出を記録したら入室時刻は pop されているはず")

    def test_leave_without_a_recorded_join_has_no_duration(self):
        """Bot再起動などで入室を取り逃した退出は、時間を捏造せず空にする。"""
        times: dict = {}
        ch = SimpleNamespace(id=1)
        _, is_leave, _, dur_s, dur_str = voice._compute_vc_transition(
            (1, 2),
            1000.0,
            ch,
            None,
            times,
        )
        self.assertTrue(is_leave)
        self.assertIsNone(dur_s)
        self.assertEqual(dur_str, "")

    def test_move_is_neither_join_nor_leave(self):
        times: dict = {}
        ch1, ch2 = SimpleNamespace(id=1), SimpleNamespace(id=2)
        is_join, is_leave, is_move, _, _ = voice._compute_vc_transition(
            (1, 2),
            1000.0,
            ch1,
            ch2,
            times,
        )
        self.assertTrue(is_move)
        self.assertFalse(is_join or is_leave)

    def test_join_prunes_stale_entries_once_the_table_grows_past_256(self):
        """退出を取り逃した記録が無限に溜まらないよう、257件目の入室で
        TTL切れ（_VC_JOIN_TTL_SECONDS より前）だけを間引く。"""
        now = 100000.0
        stale_ts = now - voice._VC_JOIN_TTL_SECONDS - 1
        times = {(0, i): stale_ts for i in range(256)}
        ch = SimpleNamespace(id=1)
        voice._compute_vc_transition((9, 9), now, None, ch, times)
        self.assertEqual(times, {(9, 9): now})


class FormatStatusTextTests(unittest.TestCase):
    """update_status が組み立てる表示文字列（bot.latency の異常値耐性）を固定する。"""

    def test_finite_latency_is_shown_in_milliseconds(self):
        text = bg._format_status_text(12.3, 45.6, 0.0512)
        self.assertEqual(text, "Ping: 51ms | CPU: 12.3% | MEM: 45.6%")

    def test_infinite_latency_falls_back_to_na(self):
        """bot.latency は heartbeat 未受信のあいだ inf を返す。「infms」のような
        表示にはしない。"""
        text = bg._format_status_text(1, 2, float("inf"))
        self.assertEqual(text, "Ping: N/A | CPU: 1% | MEM: 2%")

    def test_nan_latency_falls_back_to_na(self):
        text = bg._format_status_text(1, 2, float("nan"))
        self.assertEqual(text, "Ping: N/A | CPU: 1% | MEM: 2%")

    def test_non_numeric_latency_falls_back_to_na(self):
        text = bg._format_status_text(1, 2, None)
        self.assertEqual(text, "Ping: N/A | CPU: 1% | MEM: 2%")


class VcNotifyFilterTests(unittest.TestCase):
    """VC通知のフィルターロールによる絞り込み。

    この設定は「そのロールから見える VC の出入りだけ通知する」ためのもので、
    非公開の VC の出入りを通知チャンネル経由で全員へ漏らさないために使う。
    壊れたときに通知が止まるのは直せるが、漏れた通知は取り消せない。
    """

    def setUp(self):
        voice._warned_missing_filter_role.clear()

    @staticmethod
    def _channel(*, visible: bool):
        return SimpleNamespace(
            permissions_for=lambda role: SimpleNamespace(view_channel=visible),
        )

    @staticmethod
    def _guild(role):
        return SimpleNamespace(id=1, get_role=lambda role_id: role)

    def test_no_filter_configured_lets_everything_through(self):
        guild = self._guild(object())
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=None):
            self.assertTrue(voice._passes_vc_notify_filter(guild, True, False, None, self._channel(visible=False)))

    def test_visible_channel_passes(self):
        guild = self._guild(object())
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=77):
            self.assertTrue(voice._passes_vc_notify_filter(guild, True, False, None, self._channel(visible=True)))

    def test_invisible_channel_is_filtered_out(self):
        guild = self._guild(object())
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=77):
            self.assertFalse(voice._passes_vc_notify_filter(guild, True, False, None, self._channel(visible=False)))

    def test_move_passes_when_either_side_is_visible(self):
        """移動は移動元と移動先の両方が関係する。片方でも見えるなら通知する。"""
        guild = self._guild(object())
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=77):
            self.assertTrue(
                voice._passes_vc_notify_filter(
                    guild, False, True, self._channel(visible=False), self._channel(visible=True)
                )
            )
            self.assertFalse(
                voice._passes_vc_notify_filter(
                    guild, False, True, self._channel(visible=False), self._channel(visible=False)
                )
            )

    def test_deleted_filter_role_blocks_instead_of_letting_everything_through(self):
        """設定したロールが削除されていたら、通知を止める。

        以前は `if filter_role:` で包んでいたため、ロールが見つからないと
        絞り込みごと素通りし、フィルター無しと同じ＝全 VC の出入りが通知
        されていた。設定した意図と正反対で、非公開 VC の出入りが漏れる。
        """
        guild = self._guild(None)  # ロールが削除済み
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=77):
            self.assertFalse(voice._passes_vc_notify_filter(guild, True, False, None, self._channel(visible=True)))

    def test_missing_role_is_logged_once_not_on_every_event(self):
        """理由はログに残す。ただし VC の出入りごとに出すとログが埋まる。"""
        guild = self._guild(None)
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=77):
            with self.assertLogs(voice.logger, level="WARNING") as captured:
                for _ in range(5):
                    voice._passes_vc_notify_filter(guild, True, False, None, None)
        self.assertEqual(len(captured.records), 1)
        self.assertIn("77", captured.output[0])

    def test_the_warning_returns_after_the_role_comes_back_and_goes_again(self):
        """一度警告したら黙るが、直って再発したらまた知らせる。"""
        missing = self._guild(None)
        restored = self._guild(object())
        with patch.object(voice, "get_vc_notify_filter_role_id", return_value=77):
            with self.assertLogs(voice.logger, level="WARNING"):
                voice._passes_vc_notify_filter(missing, True, False, None, None)
            # ロールが戻れば通知は再開し、覚えていた警告済みの印も消える
            self.assertTrue(voice._passes_vc_notify_filter(restored, True, False, None, self._channel(visible=True)))
            with self.assertLogs(voice.logger, level="WARNING") as again:
                voice._passes_vc_notify_filter(missing, True, False, None, None)
        self.assertEqual(len(again.records), 1)


if __name__ == "__main__":
    unittest.main()
