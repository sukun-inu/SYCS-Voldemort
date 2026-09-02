"""カバレッジの薄い commands/ 配下（record・djaudio・chat・interaction_utils の
エラーハンドラ）を狙って埋めるテスト。

    python -m unittest tests.test_commands_coverage -v

Discord へは繋がず、tests/test_commands.py と同じ方針で Interaction を
Mock/SimpleNamespace で用意し、呼び出しの順序・引数・応答内容だけを見る。

commands/record/ は commands/recording_commands.py の分割で新設された
パッケージで、実処理は commands.record.session / config / exclude にある
（経緯は commands/record/__init__.py を参照）。したがって patch は
commands.recording_commands 側ではなく、これら実体モジュールへ当てる。
app_commands.Group だけは discord.py 側のモジュール属性そのものなので、
どこか1箇所でパッチすれば全モジュールに効く。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="commands-coverage-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="commands-coverage-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402
from discord import app_commands  # noqa: E402


def make_interaction(*, administrator: bool = True, guild: bool = True):
    """応答の呼ばれ方を記録する Interaction。tests/test_commands.py と同じ形。"""
    calls: list[str] = []
    interaction = Mock(
        spec_set=[
            "guild",
            "guild_id",
            "user",
            "client",
            "channel",
            "response",
            "followup",
        ]
    )
    interaction.guild = Mock(id=999) if guild else None
    interaction.guild_id = 999 if guild else None
    interaction.user = Mock(id=1, display_name="tester")
    interaction.user.guild_permissions = Mock(administrator=administrator)
    interaction.user.voice = None
    interaction.client = Mock()
    interaction.channel = Mock(mention="#general")

    done = {"value": False}
    response = Mock()
    response.is_done = Mock(side_effect=lambda: done["value"])

    async def _defer(*a, **k):
        calls.append("defer")
        done["value"] = True

    async def _send(*a, **k):
        calls.append("response.send_message")
        done["value"] = True

    response.defer = _defer
    response.send_message = _send
    interaction.response = response

    async def _followup(*a, **k):
        calls.append("followup.send")

    interaction.followup = Mock()
    interaction.followup.send = _followup
    return interaction, calls


class _FakeCommand:
    """テスト用の疑似 Command。

    djaudio_commands.py は bind_permission_error_handler() の中で
    `@command.error` を使ってエラーハンドラを登録する。FakeGroup.command() が
    ただの関数を返すだけだと、その関数には .error が無く AttributeError で
    落ちる（実際に一度その事故を踏んだ）。呼び出しは元の関数へ委譲しつつ、
    .error() に渡されたハンドラだけ拾えるようにしておく。
    """

    def __init__(self, fn):
        self.callback = fn
        self.error_handler = None

    def __call__(self, *args, **kwargs):
        return self.callback(*args, **kwargs)

    def error(self, fn):
        self.error_handler = fn
        return fn


def _make_group():
    """コマンドを登録して、名前から呼び出せるようにする（test_commands.py の FakeGroup と同じ形）。"""
    registry: dict[str, _FakeCommand] = {}

    class FakeGroup:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def command(self, *, name, description=""):
            def wrap(fn):
                cmd = _FakeCommand(fn)
                registry[name] = cmd
                return cmd

            return wrap

        def add_command(self, *a, **k):
            pass

    return registry, FakeGroup


def _register_record():
    """/record グループを登録する。パッチ対象は commands.record.* の実体側。"""
    import commands.record.config as rcfg
    import commands.record.exclude as rex
    import commands.record.session as rs
    import commands.recording_commands as rc

    registry, FakeGroup = _make_group()
    with patch.object(rc.app_commands, "Group", FakeGroup):
        rc.register_recording_commands(Mock())
    return rs, rcfg, rex, registry


def _register_djaudio():
    import commands.djaudio_commands as dj

    registry, FakeGroup = _make_group()
    with patch.object(dj.app_commands, "Group", FakeGroup):
        dj.register_djaudio_commands(Mock())
    return dj, registry


# ── /record start・stop・status（commands/record/session.py） ──────────────


class RecordStartTests(unittest.TestCase):
    def setUp(self):
        self.rs, _, _, self.registry = _register_record()
        self.start = self.registry["start"]

    def test_refuses_non_admin(self):
        # channel を明示して「VCが分からぬ」経路を避け、ガード自体を検証する。
        # channel=None のままだと、ガードが無くても voice 未接続の早期returnで
        # start_recording が呼ばれず、ガードを検証できていないことになる。
        interaction, calls = make_interaction(administrator=False)
        vc = Mock(spec=discord.VoiceChannel, id=99, name="general")
        with patch.object(self.rs.recording, "start_recording", AsyncMock()) as start:
            asyncio.run(self.start(interaction, channel=vc))
        start.assert_not_called()
        self.assertTrue(calls, "何も返していない")

    def test_no_channel_specified_and_not_in_voice_refuses_with_guidance(self):
        interaction, calls = make_interaction(administrator=True)
        interaction.user.voice = None
        with patch.object(self.rs.recording, "start_recording", AsyncMock()) as start:
            asyncio.run(self.start(interaction))
        start.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    def test_voice_state_channel_that_is_not_a_voice_channel_is_rejected(self):
        """StageChannel などVCでないものに繋いでいる場合も、type を確認して弾くこと。"""
        interaction, calls = make_interaction(administrator=True)
        interaction.user.voice = Mock(channel=Mock())  # discord.VoiceChannel の spec ではない
        with patch.object(self.rs.recording, "start_recording", AsyncMock()) as start:
            asyncio.run(self.start(interaction))
        start.assert_not_called()

    def test_defer_happens_before_start_recording(self):
        """外部処理（VC接続を伴う録音開始）を待つ前に defer すること。"""
        interaction, calls = make_interaction(administrator=True)
        vc = Mock(spec=discord.VoiceChannel, id=1, name="general")
        interaction.user.voice = Mock(channel=vc)
        seen = []

        async def slow_start(*a, **k):
            seen.append(list(calls))
            return SimpleNamespace(is_unlimited=True, max_seconds=0)

        with patch.object(self.rs.recording, "start_recording", slow_start):
            asyncio.run(self.start(interaction))
        self.assertTrue(seen, "start_recording が呼ばれていない")
        self.assertIn("defer", seen[0], f"開始前の応答: {seen[0]}")

    def test_explicit_channel_argument_is_used_without_consulting_voice_state(self):
        interaction, calls = make_interaction(administrator=True)
        vc = Mock(spec=discord.VoiceChannel, id=2, name="配信用")
        session = SimpleNamespace(is_unlimited=True, max_seconds=0)
        with patch.object(self.rs.recording, "start_recording", AsyncMock(return_value=session)) as start:
            asyncio.run(self.start(interaction, channel=vc))
        start.assert_awaited_once()
        self.assertIs(start.call_args.args[2], vc)
        self.assertIs(start.call_args.kwargs["started_by"], interaction.user)
        self.assertIs(start.call_args.kwargs["announce_to"], interaction.channel)

    def test_recording_error_is_reported_and_does_not_crash(self):
        interaction, calls = make_interaction(administrator=True)
        vc = Mock(spec=discord.VoiceChannel, id=3, name="general")
        interaction.user.voice = Mock(channel=vc)
        with patch.object(
            self.rs.recording,
            "start_recording",
            AsyncMock(side_effect=self.rs.recording.RecordingError("録音機能は無効だ")),
        ):
            asyncio.run(self.start(interaction))
        self.assertEqual(calls, ["defer", "followup.send"], str(calls))

    def test_unlimited_session_message_mentions_participants_leaving(self):
        interaction, calls = make_interaction(administrator=True)
        vc = Mock(spec=discord.VoiceChannel, id=4, name="general")
        interaction.user.voice = Mock(channel=vc)
        session = SimpleNamespace(is_unlimited=True, max_seconds=0)
        sent = {}

        async def fake_followup(content, **k):
            sent["content"] = content

        interaction.followup.send = fake_followup
        with patch.object(self.rs.recording, "start_recording", AsyncMock(return_value=session)):
            asyncio.run(self.start(interaction))
        self.assertIn("全員が退出したときに止まる", sent["content"])

    def test_limited_session_message_states_the_minutes(self):
        interaction, calls = make_interaction(administrator=True)
        vc = Mock(spec=discord.VoiceChannel, id=5, name="general")
        interaction.user.voice = Mock(channel=vc)
        session = SimpleNamespace(is_unlimited=False, max_seconds=1800)  # 30分
        sent = {}

        async def fake_followup(content, **k):
            sent["content"] = content

        interaction.followup.send = fake_followup
        with patch.object(self.rs.recording, "start_recording", AsyncMock(return_value=session)):
            asyncio.run(self.start(interaction))
        self.assertIn("30 分で自動的に止まる", sent["content"])


class RecordStopTests(unittest.TestCase):
    def setUp(self):
        self.rs, _, _, self.registry = _register_record()
        self.stop = self.registry["stop"]

    def test_refuses_non_admin(self):
        # is_recording を True にして「録音していない」経路を避け、ガード自体を
        # 検証する。素の False のままだと、ガードが無くてもそちらの早期return
        # で stop_recording が呼ばれず、ガードを検証できていないことになる。
        interaction, calls = make_interaction(administrator=False)
        with (
            patch.object(self.rs.recording, "is_recording", Mock(return_value=True)),
            patch.object(self.rs.recording, "stop_recording", AsyncMock()) as stop,
        ):
            asyncio.run(self.stop(interaction))
        stop.assert_not_called()
        self.assertTrue(calls)

    def test_refuses_when_not_currently_recording(self):
        interaction, calls = make_interaction(administrator=True)
        with (
            patch.object(self.rs.recording, "is_recording", Mock(return_value=False)),
            patch.object(self.rs.recording, "stop_recording", AsyncMock()) as stop,
        ):
            asyncio.run(self.stop(interaction))
        stop.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    def test_recording_error_is_reported_without_an_embed(self):
        interaction, calls = make_interaction(administrator=True)
        with (
            patch.object(self.rs.recording, "is_recording", Mock(return_value=True)),
            patch.object(
                self.rs.recording,
                "stop_recording",
                AsyncMock(side_effect=self.rs.recording.RecordingError("失敗した")),
            ),
            patch.object(self.rs.recording, "build_result_embed") as build_embed,
        ):
            asyncio.run(self.stop(interaction))
        build_embed.assert_not_called()
        self.assertEqual(calls, ["defer", "followup.send"], str(calls))

    def test_success_sends_the_result_embed(self):
        interaction, calls = make_interaction(administrator=True)
        sentinel_embed = object()
        sent = {}

        async def fake_followup(**k):
            sent.update(k)

        interaction.followup.send = fake_followup
        with (
            patch.object(self.rs.recording, "is_recording", Mock(return_value=True)),
            patch.object(self.rs.recording, "stop_recording", AsyncMock(return_value={"ok": True})),
            patch.object(self.rs.recording, "build_result_embed", Mock(return_value=sentinel_embed)) as build_embed,
        ):
            asyncio.run(self.stop(interaction))
        build_embed.assert_called_once_with(999, {"ok": True})
        self.assertIs(sent.get("embed"), sentinel_embed)


class RecordStatusTests(unittest.TestCase):
    """/record status の embed 組み立て。管理者ガードと「録音していない」は
    tests/test_commands.py の AdminGuardTests で確認済みなので、ここでは
    embed の中身の分岐（無制限/時間制限・発話者の有無）を埋める。
    """

    def setUp(self):
        self.rs, _, _, self.registry = _register_record()
        self.status_cmd = self.registry["status"]

    def _run(self, status: dict):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        session = Mock()
        session.status = Mock(return_value=status)
        with patch.object(self.rs.recording, "get_session", Mock(return_value=session)):
            asyncio.run(self.status_cmd(interaction))
        return sent["embed"]

    def _base_status(self, **overrides):
        status = {
            "channel_name": "雑談",
            "elapsed_seconds": 65,
            "started_by": "tester",
            "unlimited": False,
            "max_seconds": 600,
            "speakers": [],
        }
        status.update(overrides)
        return status

    def test_unlimited_session_shows_the_stop_condition_field(self):
        embed = self._run(self._base_status(unlimited=True))
        names = [f.name for f in embed.fields]
        self.assertIn("停止条件", names)
        self.assertNotIn("自動停止まで", names)
        field = next(f for f in embed.fields if f.name == "停止条件")
        self.assertEqual(field.value, "全員が退出したとき")

    def test_limited_session_shows_remaining_time_with_hours(self):
        """残り時間が1時間を超えると _duration が「◯時間◯分◯秒」の形式になること。"""
        # max_seconds - elapsed_seconds = 7300 - 100 = 7200秒 = 2時間0分0秒
        embed = self._run(self._base_status(unlimited=False, max_seconds=7300, elapsed_seconds=100))
        field = next(f for f in embed.fields if f.name == "自動停止まで")
        self.assertEqual(field.value, "2時間0分0秒")

    def test_remaining_time_never_goes_negative(self):
        """経過が上限を超えていても、残り時間の表示はマイナスにならないこと。"""
        embed = self._run(self._base_status(unlimited=False, max_seconds=60, elapsed_seconds=999))
        field = next(f for f in embed.fields if f.name == "自動停止まで")
        self.assertEqual(field.value, "0分0秒")

    def test_speakers_are_listed_when_present(self):
        speakers = [{"name": "太郎", "voiced_seconds": 3725}]  # 1時間2分5秒
        embed = self._run(self._base_status(speakers=speakers))
        field = next(f for f in embed.fields if f.name == "録音中の参加者")
        self.assertIn("太郎", field.value)
        self.assertIn("1時間2分5秒", field.value)

    def test_no_speakers_shows_a_placeholder(self):
        embed = self._run(self._base_status(speakers=[]))
        field = next(f for f in embed.fields if f.name == "録音中の参加者")
        self.assertEqual(field.value, "まだ誰も喋っておらぬ。")


# ── /record auto・config（commands/record/config.py） ─────────────────────


class RecordAutoTests(unittest.TestCase):
    def setUp(self):
        self.rcfg, _, _, self.registry = _register_record()
        # `_register_record` は (rs, rcfg, rex, registry) の順で返す
        _, self.rcfg, self.rex, self.registry = _register_record()
        self.auto = self.registry["auto"]

    def _patched(self, *, settings_enabled: bool, target_id):
        return (
            patch.object(self.rcfg, "get_recording_settings", Mock(return_value={"enabled": settings_enabled})),
            patch.object(self.rcfg.recording, "auto_start_channel_id", Mock(return_value=target_id)),
            patch.object(self.rcfg, "awrite", AsyncMock()),
        )

    def test_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.rcfg, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.auto(interaction, enabled=True))
        awrite.assert_not_called()
        self.assertTrue(calls)

    def test_disabling_does_not_mention_a_target_channel(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with (
            patch.object(self.rcfg, "send_ephemeral", fake_send),
            patch.object(self.rcfg, "awrite", AsyncMock()) as awrite,
        ):
            asyncio.run(self.auto(interaction, enabled=False))
        awrite.assert_awaited_once_with(self.rcfg.set_recording_settings, 999, {"auto_start": False})
        self.assertIn("自動録音を切った", sent["message"])

    def test_enabling_with_explicit_channel_includes_it_in_the_patch(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(spec=discord.VoiceChannel, id=42)
        p1, p2, p3 = self._patched(settings_enabled=True, target_id=42)
        with p1, p2, p3 as awrite:
            asyncio.run(self.auto(interaction, enabled=True, channel=channel))
        awrite.assert_awaited_once_with(
            self.rcfg.set_recording_settings, 999, {"auto_start": True, "vc_channel_id": 42}
        )

    def test_enabling_while_recording_itself_is_disabled_warns_about_it(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        p1, p2, p3 = self._patched(settings_enabled=False, target_id=None)
        with p1, p2, p3, patch.object(self.rcfg, "send_ephemeral", fake_send):
            asyncio.run(self.auto(interaction, enabled=True))
        self.assertIn("録音そのものが無効", sent["message"])

    def test_enabling_with_a_resolved_target_names_it(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        p1, p2, p3 = self._patched(settings_enabled=True, target_id=123)
        with p1, p2, p3, patch.object(self.rcfg, "send_ephemeral", fake_send):
            asyncio.run(self.auto(interaction, enabled=True))
        self.assertIn("対象は <#123> だ", sent["message"])

    def test_enabling_without_a_resolvable_target_asks_to_specify_one(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        p1, p2, p3 = self._patched(settings_enabled=True, target_id=None)
        with p1, p2, p3, patch.object(self.rcfg, "send_ephemeral", fake_send):
            asyncio.run(self.auto(interaction, enabled=True))
        self.assertIn("対象のVCが定まっておらぬ", sent["message"])


class RecordConfigTests(unittest.TestCase):
    def setUp(self):
        _, self.rcfg, self.rex, self.registry = _register_record()
        self.config = self.registry["config"]

    def _settings(self, **overrides):
        settings = {
            "enabled": True,
            "auto_start": False,
            "max_minutes": 60,
            "retention_days": 7,
            "announce_channel_id": None,
            "excluded_user_ids": [],
        }
        settings.update(overrides)
        return settings

    def _run(self, interaction, settings, **kwargs):
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with (
            patch.object(self.rcfg, "get_recording_settings", Mock(return_value=settings)),
            patch.object(self.rcfg.recording, "preferred_vc_channel_id", Mock(return_value=None)),
            patch.object(self.rcfg, "awrite", AsyncMock()) as awrite,
        ):
            asyncio.run(self.config(interaction, **kwargs))
        return sent["embed"], awrite

    def test_refuses_non_admin(self):
        # 引数なしで呼ぶと patch が空のままになり、ガードが無くても awrite は
        # 呼ばれない（=ガードを検証できない）。実際に何か変更させようとして
        # 拒否されることを確かめる。
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.rcfg, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.config(interaction, limit_minutes=30))
        awrite.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    # -- limit_minutes の境界値（0〜MAX_MINUTES_LIMIT） --------------------

    def test_limit_minutes_rejects_negative(self):
        interaction, _ = make_interaction(administrator=True)
        embed, awrite = self._run(interaction, self._settings(), limit_minutes=-1)
        awrite.assert_not_called()
        self.assertIsNone(embed)  # send_ephemeral 経由なので embed は無い

    def test_limit_minutes_accepts_zero(self):
        interaction, _ = make_interaction(administrator=True)
        _, awrite = self._run(interaction, self._settings(), limit_minutes=0)
        awrite.assert_awaited_once_with(self.rcfg.set_recording_settings, 999, {"max_minutes": 0})

    def test_limit_minutes_accepts_the_maximum(self):
        interaction, _ = make_interaction(administrator=True)
        max_minutes = self.rcfg.recording.MAX_MINUTES_LIMIT
        _, awrite = self._run(interaction, self._settings(), limit_minutes=max_minutes)
        awrite.assert_awaited_once_with(self.rcfg.set_recording_settings, 999, {"max_minutes": max_minutes})

    def test_limit_minutes_rejects_above_the_maximum(self):
        interaction, _ = make_interaction(administrator=True)
        over = self.rcfg.recording.MAX_MINUTES_LIMIT + 1
        _, awrite = self._run(interaction, self._settings(), limit_minutes=over)
        awrite.assert_not_called()

    # -- retention_days の境界値（RETENTION_DAYS_MIN〜MAX） ----------------

    def test_retention_days_rejects_zero(self):
        interaction, _ = make_interaction(administrator=True)
        _, awrite = self._run(interaction, self._settings(), retention_days=0)
        awrite.assert_not_called()

    def test_retention_days_accepts_the_minimum(self):
        interaction, _ = make_interaction(administrator=True)
        minimum = self.rcfg.recording.RETENTION_DAYS_MIN
        _, awrite = self._run(interaction, self._settings(), retention_days=minimum)
        awrite.assert_awaited_once_with(self.rcfg.set_recording_settings, 999, {"retention_days": minimum})

    def test_retention_days_accepts_the_maximum(self):
        interaction, _ = make_interaction(administrator=True)
        maximum = self.rcfg.recording.RETENTION_DAYS_MAX
        _, awrite = self._run(interaction, self._settings(), retention_days=maximum)
        awrite.assert_awaited_once_with(self.rcfg.set_recording_settings, 999, {"retention_days": maximum})

    def test_retention_days_rejects_above_the_maximum(self):
        interaction, _ = make_interaction(administrator=True)
        over = self.rcfg.recording.RETENTION_DAYS_MAX + 1
        _, awrite = self._run(interaction, self._settings(), retention_days=over)
        awrite.assert_not_called()

    # -- その他の引数の組み立てと表示 --------------------------------------

    def test_announce_channel_is_included_in_the_patch(self):
        interaction, _ = make_interaction(administrator=True)
        channel = Mock(spec=discord.TextChannel, id=555)
        _, awrite = self._run(interaction, self._settings(), announce_channel=channel)
        awrite.assert_awaited_once_with(self.rcfg.set_recording_settings, 999, {"announce_channel_id": 555})

    def test_no_arguments_only_displays_and_does_not_write(self):
        interaction, _ = make_interaction(administrator=True)
        embed, awrite = self._run(interaction, self._settings())
        awrite.assert_not_called()
        self.assertNotIn("更新した", embed.title)

    def test_all_arguments_together_build_the_full_patch(self):
        interaction, _ = make_interaction(administrator=True)
        channel = Mock(spec=discord.TextChannel, id=777)
        embed, awrite = self._run(
            interaction,
            self._settings(),
            enabled=True,
            limit_minutes=45,
            retention_days=14,
            announce_channel=channel,
        )
        awrite.assert_awaited_once_with(
            self.rcfg.set_recording_settings,
            999,
            {"enabled": True, "max_minutes": 45, "retention_days": 14, "announce_channel_id": 777},
        )
        self.assertIn("更新した", embed.title)

    def test_unlimited_max_minutes_is_shown_as_no_time_limit(self):
        interaction, _ = make_interaction(administrator=True)
        embed, _ = self._run(interaction, self._settings(max_minutes=self.rcfg.recording.UNLIMITED))
        field = next(f for f in embed.fields if f.name == "自動停止")
        self.assertEqual(field.value, "全員が退出したとき")

    def test_limited_max_minutes_states_the_minutes(self):
        interaction, _ = make_interaction(administrator=True)
        embed, _ = self._run(interaction, self._settings(max_minutes=90))
        field = next(f for f in embed.fields if f.name == "自動停止")
        self.assertEqual(field.value, "90 分後")

    def test_no_excluded_users_shows_none(self):
        interaction, _ = make_interaction(administrator=True)
        embed, _ = self._run(interaction, self._settings(excluded_user_ids=[]))
        field = next(f for f in embed.fields if f.name == "録音しない人")
        self.assertEqual(field.value, "なし")

    def test_excluded_users_are_mentioned(self):
        interaction, _ = make_interaction(administrator=True)
        embed, _ = self._run(interaction, self._settings(excluded_user_ids=[1, 2]))
        field = next(f for f in embed.fields if f.name == "録音しない人")
        self.assertEqual(field.value, "<@1>、<@2>")

    def test_disabled_with_auto_start_still_on_gets_a_footer_warning(self):
        interaction, _ = make_interaction(administrator=True)
        embed, _ = self._run(interaction, self._settings(enabled=False, auto_start=True))
        self.assertIn("自動録音はオンでも動かぬ", embed.footer.text)

    def test_enabled_gets_no_footer_warning(self):
        interaction, _ = make_interaction(administrator=True)
        embed, _ = self._run(interaction, self._settings(enabled=True, auto_start=True))
        self.assertFalse(embed.footer.text)


# ── /record exclude（commands/record/exclude.py） ─────────────────────────


class RecordExcludeTests(unittest.TestCase):
    def setUp(self):
        _, _, self.rex, self.registry = _register_record()
        self.exclude_cmd = self.registry["exclude"]

    def test_outside_a_guild_is_refused(self):
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.rex, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.exclude_cmd(interaction, exclude=True))
        awrite.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    def test_excluding_adds_the_user_and_updates_the_live_session(self):
        interaction, calls = make_interaction(guild=True)
        interaction.user.id = 7
        session = SimpleNamespace(excluded_user_ids={1, 2})
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with (
            patch.object(self.rex, "get_recording_settings", Mock(return_value={"excluded_user_ids": [1, 2]})),
            patch.object(self.rex, "awrite", AsyncMock()) as awrite,
            patch.object(self.rex.recording, "get_session", Mock(return_value=session)),
            patch.object(self.rex, "send_ephemeral", fake_send),
        ):
            asyncio.run(self.exclude_cmd(interaction, exclude=True))
        awrite.assert_awaited_once_with(self.rex.set_recording_excluded_users, 999, [1, 2, 7])
        self.assertEqual(session.excluded_user_ids, {1, 2, 7})
        self.assertIn("記録されぬ", sent["message"])

    def test_un_excluding_removes_the_user(self):
        interaction, calls = make_interaction(guild=True)
        interaction.user.id = 2
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with (
            patch.object(self.rex, "get_recording_settings", Mock(return_value={"excluded_user_ids": [1, 2]})),
            patch.object(self.rex, "awrite", AsyncMock()) as awrite,
            patch.object(self.rex.recording, "get_session", Mock(return_value=None)),
            patch.object(self.rex, "send_ephemeral", fake_send),
        ):
            asyncio.run(self.exclude_cmd(interaction, exclude=False))
        awrite.assert_awaited_once_with(self.rex.set_recording_excluded_users, 999, [1])
        self.assertIn("除外を解除した", sent["message"])

    def test_no_active_session_does_not_raise(self):
        """/record exclude は録音していないときにも使える。session=None を安全に無視すること。"""
        interaction, calls = make_interaction(guild=True)
        with (
            patch.object(self.rex, "get_recording_settings", Mock(return_value={"excluded_user_ids": []})),
            patch.object(self.rex, "awrite", AsyncMock()),
            patch.object(self.rex.recording, "get_session", Mock(return_value=None)),
        ):
            asyncio.run(self.exclude_cmd(interaction, exclude=True))
        self.assertTrue(calls)


# ── /djaudio channel・output・status（commands/djaudio_commands.py） ───────


class DjaudioRegistrationShapeTests(unittest.TestCase):
    """register_djaudio_commands が何をどう登録するかを固定する。

    144行あるこの関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    下の3クラス（Channel/Output/Status）は**登録されたあとの中身**を見て
    いるが、**登録そのもの**は誰も見ていなかった。

      - グループの名前・説明・guild_only
      - 3つのコマンドが、この名前・この順で並ぶこと
      - グループが bot のコマンドツリーへ渡されること

    最後のひとつが抜けると、**コマンドは1つも Discord に出ない。** 例外は
    出ないし、テストも（コマンドを直接呼ぶので）全部通る。
    """

    def test_the_group_and_its_three_commands_are_registered(self):
        """名前・説明・並び順ごと固定する。"""
        import commands.djaudio_commands as dj

        registry, FakeGroup = _make_group()
        created: list[dict] = []

        class RecordingGroup(FakeGroup):
            """作られたグループの引数を控えるだけの FakeGroup。"""

            def __init__(self, **kwargs):
                """kwargs を控えてから、元の FakeGroup と同じ初期化をする。"""
                created.append(kwargs)
                super().__init__(**kwargs)

        bot = Mock()
        with patch.object(dj.app_commands, "Group", RecordingGroup):
            dj.register_djaudio_commands(bot)

        self.assertEqual(
            created,
            [{"name": "djaudio", "description": "DJAudio（URL の自動MP3変換）の設定", "guild_only": True}],
        )
        self.assertEqual(list(registry), ["channel", "output", "status"])

    def test_the_group_is_handed_to_the_command_tree(self):
        """bot.tree.add_command(group) を呼ぶこと。

        ここが抜けると Discord 側にコマンドが1つも現れない。関数の中では
        全部組み上がっているので、**例外も出ず、単体テストも通る。**
        """
        import commands.djaudio_commands as dj

        _, FakeGroup = _make_group()
        bot = Mock()
        with patch.object(dj.app_commands, "Group", FakeGroup):
            dj.register_djaudio_commands(bot)

        bot.tree.add_command.assert_called_once()
        self.assertIsInstance(bot.tree.add_command.call_args.args[0], FakeGroup)


class DjaudioChannelTests(unittest.TestCase):
    def setUp(self):
        self.dj, self.registry = _register_djaudio()
        self.channel_cmd = self.registry["channel"]
        self.runtime = self.dj.get_djaudio_runtime_settings

    def _runtime_settings(self):
        from services.settings_store import DJAudioRuntimeSettings

        return DJAudioRuntimeSettings(watch_channel_id=1, cache_ttl=600, cooldown=30, max_urls=5)

    def test_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.dj, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.channel_cmd(interaction, channel=None))
        awrite.assert_not_called()
        self.assertTrue(calls)

    def test_no_channel_disables_watching(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with (
            patch.object(self.dj, "get_djaudio_runtime_settings", Mock(return_value=self._runtime_settings())),
            patch.object(self.dj, "awrite", AsyncMock()) as awrite,
        ):
            asyncio.run(self.channel_cmd(interaction, channel=None))
        awrite.assert_awaited_once_with(self.dj.set_djaudio_watch_channel, 999, None)
        self.assertEqual(sent["embed"].title, "✅ DJAudio 監視チャンネル解除")

    def test_setting_a_channel_while_base_url_is_local_warns(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(spec=discord.TextChannel, id=11, mention="<#11>")
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with (
            patch.object(self.dj, "get_djaudio_runtime_settings", Mock(return_value=self._runtime_settings())),
            patch.object(self.dj, "awrite", AsyncMock()) as awrite,
            patch.object(self.dj, "DJAUDIO_BASE_URL", "http://localhost:5001"),
        ):
            asyncio.run(self.channel_cmd(interaction, channel=channel))
        awrite.assert_awaited_once_with(self.dj.set_djaudio_watch_channel, 999, 11)
        names = [f.name for f in sent["embed"].fields]
        self.assertIn("⚠️ 注意", names)

    def test_setting_a_channel_with_a_public_base_url_has_no_warning(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(spec=discord.TextChannel, id=12, mention="<#12>")
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with (
            patch.object(self.dj, "get_djaudio_runtime_settings", Mock(return_value=self._runtime_settings())),
            patch.object(self.dj, "awrite", AsyncMock()),
            patch.object(self.dj, "DJAUDIO_BASE_URL", "https://audio.example.com"),
        ):
            asyncio.run(self.channel_cmd(interaction, channel=channel))
        names = [f.name for f in sent["embed"].fields]
        self.assertNotIn("⚠️ 注意", names)

    def test_missing_permissions_error_handler_uses_the_custom_message(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        cmd = self.registry["channel"]
        self.assertIsNotNone(cmd.error_handler, "エラーハンドラが登録されていない")
        with patch("commands.interaction_utils.send_ephemeral", fake_send):
            asyncio.run(cmd.error_handler(interaction, app_commands.MissingPermissions(["manage_channels"])))
        self.assertEqual(sent["message"], "❌ チャンネル管理の権限がなければ使えぬ。")


class DjaudioOutputTests(unittest.TestCase):
    def setUp(self):
        self.dj, self.registry = _register_djaudio()
        self.output_cmd = self.registry["output"]

    def test_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.dj, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.output_cmd(interaction, channel=None))
        awrite.assert_not_called()
        self.assertTrue(calls)

    def test_no_channel_disables_the_dedicated_output(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with patch.object(self.dj, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.output_cmd(interaction, channel=None))
        awrite.assert_awaited_once_with(self.dj.set_djaudio_output_channel, 999, None)
        self.assertEqual(sent["embed"].title, "✅ DJAudio 出力チャンネル解除")

    def test_setting_a_channel_names_it_in_the_description(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(spec=discord.TextChannel, id=21, mention="<#21>")
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with patch.object(self.dj, "awrite", AsyncMock()) as awrite:
            asyncio.run(self.output_cmd(interaction, channel=channel))
        awrite.assert_awaited_once_with(self.dj.set_djaudio_output_channel, 999, 21)
        self.assertIn("<#21>", sent["embed"].description)

    def test_missing_permissions_error_handler_uses_the_custom_message(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        cmd = self.registry["output"]
        self.assertIsNotNone(cmd.error_handler, "エラーハンドラが登録されていない")
        with patch("commands.interaction_utils.send_ephemeral", fake_send):
            asyncio.run(cmd.error_handler(interaction, app_commands.MissingPermissions(["manage_channels"])))
        self.assertEqual(sent["message"], "❌ チャンネル管理の権限がなければ使えぬ。")


class DjaudioStatusTests(unittest.TestCase):
    def setUp(self):
        self.dj, self.registry = _register_djaudio()
        self.status_cmd = self.registry["status"]

    def _runtime_settings(self, **overrides):
        from services.settings_store import DJAudioRuntimeSettings

        base = DJAudioRuntimeSettings(watch_channel_id=1, cache_ttl=600, cooldown=30, max_urls=5)
        return replace(base, **overrides)

    def test_outside_a_guild_is_refused_without_reading_settings(self):
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.dj, "get_djaudio_runtime_settings", Mock()) as runtime:
            asyncio.run(self.status_cmd(interaction))
        runtime.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    def _run(self, runtime, *, get_channel):
        interaction, calls = make_interaction(guild=True)
        interaction.guild.get_channel = get_channel
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with patch.object(self.dj, "get_djaudio_runtime_settings", Mock(return_value=runtime)):
            asyncio.run(self.status_cmd(interaction))
        return sent["embed"]

    def test_unset_watch_channel_shows_not_configured(self):
        runtime = self._runtime_settings(watch_channel_id=None)
        embed = self._run(runtime, get_channel=Mock(return_value=None))
        field = next(f for f in embed.fields if f.name == "監視チャンネル")
        self.assertEqual(field.value, "未設定")

    def test_watch_channel_id_set_but_channel_not_found(self):
        runtime = self._runtime_settings(watch_channel_id=123)
        embed = self._run(runtime, get_channel=Mock(return_value=None))
        field = next(f for f in embed.fields if f.name == "監視チャンネル")
        self.assertEqual(field.value, "ID: 123（チャンネル未検出）")

    def test_watch_channel_found_uses_its_mention(self):
        runtime = self._runtime_settings(watch_channel_id=123)
        found = Mock(mention="<#123>")
        embed = self._run(runtime, get_channel=Mock(return_value=found))
        field = next(f for f in embed.fields if f.name == "監視チャンネル")
        self.assertEqual(field.value, "<#123>")

    def test_no_dedicated_output_channel_notes_it_replies_in_the_watch_channel(self):
        runtime = self._runtime_settings(output_channel_id=None)
        embed = self._run(runtime, get_channel=Mock(return_value=None))
        field = next(f for f in embed.fields if f.name == "出力チャンネル")
        self.assertIn("監視チャンネルに返信", field.value)

    def test_local_base_url_adds_a_warning_field(self):
        runtime = self._runtime_settings()
        with patch.object(self.dj, "DJAUDIO_BASE_URL", "http://127.0.0.1:5001"):
            embed = self._run(runtime, get_channel=Mock(return_value=None))
        names = [f.name for f in embed.fields]
        self.assertIn("⚠️ 配信 URL が localhost のまま", names)

    def test_public_base_url_has_no_warning_field(self):
        runtime = self._runtime_settings()
        with patch.object(self.dj, "DJAUDIO_BASE_URL", "https://audio.example.com"):
            embed = self._run(runtime, get_channel=Mock(return_value=None))
        names = [f.name for f in embed.fields]
        self.assertNotIn("⚠️ 配信 URL が localhost のまま", names)


# ── commands/chat_commands.py ─────────────────────────────────────────────


def _make_message(*, guild_id=999, channel_id=1, author_id=2, content="こんにちは"):
    message = Mock()
    message.guild = Mock(id=guild_id)
    message.channel = Mock(id=channel_id, mention=f"<#{channel_id}>")
    message.channel.send = AsyncMock()
    message.channel._state = Mock()
    message.channel._state.http.send_typing = AsyncMock()
    message.author = Mock(id=author_id)
    message.content = content
    return message


class ChatGptMessageHandlingTests(unittest.TestCase):
    """handle_chatgpt_message: どの条件で応答し、どの条件で無視するか。"""

    def setUp(self):
        import commands.chat_commands as cc

        self.cc = cc
        # モジュール変数（ChatGPTインスタンスのキャッシュ）はテスト間で
        # 汚染されないよう、毎回退避・復元する。
        self._saved_chatgpt = dict(cc.user_chatgpt)
        self._saved_last_used = dict(cc._user_last_used)
        self._saved_counter = cc._cleanup_counter
        cc.user_chatgpt.clear()
        cc._user_last_used.clear()
        cc._cleanup_counter = 0

    def tearDown(self):
        self.cc.user_chatgpt.clear()
        self.cc.user_chatgpt.update(self._saved_chatgpt)
        self.cc._user_last_used.clear()
        self.cc._user_last_used.update(self._saved_last_used)
        self.cc._cleanup_counter = self._saved_counter

    def _fake_chatgpt(self, reply="返答"):
        instance = Mock()
        instance.input_message = AsyncMock(return_value=reply)
        return Mock(return_value=instance), instance

    def test_ignores_its_own_messages(self):
        bot = Mock()
        message = _make_message()
        message.author = bot.user
        with patch.object(self.cc, "send_large_message", AsyncMock()) as send_large:
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        send_large.assert_not_called()

    def test_ignores_messages_outside_a_guild(self):
        bot = Mock()
        message = _make_message()
        message.guild = None
        with patch.object(self.cc, "send_large_message", AsyncMock()) as send_large:
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        send_large.assert_not_called()

    def test_ignores_when_no_response_channel_is_configured(self):
        bot = Mock()
        message = _make_message(channel_id=5)
        with (
            patch.object(self.cc, "get_response_channel_id", Mock(return_value=0)),
            patch.object(self.cc, "send_large_message", AsyncMock()) as send_large,
        ):
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        send_large.assert_not_called()

    def test_ignores_a_different_channel_than_configured(self):
        bot = Mock()
        message = _make_message(channel_id=5)
        with (
            patch.object(self.cc, "get_response_channel_id", Mock(return_value=999)),
            patch.object(self.cc, "send_large_message", AsyncMock()) as send_large,
        ):
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        send_large.assert_not_called()

    def test_matching_channel_replies_and_caches_the_chatgpt_instance(self):
        bot = Mock()
        message = _make_message(channel_id=5, author_id=42, content="やあ")
        chatgpt_cls, instance = self._fake_chatgpt("返答その1")
        with (
            patch.object(self.cc, "get_response_channel_id", Mock(return_value=5)),
            patch.object(self.cc, "ChatGPT", chatgpt_cls),
            patch.object(self.cc, "send_large_message", AsyncMock()) as send_large,
            patch.object(self.cc, "log_action", AsyncMock()) as log_action,
        ):
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
            # 2回目は同じインスタンスを再利用し、ChatGPT() を作り直さないこと
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        chatgpt_cls.assert_called_once()
        self.assertEqual(instance.input_message.await_count, 2)
        send_large.assert_awaited_with(message.channel, "返答その1")
        log_action.assert_awaited()
        self.assertEqual(log_action.call_args.kwargs["fields"]["チャンネル"], "<#5>")

    def test_send_typing_failure_does_not_block_the_reply(self):
        bot = Mock()
        message = _make_message(channel_id=5)
        message.channel._state.http.send_typing = AsyncMock(side_effect=discord.HTTPException(Mock(status=500), "boom"))
        chatgpt_cls, instance = self._fake_chatgpt("平気だ")
        with (
            patch.object(self.cc, "get_response_channel_id", Mock(return_value=5)),
            patch.object(self.cc, "ChatGPT", chatgpt_cls),
            patch.object(self.cc, "send_large_message", AsyncMock()) as send_large,
            patch.object(self.cc, "log_action", AsyncMock()),
        ):
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        send_large.assert_awaited_with(message.channel, "平気だ")

    def test_chatgpt_failure_logs_and_sends_a_fallback_message(self):
        bot = Mock()
        message = _make_message(channel_id=5)
        chatgpt_cls, instance = self._fake_chatgpt()
        instance.input_message = AsyncMock(side_effect=RuntimeError("API落ち"))
        with (
            patch.object(self.cc, "get_response_channel_id", Mock(return_value=5)),
            patch.object(self.cc, "ChatGPT", chatgpt_cls),
            patch.object(self.cc, "send_large_message", AsyncMock()) as send_large,
            patch.object(self.cc, "log_action", AsyncMock()) as log_action,
        ):
            asyncio.run(self.cc.handle_chatgpt_message(bot, message))
        send_large.assert_not_called()
        message.channel.send.assert_awaited_once_with("ヴォルデモートでも手こずるとはな… 少し待ってから試せ。")
        self.assertEqual(log_action.call_args.kwargs["fields"]["エラー"], "API落ち")
        self.assertEqual(log_action.call_args.args[2], "ERROR")


class ChatGptCleanupTests(unittest.TestCase):
    """_cleanup_stale_instances: 一定間隔ごとに、しばらく使われていないインスタンスだけ捨てること。

    ChatGPT インスタンスは会話履歴を保持するため、使われなくなったユーザー分を
    残し続けるとメモリが際限なく増える。かといって毎メッセージで全走査すると
    無駄なので、間隔を空けて掃除する。
    """

    def setUp(self):
        import commands.chat_commands as cc

        self.cc = cc
        self._saved_chatgpt = dict(cc.user_chatgpt)
        self._saved_last_used = dict(cc._user_last_used)
        self._saved_counter = cc._cleanup_counter
        cc.user_chatgpt.clear()
        cc._user_last_used.clear()
        cc._cleanup_counter = 0

    def tearDown(self):
        self.cc.user_chatgpt.clear()
        self.cc.user_chatgpt.update(self._saved_chatgpt)
        self.cc._user_last_used.clear()
        self.cc._user_last_used.update(self._saved_last_used)
        self.cc._cleanup_counter = self._saved_counter

    def test_does_nothing_before_the_interval_is_reached(self):
        import time

        key = (1, 2)
        self.cc.user_chatgpt[key] = object()
        self.cc._user_last_used[key] = time.time() - 999999
        self.cc._cleanup_counter = self.cc._CLEANUP_INTERVAL - 2
        self.cc._cleanup_stale_instances()
        self.assertIn(key, self.cc.user_chatgpt, "間隔に達する前に掃除してしまっている")

    def test_removes_only_the_stale_entries_once_the_interval_is_reached(self):
        import time

        stale_key = (1, 2)
        fresh_key = (1, 3)
        self.cc.user_chatgpt[stale_key] = object()
        self.cc.user_chatgpt[fresh_key] = object()
        self.cc._user_last_used[stale_key] = time.time() - (self.cc._CHATGPT_TTL_SECONDS + 100)
        self.cc._user_last_used[fresh_key] = time.time()
        self.cc._cleanup_counter = self.cc._CLEANUP_INTERVAL - 1
        self.cc._cleanup_stale_instances()
        self.assertNotIn(stale_key, self.cc.user_chatgpt, "期限切れのインスタンスが残っている")
        self.assertIn(fresh_key, self.cc.user_chatgpt, "使用中のインスタンスまで消してしまっている")
        self.assertEqual(self.cc._cleanup_counter, 0)


# ── commands/interaction_utils.py のエラーハンドラ ─────────────────────────


class BindPermissionErrorHandlerTests(unittest.TestCase):
    """bind_permission_error_handler: 各エラー種別に応じて正しい文言を返すこと。

    権限エラーの文言を間違えると、管理者は何が足りないのか分からず、単に
    「拒否された」という不親切な体験になる。
    """

    def setUp(self):
        from commands.interaction_utils import bind_permission_error_handler

        async def dummy(interaction):
            pass

        self.cmd = _FakeCommand(dummy)
        bind_permission_error_handler(self.cmd, missing_permissions_message="独自の権限文言")
        self.assertIsNotNone(self.cmd.error_handler)

    def test_missing_permissions_uses_the_custom_message(self):
        from discord import app_commands

        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with patch("commands.interaction_utils.send_ephemeral", fake_send):
            asyncio.run(self.cmd.error_handler(interaction, app_commands.MissingPermissions(["ban_members"])))
        self.assertEqual(sent["message"], "独自の権限文言")

    def test_check_failure_uses_the_generic_message(self):
        from discord import app_commands

        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with patch("commands.interaction_utils.send_ephemeral", fake_send):
            asyncio.run(self.cmd.error_handler(interaction, app_commands.CheckFailure("だめ")))
        self.assertIn("条件を満たしておらぬ", sent["message"])

    def test_unexpected_error_is_logged_and_answered_generically(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with (
            patch("commands.interaction_utils.send_ephemeral", fake_send),
            self.assertLogs("commands.interaction_utils", level="ERROR"),
        ):
            asyncio.run(self.cmd.error_handler(interaction, RuntimeError("想定外")))
        self.assertIn("何かが邪魔をした", sent["message"])


class GlobalAppCommandErrorHandlerTests(unittest.TestCase):
    """install_global_app_command_error_handler: ツリー全体のフォールバック。

    個別コマンドに bind_permission_error_handler を付け忘れても、ここで
    最低限の応答は返ること。
    """

    def setUp(self):
        from commands.interaction_utils import install_global_app_command_error_handler

        self.handler = None
        bot = Mock()

        def capture(fn):
            self.handler = fn
            return fn

        bot.tree.error = capture
        install_global_app_command_error_handler(bot)
        self.assertIsNotNone(self.handler, "エラーハンドラが登録されていない")

    def test_command_not_found_is_silently_ignored(self):
        from discord import app_commands

        interaction, calls = make_interaction()
        asyncio.run(self.handler(interaction, app_commands.CommandNotFound("old", [])))
        self.assertEqual(calls, [], "存在しないコマンドにまで応答してしまっている")

    def test_missing_permissions_gets_the_generic_message(self):
        from discord import app_commands

        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with patch("commands.interaction_utils.send_ephemeral", fake_send):
            asyncio.run(self.handler(interaction, app_commands.MissingPermissions(["administrator"])))
        self.assertIn("権限が貴様にはない", sent["message"])

    def test_check_failure_gets_the_generic_message(self):
        from discord import app_commands

        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with patch("commands.interaction_utils.send_ephemeral", fake_send):
            asyncio.run(self.handler(interaction, app_commands.CheckFailure("だめ")))
        self.assertIn("条件を満たしておらぬ", sent["message"])

    def test_command_invoke_error_logs_the_original_exception(self):
        from discord import app_commands

        interaction, calls = make_interaction()
        sent = {}
        fake_command = Mock()
        fake_command.name = "boom"

        async def fake_send(interaction_, message):
            sent["message"] = message

        error = app_commands.CommandInvokeError(fake_command, ValueError("内部で失敗"))
        with (
            patch("commands.interaction_utils.send_ephemeral", fake_send),
            self.assertLogs("commands.interaction_utils", level="ERROR"),
        ):
            asyncio.run(self.handler(interaction, error))
        self.assertIn("処理できなかった", sent["message"])

    def test_unexpected_app_command_error_gets_the_fallback_message(self):
        from discord import app_commands

        class _OtherError(app_commands.AppCommandError):
            pass

        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(interaction_, message):
            sent["message"] = message

        with (
            patch("commands.interaction_utils.send_ephemeral", fake_send),
            self.assertLogs("commands.interaction_utils", level="ERROR"),
        ):
            asyncio.run(self.handler(interaction, _OtherError("なぞの障害")))
        self.assertIn("予期せぬ障害", sent["message"])


if __name__ == "__main__":
    unittest.main()
