"""カバレッジの薄い commands/ 配下（djaudio・chat・interaction_utils の
エラーハンドラ）を狙って埋めるテスト。

    python -m unittest tests.test_commands_coverage -v

Discord へは繋がず、tests/test_commands.py と同じ方針で Interaction を
Mock/SimpleNamespace で用意し、呼び出しの順序・引数・応答内容だけを見る。

app_commands.Group は discord.py 側のモジュール属性そのものなので、
どこか1箇所でパッチすれば全モジュールに効く。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
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
            # 実行のログ（commands/activity_log.py）が読む3つ。本物の
            # Interaction は必ず持っているので、帳票にも揃えておく。
            "channel_id",
            "id",
            "command",
            "type",
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
    interaction.channel_id = 555
    interaction.id = 123456789
    interaction.command = Mock(qualified_name="test cmd")
    interaction.type = discord.InteractionType.application_command

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


def _register_djaudio():
    import commands.djaudio_commands as dj

    registry, FakeGroup = _make_group()
    with patch.object(dj.app_commands, "Group", FakeGroup):
        dj.register_djaudio_commands(Mock())
    return dj, registry


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


class CommandActivityLogTests(unittest.TestCase):
    """打たれたスラッシュコマンドが、プロセスのログに残ること。

    `commands/` には172個の関数があるのに、ログを出しているのは**4箇所**
    だけだった。**/log channel も /tts join も、打たれた事実が
    bot.log に1行も残らない。** 「さっき誰かが何かした直後からおかしい」
    という報告に対して、手がかりが無かった。

    一部のコマンドは log_action() で Discord の監査チャンネルへ流している
    が、あれは**設定したギルドにしか出ない**うえ Discord 側に消される。

      - 成功したコマンドが1行残ること（名前・ギルド・ユーザー・所要ms）
      - **引数の中身は書かないこと**
      - 断られたコマンドも残ること
      - 172個へ個別に足すのではなく、入口で1箇所にしていること
      - 完了イベントが来なかった分が溜まり続けないこと
    """

    def setUp(self):
        from commands import activity_log

        self.activity_log = activity_log
        self.activity_log._STARTED.clear()
        self.addCleanup(self.activity_log._STARTED.clear)

    def _listeners(self):
        """install_command_activity_logging が足した listener を名前で拾う。"""
        added = {}
        bot = Mock()
        bot.add_listener = lambda coro, name: added.__setitem__(name, coro)
        self.activity_log.install_command_activity_logging(bot)
        return added

    def test_it_hooks_the_entry_point_rather_than_each_command(self):
        """コマンドごとではなく、入口の2つのイベントに乗ること。

        172個へ1行ずつ足す方式は、**次に足すコマンドで必ず忘れる。**
        `@bot.event` ではなく add_listener を使うのは、同じ名前の既存
        ハンドラを置き換えてしまわないため。
        """
        added = self._listeners()

        self.assertEqual(set(added), {"on_interaction", "on_app_command_completion"})

    def test_a_finished_command_leaves_one_line(self):
        """成功したコマンドが、名前・ギルド・ユーザー・所要ミリ秒で1行残ること。"""
        added = self._listeners()
        interaction, _ = make_interaction()
        interaction.id = 42
        command = Mock(qualified_name="tts join")

        with self.assertLogs(self.activity_log.logger, level="INFO") as captured:
            asyncio.run(added["on_interaction"](interaction))
            asyncio.run(added["on_app_command_completion"](interaction, command))

        line = captured.output[0]
        self.assertIn("/tts join", line)
        self.assertIn("guild=999", line)
        self.assertIn("tester(1)", line)
        self.assertIn("ok", line)
        self.assertRegex(line, r"\d+ms")

    def test_the_arguments_are_not_written_to_disk(self):
        """引数の中身は書かないこと。

        読み上げの辞書やチャットの本文がそのまま**10年ぶんディスクに残る**
        （保管期間は services/log_setup.py）。値まで要る操作は log_action で
        監査チャンネルへ出している。
        """
        added = self._listeners()
        interaction, _ = make_interaction()
        command = Mock(qualified_name="tts dict add")

        with self.assertLogs(self.activity_log.logger, level="INFO") as captured:
            asyncio.run(added["on_app_command_completion"](interaction, command))

        line = captured.output[0]
        self.assertIn("/tts dict add", line)
        # 引数を取り出そうとした形跡が無いこと（値が入る余地を作らない）
        self.assertLess(len(line), 200, line)

    def test_only_application_commands_are_timed(self):
        """ボタンやモーダルの操作では時刻を控えないこと。

        押すたびに控えると、**完了イベントの来ない分が溜まり続ける。**
        """
        import discord

        added = self._listeners()
        interaction, _ = make_interaction()
        interaction.id = 7
        interaction.type = discord.InteractionType.component

        asyncio.run(added["on_interaction"](interaction))

        self.assertIsNone(self.activity_log._STARTED.get(7))

    def test_the_pending_marks_expire_instead_of_piling_up(self):
        """完了イベントが来なかった分は、期限で落ちること。

        コマンドが失敗すると完了イベントは来ない。控えを消す口が無いと、
        **落ちた回数だけメモリが増え続ける。** 応答期限は15分なので、
        それを過ぎたものはもう来ない。
        """
        cache = self.activity_log._STARTED

        self.assertGreaterEqual(cache.ttl, 15 * 60)
        self.assertLessEqual(cache.max_entries, 8192)

    def test_the_startup_path_actually_installs_it(self):
        """main.py が起動時に組み込んでいること。

        この仕組みは**入口で1箇所**にまとめてあるので、その1箇所を呼び
        忘れると**全コマンドのログが丸ごと消える。** 例外も出ないし、
        コマンドは普通に動くので、bot.log を見るまで気づけない。
        原文を読んで確かめる（起動そのものは Discord に繋がないと通せない）。
        """
        source = Path("main.py").read_text(encoding="utf-8")
        lines = [line for line in source.splitlines() if not line.lstrip().startswith("#")]
        body = chr(10).join(lines)

        self.assertIn("from commands.activity_log import install_command_activity_logging", body)
        self.assertIn("install_command_activity_logging(bot)", body)
        # コマンドが出揃ったあとに入れること（登録前だと拾い漏らす）
        self.assertLess(body.index("register_all_commands(bot)"), body.index("install_command_activity_logging(bot)"))

    def test_a_refused_command_is_logged_too(self):
        """権限で断られたコマンドも1行残ること。

        成功したものだけを残すと、**断られた回数が見えない。** 権限設定を
        間違えていても「使えない」と言われるまで気づけない。
        """
        from commands.interaction_utils import install_global_app_command_error_handler
        from discord import app_commands

        handler = {}
        bot = Mock()
        bot.tree.error = lambda fn: handler.setdefault("fn", fn)
        install_global_app_command_error_handler(bot)

        interaction, _ = make_interaction()
        interaction.command = Mock(qualified_name="log channel")
        with self.assertLogs("commands.interaction_utils", level="INFO") as captured:
            asyncio.run(handler["fn"](interaction, app_commands.MissingPermissions(["administrator"])))

        line = "\n".join(captured.output)
        self.assertIn("/log channel", line)
        self.assertIn("権限なしで拒否", line)


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
