"""events/ パッケージのイベントハンドラ本体（messages/ready/members/background_tasks/voice）のテスト。

    python -m unittest discover -s tests -t .

tests/test_events.py が既に押さえている純粋ロジック
（_find_recent_audit_entry / _tts_vc_became_empty / _compute_vc_transition /
_format_status_text / _passes_vc_notify_filter）はここでは扱わない。狙いは
それ以外――「register(bot) が実際に何を bot へ配線するか」と「イベントごとに
どのサービスが呼ばれ、どれが呼ばれないか」という契約を固定すること。

discord.py の型は SimpleNamespace / Mock(spec=...) で最小限だけ用意し、
Discord API・ネットワークには一切触れない（サービス関数は全て
unittest.mock.patch で差し替える）。
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

# services/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# events.*（経由で services）の import より前に一時ディレクトリへ差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="events-handlers-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="events-handlers-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import events.background_tasks as bg  # noqa: E402
import events.members as members  # noqa: E402
import events.messages as messages  # noqa: E402
import events.ready as ready  # noqa: E402
import events.voice as voice  # noqa: E402
from events.state import EventState  # noqa: E402
from services.recording_service import RecordingError  # noqa: E402


class _FakeBot:
    """discord.ext.commands.Bot の @bot.event だけを再現する最小の帳票。

    discord.py の Client.event() は「coro.__name__ で self へ setattr する」
    だけの実装なので（tests/test_bot_setup.py 冒頭のコメント参照）、
    ここもそれだけを持たせる。テストごとに必要な属性は個別に足す。
    """

    # on_ready が起動サマリで読む。本物の Bot は常に持っている。
    guilds: list = []

    def event(self, coro):
        setattr(self, coro.__name__, coro)
        return coro


def _run(coro):
    return asyncio.run(coro)


# ============================================================
# events/messages.py
# ============================================================


def _message(*, guild=None, author=None, channel=None, content="", msg_id=1, created_at=None, attachments=()):
    return SimpleNamespace(
        guild=guild,
        author=author,
        channel=channel,
        content=content,
        id=msg_id,
        created_at=created_at,
        attachments=list(attachments),
    )


class RegisterMessagesTests(unittest.TestCase):
    def test_registers_the_three_message_handlers(self):
        bot = _FakeBot()
        messages.register(bot)
        names = {k for k in vars(bot) if k.startswith("on_")}
        self.assertEqual(names, {"on_message", "on_message_delete", "on_message_edit"})


class OnMessageDispatchTests(unittest.TestCase):
    """on_message: bot の発言・DM では何もせず、ギルドの人間の発言だけを各サービスへ配る。"""

    def setUp(self):
        self.bot = _FakeBot()
        self.bot.process_commands = AsyncMock()
        messages.register(self.bot)
        self.handler = self.bot.on_message

    def test_bot_authors_message_is_ignored_entirely(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(bot=True)
        msg = _message(guild=guild, author=author, channel=SimpleNamespace(id=2))
        with (
            patch.object(messages, "handle_security_for_message", AsyncMock()) as sec,
            patch.object(messages, "handle_chatgpt_message", AsyncMock()) as chat,
        ):
            _run(self.handler(msg))
        sec.assert_not_called()
        chat.assert_not_called()
        self.bot.process_commands.assert_not_called()

    def test_dm_message_guild_none_is_ignored_entirely(self):
        author = SimpleNamespace(bot=False)
        msg = _message(guild=None, author=author, channel=SimpleNamespace(id=2))
        with patch.object(messages, "handle_security_for_message", AsyncMock()) as sec:
            _run(self.handler(msg))
        sec.assert_not_called()
        self.bot.process_commands.assert_not_called()

    def test_normal_guild_message_dispatches_to_all_handlers_then_process_commands(self):
        guild = SimpleNamespace(id=10)
        author = SimpleNamespace(bot=False)
        channel = SimpleNamespace(id=20)
        msg = _message(guild=guild, author=author, channel=channel, content="hello")
        with (
            patch.object(messages, "handle_security_for_message", AsyncMock()) as sec,
            patch.object(messages, "handle_chatgpt_message", AsyncMock()) as chat,
            patch.object(messages, "handle_sticky", AsyncMock()) as sticky,
            patch.object(messages, "handle_djaudio_message", AsyncMock()) as djaudio,
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(None, [])),
        ):
            _run(self.handler(msg))
        sec.assert_called_once_with(self.bot, msg)
        chat.assert_called_once_with(self.bot, msg)
        sticky.assert_called_once_with(msg)
        djaudio.assert_called_once_with(self.bot, msg)
        self.bot.process_commands.assert_called_once_with(msg)

    def test_tts_enqueues_when_channel_is_in_the_watch_list(self):
        guild = SimpleNamespace(id=10)
        author = Mock(spec=discord.Member)
        author.bot = False
        channel = SimpleNamespace(id=555)
        msg = _message(guild=guild, author=author, channel=channel, content="hi")
        with (
            patch.object(messages, "handle_security_for_message", AsyncMock()),
            patch.object(messages, "handle_chatgpt_message", AsyncMock()),
            patch.object(messages, "handle_sticky", AsyncMock()),
            patch.object(messages, "handle_djaudio_message", AsyncMock()),
            patch("services.tts_store.get_tts_settings", return_value={"k": "v"}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(None, [555])),
            patch("services.tts_service.enqueue_message", AsyncMock()) as enqueue,
        ):
            _run(self.handler(msg))
        enqueue.assert_called_once_with(self.bot, guild, author, "hi")

    def test_tts_enqueues_when_channel_is_the_effective_vc_text_channel(self):
        guild = SimpleNamespace(id=10)
        author = Mock(spec=discord.Member)
        author.bot = False
        channel = SimpleNamespace(id=777)
        msg = _message(guild=guild, author=author, channel=channel)
        with (
            patch.object(messages, "handle_security_for_message", AsyncMock()),
            patch.object(messages, "handle_chatgpt_message", AsyncMock()),
            patch.object(messages, "handle_sticky", AsyncMock()),
            patch.object(messages, "handle_djaudio_message", AsyncMock()),
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(777, [])),
            patch("services.tts_service.enqueue_message", AsyncMock()) as enqueue,
        ):
            _run(self.handler(msg))
        enqueue.assert_called_once()

    def test_tts_is_skipped_when_the_author_is_not_a_discord_member(self):
        """isinstance(message.author, discord.Member) のガードそのものを確認する。"""
        guild = SimpleNamespace(id=10)
        author = SimpleNamespace(bot=False)  # discord.Member ではない
        channel = SimpleNamespace(id=555)
        msg = _message(guild=guild, author=author, channel=channel)
        with (
            patch.object(messages, "handle_security_for_message", AsyncMock()),
            patch.object(messages, "handle_chatgpt_message", AsyncMock()),
            patch.object(messages, "handle_sticky", AsyncMock()),
            patch.object(messages, "handle_djaudio_message", AsyncMock()),
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(None, [555])),
            patch("services.tts_service.enqueue_message", AsyncMock()) as enqueue,
        ):
            _run(self.handler(msg))
        enqueue.assert_not_called()

    def test_tts_is_not_triggered_when_the_channel_is_not_watched(self):
        guild = SimpleNamespace(id=10)
        author = Mock(spec=discord.Member)
        author.bot = False
        channel = SimpleNamespace(id=1)
        msg = _message(guild=guild, author=author, channel=channel)
        with (
            patch.object(messages, "handle_security_for_message", AsyncMock()),
            patch.object(messages, "handle_chatgpt_message", AsyncMock()),
            patch.object(messages, "handle_sticky", AsyncMock()),
            patch.object(messages, "handle_djaudio_message", AsyncMock()),
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(999, [555])),
            patch("services.tts_service.enqueue_message", AsyncMock()) as enqueue,
        ):
            _run(self.handler(msg))
        enqueue.assert_not_called()


class OnMessageDispatchShapeTests(unittest.TestCase):
    """on_message の配り方そのものを固定する。

    138行ある events/messages.py の register を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    上の OnMessageDispatchTests は「5つのハンドラが1回ずつ呼ばれたか」を見て
    いるが、**どう呼ばれたか**は誰も見ていない。次の3つは、崩しても
    `assert_called_once_with` が全部通る。

      1. 5つが同時に走ること（直列に書き換えても呼ばれた回数は同じ）
      2. 1つが落ちても他が止まらないこと（_safe を1つ外しても平常時は緑）
      3. process_commands が gather のあとに来ること

    2 が崩れると **prefix コマンドが一切反応しなくなる。** gather は最初の
    例外をそのまま投げるので、_safe を外したハンドラが落ちた時点で
    process_commands まで届かない。しかも落ちるのは外部APIが不調なときだけ
    なので、手元では再現しない。
    """

    def setUp(self):
        self.bot = _FakeBot()
        messages.register(self.bot)
        self.handler = self.bot.on_message
        self.guild = SimpleNamespace(id=10)
        self.msg = _message(
            guild=self.guild,
            author=SimpleNamespace(bot=False),
            channel=SimpleNamespace(id=20),
            content="hello",
        )

    def _dispatch(self, handlers):
        """4つのサービスを差し替えて on_message を1回流す。TTS は黙らせる。"""
        with (
            patch.object(messages, "handle_security_for_message", handlers["security"]),
            patch.object(messages, "handle_chatgpt_message", handlers["chat"]),
            patch.object(messages, "handle_sticky", handlers["sticky"]),
            patch.object(messages, "handle_djaudio_message", handlers["djaudio"]),
            patch("services.tts_store.get_tts_settings", return_value={}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(None, [])),
        ):
            _run(self.handler(self.msg))

    def test_the_handlers_run_at_the_same_time(self):
        """4つのサービスが、1つずつ順番待ちにならないこと。

        VT スキャンは秒単位でかかる。直列に並べると、その間 DJAudio も
        読み上げも動かない。**呼ばれた回数は直列でも同じ**なので、同時に
        走っていることをここで見ておく。
        """
        state = {"running": 0, "peak": 0}

        def make(_name):
            """走っている本数の最大を控えるだけのハンドラ。"""

            async def handler(*a, **k):
                state["running"] += 1
                state["peak"] = max(state["peak"], state["running"])
                await asyncio.sleep(0.02)
                state["running"] -= 1

            return handler

        self.bot.process_commands = AsyncMock()
        self._dispatch({name: make(name) for name in ("security", "chat", "sticky", "djaudio")})

        self.assertEqual(state["peak"], 4, "1つずつ順番に走っている")

    def test_one_failing_handler_stops_neither_the_others_nor_prefix_commands(self):
        """1つが落ちても、残りと process_commands は動くこと。

        gather は最初の例外をそのまま投げる。落ちたハンドラの _safe が
        外れていると、**そこで on_message ごと終わり、prefix コマンドが
        一切反応しなくなる。** 例外が出るのは外部APIが不調なときだけなので、
        平常時のテストでは緑のまま気づけない。
        """
        done: list[str] = []

        async def boom(*a, **k):
            """必ず落ちるハンドラ。"""
            raise RuntimeError("外部APIが落ちた")

        def make(name):
            """呼ばれたことだけ控えるハンドラ。"""

            async def handler(*a, **k):
                done.append(name)

            return handler

        self.bot.process_commands = AsyncMock()
        # 握りつぶすのではなく _safe が記録すること（黙って消えると、
        # 「動いていないのに緑」の原因が追えない）も、ここで併せて見る。
        with self.assertLogs("events._util", level="ERROR") as captured:
            self._dispatch(
                {
                    "security": boom,
                    "chat": make("chat"),
                    "sticky": make("sticky"),
                    "djaudio": make("djaudio"),
                }
            )

        self.assertEqual(sorted(done), ["chat", "djaudio", "sticky"])
        self.bot.process_commands.assert_awaited_once_with(self.msg)
        self.assertTrue(any("security_service" in line for line in captured.output), captured.output)

    def test_prefix_commands_are_processed_after_the_handlers(self):
        """process_commands は、5つを配り終えてから呼ぶこと。

        先に呼ぶと、prefix コマンドの処理が security の判定より前に走る。
        順序を入れ替えても**呼ばれた回数は同じ**なので、ここで押さえる。
        """
        order: list[str] = []

        def make(name):
            """終わった順を控えるハンドラ。"""

            async def handler(*a, **k):
                await asyncio.sleep(0.01)
                order.append(name)

            return handler

        async def process_commands(_message):
            """process_commands の代わり。"""
            order.append("process_commands")

        self.bot.process_commands = process_commands
        self._dispatch({name: make(name) for name in ("security", "chat", "sticky", "djaudio")})

        self.assertEqual(order[-1], "process_commands", order)
        self.assertEqual(len(order), 5, order)


class OnMessageDeleteTests(unittest.TestCase):
    def setUp(self):
        self.bot = _FakeBot()
        messages.register(self.bot)
        self.handler = self.bot.on_message_delete

    def test_dm_message_delete_is_ignored(self):
        msg = _message(guild=None, author=SimpleNamespace(id=1, mention="<@1>"))
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(msg))
        log.assert_not_called()

    def test_guild_message_delete_logs_the_expected_fields(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(id=2, mention="<@2>")
        created_at = datetime(2024, 1, 2, 3, 4, tzinfo=timezone.utc)
        msg = _message(guild=guild, author=author, content="hi", msg_id=99, created_at=created_at)
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(msg))
        log.assert_called_once()
        args, kwargs = log.call_args
        self.assertEqual(args[0], self.bot)
        self.assertEqual(args[1], 1)
        self.assertEqual(args[2], "INFO")
        self.assertEqual(kwargs["user"], author)
        fields = kwargs["fields"]
        self.assertEqual(fields["内容"], "hi")
        self.assertEqual(fields["ユーザーID"], "2")
        self.assertEqual(fields["メッセージID"], "99")
        self.assertNotIn("添付ファイル", fields)

    def test_empty_content_shows_a_placeholder(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(id=2, mention="<@2>")
        msg = _message(guild=guild, author=author, content="")
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(msg))
        self.assertEqual(log.call_args.kwargs["fields"]["内容"], "(内容なし)")

    def test_missing_created_at_falls_back_to_unknown_label(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(id=2, mention="<@2>")
        msg = _message(guild=guild, author=author, created_at=None)
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(msg))
        self.assertEqual(log.call_args.kwargs["fields"]["送信日時"], "(不明)")

    def test_a_none_author_still_produces_the_deletion_log(self):
        """author が無くても削除ログは出ること。

        以前はログ本文の f-string が message.author.mention を無条件に参照して
        いた。fields の「ユーザーID」は "不明" に倒しているのに本文だけ倒して
        おらず、author が None だと AttributeError になっていた。

        しかもこれは _safe() では守れない。_safe(coro, name) へ渡すコルーチンは
        引数を組み立ててから渡されるので、例外は _safe の中へ入る前に飛ぶ。
        「削除ログが出ないうえ、握りつぶされもしない」という最悪の形だった。
        """
        guild = SimpleNamespace(id=1)
        msg = _message(guild=guild, author=None)
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(msg))
        log.assert_called_once()
        self.assertIn("(不明なユーザー)", log.call_args.args[3])
        self.assertEqual(log.call_args.kwargs["fields"]["ユーザーID"], "不明")

    def test_long_attachment_urls_are_truncated(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(id=2, mention="<@2>")
        long_url = "https://example.com/" + "a" * 1100
        msg = _message(guild=guild, author=author, attachments=[SimpleNamespace(url=long_url)])
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(msg))
        field = log.call_args.kwargs["fields"]["添付ファイル"]
        self.assertTrue(field.endswith("... (省略)"))
        self.assertEqual(len(field), 1024 + len("... (省略)"))


class OnMessageEditTests(unittest.TestCase):
    def setUp(self):
        self.bot = _FakeBot()
        messages.register(self.bot)
        self.handler = self.bot.on_message_edit

    def test_dm_edit_is_ignored(self):
        before = _message(guild=None)
        after = _message(guild=None)
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(before, after))
        log.assert_not_called()

    def test_unchanged_content_is_ignored(self):
        guild = SimpleNamespace(id=1)
        before = _message(guild=guild, content="same")
        after = _message(guild=guild, content="same")
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(before, after))
        log.assert_not_called()

    def test_changed_content_logs_before_and_after(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(mention="<@2>")
        channel = SimpleNamespace(mention="#general")
        before = _message(guild=guild, author=author, channel=channel, content="old", msg_id=5)
        after = _message(guild=guild, author=author, channel=channel, content="new")
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(before, after))
        fields = log.call_args.kwargs["fields"]
        self.assertEqual(fields["編集前"], "old")
        self.assertEqual(fields["編集後"], "new")
        self.assertEqual(fields["チャンネル"], "#general")
        self.assertEqual(fields["メッセージID"], "5")

    def test_long_content_is_truncated_to_1000_chars(self):
        guild = SimpleNamespace(id=1)
        author = SimpleNamespace(mention="<@2>")
        channel = SimpleNamespace(mention="#general")
        before = _message(guild=guild, author=author, channel=channel, content="a" * 1500)
        after = _message(guild=guild, author=author, channel=channel, content="b" * 1500)
        with patch.object(messages, "log_action", AsyncMock()) as log:
            _run(self.handler(before, after))
        fields = log.call_args.kwargs["fields"]
        self.assertEqual(len(fields["編集前"]), 1000)
        self.assertEqual(len(fields["編集後"]), 1000)


# ============================================================
# events/ready.py
# ============================================================


def _make_loop(*, running=False):
    loop = Mock()
    loop.is_running.return_value = running
    loop.start = Mock()
    return loop


def _make_loops(*, running=False):
    return SimpleNamespace(
        update_status=_make_loop(running=running),
        news_feed_task=_make_loop(running=running),
        pending_sticky_task=_make_loop(running=running),
        dev_signal_task=_make_loop(running=running),
        metrics_task=_make_loop(running=running),
    )


def _make_ready_bot():
    bot = _FakeBot()
    bot.user = "TestBot#0001"
    bot.tree = SimpleNamespace(sync=AsyncMock())
    return bot


class OnReadyTests(unittest.TestCase):
    """on_ready: 何を無条件に起動し、何をフラグ・多重起動防止で止めるか。"""

    def setUp(self):
        self.bot = _make_ready_bot()
        self.state = EventState()
        self.loops = _make_loops(running=False)
        ready.register(self.bot, self.state, self.loops)
        self.handler = self.bot.on_ready

    def _default_patches(self):
        """常時オンの4系統すべてを無害化する ExitStack（with で開き直せる）。"""
        stack = ExitStack()
        stack.enter_context(patch.object(ready, "run_earthquake_ws", AsyncMock()))
        stack.enter_context(patch.object(ready, "djaudio_cache_cleanup", AsyncMock()))
        stack.enter_context(patch.object(ready, "_sync_user_state_on_ready", AsyncMock()))
        stack.enter_context(patch.object(ready, "_user_state_auto_repair_loop", AsyncMock()))
        return stack

    async def _invoke_and_settle(self):
        await self.handler()
        # asyncio.create_task() で作った背景タスクを1ステップ進めておく
        await asyncio.sleep(0)

    def test_syncs_the_command_tree_and_starts_the_always_on_loops(self):
        with self._default_patches():
            _run(self._invoke_and_settle())
        self.bot.tree.sync.assert_awaited_once()
        self.loops.update_status.start.assert_called_once()
        self.loops.dev_signal_task.start.assert_called_once()
        self.loops.metrics_task.start.assert_called_once()

    def test_does_not_restart_loops_that_are_already_running(self):
        loops = _make_loops(running=True)
        bot = _make_ready_bot()
        ready.register(bot, EventState(), loops)
        with self._default_patches():
            _run(bot.on_ready())
        loops.update_status.start.assert_not_called()
        loops.news_feed_task.start.assert_not_called()
        loops.pending_sticky_task.start.assert_not_called()
        loops.dev_signal_task.start.assert_not_called()
        loops.metrics_task.start.assert_not_called()

    def test_background_worker_disabled_skips_the_periodic_background_jobs(self):
        with (
            patch.object(ready, "_BOT_BACKGROUND_WORKER", False),
            patch.object(ready, "run_earthquake_ws", AsyncMock()) as eq_ws,
            patch.object(ready, "djaudio_cache_cleanup", AsyncMock()) as djaudio,
            patch.object(ready, "_sync_user_state_on_ready", AsyncMock()),
            patch.object(ready, "_user_state_auto_repair_loop", AsyncMock()),
        ):
            _run(self._invoke_and_settle())
        # 常時オンの3本は動く。**metrics_task がここに居ることが重要。**
        # BOT_BACKGROUND_WORKER=false のインスタンスでこれが止まると、
        # 生きているのに sycs_up{app="bot"} が 0 になり、Netdata が
        # 「Bot が落ちた」と誤って報せる。
        self.loops.update_status.start.assert_called_once()
        self.loops.dev_signal_task.start.assert_called_once()
        self.loops.metrics_task.start.assert_called_once()
        # BOT_BACKGROUND_WORKER=false のあいだ止まる3本
        self.loops.news_feed_task.start.assert_not_called()
        self.loops.pending_sticky_task.start.assert_not_called()
        eq_ws.assert_not_called()
        djaudio.assert_not_called()
        self.assertIsNone(self.state.ws_task)
        self.assertIsNone(self.state.djaudio_cleanup_task)

    def test_user_state_sync_on_ready_disabled_does_not_start_the_sync_task(self):
        with (
            patch.object(ready, "_USER_STATE_SYNC_ON_READY", False),
            patch.object(ready, "run_earthquake_ws", AsyncMock()),
            patch.object(ready, "djaudio_cache_cleanup", AsyncMock()),
            patch.object(ready, "_sync_user_state_on_ready", AsyncMock()) as sync_fn,
            patch.object(ready, "_user_state_auto_repair_loop", AsyncMock()),
        ):
            _run(self._invoke_and_settle())
        sync_fn.assert_not_called()
        self.assertFalse(self.state.user_state_sync_started)

    def test_user_state_auto_repair_disabled_does_not_start_the_repair_loop(self):
        with (
            patch.object(ready, "_USER_STATE_AUTO_REPAIR_ENABLED", False),
            patch.object(ready, "run_earthquake_ws", AsyncMock()),
            patch.object(ready, "djaudio_cache_cleanup", AsyncMock()),
            patch.object(ready, "_sync_user_state_on_ready", AsyncMock()),
            patch.object(ready, "_user_state_auto_repair_loop", AsyncMock()) as repair_fn,
        ):
            _run(self._invoke_and_settle())
        repair_fn.assert_not_called()
        self.assertFalse(self.state.user_state_repair_started)

    def test_reconnecting_does_not_start_the_sync_task_a_second_time(self):
        """on_ready は再接続のたびに何度でも発火する。多重起動防止フラグの確認。"""
        with (
            patch.object(ready, "run_earthquake_ws", AsyncMock()),
            patch.object(ready, "djaudio_cache_cleanup", AsyncMock()),
            patch.object(ready, "_sync_user_state_on_ready", AsyncMock()) as sync_fn,
            patch.object(ready, "_user_state_auto_repair_loop", AsyncMock()) as repair_fn,
        ):
            _run(self._invoke_and_settle())
            _run(self._invoke_and_settle())
        sync_fn.assert_called_once()
        repair_fn.assert_called_once()


# ============================================================
# events/members.py
# ============================================================


class RegisterMembersTests(unittest.TestCase):
    def test_registers_the_five_member_handlers(self):
        bot = _FakeBot()
        members.register(bot)
        names = {k for k in vars(bot) if k.startswith("on_")}
        self.assertEqual(
            names,
            {"on_member_join", "on_member_remove", "on_member_update", "on_member_ban", "on_member_unban"},
        )

    def test_each_wrapper_forwards_to_its_private_handler_together_with_the_bot(self):
        bot = _FakeBot()
        members.register(bot)
        member, guild, user = object(), object(), object()
        with (
            patch.object(members, "_on_member_join", AsyncMock()) as join,
            patch.object(members, "_on_member_remove", AsyncMock()) as remove,
            patch.object(members, "_on_member_update", AsyncMock()) as update,
            patch.object(members, "_on_member_ban", AsyncMock()) as ban,
            patch.object(members, "_on_member_unban", AsyncMock()) as unban,
        ):
            _run(bot.on_member_join(member))
            _run(bot.on_member_remove(member))
            _run(bot.on_member_update(member, member))
            _run(bot.on_member_ban(guild, user))
            _run(bot.on_member_unban(guild, user))
        join.assert_called_once_with(bot, member)
        remove.assert_called_once_with(bot, member)
        update.assert_called_once_with(bot, member, member)
        ban.assert_called_once_with(bot, guild, user)
        unban.assert_called_once_with(bot, guild, user)


class MemberJoinTests(unittest.TestCase):
    def _member(self, **overrides):
        base = dict(
            id=1,
            mention="<@1>",
            guild=SimpleNamespace(id=10, member_count=5),
            joined_at=None,
            created_at=None,
            timed_out_until=None,
        )
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_logs_persists_the_state_and_sends_a_welcome(self):
        member = self._member()
        with (
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
            patch.object(members, "send_welcome", AsyncMock()) as welcome,
        ):
            _run(members._on_member_join(object(), member))
        log.assert_called_once()
        self.assertEqual(record.call_args.kwargs["event_type"], "member_join")
        self.assertEqual(record.call_args.kwargs["status_after"], "active")
        welcome.assert_called_once_with(member)

    def test_a_none_member_count_falls_back_to_zero_in_the_persisted_payload(self):
        member = self._member(guild=SimpleNamespace(id=10, member_count=None))
        with (
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
            patch.object(members, "send_welcome", AsyncMock()),
        ):
            _run(members._on_member_join(object(), member))
        self.assertEqual(record.call_args.kwargs["payload"]["member_count"], 0)

    def test_welcome_failure_does_not_prevent_the_state_from_being_recorded(self):
        member = self._member()
        with (
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
            patch.object(members, "send_welcome", AsyncMock(side_effect=RuntimeError("boom"))),
            self.assertLogs("events._util", level="ERROR"),
        ):
            _run(members._on_member_join(object(), member))
        record.assert_called_once()


class MemberRemoveTests(unittest.TestCase):
    def _member(self, **overrides):
        base = dict(
            id=1,
            mention="<@1>",
            guild=SimpleNamespace(id=10, member_count=4),
            roles=[],
            timed_out_until=None,
        )
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_ordinary_leave_is_recorded_as_member_leave(self):
        member = self._member()
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(return_value=None)),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
            patch.object(members, "send_goodbye", AsyncMock()) as goodbye,
        ):
            _run(members._on_member_remove(object(), member))
        self.assertEqual(record.call_args.kwargs["event_type"], "member_leave")
        self.assertEqual(record.call_args.kwargs["status_after"], "left")
        self.assertIsNone(record.call_args.kwargs["actor"])
        goodbye.assert_called_once_with(member)

    def test_a_recent_kick_audit_entry_is_recorded_as_member_kick(self):
        member = self._member()
        kicker = SimpleNamespace(id=99)
        kick_entry = SimpleNamespace(user=kicker, reason="迷惑行為")
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(return_value=kick_entry)),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
            patch.object(members, "send_goodbye", AsyncMock()),
        ):
            _run(members._on_member_remove(object(), member))
        self.assertEqual(record.call_args.kwargs["event_type"], "member_kick")
        self.assertEqual(record.call_args.kwargs["status_after"], "kicked")
        self.assertIs(record.call_args.kwargs["actor"], kicker)
        self.assertEqual(record.call_args.kwargs["reason"], "迷惑行為")

    def test_audit_log_lookup_failure_falls_back_to_an_ordinary_leave(self):
        """監査ログ照会が例外を出しても、退出処理そのものは止まらない。"""
        member = self._member()
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(side_effect=RuntimeError("forbidden"))),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
            patch.object(members, "send_goodbye", AsyncMock()) as goodbye,
        ):
            _run(members._on_member_remove(object(), member))
        self.assertEqual(record.call_args.kwargs["event_type"], "member_leave")
        goodbye.assert_called_once()


class MemberUpdateTests(unittest.TestCase):
    """on_member_update: ニックネーム/ロール/タイムアウトのどれが変わったかで
    呼ばれるログ・永続化がちょうど1件だけ増えることを固定する。"""

    def _member(self, *, nick=None, roles=(), timed_out_until=None, guild_id=10):
        return SimpleNamespace(
            id=1,
            mention="<@1>",
            guild=SimpleNamespace(id=guild_id),
            nick=nick,
            roles=list(roles),
            timed_out_until=timed_out_until,
        )

    def test_no_changes_at_all_triggers_neither_log_nor_persist(self):
        before = self._member(nick="A")
        after = self._member(nick="A")
        with (
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_update(object(), before, after))
        log.assert_not_called()
        record.assert_not_called()

    def test_only_a_nickname_change_triggers_exactly_one_log_and_persist(self):
        before = self._member(nick="旧")
        after = self._member(nick="新")
        with (
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_update(object(), before, after))
        self.assertEqual(log.call_count, 1)
        self.assertEqual(record.call_count, 1)
        self.assertEqual(record.call_args.kwargs["event_type"], "member_nickname_changed")

    def test_only_a_role_change_triggers_exactly_one_log_and_persist(self):
        role = SimpleNamespace(id=1, name="R", position=1, mention="<@&1>", is_default=lambda: False)
        before = self._member(roles=[])
        after = self._member(roles=[role])
        with (
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_update(object(), before, after))
        self.assertEqual(log.call_count, 1)
        self.assertEqual(record.call_count, 1)
        self.assertEqual(record.call_args.kwargs["event_type"], "member_role_changed")
        self.assertEqual(record.call_args.kwargs["payload"]["added_roles"][0]["id"], 1)

    def test_a_removed_role_is_reported_in_removed_roles(self):
        role = SimpleNamespace(id=2, name="R2", position=1, mention="<@&2>", is_default=lambda: False)
        before = self._member(roles=[role])
        after = self._member(roles=[])
        with (
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_update(object(), before, after))
        self.assertEqual(record.call_args.kwargs["payload"]["removed_roles"][0]["id"], 2)
        self.assertEqual(record.call_args.kwargs["payload"]["added_roles"], [])

    def test_timeout_being_set_triggers_exactly_one_log_and_persist(self):
        until = datetime(2030, 1, 1, tzinfo=timezone.utc)
        before = self._member(timed_out_until=None)
        after = self._member(timed_out_until=until)
        with (
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_update(object(), before, after))
        self.assertEqual(log.call_count, 1)
        self.assertEqual(record.call_args.kwargs["event_type"], "member_timeout_set")
        self.assertEqual(log.call_args.kwargs["embed_color"], discord.Color.orange())

    def test_timeout_being_cleared_triggers_exactly_one_log_and_persist(self):
        until = datetime(2030, 1, 1, tzinfo=timezone.utc)
        before = self._member(timed_out_until=until)
        after = self._member(timed_out_until=None)
        with (
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_update(object(), before, after))
        self.assertEqual(log.call_count, 1)
        self.assertEqual(record.call_args.kwargs["event_type"], "member_timeout_cleared")


class MemberBanUnbanTests(unittest.TestCase):
    def _guild(self):
        return SimpleNamespace(id=1)

    def _user(self):
        return SimpleNamespace(id=2, mention="<@2>")

    def test_ban_without_an_audit_entry_still_records_the_ban(self):
        guild, user = self._guild(), self._user()
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(return_value=None)),
            patch.object(members, "log_action", AsyncMock()) as log,
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_ban(object(), guild, user))
        self.assertEqual(record.call_args.kwargs["event_type"], "member_ban")
        self.assertTrue(record.call_args.kwargs["is_banned"])
        self.assertIsNone(record.call_args.kwargs["actor"])
        self.assertEqual(log.call_args.kwargs["embed_color"], discord.Color.red())

    def test_ban_with_an_audit_entry_records_the_actor_and_reason(self):
        guild, user = self._guild(), self._user()
        actor = SimpleNamespace(id=77)
        entry = SimpleNamespace(user=actor, reason="荒らし")
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(return_value=entry)),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_ban(object(), guild, user))
        self.assertIs(record.call_args.kwargs["actor"], actor)
        self.assertEqual(record.call_args.kwargs["reason"], "荒らし")

    def test_ban_audit_lookup_failure_does_not_prevent_the_ban_from_being_recorded(self):
        """監査ログ照会が例外を出しても、BAN の記録そのものは止まらない。"""
        guild, user = self._guild(), self._user()
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(side_effect=RuntimeError("forbidden"))),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_ban(object(), guild, user))
        self.assertEqual(record.call_args.kwargs["event_type"], "member_ban")
        self.assertIsNone(record.call_args.kwargs["actor"])

    def test_unban_with_an_audit_entry_records_the_actor_and_reason(self):
        guild, user = self._guild(), self._user()
        actor = SimpleNamespace(id=88)
        entry = SimpleNamespace(user=actor, reason="誤BANのため解除")
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(return_value=entry)),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_unban(object(), guild, user))
        self.assertIs(record.call_args.kwargs["actor"], actor)
        self.assertEqual(record.call_args.kwargs["reason"], "誤BANのため解除")

    def test_unban_without_an_audit_entry_still_records_the_unban(self):
        guild, user = self._guild(), self._user()
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(return_value=None)),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_unban(object(), guild, user))
        self.assertEqual(record.call_args.kwargs["event_type"], "member_unban")
        self.assertFalse(record.call_args.kwargs["is_banned"])

    def test_audit_lookup_failure_does_not_prevent_the_unban_from_being_recorded(self):
        guild, user = self._guild(), self._user()
        with (
            patch.object(members, "_find_recent_audit_entry", AsyncMock(side_effect=RuntimeError("boom"))),
            patch.object(members, "log_action", AsyncMock()),
            patch.object(members, "record_user_state_event", AsyncMock()) as record,
        ):
            _run(members._on_member_unban(object(), guild, user))
        record.assert_called_once()


# ============================================================
# events/background_tasks.py
# ============================================================


class RegisterBackgroundTasksTests(unittest.TestCase):
    def test_returns_five_unstarted_loops(self):
        from discord.ext import tasks

        loops = bg.register(SimpleNamespace(), EventState())
        for loop in (
            loops.update_status,
            loops.news_feed_task,
            loops.pending_sticky_task,
            loops.dev_signal_task,
            loops.metrics_task,
        ):
            self.assertIsInstance(loop, tasks.Loop)
            self.assertFalse(loop.is_running())


class UpdateStatusLoopTests(unittest.TestCase):
    def setUp(self):
        self.state = EventState()
        self.bot = SimpleNamespace(
            is_ready=Mock(return_value=True),
            is_closed=Mock(return_value=False),
            latency=0.05,
            change_presence=AsyncMock(),
        )
        self.loops = bg.register(self.bot, self.state)

    def test_not_ready_skips_everything(self):
        self.bot.is_ready.return_value = False
        with patch("psutil.cpu_percent") as cpu:
            _run(self.loops.update_status())
        cpu.assert_not_called()
        self.bot.change_presence.assert_not_called()

    def test_closed_skips_everything(self):
        self.bot.is_closed.return_value = True
        with patch("psutil.cpu_percent") as cpu:
            _run(self.loops.update_status())
        cpu.assert_not_called()
        self.bot.change_presence.assert_not_called()

    def test_a_changed_text_updates_the_presence_and_remembers_it(self):
        with (
            patch("psutil.cpu_percent", return_value=1.0),
            patch("psutil.virtual_memory", return_value=SimpleNamespace(percent=2.0)),
        ):
            _run(self.loops.update_status())
        self.bot.change_presence.assert_awaited_once()
        game = self.bot.change_presence.call_args.kwargs["activity"]
        self.assertEqual(game.name, "Ping: 50ms | CPU: 1.0% | MEM: 2.0%")
        self.assertEqual(self.state.last_status_text, "Ping: 50ms | CPU: 1.0% | MEM: 2.0%")

    def test_an_unchanged_text_does_not_resend_the_presence(self):
        self.state.last_status_text = "Ping: 50ms | CPU: 1.0% | MEM: 2.0%"
        with (
            patch("psutil.cpu_percent", return_value=1.0),
            patch("psutil.virtual_memory", return_value=SimpleNamespace(percent=2.0)),
        ):
            _run(self.loops.update_status())
        self.bot.change_presence.assert_not_called()

    def test_closing_transport_errors_are_swallowed_silently(self):
        self.bot.change_presence.side_effect = RuntimeError("Cannot write to closing transport")
        with (
            patch("psutil.cpu_percent", return_value=1.0),
            patch("psutil.virtual_memory", return_value=SimpleNamespace(percent=2.0)),
            patch.object(bg.logger, "exception") as log_exc,
        ):
            _run(self.loops.update_status())  # 例外が外へ出ないことも同時に確認
        log_exc.assert_not_called()

    def test_client_connection_reset_errors_are_swallowed_silently(self):
        class ClientConnectionResetError(Exception):
            pass

        self.bot.change_presence.side_effect = ClientConnectionResetError("reset")
        with (
            patch("psutil.cpu_percent", return_value=1.0),
            patch("psutil.virtual_memory", return_value=SimpleNamespace(percent=2.0)),
            patch.object(bg.logger, "exception") as log_exc,
        ):
            _run(self.loops.update_status())
        log_exc.assert_not_called()

    def test_other_errors_are_logged(self):
        self.bot.change_presence.side_effect = RuntimeError("boom")
        with (
            patch("psutil.cpu_percent", return_value=1.0),
            patch("psutil.virtual_memory", return_value=SimpleNamespace(percent=2.0)),
            self.assertLogs(bg.logger, level="ERROR") as cm,
        ):
            _run(self.loops.update_status())
        self.assertTrue(any("boom" in line for line in cm.output))


class NewsAndStickyLoopTests(unittest.TestCase):
    def setUp(self):
        self.state = EventState()
        self.bot = SimpleNamespace()
        self.loops = bg.register(self.bot, self.state)

    def test_news_feed_task_calls_run_news_feeds_with_the_bot(self):
        with patch.object(bg, "run_news_feeds", AsyncMock()) as run_news:
            _run(self.loops.news_feed_task())
        run_news.assert_awaited_once_with(self.bot)

    def test_news_feed_task_swallows_errors_via_safe(self):
        with (
            patch.object(bg, "run_news_feeds", AsyncMock(side_effect=RuntimeError("boom"))),
            self.assertLogs("events._util", level="ERROR"),
        ):
            _run(self.loops.news_feed_task())  # 例外が外へ出ないことを確認

    def test_pending_sticky_task_calls_process_pending_stickies_with_the_bot(self):
        with patch.object(bg, "process_pending_stickies", AsyncMock()) as run_sticky:
            _run(self.loops.pending_sticky_task())
        run_sticky.assert_awaited_once_with(self.bot)


def _sig_file(name, content="", *, read_error=None):
    """dev_signal_task が読む1件のシグナルファイルの代わり。

    task_name_of() は path.name をそのまま使う実装なので、Mock に
    文字列の .name だけ持たせれば実物の Path と同じに扱える。
    """
    sig = Mock()
    sig.name = name
    if read_error is not None:
        sig.read_text = Mock(side_effect=read_error)
    else:
        sig.read_text = Mock(return_value=content)
    sig.unlink = Mock()
    return sig


class RegisterBackgroundTasksShapeTests(unittest.TestCase):
    """register() が組み立てる5本のループを、間隔ごと固定する。

    214行ある `register` を割る前に、外から見た姿を押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    振り分けの中身は下の DevSignalTaskTests が用途名ごとに押さえているが、
    **どのループが何秒間隔かは誰も見ていなかった。** クロージャを外へ出す
    ときに `seconds=30` を `minutes=30` と書き間違えても、型は tasks.Loop の
    ままだし、テストも全部通る。本番では60倍遅くなるだけで、例外も出ない。

    ステータス更新の20秒は Discord のプレゼンス更新制限（20秒あたり5回）から
    決めた値なので、短くすると制限に当たる。ここは数字そのものに意味がある。
    """

    # (フィールド名, seconds, minutes, hours, コルーチン名)
    LOOPS = [
        ("update_status", 20.0, 0.0, 0.0, "update_status"),
        ("news_feed_task", 0.0, 5.0, 0.0, "news_feed_task"),
        ("pending_sticky_task", 30.0, 0.0, 0.0, "pending_sticky_task"),
        ("dev_signal_task", 30.0, 0.0, 0.0, "dev_signal_task"),
        # メトリクスの報告。**この間隔を延ばすと、Bot が死んでから Netdata が
        # 気づくまでの時間がそのまま延びる**（sycs_up は心拍の古さで決まる）。
        # METRICS_STALE_AFTER_SECONDS（既定90秒）より十分短く保つこと。
        ("metrics_task", 30.0, 0.0, 0.0, "metrics_task"),
    ]

    def test_every_loop_keeps_its_interval(self):
        """5本とも、同じ名前・同じ間隔で作られること。"""
        loops = bg.register(SimpleNamespace(), EventState())
        actual = [
            (name, loop.seconds, loop.minutes, loop.hours, loop.coro.__name__)
            for name, loop in ((n, getattr(loops, n)) for n, *_ in self.LOOPS)
        ]
        self.assertEqual(actual, [tuple(row) for row in self.LOOPS])

    def test_the_status_interval_comes_from_the_environment(self):
        """ステータス更新の間隔だけは環境変数で変えられること。

        レート制限に当たったときに再デプロイ無しで延ばせるようにしてある。
        定数を直接参照しているので、切り出しの際に読む場所を間違えると
        環境変数が効かなくなる（効かなくなっても既定値で動くので気づけない）。
        """
        with patch.object(bg, "_STATUS_INTERVAL_SECONDS", 47):
            loops = bg.register(SimpleNamespace(), EventState())
        self.assertEqual(loops.update_status.seconds, 47.0)


class DevSignalOrderTests(unittest.TestCase):
    """シグナルを、置かれた順に処理すること。

    同じ用途が複数溜まっていることがあり（録音の開始と停止など）、順序が
    入れ替わると噛み合わない。**入れ替わっても例外は出ず、ログも全部出る。**
    「開始→停止」が「停止→開始」になれば、録音が止まらないまま残るだけ。
    """

    def setUp(self):
        self.state = EventState()
        self.bot = SimpleNamespace()
        self.loops = bg.register(self.bot, self.state)

    def test_signals_are_handled_in_the_order_they_were_collected(self):
        """並べた順にそのまま処理されること。

        用途を3つとも別にしてあるのは、並びを逆にする変異で落ちるようにする
        ため。最初は news/sticky/news の3件で書いていたが、これは逆順にしても
        同じ並びになる（回文）ので、順序を壊しても落ちなかった。
        """
        files = [_sig_file("news_feeds.signal"), _sig_file("sticky.signal"), _sig_file("djaudio_cache.signal")]
        calls: list[str] = []
        cleanup = AsyncMock(side_effect=lambda **_: calls.append("djaudio"))
        with (
            patch("services.dev_signals.collect", return_value=files),
            patch.object(bg, "run_news_feeds", AsyncMock(side_effect=lambda *_: calls.append("news"))),
            patch.object(bg, "process_pending_stickies", AsyncMock(side_effect=lambda *_: calls.append("sticky"))),
            patch("services.djaudio_cache._cleanup_expired", cleanup),
        ):
            _run(self.loops.dev_signal_task())
        self.assertEqual(calls, ["news", "sticky", "djaudio"])


class DevSignalTaskTests(unittest.TestCase):
    """dev_signal_task: シグナルの用途名ごとにどのサービスへ振り分けるか。"""

    def setUp(self):
        self.state = EventState()
        self.bot = SimpleNamespace()
        self.loops = bg.register(self.bot, self.state)

    def test_unknown_signal_warns_and_does_not_log_completion(self):
        sig = _sig_file("mystery.signal")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            self.assertLogs(bg.logger, level="INFO") as cm,
        ):
            _run(self.loops.dev_signal_task())
        sig.unlink.assert_called_once_with(missing_ok=True)
        self.assertTrue(any("未知のシグナル" in line for line in cm.output))
        self.assertFalse(any("シグナル完了" in line for line in cm.output))

    def test_an_unreadable_signal_is_skipped_without_deleting_it(self):
        sig = _sig_file("news_feeds.signal", read_error=OSError("locked"))
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch.object(bg, "run_news_feeds", AsyncMock()) as run_news,
        ):
            _run(self.loops.dev_signal_task())
        run_news.assert_not_called()
        sig.unlink.assert_not_called()

    def test_news_feeds_signal_runs_and_deletes_the_file(self):
        sig = _sig_file("news_feeds.signal")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch.object(bg, "run_news_feeds", AsyncMock()) as run_news,
        ):
            _run(self.loops.dev_signal_task())
        run_news.assert_awaited_once_with(self.bot)
        sig.unlink.assert_called_once_with(missing_ok=True)

    def test_sticky_signal_runs_process_pending_stickies(self):
        sig = _sig_file("sticky.signal")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch.object(bg, "process_pending_stickies", AsyncMock()) as run_sticky,
        ):
            _run(self.loops.dev_signal_task())
        run_sticky.assert_awaited_once_with(self.bot)

    def test_djaudio_cache_signal_runs_cleanup(self):
        sig = _sig_file("djaudio_cache.signal")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.djaudio_cache._cleanup_expired", AsyncMock()) as cleanup,
        ):
            _run(self.loops.dev_signal_task())
        cleanup.assert_awaited_once_with(bot=self.bot)

    def test_earthquake_reconnect_cancels_the_old_task_and_creates_a_new_one(self):
        old_task = Mock()
        old_task.done.return_value = False
        self.state.ws_task = old_task
        sig = _sig_file("earthquake_reconnect.signal")

        async def _scenario():
            with (
                patch("services.dev_signals.collect", return_value=[sig]),
                patch.object(bg, "run_earthquake_ws", AsyncMock()),
            ):
                await self.loops.dev_signal_task()
                new_task = self.state.ws_task
                await new_task  # 生成した Task を後片付けする（pending のまま残さない）
                return new_task

        new_task = _run(_scenario())
        old_task.cancel.assert_called_once()
        self.assertIsNot(new_task, old_task)
        self.assertIsInstance(new_task, asyncio.Task)

    def test_user_state_repair_signal_runs_a_full_sync_with_integrity_repair(self):
        sig = _sig_file("user_state_repair.signal")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch.object(bg, "_sync_user_state_all_guilds", AsyncMock()) as sync_all,
        ):
            _run(self.loops.dev_signal_task())
        sync_all.assert_awaited_once()
        kwargs = sync_all.call_args.kwargs
        self.assertEqual(kwargs["source"], "manual_signal")
        self.assertTrue(kwargs["run_integrity_repair"])
        self.assertIs(kwargs["lock"], self.state.user_state_sync_lock)

    def test_eq_replay_new_format_passes_the_guild_and_channel_overrides(self):
        payload = json.dumps({"event": {"foo": "bar"}, "guild_id": 42, "channel_id": 99})
        sig = _sig_file("eq_replay.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.earthquake_service._notify_all_guilds", AsyncMock(return_value=3)) as notify,
        ):
            _run(self.loops.dev_signal_task())
        notify.assert_awaited_once_with(self.bot, {"foo": "bar"}, only_guild_id=42, override_channel_id=99)

    def test_eq_replay_old_format_treats_the_whole_payload_as_the_event(self):
        payload = json.dumps({"foo": "legacy"})
        sig = _sig_file("eq_replay.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.earthquake_service._notify_all_guilds", AsyncMock(return_value=0)) as notify,
        ):
            _run(self.loops.dev_signal_task())
        notify.assert_awaited_once_with(self.bot, {"foo": "legacy"}, only_guild_id=None, override_channel_id=None)

    def test_test_prefixed_signal_runs_the_named_notification_test(self):
        payload = json.dumps({"guild_id": 7, "channel_id": 8})
        sig = _sig_file("test_welcome.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.dev_test_notify.KINDS", ("welcome",)),
            patch("services.dev_test_notify.run_test", AsyncMock()) as run_test,
        ):
            _run(self.loops.dev_signal_task())
        run_test.assert_awaited_once_with(self.bot, "welcome", 7, 8)

    def test_test_prefixed_signal_with_an_unknown_kind_warns_without_calling_run_test(self):
        sig = _sig_file("test_bogus.signal", content="{}")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.dev_test_notify.KINDS", ("welcome",)),
            patch("services.dev_test_notify.run_test", AsyncMock()) as run_test,
            self.assertLogs(bg.logger, level="WARNING") as cm,
        ):
            _run(self.loops.dev_signal_task())
        run_test.assert_not_called()
        self.assertTrue(any("未知の通知テスト" in line for line in cm.output))

    def test_recording_start_with_a_missing_guild_warns_and_does_not_start(self):
        payload = json.dumps({"guild_id": 123, "channel_id": 456})
        sig = _sig_file("recording_start.signal", content=payload)
        bot = SimpleNamespace(get_guild=Mock(return_value=None))
        loops = bg.register(bot, self.state)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.recording_service.start_recording", AsyncMock()) as start_rec,
            self.assertLogs(bg.logger, level="WARNING"),
        ):
            _run(loops.dev_signal_task())
        start_rec.assert_not_called()

    def test_recording_start_with_a_channel_that_is_not_a_voice_channel_warns_and_does_not_start(self):
        guild = SimpleNamespace(get_channel=Mock(return_value=SimpleNamespace()), me="me-member")
        bot = SimpleNamespace(get_guild=Mock(return_value=guild), user="bot-user")
        loops = bg.register(bot, self.state)
        payload = json.dumps({"guild_id": 123, "channel_id": 456})
        sig = _sig_file("recording_start.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.recording_service.start_recording", AsyncMock()) as start_rec,
            self.assertLogs(bg.logger, level="WARNING") as cm,
        ):
            _run(loops.dev_signal_task())
        start_rec.assert_not_called()
        self.assertTrue(any("recording_start" in line for line in cm.output))

    def test_recording_start_failure_is_warned_not_raised(self):
        channel = Mock(spec=discord.VoiceChannel)
        channel.id = 456
        guild = SimpleNamespace(get_channel=Mock(return_value=channel), me="me-member")
        bot = SimpleNamespace(get_guild=Mock(return_value=guild), user="bot-user")
        loops = bg.register(bot, self.state)
        payload = json.dumps({"guild_id": 123, "channel_id": 456})
        sig = _sig_file("recording_start.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch(
                "services.recording_service.start_recording",
                AsyncMock(side_effect=RecordingError("既に録音中")),
            ),
            self.assertLogs(bg.logger, level="WARNING") as cm,
        ):
            _run(loops.dev_signal_task())  # 例外が外へ出ないことを確認
        self.assertTrue(any("recording_start" in line for line in cm.output))

    def test_recording_start_success_starts_recording_on_the_resolved_channel(self):
        channel = Mock(spec=discord.VoiceChannel)
        channel.id = 456
        guild = SimpleNamespace(get_channel=Mock(return_value=channel), me="me-member")
        bot = SimpleNamespace(get_guild=Mock(return_value=guild), user="bot-user")
        loops = bg.register(bot, self.state)
        payload = json.dumps({"guild_id": 123, "channel_id": 456})
        sig = _sig_file("recording_start.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.recording_service.start_recording", AsyncMock()) as start_rec,
        ):
            _run(loops.dev_signal_task())
        start_rec.assert_awaited_once_with(bot, guild, channel, started_by="me-member")

    def test_recording_stop_success_sends_the_result_embed(self):
        target = Mock(spec=discord.abc.Messageable)
        guild = SimpleNamespace(get_channel=Mock(return_value=None))
        bot = SimpleNamespace(get_guild=Mock(return_value=guild))
        loops = bg.register(bot, self.state)
        payload = json.dumps({"guild_id": 123})
        sig = _sig_file("recording_stop.signal", content=payload)
        result = {"channel_id": 1, "token": "tok"}
        embed = discord.Embed(title="done")
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.recording_service.stop_recording", AsyncMock(return_value=result)),
            patch("services.recording_service.build_result_embed", return_value=embed),
            patch("services.recording_service.resolve_announce_channel", return_value=target),
        ):
            _run(loops.dev_signal_task())
        target.send.assert_awaited_once_with(embed=embed)

    def test_recording_stop_with_no_valid_send_target_warns(self):
        guild = SimpleNamespace(get_channel=Mock(return_value=None))
        bot = SimpleNamespace(get_guild=Mock(return_value=guild))
        loops = bg.register(bot, self.state)
        payload = json.dumps({"guild_id": 123})
        sig = _sig_file("recording_stop.signal", content=payload)
        result = {"channel_id": 1, "token": "tok"}
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch("services.recording_service.stop_recording", AsyncMock(return_value=result)),
            patch("services.recording_service.build_result_embed", return_value=discord.Embed()),
            patch("services.recording_service.resolve_announce_channel", return_value=None),  # 送り先が無い
            self.assertLogs(bg.logger, level="WARNING") as cm,
        ):
            _run(loops.dev_signal_task())
        self.assertTrue(any("送信先がありません" in line and "tok" in line for line in cm.output))

    def test_recording_stop_failure_is_warned_not_raised(self):
        guild = SimpleNamespace(get_channel=Mock(return_value=None))
        bot = SimpleNamespace(get_guild=Mock(return_value=guild))
        loops = bg.register(bot, self.state)
        payload = json.dumps({"guild_id": 123})
        sig = _sig_file("recording_stop.signal", content=payload)
        with (
            patch("services.dev_signals.collect", return_value=[sig]),
            patch(
                "services.recording_service.stop_recording",
                AsyncMock(side_effect=RecordingError("既に停止済み")),
            ),
            self.assertLogs(bg.logger, level="WARNING") as cm,
        ):
            _run(loops.dev_signal_task())
        self.assertTrue(any("recording_stop" in line for line in cm.output))

    def test_an_exception_while_processing_one_signal_does_not_stop_the_others(self):
        bad = _sig_file("eq_replay.signal", content="{not json")
        good = _sig_file("news_feeds.signal")
        with (
            patch("services.dev_signals.collect", return_value=[bad, good]),
            patch.object(bg, "run_news_feeds", AsyncMock()) as run_news,
            self.assertLogs(bg.logger, level="ERROR"),
        ):
            _run(self.loops.dev_signal_task())
        run_news.assert_awaited_once_with(self.bot)


# ============================================================
# events/voice.py
# ============================================================


class RegisterVoiceTests(unittest.TestCase):
    def test_registers_on_voice_state_update(self):
        bot = _FakeBot()
        voice.register(bot)
        self.assertEqual({k for k in vars(bot) if k.startswith("on_")}, {"on_voice_state_update"})


class TtsVcAnnounceTests(unittest.TestCase):
    """_tts_vc_announce: bot自身を含む全メンバーのVC参加・退出アナウンス判定。"""

    def _member(self, *, is_bot=False, guild_id=1):
        return SimpleNamespace(guild=SimpleNamespace(id=guild_id), bot=is_bot)

    def _state(self, channel_id=None, *, members=None):
        if channel_id is None:
            return SimpleNamespace(channel=None)
        return SimpleNamespace(channel=SimpleNamespace(id=channel_id, members=members or []))

    def test_join_enqueues_the_join_announcement_when_configured(self):
        bot = object()
        member = self._member()
        before = self._state(None)
        after = self._state(555)
        with (
            patch("services.tts_store.get_tts_settings", return_value={"enabled": True, "vc_notify": True}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(555, [])),
            patch("services.tts_service.enqueue_vc_event", AsyncMock()) as enqueue,
        ):
            _run(voice._tts_vc_announce(bot, member, before, after))
        enqueue.assert_called_once_with(bot, member.guild, member, "join")

    def test_bot_members_joining_are_not_announced(self):
        bot = object()
        member = self._member(is_bot=True)
        before = self._state(None)
        after = self._state(555)
        with (
            patch("services.tts_store.get_tts_settings", return_value={"enabled": True, "vc_notify": True}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(555, [])),
            patch("services.tts_service.enqueue_vc_event", AsyncMock()) as enqueue,
        ):
            _run(voice._tts_vc_announce(bot, member, before, after))
        enqueue.assert_not_called()

    def test_a_leave_that_empties_the_watched_channel_disconnects_instead_of_announcing(self):
        bot = object()
        member = self._member()
        before = self._state(555, members=[])  # 人間ゼロ
        after = self._state(None)
        with (
            patch("services.tts_store.get_tts_settings", return_value={"enabled": True, "vc_notify": True}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(555, [])),
            patch("services.tts_service.enqueue_vc_event", AsyncMock()) as enqueue,
            patch("services.tts_service.disconnect", AsyncMock()) as disconnect,
        ):
            _run(voice._tts_vc_announce(bot, member, before, after))
        disconnect.assert_called_once_with(1)
        enqueue.assert_not_called()

    def test_a_leave_that_does_not_empty_the_channel_announces_the_leave(self):
        bot = object()
        member = self._member()
        before = self._state(555, members=[SimpleNamespace(bot=False)])  # まだ人間が居る
        after = self._state(None)
        with (
            patch("services.tts_store.get_tts_settings", return_value={"enabled": True, "vc_notify": True}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(555, [])),
            patch("services.tts_service.enqueue_vc_event", AsyncMock()) as enqueue,
            patch("services.tts_service.disconnect", AsyncMock()) as disconnect,
        ):
            _run(voice._tts_vc_announce(bot, member, before, after))
        enqueue.assert_called_once_with(bot, member.guild, member, "leave")
        disconnect.assert_not_called()

    def test_a_move_is_neither_a_join_nor_a_leave_so_nothing_happens(self):
        bot = object()
        member = self._member()
        before = self._state(111)
        after = self._state(222)
        with (
            patch("services.tts_store.get_tts_settings", return_value={"enabled": True, "vc_notify": True}),
            patch("services.tts_service.get_effective_vc_watch", return_value=(111, [])),
            patch("services.tts_service.enqueue_vc_event", AsyncMock()) as enqueue,
            patch("services.tts_service.disconnect", AsyncMock()) as disconnect,
        ):
            _run(voice._tts_vc_announce(bot, member, before, after))
        enqueue.assert_not_called()
        disconnect.assert_not_called()

    def test_an_internal_exception_is_logged_and_not_raised(self):
        bot = object()
        member = self._member()
        before = self._state(None)
        after = self._state(555)
        with (
            patch("services.tts_store.get_tts_settings", side_effect=RuntimeError("boom")),
            self.assertLogs(voice.logger, level="ERROR") as cm,
        ):
            _run(voice._tts_vc_announce(bot, member, before, after))  # 例外が外へ出ないことも確認
        self.assertTrue(any("boom" in line for line in cm.output))


class LogVcTransitionTests(unittest.TestCase):
    def _member(self):
        return SimpleNamespace(guild=SimpleNamespace(id=1), mention="<@1>")

    def test_join_logs_with_the_after_channel(self):
        after_ch = SimpleNamespace(mention="#after")
        with patch.object(voice, "log_action", AsyncMock()) as log:
            _run(voice._log_vc_transition(object(), self._member(), True, False, False, None, after_ch))
        self.assertEqual(log.call_args.kwargs["fields"]["チャンネル"], "#after")

    def test_leave_logs_with_the_before_channel(self):
        before_ch = SimpleNamespace(mention="#before")
        with patch.object(voice, "log_action", AsyncMock()) as log:
            _run(voice._log_vc_transition(object(), self._member(), False, True, False, before_ch, None))
        self.assertEqual(log.call_args.kwargs["fields"]["チャンネル"], "#before")

    def test_move_logs_both_channels(self):
        before_ch = SimpleNamespace(mention="#before")
        after_ch = SimpleNamespace(mention="#after")
        with patch.object(voice, "log_action", AsyncMock()) as log:
            _run(voice._log_vc_transition(object(), self._member(), False, False, True, before_ch, after_ch))
        fields = log.call_args.kwargs["fields"]
        self.assertEqual(fields["移動前"], "#before")
        self.assertEqual(fields["移動後"], "#after")

    def test_none_of_the_three_logs_nothing(self):
        with patch.object(voice, "log_action", AsyncMock()) as log:
            _run(voice._log_vc_transition(object(), self._member(), False, False, False, None, None))
        log.assert_not_called()

    def test_log_action_failure_is_swallowed(self):
        after_ch = SimpleNamespace(mention="#after")
        with (
            patch.object(voice, "log_action", AsyncMock(side_effect=RuntimeError("down"))),
            self.assertLogs(voice.logger, level="ERROR"),
        ):
            _run(voice._log_vc_transition(object(), self._member(), True, False, False, None, after_ch))


class PersistVcTransitionTests(unittest.TestCase):
    def _member(self):
        return SimpleNamespace(guild=SimpleNamespace(id=1), id=2, timed_out_until=None)

    def test_join_persists_voice_join_with_the_after_channel(self):
        after_ch = SimpleNamespace(id=10, name="general")
        with patch.object(voice, "record_user_state_event", AsyncMock()) as record:
            _run(voice._persist_vc_transition(self._member(), True, False, False, None, after_ch, None, ""))
        kwargs = record.call_args.kwargs
        self.assertEqual(kwargs["event_type"], "voice_join")
        self.assertEqual(kwargs["payload"]["channel_after_id"], 10)

    def test_leave_persists_voice_leave_with_the_duration(self):
        before_ch = SimpleNamespace(id=10, name="general")
        with patch.object(voice, "record_user_state_event", AsyncMock()) as record:
            _run(voice._persist_vc_transition(self._member(), False, True, False, before_ch, None, 61, "00:01:01"))
        kwargs = record.call_args.kwargs
        self.assertEqual(kwargs["event_type"], "voice_leave")
        self.assertEqual(kwargs["payload"]["duration_seconds"], 61)
        self.assertEqual(kwargs["payload"]["duration_hms"], "00:01:01")

    def test_move_persists_voice_move_with_both_channels(self):
        before_ch = SimpleNamespace(id=10, name="a")
        after_ch = SimpleNamespace(id=20, name="b")
        with patch.object(voice, "record_user_state_event", AsyncMock()) as record:
            _run(voice._persist_vc_transition(self._member(), False, False, True, before_ch, after_ch, None, ""))
        kwargs = record.call_args.kwargs
        self.assertEqual(kwargs["event_type"], "voice_move")
        self.assertEqual(kwargs["payload"]["channel_before_id"], 10)
        self.assertEqual(kwargs["payload"]["channel_after_id"], 20)

    def test_none_of_the_three_persists_nothing(self):
        with patch.object(voice, "record_user_state_event", AsyncMock()) as record:
            _run(voice._persist_vc_transition(self._member(), False, False, False, None, None, None, ""))
        record.assert_not_called()

    def test_persist_failure_is_swallowed(self):
        after_ch = SimpleNamespace(id=10, name="general")
        with (
            patch.object(voice, "record_user_state_event", AsyncMock(side_effect=RuntimeError("db down"))),
            self.assertLogs(voice.logger, level="ERROR"),
        ):
            _run(voice._persist_vc_transition(self._member(), True, False, False, None, after_ch, None, ""))


class VcNotifyHandlerTests(unittest.TestCase):
    def _member(self, guild_id=1):
        guild = SimpleNamespace(id=guild_id, get_role=lambda rid: SimpleNamespace())
        return SimpleNamespace(guild=guild, display_name="太郎", display_avatar=SimpleNamespace(url="http://a/x.png"))

    def _text_channel(self):
        return Mock(spec=discord.TextChannel)

    def test_a_non_transition_returns_immediately(self):
        member = self._member()
        with patch.object(voice, "get_vc_notify_channel_id") as get_id:
            _run(voice._vc_notify_handler(member, False, False, False, None, None, 0.0, "", {}))
        get_id.assert_not_called()

    def test_no_notify_channel_configured_sends_nothing(self):
        # guild.get_channel を敢えて未定義のままにし、呼ばれたら AttributeError で分かるようにする
        member = self._member()
        with patch.object(voice, "get_vc_notify_channel_id", return_value=0):
            _run(voice._vc_notify_handler(member, True, False, False, None, SimpleNamespace(name="c"), 0.0, "", {}))

    def test_a_notify_channel_that_is_not_a_text_channel_sends_nothing(self):
        member = self._member()
        member.guild.get_channel = lambda cid: SimpleNamespace()  # discord.TextChannel ではない
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter") as filt,
        ):
            _run(voice._vc_notify_handler(member, True, False, False, None, SimpleNamespace(name="c"), 0.0, "", {}))
        filt.assert_not_called()

    def test_a_filter_rejection_sends_nothing(self):
        member = self._member()
        ch = self._text_channel()
        member.guild.get_channel = lambda cid: ch
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter", return_value=False),
        ):
            _run(voice._vc_notify_handler(member, True, False, False, None, SimpleNamespace(name="c"), 0.0, "", {}))
        ch.send.assert_not_called()

    def test_join_sends_a_green_embed_without_a_mention_when_no_role_is_configured(self):
        member = self._member()
        ch = self._text_channel()
        member.guild.get_channel = lambda cid: ch
        after_ch = SimpleNamespace(name="雑談")
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter", return_value=True),
            patch.object(voice, "get_vc_notify_role_id", return_value=0),
        ):
            _run(voice._vc_notify_handler(member, True, False, False, None, after_ch, 1_700_000_000.0, "", {}))
        ch.send.assert_called_once()
        kwargs = ch.send.call_args.kwargs
        self.assertIsNone(kwargs["content"])
        self.assertEqual(kwargs["embed"].title, "VCに参加しました")

    def test_leave_embed_never_mentions_the_role_and_includes_the_duration(self):
        member = self._member()
        ch = self._text_channel()
        member.guild.get_channel = lambda cid: ch
        before_ch = SimpleNamespace(name="雑談")
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter", return_value=True),
            patch.object(voice, "get_vc_notify_role_id", return_value=555),  # 退出は付けない
        ):
            _run(voice._vc_notify_handler(member, False, True, False, before_ch, None, 1_700_000_000.0, "01:02:03", {}))
        kwargs = ch.send.call_args.kwargs
        self.assertIsNone(kwargs["content"])
        self.assertIn("01:02:03", kwargs["embed"].description)
        self.assertEqual(kwargs["embed"].title, "VCから切断しました")

    def test_move_embed_shows_both_channel_names(self):
        member = self._member()
        ch = self._text_channel()
        member.guild.get_channel = lambda cid: ch
        before_ch = SimpleNamespace(name="A")
        after_ch = SimpleNamespace(name="B")
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter", return_value=True),
            patch.object(voice, "get_vc_notify_role_id", return_value=0),
        ):
            _run(voice._vc_notify_handler(member, False, False, True, before_ch, after_ch, 1_700_000_000.0, "", {}))
        embed = ch.send.call_args.kwargs["embed"]
        self.assertIn("A", embed.description)
        self.assertIn("B", embed.description)

    def test_join_mentions_the_role_and_records_the_mention_time(self):
        member = self._member()
        ch = self._text_channel()
        member.guild.get_channel = lambda cid: ch
        after_ch = SimpleNamespace(name="雑談")
        vc_last_mention = {}
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter", return_value=True),
            patch.object(voice, "get_vc_notify_role_id", return_value=555),
        ):
            _run(
                voice._vc_notify_handler(
                    member, True, False, False, None, after_ch, 1_700_000_000.0, "", vc_last_mention
                )
            )
        self.assertEqual(ch.send.call_args.kwargs["content"], "<@&555>")
        self.assertEqual(vc_last_mention[member.guild.id], 1_700_000_000.0)

    def test_join_mention_is_skipped_within_ten_minutes_of_the_previous_one(self):
        member = self._member()
        ch = self._text_channel()
        member.guild.get_channel = lambda cid: ch
        after_ch = SimpleNamespace(name="雑談")
        now_ts = 1_700_000_500.0
        vc_last_mention = {member.guild.id: now_ts - 100}  # 10分未満前
        with (
            patch.object(voice, "get_vc_notify_channel_id", return_value=999),
            patch.object(voice, "_passes_vc_notify_filter", return_value=True),
            patch.object(voice, "get_vc_notify_role_id", return_value=555),
        ):
            _run(voice._vc_notify_handler(member, True, False, False, None, after_ch, now_ts, "", vc_last_mention))
        self.assertIsNone(ch.send.call_args.kwargs["content"])


class StopRecordingIfVcEmptyTests(unittest.TestCase):
    def _channel(self, cid, *, members=()):
        return SimpleNamespace(id=cid, members=list(members))

    def test_no_active_session_does_nothing(self):
        guild = SimpleNamespace(id=1)
        channel = self._channel(10)
        with (
            patch("services.recording_service.get_session", return_value=None),
            patch("services.recording_service.stop_recording", AsyncMock()) as stop,
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        stop.assert_not_called()

    def test_channel_none_does_nothing(self):
        guild = SimpleNamespace(id=1)
        session = SimpleNamespace(channel_id=10)
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock()) as stop,
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, None))
        stop.assert_not_called()

    def test_a_different_channel_than_the_recording_session_does_nothing(self):
        guild = SimpleNamespace(id=1)
        session = SimpleNamespace(channel_id=999)
        channel = self._channel(10)
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock()) as stop,
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        stop.assert_not_called()

    def test_a_human_still_present_does_nothing(self):
        guild = SimpleNamespace(id=1)
        session = SimpleNamespace(channel_id=10)
        channel = self._channel(10, members=[SimpleNamespace(bot=False)])
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock()) as stop,
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        stop.assert_not_called()

    def test_only_bots_remaining_stops_and_announces_on_the_configured_channel(self):
        guild = SimpleNamespace(id=1)
        session = SimpleNamespace(channel_id=10, announce_message=None)
        channel = self._channel(10, members=[SimpleNamespace(bot=True)])
        configured = Mock(spec=discord.abc.Messageable)
        embed = discord.Embed(title="結果")
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock(return_value={"token": "abc"})) as stop,
            patch("services.recording_service.build_result_embed", return_value=embed),
            patch("services.recording_service.resolve_announce_channel", return_value=configured),
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        stop.assert_awaited_once()
        self.assertEqual(stop.call_args.kwargs["reason"], "VC が空になりました")
        configured.send.assert_awaited_once_with(embed=embed)

    def test_falls_back_to_the_original_announce_message_channel_when_nothing_is_configured(self):
        guild = SimpleNamespace(id=1)
        announced_channel = Mock(spec=discord.abc.Messageable)
        session = SimpleNamespace(channel_id=10, announce_message=SimpleNamespace(channel=announced_channel))
        channel = self._channel(10, members=[])
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock(return_value={"token": "x"})),
            patch("services.recording_service.build_result_embed", return_value=discord.Embed()),
            patch("services.recording_service.resolve_announce_channel", return_value=None),
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        announced_channel.send.assert_awaited_once()

    def test_falls_back_to_the_vc_text_chat_when_nothing_else_is_available(self):
        guild = SimpleNamespace(id=1)
        session = SimpleNamespace(channel_id=10, announce_message=None)
        channel = Mock(spec=discord.abc.Messageable)
        channel.id = 10
        channel.members = []
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock(return_value={"token": "x"})),
            patch("services.recording_service.build_result_embed", return_value=discord.Embed()),
            patch("services.recording_service.resolve_announce_channel", return_value=None),
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        channel.send.assert_awaited_once()

    def test_warns_when_every_send_target_fails(self):
        guild = SimpleNamespace(id=1)
        session = SimpleNamespace(channel_id=10, announce_message=None)
        channel = Mock(spec=discord.abc.Messageable)
        channel.id = 10
        channel.members = []
        channel.send = AsyncMock(side_effect=RuntimeError("送信失敗"))
        with (
            patch("services.recording_service.get_session", return_value=session),
            patch("services.recording_service.stop_recording", AsyncMock(return_value={"token": "x"})),
            patch("services.recording_service.build_result_embed", return_value=discord.Embed()),
            patch("services.recording_service.resolve_announce_channel", return_value=None),
            self.assertLogs(voice.logger, level="WARNING") as cm,
        ):
            _run(voice._stop_recording_if_vc_empty(object(), guild, channel))
        self.assertTrue(any("token" in line for line in cm.output))


class OnVoiceStateUpdateContractTests(unittest.TestCase):
    """on_voice_state_update: イベントの種類ごとにどのサービスが呼ばれ、
    どれが呼ばれないかの配線を固定する。個々のヘルパーの中身は上の
    専用テストクラスで確認済みなので、ここでは呼び出しの有無だけを見る。
    """

    def setUp(self):
        self.bot = _FakeBot()
        voice.register(self.bot)
        self.handler = self.bot.on_voice_state_update

    def _patch_all(self, *, tts_settings=None):
        stack = ExitStack()
        mocks = {
            "tts_announce": stack.enter_context(patch.object(voice, "_tts_vc_announce", AsyncMock())),
            "security": stack.enter_context(patch.object(voice, "handle_security_for_voice_join", AsyncMock())),
            "log_transition": stack.enter_context(patch.object(voice, "_log_vc_transition", AsyncMock())),
            "persist_transition": stack.enter_context(patch.object(voice, "_persist_vc_transition", AsyncMock())),
            "notify": stack.enter_context(patch.object(voice, "_vc_notify_handler", AsyncMock())),
            "stop_recording": stack.enter_context(patch.object(voice, "_stop_recording_if_vc_empty", AsyncMock())),
            "auto_start": stack.enter_context(patch("services.recording_service.maybe_auto_start", AsyncMock())),
            "maybe_start_for_channel": stack.enter_context(
                patch("services.recording_service.maybe_start_for_channel", AsyncMock())
            ),
            "auto_join": stack.enter_context(patch("services.tts_service.auto_join", AsyncMock())),
            "has_temp": stack.enter_context(patch("services.tts_service.has_temp_override", return_value=False)),
            "get_tts_settings": stack.enter_context(
                patch("services.tts_store.get_tts_settings", return_value=tts_settings or {})
            ),
            "disconnect": stack.enter_context(patch("services.tts_service.disconnect", AsyncMock())),
        }
        self.addCleanup(stack.close)
        return mocks

    def test_guild_none_skips_everything(self):
        member = SimpleNamespace(guild=None, bot=False)
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=None)
        mocks = self._patch_all()
        _run(self.handler(member, before, after))
        mocks["tts_announce"].assert_not_called()
        mocks["security"].assert_not_called()
        mocks["log_transition"].assert_not_called()

    def test_a_bot_member_only_gets_the_tts_announcement(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=True, id=2)
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=SimpleNamespace(id=5, name="c"))
        mocks = self._patch_all()
        _run(self.handler(member, before, after))
        mocks["tts_announce"].assert_called_once_with(self.bot, member, before, after)
        mocks["security"].assert_not_called()
        mocks["log_transition"].assert_not_called()
        mocks["persist_transition"].assert_not_called()
        mocks["notify"].assert_not_called()
        mocks["stop_recording"].assert_not_called()

    def test_a_human_join_runs_security_logging_persistence_notify_and_auto_recording(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        after_ch = SimpleNamespace(id=5, name="c")
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=after_ch)
        mocks = self._patch_all()
        _run(self.handler(member, before, after))
        mocks["security"].assert_called_once_with(self.bot, member, before, after)
        mocks["log_transition"].assert_called_once()
        self.assertTrue(mocks["log_transition"].call_args.args[2])  # is_join
        mocks["persist_transition"].assert_called_once()
        mocks["notify"].assert_called_once()
        mocks["auto_start"].assert_called_once_with(self.bot, member, after_ch)
        # before_ch=None なので毎回呼ばれるが、中では即 no-op になる（専用テストで確認済み）
        mocks["stop_recording"].assert_called_once_with(self.bot, guild, None)

    def test_a_human_leave_that_empties_the_watched_channel_disconnects_tts(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        before_ch = SimpleNamespace(id=5, name="c", members=[])
        before = SimpleNamespace(channel=before_ch)
        after = SimpleNamespace(channel=None)
        mocks = self._patch_all()
        with patch.object(voice, "_tts_vc_became_empty", return_value=True):
            _run(self.handler(member, before, after))
        mocks["disconnect"].assert_called_once_with(1)
        mocks["auto_start"].assert_not_called()  # 参加ではないので自動録音の開始は無い

    def test_a_human_leave_that_does_not_empty_the_channel_does_not_disconnect_tts(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        before_ch = SimpleNamespace(id=5, name="c", members=[SimpleNamespace(bot=False)])
        before = SimpleNamespace(channel=before_ch)
        after = SimpleNamespace(channel=None)
        mocks = self._patch_all()
        with patch.object(voice, "_tts_vc_became_empty", return_value=False):
            _run(self.handler(member, before, after))
        mocks["disconnect"].assert_not_called()

    def test_tts_auto_join_and_recording_trigger_on_the_configured_vc(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        after_ch = SimpleNamespace(id=5, name="c")
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=after_ch)
        mocks = self._patch_all(tts_settings={"enabled": True, "vc_channel_id": 5})
        _run(self.handler(member, before, after))
        mocks["auto_join"].assert_called_once_with(guild, 5)
        mocks["maybe_start_for_channel"].assert_called_once_with(self.bot, guild, after_ch, trigger="TTS参加")

    def test_tts_auto_join_is_skipped_during_a_temporary_override(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        after_ch = SimpleNamespace(id=5, name="c")
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=after_ch)
        mocks = self._patch_all(tts_settings={"enabled": True, "vc_channel_id": 5})
        mocks["has_temp"].return_value = True
        _run(self.handler(member, before, after))
        mocks["auto_join"].assert_not_called()

    def test_tts_auto_join_is_skipped_when_the_configured_vc_does_not_match(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        after_ch = SimpleNamespace(id=5, name="c")
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=after_ch)
        mocks = self._patch_all(tts_settings={"enabled": True, "vc_channel_id": 999})
        _run(self.handler(member, before, after))
        mocks["auto_join"].assert_not_called()

    def test_tts_auto_join_exception_is_logged_and_does_not_propagate(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        after_ch = SimpleNamespace(id=5, name="c")
        before = SimpleNamespace(channel=None)
        after = SimpleNamespace(channel=after_ch)
        mocks = self._patch_all()
        mocks["get_tts_settings"].side_effect = RuntimeError("boom")
        with self.assertLogs(voice.logger, level="ERROR") as cm:
            _run(self.handler(member, before, after))  # 例外が外へ出ないことも確認
        self.assertTrue(any("TTS auto_join error" in line for line in cm.output))

    def test_tts_auto_leave_exception_is_logged_and_does_not_propagate(self):
        guild = SimpleNamespace(id=1)
        member = SimpleNamespace(guild=guild, bot=False, id=2)
        before_ch = SimpleNamespace(id=5, name="c", members=[])
        before = SimpleNamespace(channel=before_ch)
        after = SimpleNamespace(channel=None)
        self._patch_all()
        with (
            patch.object(voice, "_tts_vc_became_empty", side_effect=RuntimeError("boom")),
            self.assertLogs(voice.logger, level="ERROR") as cm,
        ):
            _run(self.handler(member, before, after))  # 例外が外へ出ないことも確認
        self.assertTrue(any("TTS auto_leave error" in line for line in cm.output))


class OnVoiceStateUpdateOrderAndStateTests(unittest.TestCase):
    """on_voice_state_update の呼び出し順と、呼び出しをまたぐ状態を固定する。

    118行ある events/voice.py の register を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    上の OnVoiceStateUpdateContractTests は「どれが呼ばれ、どれが呼ばれないか」
    を見ているが、次の3つは崩しても全部通る。原文の docstring が
    「入れ替えると壊れる」と名指ししているのに、誰も見ていなかったところ。

      1. 録音の自動停止が、TTS の切断より**先**に走ること
      2. before.channel / after.channel を1回だけ読むこと
      3. 入室時刻とメンション時刻が、呼び出しをまたいで残ること

    1 を入れ替えると、VC が空になったとき **録音が途中で切れて終わる。**
    3 が崩れると在室時間が常に 0 になり、ロールメンションの10分抑止も
    毎回リセットされて連投になる。どちらも例外は出ない。
    """

    def setUp(self):
        self.bot = _FakeBot()
        voice.register(self.bot)
        self.handler = self.bot.on_voice_state_update

    def _member(self, guild_id=1):
        return SimpleNamespace(guild=SimpleNamespace(id=guild_id), bot=False, id=2)

    def _patched(self, stack, **extra):
        """配線先をすべて差し替える。中身は個別のテストクラスで確認済み。"""
        mocks = {
            "tts_announce": stack.enter_context(patch.object(voice, "_tts_vc_announce", AsyncMock())),
            "security": stack.enter_context(patch.object(voice, "handle_security_for_voice_join", AsyncMock())),
            "log_transition": stack.enter_context(patch.object(voice, "_log_vc_transition", AsyncMock())),
            "persist_transition": stack.enter_context(patch.object(voice, "_persist_vc_transition", AsyncMock())),
            "notify": stack.enter_context(patch.object(voice, "_vc_notify_handler", AsyncMock())),
            "auto_start": stack.enter_context(patch("services.recording_service.maybe_auto_start", AsyncMock())),
            "maybe_start_for_channel": stack.enter_context(
                patch("services.recording_service.maybe_start_for_channel", AsyncMock())
            ),
            "auto_join": stack.enter_context(patch("services.tts_service.auto_join", AsyncMock())),
            "has_temp": stack.enter_context(patch("services.tts_service.has_temp_override", return_value=False)),
            "get_tts_settings": stack.enter_context(patch("services.tts_store.get_tts_settings", return_value={})),
        }
        mocks.update(extra)
        return mocks

    def test_the_recording_is_stopped_before_tts_disconnects(self):
        """録音の自動停止が、TTS の切断より先に走ること。

        逆にすると、VC が空になったときに先に切断が起きる。**録音は
        途中で終わり、そこまでの音だけが書き出される。** 例外は出ないし、
        呼ばれた回数はどちらの順でも同じなので、順序を見るしかない。
        """
        order: list[str] = []

        async def stop_recording(*a, **k):
            """録音の自動停止の代わり。"""
            order.append("stop_recording")

        async def disconnect(*a, **k):
            """TTS 切断の代わり。"""
            order.append("disconnect")

        member = self._member()
        before_ch = SimpleNamespace(id=5, name="c", members=[])
        before = SimpleNamespace(channel=before_ch)
        after = SimpleNamespace(channel=None)
        with ExitStack() as stack:
            self._patched(
                stack,
                stop_recording=stack.enter_context(patch.object(voice, "_stop_recording_if_vc_empty", stop_recording)),
                disconnect=stack.enter_context(patch("services.tts_service.disconnect", disconnect)),
            )
            stack.enter_context(patch.object(voice, "_tts_vc_became_empty", return_value=True))
            _run(self.handler(member, before, after))

        self.assertEqual(order, ["stop_recording", "disconnect"])

    def test_the_channel_properties_are_read_only_once(self):
        """before.channel / after.channel を読み直さないこと。

        discord.py の VoiceState.channel はプロパティで、読み直すと None に
        化けることがある（原文のコメント参照）。**化けるのは実運用の一部の
        場面だけ**なので、読み直しが増えてもテストは緑のまま通る。
        """
        counts = {"before": 0, "after": 0}

        class CountingState:
            """channel を読まれた回数を数える VoiceState の代わり。"""

            def __init__(self, key, channel):
                """どちらの側かと、返すチャンネルを控える。"""
                self._key = key
                self._channel = channel

            @property
            def channel(self):
                """読まれた回数を数えてから返す。"""
                counts[self._key] += 1
                return self._channel

        member = self._member()
        before = CountingState("before", None)
        after = CountingState("after", SimpleNamespace(id=5, name="c"))
        with ExitStack() as stack:
            self._patched(
                stack,
                stop_recording=stack.enter_context(patch.object(voice, "_stop_recording_if_vc_empty", AsyncMock())),
                disconnect=stack.enter_context(patch("services.tts_service.disconnect", AsyncMock())),
            )
            _run(self.handler(member, before, after))

        self.assertEqual(counts, {"before": 1, "after": 1})

    def test_the_join_time_survives_between_calls(self):
        """入室時刻が次の呼び出しまで残り、在室時間になること。

        入室時刻を持つ辞書を呼び出しごとに作り直すと、退出時に引ける
        入室時刻が無くなり、**在室時間は常に 0 になる。** ログには
        「0分」と出るだけで、誰も落ちない。
        """
        member = self._member()
        channel = SimpleNamespace(id=5, name="c", members=[])
        clock = iter([1_700_000_000.0, 1_700_000_090.0])
        with ExitStack() as stack:
            mocks = self._patched(
                stack,
                stop_recording=stack.enter_context(patch.object(voice, "_stop_recording_if_vc_empty", AsyncMock())),
                disconnect=stack.enter_context(patch("services.tts_service.disconnect", AsyncMock())),
            )
            stack.enter_context(patch.object(voice.time, "time", lambda: next(clock)))
            _run(self.handler(member, SimpleNamespace(channel=None), SimpleNamespace(channel=channel)))
            _run(self.handler(member, SimpleNamespace(channel=channel), SimpleNamespace(channel=None)))

        # _persist_vc_transition(member, is_join, is_leave, is_move, before_ch,
        #                        after_ch, duration_seconds, duration_str)
        self.assertEqual(mocks["persist_transition"].call_args.args[6], 90)

    def test_the_mention_throttle_state_survives_between_calls(self):
        """メンションの抑止に使う辞書が、呼び出しごとに作り直されないこと。

        作り直すと10分の抑止が毎回リセットされ、入室のたびにロールメンション
        が飛ぶ。**荒らしに見える挙動になるが、例外は出ない。**
        """
        member = self._member()
        after_ch = SimpleNamespace(id=5, name="c")
        with ExitStack() as stack:
            mocks = self._patched(
                stack,
                stop_recording=stack.enter_context(patch.object(voice, "_stop_recording_if_vc_empty", AsyncMock())),
                disconnect=stack.enter_context(patch("services.tts_service.disconnect", AsyncMock())),
            )
            _run(self.handler(member, SimpleNamespace(channel=None), SimpleNamespace(channel=after_ch)))
            first = mocks["notify"].call_args.args[8]
            _run(self.handler(member, SimpleNamespace(channel=None), SimpleNamespace(channel=after_ch)))
            second = mocks["notify"].call_args.args[8]

        self.assertIs(first, second, "呼び出しごとに作り直されている")


if __name__ == "__main__":
    unittest.main()
