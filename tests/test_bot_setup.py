"""bot_setup.py の分割前の振る舞いを固定するテスト。

    python -m unittest discover -s tests -t .

setup_events(bot) は 1,210 行の単一関数で、テストが1行も無かった。events/
パッケージへ分割する前に「今なにが保証されているか」をここへ書き下し、分割の
前後で同じ集合が観測できることを安全網にする。

分割後の唯一の差分: _safe() は bot_setup.py 直下から events/_util.py へ
移した（bot_setup.py が events/*.py を import し、それらが _safe を
bot_setup から import し返すと循環 import になるため）。実体・挙動は
1文字も変えていないので、SafeWrapperTests は import 元とロガー名だけを
移動先に合わせてある。

観測できるものだけを固定する方針:
- discord.py の @bot.event は Client.event() が
  setattr(self, coro.__name__, coro) でインスタンス属性を直接書き換える実装
  なので、vars(bot) に現れる "on_" 始まりのキー集合が「実際に登録された
  イベントハンドラ名」そのものになる（bot.extra_events は @bot.listen() 用で
  @bot.event では更新されないため使えない）。
- 背景タスク（tasks.loop）は setup_events の時点ではただ定義されるだけで
  start() されない。discord.ext.tasks.Loop.start をパッチして直接見る。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# services/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# bot_setup（経由で services）の import より前に一時ディレクトリへ差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="bot-setup-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="bot-setup-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bot_setup import create_bot, setup_events  # noqa: E402
from events._util import _safe  # noqa: E402

# setup_events(bot) が @bot.event で登録するはずのイベントハンドラ名。
# 現状の setup_events 内を数えると 12 個ちょうど（背景タスクは @tasks.loop
# デコレータなのでここには含まれない）。
EXPECTED_EVENT_NAMES = {
    "on_ready",
    "on_message",
    "on_message_delete",
    "on_message_edit",
    "on_voice_state_update",
    "on_member_join",
    "on_member_remove",
    "on_member_update",
    "on_member_ban",
    "on_member_unban",
    "on_raw_reaction_add",
    "on_raw_reaction_remove",
}


class CreateBotTests(unittest.TestCase):
    def test_intents_enable_what_the_handlers_need(self):
        """on_message や on_voice_state_update などが読む intents が立っていること。"""
        bot = create_bot()
        self.assertTrue(bot.intents.message_content)
        self.assertTrue(bot.intents.members)
        self.assertTrue(bot.intents.voice_states)
        self.assertTrue(bot.intents.moderation)
        self.assertTrue(bot.intents.reactions)

    def test_command_prefix_is_bang(self):
        bot = create_bot()
        self.assertEqual(bot.command_prefix, "!")

    def test_returns_a_fresh_bot_each_time(self):
        """複数回呼んでも同じインスタンスを使い回さないこと（テスト間の汚染防止の前提）。"""
        self.assertIsNot(create_bot(), create_bot())


class SetupEventsRegistrationTests(unittest.TestCase):
    """setup_events(bot) が実際に何を bot へ書き込むかを固定する。

    ここが events/ への分割の安全網。分割の前後でこのテストが同じ集合を
    見続けることを、分割を始める前と終えた後の両方で確認する。
    """

    def test_registers_exactly_the_expected_event_handlers(self):
        bot = create_bot()
        before = {k for k in vars(bot) if k.startswith("on_")}
        self.assertEqual(before, set(), "登録前から on_* 属性が生えている前提が崩れている")

        setup_events(bot)

        after = {k for k in vars(bot) if k.startswith("on_")}
        self.assertEqual(after, EXPECTED_EVENT_NAMES)

    def test_background_tasks_are_not_started_by_setup_events(self):
        """tasks.loop の4本（ステータス/ニュース/スティッキー/シグナル監視）は
        on_ready が来るまで動き始めてはいけない（起動直後に多重で走ると
        レート制限や API 二重叩きにつながる）。Loop.start をパッチして直接見る。
        """
        bot = create_bot()
        with patch("discord.ext.tasks.Loop.start") as start_mock:
            setup_events(bot)
        start_mock.assert_not_called()


class SafeWrapperTests(unittest.TestCase):
    """_safe(coro, name) が「本筋を止めない」の実体を保証する。"""

    def test_success_runs_the_coroutine_without_side_effects(self):
        calls = []

        async def ok():
            calls.append("ran")

        asyncio.run(_safe(ok(), "ok_task"))
        self.assertEqual(calls, ["ran"])

    def test_exception_is_swallowed_and_logged(self):
        async def boom():
            raise RuntimeError("kaboom")

        with self.assertLogs("events._util", level="ERROR") as cm:
            asyncio.run(_safe(boom(), "boom_task"))

        self.assertTrue(
            any("boom_task" in line and "kaboom" in line for line in cm.output),
            cm.output,
        )


if __name__ == "__main__":
    unittest.main()
