"""スラッシュコマンドの振る舞い。

    python -m unittest discover -s tests -t .

Discord へは繋がないので、Interaction を差し替えて呼び出しの順序と権限だけを見る。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="commands-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="commands-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402


def make_interaction(*, administrator: bool = True, guild: bool = True):
    """応答の呼ばれ方を記録する Interaction。"""
    calls: list[str] = []
    interaction = Mock(spec_set=[
        "guild", "guild_id", "user", "client", "channel", "response", "followup",
    ])
    interaction.guild = Mock(id=999) if guild else None
    interaction.guild_id = 999 if guild else None
    interaction.user = Mock(id=1, display_name="tester")
    interaction.user.guild_permissions = Mock(administrator=administrator)
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


class MetalDeferTests(unittest.TestCase):
    """外部APIを待つ前に defer すること。

    Discord は最初の応答まで3秒しか待たない。金属価格は外部APIから取るので、
    先に取りに行くと「アプリケーションが応答しませんでした」になる。
    """

    def setUp(self):
        import commands.metal_commands as metal
        from config import METAL_COMMANDS
        self.metal = metal
        self.spec = next(iter(METAL_COMMANDS.values()))

    def test_defer_happens_before_the_price_lookup(self):
        seen = []

        async def slow_price(*args, **kwargs):
            seen.append(list(self.calls))      # 呼ばれた時点の応答状況
            return {"買取価格": 1000}

        interaction, self.calls = make_interaction()
        with patch.object(self.metal, "calculate_metal_value", slow_price), \
             patch.object(self.metal, "log_action", AsyncMock()):
            asyncio.run(self.metal._handle_single_metal(interaction, 1.0, self.spec))

        self.assertTrue(seen, "価格取得が呼ばれていない")
        self.assertIn("defer", seen[0], f"取得前の応答: {seen[0]}")

    def test_the_result_is_sent_after_deferring(self):
        interaction, calls = make_interaction()
        with patch.object(self.metal, "calculate_metal_value",
                          AsyncMock(return_value={"買取価格": 1000})), \
             patch.object(self.metal, "log_action", AsyncMock()):
            asyncio.run(self.metal._handle_single_metal(interaction, 1.0, self.spec))
        # defer 済みなので、結果は followup で送られる
        self.assertEqual(calls, ["defer", "followup.send"], str(calls))

    def test_a_bad_amount_answers_without_calling_the_api(self):
        interaction, calls = make_interaction()
        called = Mock()
        with patch.object(self.metal, "calculate_metal_value", called):
            asyncio.run(self.metal._handle_single_metal(interaction, 0, self.spec))
        called.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    def test_defer_failure_does_not_break_the_command(self):
        """defer 自体が失敗しても、処理は続けられること。"""
        interaction, calls = make_interaction()

        async def boom(*a, **k):
            raise discord.HTTPException(Mock(status=500), "boom")
        interaction.response.defer = boom

        with patch.object(self.metal, "calculate_metal_value",
                          AsyncMock(return_value={"買取価格": 1000})), \
             patch.object(self.metal, "log_action", AsyncMock()), \
             self.assertLogs("commands.metal_commands", level="WARNING"):
            asyncio.run(self.metal._handle_single_metal(interaction, 1.0, self.spec))
        self.assertIn("response.send_message", calls, str(calls))


class AdminGuardTests(unittest.TestCase):
    """ドキュメントで管理者専用としているものに、実際にガードがあること。

    録音の状況は「誰が録音されていて、どれだけ喋ったか」を含む。
    """

    def _tree(self):
        """コマンドを登録して、名前から呼び出せるようにする。"""
        registry = {}

        class FakeGroup:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
            def command(self, *, name, description=""):
                def wrap(fn):
                    registry[name] = fn
                    return fn
                return wrap

        return registry, FakeGroup

    def test_record_status_refuses_non_admins(self):
        import commands.recording_commands as rc
        registry, FakeGroup = self._tree()
        with patch.object(rc.app_commands, "Group", FakeGroup):
            rc.register_recording_commands(Mock())

        interaction, calls = make_interaction(administrator=False)
        with patch.object(rc.recording, "get_session", Mock()) as get_session:
            asyncio.run(registry["status"](interaction))
        get_session.assert_not_called()
        self.assertTrue(calls, "何も返していない")

    def test_record_status_answers_admins(self):
        import commands.recording_commands as rc
        registry, FakeGroup = self._tree()
        with patch.object(rc.app_commands, "Group", FakeGroup):
            rc.register_recording_commands(Mock())

        interaction, calls = make_interaction(administrator=True)
        with patch.object(rc.recording, "get_session", Mock(return_value=None)):
            asyncio.run(registry["status"](interaction))
        self.assertTrue(calls, "何も返していない")

    def test_tts_status_refuses_non_admins(self):
        import commands.tts_commands as tc
        interaction, calls = make_interaction(administrator=False)
        with patch.object(tc, "get_tts_settings", Mock()) as settings:
            asyncio.run(tc.tts_status.callback(interaction))
        settings.assert_not_called()
        self.assertTrue(calls, "何も返していない")


class GuardHelperTests(unittest.TestCase):
    def test_is_admin_is_false_outside_a_guild(self):
        from commands.guards import is_admin
        interaction, _ = make_interaction(guild=False)
        self.assertFalse(is_admin(interaction))

    def test_ensure_admin_explains_why_it_refused(self):
        from commands.guards import ensure_admin
        interaction, calls = make_interaction(administrator=False)
        self.assertFalse(asyncio.run(ensure_admin(interaction)))
        self.assertTrue(calls, "断った理由を返していない")


if __name__ == "__main__":
    unittest.main()


class CommandTreeTests(unittest.TestCase):
    """実際に登録されるコマンドツリーの形。

    名前の付け替えは「そう書いたつもり」では足りない。Discord に載る形と、
    ドキュメントに書いてある形が一致していることを確かめる。
    """

    @classmethod
    def setUpClass(cls):
        import discord
        from discord import app_commands
        from discord.ext import commands as dpy
        from commands import register_all_commands

        bot = dpy.Bot(command_prefix="!", intents=discord.Intents.default())
        register_all_commands(bot)
        cls.app_commands = app_commands
        cls.tree = bot.tree
        cls.top = list(bot.tree.get_commands())
        cls.leaves = {
            c.qualified_name: c
            for c in bot.tree.walk_commands()
            if not isinstance(c, app_commands.Group)
        }

    def test_every_command_lives_under_a_group(self):
        """平坦な名前を並べると、/ の一覧が長くなり関連するものが離れる。"""
        loose = [name for name in self.leaves if " " not in name]
        self.assertEqual(loose, [], f"グループに属していない: {loose}")

    def test_the_command_picker_stays_short(self):
        self.assertLessEqual(len(self.top), 25, f"トップレベル {len(self.top)} 個")

    def test_group_children_stay_within_the_discord_limit(self):
        """Discord はグループの子を 25 個までしか受け付けない。"""
        for cmd in self.top:
            if isinstance(cmd, self.app_commands.Group):
                self.assertLessEqual(len(cmd.commands), 25, f"/{cmd.name}")

    def test_names_are_valid_for_discord(self):
        """英小文字・数字・アンダースコア・ハイフンのみ、32文字まで。"""
        import re
        pattern = re.compile(r"^[a-z0-9_-]{1,32}$")
        for cmd in self.tree.walk_commands():
            self.assertRegex(cmd.name, pattern, f"/{cmd.qualified_name}")

    def test_nothing_is_lost_in_the_rename(self):
        """グループ化で機能が減っていないこと。"""
        self.assertEqual(len(self.leaves), 64, sorted(self.leaves))

    def test_the_docs_list_exactly_what_is_registered(self):
        """ドキュメントと実装のずれは、読んだ人の理解と挙動のずれになる。"""
        import re
        doc = (Path(__file__).resolve().parent.parent
               / "docs" / "COMMANDS.ja.md").read_text(encoding="utf-8")
        # <details> の中は旧名からの対応表。いまのコマンドではないので外す。
        doc = re.sub(r"<details>.*?</details>", "", doc, flags=re.S)

        # `/dict add word` の "word" は引数。コマンド名の切れ目は引数と
        # 区別がつかないので、登録されている名前の側から探しにいく。
        missing = sorted(
            name for name in self.leaves
            if not re.search(rf"`/{re.escape(name)}(?=[ `\[<])", doc)
        )
        self.assertEqual(missing, [], f"実装にあるがドキュメントに無い: {missing}")

        known = {c.qualified_name for c in self.tree.walk_commands()}
        mentioned = re.findall(r"`/([a-z0-9_]+(?: [a-z0-9_]+)*)", doc)
        stale = sorted({
            m for m in mentioned
            if not any(m == k or m.startswith(k + " ") for k in known)
        })
        self.assertEqual(stale, [], f"ドキュメントにあるが実装に無い: {stale}")

    def test_the_help_command_shows_the_full_path(self):
        """/log channel と /quake channel が衝突して消えないこと。"""
        listed = {}
        for cmd in self.tree.walk_commands():
            if isinstance(cmd, self.app_commands.Group):
                continue
            listed[cmd.qualified_name] = cmd.description
        self.assertEqual(len(listed), len(self.leaves))
        self.assertIn("log channel", listed)
        self.assertIn("quake channel", listed)
