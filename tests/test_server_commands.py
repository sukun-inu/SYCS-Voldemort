"""commands/server_commands.py のテスト。

    python -m unittest tests.test_server_commands -v

register_server_commands() は 456行・循環的複雑度75の巨大関数で、ほぼ未検証
だった（371行中264行が未実行）。特に「【管理者】」と明記されたサブコマンドに
実際に権限ガードが掛かっているかは、一般ユーザーがサーバー設定を書き換え
られてしまうかどうかに直結するため最優先で確かめる。

test_commands.py と同じ方針: Discord へは繋がず、Interaction を最小限の
Mock/SimpleNamespace で用意し、呼び出しの順序・引数・応答内容だけを見る。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="server-commands-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="server-commands-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402
from config import JST  # noqa: E402


def make_interaction(*, administrator: bool = True, guild: bool = True):
    """応答の呼ばれ方（defer / send_message / followup.send / edit_message）を記録する Interaction。"""
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
            "namespace",
        ]
    )
    interaction.guild = Mock(id=999) if guild else None
    interaction.guild_id = 999 if guild else None
    interaction.user = Mock(id=1, display_name="tester")
    interaction.user.guild_permissions = Mock(administrator=administrator)
    interaction.client = Mock()
    interaction.channel = Mock(mention="#general")
    interaction.namespace = Mock()

    done = {"value": False}
    response = Mock()
    response.is_done = Mock(side_effect=lambda: done["value"])

    async def _defer(*a, **k):
        calls.append("defer")
        done["value"] = True

    async def _send(*a, **k):
        calls.append("response.send_message")
        done["value"] = True

    async def _edit(*a, **k):
        calls.append("response.edit_message")

    response.defer = _defer
    response.send_message = _send
    response.edit_message = _edit
    interaction.response = response

    async def _followup(*a, **k):
        calls.append("followup.send")

    interaction.followup = Mock()
    interaction.followup.send = _followup
    return interaction, calls


def _register():
    """register_server_commands() を実行し、qualified name → callback の対応表を作る。

    test_commands.py の FakeGroup は name だけで平坦に登録するため、
    welcome/goodbye/quake の "channel" のように同名サブコマンドが複数ある
    ここでは後勝ちで潰れてしまう。親を辿って "greeting welcome channel" の
    ような完全な名前を組み立て、衝突を避ける。

    commands/server_commands.py が commands/server/ 配下のトピック別モジュール
    (welcome_goodbye.py 等) へ分割されたことで、ここではもう1つの sc モジュール
    に全設定関数がぶら下がっているわけではない。app_commands.Group は discord.py
    側のシングルトンモジュール属性なので、ここで1回パッチすれば分割後も
    全トピックのモジュールへ効く。設定関数側の patch.object は、各テストクラスの
    setUp が担当トピックのモジュールを個別に import して行う。
    """
    import commands.server_commands as sc

    registry: dict[str, object] = {}
    autocomplete_registry: dict[tuple[str, str], object] = {}

    class FakeGroup:
        def __init__(self, *, name, parent=None, **_kwargs):
            self.name = name
            self.parent = parent

        def _qualname(self, name):
            parts = [name]
            node = self
            while node is not None:
                parts.insert(0, node.name)
                node = node.parent
            return " ".join(parts)

        def command(self, *, name, description=""):
            qualname = self._qualname(name)

            def wrap(fn):
                def autocomplete(param_name):
                    def deco(g):
                        autocomplete_registry[(qualname, param_name)] = g
                        return g

                    return deco

                fn.autocomplete = autocomplete
                registry[qualname] = fn
                return fn

            return wrap

        def add_command(self, *a, **k):
            pass

    with patch.object(discord.app_commands, "Group", FakeGroup):
        sc.register_server_commands(Mock())
    return registry, autocomplete_registry


class WelcomeGoodbyeAdminGuardTests(unittest.TestCase):
    """welcome/goodbye の channel・message は【管理者】限定。"""

    def setUp(self):
        import commands.server.welcome_goodbye as sc

        self.sc = sc
        self.registry, _ = _register()

    def test_welcome_channel_refuses_non_admin_and_does_not_write(self):
        interaction, calls = make_interaction(administrator=False)
        channel = Mock(id=111, mention="#w")
        with patch.object(self.sc, "set_welcome_channel") as setter:
            asyncio.run(self.registry["greeting welcome channel"](interaction, channel))
        setter.assert_not_called()
        self.assertTrue(calls, "何も返していない")

    def test_welcome_channel_admin_writes_correct_key_and_args(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=111, mention="#w")
        with patch.object(self.sc, "set_welcome_channel") as setter:
            asyncio.run(self.registry["greeting welcome channel"](interaction, channel))
        setter.assert_called_once_with(999, 111)
        self.assertEqual(calls, ["response.send_message"])

    def test_welcome_message_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "set_welcome_message") as setter:
            asyncio.run(self.registry["greeting welcome message"](interaction, "こんにちは"))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_welcome_message_admin_writes(self):
        interaction, calls = make_interaction(administrator=True)
        with patch.object(self.sc, "set_welcome_message") as setter:
            asyncio.run(self.registry["greeting welcome message"](interaction, "こんにちは {user}"))
        setter.assert_called_once_with(999, "こんにちは {user}")

    def test_goodbye_channel_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        channel = Mock(id=222, mention="#g")
        with patch.object(self.sc, "set_goodbye_channel") as setter:
            asyncio.run(self.registry["greeting goodbye channel"](interaction, channel))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_goodbye_channel_admin_writes(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=222, mention="#g")
        with patch.object(self.sc, "set_goodbye_channel") as setter:
            asyncio.run(self.registry["greeting goodbye channel"](interaction, channel))
        setter.assert_called_once_with(999, 222)

    def test_goodbye_message_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "set_goodbye_message") as setter:
            asyncio.run(self.registry["greeting goodbye message"](interaction, "さらば"))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_goodbye_message_admin_writes(self):
        interaction, calls = make_interaction(administrator=True)
        with patch.object(self.sc, "set_goodbye_message") as setter:
            asyncio.run(self.registry["greeting goodbye message"](interaction, "さらば {user}"))
        setter.assert_called_once_with(999, "さらば {user}")

    def test_greeting_status_refuses_outside_guild(self):
        """管理者権限は不要だが、ギルド外では拒否すること。"""
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.sc, "get_welcome_settings") as getter:
            asyncio.run(self.registry["greeting status"](interaction))
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_greeting_status_shows_settings_and_is_ephemeral(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(*a, **k):
            sent.update(k)

        interaction.response.send_message = fake_send
        with (
            patch.object(self.sc, "get_welcome_settings", Mock(return_value={"channel_id": 1, "message": "hi"})),
            patch.object(self.sc, "get_goodbye_settings", Mock(return_value={"channel_id": None, "message": None})),
        ):
            asyncio.run(self.registry["greeting status"](interaction))
        self.assertTrue(sent.get("ephemeral"))
        embed = sent["embed"]
        w_ch = next(f for f in embed.fields if f.name == "ウェルカムチャンネル")
        self.assertEqual(w_ch.value, "<#1>")
        g_ch = next(f for f in embed.fields if f.name == "グッバイチャンネル")
        self.assertEqual(g_ch.value, "未設定")


class VcNotifyAdminGuardTests(unittest.TestCase):
    """vcnotify set/clear は【管理者】限定。"""

    def setUp(self):
        import commands.server.vcnotify as sc

        self.sc = sc
        self.registry, _ = _register()

    def test_set_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        channel = Mock(id=333, mention="#vc")
        with patch.object(self.sc, "set_vc_notify_channel_id") as setter:
            asyncio.run(self.registry["vcnotify set"](interaction, channel))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_set_admin_writes(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=333, mention="#vc")
        with patch.object(self.sc, "set_vc_notify_channel_id") as setter:
            asyncio.run(self.registry["vcnotify set"](interaction, channel))
        setter.assert_called_once_with(999, 333)

    def test_clear_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "set_vc_notify_channel_id") as setter:
            asyncio.run(self.registry["vcnotify clear"](interaction))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_clear_admin_writes_none(self):
        interaction, calls = make_interaction(administrator=True)
        with patch.object(self.sc, "set_vc_notify_channel_id") as setter:
            asyncio.run(self.registry["vcnotify clear"](interaction))
        setter.assert_called_once_with(999, None)


class StickyAdminGuardTests(unittest.TestCase):
    """sticky set/clear は【管理者】限定。list は誰でも見られるがギルド必須。"""

    def setUp(self):
        import commands.server.sticky as sc

        self.sc = sc
        self.registry, _ = _register()

    def test_set_refuses_non_admin_without_touching_settings(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "set_sticky_message") as setter:
            asyncio.run(self.registry["sticky set"](interaction, "内容"))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_set_refuses_non_text_channel(self):
        interaction, calls = make_interaction(administrator=True)
        interaction.channel = Mock(spec=discord.VoiceChannel)
        with patch.object(self.sc, "set_sticky_message") as setter:
            asyncio.run(self.registry["sticky set"](interaction, "内容"))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_set_admin_writes_and_replaces_escaped_newline(self):
        interaction, calls = make_interaction(administrator=True)
        interaction.channel = Mock(spec=discord.TextChannel, id=555)
        with (
            patch.object(self.sc, "set_sticky_message") as setter,
            patch.object(self.sc, "post_sticky", AsyncMock()) as post,
        ):
            asyncio.run(self.registry["sticky set"](interaction, "1行目\\n2行目"))
        setter.assert_called_once_with(999, 555, "1行目\n2行目")
        post.assert_called_once_with(interaction.channel, 999)

    def test_clear_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "delete_sticky", AsyncMock()) as deleter:
            asyncio.run(self.registry["sticky clear"](interaction))
        deleter.assert_not_called()
        self.assertTrue(calls)

    def test_clear_refuses_non_text_channel(self):
        interaction, calls = make_interaction(administrator=True)
        interaction.channel = Mock(spec=discord.VoiceChannel)
        with patch.object(self.sc, "delete_sticky", AsyncMock()) as deleter:
            asyncio.run(self.registry["sticky clear"](interaction))
        deleter.assert_not_called()
        self.assertTrue(calls)

    def test_clear_admin_calls_delete_sticky(self):
        interaction, calls = make_interaction(administrator=True)
        interaction.channel = Mock(spec=discord.TextChannel, id=555)
        with patch.object(self.sc, "delete_sticky", AsyncMock()) as deleter:
            asyncio.run(self.registry["sticky clear"](interaction))
        deleter.assert_called_once_with(interaction.channel, 999)

    def test_list_refuses_outside_guild(self):
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.sc, "get_sticky_messages") as getter:
            asyncio.run(self.registry["sticky list"](interaction))
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_list_shows_entries_ephemerally(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(*a, **k):
            sent["content"] = a[0] if a else k.get("content")
            sent["ephemeral"] = k.get("ephemeral")

        interaction.response.send_message = fake_send
        with patch.object(self.sc, "get_sticky_messages", Mock(return_value={555: {"content": "内容"}})):
            asyncio.run(self.registry["sticky list"](interaction))
        self.assertTrue(sent["ephemeral"])
        self.assertIn("<#555>", sent["content"])

    def test_list_reports_when_nothing_is_set(self):
        interaction, calls = make_interaction()
        with patch.object(self.sc, "get_sticky_messages", Mock(return_value={})):
            asyncio.run(self.registry["sticky list"](interaction))
        self.assertEqual(calls, ["response.send_message"])


class ReactionRoleAdminGuardTests(unittest.TestCase):
    """reactionrole add/remove は【管理者】限定。引数検証も併せて確認する。"""

    def setUp(self):
        import commands.server.reactionrole as sc

        self.sc = sc
        self.registry, self.autocomplete = _register()

    def test_add_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        role = Mock(id=1, mention="@role")
        with patch.object(self.sc, "add_reaction_role") as setter:
            asyncio.run(self.registry["reactionrole add"](interaction, "123", "😀", role))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_add_rejects_non_numeric_message_id_without_writing(self):
        interaction, calls = make_interaction(administrator=True)
        role = Mock(id=1, mention="@role")
        with patch.object(self.sc, "add_reaction_role") as setter:
            asyncio.run(self.registry["reactionrole add"](interaction, "not-a-number", "😀", role))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_add_admin_writes_parsed_id_and_stripped_emoji(self):
        interaction, calls = make_interaction(administrator=True)
        role = Mock(id=77, mention="@role")
        with patch.object(self.sc, "add_reaction_role") as setter:
            asyncio.run(self.registry["reactionrole add"](interaction, "123", " 😀 ", role))
        setter.assert_called_once_with(999, 123, "😀", 77)

    def test_remove_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "remove_reaction_role") as remover:
            asyncio.run(self.registry["reactionrole remove"](interaction, "123", "😀"))
        remover.assert_not_called()
        self.assertTrue(calls)

    def test_remove_rejects_non_numeric_message_id(self):
        interaction, calls = make_interaction(administrator=True)
        with patch.object(self.sc, "remove_reaction_role") as remover:
            asyncio.run(self.registry["reactionrole remove"](interaction, "abc", "😀"))
        remover.assert_not_called()
        self.assertTrue(calls)

    def test_remove_admin_found_reports_success(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(content, **k):
            sent["content"] = content

        interaction.response.send_message = fake_send
        with patch.object(self.sc, "remove_reaction_role", Mock(return_value=True)) as remover:
            asyncio.run(self.registry["reactionrole remove"](interaction, "123", "😀"))
        remover.assert_called_once_with(999, 123, "😀")
        self.assertIn("取り除いた", sent["content"])

    def test_remove_admin_not_found_reports_failure(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(content, **k):
            sent["content"] = content

        interaction.response.send_message = fake_send
        with patch.object(self.sc, "remove_reaction_role", Mock(return_value=False)):
            asyncio.run(self.registry["reactionrole remove"](interaction, "123", "😀"))
        self.assertIn("見つからなかった", sent["content"])

    def test_list_refuses_outside_guild(self):
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.sc, "get_reaction_roles") as getter:
            asyncio.run(self.registry["reactionrole list"](interaction))
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_message_id_autocomplete_filters_by_current_input(self):
        interaction, _ = make_interaction()
        fn = self.autocomplete[("reactionrole remove", "message_id")]
        with patch.object(self.sc, "get_reaction_roles", Mock(return_value={"123": {"😀": 1}, "456": {"😀": 1}})):
            choices = asyncio.run(fn(interaction, "12"))
        self.assertEqual([c.value for c in choices], ["123"])

    def test_message_id_autocomplete_empty_outside_guild(self):
        interaction, _ = make_interaction(guild=False)
        fn = self.autocomplete[("reactionrole remove", "message_id")]
        choices = asyncio.run(fn(interaction, ""))
        self.assertEqual(choices, [])

    def test_emoji_autocomplete_empty_outside_guild(self):
        interaction, _ = make_interaction(guild=False)
        fn = self.autocomplete[("reactionrole remove", "emoji")]
        choices = asyncio.run(fn(interaction, ""))
        self.assertEqual(choices, [])

    def test_emoji_autocomplete_filters_within_the_selected_message(self):
        interaction, _ = make_interaction()
        interaction.namespace = SimpleNamespace(message_id="123")
        interaction.guild.get_role = Mock(return_value=Mock(name="role", id=1))
        fn = self.autocomplete[("reactionrole remove", "emoji")]
        rr = {"123": {"😀": 1, "😢": 2}, "456": {"🎉": 3}}
        with patch.object(self.sc, "get_reaction_roles", Mock(return_value=rr)):
            choices = asyncio.run(fn(interaction, "😀"))
        self.assertEqual([c.value for c in choices], ["😀"])

    def test_emoji_autocomplete_lists_all_messages_when_none_selected(self):
        interaction, _ = make_interaction()
        interaction.namespace = SimpleNamespace(message_id="")
        interaction.guild.get_role = Mock(return_value=None)
        fn = self.autocomplete[("reactionrole remove", "emoji")]
        rr = {"123": {"😀": 1}, "456": {"🎉": 3}}
        with patch.object(self.sc, "get_reaction_roles", Mock(return_value=rr)):
            choices = asyncio.run(fn(interaction, ""))
        self.assertEqual({c.value for c in choices}, {"😀", "🎉"})

    def test_list_reports_when_nothing_is_set(self):
        interaction, calls = make_interaction()
        with patch.object(self.sc, "get_reaction_roles", Mock(return_value={})):
            asyncio.run(self.registry["reactionrole list"](interaction))
        self.assertEqual(calls, ["response.send_message"])

    def test_list_shows_entries(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(content, **k):
            sent["content"] = content

        interaction.response.send_message = fake_send
        with patch.object(self.sc, "get_reaction_roles", Mock(return_value={"123": {"😀": 1}})):
            asyncio.run(self.registry["reactionrole list"](interaction))
        self.assertIn("123", sent["content"])


class NewsFeedAdminGuardTests(unittest.TestCase):
    """news add/remove は【管理者】限定。間隔・件数の検証も確認する。"""

    def setUp(self):
        import commands.server.news as sc

        self.sc = sc
        self.registry, self.autocomplete = _register()

    def test_add_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        channel = Mock(id=1, mention="#news")
        with patch.object(self.sc, "add_news_feed") as adder, patch.object(self.sc, "get_news_feeds") as getter:
            asyncio.run(self.registry["news add"](interaction, channel, "AI技術", 60))
        adder.assert_not_called()
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_add_rejects_interval_under_5_minutes(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=1, mention="#news")
        with patch.object(self.sc, "add_news_feed") as adder:
            asyncio.run(self.registry["news add"](interaction, channel, "AI技術", 4))
        adder.assert_not_called()
        self.assertTrue(calls)

    def test_add_rejects_when_already_at_the_limit_of_ten(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=1, mention="#news")
        existing = {str(i): {} for i in range(10)}
        with (
            patch.object(self.sc, "get_news_feeds", Mock(return_value=existing)),
            patch.object(self.sc, "add_news_feed") as adder,
        ):
            asyncio.run(self.registry["news add"](interaction, channel, "AI技術", 60))
        adder.assert_not_called()
        self.assertTrue(calls)

    def test_add_admin_writes_with_generated_feed_id(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=1, mention="#news")
        fake_uuid = Mock()
        fake_uuid.hex = "abcd1234ef567890"
        with (
            patch.object(self.sc, "get_news_feeds", Mock(return_value={})),
            patch.object(self.sc, "add_news_feed") as adder,
            patch.object(self.sc.uuid, "uuid4", Mock(return_value=fake_uuid)),
        ):
            asyncio.run(self.registry["news add"](interaction, channel, "AI技術", 60))
        adder.assert_called_once_with(999, "abcd1234", 1, "AI技術", 60)

    def test_remove_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "remove_news_feed") as remover:
            asyncio.run(self.registry["news remove"](interaction, "abcd1234"))
        remover.assert_not_called()
        self.assertTrue(calls)

    def test_remove_admin_strips_feed_id_and_writes(self):
        interaction, calls = make_interaction(administrator=True)
        with patch.object(self.sc, "remove_news_feed", Mock(return_value=True)) as remover:
            asyncio.run(self.registry["news remove"](interaction, " abcd1234 "))
        remover.assert_called_once_with(999, "abcd1234")

    def test_remove_admin_not_found_reports_failure(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(content, **k):
            sent["content"] = content

        interaction.response.send_message = fake_send
        with patch.object(self.sc, "remove_news_feed", Mock(return_value=False)):
            asyncio.run(self.registry["news remove"](interaction, "abcd1234"))
        self.assertIn("見つからなかった", sent["content"])

    def test_list_refuses_outside_guild(self):
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.sc, "get_news_feeds") as getter:
            asyncio.run(self.registry["news list"](interaction))
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_list_reports_when_nothing_is_registered(self):
        interaction, calls = make_interaction()
        with patch.object(self.sc, "get_news_feeds", Mock(return_value={})):
            asyncio.run(self.registry["news list"](interaction))
        self.assertEqual(calls, ["response.send_message"])

    def test_list_shows_registered_feeds_ephemerally(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(content, **k):
            sent["content"] = content
            sent["ephemeral"] = k.get("ephemeral")

        interaction.response.send_message = fake_send
        feeds = {"abcd1234": {"query": "AI技術", "channel_id": 1, "interval": 60}}
        with patch.object(self.sc, "get_news_feeds", Mock(return_value=feeds)):
            asyncio.run(self.registry["news list"](interaction))
        self.assertTrue(sent["ephemeral"])
        self.assertIn("abcd1234", sent["content"])
        self.assertIn("AI技術", sent["content"])

    def test_feed_id_autocomplete_empty_outside_guild(self):
        interaction, _ = make_interaction(guild=False)
        fn = self.autocomplete[("news remove", "feed_id")]
        choices = asyncio.run(fn(interaction, ""))
        self.assertEqual(choices, [])

    def test_feed_id_autocomplete_filters_by_query_or_id(self):
        interaction, _ = make_interaction()
        interaction.guild.get_channel = Mock(return_value=Mock(name="channel", id=1, __bool__=lambda self: True))
        interaction.guild.get_channel.return_value.name = "news-ch"
        feeds = {
            "abcd1234": {"query": "AI技術", "channel_id": 1},
            "ef567890": {"query": "スポーツ", "channel_id": 1},
        }
        fn = self.autocomplete[("news remove", "feed_id")]
        with patch.object(self.sc, "get_news_feeds", Mock(return_value=feeds)):
            choices = asyncio.run(fn(interaction, "AI"))
        self.assertEqual([c.value for c in choices], ["abcd1234"])

    def test_feed_id_autocomplete_reports_unknown_channel(self):
        interaction, _ = make_interaction()
        interaction.guild.get_channel = Mock(return_value=None)
        feeds = {"abcd1234": {"query": "AI技術", "channel_id": 1}}
        fn = self.autocomplete[("news remove", "feed_id")]
        with patch.object(self.sc, "get_news_feeds", Mock(return_value=feeds)):
            choices = asyncio.run(fn(interaction, ""))
        self.assertIn("不明なチャンネル", choices[0].name)


class QuakeAdminGuardTests(unittest.TestCase):
    """quake channel/min_scale/type は【管理者】限定。status は誰でも見られる。"""

    def setUp(self):
        import commands.server.quake as sc

        self.sc = sc
        self.registry, _ = _register()

    def test_channel_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        channel = Mock(id=1, mention="#eq")
        with patch.object(self.sc, "set_earthquake_channel") as setter:
            asyncio.run(self.registry["quake channel"](interaction, channel))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_channel_admin_writes(self):
        interaction, calls = make_interaction(administrator=True)
        channel = Mock(id=1, mention="#eq")
        with patch.object(self.sc, "set_earthquake_channel") as setter:
            asyncio.run(self.registry["quake channel"](interaction, channel))
        setter.assert_called_once_with(999, 1)

    def test_min_scale_refuses_non_admin(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "set_earthquake_min_scale") as setter:
            asyncio.run(self.registry["quake min_scale"](interaction, 50))
        setter.assert_not_called()
        self.assertTrue(calls)

    def test_min_scale_admin_writes(self):
        interaction, calls = make_interaction(administrator=True)
        with patch.object(self.sc, "set_earthquake_min_scale") as setter:
            asyncio.run(self.registry["quake min_scale"](interaction, 50))
        setter.assert_called_once_with(999, 50)

    def test_type_refuses_non_admin_without_reading_settings(self):
        interaction, calls = make_interaction(administrator=False)
        with patch.object(self.sc, "get_earthquake_notify_types") as getter:
            asyncio.run(self.registry["quake type"](interaction))
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_type_admin_shows_the_toggle_view(self):
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            sent.update(k)

        interaction.response.send_message = fake_send
        with patch.object(self.sc, "get_earthquake_notify_types", Mock(return_value={})):
            asyncio.run(self.registry["quake type"](interaction))
        self.assertTrue(sent.get("ephemeral"))
        self.assertIsInstance(sent["view"], self.sc._NotifyTypeView)

    def test_status_refuses_outside_guild(self):
        interaction, calls = make_interaction(guild=False)
        with patch.object(self.sc, "get_earthquake_settings") as getter:
            asyncio.run(self.registry["quake status"](interaction))
        getter.assert_not_called()
        self.assertTrue(calls)

    def test_status_shows_settings_ephemerally(self):
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(*a, **k):
            sent.update(k)

        interaction.response.send_message = fake_send
        with (
            patch.object(self.sc, "get_earthquake_settings", Mock(return_value={"channel_id": 1, "min_scale": 40})),
            patch.object(self.sc, "get_earthquake_notify_types", Mock(return_value={})),
        ):
            asyncio.run(self.registry["quake status"](interaction))
        self.assertTrue(sent.get("ephemeral"))
        min_scale = next(f for f in sent["embed"].fields if f.name == "最小震度")
        self.assertEqual(min_scale.value, "40")


class InfoCommandsTests(unittest.TestCase):
    """info server/user は管理者権限が不要な代わりに、公開応答（ephemeral 無し）であること。"""

    def setUp(self):
        self.registry, _ = _register()

    def _guild(self):
        role_everyone = SimpleNamespace(is_default=lambda: True)
        role_other = SimpleNamespace(is_default=lambda: False, mention="@other")
        text_ch = Mock(spec=discord.TextChannel)
        voice_ch = Mock(spec=discord.VoiceChannel)
        return SimpleNamespace(
            id=999,
            name="テストサーバー",
            icon=None,
            owner=SimpleNamespace(mention="@owner"),
            member_count=42,
            channels=[text_ch, voice_ch],
            roles=[role_everyone, role_other],
            created_at=datetime(2020, 1, 1, tzinfo=JST),
            premium_tier=1,
            premium_subscription_count=3,
        )

    def test_server_refuses_outside_guild(self):
        interaction, calls = make_interaction(guild=False)
        asyncio.run(self.registry["info server"](interaction))
        self.assertTrue(calls)

    def test_server_reply_is_not_ephemeral(self):
        interaction, calls = make_interaction()
        interaction.guild = self._guild()
        sent = {}

        async def fake_send(*a, **k):
            sent.update(k)

        interaction.response.send_message = fake_send
        asyncio.run(self.registry["info server"](interaction))
        self.assertNotIn("ephemeral", sent)
        member_count = next(f for f in sent["embed"].fields if f.name == "メンバー数")
        self.assertEqual(member_count.value, "42")

    def test_server_sets_the_thumbnail_when_the_guild_has_an_icon(self):
        interaction, calls = make_interaction()
        guild = self._guild()
        guild.icon = SimpleNamespace(url="http://example.invalid/icon.png")
        interaction.guild = guild
        sent = {}

        async def fake_send(*a, **k):
            sent.update(k)

        interaction.response.send_message = fake_send
        asyncio.run(self.registry["info server"](interaction))
        self.assertEqual(sent["embed"].thumbnail.url, "http://example.invalid/icon.png")

    def _member(self, **overrides):
        defaults = dict(
            id=1,
            nick=None,
            bot=False,
            joined_at=datetime(2021, 1, 1, tzinfo=JST),
            created_at=datetime(2020, 1, 1, tzinfo=JST),
            roles=[SimpleNamespace(is_default=lambda: True, mention="@everyone")],
            color=discord.Color.default(),
            display_avatar=SimpleNamespace(url="http://example.invalid/a.png"),
        )
        defaults.update(overrides)
        member = Mock(spec=discord.Member, **defaults)
        member.__str__ = Mock(return_value="tester#0001")
        return member

    def test_user_refuses_outside_guild(self):
        interaction, calls = make_interaction(guild=False)
        asyncio.run(self.registry["info user"](interaction, None))
        self.assertTrue(calls)

    def test_user_defaults_to_the_caller_and_is_not_ephemeral(self):
        interaction, calls = make_interaction()
        interaction.user = self._member(id=1)
        sent = {}

        async def fake_send(*a, **k):
            sent.update(k)

        interaction.response.send_message = fake_send
        asyncio.run(self.registry["info user"](interaction, None))
        self.assertNotIn("ephemeral", sent)
        uid = next(f for f in sent["embed"].fields if f.name == "ユーザーID")
        self.assertEqual(uid.value, "1")

    def test_user_rejects_a_non_member_target(self):
        """member 引数も interaction.user も discord.Member でない場合は取得失敗として扱う。"""
        interaction, calls = make_interaction()
        interaction.user = Mock(spec_set=["id"], id=1)  # discord.Member ではない
        asyncio.run(self.registry["info user"](interaction, None))
        self.assertTrue(calls)


class NotifyTypeViewTests(unittest.TestCase):
    """地震通知タイプ設定ビュー：本人以外の操作を拒否し、保存が正しいキーへ通ること。"""

    def setUp(self):
        import commands.server.quake as sc

        self.sc = sc

    def test_non_author_toggle_is_refused_and_state_is_untouched(self):
        view = self.sc._NotifyTypeView(999, author_id=1, types={"eew_forecast": True})
        interaction, calls = make_interaction()
        interaction.user = Mock(id=2)  # author_id と不一致
        asyncio.run(view.handle_toggle(interaction, "eew_forecast"))
        self.assertTrue(view.types["eew_forecast"])
        self.assertEqual(calls, ["response.send_message"])

    def test_author_toggle_flips_the_value(self):
        view = self.sc._NotifyTypeView(999, author_id=1, types={"eew_forecast": True})
        interaction, calls = make_interaction()
        interaction.user = Mock(id=1)
        asyncio.run(view.handle_toggle(interaction, "eew_forecast"))
        self.assertFalse(view.types["eew_forecast"])
        self.assertEqual(calls, ["response.edit_message"])

    def test_non_author_save_does_not_write_settings(self):
        view = self.sc._NotifyTypeView(999, author_id=1, types={"eew_forecast": True})
        interaction, calls = make_interaction()
        interaction.user = Mock(id=2)
        with patch.object(self.sc, "set_earthquake_notify_types") as setter:
            asyncio.run(view.handle_save(interaction))
        setter.assert_not_called()
        self.assertEqual(calls, ["response.send_message"])

    def test_author_save_writes_the_guild_id_and_current_types(self):
        view = self.sc._NotifyTypeView(999, author_id=1, types={"eew_forecast": False, "tsunami": True})
        interaction, calls = make_interaction()
        interaction.user = Mock(id=1)
        with patch.object(self.sc, "set_earthquake_notify_types") as setter:
            asyncio.run(view.handle_save(interaction))
        setter.assert_called_once_with(999, {"eew_forecast": False, "tsunami": True})
        self.assertEqual(calls, ["response.edit_message"])

    def test_toggle_button_callback_delegates_to_the_view(self):
        """ボタンの callback が self.view.handle_toggle を実際に呼んでいること。"""
        view = self.sc._NotifyTypeView(999, author_id=1, types={"eew_forecast": True})
        toggle_buttons = [c for c in view.children if isinstance(c, self.sc._ToggleButton)]
        self.assertTrue(toggle_buttons, "トグルボタンが生成されていない")
        button = toggle_buttons[0]
        interaction, calls = make_interaction()
        interaction.user = Mock(id=1)
        before = view.types[button.key]
        asyncio.run(button.callback(interaction))
        self.assertNotEqual(before, view.types[button.key])

    def test_save_button_callback_delegates_to_the_view(self):
        view = self.sc._NotifyTypeView(999, author_id=1, types={"eew_forecast": True})
        save_buttons = [c for c in view.children if isinstance(c, self.sc._SaveButton)]
        self.assertTrue(save_buttons, "保存ボタンが生成されていない")
        interaction, calls = make_interaction()
        interaction.user = Mock(id=1)
        with patch.object(self.sc, "set_earthquake_notify_types") as setter:
            asyncio.run(save_buttons[0].callback(interaction))
        setter.assert_called_once()


if __name__ == "__main__":
    unittest.main()
