"""services/ 層のうち、モデレーション関連5モジュールのテスト。

対象: logging_service / reaction_role_service / content_moderation /
spam_detection / raid_detection

    python -m unittest tests.test_services_moderation -v

Discord とネットワークには一切触らない。discord.py の型は Mock(spec=...) で
差し替え、設定ストアは tests/test_services.py と同じく一時ディレクトリを使う
（このファイル単体で実行されたときのために、ここでも同じ setdefault を行う）。

spam_detection / raid_detection はモジュールグローバルな辞書と経過時間の
カウンタで状態を持つ。時刻は `time` モジュールごと差し替えて固定し、
辞書は setUp/tearDown で退避・復元して他のテストへ状態が漏れないようにする。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="services-moderation-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="services-moderation-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import services.content_moderation as content_moderation  # noqa: E402
import services.logging_service as logging_service  # noqa: E402
import services.raid_detection as raid_detection  # noqa: E402
import services.reaction_role_service as reaction_role_service  # noqa: E402
import services.spam_detection as spam_detection  # noqa: E402


# ──────────────────────────────────────────────
# logging_service
# ──────────────────────────────────────────────


class LogSettingsTests(unittest.TestCase):
    """設定の読み書きと、レベル文字列のバリデーション。"""

    def test_get_log_settings_reads_from_the_store(self):
        """設定ストアの結果が素通りせずに解釈されること（大文字化・キー変換）。"""
        mock_get = Mock(return_value={"log_level": "debug", "log_channel_id": 999})
        with patch.object(logging_service, "get_guild_settings", mock_get):
            settings = logging_service.get_log_settings(1)
        mock_get.assert_called_once_with(1)
        self.assertEqual(settings, {"channel_id": 999, "level": "DEBUG"})

    def test_get_log_settings_defaults_to_info_when_unset(self):
        with patch.object(logging_service, "get_guild_settings", Mock(return_value={})):
            settings = logging_service.get_log_settings(1)
        self.assertEqual(settings["level"], "INFO")
        self.assertIsNone(settings["channel_id"])

    def test_set_log_channel_writes_through_the_store(self):
        mock_update = Mock()
        with patch.object(logging_service, "update_guild_settings", mock_update):
            logging_service.set_log_channel(1, 555)
        mock_update.assert_called_once_with(1, {"log_channel_id": 555})

    def test_set_log_channel_can_clear_the_setting(self):
        mock_update = Mock()
        with patch.object(logging_service, "update_guild_settings", mock_update):
            logging_service.set_log_channel(1, None)
        mock_update.assert_called_once_with(1, {"log_channel_id": None})

    def test_set_log_level_normalizes_case(self):
        mock_update = Mock()
        with patch.object(logging_service, "update_guild_settings", mock_update):
            logging_service.set_log_level(1, "debug")
        mock_update.assert_called_once_with(1, {"log_level": "DEBUG"})

    def test_set_log_level_rejects_unknown_values(self):
        """タイプミスをそのまま保存すると、以後ログが一切出なくなり気付きにくい。"""
        mock_update = Mock()
        with patch.object(logging_service, "update_guild_settings", mock_update):
            with self.assertRaises(ValueError):
                logging_service.set_log_level(1, "VERBOSE")
        mock_update.assert_not_called()


class ShouldLogTests(unittest.TestCase):
    """レベルの優先度比較。境界（同値）を必ず確認する。"""

    def _with_level(self, level: str):
        return patch.object(logging_service, "get_log_settings", Mock(return_value={"level": level}))

    def test_error_always_passes_info_threshold(self):
        with self._with_level("INFO"):
            self.assertTrue(logging_service._should_log(1, "ERROR"))

    def test_debug_is_blocked_by_info_threshold(self):
        with self._with_level("INFO"):
            self.assertFalse(logging_service._should_log(1, "DEBUG"))

    def test_equal_level_passes(self):
        """しきい値ちょうど（同じレベル）は出ること。ここが不等号1つの off-by-one の的。"""
        with self._with_level("ERROR"):
            self.assertTrue(logging_service._should_log(1, "ERROR"))

    def test_none_threshold_blocks_everything_including_error(self):
        with self._with_level("NONE"):
            self.assertFalse(logging_service._should_log(1, "ERROR"))


class LevelColorTests(unittest.TestCase):
    def test_error_is_red(self):
        self.assertEqual(logging_service._level_color("ERROR"), discord.Color.red())

    def test_info_is_blue(self):
        self.assertEqual(logging_service._level_color("INFO"), discord.Color.blue())

    def test_debug_is_dark_grey(self):
        self.assertEqual(logging_service._level_color("DEBUG"), discord.Color.dark_grey())

    def test_unknown_level_falls_back_to_light_grey(self):
        self.assertEqual(logging_service._level_color("NONE"), discord.Color.light_grey())
        self.assertEqual(logging_service._level_color("BOGUS"), discord.Color.light_grey())


class _FakeAvatarResponse:
    def __init__(self, status=200, data=b"binarydata"):
        self.status = status
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def read(self):
        return self._data


class _FakeAvatarSession:
    """logging_service.aiohttp.ClientSession の差し替え先。"""

    response = _FakeAvatarResponse()
    get_calls: list = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, **kwargs):
        type(self).get_calls.append(url)
        return type(self).response


class _FakeColorThief:
    color = (10, 20, 30)

    def __init__(self, fp):
        self.fp = fp

    def get_color(self, quality=10):
        return type(self).color


class _BoomColorThief:
    def __init__(self, fp):
        pass

    def get_color(self, quality=10):
        raise RuntimeError("解析失敗")


class _BoomAvatarAsset:
    @property
    def url(self):
        raise RuntimeError("アバターURL取得失敗")


class UserAvatarColorTests(unittest.TestCase):
    """アバター代表色の抽出。ネットワークにもキャッシュにも複数の分岐がある。"""

    def setUp(self):
        self._orig_cache = dict(logging_service._USER_COLOR_CACHE)
        logging_service._USER_COLOR_CACHE.clear()
        _FakeAvatarSession.get_calls = []

    def tearDown(self):
        logging_service._USER_COLOR_CACHE.clear()
        logging_service._USER_COLOR_CACHE.update(self._orig_cache)

    def _user(self, user_id=1, url="https://example.com/a.png"):
        user = Mock(spec=discord.abc.User)
        user.id = user_id
        user.display_avatar = SimpleNamespace(url=url)
        return user

    def test_no_user_returns_none(self):
        self.assertIsNone(asyncio.run(logging_service._user_avatar_color(None)))

    def test_colorthief_unavailable_returns_none_without_touching_network(self):
        with patch.object(logging_service, "ColorThief", None):
            result = asyncio.run(logging_service._user_avatar_color(self._user()))
        self.assertIsNone(result)
        self.assertEqual(_FakeAvatarSession.get_calls, [])

    def test_cache_hit_skips_the_network(self):
        logging_service._USER_COLOR_CACHE[42] = (10 << 16) + (20 << 8) + 30
        with (
            patch.object(logging_service, "ColorThief", _FakeColorThief),
            patch.object(logging_service.aiohttp, "ClientSession", _FakeAvatarSession),
        ):
            result = asyncio.run(logging_service._user_avatar_color(self._user(user_id=42)))
        self.assertEqual(result, discord.Color.from_rgb(10, 20, 30))
        self.assertEqual(_FakeAvatarSession.get_calls, [])  # キャッシュが効いた証拠

    def test_avatar_url_access_failure_returns_none(self):
        user = Mock(spec=discord.abc.User)
        user.id = 7
        user.display_avatar = _BoomAvatarAsset()
        with patch.object(logging_service, "ColorThief", _FakeColorThief):
            result = asyncio.run(logging_service._user_avatar_color(user))
        self.assertIsNone(result)

    def test_non_200_response_returns_none(self):
        _FakeAvatarSession.response = _FakeAvatarResponse(status=404)
        try:
            with (
                patch.object(logging_service, "ColorThief", _FakeColorThief),
                patch.object(logging_service.aiohttp, "ClientSession", _FakeAvatarSession),
            ):
                result = asyncio.run(logging_service._user_avatar_color(self._user(user_id=8)))
        finally:
            _FakeAvatarSession.response = _FakeAvatarResponse()
        self.assertIsNone(result)

    def test_network_exception_returns_none(self):
        class _RaisingSession(_FakeAvatarSession):
            def get(self, url, **kwargs):
                raise RuntimeError("接続失敗")

        with (
            patch.object(logging_service, "ColorThief", _FakeColorThief),
            patch.object(logging_service.aiohttp, "ClientSession", _RaisingSession),
        ):
            result = asyncio.run(logging_service._user_avatar_color(self._user(user_id=9)))
        self.assertIsNone(result)

    def test_colorthief_failure_returns_none(self):
        with (
            patch.object(logging_service, "ColorThief", _BoomColorThief),
            patch.object(logging_service.aiohttp, "ClientSession", _FakeAvatarSession),
        ):
            result = asyncio.run(logging_service._user_avatar_color(self._user(user_id=10)))
        self.assertIsNone(result)

    def test_success_caches_the_result(self):
        with (
            patch.object(logging_service, "ColorThief", _FakeColorThief),
            patch.object(logging_service.aiohttp, "ClientSession", _FakeAvatarSession),
        ):
            result = asyncio.run(logging_service._user_avatar_color(self._user(user_id=11)))
        self.assertEqual(result, discord.Color.from_rgb(10, 20, 30))
        self.assertEqual(logging_service._USER_COLOR_CACHE[11], (10 << 16) + (20 << 8) + 30)

    def test_cache_eviction_keeps_it_bounded(self):
        """上限ちょうどで詰まっていても、新規ユーザーが弾かれず最古が追い出されること。

        `>=` を `>` に崩すと上限を超えて際限なく増え続ける（実運用ではメモリを
        圧迫し続ける）。
        """
        for i in range(logging_service._USER_COLOR_CACHE_MAX):
            logging_service._USER_COLOR_CACHE[i] = i
        with (
            patch.object(logging_service, "ColorThief", _FakeColorThief),
            patch.object(logging_service.aiohttp, "ClientSession", _FakeAvatarSession),
        ):
            asyncio.run(logging_service._user_avatar_color(self._user(user_id=999999)))
        self.assertEqual(len(logging_service._USER_COLOR_CACHE), logging_service._USER_COLOR_CACHE_MAX)
        self.assertNotIn(0, logging_service._USER_COLOR_CACHE)  # 最古（挿入順で先頭）が追い出された
        self.assertIn(999999, logging_service._USER_COLOR_CACHE)


class GetLogChannelTests(unittest.TestCase):
    def test_no_channel_configured_returns_none(self):
        with patch.object(logging_service, "get_log_settings", Mock(return_value={"channel_id": None})):
            self.assertIsNone(logging_service._get_log_channel(Mock(), 1))

    def test_configured_id_not_a_text_channel_returns_none(self):
        bot = Mock()
        bot.get_channel.return_value = Mock(spec=discord.VoiceChannel)
        with patch.object(logging_service, "get_log_settings", Mock(return_value={"channel_id": 5})):
            self.assertIsNone(logging_service._get_log_channel(bot, 1))

    def test_configured_text_channel_is_returned(self):
        channel = Mock(spec=discord.TextChannel)
        bot = Mock()
        bot.get_channel.return_value = channel
        with patch.object(logging_service, "get_log_settings", Mock(return_value={"channel_id": 5})):
            result = logging_service._get_log_channel(bot, 1)
        self.assertIs(result, channel)
        bot.get_channel.assert_called_once_with(5)


class BuildLogEmbedTests(unittest.TestCase):
    def _user(self, name="user#0001", url="https://example.com/a.png"):
        user = Mock(spec=discord.abc.User)
        user.__str__ = Mock(return_value=name)
        user.display_avatar = SimpleNamespace(url=url)
        return user

    def test_description_over_the_limit_is_truncated(self):
        embed = asyncio.run(logging_service.build_log_embed("INFO", "あ" * 4100))
        self.assertEqual(len(embed.description), 4096)
        self.assertTrue(embed.description.endswith("..."))

    def test_description_under_the_limit_is_untouched(self):
        embed = asyncio.run(logging_service.build_log_embed("INFO", "短い本文"))
        self.assertEqual(embed.description, "短い本文")

    def test_explicit_color_skips_the_avatar_lookup(self):
        """アバター色の抽出は失敗しうる重い処理。明示指定があるなら呼ばれてはいけない。"""
        mock_avatar_color = AsyncMock(return_value=discord.Color.gold())
        with patch.object(logging_service, "_user_avatar_color", mock_avatar_color):
            embed = asyncio.run(
                logging_service.build_log_embed("INFO", "本文", user=self._user(), embed_color=discord.Color.purple())
            )
        mock_avatar_color.assert_not_called()
        self.assertEqual(embed.color, discord.Color.purple())

    def test_no_explicit_color_falls_back_to_level_color_when_avatar_color_is_none(self):
        mock_avatar_color = AsyncMock(return_value=None)
        with patch.object(logging_service, "_user_avatar_color", mock_avatar_color):
            embed = asyncio.run(logging_service.build_log_embed("ERROR", "本文", user=self._user()))
        mock_avatar_color.assert_called_once()
        self.assertEqual(embed.color, discord.Color.red())

    def test_avatar_color_is_used_when_present(self):
        mock_avatar_color = AsyncMock(return_value=discord.Color.teal())
        with patch.object(logging_service, "_user_avatar_color", mock_avatar_color):
            embed = asyncio.run(logging_service.build_log_embed("ERROR", "本文", user=self._user()))
        self.assertEqual(embed.color, discord.Color.teal())

    def test_author_name_over_the_limit_is_truncated(self):
        mock_avatar_color = AsyncMock(return_value=None)
        with patch.object(logging_service, "_user_avatar_color", mock_avatar_color):
            embed = asyncio.run(logging_service.build_log_embed("INFO", "本文", user=self._user(name="な" * 300)))
        self.assertEqual(len(embed.author.name), 256)
        self.assertTrue(embed.author.name.endswith("..."))

    def test_author_icon_fetch_failure_still_sets_the_name(self):
        """アイコンURLが取れなくても著者名は諦めない（例外を握りつぶして無表示にはしない）。"""
        user = Mock(spec=discord.abc.User)
        user.__str__ = Mock(return_value="user#0002")
        user.display_avatar = _BoomAvatarAsset()
        mock_avatar_color = AsyncMock(return_value=None)
        with patch.object(logging_service, "_user_avatar_color", mock_avatar_color):
            embed = asyncio.run(logging_service.build_log_embed("INFO", "本文", user=user))
        self.assertEqual(embed.author.name, "user#0002")
        self.assertIsNone(embed.author.icon_url)

    def test_author_name_over_the_limit_is_truncated_even_on_the_fallback_path(self):
        """アイコン取得に失敗した側の分岐にも、同じ256文字上限の切り詰めがある。

        2箇所に同じ判定を書いているため、片方だけ直る取りこぼしが起きやすい
        （CONTRIBUTING 10.）。
        """
        user = Mock(spec=discord.abc.User)
        user.__str__ = Mock(return_value="な" * 300)
        user.display_avatar = _BoomAvatarAsset()
        mock_avatar_color = AsyncMock(return_value=None)
        with patch.object(logging_service, "_user_avatar_color", mock_avatar_color):
            embed = asyncio.run(logging_service.build_log_embed("INFO", "本文", user=user))
        self.assertEqual(len(embed.author.name), 256)
        self.assertTrue(embed.author.name.endswith("..."))

    def test_no_user_means_no_author(self):
        embed = asyncio.run(logging_service.build_log_embed("INFO", "本文"))
        self.assertIsNone(embed.author.name)

    def test_field_value_over_the_limit_is_truncated_with_a_marker(self):
        embed = asyncio.run(logging_service.build_log_embed("INFO", "本文", fields={"詳細": "x" * 1100}))
        field = embed.fields[0]
        self.assertEqual(field.name, "詳細")
        self.assertTrue(field.value.startswith("x" * 1024))
        self.assertTrue(field.value.endswith("... (省略)"))

    def test_field_value_under_the_limit_is_untouched(self):
        embed = asyncio.run(logging_service.build_log_embed("INFO", "本文", fields={"詳細": "短い"}))
        self.assertEqual(embed.fields[0].value, "短い")

    def test_footer_has_the_jst_label(self):
        embed = asyncio.run(logging_service.build_log_embed("INFO", "本文"))
        self.assertTrue(embed.footer.text.startswith("時刻 (JST): "))


class LogActionTests(unittest.TestCase):
    """log_action は3つのガード（レベル不正・非表示設定・チャンネル未設定）を
    すべて通過したときだけ送信する。"""

    def setUp(self):
        self.bot = Mock()
        self.channel = Mock(spec=discord.TextChannel)
        self.channel.send = AsyncMock()

    def test_unknown_level_is_silently_ignored(self):
        with patch.object(logging_service, "_should_log") as mock_should:
            asyncio.run(logging_service.log_action(self.bot, 1, "TRACE", "本文"))
        mock_should.assert_not_called()
        self.channel.send.assert_not_called()

    def test_level_below_threshold_sends_nothing(self):
        with (
            patch.object(logging_service, "_should_log", Mock(return_value=False)) as mock_should,
            patch.object(logging_service, "_get_log_channel") as mock_get_channel,
        ):
            asyncio.run(logging_service.log_action(self.bot, 1, "DEBUG", "本文"))
        mock_should.assert_called_once_with(1, "DEBUG")
        mock_get_channel.assert_not_called()

    def test_no_channel_configured_sends_nothing(self):
        with (
            patch.object(logging_service, "_should_log", Mock(return_value=True)),
            patch.object(logging_service, "_get_log_channel", Mock(return_value=None)) as mock_get_channel,
        ):
            asyncio.run(logging_service.log_action(self.bot, 1, "INFO", "本文"))
        mock_get_channel.assert_called_once_with(self.bot, 1)

    def test_all_gates_pass_sends_the_embed(self):
        with (
            patch.object(logging_service, "_should_log", Mock(return_value=True)),
            patch.object(logging_service, "_get_log_channel", Mock(return_value=self.channel)),
        ):
            asyncio.run(logging_service.log_action(self.bot, 1, "INFO", "本文"))
        self.channel.send.assert_called_once()
        sent_embed = self.channel.send.call_args.kwargs["embed"]
        self.assertIn("本文", sent_embed.description)


class SendLogEmbedTests(unittest.TestCase):
    def setUp(self):
        self.bot = Mock()
        self.channel = Mock(spec=discord.TextChannel)
        self.embed = discord.Embed(title="t")

    def test_unknown_level_returns_none(self):
        result = asyncio.run(logging_service.send_log_embed(self.bot, 1, "TRACE", self.embed))
        self.assertIsNone(result)

    def test_below_threshold_returns_none(self):
        with patch.object(logging_service, "_should_log", Mock(return_value=False)):
            result = asyncio.run(logging_service.send_log_embed(self.bot, 1, "DEBUG", self.embed))
        self.assertIsNone(result)

    def test_no_channel_returns_none(self):
        with (
            patch.object(logging_service, "_should_log", Mock(return_value=True)),
            patch.object(logging_service, "_get_log_channel", Mock(return_value=None)),
        ):
            result = asyncio.run(logging_service.send_log_embed(self.bot, 1, "INFO", self.embed))
        self.assertIsNone(result)

    def test_success_returns_the_sent_message(self):
        sent_message = Mock(spec=discord.Message)
        self.channel.send = AsyncMock(return_value=sent_message)
        with (
            patch.object(logging_service, "_should_log", Mock(return_value=True)),
            patch.object(logging_service, "_get_log_channel", Mock(return_value=self.channel)),
        ):
            result = asyncio.run(logging_service.send_log_embed(self.bot, 1, "INFO", self.embed))
        self.assertIs(result, sent_message)
        self.channel.send.assert_called_once_with(embed=self.embed)

    def test_send_failure_is_swallowed_and_returns_none(self):
        """進捗更新に使われるため、送信失敗のたびに例外で呼び出し元を落とさない。"""
        self.channel.send = AsyncMock(side_effect=discord.HTTPException(Mock(status=500), "boom"))
        with (
            patch.object(logging_service, "_should_log", Mock(return_value=True)),
            patch.object(logging_service, "_get_log_channel", Mock(return_value=self.channel)),
            self.assertLogs(logging_service.logger, level="DEBUG"),
        ):
            result = asyncio.run(logging_service.send_log_embed(self.bot, 1, "INFO", self.embed))
        self.assertIsNone(result)


# ──────────────────────────────────────────────
# reaction_role_service
# ──────────────────────────────────────────────


class ReactionRoleAddTests(unittest.TestCase):
    """付与処理。ガードを1つ外すだけで、無関係なユーザーにロールが付く。"""

    def _payload(self, guild_id=1, message_id=100, emoji="👍", member=None):
        return SimpleNamespace(guild_id=guild_id, message_id=message_id, emoji=emoji, member=member)

    def _member(self, bot=False, uid=5):
        member = Mock()
        member.id = uid
        member.bot = bot
        member.add_roles = AsyncMock()
        return member

    def test_dm_reactions_are_ignored(self):
        payload = self._payload(guild_id=None, member=self._member())
        bot = Mock()
        asyncio.run(reaction_role_service.handle_reaction_add(bot, payload))
        bot.get_guild.assert_not_called()

    def test_missing_member_is_ignored(self):
        payload = self._payload(member=None)
        bot = Mock()
        asyncio.run(reaction_role_service.handle_reaction_add(bot, payload))
        bot.get_guild.assert_not_called()

    def test_bot_reactions_are_ignored(self):
        payload = self._payload(member=self._member(bot=True))
        bot = Mock()
        asyncio.run(reaction_role_service.handle_reaction_add(bot, payload))
        bot.get_guild.assert_not_called()

    def test_unknown_guild_is_ignored(self):
        bot = Mock()
        bot.get_guild.return_value = None
        payload = self._payload(member=self._member())
        asyncio.run(reaction_role_service.handle_reaction_add(bot, payload))
        bot.get_guild.assert_called_once_with(1)

    def test_message_without_reaction_role_setup_does_nothing(self):
        guild = Mock()
        bot = Mock()
        bot.get_guild.return_value = guild
        mock_get_rr = Mock(return_value={})
        member = self._member()
        with patch.object(reaction_role_service, "get_reaction_roles", mock_get_rr):
            asyncio.run(reaction_role_service.handle_reaction_add(bot, self._payload(member=member)))
        mock_get_rr.assert_called_once_with(1)
        guild.get_role.assert_not_called()
        member.add_roles.assert_not_called()

    def test_unmapped_emoji_does_nothing(self):
        guild = Mock()
        bot = Mock()
        bot.get_guild.return_value = guild
        mapping = {"999": 42}
        with (
            patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": mapping})),
            self.assertLogs(reaction_role_service.logger, level="DEBUG"),
        ):
            asyncio.run(
                reaction_role_service.handle_reaction_add(bot, self._payload(emoji="👍", member=self._member()))
            )
        guild.get_role.assert_not_called()

    def test_missing_role_logs_a_warning_and_does_nothing(self):
        guild = Mock()
        guild.get_role.return_value = None
        bot = Mock()
        bot.get_guild.return_value = guild
        member = self._member()
        with (
            patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"👍": 42}})),
            self.assertLogs(reaction_role_service.logger, level="WARNING"),
        ):
            asyncio.run(reaction_role_service.handle_reaction_add(bot, self._payload(member=member)))
        guild.get_role.assert_called_once_with(42)
        member.add_roles.assert_not_called()

    def test_success_grants_the_role(self):
        role = Mock()
        role.name = "参加者"
        guild = Mock()
        guild.get_role.return_value = role
        bot = Mock()
        bot.get_guild.return_value = guild
        member = self._member()
        with patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"👍": 42}})):
            asyncio.run(reaction_role_service.handle_reaction_add(bot, self._payload(member=member)))
        member.add_roles.assert_called_once_with(role, reason="リアクションロール")

    def test_discord_error_on_grant_is_logged_not_raised(self):
        role = Mock()
        guild = Mock()
        guild.get_role.return_value = role
        bot = Mock()
        bot.get_guild.return_value = guild
        member = self._member()
        member.add_roles = AsyncMock(side_effect=discord.HTTPException(Mock(status=403), "権限不足"))
        with (
            patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"👍": 42}})),
            self.assertLogs(reaction_role_service.logger, level="ERROR"),
        ):
            asyncio.run(reaction_role_service.handle_reaction_add(bot, self._payload(member=member)))


class ReactionRoleRemoveTests(unittest.TestCase):
    """解除処理。add と分岐が独立しているので、それぞれ別に壊れうる。"""

    def _payload(self, guild_id=1, message_id=100, emoji="👍", user_id=5):
        return SimpleNamespace(guild_id=guild_id, message_id=message_id, emoji=emoji, user_id=user_id)

    def _member(self, bot=False, uid=5):
        member = Mock()
        member.id = uid
        member.bot = bot
        member.remove_roles = AsyncMock()
        return member

    def test_dm_reactions_are_ignored(self):
        bot = Mock()
        asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload(guild_id=None)))
        bot.get_guild.assert_not_called()

    def test_unknown_guild_is_ignored(self):
        bot = Mock()
        bot.get_guild.return_value = None
        asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))
        bot.get_guild.assert_called_once_with(1)

    def test_member_who_left_is_ignored(self):
        guild = Mock()
        guild.get_member.return_value = None
        bot = Mock()
        bot.get_guild.return_value = guild
        asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))
        guild.get_member.assert_called_once_with(5)

    def test_bot_member_is_ignored(self):
        guild = Mock()
        guild.get_member.return_value = self._member(bot=True)
        bot = Mock()
        bot.get_guild.return_value = guild
        with patch.object(reaction_role_service, "get_reaction_roles") as mock_get_rr:
            asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))
        mock_get_rr.assert_not_called()

    def test_message_without_reaction_role_setup_does_nothing(self):
        member = self._member()
        guild = Mock()
        guild.get_member.return_value = member
        bot = Mock()
        bot.get_guild.return_value = guild
        with patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={})):
            asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))
        member.remove_roles.assert_not_called()

    def test_unmapped_emoji_does_nothing(self):
        member = self._member()
        guild = Mock()
        guild.get_member.return_value = member
        bot = Mock()
        bot.get_guild.return_value = guild
        with (
            patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"999": 42}})),
            self.assertLogs(reaction_role_service.logger, level="DEBUG"),
        ):
            asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload(emoji="👍")))
        member.remove_roles.assert_not_called()

    def test_missing_role_logs_a_warning_and_does_nothing(self):
        member = self._member()
        guild = Mock()
        guild.get_member.return_value = member
        guild.get_role.return_value = None
        bot = Mock()
        bot.get_guild.return_value = guild
        with (
            patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"👍": 42}})),
            self.assertLogs(reaction_role_service.logger, level="WARNING"),
        ):
            asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))
        member.remove_roles.assert_not_called()

    def test_success_revokes_the_role(self):
        role = Mock()
        member = self._member()
        guild = Mock()
        guild.get_member.return_value = member
        guild.get_role.return_value = role
        bot = Mock()
        bot.get_guild.return_value = guild
        with patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"👍": 42}})):
            asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))
        member.remove_roles.assert_called_once_with(role, reason="リアクションロール解除")

    def test_discord_error_on_revoke_is_logged_not_raised(self):
        role = Mock()
        member = self._member()
        member.remove_roles = AsyncMock(side_effect=discord.HTTPException(Mock(status=403), "権限不足"))
        guild = Mock()
        guild.get_member.return_value = member
        guild.get_role.return_value = role
        bot = Mock()
        bot.get_guild.return_value = guild
        with (
            patch.object(reaction_role_service, "get_reaction_roles", Mock(return_value={"100": {"👍": 42}})),
            self.assertLogs(reaction_role_service.logger, level="ERROR"),
        ):
            asyncio.run(reaction_role_service.handle_reaction_remove(bot, self._payload()))


# ──────────────────────────────────────────────
# content_moderation
# ──────────────────────────────────────────────


class GptAssessVirusTotalTests(unittest.TestCase):
    """VirusTotal の結果だけで即決できる場合、Groq を呼ばずに返すこと（レイテンシとAPI費用のため）。"""

    def test_malicious_at_threshold_is_dangerous(self):
        """MALICIOUS_THRESHOLD ちょうどで判定が変わる境界。"""
        self.assertEqual(
            content_moderation.MALICIOUS_THRESHOLD,
            10,
            "定数が変わっているとこのテストの前提が崩れる",
        )
        result = asyncio.run(content_moderation.gpt_assess("text", [{"malicious": 10, "suspicious": 0}]))
        self.assertEqual(result, "DANGEROUS")

    def test_malicious_one_below_threshold_is_only_suspicious(self):
        result = asyncio.run(content_moderation.gpt_assess("text", [{"malicious": 9, "suspicious": 0}]))
        self.assertEqual(result, "SUSPICIOUS")

    def test_any_suspicious_hit_is_flagged(self):
        result = asyncio.run(content_moderation.gpt_assess("text", [{"malicious": 0, "suspicious": 1}]))
        self.assertEqual(result, "SUSPICIOUS")

    def test_clean_results_fall_through_to_groq(self):
        with patch.object(content_moderation, "GROQ_API_KEY", ""):
            result = asyncio.run(content_moderation.gpt_assess("text", [{"malicious": 0, "suspicious": 0}]))
        self.assertEqual(result, "SAFE")

    def test_a_later_malicious_entry_still_wins(self):
        """複数URLのうち、後方に危険なものが混じっていても見逃さない。"""
        vt_results = [{"malicious": 0, "suspicious": 0}, {"malicious": 10, "suspicious": 0}]
        result = asyncio.run(content_moderation.gpt_assess("text", vt_results))
        self.assertEqual(result, "DANGEROUS")

    def test_missing_keys_are_treated_as_zero(self):
        with patch.object(content_moderation, "GROQ_API_KEY", ""):
            result = asyncio.run(content_moderation.gpt_assess("text", [{}]))
        self.assertEqual(result, "SAFE")


class GptAssessGroqTests(unittest.TestCase):
    """VirusTotal だけでは決まらないとき、Groq の一言判定に委ねる経路。"""

    def setUp(self):
        """判定のキャッシュを毎回空にする。

        gpt_assess は同じ入力の判定を使い回す（連投対策）。このクラスは
        どのテストも `("hello", [])` を投げるので、消さないと**2件目以降が
        1件目の答えを受け取る**。実際、キャッシュを入れた直後に7件が落ちた。
        """
        content_moderation._verdict_cache.clear()
        self.addCleanup(content_moderation._verdict_cache.clear)

    def _mock_completion(self, reply: str):
        response = Mock()
        response.choices = [Mock(message=Mock(content=reply))]
        return AsyncMock(return_value=response)

    def test_no_api_key_returns_safe_without_calling_groq(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", ""),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            result = asyncio.run(content_moderation.gpt_assess("hello", []))
        self.assertEqual(result, "SAFE")
        mock_create.assert_not_called()

    def test_dangerous_reply_is_recognized(self):
        mock_create = self._mock_completion("DANGEROUS")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            result = asyncio.run(content_moderation.gpt_assess("hello", []))
        self.assertEqual(result, "DANGEROUS")
        mock_create.assert_called_once()  # モックが実際に呼ばれた（差し替えが効いた）ことの確認

    def test_suspicious_reply_is_recognized(self):
        mock_create = self._mock_completion("this looks SUSPICIOUS to me")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            result = asyncio.run(content_moderation.gpt_assess("hello", []))
        self.assertEqual(result, "SUSPICIOUS")

    def test_warning_word_also_counts_as_suspicious(self):
        mock_create = self._mock_completion("WARNING: possible spam")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            result = asyncio.run(content_moderation.gpt_assess("hello", []))
        self.assertEqual(result, "SUSPICIOUS")

    def test_safe_reply_is_recognized(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            result = asyncio.run(content_moderation.gpt_assess("hello", []))
        self.assertEqual(result, "SAFE")

    def test_groq_failure_is_reported_as_unknown_not_safe(self):
        """判定できなかったことを「安全」に化けさせない。"""
        mock_create = AsyncMock(side_effect=RuntimeError("timeout"))
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
            self.assertLogs(content_moderation.logger, level="WARNING"),
        ):
            result = asyncio.run(content_moderation.gpt_assess("hello", []))
        self.assertEqual(result, "UNKNOWN")

    def _sent_prompt(self, mock_create) -> str:
        messages = mock_create.call_args.kwargs["messages"]
        return next(m["content"] for m in messages if m["role"] == "user")

    def test_spam_warning_line_appears_at_the_threshold(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", [], spam_count=4))
        self.assertIn("スパム警告", self._sent_prompt(mock_create))

    def test_spam_warning_line_is_absent_just_below_the_threshold(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", [], spam_count=3))
        self.assertNotIn("スパム警告", self._sent_prompt(mock_create))

    def test_high_frequency_line_appears_just_under_two_seconds(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", [], min_interval=1.9))
        self.assertIn("高頻度", self._sent_prompt(mock_create))

    def test_high_frequency_line_is_absent_exactly_at_two_seconds(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", [], min_interval=2.0))
        self.assertNotIn("高頻度", self._sent_prompt(mock_create))

    def test_infinite_interval_never_shows_the_high_frequency_line(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", []))  # デフォルト値 inf
        self.assertNotIn("高頻度", self._sent_prompt(mock_create))

    def test_new_member_line_appears_when_flagged(self):
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", [], is_new_member=True))
        self.assertIn("新規", self._sent_prompt(mock_create))

    def test_bucket_and_model_are_passed_through(self):
        """呼び出しがモデレーション用バケットを通ること（レート制御の対象から漏れない）。"""
        mock_create = self._mock_completion("SAFE")
        with (
            patch.object(content_moderation, "GROQ_API_KEY", "key"),
            patch.object(content_moderation, "get_groq_client", Mock(return_value=Mock())),
            patch.object(content_moderation, "create_chat_completion", mock_create),
        ):
            asyncio.run(content_moderation.gpt_assess("hello", []))
        mock_create.assert_called_once()
        self.assertEqual(mock_create.call_args.kwargs["bucket"], content_moderation._GROQ_BUCKET)


# ──────────────────────────────────────────────
# spam_detection / raid_detection: 共通の時刻差し替え
# ──────────────────────────────────────────────


class _FakeClock:
    """time モジュールの代わりに差し込む、時刻を手で進められる時計。"""

    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def time(self) -> float:
        return self.now


class SpamDetectionTests(unittest.TestCase):
    """しきい値ちょうど・時間窓ちょうどの境界と、掃除タイマーの境界を確認する。"""

    def setUp(self):
        self._orig_history = {k: list(v) for k, v in spam_detection._user_message_times.items()}
        self._orig_counter = spam_detection._cleanup_counter
        spam_detection._user_message_times.clear()
        spam_detection._cleanup_counter = 0
        self.clock = _FakeClock()
        self._time_patch = patch.object(spam_detection, "time", self.clock)
        self._time_patch.start()

    def tearDown(self):
        self._time_patch.stop()
        spam_detection._user_message_times.clear()
        spam_detection._user_message_times.update(self._orig_history)
        spam_detection._cleanup_counter = self._orig_counter

    def test_below_threshold_is_not_spam(self):
        result = None
        for _ in range(spam_detection.SPAM_REPEAT_THRESHOLD - 1):
            result = spam_detection.check_spam(1, 1)
        is_spam, count, _ = result
        self.assertFalse(is_spam)
        self.assertEqual(count, spam_detection.SPAM_REPEAT_THRESHOLD - 1)

    def test_exactly_at_threshold_is_spam(self):
        """しきい値ちょうどで発火する境界。`>=` を `>` に崩すと1件遅れて発火する。"""
        result = None
        for _ in range(spam_detection.SPAM_REPEAT_THRESHOLD):
            result = spam_detection.check_spam(1, 1)
        is_spam, count, _ = result
        self.assertTrue(is_spam)
        self.assertEqual(count, spam_detection.SPAM_REPEAT_THRESHOLD)

    def test_min_interval_is_the_smallest_gap(self):
        spam_detection.check_spam(1, 1)
        self.clock.now += 1.0
        spam_detection.check_spam(1, 1)
        self.clock.now += 5.0
        _, _, min_interval = spam_detection.check_spam(1, 1)
        self.assertAlmostEqual(min_interval, 1.0)

    def test_single_message_has_infinite_min_interval(self):
        _, _, min_interval = spam_detection.check_spam(1, 1)
        self.assertEqual(min_interval, float("inf"))

    def test_message_exactly_at_the_window_edge_is_dropped(self):
        """窓境界の off-by-one。ちょうど窓幅ぶん古いメッセージは数えない仕様。"""
        spam_detection.check_spam(1, 1)
        self.clock.now += spam_detection.SPAM_TIME_WINDOW
        _, count, _ = spam_detection.check_spam(1, 1)
        self.assertEqual(count, 1)

    def test_message_just_inside_the_window_still_counts(self):
        spam_detection.check_spam(1, 1)
        self.clock.now += spam_detection.SPAM_TIME_WINDOW - 0.001
        _, count, _ = spam_detection.check_spam(1, 1)
        self.assertEqual(count, 2)

    def test_different_users_are_tracked_independently(self):
        for _ in range(spam_detection.SPAM_REPEAT_THRESHOLD):
            spam_detection.check_spam(1, 100)
        is_spam_other, count_other, _ = spam_detection.check_spam(1, 200)
        self.assertFalse(is_spam_other)
        self.assertEqual(count_other, 1)

    def test_different_guilds_are_tracked_independently(self):
        for _ in range(spam_detection.SPAM_REPEAT_THRESHOLD):
            spam_detection.check_spam(1, 100)
        is_spam_other, count_other, _ = spam_detection.check_spam(2, 100)
        self.assertFalse(is_spam_other)
        self.assertEqual(count_other, 1)

    def test_cleanup_boundary_leaves_stale_entries_until_the_interval_is_reached(self):
        """掃除は _CLEANUP_INTERVAL 回目でようやく走る。1回早すぎても遅すぎても壊れる。"""
        stale_key = (99, 999)
        spam_detection._user_message_times[stale_key] = [self.clock.now - spam_detection.SPAM_TIME_WINDOW - 1]

        for _ in range(spam_detection._CLEANUP_INTERVAL - 1):
            spam_detection.check_spam(1, 1)
        self.assertIn(stale_key, spam_detection._user_message_times, "早すぎるタイミングで掃除された")

        spam_detection.check_spam(1, 1)  # ちょうど _CLEANUP_INTERVAL 回目
        self.assertNotIn(stale_key, spam_detection._user_message_times, "しきい値に達しても掃除されなかった")
        self.assertIn((1, 1), spam_detection._user_message_times)


class RaidDetectionTests(unittest.TestCase):
    """VC 大量参加の検出。人数しきい値・時間窓・名前の同一視の3つが要。"""

    def setUp(self):
        self._orig_history = {k: list(v) for k, v in raid_detection._vc_join_history.items()}
        self._orig_counter = raid_detection._cleanup_counter
        raid_detection._vc_join_history.clear()
        raid_detection._cleanup_counter = 0
        self.clock = _FakeClock()
        self._time_patch = patch.object(raid_detection, "time", self.clock)
        self._time_patch.start()

    def tearDown(self):
        self._time_patch.stop()
        raid_detection._vc_join_history.clear()
        raid_detection._vc_join_history.update(self._orig_history)
        raid_detection._cleanup_counter = self._orig_counter

    def _member(self, name: str, uid: int):
        member = Mock(spec=discord.Member)
        member.display_name = name
        member.id = uid
        return member

    def test_below_threshold_is_not_a_raid(self):
        result = False
        for i in range(raid_detection.VC_RAID_THRESHOLD - 1):
            result = raid_detection.check_vc_raid(self._member(f"Raid{i}", i), channel_id=1)
        self.assertFalse(result)

    def test_exactly_at_threshold_is_a_raid(self):
        """人数しきい値ちょうどで発火する境界。"""
        result = False
        for i in range(raid_detection.VC_RAID_THRESHOLD):
            result = raid_detection.check_vc_raid(self._member(f"Raid{i}", i), channel_id=1)
        self.assertTrue(result)

    def test_different_name_prefixes_are_not_grouped_together(self):
        names = ["Alice", "Bob__", "Carol", "Dave1", "Eve__"]
        result = False
        for i, name in enumerate(names):
            result = raid_detection.check_vc_raid(self._member(name, i), channel_id=1)
        self.assertFalse(result)

    def test_names_sharing_only_the_prefix_length_are_grouped(self):
        """先頭 VC_RAID_SIMILAR_PREFIX 文字だけが比較対象。その先が違っても同一視する。"""
        names = ["Raid-alpha", "Raid-beta", "Raid-gamma", "Raid-delta", "Raid-epsilon"]
        result = False
        for i, name in enumerate(names):
            result = raid_detection.check_vc_raid(self._member(name, i), channel_id=1)
        self.assertTrue(result)

    def test_names_differing_within_the_prefix_are_not_grouped(self):
        """5文字目より前で違えば別グループ（プレフィックス長ちょうどの境界）。"""
        names = ["AAAA1", "AAAB2", "AAAC3", "AAAD4", "AAAE5"]
        result = False
        for i, name in enumerate(names):
            result = raid_detection.check_vc_raid(self._member(name, i), channel_id=1)
        self.assertFalse(result)

    def test_different_channels_are_tracked_independently(self):
        for i in range(raid_detection.VC_RAID_THRESHOLD - 1):
            raid_detection.check_vc_raid(self._member(f"Raid{i}", i), channel_id=1)
        result = raid_detection.check_vc_raid(self._member("Raid9", 9), channel_id=2)
        self.assertFalse(result)

    def test_join_exactly_at_the_window_edge_is_dropped(self):
        for i in range(raid_detection.VC_RAID_THRESHOLD - 1):
            raid_detection.check_vc_raid(self._member(f"Raid{i}", i), channel_id=1)
        self.clock.now += raid_detection.VC_RAID_WINDOW_SEC
        result = raid_detection.check_vc_raid(self._member("Raid9", 9), channel_id=1)
        self.assertFalse(result)

    def test_join_just_inside_the_window_still_counts(self):
        for i in range(raid_detection.VC_RAID_THRESHOLD - 1):
            raid_detection.check_vc_raid(self._member(f"Raid{i}", i), channel_id=1)
        self.clock.now += raid_detection.VC_RAID_WINDOW_SEC - 0.001
        result = raid_detection.check_vc_raid(self._member("Raid9", 9), channel_id=1)
        self.assertTrue(result)

    def test_cleanup_boundary_leaves_stale_entries_until_the_interval_is_reached(self):
        stale_channel = 999
        raid_detection._vc_join_history[stale_channel] = [
            (self.clock.now - raid_detection.VC_RAID_WINDOW_SEC - 1, "AAAA", 1)
        ]

        for i in range(raid_detection._CLEANUP_INTERVAL - 1):
            raid_detection.check_vc_raid(self._member(f"N{i}", i), channel_id=1)
        self.assertIn(stale_channel, raid_detection._vc_join_history, "早すぎるタイミングで掃除された")

        raid_detection.check_vc_raid(self._member("last", 9999), channel_id=1)
        self.assertNotIn(stale_channel, raid_detection._vc_join_history, "しきい値に達しても掃除されなかった")
        self.assertIn(1, raid_detection._vc_join_history)


if __name__ == "__main__":
    unittest.main()
