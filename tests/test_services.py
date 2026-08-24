"""services/ 層のテスト。

    python -m unittest discover -s tests -t .

これまで services/ にはテストが1つも無く（70件はすべて管理画面 API と UI 向け）、
地震通知の不具合は毎回「本番で気付いて、使い捨てスクリプトで確かめる」流れに
なっていた。監査で洗い出した分岐をここに固定して、次からは自動で捕まえる。

Discord とネットワークには一切触らない。discord.py の型は Mock(spec=...) で
差し替え、設定ストアは一時ディレクトリを使う。
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import time
import unittest
import zipfile
from collections import deque
from pathlib import Path
from unittest.mock import Mock, patch

# services/* は読み込み時に SETTINGS_DIR を解決するため、import より前に差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="services-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import services.earthquake_service as eq  # noqa: E402
from services import settings_store as store  # noqa: E402
from services.news_service import _favicon_url  # noqa: E402
from services.url_safety import URLSafetyError, validate_public_http_url  # noqa: E402
from services.welcome_service import DEFAULT_GOODBYE, DEFAULT_WELCOME, render_template  # noqa: E402
from webapp_admin.schema.validation import InvalidValue, validate_field  # noqa: E402


def text_channel(channel_id: int = 555):
    channel = Mock(spec=discord.TextChannel)
    channel.id = channel_id
    return channel


def guild_with(channel, channel_id: int = 555, name: str = "テスト鯖", members: int = 7):
    guild = Mock()
    guild.name = name
    guild.member_count = members
    guild.get_channel.side_effect = lambda i: channel if int(i) == channel_id else None
    return guild


def bot_with(guild, guild_id: int = 1):
    bot = Mock()
    bot.get_guild.side_effect = lambda g: guild if int(g) == guild_id else None
    return bot


QUAKE_551 = {
    "code": 551, "id": "q1",
    "earthquake": {
        "time": "2026/08/24 12:54:41", "maxScale": 40, "domesticTsunami": "None",
        "hypocenter": {"name": "茨城県沖", "latitude": 36.5, "longitude": 141.0,
                       "depth": 40, "magnitude": 5.2},
    },
    "issue": {"type": "DetailScale", "time": "2026/08/24 12:57:23"},
    "points": [{"addr": "水戸市", "pref": "茨城県", "scale": 40}],
}

# 遠地地震。points も areas も maxScale も無く、震度が決まらない。
QUAKE_FOREIGN = {
    "code": 551, "id": "q2",
    "earthquake": {"time": "2026/08/24 13:00:00", "domesticTsunami": "None",
                   "hypocenter": {"name": "南太平洋", "magnitude": 7.1, "depth": 10}},
    "issue": {"type": "Foreign", "time": "2026/08/24 13:02:00"},
}


class MaxScaleTests(unittest.TestCase):
    """震度の取り出し。ペイロードの形ごとに経路が違う。"""

    def test_points_win(self):
        self.assertEqual(eq._max_scale(QUAKE_551), 40)

    def test_eew_forecast_uses_areas(self):
        """556 は points ではなく areas に scaleFrom/scaleTo が入る。

        以前は intensity.forecastMaxInt を見ており、実データにその形が
        現れないため 556 の予想最大震度が常に不明になっていた。
        """
        event = {"code": 556, "areas": [{"scaleFrom": 30, "scaleTo": 45},
                                        {"scaleFrom": 20, "scaleTo": 30}]}
        self.assertEqual(eq._max_scale(event), 45)

    def test_areas_fall_back_to_scale_from(self):
        self.assertEqual(eq._max_scale({"code": 556, "areas": [{"scaleFrom": 50}]}), 50)

    def test_max_scale_field_is_used_when_no_points(self):
        self.assertEqual(eq._max_scale({"earthquake": {"maxScale": 55}}), 55)

    def test_unknown_returns_minus_one(self):
        self.assertEqual(eq._max_scale(QUAKE_FOREIGN), -1)
        self.assertEqual(eq._max_scale({}), -1)


class BadgeTests(unittest.TestCase):
    def test_known_scale_produces_an_image(self):
        buf = eq._generate_badge(40)
        self.assertIsNotNone(buf)
        self.assertGreater(len(buf.getvalue()), 0)

    def test_notify_does_not_build_a_badge_for_unknown_scale(self):
        """震度不明のまま作ると「最大震度 -1」と大書きした画像になる。"""
        made = []
        channel = text_channel()
        bot = bot_with(guild_with(channel))

        async def no_jma(event, scale):
            return "https://example.invalid/jma"

        with patch.object(eq, "_resolve_jma_detail_url", no_jma), \
             patch.object(eq, "_generate_badge", lambda s: made.append(s)), \
             patch.object(eq, "get_all_guild_ids", lambda: [1]), \
             patch.object(eq, "get_earthquake_settings",
                          lambda g: {"channel_id": 555, "min_scale": -1}), \
             patch.object(eq, "get_earthquake_notify_types", lambda g: {}):
            asyncio.run(eq._notify_all_guilds(bot, QUAKE_FOREIGN))

        self.assertEqual(made, [])


class EvaluateGuildTests(unittest.TestCase):
    """対象判定。ここが地震・津波・EEW・診断の唯一の判定元。"""

    def evaluate(self, settings, notify_types, *, max_scale=40, guild=None, **kw):
        bot = bot_with(guild) if guild is not None else bot_with(None)
        with patch.object(eq, "get_earthquake_settings", lambda g: settings), \
             patch.object(eq, "get_earthquake_notify_types", lambda g: notify_types):
            return eq._evaluate_guild(
                bot, 1, notify_type=kw.get("notify_type", "quake_info"),
                max_scale=max_scale, apply_min_scale=kw.get("apply_min_scale", True),
            )

    def test_missing_channel_is_the_first_reason(self):
        channel, reason = self.evaluate({}, {})
        self.assertIsNone(channel)
        self.assertIn("チャンネル", reason)

    def test_min_scale_reason_names_both_numbers(self):
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 50}, {})
        self.assertIn("50", reason)
        self.assertIn("40", reason)

    def test_notify_type_off_uses_a_japanese_label(self):
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 10},
                                  {"quake_info": False})
        self.assertIn("地震情報", reason)
        self.assertIn("オフ", reason)

    def test_uncached_guild_is_reported(self):
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {})
        self.assertIn("キャッシュ", reason)

    def test_channel_of_wrong_type_is_reported(self):
        voice = Mock(spec=discord.VoiceChannel)
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {},
                                  guild=guild_with(voice))
        self.assertIn("テキストチャンネル", reason)

    def test_eligible_guild_returns_the_channel(self):
        channel = text_channel()
        got, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {},
                                    guild=guild_with(channel))
        self.assertIs(got, channel)
        self.assertEqual(reason, "")

    def test_broken_min_scale_falls_back_to_the_default(self):
        """設定が壊れていても例外にせず、既定の閾値で判定する。"""
        channel = text_channel()
        got, _ = self.evaluate({"channel_id": 555, "min_scale": "こわれた"}, {},
                               guild=guild_with(channel))
        self.assertIs(got, channel)

    def test_min_scale_can_be_skipped(self):
        """津波は震度を持たないので閾値を当てない。"""
        channel = text_channel()
        got, _ = self.evaluate({"channel_id": 555, "min_scale": 70}, {},
                               max_scale=-1, apply_min_scale=False,
                               notify_type="tsunami", guild=guild_with(channel))
        self.assertIs(got, channel)


class DiagnoseTests(unittest.TestCase):
    def test_diagnosis_matches_the_filter(self):
        """説明用に条件を書き写すと実際のフィルタとずれて嘘の理由が出る。"""
        bot = bot_with(None)
        settings = {"channel_id": 555, "min_scale": 50}
        with patch.object(eq, "get_earthquake_settings", lambda g: settings), \
             patch.object(eq, "get_earthquake_notify_types", lambda g: {}):
            _, reason = eq._evaluate_guild(bot, 1, notify_type="quake_info",
                                           max_scale=40, apply_min_scale=True)
            diagnosed = eq._diagnose_no_target(bot, 1, notify_type="quake_info",
                                               max_scale=40)
        self.assertEqual(reason, diagnosed)

    def test_settings_failure_does_not_crash_the_diagnosis(self):
        def boom(_):
            raise RuntimeError("設定が読めない")

        with patch.object(eq, "get_earthquake_settings", boom):
            reason = eq._diagnose_no_target(bot_with(None), 1,
                                            notify_type="quake_info", max_scale=40)
        self.assertIn("読み取りに失敗", reason)


class CollectTargetsTests(unittest.TestCase):
    def test_a_broken_guild_does_not_stop_the_others(self):
        """1ギルドの設定不正で全ギルドへの通知が巻き添えで止まらないこと。"""
        channel = text_channel()
        guild = Mock()
        guild.get_channel.side_effect = lambda i: channel

        def settings(guild_id):
            if guild_id == 2:
                raise RuntimeError("この設定は壊れている")
            return {"channel_id": 555, "min_scale": 10}

        bot = Mock()
        bot.get_guild.side_effect = lambda g: guild
        with patch.object(eq, "get_all_guild_ids", lambda: [1, 2, 3]), \
             patch.object(eq, "get_earthquake_settings", settings), \
             patch.object(eq, "get_earthquake_notify_types", lambda g: {}), \
             self.assertLogs(eq.logger, level="ERROR") as captured:
            targets = eq._collect_targets(bot, notify_type="quake_info", max_scale=40)

        self.assertEqual([g for g, _ in targets], [1, 3])
        self.assertIn("guild=2", "\n".join(captured.output))

    def test_only_guild_id_narrows_to_one(self):
        channel = text_channel()
        bot = bot_with(guild_with(channel), guild_id=2)
        with patch.object(eq, "get_all_guild_ids", lambda: [1, 2, 3]), \
             patch.object(eq, "get_earthquake_settings",
                          lambda g: {"channel_id": 555, "min_scale": 10}), \
             patch.object(eq, "get_earthquake_notify_types", lambda g: {}):
            targets = eq._collect_targets(bot, notify_type="quake_info",
                                          max_scale=40, only_guild_id=2)
        self.assertEqual([g for g, _ in targets], [2])


class OverrideTargetTests(unittest.TestCase):
    """開発者パネル専用の経路。本番設定が無いギルドでも送れること。"""

    def test_override_ignores_settings(self):
        channel = text_channel(42)
        bot = bot_with(guild_with(channel, channel_id=42), guild_id=7)
        self.assertEqual(eq._override_target(bot, 7, 42), [(7, channel)])

    def test_missing_channel_is_reported(self):
        bot = bot_with(guild_with(text_channel(42), channel_id=42), guild_id=7)
        with self.assertLogs(eq.logger, level="WARNING") as captured:
            self.assertEqual(eq._override_target(bot, 7, 99), [])
        self.assertIn("指定チャンネル", "\n".join(captured.output))

    def test_uncached_guild_is_reported(self):
        with self.assertLogs(eq.logger, level="WARNING") as captured:
            self.assertEqual(eq._override_target(bot_with(None), 7, 42), [])
        self.assertIn("キャッシュ", "\n".join(captured.output))


class DispatchTests(unittest.TestCase):
    def test_send_failure_keeps_the_traceback(self):
        """gather の結果ループは except の外。exc_info を渡さないとトレースが
        "NoneType: None" になり、どこで落ちたかログに残らない。"""
        channel = text_channel(777)

        async def boom(**kwargs):
            raise RuntimeError("discord が 403 を返した")

        channel.send = boom
        with self.assertLogs(eq.logger, level="ERROR") as captured:
            ok = asyncio.run(eq._dispatch([(1, channel)], tag="earthquake",
                                          embed=discord.Embed(title="t")))
        self.assertEqual(ok, 0)
        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertIsNotNone(record.exc_info)
        self.assertIsInstance(record.exc_info[1], RuntimeError)

    def test_successful_sends_are_counted(self):
        channels = []
        for i in range(3):
            channel = text_channel(i)
            channel.send = Mock(return_value=asyncio.sleep(0))
            channels.append(channel)
        ok = asyncio.run(eq._dispatch([(i, c) for i, c in enumerate(channels)],
                                      tag="earthquake", embed=discord.Embed(title="t")))
        self.assertEqual(ok, 3)

    def test_each_channel_gets_its_own_file_object(self):
        """discord.File は送信で消費されるので使い回せない。"""
        seen = []

        def make(**kwargs):
            seen.append(kwargs.get("files"))
            return asyncio.sleep(0)

        channels = []
        for i in range(2):
            channel = text_channel(i)
            channel.send = make
            channels.append((i, channel))
        asyncio.run(eq._dispatch(channels, tag="earthquake",
                                 embed=discord.Embed(title="t"),
                                 attachments=[("a.png", b"xyz")]))
        self.assertEqual(len(seen), 2)
        self.assertIsNot(seen[0][0], seen[1][0])


class DedupTests(unittest.TestCase):
    def test_oldest_ids_are_evicted_not_the_whole_set(self):
        """全消しだと、消した直後の再配信を弾けず二重通知になる。"""
        seen, order = set(), deque()
        for i in range(eq._SEEN_ID_LIMIT + 10):
            seen.add(i)
            order.append(i)
            while len(order) > eq._SEEN_ID_LIMIT:
                seen.discard(order.popleft())
        self.assertEqual(len(seen), eq._SEEN_ID_LIMIT)
        self.assertIn(eq._SEEN_ID_LIMIT + 9, seen)   # 直近は残る
        self.assertNotIn(0, seen)                    # 最古は落ちる


class DetailUrlTests(unittest.TestCase):
    def test_eid_becomes_a_human_readable_page(self):
        """以前は list.json の "json"（生データのファイル名）に当たり、
        ブラウザで開くとパーサーの値が出るだけのページになっていた。"""
        url = eq._item_detail_url({"eid": "20260824125441",
                                   "json": "20260824125723_..._VXSE5k_1.json"})
        self.assertIsNotNone(url)
        self.assertIn("map.html", url)
        self.assertIn("20260824125441", url)
        self.assertNotIn(".json", url)

    def test_missing_eid_gives_no_url(self):
        self.assertIsNone(eq._item_detail_url({"json": "x.json"}))


class EmbedTests(unittest.TestCase):
    def test_unknown_values_are_omitted_not_written_as_unknown(self):
        embed = eq._build_embed(QUAKE_FOREIGN, -1)
        rendered = embed.description + "".join(
            f.name + str(f.value) for f in embed.fields
        )
        self.assertNotIn("不明", rendered)
        self.assertIn("地震がありました", embed.description)

    def test_known_values_are_shown(self):
        embed = eq._build_embed(QUAKE_551, 40)
        names = [f.name for f in embed.fields]
        self.assertIn("震源", names)
        self.assertIn("規模", names)
        self.assertIn("深さ", names)

    def test_eew_cancellation_is_announced(self):
        """取り消しを黙って捨てると、外れた警報を訂正できない。"""
        embed = eq._build_eew_embed({"code": 556, "cancelled": True,
                                     "earthquake": {"hypocenter": {"name": "茨城県沖"}}})
        self.assertIn("取り消", embed.title)

    def test_detection_only_event_does_not_invent_fields(self):
        """554 は earthquake を持たない検出通知。埋められない欄は出さない。"""
        embed = eq._build_eew_embed({"code": 554, "type": "Full"})
        self.assertNotIn("不明", embed.description)
        self.assertEqual(embed.fields, [])

    def test_serial_comes_from_issue(self):
        embed = eq._build_eew_embed({
            "code": 556, "issue": {"serial": 3},
            "earthquake": {"originTime": "2026/08/24 12:00:00",
                           "hypocenter": {"name": "茨城県沖", "magnitude": 5.0}},
        })
        self.assertIn("第3報", embed.title)


class DevTestNotifyTests(unittest.TestCase):
    """開発者パネルの通知テスト。本番設定なしで全種類が確かめられること。"""

    def setUp(self):
        from services import dev_test_notify
        self.dt = dev_test_notify
        self.sent = []

        channel = Mock(spec=discord.TextChannel)
        channel.id = 555

        async def send(content=None, embed=None, **kwargs):
            self.sent.append({"content": content, "embed": embed})
            message = Mock()

            async def add_reaction(emoji):
                self.sent.append({"reaction": emoji})

            message.add_reaction = add_reaction
            return message

        channel.send = send
        self.channel = channel

        role = Mock()
        role.mention = "@ロール"
        guild = Mock()
        guild.id = 1
        guild.name = "テスト鯖"
        guild.member_count = 7
        guild.me = None
        guild.members = []
        guild.get_channel.side_effect = lambda i: channel if int(i) == 555 else None
        guild.get_role.side_effect = lambda i: role if i else None
        self.guild = guild
        self.bot = bot_with(guild)

        self.empty = patch.multiple(
            "services.settings_store",
            get_welcome_settings=Mock(return_value={}),
            get_goodbye_settings=Mock(return_value={}),
            get_vc_notify_channel_id=Mock(return_value=0),
            get_sticky_messages=Mock(return_value={}),
            get_reaction_roles=Mock(return_value={}),
        )

    def test_every_kind_sends_without_production_config(self):
        """全種類が、本番のチャンネル設定なしで送信先を指定して確かめられること。"""
        for kind in self.dt.KINDS:
            with self.subTest(kind=kind):
                self.sent.clear()
                with self.empty, patch("services.tts_store.get_tts_settings",
                                       return_value={}):
                    asyncio.run(self.dt.run_test(self.bot, kind, 1, 555))
                self.assertTrue(self.sent, f"{kind} が何も送っていない")

    def test_every_kind_reports_one_reason_when_unconfigured(self):
        for kind in self.dt.KINDS:
            with self.subTest(kind=kind):
                with self.empty,                      patch("services.logging_service.get_log_settings", return_value={}),                      self.assertLogs(self.dt.logger, level="WARNING") as captured:
                    asyncio.run(self.dt.run_test(self.bot, kind, 1, None))
                reasons = [m for m in captured.output if "送れませんでした" in m]
                self.assertEqual(len(reasons), 1)
                self.assertIn("未設定", reasons[0])

    def test_goodbye_uses_the_production_default(self):
        with self.empty:
            asyncio.run(self.dt.run_test(self.bot, "goodbye", 1, 555))
        self.assertIn("去っていった", self.sent[0]["content"])

    def test_logging_reuses_the_production_embed(self):
        with patch("services.logging_service.get_log_settings",
                   return_value={"log_level": "WARNING"}):
            asyncio.run(self.dt.run_test(self.bot, "logging", 1, 555))
        embed = self.sent[0]["embed"]
        self.assertIn("ボットログ", embed.title)
        self.assertIn("WARNING", embed.title)

    def test_reaction_roles_actually_adds_the_emoji(self):
        """絵文字がもう使えない、が主な故障なので一覧表示では確かめられない。"""
        mappings = {"m1": {"emoji": "👍", "role_id": 42, "channel_id": 555}}
        with patch("services.settings_store.get_reaction_roles", return_value=mappings):
            asyncio.run(self.dt.run_test(self.bot, "reaction_roles", 1, 555))
        self.assertIn("👍", [s.get("reaction") for s in self.sent])

    def test_sticky_calls_the_production_path(self):
        called = []

        async def fake_post(channel, guild_id):
            called.append((channel.id, guild_id))

        entry = {"555": {"content": "固定文", "message_id": None}}
        with patch("services.settings_store.get_sticky_messages", return_value=entry),              patch("services.sticky_service.post_sticky", fake_post):
            asyncio.run(self.dt.run_test(self.bot, "sticky", 1, 555))
        self.assertEqual(called, [(555, 1)])

    def test_unknown_kind_is_reported(self):
        with self.assertLogs(self.dt.logger, level="WARNING") as captured:
            asyncio.run(self.dt.run_test(self.bot, "nope", 1, 555))
        self.assertIn("未知の種類", "\n".join(captured.output))


class SettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self.guild_id = 4242

    def test_guild_settings_roundtrip(self):
        store.update_guild_settings(self.guild_id, {"probe": "値"})
        self.assertEqual(store.get_guild_settings(self.guild_id)["probe"], "値")

    def test_unknown_guild_returns_empty_dict_not_an_error(self):
        """通知先の判定はこれを前提に書かれている（例外だと全体が止まる）。"""
        self.assertEqual(store.get_earthquake_settings(999_999_999), {})

    def test_notify_types_key_order_is_stable(self):
        """順序が実行ごとに変わると、管理画面が「未保存」を誤検知し続ける。

        frozenset は文字列ハッシュのランダム化で反復順序が毎回変わるため、
        tuple で持っている。
        """
        first = list(store.get_earthquake_notify_types(self.guild_id))
        self.assertEqual(first, list(store._NOTIFY_TYPE_KEYS))
        self.assertEqual(first, list(store.get_earthquake_notify_types(self.guild_id + 1)))

    def test_notify_types_default_to_enabled(self):
        self.assertTrue(all(store.get_earthquake_notify_types(self.guild_id).values()))

    def test_unknown_notify_type_keys_are_dropped(self):
        store.set_earthquake_notify_types(self.guild_id, {"quake_info": False, "nope": True})
        saved = store.get_earthquake_notify_types(self.guild_id)
        self.assertFalse(saved["quake_info"])
        self.assertNotIn("nope", saved)

    def test_news_feed_state_keeps_only_recent_hashes(self):
        store.add_news_feed(self.guild_id, "feed1", 100, "クエリ", 60)
        store.update_news_feed_state(self.guild_id, "feed1", 1.0, [str(i) for i in range(150)])
        seen = store.get_news_feeds(self.guild_id)["feed1"]["seen_hashes"]
        self.assertEqual(len(seen), 100)
        self.assertEqual(seen[-1], "149")

    def test_async_write_matches_the_sync_one(self):
        store.add_news_feed(self.guild_id, "feed2", 100, "クエリ", 60)
        asyncio.run(store.aupdate_news_feed_state(self.guild_id, "feed2", 9.0, ["a"]))
        row = store.get_news_feeds(self.guild_id)["feed2"]
        self.assertEqual(row["last_run"], 9.0)
        self.assertEqual(row["seen_hashes"], ["a"])


class WelcomeTemplateTests(unittest.TestCase):
    """開発者パネルのテスト送信と本番が同じ描画を使うこと。"""

    def test_placeholders_are_replaced(self):
        out = render_template("{user}/{username}/{server}/{count}",
                              user="U", username="N", server="S", count=3)
        self.assertEqual(out, "U/N/S/3")

    def test_missing_member_count_does_not_render_none(self):
        self.assertEqual(
            render_template("{count}", user="", username="", server="", count=None), "0")

    def test_defaults_are_shared(self):
        self.assertIn("{user}", DEFAULT_WELCOME)
        self.assertIn("{username}", DEFAULT_GOODBYE)


class UrlSafetyTests(unittest.TestCase):
    def test_public_url_passes(self):
        validate_public_http_url("https://example.com/path")

    def test_private_and_loopback_are_blocked(self):
        for url in ("http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
                    "http://169.254.169.254/", "http://localhost/", "http://[::1]/"):
            with self.subTest(url=url), self.assertRaises(URLSafetyError):
                validate_public_http_url(url)

    def test_non_http_schemes_are_blocked(self):
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/"):
            with self.subTest(url=url), self.assertRaises(URLSafetyError):
                validate_public_http_url(url)

    def test_credentials_in_the_url_are_blocked(self):
        with self.assertRaises(URLSafetyError):
            validate_public_http_url("https://user:pass@example.com/")

    def test_missing_scheme_is_blocked(self):
        with self.assertRaises(URLSafetyError):
            validate_public_http_url("example.com")


class NewsFaviconTests(unittest.TestCase):
    def test_domain_becomes_a_favicon_url(self):
        url = _favicon_url("https://www.example.co.jp")
        self.assertIn("www.example.co.jp", url)

    def test_www_prefix_is_kept_intact(self):
        """lstrip("www.") は文字集合を剥がすため 'wsj.com' が 'sj.com' になる。"""
        self.assertIn("www.wsj.com", _favicon_url("https://www.wsj.com"))

    def test_no_domain_gives_none(self):
        self.assertIsNone(_favicon_url(""))
        self.assertIsNone(_favicon_url("not a url"))



class VoiceSessionTests(unittest.TestCase):
    """読み上げと録音がひとつの接続を共有するための層。"""

    def setUp(self):
        from services import voice_session
        self.vs = voice_session
        self.vs._clients.clear()
        self.vs._holds.clear()
        self.vs._locks.clear()

    def test_hold_prevents_release(self):
        """録音中に読み上げ側の「VCが空になったら切る」で落とされないこと。"""
        client = Mock(spec=discord.VoiceClient)
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")

        self.assertFalse(asyncio.run(self.vs.release(1)))
        client.disconnect.assert_not_called()
        self.assertIn(1, self.vs._clients)

    def test_release_works_once_the_hold_is_gone(self):
        client = Mock(spec=discord.VoiceClient)
        client.disconnect = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")
        self.vs.unhold(1, "recording")

        self.assertTrue(asyncio.run(self.vs.release(1)))
        self.assertNotIn(1, self.vs._clients)

    def test_force_release_ignores_the_hold(self):
        client = Mock(spec=discord.VoiceClient)
        client.disconnect = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")

        self.assertTrue(asyncio.run(self.vs.release(1, force=True)))
        self.assertFalse(self.vs.is_held(1))

    def test_multiple_holders_each_have_to_let_go(self):
        self.vs.hold(1, "recording")
        self.vs.hold(1, "something-else")
        self.vs.unhold(1, "recording")
        self.assertTrue(self.vs.is_held(1))
        self.vs.unhold(1, "something-else")
        self.assertFalse(self.vs.is_held(1))

    def test_held_connection_is_not_moved_to_another_channel(self):
        """録音中に読み上げの都合で別VCへ連れ出されると録音が途切れる。"""
        client = Mock(spec=discord.VoiceClient)
        client.is_connected.return_value = True
        client.channel = Mock(id=10)
        client.move_to = Mock()
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")

        guild = Mock()
        guild.id = 1
        got = asyncio.run(self.vs.acquire(guild, 99, purpose="tts"))

        self.assertIs(got, client)
        client.move_to.assert_not_called()

    def test_unheld_connection_moves_normally(self):
        client = Mock(spec=discord.VoiceClient)
        client.is_connected.return_value = True
        client.channel = Mock(id=10)
        client.move_to = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client

        target = Mock(spec=discord.VoiceChannel)
        guild = Mock()
        guild.id = 1
        guild.get_channel.return_value = target

        got = asyncio.run(self.vs.acquire(guild, 99, purpose="tts"))
        self.assertIs(got, client)
        client.move_to.assert_called_once()


class RecordingTests(unittest.TestCase):
    """録音のトラック生成。ffmpeg を実際に動かして中身を確かめる。"""

    def setUp(self):
        import services.recording_service as recording
        self.rec = recording
        self.work = Path(tempfile.mkdtemp(prefix="rectest-"))

    def _tone(self, seconds: float, freq: float = 440.0) -> bytes:
        import math
        import struct
        out = bytearray()
        for i in range(int(self.rec.SAMPLE_RATE * seconds)):
            v = int(12000 * math.sin(2 * math.pi * freq * i / self.rec.SAMPLE_RATE))
            out += struct.pack("<hh", v, v)
        return bytes(out)

    def _duration(self, path: Path) -> float:
        """mp3 の長さを ffmpeg でデコードして測る。"""
        import re
        import subprocess
        from config import DJAUDIO_FFMPEG_PATH
        out = subprocess.run(
            [DJAUDIO_FFMPEG_PATH, "-i", str(path), "-f", "null", "-"],
            capture_output=True, text=True, timeout=60,
        )
        match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", out.stderr)
        if not match:
            return -1.0
        return int(match.group(1)) * 3600 + int(match.group(2)) * 60 + float(match.group(3))

    def test_tracks_are_padded_onto_one_timeline(self):
        """喋った時刻が違っても、全トラックが同じ長さ・同じ時間軸に揃うこと。

        受信できるのは発話中のパケットだけなので、素直に繋ぐと無音が詰まって
        トラック同士がずれる。ずれると重ねて編集できず、マルチトラックの意味が無い。
        """
        started = time.monotonic()
        early = self.rec._TrackWriter(1, "A", self.work / "01-A.mp3", started)
        late = self.rec._TrackWriter(2, "B", self.work / "02-B.mp3", started)

        early.write(self._tone(0.5), 0.0)   # A は冒頭で発話
        late.write(self._tone(0.5), 3.0)    # B は3秒後に発話
        early.close(5.0)
        late.close(5.0)

        a = self._duration(self.work / "01-A.mp3")
        b = self._duration(self.work / "02-B.mp3")
        self.assertAlmostEqual(a, 5.0, delta=0.3)
        self.assertAlmostEqual(b, 5.0, delta=0.3)
        self.assertAlmostEqual(a, b, delta=0.3)

    def test_voiced_time_excludes_the_padding(self):
        started = time.monotonic()
        track = self.rec._TrackWriter(1, "A", self.work / "a.mp3", started)
        track.write(self._tone(1.0), 0.0)
        track.write(self._tone(1.0), 4.0)
        track.close(6.0)
        self.assertAlmostEqual(track.voiced_seconds, 2.0, delta=0.05)

    def _session(self, **kwargs):
        defaults = dict(
            guild_id=999, channel_id=555, channel_name="雑談",
            started_by_id=1, started_by_name="すずき",
            started_at=time.monotonic(), max_seconds=3600, retention_days=7,
        )
        defaults.update(kwargs)
        return self.rec.RecordingSession(**defaults)

    def test_excluded_users_get_no_track(self):
        session = self._session(excluded_user_ids={3})
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.2))
        session.feed(Mock(id=3, display_name="除外された人"), self._tone(0.2))
        self.assertEqual(sorted(session.tracks), [1])
        self.rec._finalize(session, 1.0, "テスト")

    def test_finalize_builds_a_zip_with_one_track_per_speaker(self):
        session = self._session()
        for user_id, name in ((1, "すずき"), (2, "たなか")):
            session.feed(Mock(id=user_id, display_name=name), self._tone(0.2))

        result = self.rec._finalize(session, 2.0, "テスト停止")
        self.assertEqual(result["track_count"], 2)

        from services.djaudio_cache import get_meta, payload_path
        meta = get_meta(result["token"])
        self.assertEqual(meta["kind"], "recording")
        self.assertEqual(meta["extension"], ".zip")

        with zipfile.ZipFile(payload_path(result["token"], meta)) as archive:
            names = archive.namelist()
            info = json.loads(archive.read("info.json").decode("utf-8"))
        self.assertEqual(len([n for n in names if n.endswith(".mp3")]), 2)
        self.assertIn("info.txt", names)
        self.assertEqual({t["名前"] for t in info["トラック"]}, {"すずき", "たなか"})

    def test_retention_days_control_the_link_lifetime(self):
        session = self._session(retention_days=3)
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.2))
        result = self.rec._finalize(session, 1.0, "テスト")

        from services.djaudio_cache import get_meta
        remaining = get_meta(result["token"])["expires_at"] - time.time()
        self.assertAlmostEqual(remaining, 3 * 24 * 3600, delta=60)

    def test_workdir_is_cleaned_up(self):
        session = self._session()
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.2))
        workdir = session.workdir
        self.rec._finalize(session, 1.0, "テスト")
        self.assertFalse(workdir.exists())

    def test_state_file_lets_the_admin_process_see_the_session(self):
        """管理画面は別プロセスなので、状態はファイル越しにしか見えない。"""
        session = self._session()
        self.rec._sessions[999] = session
        try:
            self.rec._write_state()
            state = self.rec.read_state()
        finally:
            self.rec._sessions.pop(999, None)
        self.assertIn("999", state["sessions"])
        self.assertEqual(state["sessions"]["999"]["channel_name"], "雑談")

    def test_start_refuses_without_the_receive_extension(self):
        """受信拡張が無い環境では、黙って失敗せず理由を返すこと。"""
        from services import voice_session
        guild = Mock()
        guild.id = 999
        with patch.object(voice_session, "RECEIVE_AVAILABLE", False):
            with self.assertRaises(self.rec.RecordingError) as caught:
                asyncio.run(self.rec.start_recording(
                    Mock(), guild, Mock(spec=discord.VoiceChannel), started_by=Mock(),
                ))
        self.assertIn("受信", str(caught.exception))


class RecordingSettingsTests(unittest.TestCase):
    def test_defaults_match_the_agreed_limits(self):
        settings = store.get_recording_settings(4243)
        self.assertEqual(settings["max_minutes"], 360)   # 6時間
        self.assertEqual(settings["retention_days"], 7)
        self.assertEqual(settings["excluded_user_ids"], [])

    def test_unknown_keys_are_dropped(self):
        store.set_recording_settings(4243, {"max_minutes": 60, "nope": "x"})
        settings = store.get_recording_settings(4243)
        self.assertEqual(settings["max_minutes"], 60)
        self.assertNotIn("nope", settings)

    def test_excluded_users_survive_a_reread(self):
        store.set_recording_excluded_users(4243, [111, 222])
        self.assertEqual(store.get_recording_settings(4243)["excluded_user_ids"], [111, 222])


class DurationWidgetTests(unittest.TestCase):
    """期間の入力。保存は秒のまま、入力と表示だけ単位を付ける。"""

    def setUp(self):
        from webapp_admin.schema import duration
        from webapp_admin.schema.registry import PANEL_BY_ID
        self.duration = duration
        self.field = PANEL_BY_ID["djaudio"].field("cache_ttl")

    def test_largest_whole_unit_is_used(self):
        cases = {60: "1分", 600: "10分", 3600: "1時間",
                 86400: "1日", 2592000: "30日", 90: "90秒", 5400: "90分"}
        for seconds, expected in cases.items():
            with self.subTest(seconds=seconds):
                self.assertEqual(self.duration.humanize(seconds), expected)

    def test_cache_ttl_accepts_thirty_days(self):
        """30日まで指定できること。以前は 86400 秒（1日）で頭打ちだった。"""
        self.assertEqual(self.field.widget.value, "duration")
        self.assertEqual(self.field.max, 30 * 86400)
        self.assertEqual(validate_field(self.field, 30 * 86400, {}), 2592000)

    def test_over_the_limit_is_reported_in_days_not_seconds(self):
        """「2592000 以下」では何日なのか読み取れない。"""
        with self.assertRaises(InvalidValue) as caught:
            validate_field(self.field, 30 * 86400 + 1, {})
        self.assertIn("30日", str(caught.exception))
        self.assertNotIn("2592000", str(caught.exception))

    def test_below_the_minimum_is_reported_in_minutes(self):
        with self.assertRaises(InvalidValue) as caught:
            validate_field(self.field, 59, {})
        self.assertIn("1分", str(caught.exception))

    def test_non_numeric_is_rejected(self):
        with self.assertRaises(InvalidValue):
            validate_field(self.field, "しばらく", {})

    def test_store_and_schema_share_the_same_ceiling(self):
        """片方だけ古いと、画面で入れた値が黙って丸められる。"""
        self.assertEqual(store._CACHE_TTL_MAX, self.field.max)
        self.assertEqual(store._CACHE_TTL_MIN, self.field.min)

    def test_thirty_days_survives_a_save_and_reread(self):
        store.set_djaudio_settings(4244, {"cache_ttl": 30 * 86400})
        self.assertEqual(store.get_djaudio_cache_ttl(4244), 2592000)

    def test_values_beyond_the_ceiling_are_clamped(self):
        store.set_djaudio_settings(4244, {"cache_ttl": 99_999_999})
        self.assertEqual(store.get_djaudio_cache_ttl(4244), 30 * 86400)

    def test_existing_second_values_still_load(self):
        """保存形式は秒のままなので、以前の設定がそのまま読めること。"""
        store.set_djaudio_settings(4245, {"cache_ttl": 600})
        self.assertEqual(store.get_djaudio_cache_ttl(4245), 600)

    def test_client_and_server_split_durations_the_same_way(self):
        """widgets.js の単位表と webapp_admin/schema/duration.py がずれていないこと。"""
        js = Path(__file__).resolve().parent.parent / "webapp_admin/static/js/forms/widgets.js"
        text = js.read_text(encoding="utf-8")
        for label, factor in self.duration.UNITS:
            with self.subTest(unit=label):
                self.assertIn(f'["{label}", {factor}]', text)


class UnlimitedRecordingTests(unittest.TestCase):
    """max_minutes=0 は「時間では止めない」。VC が無人になるまで録り続ける。"""

    def setUp(self):
        import services.recording_service as recording
        self.rec = recording

    def _session(self, max_seconds):
        return self.rec.RecordingSession(
            guild_id=999, channel_id=555, channel_name="雑談VC",
            started_by_id=1, started_by_name="すずき",
            started_at=time.monotonic(), max_seconds=max_seconds, retention_days=7,
        )

    def test_zero_means_unlimited(self):
        self.assertTrue(self._session(0).is_unlimited)
        self.assertTrue(self._session(self.rec.UNLIMITED).is_unlimited)

    def test_a_real_limit_is_not_unlimited(self):
        self.assertFalse(self._session(3600).is_unlimited)

    def test_status_carries_the_flag_to_the_admin_screen(self):
        """管理画面は別プロセスなので、状態ファイル越しに伝わる必要がある。"""
        self.assertTrue(self._session(0).status()["unlimited"])
        self.assertFalse(self._session(3600).status()["unlimited"])

    def test_negative_settings_do_not_become_a_huge_limit(self):
        """設定が壊れていても「負の上限」で即停止したりしないこと。"""
        self.assertTrue(self._session(-60).is_unlimited)

    def test_empty_vc_is_detected(self):
        """無人判定。bot だけ残っている状態を「無人」とみなす。"""
        session = self._session(0)
        human = Mock()
        human.bot = False
        robot = Mock()
        robot.bot = True

        for members, expected in ((None, False), ([], True), ([robot], True),
                                  ([human], False), ([human, robot], False)):
            with self.subTest(members=members):
                channel = Mock()
                channel.members = members
                guild = Mock()
                guild.get_channel.return_value = channel
                bot = Mock()
                bot.get_guild.return_value = guild
                self.assertIs(self.rec._vc_is_empty(bot, session), expected)

    def test_unknown_guild_is_not_treated_as_empty(self):
        """判断できないときに止めてしまうと、録音が勝手に切れる。"""
        bot = Mock()
        bot.get_guild.return_value = None
        self.assertFalse(self.rec._vc_is_empty(bot, self._session(0)))


class RecordingSettingsRangeTests(unittest.TestCase):
    def test_zero_is_accepted_and_kept(self):
        store.set_recording_settings(4246, {"max_minutes": 0})
        self.assertEqual(store.get_recording_settings(4246)["max_minutes"], 0)

if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
