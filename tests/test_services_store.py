"""services/sticky_service.py, metal_service.py, tts_store.py, welcome_service.py のテスト。

    python -m unittest tests.test_services_store -v

この4モジュールはこれまでテストが無く、カバレッジも1〜3割台だった。監査で
洗い出した分岐をここに固定する。Discord とネットワークには一切触らない。
discord.py の型は Mock(spec=...) で差し替え、外部APIは aiohttp.ClientSession
そのものを差し替える。設定ストア（tts_store）は既存の tests/test_services.py
と同じく SETTINGS_DIR を一時ディレクトリへ向けたうえで、実物の
services.settings_store を使う（JSONファイルのみで、Postgres 等の実DBは
使わない）。
"""

import asyncio
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

# services/* は読み込み時に SETTINGS_DIR を解決するため、import より前に差し替える。
# tests/test_services.py と同じ変数を setdefault するだけなので、どちらが先に
# import されても同じ一時ディレクトリに落ち着く。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="services-store-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="services-store-cache-"))

from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aiohttp  # noqa: E402
import discord  # noqa: E402

import services.metal_service as metal_service  # noqa: E402
import services.sticky_service as sticky_service  # noqa: E402
import services.tts_store as tts_store  # noqa: E402
import services.welcome_service as welcome_service  # noqa: E402
from services import settings_store as store  # noqa: E402
from services.metal_service import MetalPriceError  # noqa: E402


def text_channel(channel_id: int = 555):
    channel = Mock(spec=discord.TextChannel)
    channel.id = channel_id
    return channel


def member_with(*, mention="<@1>", username="U#0001", server="鯖", count=7, guild_id=1):
    """discord.Member 相当。str(member) が使われるので MagicMock で __str__ を差す。"""
    guild = Mock()
    guild.id = guild_id
    guild.name = server
    guild.member_count = count
    member = MagicMock(spec=discord.Member)
    member.mention = mention
    member.guild = guild
    member.__str__.return_value = username
    return member


# ──────────────────────────────────────────────
# sticky_service
# ──────────────────────────────────────────────


class StickyServiceTestCase(unittest.TestCase):
    """全スティッキーテストの共通処理。テスト間でロック/pendingフラグが
    残ると次のテストが変な状態から始まってしまうため、毎回クリアする。"""

    def setUp(self):
        sticky_service._locks.clear()
        sticky_service._pending.clear()

    def run_async(self, coro):
        return asyncio.run(coro)


class GetLockTests(StickyServiceTestCase):
    def test_same_channel_reuses_the_same_lock_object(self):
        """チャンネルごとに別ロックだと、同時実行の直列化が保証できない。"""
        a = sticky_service._get_lock(111)
        b = sticky_service._get_lock(111)
        self.assertIs(a, b)

    def test_different_channels_get_different_locks(self):
        a = sticky_service._get_lock(111)
        b = sticky_service._get_lock(222)
        self.assertIsNot(a, b)


class PostOnceTests(StickyServiceTestCase):
    def test_sends_and_persists_the_new_message_id_via_awrite(self):
        """message_id を保存し損なうと、次の投稿で古いメッセージを消せなくなる。

        永続化は awrite（別スレッド実行）経由であること自体も確かめる。直呼びに
        戻すと、非同期の文脈からイベントループが settings.json のロック待ちで
        止まる（CONTRIBUTING 5.）。
        """
        channel = text_channel(777)
        channel.send.return_value = Mock(id=9999)
        awrite_mock = AsyncMock()
        with patch.object(sticky_service, "awrite", awrite_mock):
            self.run_async(sticky_service._post_once(channel, 1, "こんにちは", None))

        channel.send.assert_awaited_once_with("📌 こんにちは")
        channel.fetch_message.assert_not_called()
        self.assertTrue(awrite_mock.called)
        args = awrite_mock.call_args.args
        self.assertIs(args[0], sticky_service.update_sticky_message_id)
        self.assertEqual(args[1:], (1, 777, 9999))

    def test_deletes_the_old_message_before_posting_a_new_one(self):
        old_msg = Mock(spec=discord.Message)
        channel = text_channel(777)
        channel.fetch_message.return_value = old_msg
        channel.send.return_value = Mock(id=42)
        with patch.object(sticky_service, "awrite", AsyncMock()):
            self.run_async(sticky_service._post_once(channel, 1, "本文", 555))

        channel.fetch_message.assert_awaited_once_with(555)
        old_msg.delete.assert_awaited_once()

    def test_old_message_already_gone_does_not_block_the_new_post(self):
        """WebUIから消された後にBotが追いかけて消そうとするのはよくある競合。
        NotFound で全体が落ちると、以後スティッキーが二度と更新されなくなる。"""
        channel = text_channel(777)
        channel.fetch_message.side_effect = discord.NotFound(Mock(status=404), "Unknown Message")
        channel.send.return_value = Mock(id=42)
        with patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock:
            self.run_async(sticky_service._post_once(channel, 1, "本文", 555))

        channel.send.assert_awaited_once()
        self.assertTrue(awrite_mock.called)

    def test_send_failure_is_logged_and_does_not_persist_a_stale_id(self):
        """送信に失敗したのに旧IDを更新してしまうと、二度と消せない/直せない
        スティッキーが残る。"""
        channel = text_channel(777)
        channel.send.side_effect = discord.HTTPException(Mock(status=500), "boom")
        with (
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
            self.assertLogs(sticky_service.logger, level="ERROR") as captured,
        ):
            self.run_async(sticky_service._post_once(channel, 1, "本文", None))

        awrite_mock.assert_not_called()
        self.assertTrue(any("send error" in m for m in captured.output))


class PostLatestAndPostStickyTests(StickyServiceTestCase):
    def test_no_entry_configured_sends_nothing(self):
        channel = text_channel(1)
        with patch.object(sticky_service, "get_sticky_messages", Mock(return_value={})):
            self.run_async(sticky_service.post_sticky(channel, 1))
        channel.send.assert_not_called()

    def test_posts_the_configured_content(self):
        channel = text_channel(1)
        entry = {"1": {"content": "定期connect", "message_id": None}}
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "awrite", AsyncMock()),
        ):
            self.run_async(sticky_service.post_sticky(channel, 1))
        channel.send.assert_awaited_once_with("📌 定期connect")

    def test_post_sticky_clears_the_pending_flag(self):
        """コマンドで即時投稿したのに古い pending が残っていると、次のメッセージ
        到着時にまた重複投稿してしまう。"""
        channel = text_channel(1)
        sticky_service._pending[1] = True
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value={})),
            patch.object(sticky_service, "awrite", AsyncMock()),
        ):
            self.run_async(sticky_service.post_sticky(channel, 1))
        self.assertFalse(sticky_service._pending[1])


class DeleteStickyTests(StickyServiceTestCase):
    def test_deletes_the_discord_message_and_removes_the_setting(self):
        channel = text_channel(1)
        old_msg = Mock(spec=discord.Message)
        channel.fetch_message.return_value = old_msg
        entry = {"1": {"content": "x", "message_id": 321}}
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
        ):
            self.run_async(sticky_service.delete_sticky(channel, 1))

        channel.fetch_message.assert_awaited_once_with(321)
        old_msg.delete.assert_awaited_once()
        args = awrite_mock.call_args.args
        self.assertIs(args[0], sticky_service.remove_sticky_message)
        self.assertEqual(args[1:], (1, 1))

    def test_removes_the_setting_even_when_there_was_no_message_id(self):
        """message_id が無くても設定は必ず消す。ここを条件付きにすると、
        投稿前に消した場合に設定だけ残り続ける。"""
        channel = text_channel(1)
        entry = {"1": {"content": "x", "message_id": None}}
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
        ):
            self.run_async(sticky_service.delete_sticky(channel, 1))
        channel.fetch_message.assert_not_called()
        self.assertTrue(awrite_mock.called)

    def test_missing_discord_message_does_not_prevent_removal(self):
        channel = text_channel(1)
        channel.fetch_message.side_effect = discord.NotFound(Mock(status=404), "Unknown Message")
        entry = {"1": {"content": "x", "message_id": 321}}
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
        ):
            self.run_async(sticky_service.delete_sticky(channel, 1))
        self.assertTrue(awrite_mock.called)


class HandleStickyTests(StickyServiceTestCase):
    def _message(self, *, guild=Mock(id=1), bot=False, channel=None):
        return SimpleNamespace(guild=guild, author=SimpleNamespace(bot=bot), channel=channel or text_channel(1))

    def test_dm_message_is_ignored(self):
        message = self._message(guild=None)
        with patch.object(sticky_service, "get_sticky_messages") as get_mock:
            self.run_async(sticky_service.handle_sticky(message))
        get_mock.assert_not_called()

    def test_bot_message_is_ignored(self):
        """Bot自身の投稿にまで反応すると自己増殖する。"""
        message = self._message(bot=True)
        with patch.object(sticky_service, "get_sticky_messages") as get_mock:
            self.run_async(sticky_service.handle_sticky(message))
        get_mock.assert_not_called()

    def test_channel_without_a_sticky_does_nothing(self):
        message = self._message()
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value={})),
            patch.object(sticky_service, "_post_latest", AsyncMock()) as post_mock,
        ):
            self.run_async(sticky_service.handle_sticky(message))
        post_mock.assert_not_called()

    def test_pending_delete_is_not_reposted(self):
        """削除待ちのチャンネルに新しい発言が来ても、消す予定のものを
        また貼り直してはいけない。"""
        channel = text_channel(1)
        message = self._message(channel=channel)
        entry = {"1": {"content": "x", "message_id": 1, "pending": "delete"}}
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "_post_latest", AsyncMock()) as post_mock,
        ):
            self.run_async(sticky_service.handle_sticky(message))
        post_mock.assert_not_called()

    def test_normal_message_reposts_the_sticky(self):
        channel = text_channel(1)
        message = self._message(channel=channel)
        entry = {"1": {"content": "本文", "message_id": None}}
        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "awrite", AsyncMock()),
        ):
            self.run_async(sticky_service.handle_sticky(message))
        channel.send.assert_awaited_once_with("📌 本文")

    def test_locked_channel_defers_instead_of_blocking(self):
        """ロック中にもう1通来たら、待たずに pending フラグだけ立てて返る。
        ここでブロックすると、連投のたびにイベントループが詰まる。"""
        channel = text_channel(1)
        message = self._message(channel=channel)
        entry = {"1": {"content": "本文", "message_id": None}}

        async def scenario():
            lock = sticky_service._get_lock(1)
            await lock.acquire()
            try:
                with patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)):
                    await sticky_service.handle_sticky(message)
            finally:
                lock.release()

        self.run_async(scenario())
        channel.send.assert_not_called()
        self.assertTrue(sticky_service._pending[1])

    def test_a_message_arriving_during_the_post_triggers_one_more_repost(self):
        """投稿中にロック待ちで弾かれたメッセージがあった場合、取りこぼさず
        もう一度だけ最新設定で貼り直すこと。"""
        channel = text_channel(1)
        message = self._message(channel=channel)
        entry = {"1": {"content": "本文", "message_id": None}}
        calls = {"n": 0}

        async def fake_post_latest(ch, guild_id):
            calls["n"] += 1
            if calls["n"] == 1:
                sticky_service._pending[1] = True

        with (
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=entry)),
            patch.object(sticky_service, "_post_latest", fake_post_latest),
        ):
            self.run_async(sticky_service.handle_sticky(message))
        self.assertEqual(calls["n"], 2)


class ProcessPendingStickiesTests(StickyServiceTestCase):
    def _bot(self, guild):
        bot = Mock()
        bot.get_guild.side_effect = lambda gid: guild if gid == 1 else None
        return bot

    def test_entries_without_a_pending_flag_are_skipped(self):
        stickies = {"1": {"content": "x"}}
        bot = Mock()
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=stickies)),
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        bot.get_guild.assert_not_called()

    def test_unknown_guild_is_skipped(self):
        stickies = {"1": {"content": "x", "pending": "post"}}
        bot = Mock()
        bot.get_guild.return_value = None
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=stickies)),
            patch.object(sticky_service, "_post_latest", AsyncMock()) as post_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        post_mock.assert_not_called()

    def test_non_text_channel_is_skipped(self):
        stickies = {"9": {"content": "x", "pending": "post"}}
        guild = Mock()
        guild.get_channel.return_value = Mock(spec=discord.VoiceChannel)
        bot = self._bot(guild)
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=stickies)),
            patch.object(sticky_service, "_post_latest", AsyncMock()) as post_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        post_mock.assert_not_called()

    def test_pending_post_reposts_when_still_fresh(self):
        channel = text_channel(9)
        stickies = {"9": {"content": "x", "pending": "post"}}
        fresh = {"9": {"content": "x", "pending": "post"}}
        guild = Mock()
        guild.get_channel.return_value = channel
        bot = self._bot(guild)
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(side_effect=[stickies, fresh])),
            patch.object(sticky_service, "_post_latest", AsyncMock()) as post_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        post_mock.assert_awaited_once_with(channel, 1)

    def test_pending_post_skipped_when_already_handled_meanwhile(self):
        """handle_sticky がロック待ちの間に処理してしまっていたら、
        定期タスク側は二重投稿しないこと。"""
        channel = text_channel(9)
        stickies = {"9": {"content": "x", "pending": "post"}}
        fresh_no_longer_pending = {"9": {"content": "x", "message_id": 1}}
        guild = Mock()
        guild.get_channel.return_value = channel
        bot = self._bot(guild)
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(side_effect=[stickies, fresh_no_longer_pending])),
            patch.object(sticky_service, "_post_latest", AsyncMock()) as post_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        post_mock.assert_not_called()

    def test_pending_delete_removes_discord_message_and_setting(self):
        channel = text_channel(9)
        old_msg = Mock(spec=discord.Message)
        channel.fetch_message.return_value = old_msg
        stickies = {"9": {"content": "x", "pending": "delete", "message_id": 55}}
        guild = Mock()
        guild.get_channel.return_value = channel
        bot = self._bot(guild)
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=stickies)),
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        old_msg.delete.assert_awaited_once()
        args = awrite_mock.call_args.args
        self.assertIs(args[0], sticky_service.remove_sticky_message)
        self.assertEqual(args[1:], (1, 9))

    def test_pending_delete_missing_discord_message_still_removes_the_setting(self):
        """定期タスクが追いつく前に誰かが手動で消していても、設定は必ず片付ける。"""
        channel = text_channel(9)
        channel.fetch_message.side_effect = discord.NotFound(Mock(status=404), "Unknown Message")
        stickies = {"9": {"content": "x", "pending": "delete", "message_id": 55}}
        guild = Mock()
        guild.get_channel.return_value = channel
        bot = self._bot(guild)
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=stickies)),
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        self.assertTrue(awrite_mock.called)

    def test_pending_delete_without_a_message_id_still_removes_the_setting(self):
        channel = text_channel(9)
        stickies = {"9": {"content": "x", "pending": "delete", "message_id": None}}
        guild = Mock()
        guild.get_channel.return_value = channel
        bot = self._bot(guild)
        with (
            patch.object(sticky_service, "get_all_guild_ids", Mock(return_value=[1])),
            patch.object(sticky_service, "get_sticky_messages", Mock(return_value=stickies)),
            patch.object(sticky_service, "awrite", AsyncMock()) as awrite_mock,
        ):
            self.run_async(sticky_service.process_pending_stickies(bot))
        channel.fetch_message.assert_not_called()
        self.assertTrue(awrite_mock.called)


# ──────────────────────────────────────────────
# metal_service
# ──────────────────────────────────────────────


class _FakeMetalResponse:
    def __init__(self, status=200, payload=None, json_error=False, text="bad response"):
        self.status = status
        self._payload = payload if payload is not None else {"success": True, "rates": {}}
        self._json_error = json_error
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def json(self):
        if self._json_error:
            raise aiohttp.ContentTypeError(None, ())
        return self._payload

    async def text(self):
        return self._text


class _FakeMetalSession:
    def __init__(self, response, captured):
        self._response = response
        self._captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def get(self, url, params=None, **kwargs):
        self._captured["url"] = url
        self._captured["params"] = params
        return self._response


class MetalServiceTestCase(unittest.TestCase):
    def setUp(self):
        # プロセス内キャッシュはモジュール共有なので、他のテストの残骸を引きずらない。
        metal_service._price_cache = {}
        self._api_key_patch = patch.object(metal_service, "METALPRICE_API_KEY", "test-key")
        self._api_key_patch.start()
        self.addCleanup(self._api_key_patch.stop)

    def run_async(self, coro):
        return asyncio.run(coro)

    def patch_session(self, response):
        captured = {}

        def make_session(*args, **kwargs):
            return _FakeMetalSession(response, captured)

        return patch.object(metal_service.aiohttp, "ClientSession", make_session), captured


class FetchMetalPricesLiveTests(MetalServiceTestCase):
    def test_no_codes_returns_empty_without_calling_the_api(self):
        with patch.object(metal_service.aiohttp, "ClientSession") as session_cls:
            result = self.run_async(metal_service._fetch_metal_prices_live([]))
        self.assertEqual(result, {})
        session_cls.assert_not_called()

    def test_missing_api_key_raises_without_calling_the_api(self):
        with patch.object(metal_service, "METALPRICE_API_KEY", ""):
            with patch.object(metal_service.aiohttp, "ClientSession") as session_cls:
                with self.assertRaises(MetalPriceError):
                    self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))
        session_cls.assert_not_called()

    def test_converts_troy_ounce_rate_to_price_per_gram(self):
        response = _FakeMetalResponse(payload={"success": True, "rates": {"JPYXAU": 31103.5}})
        patcher, captured = self.patch_session(response)
        with patcher:
            result = self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))
        self.assertAlmostEqual(result["XAU"], 1000.0)
        self.assertEqual(captured["params"]["currencies"], "XAU")
        self.assertEqual(captured["params"]["api_key"], "test-key")

    def test_missing_success_key_defaults_to_success(self):
        """success キーそのものが無い応答（実際のAPIでよくある形）を
        「失敗」扱いにすると、正常時まで全部エラーになる。"""
        response = _FakeMetalResponse(payload={"rates": {"JPYXAG": 62.207}})
        patcher, _ = self.patch_session(response)
        with patcher:
            result = self.run_async(metal_service._fetch_metal_prices_live(["XAG"]))
        self.assertAlmostEqual(result["XAG"], 2.0)

    def test_non_200_status_raises_with_the_error_message(self):
        response = _FakeMetalResponse(status=401, payload={"error": {"message": "invalid key"}})
        patcher, _ = self.patch_session(response)
        with patcher:
            with self.assertRaises(MetalPriceError) as ctx:
                self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))
        self.assertIn("invalid key", str(ctx.exception))

    def test_non_200_status_without_error_field_falls_back_to_raw_payload(self):
        response = _FakeMetalResponse(status=500, payload={"whatever": 1})
        patcher, _ = self.patch_session(response)
        with patcher:
            with self.assertRaises(MetalPriceError) as ctx:
                self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))
        self.assertIn("whatever", str(ctx.exception))

    def test_explicit_success_false_is_treated_as_failure(self):
        response = _FakeMetalResponse(status=200, payload={"success": False, "error": {"message": "down"}})
        patcher, _ = self.patch_session(response)
        with patcher:
            with self.assertRaises(MetalPriceError):
                self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))

    def test_bad_content_type_raises_with_status_and_body_snippet(self):
        response = _FakeMetalResponse(json_error=True, text="<html>500</html>")
        patcher, _ = self.patch_session(response)
        with patcher:
            with self.assertRaises(MetalPriceError) as ctx:
                self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))
        self.assertIn("<html>500</html>", str(ctx.exception))

    def test_no_matching_rates_in_the_response_raises(self):
        response = _FakeMetalResponse(payload={"success": True, "rates": {"JPYXAG": 10.0}})
        patcher, _ = self.patch_session(response)
        with patcher:
            with self.assertRaises(MetalPriceError):
                self.run_async(metal_service._fetch_metal_prices_live(["XAU"]))


class FetchMetalPricesPerGramCacheTests(MetalServiceTestCase):
    def test_empty_list_returns_empty_without_calling_live_fetch(self):
        with patch.object(metal_service, "_fetch_metal_prices_live", AsyncMock()) as live:
            result = self.run_async(metal_service.fetch_metal_prices_per_gram([]))
        self.assertEqual(result, {})
        live.assert_not_called()

    def test_duplicate_and_falsy_codes_collapse_to_one_request(self):
        live = AsyncMock(return_value={"XAU": 1000.0})
        with patch.object(metal_service, "_fetch_metal_prices_live", live):
            result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU", "", "XAU"]))
        self.assertEqual(result, {"XAU": 1000.0})
        live.assert_awaited_once_with(["XAU"])

    def test_fresh_cache_entry_skips_the_api_entirely(self):
        """キャッシュが効いていないと、無料枠(月100回)をコマンド連打で
        使い切ってしまう。"""
        metal_service._price_cache["XAU"] = (1234.5, time.monotonic())
        with (
            patch.object(metal_service, "METALPRICE_CACHE_TTL_SECONDS", 1800),
            patch.object(metal_service, "_fetch_metal_prices_live", AsyncMock()) as live,
        ):
            result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU"]))
        self.assertEqual(result, {"XAU": 1234.5})
        live.assert_not_called()

    def test_expired_cache_entry_triggers_a_refetch(self):
        metal_service._price_cache["XAU"] = (1111.0, time.monotonic() - 10_000)
        live = AsyncMock(return_value={"XAU": 2222.0})
        with (
            patch.object(metal_service, "METALPRICE_CACHE_TTL_SECONDS", 5),
            patch.object(metal_service, "_fetch_metal_prices_live", live),
        ):
            result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU"]))
        self.assertEqual(result, {"XAU": 2222.0})
        live.assert_awaited_once_with(["XAU"])

    def test_only_the_missing_codes_are_requested(self):
        metal_service._price_cache["XAU"] = (1000.0, time.monotonic())
        live = AsyncMock(return_value={"XAG": 20.0})
        with (
            patch.object(metal_service, "METALPRICE_CACHE_TTL_SECONDS", 1800),
            patch.object(metal_service, "_fetch_metal_prices_live", live),
        ):
            result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU", "XAG"]))
        self.assertEqual(result, {"XAU": 1000.0, "XAG": 20.0})
        live.assert_awaited_once_with(["XAG"])

    def test_single_missing_code_batch_failure_propagates_without_fallback(self):
        live = AsyncMock(side_effect=MetalPriceError("down"))
        with patch.object(metal_service, "_fetch_metal_prices_live", live):
            with self.assertRaises(MetalPriceError):
                self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU"]))
        self.assertEqual(live.await_count, 1)

    def test_multi_code_batch_failure_falls_back_to_individual_fetches(self):
        """カンマ区切りの複数指定をAPIが拒否した場合の保険。ここが働かないと
        日次スナップショット全体がその日だけ欠損する。"""

        async def side_effect(codes):
            if len(codes) > 1:
                raise MetalPriceError("batch rejected")
            if codes == ["XAU"]:
                return {"XAU": 1000.0}
            raise MetalPriceError("still down")

        with patch.object(metal_service, "_fetch_metal_prices_live", AsyncMock(side_effect=side_effect)):
            with self.assertLogs(metal_service.logger, level="WARNING"):
                result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU", "XAG"]))
        self.assertEqual(result, {"XAU": 1000.0})

    def test_batch_response_missing_a_code_falls_back_for_that_code_only(self):
        async def side_effect(codes):
            if len(codes) > 1:
                return {"XAU": 1000.0}
            return {"XAG": 20.0}

        with patch.object(metal_service, "_fetch_metal_prices_live", AsyncMock(side_effect=side_effect)):
            with self.assertLogs(metal_service.logger, level="WARNING"):
                result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU", "XAG"]))
        self.assertEqual(result, {"XAU": 1000.0, "XAG": 20.0})

    def test_when_nothing_can_be_resolved_it_raises(self):
        async def side_effect(codes):
            raise MetalPriceError("down")

        with patch.object(metal_service, "_fetch_metal_prices_live", AsyncMock(side_effect=side_effect)):
            with self.assertLogs(metal_service.logger, level="WARNING"):
                with self.assertRaises(MetalPriceError):
                    self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU", "XAG"]))

    def test_value_cached_by_another_task_while_waiting_for_the_lock_is_reused(self):
        """ロック取得を待っている間に別タスクが同じ金属を取得し終えていたら、
        ロックの中でもう一度APIを叩いてはいけない（無料枠を無駄に消費する）。

        time.monotonic を丸ごと差し替えると asyncio 自身の内部呼び出しまで
        巻き込んでタイミングがずれるため、_cached_price だけを差し替える。
        """
        calls = {"n": 0}

        def fake_cached_price(code, now):
            calls["n"] += 1
            if calls["n"] == 1:
                # 最初の楽観チェック（ロック取得前）では未取得。
                return None
            # ロック取得後の再チェックでは、既に別タスクが書き込んだ体で進める。
            return 999.0

        with (
            patch.object(metal_service, "_cached_price", fake_cached_price),
            patch.object(metal_service, "_fetch_metal_prices_live", AsyncMock()) as live,
        ):
            result = self.run_async(metal_service.fetch_metal_prices_per_gram(["XAU"]))
        self.assertEqual(result, {"XAU": 999.0})
        live.assert_not_called()


class FetchMetalPricePerGramTests(MetalServiceTestCase):
    def test_returns_the_single_price(self):
        with patch.object(metal_service, "fetch_metal_prices_per_gram", AsyncMock(return_value={"XAU": 1000.0})):
            price = self.run_async(metal_service.fetch_metal_price_per_gram("XAU"))
        self.assertEqual(price, 1000.0)

    def test_missing_code_in_the_result_raises(self):
        with patch.object(metal_service, "fetch_metal_prices_per_gram", AsyncMock(return_value={})):
            with self.assertRaises(MetalPriceError):
                self.run_async(metal_service.fetch_metal_price_per_gram("XAU"))


class CalculateMetalValueTests(MetalServiceTestCase):
    def test_non_positive_grams_raises_without_calling_the_api(self):
        with patch.object(metal_service, "fetch_metal_price_per_gram", AsyncMock()) as fetch:
            with self.assertRaises(MetalPriceError):
                self.run_async(metal_service.calculate_metal_value(0, "XAU", {"K18": 0.75}))
        fetch.assert_not_called()

    def test_computes_the_value_for_every_purity_grade(self):
        with patch.object(metal_service, "fetch_metal_price_per_gram", AsyncMock(return_value=1000.0)) as fetch:
            result = self.run_async(metal_service.calculate_metal_value(2.0, "XAU", {"K24": 1.0, "K18": 0.75}))
        fetch.assert_awaited_once_with("XAU")
        self.assertEqual(result, {"K24": 2000, "K18": 1500})


# ──────────────────────────────────────────────
# tts_store（実物の settings_store を一時ディレクトリで動かす）
# ──────────────────────────────────────────────

_GUILD_SEQ = [900_000_001]


def next_guild_id() -> int:
    """テストごとに別ギルドIDを使い、settings.json 上で互いに干渉しないようにする。"""
    _GUILD_SEQ[0] += 1
    return _GUILD_SEQ[0]


class TtsSimpleSettingsTests(unittest.TestCase):
    def setUp(self):
        self.guild_id = next_guild_id()

    def test_unset_guild_returns_empty_settings(self):
        self.assertEqual(tts_store.get_tts_settings(self.guild_id), {})

    def test_set_enabled_true_then_false_preserves_other_keys(self):
        tts_store.set_tts_default_voice(self.guild_id, "voice-a")
        tts_store.set_tts_enabled(self.guild_id, True)
        self.assertTrue(tts_store.get_tts_settings(self.guild_id)["enabled"])
        self.assertEqual(tts_store.get_tts_settings(self.guild_id)["default_voice"], "voice-a")

        tts_store.set_tts_enabled(self.guild_id, False)
        settings = tts_store.get_tts_settings(self.guild_id)
        self.assertFalse(settings["enabled"])
        self.assertEqual(settings["default_voice"], "voice-a")

    def test_set_channels_preserves_previously_set_enabled_flag(self):
        tts_store.set_tts_enabled(self.guild_id, True)
        tts_store.set_tts_channels(self.guild_id, [1, 2, 3], 99)
        settings = tts_store.get_tts_settings(self.guild_id)
        self.assertEqual(settings["watch_channel_ids"], [1, 2, 3])
        self.assertEqual(settings["vc_channel_id"], 99)
        self.assertTrue(settings["enabled"])

    def test_set_channels_recovers_from_a_corrupted_tts_value(self):
        """settings.json を直接編集された等で tts が辞書でなくなっていても、
        次の保存で静かに壊れたまま固まるのではなく、辞書へ復旧できること。"""
        store.update_guild_settings(self.guild_id, {"tts": "corrupted"})
        tts_store.set_tts_channels(self.guild_id, [1], None)
        self.assertEqual(tts_store.get_tts_settings(self.guild_id)["watch_channel_ids"], [1])

    def test_default_voice_rate_max_lengths_read_name_vc_notify_round_trip(self):
        tts_store.set_tts_default_voice(self.guild_id, "ja-JP-A")
        tts_store.set_tts_default_rate(self.guild_id, 120)
        tts_store.set_tts_max_lengths(self.guild_id, 200, 100)
        tts_store.set_tts_read_name(self.guild_id, True)
        tts_store.set_tts_vc_notify(self.guild_id, False)

        settings = tts_store.get_tts_settings(self.guild_id)
        self.assertEqual(settings["default_voice"], "ja-JP-A")
        self.assertEqual(settings["default_rate"], 120)
        self.assertEqual(settings["max_length"], 200)
        self.assertEqual(settings["speak_max_length"], 100)
        self.assertTrue(settings["read_name"])
        self.assertFalse(settings["vc_notify"])


class TtsUserSettingsTests(unittest.TestCase):
    def setUp(self):
        self.guild_id = next_guild_id()

    def test_unset_user_returns_empty_dict(self):
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 42), {})

    def test_corrupted_user_settings_container_reads_as_empty(self):
        store.update_guild_settings(self.guild_id, {"tts": {"user_settings": "corrupted"}})
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 42), {})

    def test_partial_update_preserves_the_field_not_being_updated(self):
        """voice だけ更新したつもりで rate が消えると、ユーザーが設定を
        更新するたびに他の項目を作り直させられる。"""
        tts_store.set_user_tts_settings(self.guild_id, 42, voice="v1", rate=5)
        tts_store.set_user_tts_settings(self.guild_id, 42, voice="v2")
        entry = tts_store.get_user_tts_settings(self.guild_id, 42)
        self.assertEqual(entry["voice"], "v2")
        self.assertEqual(entry["rate"], 5)

    def test_different_users_do_not_clobber_each_other(self):
        tts_store.set_user_tts_settings(self.guild_id, 1, voice="v1")
        tts_store.set_user_tts_settings(self.guild_id, 2, voice="v2")
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 1)["voice"], "v1")
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 2)["voice"], "v2")

    def test_reset_removes_only_the_target_user(self):
        tts_store.set_user_tts_settings(self.guild_id, 1, voice="v1")
        tts_store.set_user_tts_settings(self.guild_id, 2, voice="v2")
        tts_store.reset_user_tts_settings(self.guild_id, 1)
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 1), {})
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 2)["voice"], "v2")

    def test_reset_on_a_guild_with_no_tts_settings_does_not_crash(self):
        tts_store.reset_user_tts_settings(self.guild_id, 1)
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 1), {})

    def test_reset_recovers_from_a_corrupted_tts_container_without_crashing(self):
        """tts 自体が辞書でないほど壊れていたら、pop する対象すら無い。
        ここで例外を出すと定期処理やコマンドが巻き込まれて落ちる。"""
        store.update_guild_settings(self.guild_id, {"tts": "corrupted"})
        tts_store.reset_user_tts_settings(self.guild_id, 1)  # 例外を出さないことが検証点

    def test_set_user_settings_recovers_from_a_corrupted_tts_value(self):
        store.update_guild_settings(self.guild_id, {"tts": "corrupted"})
        tts_store.set_user_tts_settings(self.guild_id, 1, voice="v1")
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 1)["voice"], "v1")

    def test_set_user_settings_recovers_from_a_corrupted_user_settings_value(self):
        store.update_guild_settings(self.guild_id, {"tts": {"user_settings": "corrupted"}})
        tts_store.set_user_tts_settings(self.guild_id, 1, voice="v1")
        self.assertEqual(tts_store.get_user_tts_settings(self.guild_id, 1)["voice"], "v1")


class TtsDictionaryTests(unittest.TestCase):
    def setUp(self):
        self.guild_id = next_guild_id()

    def test_unset_guild_has_an_empty_dictionary(self):
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {})

    def test_add_then_get_round_trips(self):
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "でぃすこーど")
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {"Discord": "でぃすこーど"})

    def test_adding_the_same_word_overwrites_the_reading(self):
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "A")
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "B")
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id)["Discord"], "B")

    def test_remove_existing_word_returns_true_and_deletes_it(self):
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "A")
        removed = tts_store.remove_tts_dictionary_entry(self.guild_id, "Discord")
        self.assertTrue(removed)
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {})

    def test_remove_missing_word_returns_false(self):
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "A")
        removed = tts_store.remove_tts_dictionary_entry(self.guild_id, "Voldemort")
        self.assertFalse(removed)
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {"Discord": "A"})

    def test_remove_on_a_guild_with_no_tts_settings_returns_false(self):
        self.assertFalse(tts_store.remove_tts_dictionary_entry(self.guild_id, "Discord"))

    def test_get_dictionary_recovers_from_a_corrupted_dictionary_value(self):
        store.update_guild_settings(self.guild_id, {"tts": {"dictionary": "corrupted"}})
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {})

    def test_add_entry_recovers_from_a_corrupted_tts_value(self):
        store.update_guild_settings(self.guild_id, {"tts": "corrupted"})
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "A")
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {"Discord": "A"})

    def test_add_entry_recovers_from_a_corrupted_dictionary_value(self):
        store.update_guild_settings(self.guild_id, {"tts": {"dictionary": "corrupted"}})
        tts_store.add_tts_dictionary_entry(self.guild_id, "Discord", "A")
        self.assertEqual(tts_store.get_tts_dictionary(self.guild_id), {"Discord": "A"})

    def test_remove_entry_on_a_corrupted_tts_value_returns_false(self):
        store.update_guild_settings(self.guild_id, {"tts": "corrupted"})
        self.assertFalse(tts_store.remove_tts_dictionary_entry(self.guild_id, "Discord"))


# ──────────────────────────────────────────────
# welcome_service
# ──────────────────────────────────────────────


class SendWelcomeTests(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_no_channel_configured_sends_nothing_and_does_not_touch_the_guild(self):
        member = member_with()
        with patch.object(welcome_service, "get_welcome_settings", Mock(return_value={})):
            self.run_async(welcome_service.send_welcome(member))
        member.guild.get_channel.assert_not_called()

    def test_unresolvable_channel_id_sends_nothing(self):
        member = member_with()
        member.guild.get_channel.return_value = None
        settings = {"channel_id": 123}
        with patch.object(welcome_service, "get_welcome_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_welcome(member))

    def test_non_text_channel_sends_nothing(self):
        """VCやカテゴリのIDが紛れ込んでいても、そこへ送信を試みて例外を
        出さないこと。"""
        member = member_with()
        member.guild.get_channel.return_value = Mock(spec=discord.VoiceChannel)
        settings = {"channel_id": 123}
        with patch.object(welcome_service, "get_welcome_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_welcome(member))

    def test_uses_the_production_default_message_when_unset(self):
        channel = text_channel(123)
        member = member_with(mention="<@1>", username="U", server="鯖", count=5)
        member.guild.get_channel.return_value = channel
        settings = {"channel_id": 123}
        with patch.object(welcome_service, "get_welcome_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_welcome(member))
        sent = channel.send.call_args.args[0]
        expected = welcome_service.render_template(
            welcome_service.DEFAULT_WELCOME, user="<@1>", username="U", server="鯖", count=5
        )
        self.assertEqual(sent, expected)

    def test_uses_the_configured_custom_message(self):
        channel = text_channel(123)
        member = member_with(mention="<@1>", server="鯖")
        member.guild.get_channel.return_value = channel
        settings = {"channel_id": 123, "message": "ようこそ {user}、{server}へ"}
        with patch.object(welcome_service, "get_welcome_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_welcome(member))
        channel.send.assert_awaited_once_with("ようこそ <@1>、鯖へ")

    def test_send_failure_is_logged_and_does_not_raise(self):
        channel = text_channel(123)
        channel.send.side_effect = discord.HTTPException(Mock(status=500), "boom")
        member = member_with()
        member.guild.get_channel.return_value = channel
        settings = {"channel_id": 123}
        with (
            patch.object(welcome_service, "get_welcome_settings", Mock(return_value=settings)),
            self.assertLogs(welcome_service.logger, level="ERROR") as captured,
        ):
            self.run_async(welcome_service.send_welcome(member))
        self.assertTrue(any("send_welcome error" in m for m in captured.output))


class SendGoodbyeTests(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_no_channel_configured_sends_nothing(self):
        member = member_with()
        with patch.object(welcome_service, "get_goodbye_settings", Mock(return_value={})):
            self.run_async(welcome_service.send_goodbye(member))
        member.guild.get_channel.assert_not_called()

    def test_non_text_channel_sends_nothing(self):
        member = member_with()
        member.guild.get_channel.return_value = Mock(spec=discord.VoiceChannel)
        settings = {"channel_id": 123}
        with patch.object(welcome_service, "get_goodbye_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_goodbye(member))

    def test_uses_the_production_default_message_when_unset(self):
        channel = text_channel(123)
        member = member_with(username="U#0001")
        member.guild.get_channel.return_value = channel
        settings = {"channel_id": 123}
        with patch.object(welcome_service, "get_goodbye_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_goodbye(member))
        sent = channel.send.call_args.args[0]
        self.assertIn("U#0001", sent)
        self.assertIn("去っていった", sent)

    def test_uses_the_configured_custom_message(self):
        channel = text_channel(123)
        member = member_with(username="U#0001")
        member.guild.get_channel.return_value = channel
        settings = {"channel_id": 123, "message": "またね {username}"}
        with patch.object(welcome_service, "get_goodbye_settings", Mock(return_value=settings)):
            self.run_async(welcome_service.send_goodbye(member))
        channel.send.assert_awaited_once_with("またね U#0001")

    def test_send_failure_is_logged_and_does_not_raise(self):
        channel = text_channel(123)
        channel.send.side_effect = discord.HTTPException(Mock(status=500), "boom")
        member = member_with()
        member.guild.get_channel.return_value = channel
        settings = {"channel_id": 123}
        with (
            patch.object(welcome_service, "get_goodbye_settings", Mock(return_value=settings)),
            self.assertLogs(welcome_service.logger, level="ERROR") as captured,
        ):
            self.run_async(welcome_service.send_goodbye(member))
        self.assertTrue(any("send_goodbye error" in m for m in captured.output))


if __name__ == "__main__":
    unittest.main()
