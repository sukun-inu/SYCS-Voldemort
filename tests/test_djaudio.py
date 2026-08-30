"""services/djaudio_service.py のテスト。

Discord のメッセージに貼られた URL から音源を落として配信する機能のうち、
これまでテストが無かった部分（URL抽出・件数制限、対応サイト判定との連携、
ダウンロードの並列度・タイムアウト、失敗時の後始末、公開URLの組み立て）を
固定する。

yt-dlp・ネットワーク・実ファイルの外部取得には一切出ない。
サブプロセス起動（asyncio.create_subprocess_exec）・SoundCloud client_id 取得・
実際のダウンロード処理はすべて patch で差し替える。
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

# services/* はモジュール読み込み時に SETTINGS_DIR / DJAUDIO_CACHE_DIR を解決するため、
# import より前に隔離用の一時ディレクトリへ差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="djaudio-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="djaudio-test-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import services.djaudio_service as djaudio  # noqa: E402
from services.settings_store import DJAudioRuntimeSettings  # noqa: E402
from services.url_safety import URLSafetyError  # noqa: E402


class ExtractUrlsTests(unittest.TestCase):
    """メッセージからの URL 抽出と DJAUDIO_MAX_URLS による件数制限。"""

    def test_finds_multiple_urls_and_strips_wrapping(self):
        content = "見て <https://youtu.be/abc123> あと http://example.com/x! も"
        self.assertEqual(
            djaudio._extract_urls(content, 5),
            ["https://youtu.be/abc123", "http://example.com/x"],
        )

    def test_deduplicates_repeated_urls(self):
        content = "同じの2回: https://a.com/x https://a.com/x"
        self.assertEqual(djaudio._extract_urls(content, 5), ["https://a.com/x"])

    def test_respects_max_urls_limit(self):
        """DJAUDIO_MAX_URLS 相当の上限に達したら、それ以上は拾わないこと。"""
        content = "a https://a.com/1 b https://a.com/2 c https://a.com/3"
        self.assertEqual(djaudio._extract_urls(content, 2), ["https://a.com/1", "https://a.com/2"])

    def test_no_urls_returns_empty_list(self):
        self.assertEqual(djaudio._extract_urls("URLなしのメッセージ", 5), [])


class NormalizeTextTests(unittest.TestCase):
    def test_collapses_whitespace_and_strips(self):
        self.assertEqual(djaudio._normalize_text("  a   b\tc\n"), "a b c")

    def test_none_becomes_empty_string(self):
        self.assertEqual(djaudio._normalize_text(None), "")


class FormatTitleFromMetadataTests(unittest.TestCase):
    """メタデータから表示タイトルを組み立てるロジック。サイトごとに規則が違うため、
    まとめて表で確かめる（youtube/soundcloud/bandcamp/nicovideo/tiktok/generic）。
    """

    def test_site_specific_formatting_rules(self):
        cases = [
            ({"extractor": "youtube", "title": "Song Title", "artist": "Artist", "track": "Track"}, "Artist - Track"),
            ({"extractor": "youtube", "title": "Song Title", "artist": "Artist"}, "Artist - Song Title"),
            ({"extractor": "youtube", "title": "Song Title", "uploader": "Uploader"}, "Uploader - Song Title"),
            ({"extractor": "youtube", "title": "Song Title"}, "Song Title"),
            # uploader が空白のみだと artist 側の正規化で空になり、236-237行目の
            # 「uploader 個別フォールバック」分岐に落ちる（_with_artist の first 側が
            # 空になる 221 行目も同時に踏む）。
            ({"extractor": "youtube", "title": "Song Title", "uploader": "   "}, "Song Title"),
            ({"extractor": "soundcloud", "title": "Song", "artist": "Art"}, "Art - Song"),
            ({"extractor": "soundcloud", "title": "Song"}, "Song"),
            ({"extractor": "bandcamp", "title": "Song", "artist": "Art"}, "Art - Song"),
            ({"extractor": "bandcamp", "title": "Song", "track": "Trk"}, "Trk - Song"),
            ({"extractor": "bandcamp", "title": "Song"}, "Song"),
            ({"extractor": "nicovideo", "title": "Song", "artist": "Art"}, "Song"),
            ({"extractor": "tiktok", "title": "Song", "uploader": "Up"}, "Up - Song"),
            ({"extractor": "tiktok", "title": "Song"}, "Song"),
            ({"title": "Song", "artist": "Art"}, "Art - Song"),
            ({"title": "Song", "track": "Trk"}, "Trk - Song"),
            ({"title": "Song"}, "Song"),
            ({"artist": "Art"}, "Art"),
            ({}, "unknown"),
            # 第二候補が既に第一候補で始まっているなら連結しない
            ({"extractor": "youtube", "title": "Artist - Track Title", "artist": "Artist"}, "Artist - Track Title"),
        ]
        for meta, expected in cases:
            with self.subTest(meta=meta):
                self.assertEqual(djaudio._format_title_from_metadata(meta), expected)


class LoadInfoJsonTests(unittest.TestCase):
    """yt-dlp が書き出す *.info.json の読み込み。壊れていても例外を漏らさないこと。"""

    def test_missing_info_json_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            mp3 = Path(d) / "song.mp3"
            mp3.write_bytes(b"x")
            self.assertIsNone(djaudio._load_info_json(mp3))

    def test_valid_info_json_is_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            mp3 = Path(d) / "song.mp3"
            mp3.write_bytes(b"x")
            info = Path(d) / "song.info.json"
            info.write_text(json.dumps({"title": "曲名"}), encoding="utf-8")
            self.assertEqual(djaudio._load_info_json(mp3), {"title": "曲名"})

    def test_corrupt_info_json_logs_warning_and_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            mp3 = Path(d) / "song.mp3"
            mp3.write_bytes(b"x")
            info = Path(d) / "song.info.json"
            info.write_text("{not valid json", encoding="utf-8")
            with self.assertLogs(djaudio.logger, level="WARNING") as captured:
                result = djaudio._load_info_json(mp3)
            self.assertIsNone(result)
            self.assertTrue(any("info.json" in m for m in captured.output), captured.output)


class IsSoundcloudUrlTests(unittest.TestCase):
    def test_soundcloud_hosts_are_true(self):
        for url in (
            "https://soundcloud.com/artist/track",
            "https://www.soundcloud.com/artist/track",
            "https://on.soundcloud.com/abc",
        ):
            with self.subTest(url=url):
                self.assertTrue(djaudio._is_soundcloud_url(url))

    def test_other_hosts_are_false(self):
        for url in ("https://youtube.com/watch?v=1", "https://example.com/x", "not-a-url"):
            with self.subTest(url=url):
                self.assertFalse(djaudio._is_soundcloud_url(url))


class SemaphoreConcurrencyTests(unittest.TestCase):
    """DJAUDIO_DL_CONCURRENCY が同時ダウンロード数の上限として実際に使われていること。"""

    def setUp(self):
        self._orig = djaudio._dl_semaphore
        djaudio._dl_semaphore = None

    def tearDown(self):
        djaudio._dl_semaphore = self._orig

    def test_semaphore_size_follows_dl_concurrency_setting(self):
        with patch.object(djaudio, "DJAUDIO_DL_CONCURRENCY", 7):
            sem = djaudio._get_semaphore()
        self.assertEqual(sem._value, 7)

    def test_semaphore_instance_is_reused_singleton(self):
        """毎回新しいセマフォを作ると並列度の上限が意味を持たなくなる。"""
        sem1 = djaudio._get_semaphore()
        sem2 = djaudio._get_semaphore()
        self.assertIs(sem1, sem2)


class RunYtdlpCommandTests(unittest.TestCase):
    """yt-dlp コマンド組み立てのテスト。subprocess は必ず patch で差し替え、実行しない。"""

    def _run(self, url, output_dir, sc_client_id=None, returncode=0, stderr=b""):
        captured = {}

        async def fake_exec(*cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            proc = Mock()
            proc.returncode = returncode
            proc.communicate = AsyncMock(return_value=(b"", stderr))
            return proc

        with patch("services.djaudio_service.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = asyncio.run(djaudio._run_ytdlp(url, output_dir, sc_client_id))
        return result, captured["cmd"]

    def test_builds_expected_command_and_parses_result(self):
        (returncode, err), cmd = self._run("https://youtu.be/abc", "/tmp/out", returncode=0, stderr=b"")
        self.assertEqual(returncode, 0)
        self.assertEqual(err, "")
        self.assertEqual(cmd[0], "yt-dlp")
        self.assertEqual(cmd[-2:], ("--", "https://youtu.be/abc"))
        self.assertIn(djaudio.DJAUDIO_FFMPEG_PATH, cmd)
        self.assertIn("-o", cmd)
        o_index = cmd.index("-o")
        self.assertEqual(cmd[o_index + 1], str(Path("/tmp/out") / "%(title).80s.%(ext)s"))
        self.assertNotIn("--extractor-args", cmd)

    def test_adds_extractor_args_when_client_id_given(self):
        (_, _), cmd = self._run("https://soundcloud.com/a/b", "/tmp/out", sc_client_id="cid-xyz")
        self.assertIn("--extractor-args", cmd)
        idx = cmd.index("--extractor-args")
        self.assertEqual(cmd[idx + 1], "soundcloud:client_id=cid-xyz")

    def test_stderr_is_decoded_and_returned(self):
        (returncode, err), _cmd = self._run(
            "https://youtu.be/abc", "/tmp/out", returncode=1, stderr="エラー発生".encode("utf-8")
        )
        self.assertEqual(returncode, 1)
        self.assertEqual(err, "エラー発生")


class DownloadAsMp3Tests(unittest.TestCase):
    """SoundCloud の client_id エラー時のリトライと、リトライしない境界。

    _run_ytdlp / _fetch_soundcloud_client_id を patch し、yt-dlp・ネットワークには出ない。
    """

    @staticmethod
    def _touch(output_dir, name):
        p = Path(output_dir) / name
        p.write_bytes(b"dummy")
        return p

    def test_success_returns_sorted_mp3_paths(self):
        with tempfile.TemporaryDirectory() as outdir:
            self._touch(outdir, "b.mp3")
            self._touch(outdir, "a.mp3")
            run_mock = AsyncMock(return_value=(0, ""))
            with patch.object(djaudio, "_run_ytdlp", run_mock):
                result = asyncio.run(djaudio._download_as_mp3("https://youtu.be/x", outdir))
        self.assertEqual([p.name for p in result], ["a.mp3", "b.mp3"])
        run_mock.assert_called_once_with("https://youtu.be/x", outdir)

    def test_non_soundcloud_failure_raises_without_client_id_retry(self):
        with tempfile.TemporaryDirectory() as outdir:
            run_mock = AsyncMock(return_value=(1, "other yt-dlp error"))
            fetch_mock = AsyncMock()
            with (
                patch.object(djaudio, "_run_ytdlp", run_mock),
                patch.object(djaudio, "_fetch_soundcloud_client_id", fetch_mock),
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    asyncio.run(djaudio._download_as_mp3("https://youtu.be/x", outdir))
            self.assertIn("other yt-dlp error", str(ctx.exception))
            fetch_mock.assert_not_called()
            run_mock.assert_called_once()

    def test_soundcloud_client_id_error_retries_and_succeeds(self):
        url = "https://soundcloud.com/artist/track"
        err = f"ERROR: {djaudio._SOUNDCLOUD_CLIENT_ID_ERR}"
        with tempfile.TemporaryDirectory() as outdir:
            self._touch(outdir, "track.mp3")
            run_mock = AsyncMock(side_effect=[(1, err), (0, "")])
            fetch_mock = AsyncMock(return_value="cid-123")
            with (
                patch.object(djaudio, "_run_ytdlp", run_mock),
                patch.object(djaudio, "_fetch_soundcloud_client_id", fetch_mock),
            ):
                result = asyncio.run(djaudio._download_as_mp3(url, outdir))
            self.assertEqual([p.name for p in result], ["track.mp3"])
            self.assertEqual(run_mock.call_count, 2)
            fetch_mock.assert_awaited_once_with()
            second_call = run_mock.call_args_list[1]
            self.assertEqual(second_call.kwargs.get("sc_client_id"), "cid-123")

    def test_soundcloud_retry_gives_up_when_client_id_fetch_fails(self):
        """通常取得・強制再取得のどちらも client_id を得られない場合、
        _run_ytdlp は最初の1回のみで、無意味な再ダウンロードは行わないこと。"""
        url = "https://soundcloud.com/artist/track"
        err = f"ERROR: {djaudio._SOUNDCLOUD_CLIENT_ID_ERR}"
        with tempfile.TemporaryDirectory() as outdir:
            run_mock = AsyncMock(return_value=(1, err))
            fetch_mock = AsyncMock(return_value=None)
            with (
                patch.object(djaudio, "_run_ytdlp", run_mock),
                patch.object(djaudio, "_fetch_soundcloud_client_id", fetch_mock),
            ):
                with self.assertRaises(RuntimeError):
                    asyncio.run(djaudio._download_as_mp3(url, outdir))
            self.assertEqual(run_mock.call_count, 1, "client_id が取れないのに yt-dlp を再実行してはいけない")
            # 通常取得が失敗しても、強制再取得（force=True）は1回試みられる仕様
            self.assertEqual(fetch_mock.call_count, 2)
            self.assertEqual(fetch_mock.call_args_list[0].kwargs, {})
            self.assertEqual(fetch_mock.call_args_list[1].kwargs, {"force": True})

    def test_soundcloud_second_failure_forces_client_id_refetch(self):
        """client_id 指定でも失敗が続いたら force=True で再取得し、もう一度だけ試すこと。"""
        url = "https://soundcloud.com/artist/track"
        err = f"ERROR: {djaudio._SOUNDCLOUD_CLIENT_ID_ERR}"
        with tempfile.TemporaryDirectory() as outdir:
            self._touch(outdir, "track.mp3")
            run_mock = AsyncMock(side_effect=[(1, err), (1, err), (0, "")])
            fetch_mock = AsyncMock(side_effect=["cid-1", "cid-2"])
            with (
                patch.object(djaudio, "_run_ytdlp", run_mock),
                patch.object(djaudio, "_fetch_soundcloud_client_id", fetch_mock),
            ):
                result = asyncio.run(djaudio._download_as_mp3(url, outdir))
            self.assertEqual([p.name for p in result], ["track.mp3"])
            self.assertEqual(run_mock.call_count, 3)
            self.assertEqual(fetch_mock.call_count, 2)
            self.assertEqual(fetch_mock.call_args_list[0].kwargs, {})
            self.assertEqual(fetch_mock.call_args_list[1].kwargs, {"force": True})
            self.assertEqual(run_mock.call_args_list[2].kwargs.get("sc_client_id"), "cid-2")


class DownloadAndRegisterTests(unittest.TestCase):
    """MP3 → メタデータ補完 → キャッシュ登録までの一連の流れ。"""

    def test_no_mp3_files_raises_runtime_error(self):
        with (
            patch.object(djaudio, "_download_as_mp3", AsyncMock(return_value=[])),
            patch.object(djaudio, "register_file") as reg_mock,
        ):
            with self.assertRaises(RuntimeError):
                asyncio.run(djaudio._download_and_register("https://x", 1, "/tmp/x", 600))
        reg_mock.assert_not_called()

    def test_metadata_present_enriches_and_uses_formatted_title(self):
        with tempfile.TemporaryDirectory() as outdir:
            mp3 = Path(outdir) / "raw.mp3"
            mp3.write_bytes(b"dummy")
            info = Path(outdir) / "raw.info.json"
            info.write_text(json.dumps({"extractor": "youtube", "title": "Song", "artist": "Art"}), encoding="utf-8")

            enrich_mock = AsyncMock(return_value=True)
            register_mock = Mock(return_value="token-abc")
            with (
                patch.object(djaudio, "_download_as_mp3", AsyncMock(return_value=[mp3])),
                patch.object(djaudio, "enrich_metadata", enrich_mock),
                patch.object(djaudio, "register_file", register_mock),
            ):
                result = asyncio.run(djaudio._download_and_register("https://x", 1, outdir, 600))

        self.assertEqual(result, [("Art - Song", "token-abc")])
        enrich_mock.assert_awaited_once()
        self.assertEqual(enrich_mock.call_args.args[0], mp3)
        register_mock.assert_called_once_with(mp3, source_url="https://x", title="Art - Song", guild_id=1, ttl=600)

    def test_metadata_absent_uses_filename_stem_as_title(self):
        with tempfile.TemporaryDirectory() as outdir:
            mp3 = Path(outdir) / "MyTrack.mp3"
            mp3.write_bytes(b"dummy")
            enrich_mock = AsyncMock()
            register_mock = Mock(return_value="tok")
            with (
                patch.object(djaudio, "_download_as_mp3", AsyncMock(return_value=[mp3])),
                patch.object(djaudio, "enrich_metadata", enrich_mock),
                patch.object(djaudio, "register_file", register_mock),
            ):
                result = asyncio.run(djaudio._download_and_register("https://x", 1, outdir, 600))
        self.assertEqual(result, [("MyTrack", "tok")])
        enrich_mock.assert_not_awaited()

    def test_multiple_files_each_registered_independently(self):
        with tempfile.TemporaryDirectory() as outdir:
            mp3a = Path(outdir) / "a.mp3"
            mp3a.write_bytes(b"1")
            mp3b = Path(outdir) / "b.mp3"
            mp3b.write_bytes(b"2")
            register_mock = Mock(side_effect=["tok-a", "tok-b"])
            with (
                patch.object(djaudio, "_download_as_mp3", AsyncMock(return_value=[mp3a, mp3b])),
                patch.object(djaudio, "enrich_metadata", AsyncMock()),
                patch.object(djaudio, "register_file", register_mock),
            ):
                result = asyncio.run(djaudio._download_and_register("https://x", 1, outdir, 600))
        self.assertEqual(result, [("a", "tok-a"), ("b", "tok-b")])
        self.assertEqual(register_mock.call_count, 2)


class BuildResultEmbedTests(unittest.TestCase):
    """生成される公開URL（DJAUDIO_BASE_URL 起点）と表示の組み立て。"""

    def test_links_use_base_url_and_ttl_minutes(self):
        with patch.object(djaudio, "DJAUDIO_BASE_URL", "https://cdn.test.example"):
            embed = djaudio._build_result_embed([("曲A", "tok1"), ("曲B", "tok2")], 42, 600)
        self.assertIn("10分後", embed.description)
        self.assertEqual(len(embed.fields), 2)
        self.assertIn("https://cdn.test.example/dlaudio/files/42/tok1", embed.fields[0].value)
        self.assertIn("https://cdn.test.example/dlaudio/files/42/tok2", embed.fields[1].value)

    def test_long_title_is_truncated_in_field_name(self):
        long_title = "あ" * 80
        embed = djaudio._build_result_embed([(long_title, "tok")], 1, 600)
        self.assertEqual(embed.fields[0].name, f"📥 {long_title[:50]}")


class HandleDjaudioMessageTests(unittest.TestCase):
    """URL 監視ハンドラの入口の分岐（対応判定・セキュリティ判定・クールダウン・件数制限）。"""

    def setUp(self):
        djaudio._user_cooldown.clear()
        djaudio._processing.clear()

    def tearDown(self):
        djaudio._user_cooldown.clear()
        djaudio._processing.clear()

    @staticmethod
    def _message(*, guild_id=1, channel_id=555, author_id=2, content=""):
        message = Mock(spec=discord.Message)
        message.guild = Mock(id=guild_id)
        message.channel = Mock(id=channel_id)
        message.author = Mock(id=author_id, display_name="テストユーザー")
        message.content = content
        message.id = 999
        return message

    @staticmethod
    def _settings(**overrides):
        base = dict(watch_channel_id=555, cache_ttl=600, cooldown=30, max_urls=3, output_channel_id=None)
        base.update(overrides)
        return DJAudioRuntimeSettings(**base)

    def test_dm_without_guild_is_ignored(self):
        message = self._message()
        message.guild = None
        with patch.object(djaudio, "get_djaudio_runtime_settings") as settings_mock:
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        settings_mock.assert_not_called()
        message.reply.assert_not_called()

    def test_unconfigured_watch_channel_is_ignored(self):
        message = self._message(content="https://youtu.be/abc")
        with patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings(watch_channel_id=0)):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_not_called()

    def test_wrong_channel_is_ignored(self):
        message = self._message(channel_id=1, content="https://youtu.be/abc")
        with patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings(watch_channel_id=555)):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_not_called()

    def test_message_without_url_is_ignored(self):
        message = self._message(content="こんにちは、URLはないよ")
        with patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings()):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_not_called()

    def test_unsupported_platform_url_gets_reason_reply(self):
        message = self._message(content="https://open.spotify.com/track/abc")
        with (
            patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings()),
            patch.object(djaudio, "_process_url") as process_mock,
        ):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_awaited_once()
        args, kwargs = message.reply.call_args
        self.assertIn("Spotify", args[0])
        self.assertFalse(kwargs["mention_author"])
        process_mock.assert_not_called()

    def test_disallowed_domain_gets_generic_reply(self):
        message = self._message(content="https://example.com/song.mp3")
        with (
            patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings()),
            patch.object(djaudio, "_process_url") as process_mock,
        ):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_awaited_once()
        args, _kwargs = message.reply.call_args
        self.assertIn("サポートされていない", args[0])
        process_mock.assert_not_called()

    def test_security_rejected_url_gets_reply(self):
        message = self._message(content="https://www.youtube.com/watch?v=abc")
        with (
            patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings()),
            patch.object(djaudio, "validate_public_http_url", side_effect=URLSafetyError("blocked")),
            patch.object(djaudio, "_process_url") as process_mock,
        ):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_awaited_once()
        args, _kwargs = message.reply.call_args
        self.assertIn("セキュリティ", args[0])
        process_mock.assert_not_called()

    def test_cooldown_blocks_repeat_request(self):
        """クールダウン中は _process_url を一切呼ばず、残り秒数を伝えて終わること。"""
        message = self._message(content="https://www.youtube.com/watch?v=abc")
        djaudio._user_cooldown.set((1, 2), time.monotonic())
        with (
            patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings(cooldown=30)),
            patch.object(djaudio, "validate_public_http_url", return_value=None),
            patch.object(djaudio, "_process_url") as process_mock,
        ):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        message.reply.assert_awaited_once()
        args, _kwargs = message.reply.call_args
        self.assertIn("再試行", args[0])
        process_mock.assert_not_called()

    def test_supported_urls_are_dispatched_concurrently(self):
        message = self._message(content="https://www.youtube.com/watch?v=a https://soundcloud.com/artist/b")
        bot = Mock()
        with (
            patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings()),
            patch.object(djaudio, "validate_public_http_url", return_value=None),
            patch.object(djaudio, "_process_url", AsyncMock()) as process_mock,
        ):
            asyncio.run(djaudio.handle_djaudio_message(bot, message))
        self.assertEqual(process_mock.call_count, 2)
        called_urls = {c.args[2] for c in process_mock.call_args_list}
        self.assertEqual(called_urls, {"https://www.youtube.com/watch?v=a", "https://soundcloud.com/artist/b"})
        message.reply.assert_not_called()

    def test_max_urls_setting_limits_dispatch_count(self):
        """settings.max_urls（DJAUDIO_MAX_URLS 由来）を超える分は処理に回さないこと。"""
        message = self._message(content="https://www.youtube.com/watch?v=a https://www.youtube.com/watch?v=b")
        with (
            patch.object(djaudio, "get_djaudio_runtime_settings", return_value=self._settings(max_urls=1)),
            patch.object(djaudio, "validate_public_http_url", return_value=None),
            patch.object(djaudio, "_process_url", AsyncMock()) as process_mock,
        ):
            asyncio.run(djaudio.handle_djaudio_message(Mock(), message))
        self.assertEqual(process_mock.call_count, 1)
        self.assertEqual(process_mock.call_args.args[2], "https://www.youtube.com/watch?v=a")


class ProcessUrlTests(unittest.TestCase):
    """1 URL ぶんの実処理: 二重実行防止・一時ディレクトリの後始末・失敗時の通知経路。"""

    def setUp(self):
        djaudio._processing.clear()

    def tearDown(self):
        djaudio._processing.clear()

    @staticmethod
    def _message(*, guild_id=1, channel_id=555, msg_id=999, author_id=2):
        message = Mock(spec=discord.Message)
        message.guild = Mock(id=guild_id)
        message.channel = Mock(id=channel_id)
        message.author = Mock(id=author_id, display_name="テストユーザー")
        message.id = msg_id
        return message

    @staticmethod
    def _settings(**overrides):
        base = dict(watch_channel_id=555, cache_ttl=600, cooldown=30, max_urls=3, output_channel_id=None)
        base.update(overrides)
        return DJAudioRuntimeSettings(**base)

    def test_duplicate_in_flight_key_is_skipped(self):
        """同じ (guild, message, url) が処理中なら、二重にダウンロードへ進まないこと。"""
        message = self._message()
        url = "https://youtu.be/abc"
        djaudio._processing.add((message.guild.id, message.id, url))
        with patch.object(djaudio, "_download_and_register", AsyncMock()) as dl_mock:
            asyncio.run(djaudio._process_url(Mock(), message, url, self._settings()))
        dl_mock.assert_not_called()
        message.add_reaction.assert_not_called()

    def test_success_flow_replies_with_embed_and_registers_message(self):
        message = self._message()
        url = "https://youtu.be/abc"
        reply_msg = Mock(channel=Mock(id=777), id=888)
        message.reply = AsyncMock(return_value=reply_msg)
        bot = Mock()
        bot.user = Mock(id=1)

        with (
            patch.object(djaudio, "_download_and_register", AsyncMock(return_value=[("曲名", "tok1")])) as dl_mock,
            patch.object(djaudio, "update_discord_message") as update_mock,
        ):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings(output_channel_id=None)))

        dl_mock.assert_awaited_once()
        self.assertEqual(dl_mock.call_args.args[0], url)
        self.assertEqual(dl_mock.call_args.args[1], message.guild.id)
        self.assertEqual(dl_mock.call_args.args[3], 600)

        add_calls = [c.args[0] for c in message.add_reaction.call_args_list]
        self.assertEqual(add_calls, ["⏳", "✅"])
        message.remove_reaction.assert_awaited_once_with("⏳", bot.user)

        message.reply.assert_awaited_once()
        _args, kwargs = message.reply.call_args
        self.assertIsInstance(kwargs["embed"], discord.Embed)
        self.assertFalse(kwargs["mention_author"])

        update_mock.assert_called_once_with("tok1", 777, 888)
        self.assertNotIn((message.guild.id, message.id, url), djaudio._processing)

    def test_temp_directory_is_removed_after_success(self):
        """ダウンロード先の一時ディレクトリが、成功後に残っていないこと。"""
        message = self._message()
        url = "https://youtu.be/abc"
        captured = {}

        async def fake_download(_url, _guild_id, tmpdir, _ttl):
            captured["tmpdir"] = tmpdir
            self.assertTrue(Path(tmpdir).exists())
            return [("曲", "tok")]

        with (
            patch.object(djaudio, "_download_and_register", fake_download),
            patch.object(djaudio, "update_discord_message"),
        ):
            asyncio.run(djaudio._process_url(Mock(user=Mock()), message, url, self._settings()))

        self.assertFalse(Path(captured["tmpdir"]).exists(), "一時ディレクトリが後始末されていない")

    def test_temp_directory_is_removed_after_failure(self):
        """ダウンロードが失敗しても、一時ファイル・ディレクトリが残らないこと。"""
        message = self._message()
        url = "https://youtu.be/abc"
        captured = {}

        async def fake_download(_url, _guild_id, tmpdir, _ttl):
            captured["tmpdir"] = tmpdir
            self.assertTrue(Path(tmpdir).exists())
            raise RuntimeError("ダウンロード失敗のふり")

        with patch.object(djaudio, "_download_and_register", fake_download):
            asyncio.run(djaudio._process_url(Mock(user=Mock()), message, url, self._settings()))

        self.assertFalse(Path(captured["tmpdir"]).exists(), "失敗時に一時ディレクトリが残っている")

    def test_output_channel_used_when_configured_and_different(self):
        message = self._message(channel_id=555)
        url = "https://youtu.be/abc"
        output_channel = Mock(spec=discord.TextChannel, id=999)
        sent_msg = Mock(channel=Mock(id=999), id=321)
        output_channel.send = AsyncMock(return_value=sent_msg)
        bot = Mock()
        bot.user = Mock()
        bot.get_channel = Mock(return_value=output_channel)

        with (
            patch.object(djaudio, "_download_and_register", AsyncMock(return_value=[("曲", "tok")])),
            patch.object(djaudio, "update_discord_message") as update_mock,
        ):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings(output_channel_id=999)))

        output_channel.send.assert_awaited_once()
        message.reply.assert_not_called()
        update_mock.assert_called_once_with("tok", 999, 321)

    def test_output_channel_same_as_message_channel_falls_back_to_reply(self):
        message = self._message(channel_id=555)
        reply_msg = Mock(channel=Mock(id=555), id=1)
        message.reply = AsyncMock(return_value=reply_msg)
        url = "https://youtu.be/abc"
        bot = Mock()
        bot.user = Mock()
        output_channel = Mock(spec=discord.TextChannel, id=555)
        output_channel.send = AsyncMock()
        bot.get_channel = Mock(return_value=output_channel)

        with (
            patch.object(djaudio, "_download_and_register", AsyncMock(return_value=[("曲", "tok")])),
            patch.object(djaudio, "update_discord_message"),
        ):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings(output_channel_id=555)))

        output_channel.send.assert_not_called()
        message.reply.assert_awaited_once()

    def test_timeout_notifies_user_and_releases_processing_key(self):
        message = self._message()
        url = "https://youtu.be/abc"
        bot = Mock()
        bot.user = Mock()
        key = (message.guild.id, message.id, url)

        with patch.object(djaudio, "_download_and_register", AsyncMock(side_effect=asyncio.TimeoutError())):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings()))

        add_calls = [c.args[0] for c in message.add_reaction.call_args_list]
        self.assertIn("❌", add_calls)
        message.reply.assert_awaited_once()
        args, _kwargs = message.reply.call_args
        self.assertIn("タイムアウト", args[0])
        self.assertNotIn(key, djaudio._processing)

    def test_timeout_notification_error_is_logged_not_raised(self):
        """タイムアウトを伝える返信自体が失敗しても、例外を外へ漏らさずログに残すこと。"""
        message = self._message()
        url = "https://youtu.be/abc"
        bot = Mock()
        bot.user = Mock()
        message.reply = AsyncMock(side_effect=discord.HTTPException(Mock(status=500), "fail"))
        key = (message.guild.id, message.id, url)

        with (
            patch.object(djaudio, "_download_and_register", AsyncMock(side_effect=asyncio.TimeoutError())),
            self.assertLogs(djaudio.logger, level="WARNING") as captured,
        ):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings()))

        self.assertTrue(any("タイムアウト通知を送れませんでした" in m for m in captured.output), captured.output)
        self.assertNotIn(key, djaudio._processing)

    def test_generic_failure_notifies_user_and_releases_processing_key(self):
        message = self._message()
        url = "https://youtu.be/abc"
        bot = Mock()
        bot.user = Mock()
        key = (message.guild.id, message.id, url)

        with (
            patch.object(djaudio, "_download_and_register", AsyncMock(side_effect=RuntimeError("boom"))),
            self.assertLogs(djaudio.logger, level="ERROR"),
        ):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings()))

        message.reply.assert_awaited_once()
        args, _kwargs = message.reply.call_args
        self.assertIn("ダウンロードに失敗した", args[0])
        self.assertNotIn(key, djaudio._processing)

    def test_failure_notification_error_is_logged_not_raised(self):
        """失敗を伝える返信自体が失敗しても、例外を外へ漏らさずログに残すこと。"""
        message = self._message()
        url = "https://youtu.be/abc"
        bot = Mock()
        bot.user = Mock()
        message.reply = AsyncMock(side_effect=discord.HTTPException(Mock(status=500), "fail"))
        key = (message.guild.id, message.id, url)

        with (
            patch.object(djaudio, "_download_and_register", AsyncMock(side_effect=RuntimeError("boom"))),
            self.assertLogs(djaudio.logger, level="WARNING") as captured,
        ):
            asyncio.run(djaudio._process_url(bot, message, url, self._settings()))

        self.assertTrue(any("失敗通知を送れませんでした" in m for m in captured.output), captured.output)
        self.assertNotIn(key, djaudio._processing)


if __name__ == "__main__":
    unittest.main()
