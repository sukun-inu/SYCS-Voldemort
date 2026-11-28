"""メッセージの検査まわりで見つけた、直し方のはっきりした 9 つ（トラッカーの rust-09、B12-sec）を固定する。

(a) マルチキャストを公開アドレスとして通さない（url_safety）
(b) VirusTotal の解析待ちに全体の上限を付ける（virustotal_service）
(c) 結果の Embed を Discord の上限に収める（security_service.build_final_embed）
(e) VC の荒らしの数え方に、VC にいる人の発言を入れない（raid_detection・security_service）
(f) Groq の判定に、いちばん重い VirusTotal の結果を使う（content_moderation）
(g) Groq の retry-after に上限を付け、1 回の呼び出しで送る回数を GROQ_MAX_RETRIES + 1 までにする（groq_client）
(h) 結果の Embed の書き換えが通信で失敗しても、最後のログを出す（security_service._report_result）
(i) 剥がした結果をログチャンネルの報告に出す（security_service）
(j) AI の会話で Groq が失敗したとき、誤りの文を返事にも履歴にも出さない（chatgpt_service）

どれも、直す前のコードでは落ちることを確かめてある（HANDBACK に記録）。
"""

import asyncio
import ipaddress
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
import discord


class MulticastIsNotPublicTests(unittest.TestCase):
    """(a) マルチキャスト（224.0.0.0/4・ff00::/8）を公開アドレスとして通さない。

    Python の ipaddress では、マルチキャストの is_global が True になる（IANA の表で
    「globally reachable」に数えられている）。is_global だけを見ていたので、説明は
    「マルチキャストも拒否」なのに通っていた。
    """

    def test_multicast_addresses_are_not_public(self):
        """IPv4・IPv6・IPv4-mapped のマルチキャストを、どれも公開扱いにしない。"""
        from services.url_safety import _is_public_ip

        for text in ["224.0.0.1", "224.0.0.251", "239.255.255.250", "ff02::1", "ff0e::1", "::ffff:224.0.0.251"]:
            self.assertFalse(_is_public_ip(ipaddress.ip_address(text)), text)

    def test_the_neighbours_of_multicast_stay_public(self):
        """マルチキャストのすぐ外側（と、ふつうの公開アドレス）は、これまでどおり通す。"""
        from services.url_safety import _is_public_ip

        for text in ["223.255.255.255", "8.8.8.8", "2606:4700::1111", "feff:ffff::1", "::ffff:142.251.150.119"]:
            self.assertTrue(_is_public_ip(ipaddress.ip_address(text)), text)

    def test_a_multicast_url_is_refused(self):
        """アドレスが書いてある URL も、マルチキャストなら non_public_ip で拒否する。"""
        from services.url_safety import URLSafetyError, validate_public_http_url

        for url in ["http://224.0.0.1/", "http://[ff02::1]/", "http://[::ffff:239.1.2.3]/"]:
            with self.assertRaises(URLSafetyError, msg=url) as cm:
                validate_public_http_url(url)
            self.assertTrue(str(cm.exception).startswith("non_public_ip:"), str(cm.exception))


class _NeverEndingVtClient:
    """vt.Client の代わり。解析は終わらない（get_object はいつも queued を返す）。

    wait_for_completion=True で呼ばれたら、vt-py と同じく終わるまで問い合わせ続ける
    （ここでは 200 回で諦めて、待ち続けたことが分かる例外にする）。
    """

    polls = 0
    submitted: list = []

    def __init__(self, apikey, **kwargs):
        """鍵と制限時間は受け取るだけ。"""

    def __enter__(self):
        """with で使えるようにする。"""
        return self

    def __exit__(self, *exc):
        """例外は飲み込まない。"""
        return False

    def get_object(self, path, *args):
        """解析の状態の問い合わせ（いつも queued）。ファイルの照会は「無い」。"""
        if path.startswith("/files/"):
            import vt

            raise vt.error.APIError("NotFoundError", "not found")
        type(self).polls += 1
        return SimpleNamespace(id="an-1", status="queued", stats={})

    def _submit(self, kind, wait_for_completion):
        """送った解析を返す。wait_for_completion なら vt-py のように終わるまで待つ。"""
        type(self).submitted.append(kind)
        analysis = SimpleNamespace(id="an-1")
        if wait_for_completion:
            for _ in range(200):
                analysis = self.get_object("/analyses/{}", analysis.id)
                if analysis.status == "completed":
                    return analysis
            raise RuntimeError("終わらない解析を待ち続けた")
        return analysis

    def scan_url(self, url, wait_for_completion=False):
        """URL を送る。"""
        return self._submit("url", wait_for_completion)

    def scan_file(self, f, wait_for_completion=False):
        """ファイルを送る。"""
        return self._submit("file", wait_for_completion)


class VirusTotalAnalysisTimeoutTests(unittest.TestCase):
    """(b) 解析の終わりを待つのに、全体の上限（VT_ANALYSIS_TIMEOUT_SECONDS）を付ける。

    vt-py の wait_for_completion=True は 20 秒おきに終わるまで問い合わせ続け、上限が無い。
    終わらないと、そのメッセージの検査がいつまでも返らない。
    """

    def setUp(self):
        """鍵を入れ、待ちを短くし、結果の覚えを空にする。"""
        import services.virustotal_service as vts

        self.vts = vts
        for name, value in (
            ("VIRUSTOTAL_API_KEY", "dummy-key"),
            ("VT_ANALYSIS_TIMEOUT_SEC", 0.05),
            ("VT_ANALYSIS_POLL_SEC", 0.01),
        ):
            # create=True: 直す前のコード（定数が無い）でも同じテストを回せるように。
            p = patch.object(vts, name, value, create=True)
            p.start()
            self.addCleanup(p.stop)
        vts._vt_cache.clear()
        vts._vt_failure_cache.clear()
        self.addCleanup(vts._vt_cache.clear)
        self.addCleanup(vts._vt_failure_cache.clear)
        _NeverEndingVtClient.polls = 0
        _NeverEndingVtClient.submitted = []

    def test_a_url_analysis_that_never_ends_is_given_up(self):
        """終わらない URL の解析は、上限で諦めて「走査できなかった」にする。"""
        with (
            patch.object(self.vts.vt, "Client", _NeverEndingVtClient),
            patch.object(self.vts.logger, "error"),
        ):
            result = asyncio.run(self.vts.vt_check_url("https://never.example/"))
        self.assertEqual(
            result,
            {"status": "error", "type": "url", "reason": "analysis_timeout>0.05", "malicious": 0, "suspicious": 0},
        )
        # すぐに 1 回、待って問い合わせ直す（vt-py と同じ）。上限のあとは問い合わせない。
        self.assertGreaterEqual(_NeverEndingVtClient.polls, 2)
        self.assertLessEqual(_NeverEndingVtClient.polls, 8)

    def test_a_file_analysis_that_never_ends_is_given_up(self):
        """ファイルの解析も同じく、上限で諦めて「走査できなかった」にする。"""
        with (
            patch.object(self.vts.vt, "Client", _NeverEndingVtClient),
            patch.object(self.vts.logger, "error"),
        ):
            result = asyncio.run(self.vts.vt_check_file(b"never ending"))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "analysis_timeout>0.05")
        self.assertEqual((result["malicious"], result["suspicious"]), (0, 0))
        self.assertEqual(_NeverEndingVtClient.submitted, ["file"])

    def test_an_analysis_that_ends_is_still_waited_for(self):
        """上限の中で終わる解析は、これまでどおり結果を返す。"""

        class EndsOnThirdPoll(_NeverEndingVtClient):
            """3 回目の問い合わせで終わる。"""

            def get_object(self, path, *args):
                """3 回目で completed。"""
                type(self).polls += 1
                if type(self).polls >= 3:
                    return SimpleNamespace(id="an-1", status="completed", stats={"malicious": 4, "suspicious": 1})
                return SimpleNamespace(id="an-1", status="queued", stats={})

        EndsOnThirdPoll.polls = 0
        with (
            patch.object(self.vts, "VT_ANALYSIS_TIMEOUT_SEC", 5),
            patch.object(self.vts.vt, "Client", EndsOnThirdPoll),
        ):
            result = asyncio.run(self.vts.vt_check_url("https://ends.example/"))
        self.assertEqual(result, {"status": "ok", "type": "url", "malicious": 4, "suspicious": 1})


def _vt(*pairs, status="ok"):
    """VirusTotal の結果の並び。"""
    return [{"status": status, "type": "url", "malicious": m, "suspicious": s} for m, s in pairs]


class FinalEmbedLimitTests(unittest.TestCase):
    """(c) 結果の Embed を Discord の上限（項目 25 個・説明 4096 文字・全体 6000 文字）に収める。"""

    def setUp(self):
        """時刻を止める。"""
        import services.security_service as sec

        self.sec = sec
        p = patch.object(sec, "now_jst", lambda: "2026-11-28 09:00:00")
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def _total(embed):
        """Discord が数える文字数（題・説明・項目の名前と値・足元）。"""
        d = embed.to_dict()
        fields = d.get("fields", [])
        return (
            len(d.get("title", ""))
            + len(d.get("description", ""))
            + sum(len(f["name"]) + len(f["value"]) for f in fields)
            + len(d.get("footer", {}).get("text", ""))
        )

    def test_many_targets_are_folded_into_the_last_field(self):
        """走査の結果が多ければ、GPT 判定と理由の項目を残して 25 個に収め、残りを「…他N件」に畳む。"""
        results = _vt(*[(0, 0)] * 30) + _vt((12, 0))
        embed = self.sec.build_final_embed(results, "SAFE", ["VT_DANGEROUS", "GPT:SAFE"], ["x"])
        fields = embed.to_dict()["fields"]
        self.assertEqual(len(fields), 25)
        self.assertEqual(fields[-2]["name"], "[SAFE] GPT判定")
        self.assertEqual(fields[-1]["name"], "判定理由")
        self.assertEqual(fields[21]["name"], "[SAFE] ターゲット 22 (url)")
        # 隠れた中に危険があれば、畳んだ項目の印も危険。
        self.assertEqual(fields[22]["name"], "[ALERT] ターゲット 23〜31")
        self.assertEqual(fields[22]["value"], "…他9件")

    def test_exactly_enough_fields_are_not_folded(self):
        """ちょうど 25 個に収まるなら畳まない（理由の項目が無ければ 24 件まで並ぶ）。"""
        embed = self.sec.build_final_embed(_vt(*[(0, 0)] * 24), "SAFE", [], ["x"])
        fields = embed.to_dict()["fields"]
        self.assertEqual(len(fields), 25)
        self.assertEqual(fields[23]["name"], "[SAFE] ターゲット 24 (url)")

    def test_long_logs_are_folded_to_fit_the_description_and_the_total(self):
        """ログの行が長ければ、説明を 4096 文字・全体を 6000 文字に収め、はみ出す行を「…他N行」に畳む。"""
        logs = ["[2026-11-28 09:00:00] スキャン開始"] + [
            f"[SAFE] https://example.com/{'a' * 150}/{i} をスキャン: status=ok Malicious=0 Suspicious=0"
            for i in range(40)
        ]
        # 項目も長め（落とせなかったファイル）にして、説明の 4096 文字と項目を足すと 6000 文字を超える形にする。
        results = [{"status": "conflict_fallback", "type": "image", "malicious": -1, "suspicious": -1}] * 40
        embed = self.sec.build_final_embed(results, "SAFE", ["TOO_MANY_LINKS", "GPT:SAFE"], logs)
        d = embed.to_dict()
        self.assertLessEqual(len(d["description"]), 4096)
        self.assertLessEqual(self._total(embed), 6000)
        self.assertLessEqual(len(d["fields"]), 25)
        self.assertRegex(d["description"], r"\n…他\d+行$")
        self.assertTrue(d["description"].startswith("[2026-11-28 09:00:00] スキャン開始\n"))

    def test_a_small_result_is_unchanged(self):
        """上限に遠い結果は、これまでと同じ（説明はログの行をつないだもの、項目は全部）。"""
        embed = self.sec.build_final_embed(_vt((0, 0)), "SAFE", ["GPT:SAFE"], ["a", "b"])
        d = embed.to_dict()
        self.assertEqual(d["description"], "a\nb")
        self.assertEqual([f["name"] for f in d["fields"]], ["[SAFE] ターゲット 1 (url)", "[SAFE] GPT判定", "判定理由"])


def _member(*, roles=(), voice_channel=None, name="nelly"):
    """検査に通る、最小の Member。"""
    member = Mock(spec=discord.Member)
    member.id = 5
    member.bot = False
    member.guild = SimpleNamespace(id=1)
    member.roles = [SimpleNamespace(id=1, is_default=lambda: True)] + [
        SimpleNamespace(id=r, is_default=lambda: False) for r in roles
    ]
    member.joined_at = None
    member.display_name = name
    member.voice = SimpleNamespace(channel=SimpleNamespace(id=voice_channel)) if voice_channel else None
    member.mention = "@nelly"
    return member


class VcRaidCountsOnlyJoinsTests(unittest.TestCase):
    """(e) VC の荒らしの数え方には、VC への参加だけを入れる（発言は入れない）。"""

    def setUp(self):
        """荒らしの記録を空にし、時刻を止める。"""
        from services import raid_detection

        self.raid = raid_detection
        saved = {k: list(v) for k, v in raid_detection._vc_join_history.items()}
        raid_detection._vc_join_history.clear()
        self.addCleanup(
            lambda: (raid_detection._vc_join_history.clear(), raid_detection._vc_join_history.update(saved))
        )
        self.now = {"t": 1000.0}
        p = patch.object(raid_detection, "time", SimpleNamespace(time=lambda: self.now["t"]))
        p.start()
        self.addCleanup(p.stop)

    def _findings(self, member):
        """本物の _collect_findings を、外のものだけ差し替えて回す。"""
        import services.security_service as sec

        with (
            patch.object(sec, "check_spam", lambda g, u: (False, 1, float("inf"))),
            patch.object(sec, "gpt_assess", AsyncMock(return_value="SAFE")),
        ):
            return asyncio.run(sec._collect_findings(Mock(), 1, member, "VC から", [], [], []))

    def test_posts_in_voice_are_not_counted_as_joins(self):
        """VC の中で 20 秒に 5 回発言しても、VC の荒らしにならず、記録にも入らない。"""
        member = _member(voice_channel=777)
        for i in range(5):
            self.now["t"] = 1000.0 + i
            findings = self._findings(member)
            self.assertNotIn("VC_RAID", findings.reason_flags, i)
        self.assertEqual(self.raid._vc_join_history.get(777, []), [])

    def test_four_joins_and_a_post_are_not_a_raid(self):
        """似た名前の参加が 4 回のところへ、5 人目に似た名前の人が発言しても荒らしにしない。"""
        for i in range(4):
            self.raid.check_vc_raid(SimpleNamespace(display_name=f"raid_bot_0{i}", id=i), 777)
        findings = self._findings(_member(voice_channel=777, name="raid_bot_05"))
        self.assertNotIn("VC_RAID", findings.reason_flags)
        self.assertEqual(len(self.raid._vc_join_history[777]), 4)

    def test_a_raid_made_of_joins_is_still_seen_from_a_post(self):
        """参加の記録が荒らしの形（似た名前が 5 回）なら、VC にいる人の発言はこれまでどおり荒らしに数える。"""
        for i in range(5):
            self.raid.check_vc_raid(SimpleNamespace(display_name=f"raid_bot_0{i}", id=i), 777)
        findings = self._findings(_member(voice_channel=777, name="raid_bot_01"))
        self.assertIn("VC_RAID", findings.reason_flags)
        self.assertTrue(findings.danger)
        self.assertEqual(len(self.raid._vc_join_history[777]), 5, "発言を記録に足した")

    def test_old_joins_are_not_seen(self):
        """20 秒より前の参加は数えない（参加の側の数え方と同じ）。"""
        for i in range(5):
            self.raid.check_vc_raid(SimpleNamespace(display_name=f"raid_bot_0{i}", id=i), 777)
        self.now["t"] = 1020.0
        self.assertFalse(self.raid.is_vc_raid_ongoing(777))
        self.now["t"] = 1019.9
        self.assertTrue(self.raid.is_vc_raid_ongoing(777))


class HeaviestVirusTotalResultTests(unittest.TestCase):
    """(f) Groq の判定に使う VirusTotal の結果は、いちばん重いもの（危険 > 疑わしい）。"""

    def test_a_later_dangerous_result_wins(self):
        """前に「疑わしい」、後ろに「危険」があれば DANGEROUS。"""
        from services.content_moderation import gpt_assess

        self.assertEqual(asyncio.run(gpt_assess("x", _vt((0, 1), (30, 0)))), "DANGEROUS")
        self.assertEqual(asyncio.run(gpt_assess("x", _vt((3, 0), (0, 0), (10, 2)))), "DANGEROUS")

    def test_a_later_suspicious_result_wins_over_clean_ones(self):
        """前が引っかからず、後ろが「疑わしい」なら SUSPICIOUS（これまでどおり）。"""
        from services.content_moderation import gpt_assess

        self.assertEqual(asyncio.run(gpt_assess("x", _vt((0, 0), (-1, -1), (9, 0)))), "SUSPICIOUS")

    def test_nothing_flagged_goes_on_to_groq(self):
        """どれも引っかからなければ VirusTotal では決めない（鍵が無ければ SAFE）。"""
        import services.content_moderation as cm

        with patch.object(cm, "GROQ_API_KEY", ""):
            self.assertEqual(asyncio.run(cm.gpt_assess("x", _vt((0, 0), (-1, -1)))), "SAFE")


class _FakeGroqHandler(BaseHTTPRequestHandler):
    """台本どおりに答える偽物の Groq（届いた数を数える）。"""

    script: list = []
    hits = 0

    def do_POST(self):
        """台本の次の応答を返す（尽きたら最後の応答をくり返す）。"""
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).hits += 1
        status, headers = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if status == 200:
            body = json.dumps(
                {
                    "id": "x",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "m",
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": "SAFE"}, "finish_reason": "stop"}
                    ],
                }
            ).encode()
        else:
            body = json.dumps({"error": {"message": "org_secret123 rate limit", "type": "tokens"}}).encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """届いた依頼を標準エラーに書かない。"""


class GroqRetryTests(unittest.TestCase):
    """(g) 1 回の呼び出しで送るのは GROQ_MAX_RETRIES + 1 回まで。retry-after には上限を付ける。

    以前は SDK の再試行（2 回）とこちらの再試行（2 回）が掛け算になり、回数制限が続くと
    1 回で 9 回送っていた。retry-after は上限が無く、極端な値が来ると枠を持ったまま待ち続けた。
    """

    @classmethod
    def setUpClass(cls):
        """偽物の Groq を立てる。"""
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeGroqHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        """偽物を止める。"""
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        """鍵・場所・待ちを差し替え、使い回しのクライアントを捨てる。"""
        import services.groq_client as gc

        self.gc = gc
        for name, value in (
            ("GROQ_API_KEY", "test-key"),
            ("GROQ_MIN_REQUEST_INTERVAL_SECONDS", 0.0),
            ("GROQ_MAX_RETRIES", 2),
            ("GROQ_RETRY_BASE_DELAY_SECONDS", 0.01),
            ("GROQ_RETRY_MAX_DELAY_SECONDS", 0.01),
            ("GROQ_MAX_RETRY_AFTER_SECONDS", 0.01),
        ):
            # create=True: 直す前のコード（定数が無い）でも同じテストを回せるように。
            p = patch.object(gc, name, value, create=True)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(os.environ, {"GROQ_BASE_URL": self.base})
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(gc, "random", SimpleNamespace(uniform=lambda a, b: 0.0))
        p.start()
        self.addCleanup(p.stop)
        saved = dict(gc._clients)
        gc._clients.clear()
        self.addCleanup(lambda: (gc._clients.clear(), gc._clients.update(saved)))
        _FakeGroqHandler.hits = 0

    def _call(self, script):
        """台本を決めて 1 回呼ぶ。(結果か例外, 届いた数) を返す。"""
        _FakeGroqHandler.script = list(script)
        _FakeGroqHandler.hits = 0
        # クライアントは呼ぶたびに作り直す（前の asyncio.run のイベントループに結び付いたものを使わない）。
        self.gc._clients.clear()

        async def go():
            """10 秒で切る（上限が無いと、retry-after のぶん待ち続ける）。"""
            client = self.gc.get_groq_client(timeout=5.0, bucket="b12sec-test")
            return await asyncio.wait_for(
                self.gc.create_chat_completion(client, bucket="b12sec-test", model="m", messages=[]), 10
            )

        with patch.object(self.gc.logger, "warning"):
            try:
                outcome = asyncio.run(go())
            except Exception as e:  # noqa: BLE001 - 結果として比べる
                outcome = e
        return outcome, _FakeGroqHandler.hits

    def test_rate_limits_send_at_most_max_retries_plus_one(self):
        """回数制限が続いても、送るのは GROQ_MAX_RETRIES + 1（＝3）回まで。"""
        outcome, hits = self._call([(429, {"retry-after": "0"})])
        self.assertIsInstance(outcome, self.gc.RateLimitError)
        self.assertEqual(hits, 3)

    def test_an_extreme_retry_after_is_capped(self):
        """retry-after が極端（10 万秒）でも、上限だけ待って再試行する（待ち続けない）。"""
        rate_limited = (429, {"retry-after": "100000"})
        with patch.object(self.gc, "GROQ_MAX_RETRIES", 3):
            outcome, hits = self._call([rate_limited, rate_limited, rate_limited, (200, {})])
        self.assertNotIsInstance(outcome, Exception, outcome)
        self.assertEqual(hits, 4)

    def test_the_retry_after_reader_caps_the_value(self):
        """retry-after の読み方: 上限で切る・負と NaN は 0・読めなければ None。"""
        with patch.object(self.gc, "GROQ_MAX_RETRY_AFTER_SECONDS", 30.0):
            for header, want in (
                ("100000", 30.0),
                ("inf", 30.0),
                ("7", 7.0),
                ("-3", 0.0),
                ("nan", 0.0),
                ("soon", None),
            ):
                exc = SimpleNamespace(response=SimpleNamespace(headers={"retry-after": header}))
                self.assertEqual(self.gc._retry_after_seconds(exc), want, header)
            self.assertIsNone(self.gc._retry_after_seconds(SimpleNamespace(response=None)))

    def test_transient_server_errors_are_still_retried(self):
        """SDK が再試行していた一時的な失敗（5xx）も、こちらで再試行する（回数は同じく 3 回まで）。"""
        outcome, hits = self._call([(503, {}), (502, {}), (200, {})])
        self.assertNotIsInstance(outcome, Exception, outcome)
        self.assertEqual(hits, 3)
        outcome, hits = self._call([(500, {})])
        self.assertIsInstance(outcome, self.gc.APIStatusError)
        self.assertEqual(hits, 3)

    def test_what_the_sdk_would_not_retry_is_not_retried(self):
        """400 や x-should-retry: false の 5xx は再試行しない（SDK と同じ）。x-should-retry: true なら再試行する。"""
        outcome, hits = self._call([(400, {})])
        self.assertIsInstance(outcome, self.gc.BadRequestError)
        self.assertEqual(hits, 1)
        outcome, hits = self._call([(500, {"x-should-retry": "false"})])
        self.assertEqual(hits, 1)
        outcome, hits = self._call([(400, {"x-should-retry": "true"}), (200, {})])
        self.assertNotIsInstance(outcome, Exception, outcome)
        self.assertEqual(hits, 2)

    def test_the_sdk_does_not_retry_by_itself(self):
        """SDK の再試行は切ってある（再試行は create_chat_completion だけが受け持つ）。"""
        client = self.gc.get_groq_client(timeout=5.0, bucket="b12sec-test")
        self.assertEqual(client.max_retries, 0)


class FinalLogAfterNetworkFailureTests(unittest.TestCase):
    """(h) 結果の Embed の書き換えが通信で失敗しても、最後の「メッセージセキュリティ検査」を出す。"""

    def test_a_network_failure_while_editing_still_logs(self):
        """書き換えが aiohttp の通信の失敗・時間切れでも、最後のログを出し、例外を外へ出さない。"""
        import services.security_service as sec

        for failure in (aiohttp.ClientConnectionError("Connection reset by peer"), asyncio.TimeoutError()):
            logged = []

            async def log_action(bot, guild_id, level, message, **kwargs):
                """見出しを控える。"""
                logged.append(message)

            progress = SimpleNamespace(edit=AsyncMock(side_effect=failure))
            findings = sec._Findings(False, ["GPT:SAFE"], _vt((0, 0)), progress, "SAFE", 1)
            with patch.object(sec, "log_action", log_action), patch.object(sec.logger, "warning"):
                asyncio.run(sec._report_result(Mock(), 1, _member(), findings, ["https://a.example"], [], ["x"]))
            progress.edit.assert_awaited_once()
            self.assertEqual(logged, ["メッセージセキュリティ検査"], repr(failure))


class _Forbidden(discord.Forbidden):
    """権限不足（discord.Forbidden）。"""

    def __init__(self):
        """応答を組み立てずに作る。"""
        Exception.__init__(self, "403 Forbidden (error code: 50013): Missing Permissions")


class StripResultReportingTests(unittest.TestCase):
    """(i) 剥がした結果（剥がせたロール・剥がせなかったロール）を、ログチャンネルの報告に出す。"""

    def setUp(self):
        """security_service を読む。"""
        import services.security_service as sec

        self.sec = sec

    def _member_failing_at(self, roles, fail_at=None, error=None):
        """remove_roles が fail_at のロールで失敗する Member。送った順を控える。"""
        member = _member(roles=roles)
        sent = []

        async def remove_roles(*rs, reason=None):
            """1 回に 1 つずつ届くこと（discord.py の atomic と同じ送り方）を控える。"""
            sent.append([r.id for r in rs])
            if fail_at is not None and rs[0].id == fail_at:
                raise error or _Forbidden()

        member.remove_roles = remove_roles
        return member, sent

    def test_roles_are_removed_one_by_one_and_stop_at_the_first_failure(self):
        """1 つずつ外し、権限不足で止まる。剥がせたものと、残ったもの（失敗した 1 つと、その後ろ）を返す。"""
        member, sent = self._member_failing_at([11, 12, 13], fail_at=12)
        result = asyncio.run(self.sec.strip_roles(member))
        self.assertEqual(sent, [[11], [12]])
        self.assertEqual((result.ok, result.reason), (False, "forbidden"))
        self.assertEqual([r.id for r in result.removed], [11])
        self.assertEqual([r.id for r in result.kept], [12, 13])

    def test_the_report_fields(self):
        """報告の項目: 剥がしたロール（無ければ「なし」）と、残ったロール（理由つき）。"""
        member, _ = self._member_failing_at([11, 12, 13], fail_at=12)
        fields = self.sec.strip_fields(asyncio.run(self.sec.strip_roles(member)))
        self.assertEqual(fields, {"剥がしたロール": "<@&11>", "剥がせなかったロール（権限不足）": "<@&12> <@&13>"})
        member, _ = self._member_failing_at([11], fail_at=11, error=RuntimeError("boom"))
        with patch.object(self.sec.logger, "error"):
            fields = self.sec.strip_fields(asyncio.run(self.sec.strip_roles(member)))
        self.assertEqual(fields, {"剥がしたロール": "なし", "剥がせなかったロール（失敗）": "<@&11>"})
        member, _ = self._member_failing_at([11, 12])
        self.assertEqual(
            self.sec.strip_fields(asyncio.run(self.sec.strip_roles(member))), {"剥がしたロール": "<@&11> <@&12>"}
        )
        self.assertEqual(
            self.sec.strip_fields(asyncio.run(self.sec.strip_roles(_member()))), {"剥がしたロール": "なし"}
        )

    def test_many_roles_fit_in_one_field(self):
        """ロールが多くても 1 つの項目の上限（1024 文字）に収め、はみ出す分は「…他N個」。"""
        roles = list(range(10**18, 10**18 + 60))
        member, _ = self._member_failing_at(roles)
        value = self.sec.strip_fields(asyncio.run(self.sec.strip_roles(member)))["剥がしたロール"]
        self.assertLessEqual(len(value), 1024)
        self.assertRegex(value, r" …他\d+個$")

    def _check_message(self, member):
        """本物の handle_security_for_message を、危険（GPT の DANGEROUS）として回し、ログの項目を返す。"""
        logged = []

        async def log_action(bot, guild_id, level, message, **kwargs):
            """見出しと項目を控える。"""
            logged.append((message, kwargs.get("fields")))

        message = SimpleNamespace(
            author=member,
            guild=member.guild,
            channel=SimpleNamespace(id=77),
            content="危ない",
            attachments=[],
            delete=AsyncMock(),
        )
        with (
            patch.object(self.sec, "get_trusted_user_ids", lambda g: []),
            patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
            patch.object(self.sec, "get_response_channel_id", lambda g: None),
            patch.object(self.sec, "check_spam", lambda g, u: (False, 1, float("inf"))),
            patch.object(self.sec, "gpt_assess", AsyncMock(return_value="DANGEROUS")),
            patch.object(self.sec, "log_action", log_action),
            patch.object(self.sec, "send_log_embed", AsyncMock(return_value=None)),
        ):
            asyncio.run(self.sec.handle_security_for_message(Mock(), message))
        return dict(logged)

    def test_the_message_check_reports_what_was_stripped(self):
        """メッセージの検査で剥がしたら、「メッセージセキュリティ検査」に剥がした結果を足す。"""
        member, _ = self._member_failing_at([11, 12, 13], fail_at=13)
        fields = self._check_message(member)["メッセージセキュリティ検査"]
        self.assertEqual(fields["剥がしたロール"], "<@&11> <@&12>")
        self.assertEqual(fields["剥がせなかったロール（権限不足）"], "<@&13>")
        self.assertEqual(list(fields)[:4], ["理由", "GPT判定", "リンク数", "スパム回数"])

    def test_a_safe_message_has_no_strip_fields(self):
        """剥がさなかった（安全）なら、剥がした結果の項目は足さない。"""
        member, sent = self._member_failing_at([11])
        with patch.object(self.sec, "gpt_assess", AsyncMock(return_value="SAFE")):
            logged = []

            async def log_action(bot, guild_id, level, message, **kwargs):
                """項目を控える。"""
                logged.append(kwargs.get("fields"))

            message = SimpleNamespace(
                author=member, guild=member.guild, channel=SimpleNamespace(id=77), content="x", attachments=[]
            )
            with (
                patch.object(self.sec, "get_trusted_user_ids", lambda g: []),
                patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
                patch.object(self.sec, "get_response_channel_id", lambda g: None),
                patch.object(self.sec, "check_spam", lambda g, u: (False, 1, float("inf"))),
                patch.object(self.sec, "log_action", log_action),
            ):
                asyncio.run(self.sec.handle_security_for_message(Mock(), message))
        self.assertEqual(sent, [])
        self.assertNotIn("剥がしたロール", logged[-1])

    def test_the_vc_raid_report_shows_what_was_stripped(self):
        """VC の荒らしで剥がしたら、「VCレイド検出」に剥がした結果を足す。"""
        member, _ = self._member_failing_at([11, 12], fail_at=11)
        logged = []

        async def log_action(bot, guild_id, level, message, **kwargs):
            """見出しと項目を控える。"""
            logged.append((message, kwargs.get("fields")))

        after = SimpleNamespace(channel=SimpleNamespace(id=777, mention="<#777>"))
        with (
            patch.object(self.sec, "get_trusted_user_ids", lambda g: []),
            patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
            patch.object(self.sec, "check_vc_raid", lambda m, c: True),
            patch.object(self.sec, "log_action", log_action),
        ):
            asyncio.run(self.sec.handle_security_for_voice_join(Mock(), member, SimpleNamespace(channel=None), after))
        self.assertEqual(
            logged,
            [
                (
                    "VCレイド検出",
                    {
                        "チャンネル": "<#777>",
                        "剥がしたロール": "なし",
                        "剥がせなかったロール（権限不足）": "<@&11> <@&12>",
                    },
                )
            ],
        )


class ChatFailureIsNotShownTests(unittest.TestCase):
    """(j) AI の会話で Groq が失敗したら、決まった短い文だけを返し、失敗の文は履歴に入れない。"""

    def test_the_groq_error_is_logged_but_not_returned_or_remembered(self):
        """誤りの文（組織の ID などを含む）は返事にも履歴にも出さず、ログにだけ残す。"""
        from services import chatgpt_service

        chat = chatgpt_service.ChatGPT()
        failure = RuntimeError(
            "Error code: 429 - {'error': {'message': 'Rate limit reached in organization org_secret123'}}"
        )
        with (
            patch.object(chat, "_call_chat_api", AsyncMock(side_effect=failure)),
            self.assertLogs(chatgpt_service.logger, level="ERROR") as logs,
        ):
            reply = asyncio.run(chat.input_message("急げ"))
        self.assertEqual(reply, "ヴォルデモートでも手こずるとはな… 少し待ってから試せ。")
        self.assertEqual(reply, chatgpt_service.FAILURE_REPLY)
        self.assertEqual(chat.history, [{"role": "user", "content": "急げ"}])
        self.assertIn("org_secret123", "\n".join(logs.output))

    def test_the_next_request_does_not_carry_the_failure(self):
        """次の問い合わせに、失敗の文を送り返さない。"""
        from services import chatgpt_service

        chat = chatgpt_service.ChatGPT()
        call = AsyncMock(side_effect=[RuntimeError("org_secret123"), {"role": "assistant", "content": "待たせたな。"}])
        with patch.object(chat, "_call_chat_api", call), patch.object(chatgpt_service.logger, "exception"):
            asyncio.run(chat.input_message("急げ"))
            reply = asyncio.run(chat.input_message("まだか"))
        self.assertEqual(reply, "待たせたな。")
        sent = call.await_args_list[1].args[0]
        self.assertEqual([m["role"] for m in sent], ["system", "user", "user"])
        self.assertNotIn("org_secret123", json.dumps(sent, ensure_ascii=False))
        self.assertEqual(
            chat.history,
            [
                {"role": "user", "content": "急げ"},
                {"role": "user", "content": "まだか"},
                {"role": "assistant", "content": "待たせたな。"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
