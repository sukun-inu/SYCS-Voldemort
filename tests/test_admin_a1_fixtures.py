"""管理画面の骨組みの基準を作る道具（rust/apps/admin/tests/fixtures/ の session と errors）が決めたとおりに書くこと。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは小さな例の文書を
道具に通して、Rust のテストが頼りにする決めごと（Cookie の値を埋めて記録する・読めない Cookie は例外の名前を書く・
作った秘密鍵の中身は書かない・基準のためだけの経路が効いている・CSRF の印とインシデントの ID と時刻が決まった並びに
なる・数とインシデントを例ごとに区切る・何度作っても同じ）を確かめる。

道具は別のプロセスで回す。道具は import の前に環境変数を消して入れ直し、webapp_admin/app.py を読み込むので、同じ
プロセスで回すと、ほかのテスト（tests/test_admin_api.py など）が入れた環境を壊す。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "rust" / "apps" / "admin" / "tests" / "fixtures"
SESSION_GENERATOR = FIXTURES / "session" / "generate.py"
ERRORS_GENERATOR = FIXTURES / "errors" / "generate.py"
SECRET = "w2-admin-fixture-secret-0123456789abcdef0123456789abcdef"
NOW = 1798761600
TOKEN = "0123456789abcdef" * 4

SESSION_DOCUMENT = {
    "secret": SECRET,
    "now": NOW,
    "signing": [
        {"name": "minimal", "session": {"user": {"id": "1"}, "guild_id": 999}},
        {"name": "expired", "session": {"user": {"id": "1"}}, "signed_at": NOW - 3601},
    ],
    "raw": [{"name": "garbage", "payload": "!!!"}, {"name": "empty", "payload": "e30="}],
    "reading": [
        {"name": "fresh", "cookies": ["admin_session={signing:minimal}"], "ops": [["access"]]},
        {"name": "expired", "cookies": ["admin_session={signing:expired}"]},
        {"name": "tampered", "cookies": ["admin_session={tampered:minimal}"]},
        {"name": "garbage", "cookies": ["admin_session={raw:garbage}"]},
        {"name": "cleared", "cookies": ["admin_session={raw:empty}"], "ops": [["clear"]]},
    ],
    "secrets": [
        {"name": "env", "env": " from-env ", "setup": "dir"},
        {"name": "generated", "setup": "dir"},
        {"name": "short", "setup": "dir", "file_text": "short"},
    ],
    "dumps": [{"a": "テ"}],
    "floats": [1e16],
    "b64decode": ["e30"],
    "cookie_headers": [["a=1; a=2"]],
    "ints": [" 0012 ", "x"],
    "compact": [[{"id": " 7 ", "name": None}]],
    "forms": [
        {"name": "form", "content_type": "application/x-www-form-urlencoded", "body": [["a=1&a=2", 1]]},
        {"name": "many", "content_type": "application/x-www-form-urlencoded", "body": [["a=1&", 1001]]},
    ],
}

ERRORS_DOCUMENT = {
    "secret": SECRET,
    "now": NOW,
    "sessions": {
        "csrf": {"user": {"id": "1"}, "guild_id": 999, "_csrf_token": TOKEN},
        "minimal": {"user": {"id": "1"}, "guild_id": 999},
    },
    "cases": [
        {
            "name": "page_and_crash",
            "requests": [
                {"method": "GET", "target": "/nope", "expect_status": 404},
                {"method": "GET", "target": "/nope", "expect_status": 404},
                {"method": "GET", "target": "/admin/api/__a1/crash?type=RuntimeError&message=x", "expect_status": 500},
            ],
        },
        {
            "name": "checks",
            "env": {"DEV_USER_ID": "1"},
            "requests": [
                {"method": "GET", "target": "/admin/api/__a1/dev", "session": "minimal", "expect_status": 200},
                {
                    "method": "POST",
                    "target": "/admin/api/__a1/csrf",
                    "session": "csrf",
                    "headers": {"x-csrftoken": TOKEN},
                    "expect_status": 200,
                },
                {"method": "GET", "target": "/admin/dev", "repeat": 3, "expect_status": 303},
            ],
        },
        {
            "name": "fresh_numbers",
            "note": "前の例のあとでも、数とインシデントと印の並びは 1 から",
            "requests": [{"method": "GET", "target": "/admin/api/__a1/status/503", "expect_status": 503}],
        },
    ],
}


def _generate(generator: Path, document: dict) -> tuple[subprocess.CompletedProcess, str | None]:
    """例の文書を道具に通す（別のプロセスで。モジュールの説明）。書き出した基準の文字列も返す（失敗なら None）。"""
    with tempfile.TemporaryDirectory(prefix="admin-a1-fixture-test-") as tmp:
        cases = Path(tmp) / "cases.json"
        output = Path(tmp) / "expected.json"
        cases.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        done = subprocess.run(
            [sys.executable, str(generator), str(cases), str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            encoding="utf-8",
            timeout=600,
        )
        text = output.read_text(encoding="utf-8") if output.exists() else None
    return done, text


class SessionFixtureTests(unittest.TestCase):
    """セッションの基準の道具を 2 回通し、書き出したものを確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp_admin/app.py を読み込む）ので、1 回だけ回す（何度作っても同じかを見るため 2 回）。"""
        cls.first, cls.first_text = _generate(SESSION_GENERATOR, SESSION_DOCUMENT)
        cls.second, cls.second_text = _generate(SESSION_GENERATOR, SESSION_DOCUMENT)
        cls.output = json.loads(cls.first_text) if cls.first_text else {}

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じこと（作った秘密鍵の中身は書かないので、乱数に揺れない）。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_cookies_are_filled_into_the_reading_table(self):
        """読み方の表の Cookie が、signing・raw の値で埋められて記録されること（Rust は記録どおりに送る）。"""
        reading = {case["name"]: case for case in self.output["reading"]}
        minimal = self.output["signing"][0]["cookie"]
        self.assertEqual(reading["fresh"]["cookies"], [f"admin_session={minimal}"])
        self.assertNotEqual(reading["tampered"]["cookies"], [f"admin_session={minimal}"])
        self.assertEqual(reading["fresh"]["session_json"], '{"user": {"id": "1"}, "guild_id": 999}')
        self.assertEqual(reading["fresh"]["headers"], [["vary", "Cookie"]])
        self.assertEqual(reading["expired"]["session_json"], "{}")
        self.assertEqual(reading["garbage"]["raised"], "JSONDecodeError")
        self.assertEqual(reading["cleared"]["headers"][1][0], "set-cookie")
        self.assertIn("admin_session=null;", reading["cleared"]["headers"][1][1])

    def test_secrets_are_recorded_without_random_values(self):
        """秘密鍵の表は、環境変数と読んだファイルの鍵だけを書き、作った鍵は長さと形とファイルとの一致だけを書くこと。"""
        secrets_table = {case["name"]: case for case in self.output["secrets"]}
        self.assertEqual(secrets_table["env"]["source"], "env")
        self.assertEqual(secrets_table["env"]["secret"], "from-env")
        self.assertEqual(secrets_table["generated"]["source"], "generated")
        self.assertIsNone(secrets_table["generated"]["secret"])
        self.assertIsNone(secrets_table["generated"]["file_after_hex"])
        self.assertTrue(secrets_table["generated"]["file_is_the_secret"])
        self.assertEqual(secrets_table["generated"]["length"], 64)
        self.assertEqual(secrets_table["short"]["source"], "temporary")
        self.assertEqual(secrets_table["short"]["file_after_hex"], b"short".hex())

    def test_parts_are_recorded(self):
        """部品ごとの表が、本物の Python の答えで埋まること。"""
        self.assertEqual(self.output["dumps"][0]["default"], '{"a": "\\u30c6"}')
        self.assertEqual(self.output["floats"][0]["repr"], "1e+16")
        self.assertIsNone(self.output["b64decode"][0]["standard"])
        self.assertEqual(self.output["cookie_headers"][0]["cookies"], [["a", "2"]])
        self.assertEqual(self.output["ints"][0]["text"], "12")
        self.assertEqual(self.output["ints"][1]["raised"], "ValueError")
        self.assertEqual(self.output["compact"][0]["compact"], [{"id": "7", "name": "Unknown", "icon": None}])
        forms = {case["name"]: case for case in self.output["forms"]}
        self.assertEqual(forms["form"]["items"], [["a", "1"], ["a", "2"]])
        self.assertEqual(forms["many"]["status"], 400)


class ErrorsFixtureTests(unittest.TestCase):
    """骨組みの基準の道具を 2 回通し、書き出したものを確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重いので、文書ごとに 2 回だけ回す。"""
        cls.first, cls.first_text = _generate(ERRORS_GENERATOR, ERRORS_DOCUMENT)
        cls.second, cls.second_text = _generate(ERRORS_GENERATOR, ERRORS_DOCUMENT)
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.cases = {case["name"]: case for case in cls.output.get("cases", [])}

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り（例の expect_status も通り）、2 回作ってバイトまで同じこと。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_tokens_and_incidents_follow_the_sequence(self):
        """HTML のページで入る CSRF の印と、インシデントの ID・時刻が、決まった並び（例ごとに 1 から）になること。"""
        case = self.cases["page_and_crash"]
        first = dict(case["steps"][0]["response"]["headers"])
        second = dict(case["steps"][1]["response"]["headers"])
        self.assertIn("set-cookie", first)
        # Cookie は持ち越さないので、2 回目も印を入れ直す。並びは進むので、Cookie の値は 1 回目と違う。
        self.assertNotEqual(first["set-cookie"], second["set-cookie"])
        self.assertEqual(len(case["incidents"]), 1)
        incident = json.loads(case["incidents"][0])
        self.assertEqual(incident["id"], f"{0x1D000000 + 1:032x}")
        self.assertEqual(incident["created_epoch"], NOW + 0.25)
        self.assertEqual(incident["title"], "RuntimeError")
        self.assertEqual(incident["metadata"]["remote_addr"], "testclient")
        fresh = self.cases["fresh_numbers"]
        self.assertEqual(json.loads(fresh["incidents"][0])["id"], f"{0x1D000000 + 1:032x}")

    def test_probes_and_counters(self):
        """基準のためだけの経路が効き（確かめを通ると 200）、数が例ごとに区切られること。"""
        case = self.cases["checks"]
        self.assertEqual(case["dev_user_id"], "1")
        self.assertEqual(case["steps"][0]["response"]["json"], {"ok": True, "user": {"id": "1"}})
        self.assertEqual(case["steps"][2]["repeat"], 3)
        requests_total = [item for item in case["counters"] if item[0] == "requests_total"]
        self.assertEqual(requests_total, [["requests_total", {"app": "admin"}, 5]])
        fresh = self.cases["fresh_numbers"]
        self.assertIn(["http_responses_total", {"app": "admin", "code": "503"}, 1], fresh["counters"])

    def test_requests_are_recorded_as_sent(self):
        """送った要求が、TestClient が付けた見出しと本文ごと記録されること（Rust は同じものを渡す）。"""
        step = self.cases["checks"]["steps"][1]["request"]
        names = [name for name, _ in step["headers"]]
        self.assertIn("host", names)
        self.assertIn("cookie", names)
        self.assertEqual(step["body_hex"], "")


if __name__ == "__main__":
    unittest.main()
