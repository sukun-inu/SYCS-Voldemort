"""管理画面の監視の基準を作る道具（rust/apps/admin/tests/fixtures/monitor・prometheus。A7）のテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは、リポジトリの
cases.json のまま道具を 2 回ずつ通し、次を確かめる:

- 最後まで回り、2 回作ってバイトまで同じこと（時刻・ID・置き場の中身を例で決めているか。本物の監視のスレッドが例の
  置き場に書き込んでいないか）
- 全部の例が同じ並びで書かれること（Rust のテストは並びで突き合わせる）
- いちばん大事な /metrics の接続元の判定が、本番の並び（uvicorn の ProxyHeadersMiddleware → app）で、nginx の後ろの
  外の利用者を断り、ホストの Netdata を通すこと
- 道具の差し替え（偽物の psutil・時計・Valkey・バックアップの置き場）が効いていること（いくつかの答えを、読んだ
  コードから決まる値で確かめる）

道具は別のプロセスで回す（import の前に環境変数を消して入れ直し、webapp_admin/app.py を読み込むので、同じプロセスで
回すと、ほかのテストが入れた環境を壊す）。
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
MONITOR = FIXTURES / "monitor"
PROMETHEUS = FIXTURES / "prometheus"


def _generate(fixture: Path) -> tuple[subprocess.CompletedProcess, str | None]:
    """リポジトリの cases.json を道具に通す（別のプロセスで）。書き出した基準の文字列も返す。"""
    with tempfile.TemporaryDirectory(prefix="admin-monitor-fixture-test-") as tmp:
        output = Path(tmp) / "expected.json"
        done = subprocess.run(
            [sys.executable, str(fixture / "generate.py"), str(fixture / "cases.json"), str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            encoding="utf-8",
            timeout=600,
        )
        text = output.read_text(encoding="utf-8") if output.exists() else None
    return done, text


class MonitorFixtureTests(unittest.TestCase):
    """monitor/generate.py（/admin/api/metrics・incidents、整形、/proc、巡回）を 2 回通して確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp_admin/app.py を読み込む）ので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate(MONITOR)
        cls.second, cls.second_text = _generate(MONITOR)
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads((MONITOR / "cases.json").read_text(encoding="utf-8"))

    def _case(self, name: str) -> dict:
        """その名前の API の例の答え。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]["response"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること（同じでなければ、CI の「基準」が落ち続ける）。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_section_is_written_in_order(self):
        """6 つの節の全部の例が、同じ並びで書かれること。"""
        for section in ("cases", "procfs", "downtime", "heartbeat", "alerts"):
            want = [case["name"] for case in self.document[section]]
            got = [case["name"] for case in self.output[section]]
            self.assertEqual(got, want, section)

    def test_the_fakes_are_used(self):
        """偽物の psutil・時計・要求の時刻が効いていること（読んだコードから決まる値）。"""
        metrics = self._case("metrics_basic")["json"]
        self.assertEqual(metrics["updated_at"], "10:02:03")
        self.assertEqual(metrics["metrics"]["cpu"]["display"], "12.3%")
        self.assertEqual(metrics["metrics"]["cpu"]["detail"], "論理コア 8")
        self.assertEqual(metrics["metrics"]["memory"]["detail"], "3.5 GB / 7.7 GB")
        self.assertEqual(metrics["metrics"]["tps"]["display"], "0.27 req/s")
        self.assertEqual(metrics["metrics"]["tps"]["detail"], "目標 50 req/s の 1%")
        self.assertEqual(metrics["metrics"]["sla"]["display"], "100.00%")
        self.assertEqual(metrics["runtime"], {"admin_app": "1h 2m", "host": "12d 6h"})

    def test_sla_counts_only_downtime_in_this_month(self):
        """SLA は、月初からの downtime の重なりだけを引くこと（月をまたぐもの・未来・ほかの種類は数えない）。"""
        sla = self._case("metrics_sla_with_downtime")["json"]["metrics"]["sla"]
        self.assertEqual(sla["display"], "99.71%")
        self.assertEqual(sla["tone"], "warning")
        self.assertEqual(sla["detail"], "記録済み停止 1h 2m")

    def test_failures_are_server_errors(self):
        """測れない・インシデントのファイルが UTF-8 でないときは 500 の JSON になること。"""
        for name in ("metrics_host_fails", "metrics_incidents_not_utf8", "incidents_not_utf8"):
            response = self._case(name)
            self.assertEqual(response["status"], 500, name)
            self.assertEqual(response["json"], {"detail": "サーバーエラーが発生しました。"}, name)

    def test_incidents_are_listed_newest_first(self):
        """一覧は新しい順で、str.splitlines() の区切り（\\x0b・\\x1c・\\x85・\\u2028 など）で行を割ること。"""
        listed = self._case("incidents_listing")["json"]["incidents"]
        ids = [incident["id"] for incident in listed]
        self.assertEqual(ids[:4], ["last", "cr-only", "after-nel", "nel"])
        self.assertIn("after-vt", ids)
        self.assertNotIn("bom", ids)
        self.assertEqual(len(listed), 18)
        limited = self._case("incidents_limit_is_thirty")["json"]["incidents"]
        self.assertEqual([item["id"] for item in limited][::29], ["n35", "n06"])

    def test_heartbeat_and_downtime(self):
        """心拍は .tmp を残さず、猶予を超えた停止だけが 1 行になること。"""
        for case in self.output["heartbeat"]:
            self.assertEqual(case["files"], ["heartbeat.json"], case["name"])
        downtime = {case["name"]: case for case in self.output["downtime"]}
        self.assertEqual(downtime["within_grace"]["lines"], [])
        self.assertEqual(downtime["exactly_the_grace"]["lines"], [])
        self.assertEqual(len(downtime["beyond_the_grace"]["lines"]), 1)
        self.assertEqual(downtime["not_utf8"]["error"], "UnicodeDecodeError")


class PrometheusFixtureTests(unittest.TestCase):
    """prometheus/generate.py（/metrics の接続元の判定と本文）を 2 回通して確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重いので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate(PROMETHEUS)
        cls.second, cls.second_text = _generate(PROMETHEUS)
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads((PROMETHEUS / "cases.json").read_text(encoding="utf-8"))

    def _response(self, name: str) -> dict:
        """その名前の要求の答え。"""
        found = [case for case in self.output.get("requests", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]["response"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_request_is_written_in_order(self):
        """全部の要求の例が、同じ並びで書かれること。"""
        want = [case["name"] for case in self.document["requests"]]
        self.assertEqual([case["name"] for case in self.output["requests"]], want)

    def test_clients_behind_nginx_are_judged_after_the_proxy(self):
        """nginx の後ろでは、TCP の相手（nginx）ではなく、X-Forwarded-For で直した接続元で判定すること。"""
        self.assertEqual(self._response("nginx_forwards_netdata")["status"], 200)
        for name in ("nginx_forwards_outside", "tunnel_through_nginx", "spoofed_loopback_through_tunnel"):
            response = self._response(name)
            self.assertEqual(response["status"], 403, name)
            self.assertEqual(response["body"], "Forbidden\n", name)

    def test_the_body_comes_from_the_fake_valkey(self):
        """本文が偽物の Valkey の中身と、時計・バックアップの置き場から組み立てられていること。"""
        body = self._response("body_full")["body"]
        for line in (
            'sycs_up{app="bot"} 1',
            'sycs_up{app="web"} 0',
            "sycs_shared_cache_available 1",
            'sycs_requests_total{app="admin"} 1234',
            'sycs_arabic{v="1"} 123',
            'sycs_big{v="1"} 1000000000000000.0',
            "sycs_backup_age_seconds 101.25",
            "sycs_backup_status 1",
        ):
            self.assertIn(line + "\n", body, line)
        partial = self._response("body_scan_fails_on_the_second_page")["body"]
        self.assertIn("sycs_shared_cache_available 0\n", partial)
        self.assertIn('sycs_up{app="bot"} 1\n', partial)

    def test_the_scan_is_recorded(self):
        """Valkey から読めたもの（途中で切れたら、それまでの分）と、届いた SCAN・MGET が書かれること。"""
        scans = {case["name"]: case["scan"] for case in self.output["requests"]}
        partial = scans["body_scan_fails_on_the_second_page"]
        self.assertEqual(partial["items"], {"hb:bot": "1799999995.25"})
        self.assertFalse(partial["available"])
        self.assertEqual(partial["calls"][0], ["scan", 0, "sycs:metrics:*", 256])
        self.assertEqual(scans["body_not_configured"], {"items": {}, "available": False, "calls": []})

    def test_functions(self):
        """許す帯域 × 接続元の表と、値の読み方・書き方。"""
        functions = self.output["functions"]
        allowed = {(row[0], row[1]): row[2] for row in functions["client_allowed"]}
        self.assertTrue(allowed[(None, "127.0.0.1")])
        self.assertTrue(allowed[("10.0.0.1/8", "10.1.2.3")])
        self.assertFalse(allowed[("10.0.0.0/255.0.255.0", "10.1.2.3")])
        self.assertFalse(allowed[(None, None)])
        floats = dict((row[0], row[1]) for row in functions["parse_float"])
        self.assertEqual(floats[" 7 "], "7.0")
        self.assertIsNone(floats["1__0"])
        formats = dict((row[0], row[1]) for row in functions["format_value"])
        self.assertEqual(formats["nan"]["error"], "ValueError")
        self.assertEqual(formats["3.0"], {"value": "3"})


if __name__ == "__main__":
    unittest.main()
