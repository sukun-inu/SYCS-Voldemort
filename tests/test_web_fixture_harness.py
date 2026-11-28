"""Web の API の基準を作る道具（rust/apps/web/tests/fixtures/）が、決めたとおりに書き出すことのテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは小さな例の
文書を道具に通して、Rust のテストが頼りにする決めごと（偽物が効いている・状態は例の中で持ち越して例の間で消える・
書いたとおりの要求を送って記録する・見出しを並べ直す・書き漏らしと道具の誤りで止まる・何度作っても同じ）を確かめる。

道具は別のプロセスで回す。道具は import の前に環境変数を消して入れ直し、webapp/app.py を読み込むので、同じ
プロセスで回すと、ほかのテスト（tests/test_webapp.py など）が入れた環境（VAPID の鍵・許すホスト）を壊す。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "rust" / "apps" / "web" / "tests" / "fixtures"
GENERATOR = FIXTURES / "prices_calculate" / "generate.py"
SHIPPED_CASES = FIXTURES / "prices_calculate" / "cases.json"

GOLD_ROW = {
    "$row": {
        "snapshot_date": {"$date": "2026-11-27"},
        "price_per_gram": {"$decimal": "21345.6789"},
        "delta_from_previous": {"$decimal": "-123.4500"},
    },
}
SILVER_ROW = {
    "$row": {
        "snapshot_date": {"$date": "2026-11-27"},
        "price_per_gram": {"$decimal": "265.4321"},
        "delta_from_previous": None,
    },
}
SERVICE = {"load_latest_rows": {"$ref": "rows"}}
GOLD_10 = "/api/prices/calculate?metal=gold&grams=10"
GOLD_1 = "/api/prices/calculate?metal=gold&grams=1"
SILVER_2 = "/api/prices/calculate?metal=silver&grams=2"
DOCUMENT = {
    "now": "2026-11-28T10:00:00+09:00",
    "library": {"rows": {"gold": GOLD_ROW, "silver": SILVER_ROW}},
    "cases": [
        {
            "name": "two_requests",
            "note": "2 回目は最新の値段をキャッシュから読む",
            "service": SERVICE,
            "requests": [
                {"method": "GET", "target": GOLD_10, "expect_status": 200},
                {"method": "GET", "target": SILVER_2, "client": "203.0.113.9", "expect_status": 200},
            ],
        },
        {
            "name": "rate_limited",
            "service": SERVICE,
            "requests": [{"method": "GET", "target": GOLD_1, "repeat": 6}],
        },
        {
            "name": "fresh_state",
            "note": "前の例と同じ接続元・同じ要求でも、429 にならず DB を読み直す",
            "service": SERVICE,
            "requests": [{"method": "GET", "target": GOLD_1}],
        },
        {
            "name": "not_allowed",
            "requests": [{"method": "POST", "target": GOLD_10}],
        },
    ],
}


def _generate(document: dict) -> tuple[subprocess.CompletedProcess, str | None]:
    """例の文書を道具に通す（別のプロセスで。モジュールの説明）。書き出した基準の文字列も返す（失敗なら None）。"""
    with tempfile.TemporaryDirectory(prefix="web-fixture-test-") as tmp:
        cases = Path(tmp) / "cases.json"
        output = Path(tmp) / "expected.json"
        cases.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        done = subprocess.run(
            [sys.executable, str(GENERATOR), str(cases), str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            encoding="utf-8",
            timeout=300,
        )
        text = output.read_text(encoding="utf-8") if output.exists() else None
    return done, text


def _with_cases(*cases: dict) -> dict:
    """DOCUMENT の library と now のまま、例だけを差し替えた文書。"""
    return {**DOCUMENT, "cases": list(cases)}


class WebFixtureHarnessTests(unittest.TestCase):
    """小さな例の文書を 2 回道具に通し、書き出したものを確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp/app.py を読み込む）ので、文書ごとに 1 回だけ回す。"""
        cls.first, cls.first_text = _generate(DOCUMENT)
        cls.second, cls.second_text = _generate(DOCUMENT)
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.cases = {case["name"]: case for case in cls.output.get("cases", [])}

    def _statuses(self, name: str) -> list[int]:
        """その例の要求ごとの状態。"""
        return [step["response"]["status"] for step in self.cases[name]["steps"]]

    def test_the_generator_succeeds(self):
        """道具が最後まで回ること。

        回らなければ、CI の「基準」は expected.json を作れず、Rust のテストは比べる相手を持てない。
        """
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(sorted(self.cases), ["fresh_state", "not_allowed", "rate_limited", "two_requests"])

    def test_the_fake_rows_reach_the_payload(self):
        """偽物の行が、値段の計算の答えまで届くこと。

        偽物が効いていないと、要求は使われない番地の DB へ行って 500 になる。偽物が効いていても計算に
        使われていなければ、Rust は「何を返せばよいか」を基準から読めない。値は Decimal で掛けて切り捨てたもの
        （21345.6789×10＝213456.789、その 0.75 倍＝160092.59175）。
        """
        payload = self.cases["two_requests"]["steps"][0]["response"]["json"]
        self.assertEqual(payload["metal"], "gold")
        self.assertEqual(payload["display_name"], "金")
        self.assertEqual(payload["snapshot_date"], "2026-11-27")
        self.assertEqual(payload["price_per_gram"], 21345.6789)
        self.assertEqual(payload["pure_value"], 213456)
        self.assertEqual(payload["by_purity"]["18K"], 160092)

    def test_the_call_is_recorded_with_the_fake_session(self):
        """偽物に届いた呼び出しが、引数（偽物のセッション）まで記録されること。

        Rust のテストは、偽物の store に届いた呼び出しを基準と比べる。記録が無いと、キャッシュから返すべき
        2 回目に DB を読んでも気づけない。
        """
        calls = self.cases["two_requests"]["steps"][0]["calls"]
        self.assertEqual(calls, [{"fn": "load_latest_rows", "args": [{"$session": True}], "kwargs": {}}])

    def test_the_latest_prices_are_cached_within_a_case(self):
        """例の中では、2 回目の要求が最新の値段をキャッシュから読むこと（DB を読まない）。

        例の中でキャッシュが持ち越されないと、「20 秒は DB を読まない」振る舞いを基準にできない。
        """
        steps = self.cases["two_requests"]["steps"]
        self.assertEqual([len(step["calls"]) for step in steps], [1, 0])
        self.assertEqual(self._statuses("two_requests"), [200, 200])

    def test_the_rate_limit_counts_within_a_case(self):
        """例の中では、レート制限の数えが持ち越されること（calculate の枠は 5 回なので 6 回目が 429）。"""
        self.assertEqual(self._statuses("rate_limited"), [200, 200, 200, 200, 200, 429])
        refused = self.cases["rate_limited"]["steps"][-1]["response"]
        self.assertEqual(refused["json"], {"detail": "Too Many Requests"})
        self.assertIn(["retry-after", "60"], refused["headers"])

    def test_each_case_starts_with_empty_state(self):
        """次の例は、空のキャッシュと空のレート制限の数えで始まること。

        fresh_state は rate_limited と同じ接続元・同じ要求を送る。数えが残っていれば 429 に、キャッシュが
        残っていれば DB を読まずに返る。前の例の状態が残ると、例の並びを変えただけで基準が変わり、Rust の
        テストは例を 1 つずつ確かめられない。
        """
        steps = self.cases["fresh_state"]["steps"]
        self.assertEqual(self._statuses("fresh_state"), [200])
        self.assertEqual(len(steps[0]["calls"]), 1)

    def test_the_request_is_recorded_as_sent(self):
        """送った要求（target・接続元・見出し）が、そのまま記録されること。

        Rust のテストは、記録された要求を組み直して送る。既定の見出し（圧縮しない）と接続元が抜けると、
        Python と違う要求を送って比べることになる。
        """
        request = self.cases["two_requests"]["steps"][0]["request"]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["target"], GOLD_10)
        self.assertEqual(request["client"], "198.51.100.7")
        self.assertEqual(request["headers"], [["accept-encoding", "identity"], ["user-agent", "sycs-fixture"]])
        self.assertEqual(self.cases["two_requests"]["steps"][1]["request"]["client"], "203.0.113.9")

    def test_headers_are_sorted_by_name(self):
        """応答の見出しが名前の順に並ぶこと（405 の allow も記録されること）。

        Rust の見出しの順は Python と同じにならないので、並べ直さないと比べられない。
        """
        for case in self.cases.values():
            for step in case["steps"]:
                names = [name for name, _ in step["response"]["headers"]]
                self.assertEqual(names, sorted(names), case["name"])
        refused = self.cases["not_allowed"]["steps"][0]["response"]
        self.assertEqual(refused["status"], 405)
        self.assertIn("allow", [name for name, _ in refused["headers"]])

    def test_the_service_is_written_out_with_refs_resolved(self):
        """基準に、$ref を開いたあとの service と note が書かれること。

        Rust のテストは expected.json だけを読んで偽物の store を作る。$ref のまま書くと、Rust 側にも印の
        読み方を全部写すことになる。
        """
        case = self.cases["two_requests"]
        self.assertEqual(case["note"], "2 回目は最新の値段をキャッシュから読む")
        self.assertEqual(case["service"]["load_latest_rows"]["gold"], GOLD_ROW)
        self.assertEqual(self.cases["not_allowed"]["service"], {})

    def test_the_header_carries_what_the_rust_test_needs(self):
        """基準の先頭に、Rust のテストが app を組むのに要る値（環境変数・時刻・既定の接続元）があること。"""
        self.assertEqual(self.output["now"], DOCUMENT["now"])
        self.assertEqual(self.output["env"]["API_CALCULATE_RATE_LIMIT_PER_MINUTE"], "5")
        self.assertEqual(self.output["default_client"], "198.51.100.7")
        self.assertNotIn("POSTGRES_DSN", self.output["env"])

    def test_two_runs_write_the_same_bytes(self):
        """同じ文書から、2 回とも同じ基準ができること。

        揺れると、CI の「基準」が毎回差分を出して落ちる（何も変えていないのに）。
        """
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)


class WebFixtureHarnessStopsTests(unittest.TestCase):
    """道具が、例の書き漏らしと道具自身の誤りで止まること。

    止まらないと、間違った基準（全部 500・全部 400）が黙ってでき、Rust はそれに合わせてしまう。
    """

    def test_an_unwritten_service_stops_the_generator(self):
        """例に書いていない関数（DB を読む関数）が呼ばれたら止まること。"""
        case = {"name": "forgot_service", "requests": [{"method": "GET", "target": GOLD_10}]}
        done, _ = _generate(_with_cases(case))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("例に書いていない load_latest_rows", done.stderr)

    def test_a_wrong_expect_status_stops_the_generator(self):
        """状態が expect_status と違ったら止まること。"""
        request = {"method": "GET", "target": GOLD_10, "expect_status": 418}
        done, _ = _generate(_with_cases({"name": "wrong_status", "service": SERVICE, "requests": [request]}))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("道具の確かめでは 418", done.stderr)

    def test_a_misspelt_service_stops_the_generator(self):
        """service の鍵を書き間違えたら止まること（偽物が効かないまま進まない）。"""
        case = {"name": "typo", "service": {"load_latest_row": {"$ref": "rows"}}}
        done, _ = _generate(_with_cases({**case, "requests": [{"method": "GET", "target": GOLD_10}]}))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("差し替えられない service の鍵: load_latest_row", done.stderr)


class ShippedCasesTests(unittest.TestCase):
    """リポジトリに置いた例の文書（prices_calculate/cases.json）の形のテスト。道具は回さない。"""

    @classmethod
    def setUpClass(cls) -> None:
        """例の文書を読む。"""
        cls.document = json.loads(SHIPPED_CASES.read_text(encoding="utf-8"))

    def test_case_names_are_unique(self):
        """例の名前が重ならないこと（Rust のテストは名前で引く。道具も重なれば止まる）。"""
        names = [case["name"] for case in self.document["cases"]]
        self.assertEqual(len(names), len(set(names)))

    def test_every_request_is_complete(self):
        """要求ごとに method と target（/ から始まる）があり、repeat と expect_status は整数であること。

        欠けていると、道具は CI の「基準」で初めて落ちる（KeyError）。
        """
        for case in self.document["cases"]:
            self.assertTrue(case["requests"], case["name"])
            for request in case["requests"]:
                self.assertIn(request["method"], {"GET", "HEAD", "POST"}, case["name"])
                self.assertTrue(request["target"].startswith("/"), case["name"])
                self.assertGreaterEqual(int(request.get("repeat", 1)), 1, case["name"])
                self.assertIsInstance(request.get("expect_status", 0), int, case["name"])

    def test_every_ref_points_into_the_library(self):
        """$ref が library の名前を指していること（書き間違えると、道具は KeyError で止まる）。"""
        library = self.document["library"]
        missing = []

        def walk(value: object) -> None:
            """値をたどって、$ref の行き先を確かめる。"""
            if isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, dict):
                if "$ref" in value and value["$ref"] not in library:
                    missing.append(value["$ref"])
                for item in value.values():
                    walk(item)

        walk(self.document)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
