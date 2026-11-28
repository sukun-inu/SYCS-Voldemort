"""管理画面の利用者の状態の基準を作る道具（rust/apps/admin/tests/fixtures/users_state・users_state_db）のテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは:

- users_state/generate.py（API の基準。A0）を、リポジトリの cases.json のまま 2 回通し、Rust のテストが頼りにする
  決めごと（全部の例が同じ並びで書かれる・rust_skip の例も Python の答えは書く・何度作っても同じ）を確かめる
- users_state_db/generate.py（読み出しの基準。A4）は空の Postgres が要るので、ここでは Postgres の要らない部品
  （行のそろえ方・入れる文・step の形・文字の種類の表）だけを確かめる

道具は別のプロセスで回す（import の前に環境変数を消して入れ直し、webapp_admin/app.py を読み込むので、同じプロセスで
回すと、ほかのテストが入れた環境を壊す）。users_state_db の部品は、道具のモジュールを読み込んで呼ぶ（services は
関数の中でしか読み込まない）。
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "rust" / "apps" / "admin" / "tests" / "fixtures"
API_FIXTURE = FIXTURES / "users_state"
DB_FIXTURE = FIXTURES / "users_state_db"


def _generate_api() -> tuple[subprocess.CompletedProcess, str | None]:
    """リポジトリの users_state/cases.json を道具に通す（別のプロセスで）。書き出した基準の文字列も返す。"""
    with tempfile.TemporaryDirectory(prefix="admin-users-state-fixture-test-") as tmp:
        output = Path(tmp) / "expected.json"
        done = subprocess.run(
            [sys.executable, str(API_FIXTURE / "generate.py"), str(API_FIXTURE / "cases.json"), str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            encoding="utf-8",
            timeout=300,
        )
        text = output.read_text(encoding="utf-8") if output.exists() else None
    return done, text


def _load_db_generator():
    """users_state_db/generate.py をモジュールとして読み込む（main は動かさない。足された sys.path は戻す）。"""
    spec = importlib.util.spec_from_file_location("users_state_db_generate", DB_FIXTURE / "generate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    saved = list(sys.path)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved
    return module


class UsersStateApiFixtureTests(unittest.TestCase):
    """API の基準の道具を、リポジトリの例の文書のまま 2 回通して確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp_admin/app.py を読み込む）ので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate_api()
        cls.second, cls.second_text = _generate_api()
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads((API_FIXTURE / "cases.json").read_text(encoding="utf-8"))

    def _case(self, name: str) -> dict:
        """その名前の例の答え。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること（同じでなければ、CI の「基準」が落ち続ける）。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_case_is_written_in_order(self):
        """例の文書の全部の例が、同じ並びで書かれること（Rust のテストは並びが同じことを先に確かめる）。"""
        want = [case["name"] for case in self.document["cases"]]
        got = [case["name"] for case in self.output["cases"]]
        self.assertEqual(got, want)

    def test_skipped_cases_still_record_python(self):
        """rust_skip の例も、Python の答え（状態と本文）は書くこと（Python の振る舞いの記録として残す）。"""
        skipped = [case["name"] for case in self.document["cases"] if "rust_skip" in case]
        self.assertEqual(len(skipped), 3, skipped)
        for name in skipped:
            response = self._case(name)["response"]
            self.assertEqual(response["status"], 200, name)
            self.assertTrue(response["body"], name)

    def test_validation_comes_before_the_guild_id(self):
        """引数の検証（422）は int(session["guild_id"]) より先で、services を呼ばないこと。"""
        case = self._case("list_guild_not_a_number_and_bad_limit")
        self.assertEqual(case["response"]["status"], 422)
        self.assertEqual(case["calls"], [])
        crashed = self._case("list_guild_not_a_number")
        self.assertEqual(crashed["response"]["status"], 500)
        self.assertEqual(crashed["calls"], [])

    def test_huge_offsets_are_passed_through(self):
        """64 ビットを超える offset は、そのまま services に渡り（印つきで書く）、答えでは文字になること。"""
        case = self._case("list_offset_beyond_64_bits")
        self.assertEqual(case["calls"][0]["kwargs"]["offset"], {"$int": "100000000000000000000"})
        self.assertEqual(case["response"]["json"]["offset"], "100000000000000000000")


class UsersStateDbFixtureTests(unittest.TestCase):
    """読み出しの基準の道具の、Postgres の要らない部品を確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具のモジュールと例の文書を読む。"""
        cls.generator = _load_db_generator()
        cls.document = json.loads((DB_FIXTURE / "cases.json").read_text(encoding="utf-8"))

    def test_rows_fill_every_column(self):
        """current・events の行が既定と合わせて全部の列を持ち、ID が重ならないこと（足りなければ道具が止まる）。"""
        for columns_key, defaults_key, rows_key in (
            ("current_columns", "current_defaults", "current"),
            ("event_columns", "event_defaults", "events"),
        ):
            columns = self.document[columns_key]
            rows = self.generator.merged_rows(self.document[defaults_key], self.document[rows_key], columns)
            self.assertEqual([list(row) for row in rows], [columns] * len(rows))
            ids = [row["id"] for row in rows]
            self.assertEqual(len(ids), len(set(ids)), rows_key)
        with self.assertRaises(SystemExit):
            self.generator.merged_rows({}, [{"id": 1}], ["id", "user_id"])

    def test_timestamps_are_read_by_postgres(self):
        """入れる文は、時刻の列だけ文字を timestamptz に読ませ、ほかはそのまま渡すこと（Rust のテストも同じ文）。"""
        sql = self.generator.insert_sql("user_state_event", ["id", "event_at", "payload_json"])
        self.assertEqual(
            sql,
            "INSERT INTO user_state_event (id, event_at, payload_json) "
            "VALUES (:id, (:event_at)::text::timestamptz, :payload_json)",
        )

    def test_steps_are_well_formed(self):
        """step は名前が重ならず、fn の step は引数を全部持ち、sql の step は表を消す文だけであること。"""
        names = [step["name"] for step in self.document["steps"]]
        self.assertEqual(len(names), len(set(names)))
        for step in self.document["steps"]:
            if "sql" in step:
                self.assertTrue(step["sql"].startswith("DROP TABLE user_state_"), step["name"])
                continue
            name, args, _ = self.generator.call_arguments(step)
            self.assertIn(name, ("list_recent_user_states", "count_user_states", "get_user_state_detail"))
            self.assertTrue(args, step["name"])
        _, args, kwargs = self.generator.call_arguments(
            {"fn": "list", "guild_id": {"$int": "99999999999999999999"}, "query": None, "limit": 5, "offset": 0}
        )
        self.assertEqual(args, [99999999999999999999])
        self.assertEqual(kwargs, {"query": None, "limit": 5, "offset": 0})

    def test_digit_only_ranges_follow_unicodedata(self):
        """文字の種類の表が、isdigit で isdecimal でない文字だけを、昇順・重なり無しで持つこと。"""
        ranges = self.generator.digit_only_ranges()
        self.assertIn([0xB2, 0xB3], ranges)
        previous = -1
        for start, end in ranges:
            self.assertGreater(start, previous)
            previous = end
            for code in (start, end):
                char = chr(code)
                self.assertTrue(char.isdigit() and not char.isdecimal(), hex(code))
                self.assertIsNotNone(unicodedata.numeric(char, None), hex(code))
        self.assertFalse(any(start <= ord("5") <= end for start, end in ranges))

    def test_build_needs_a_database(self):
        """空の Postgres の接続先が無ければ、行を入れる前に止まること（本物の DB を触らない）。"""
        with patch.dict(os.environ, {"USER_STATE_POSTGRES_DSN": ""}):
            with self.assertRaises(SystemExit):
                self.generator.build(self.document)


if __name__ == "__main__":
    unittest.main()
