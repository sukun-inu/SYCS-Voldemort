"""管理画面の設定パネルの書く側の基準を作る道具（rust/apps/admin/tests/fixtures/validation・apps_write）のテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは、
リポジトリの cases.json をそのまま道具に 2 回通して、Rust のテストが頼りにする決めごと（宣言の入力欄を全部通す・
本物の置き場に書いて版番号が上がる・時刻と ID が決まった並び・何度作っても同じ）を確かめる。

道具は別のプロセスで回す（import の前に環境変数を消して入れ直し、webapp_admin を読み込むため。a5 のテストと同じ）。
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
GUILD = "900000000000000001"
STAMP_KEY = "_updated_at"


def _generate(name: str) -> tuple[subprocess.CompletedProcess, str | None]:
    """その基準のリポジトリの cases.json を道具に通す（別のプロセスで）。書き出した文字列も返す（失敗なら None）。"""
    folder = FIXTURES / name
    with tempfile.TemporaryDirectory(prefix=f"admin-{name}-fixture-test-") as tmp:
        output = Path(tmp) / "expected.json"
        done = subprocess.run(
            [sys.executable, str(folder / "generate.py"), str(folder / "cases.json"), str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            encoding="utf-8",
            timeout=900,
        )
        text = output.read_text(encoding="utf-8") if output.exists() else None
    return done, text


class ValidationFixtureTests(unittest.TestCase):
    """入力の検証の基準（fixtures/validation）の道具。"""

    @classmethod
    def setUpClass(cls) -> None:
        """2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate("validation")
        cls.second, cls.second_text = _generate("validation")
        cls.output = json.loads(cls.first_text) if cls.first_text else {}

    def _result(self, panel: str, key: str, raw: object, choices: str = "none", collection: str | None = None) -> dict:
        """その入力欄にその入力を通した答え。"""
        fields = self.output["fields"]
        index = next(
            i for i, f in enumerate(fields) if (f["panel"], f["collection"], f["key"]) == (panel, collection, key)
        )
        position = self.output["raws"].index(raw)
        found = [r for r in self.output["rows"] if (r["f"], r["c"], r["r"]) == (index, choices, position)]
        self.assertEqual(len(found), 1, (panel, key, raw, choices))
        return found[0]["result"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること（set の並びなどが答えに出ていない）。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_schema_field_is_listed(self):
        """schema.json の入力欄（パネルの直下と一覧）が、ちょうど全部、宣言の並びで表に載ること。"""
        schema = json.loads((FIXTURES / "schema" / "schema.json").read_text(encoding="utf-8"))
        want = []
        for panel in schema["panels"]:
            for section in panel["wire"]["sections"]:
                want.extend((panel["id"], None, field["key"]) for field in section["fields"])
            for section in panel["wire"]["sections"]:
                for collection in section["collections"]:
                    want.extend((panel["id"], collection["key"], field["key"]) for field in collection["fields"])
        got = [(f["panel"], f["collection"], f["key"]) for f in self.output["fields"]]
        self.assertEqual(got, want)

    def test_ids_are_checked_against_the_list(self):
        """ID は一覧が取れていればその中だけ、取れていなければ数字なら通り、上付きの数字は拾われない ValueError。"""
        self.assertEqual(self._result("logging", "log_channel_id", " 12 ", "full"), {"value": 12})
        self.assertEqual(
            self._result("logging", "log_channel_id", "800000000000000099", "full"),
            {"invalid": "一覧にない項目です。選び直してください。"},
        )
        self.assertEqual(self._result("logging", "log_channel_id", "800000000000000099"), {"value": 800000000000000099})
        raised = self._result("logging", "log_channel_id", "²")
        self.assertEqual(raised["raises"]["type"], "ValueError")

    def test_durations_use_units(self):
        """期間の範囲の文は単位つき（1分・30日）。"""
        self.assertEqual(self._result("djaudio", "cache_ttl", 59), {"invalid": "1分 以上で入力してください。"})
        self.assertEqual(self._result("djaudio", "cache_ttl", 2592001), {"invalid": "30日 以下で入力してください。"})
        self.assertIn([60, "1分"], self.output["humanize"])

    def test_long_texts_are_refused_before_they_are_cut(self):
        """長さの上限を超えた文字は、黙って切らずに断ること（削る前の長さで数える）。"""
        result = self._result("tts", "word", "x" * 51, collection="dictionary")
        self.assertEqual(result, {"invalid": "50 文字以内で入力してください。"})


class AppsWriteFixtureTests(unittest.TestCase):
    """設定パネルの書く側の基準（fixtures/apps_write）の道具。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（app.py を読み込み、偽物 2 つと置き場を例ごとに立てる）ので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate("apps_write")
        cls.second, cls.second_text = _generate("apps_write")
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads((FIXTURES / "apps_write" / "cases.json").read_text(encoding="utf-8"))

    def _steps(self, name: str) -> list[dict]:
        """その名前の例の要求の控え。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]["steps"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。

        回らなければ CI の「基準」は expected.json を作れない。同じにならなければ（時刻・ID・置き場の版番号・
        偽物の口が答えに出る）、作り直すたびに基準の差分が出て CI が落ち続ける。
        """
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_case_is_written_in_order(self):
        """例の文書の全部の例が、同じ並びで、要求の数も同じに書かれること（Rust のテストは並びのまま読む）。"""
        want = [(case["name"], len(case["steps"])) for case in self.document["cases"]]
        got = [(case["name"], len(case["steps"])) for case in self.output["cases"]]
        self.assertEqual(got, want)

    def test_writes_go_through_the_real_store(self):
        """書くたびに本物の置き場の版番号が上がり（変わらなければ上がらない）、触られた時刻が押されること。

        置き場を差し替えていなければ（settings.json に書いていれば）、版番号は 0 のまま変わらない。
        """
        first, second = self._steps("logging_save_all")
        self.assertEqual(first["writes"], [2, 3, 3])
        self.assertEqual(second["writes"], [3, 3, 3])
        guild = first["settings"][GUILD]
        self.assertEqual(guild["log_channel_id"], 800000000000000002)
        self.assertEqual(guild[STAMP_KEY], self.output["stamp"])
        self.assertNotIn("response_channel_id", guild)

    def test_stored_nulls_are_rewritten_without_a_stamp(self):
        """null が保存されていると、値を変えなくても null を落として書き直し（版番号が上がる）、時刻は押さないこと。"""
        step = self._steps("logging_stored_nulls_are_rewritten_without_a_stamp")[0]
        self.assertEqual(step["writes"], [2])
        self.assertEqual(step["settings"][GUILD], {"log_level": "INFO", "z": {}})

    def test_saving_one_djaudio_limit_drops_the_legacy_ttl(self):
        """古い平らな djaudio_cache_ttl だけを持つサーバーでクールダウンを保存すると、保持時間が既定に戻ること。

        Python の set_djaudio_settings が、古い鍵を入れ子の値（無いので None）で上書きするため
        （引き渡しの見直しの候補）。既定は道具が入れた環境変数 DJAUDIO_CACHE_TTL_SECONDS の値。
        """
        step = self._steps("djaudio_cooldown_drops_the_legacy_ttl")[0]
        self.assertEqual(step["response"]["json"]["values"]["cache_ttl"], self.output["djaudio"]["cache_ttl"])
        self.assertNotIn("djaudio_cache_ttl", step["settings"][GUILD])

    def test_news_feed_ids_follow_the_sequence(self):
        """ニュースのフィードの ID は、決めた並びの先頭 8 文字（例ごとに 1 から）。"""
        body = self._steps("news_add")[0]["response"]["json"]
        self.assertEqual(body["id"], f"{self.output['id_base'] + 1:08x}")

    def test_guild_data_is_removed_everywhere(self):
        """サーバーのデータの削除は、利用者の状態を消す関数にサーバーの ID を渡し、設定のギルドを消すこと。"""
        step = self._steps("delete_as_owner")[0]
        self.assertEqual(step["response"]["json"], {"removed": {"settings": 1, "events": 3, "states": 2}})
        self.assertEqual(step["user_states"], [GUILD])
        self.assertNotIn(GUILD, step["settings"])
        self.assertEqual(step["writes"], [2])

    def test_form_bodies_cannot_be_read_as_json(self):
        """フォームの本文は CSRF の確かめで読み切られ、JSON としては読めずに 400 になること。"""
        response = self._steps("put_form_body")[0]["response"]
        self.assertEqual(response["status"], 400)
        self.assertEqual(response["json"], {"detail": "JSON を解釈できませんでした。"})

    def test_settings_not_loaded_is_reported_per_field(self):
        """設定を読み込めないとき、項目ごとに「保存できませんでした（…）」で 422、書き換えは 1 回呼んで失敗すること。"""
        step = self._steps("logging_settings_not_loaded")[0]
        self.assertEqual(step["response"]["status"], 422)
        self.assertTrue(step["response"]["json"]["errors"]["log_level"].startswith("保存できませんでした（"))
        self.assertEqual(step["writes"], [0])


if __name__ == "__main__":
    unittest.main()
