"""管理画面の設定パネルの読む側の基準を作る道具（rust/apps/admin/tests/fixtures/apps_read・getters）のテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは、
リポジトリの cases.json をそのまま道具に 2 回通して、Rust のテストが頼りにする決めごと（偽物の Discord と読み上げの
API に要求が届く・設定は差し替えたものを読む・時刻と乱数が決まった並び・何度作っても同じ）を確かめる。

道具は別のプロセスで回す。道具は import の前に環境変数を消して入れ直し、webapp_admin/app.py を読み込むので、
同じプロセスで回すと、ほかのテストが入れた環境を壊す。
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


class AppsReadFixtureTests(unittest.TestCase):
    """設定パネルの読む側の基準（fixtures/apps_read）の道具。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp_admin/app.py を読み込み、偽物を 2 つ立てる）ので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate("apps_read")
        cls.second, cls.second_text = _generate("apps_read")
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads((FIXTURES / "apps_read" / "cases.json").read_text(encoding="utf-8"))

    def _steps(self, name: str) -> list[dict]:
        """その名前の例の要求の控え。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]["steps"]

    def _json(self, name: str, index: int = 0) -> dict:
        """その名前の例の index 番目の答えの JSON。"""
        return self._steps(name)[index]["response"]["json"]

    def _counts(self, name: str) -> list[int]:
        """その名前の例の、要求ごとに偽物の Discord に届いた要求の数。"""
        return [len(step["discord"]) for step in self._steps(name)]

    def _tiles(self, name: str) -> dict:
        """その名前の例の答え（タイルの一覧）の、パネルの ID → タイル。"""
        return {app["id"]: app for group in self._json(name)["groups"] for app in group["apps"]}

    def _body(self, name: str) -> str:
        """その名前の例の最初の答えの本文。"""
        return self._steps(name)[0]["response"]["body"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。

        回らなければ CI の「基準」は expected.json を作れない。同じにならなければ（時刻・乱数・偽物の口・届いた順が
        答えに出る）、作り直すたびに基準の差分が出て CI が落ち続ける。
        """
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_case_is_written_in_order(self):
        """例の文書の全部の例が、同じ並びで、要求の数も同じに書かれること（Rust のテストは並びのまま読む）。"""
        want = [(case["name"], len(case["steps"])) for case in self.document["cases"]]
        got = [(case["name"], len(case["steps"])) for case in self.output["cases"]]
        self.assertEqual(got, want)

    def test_dev_panels_are_hidden_from_other_people(self):
        """開発者でなければ「開発者」のグループが無く、開発者には末尾に出ること。開発者専用のパネルは 404。"""
        labels = [group["label"] for group in self._json("list_full")["groups"]]
        self.assertNotIn("開発者", labels)
        self.assertEqual([group["label"] for group in self._json("list_as_dev")["groups"]][-1], "開発者")
        self.assertEqual(self._steps("get_dev_as_other_user")[0]["response"]["status"], 404)

    def test_badges_are_counted_from_the_settings(self):
        """タイルのバッジは差し替えた設定から数え、読めない設定では null になること。

        settings_store._load_all を差し替えていなければ、空の settings.json を読んで、どのバッジも null になる。
        """
        tiles = self._tiles("list_full")
        self.assertEqual(tiles["news-feeds"]["badge"], 3)
        self.assertEqual(tiles["sticky"]["badge"], 2)
        self.assertEqual(tiles["reaction-roles"]["badge"], 2)
        self.assertEqual(tiles["security"]["badge"], 5)
        self.assertIsNone(self._tiles("list_settings_not_loaded")["news-feeds"]["badge"])

    def test_values_fall_back_when_settings_cannot_be_read(self):
        """設定を読み込めないとき、どの入力欄も既定値で埋まり、errors に同じ文が入ること。"""
        body = self._json("get_logging_settings_not_loaded")
        self.assertEqual(body["values"], {"log_channel_id": None, "log_level": "INFO", "chatgpt_channel_id": None})
        self.assertEqual(list(body["errors"]), ["log_channel_id", "log_level", "chatgpt_channel_id"])
        self.assertTrue(all("30 秒以内に読み込めませんでした" in text for text in body["errors"].values()))

    def test_choices_come_from_the_fake_discord(self):
        """チャンネルとロールの選択肢が偽物の Discord から来て、テキストは位置の順・ロールは @everyone を除くこと。"""
        body = self._json("get_vc_notify_full")
        self.assertEqual(
            [item["label"] for item in body["choices"]["channels"]],
            ["# general", "# 数の ID", "# 雑談", "# <b>\"お知らせ\" & 'news'</b>"],
        )
        self.assertEqual(
            [item["label"] for item in body["choices"]["roles"]], ["管理者", "Bot", "メンバー", "同じ位置", 12345]
        )
        seen = self._steps("get_vc_notify_full")[0]["discord"]
        self.assertEqual(
            sorted((item["path"], item["authorization"]) for item in seen),
            [
                (f"/guilds/{GUILD}/channels", "Bot a5-bot-token"),
                (f"/guilds/{GUILD}/roles", "Bot a5-bot-token"),
            ],
        )

    def test_channels_are_shared_and_kept_for_sixty_seconds(self):
        """チャンネルの一覧はテキストとボイスで 1 回だけ取り、60 秒使い回し、ちょうど 60 秒で取り直すこと。

        失敗したときは使い回すものが無いので、TTS のパネル（テキストとボイス）では 2 回取りに行く。
        """
        self.assertEqual(self._counts("channels_cached_for_sixty_seconds"), [1, 0, 1])
        self.assertEqual(self._counts("channels_shared_between_text_and_voice"), [1, 0])
        self.assertEqual(self._counts("channels_failure_is_fetched_twice_in_tts"), [2])

    def test_rate_limits_wait_for_retry_after(self):
        """429 のあとは Retry-After のあいだ取りに行かないこと。

        読めなければ 30 秒、長くても 300 秒。0 以下なら待たない（TTS のパネルでは、ボイスの側ももう一度取りに行く）。
        """
        counts = {
            name: self._counts(name)
            for name in (
                "channels_429_waits_for_retry_after",
                "channels_429_unreadable_retry_after_waits_thirty_seconds",
                "channels_429_long_retry_after_is_capped",
                "channels_429_in_tts_is_fetched_once",
                "channels_429_negative_retry_after_does_not_wait",
            )
        }
        self.assertEqual(
            counts,
            {
                "channels_429_waits_for_retry_after": [1, 0, 1],
                "channels_429_unreadable_retry_after_waits_thirty_seconds": [1, 0, 1],
                "channels_429_long_retry_after_is_capped": [1, 0, 1],
                "channels_429_in_tts_is_fetched_once": [1, 0, 1],
                "channels_429_negative_retry_after_does_not_wait": [2, 1],
            },
        )
        stale = self._json("channels_429_with_the_stale_list", 2)
        self.assertEqual(len(stale["choices"]["channels"]), 4)

    def test_voices_come_from_the_fake_tts_and_time_out(self):
        """声の一覧は偽物の読み上げの API から来て（名前はそのまま）、答えが遅ければ見切って空になること。"""
        body = self._json("get_tts_full")
        self.assertEqual(
            body["choices"]["tts_voices"],
            [
                {"value": "Kyoko", "label": "Kyoko"},
                {"value": "Otoya", "label": "Otoya"},
                {"value": 7, "label": 7},
            ],
        )
        self.assertEqual(self._steps("get_tts_full")[0]["tts"][0]["path"], "/api/v1/voices?locale=ja")
        late = self._steps("voices_time_out")[0]
        self.assertEqual(late["response"]["json"]["choices"]["tts_voices"], [])
        self.assertEqual(len(late["tts"]), 1)

    def test_custom_panels_do_not_read_the_guild_id(self):
        """custom のパネルは壊れたサーバーの ID でも 200、タイルの一覧は 500 とインシデントになること。"""
        self.assertEqual(self._steps("get_monitoring_with_bad_guild_id")[0]["response"]["status"], 200)
        found = [case for case in self.output["cases"] if case["name"] == "list_bad_guild_id"][0]
        self.assertEqual(found["steps"][0]["response"]["status"], 500)
        self.assertTrue(any("ValueError" in line for line in found["incidents"]), found["incidents"])

    def test_big_ids_become_text(self):
        """2^53-1 を超える整数（スティッキーのメッセージの ID）は、答えでは文字になること（SafeJSONResponse）。"""
        rows = self._json("get_sticky_full")["collections"]["stickies"]
        self.assertEqual(rows[0]["message_id"], "1234567890123456789")

    def test_the_landing_page_counts_stored_guilds(self):
        """Bot のサーバー数が失敗か 0 なら設定のあるサーバー（鍵を int() できるもの）の数を出し、5 分使い回すこと。"""
        self.assertIn("4 サーバーに導入済み", self._body("landing_counts_stored_guilds_when_discord_fails"))
        self.assertEqual(self._counts("landing_counts_stored_guilds_when_discord_fails"), [1, 0])
        self.assertIn("2 サーバーに導入済み", self._body("landing_counts_stored_guilds_when_discord_gives_zero"))
        self.assertNotIn("サーバーに導入済み", self._body("landing_without_loaded_settings"))


class GettersFixtureTests(unittest.TestCase):
    """設定の値を読む関数の基準（fixtures/getters）の道具。"""

    @classmethod
    def setUpClass(cls) -> None:
        """2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate("getters")
        cls.second, cls.second_text = _generate("getters")
        cls.output = json.loads(cls.first_text) if cls.first_text else {}

    def _results(self, name: str) -> dict:
        """その名前の例の、関数ごとの答え。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]["results"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_schema_function_is_called(self):
        """schema.json が指す読む関数（入力欄の get・一覧の list・バッジ）が、ちょうど全部呼ばれていること。

        名前の付け方が schema.json と食い違うと、Rust のテストが関数を引けない。
        """
        schema = json.loads((FIXTURES / "schema" / "schema.json").read_text(encoding="utf-8"))
        wanted = set()
        for panel in schema["panels"]:
            wanted.update(field["get"] for field in panel["fields"] if field["get"])
            wanted.update(collection["list"] for collection in panel["collections"] if collection["list"])
            if panel["badge"]:
                wanted.add(panel["badge"])
        self.assertEqual(set(self.output["functions"]), wanted)
        for case in self.output["cases"]:
            self.assertEqual(set(case["results"]), wanted, case["name"])

    def test_settings_not_loaded_reaches_every_function(self):
        """設定を読み込めないとき、TypeError・ValueError を拾う関数も含めて、全部が SettingsNotLoaded になること。"""
        for name, result in self._results("not_loaded").items():
            self.assertEqual(result["raises"]["type"], "SettingsNotLoaded", name)

    def test_djaudio_reads_the_environment_defaults(self):
        """DJAudio の数の設定が読めないときは、道具が入れた環境変数の値（720・45）を使うこと。"""
        self.assertEqual(self.output["djaudio"], {"cache_ttl": 720, "cooldown": 45, "max_urls": 4})
        results = self._results("djaudio_legacy")
        self.assertEqual(results["services.settings_store.get_djaudio_cache_ttl"]["value"], 720)
        self.assertEqual(results["services.settings_store.get_djaudio_cooldown"]["value"], 45)
        self.assertEqual(results["services.settings_store.get_djaudio_max_urls"]["value"], 1)

    def test_the_settings_are_read_from_the_case(self):
        """読む関数が例の設定を読んでいること（差し替えていなければ、どの例も空の設定の答えになる）。"""
        results = self._results("full")
        self.assertEqual(results["webapp_admin.schema.panels.logging._log_level"]["value"], "DEBUG")
        self.assertEqual(results["webapp_admin.schema.panels.earthquake._min_scale"]["json"], "45")
        empty = self._results("empty")
        self.assertEqual(empty["webapp_admin.schema.panels.logging._log_level"]["value"], "INFO")

    def test_to_json_rows_cover_every_widget(self):
        """to_json_value の表が、入力欄の種類 × 値の全部の組を持つこと。"""
        widgets = {row["widget"] for row in self.output["to_json"]}
        self.assertEqual(len(widgets), 11)
        self.assertEqual(len(self.output["to_json"]) % 11, 0)


if __name__ == "__main__":
    unittest.main()
