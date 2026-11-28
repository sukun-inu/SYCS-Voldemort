"""管理画面のログインとサーバー選択の基準を作る道具（rust/apps/admin/tests/fixtures/auth・admin_check）のテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは、
リポジトリの cases.json をそのまま道具に 2 回通して、Rust のテストが頼りにする決めごと（偽物の Discord に
要求が届く・時刻と乱数が決まった並び・Cookie を持ち回る・何度作っても同じ）を確かめる。

道具は別のプロセスで回す。道具は import の前に環境変数を消して入れ直し、webapp_admin/app.py を読み込むので、
同じプロセスで回すと、ほかのテストが入れた環境を壊す。
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "rust" / "apps" / "admin" / "tests" / "fixtures"
TOKEN_BASE = 0xA3000000
STATE_BASE = 0x5A3E0000


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


def _headers(response: dict, name: str) -> list[str]:
    """答えの、その名前の見出しの値（来た順）。"""
    return [value for header, value in response["headers"] if header == name]


def _session(response: dict) -> dict | None:
    """答えの Set-Cookie が運んだセッション（書いていなければ None、消す Cookie なら空）。"""
    cookies = [value for value in _headers(response, "set-cookie") if value.startswith("admin_session=")]
    if not cookies:
        return None
    data = cookies[-1].split(";", 1)[0][len("admin_session=") :]
    if data == "null":
        return {}
    return json.loads(base64.b64decode(data.split(".", 1)[0]))


class AuthFixtureTests(unittest.TestCase):
    """ログインとサーバー選択の基準（fixtures/auth）の道具。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp_admin/app.py を読み込み、千回ほど要求を送る）ので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate("auth")
        cls.second, cls.second_text = _generate("auth")
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads((FIXTURES / "auth" / "cases.json").read_text(encoding="utf-8"))

    def _steps(self, name: str) -> list[dict]:
        """その名前の例の要求の控え。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]["steps"]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。

        回らなければ CI の「基準」は expected.json を作れない。同じにならなければ（時刻・乱数・偽物の Discord の口・
        届いた順が答えに出る）、作り直すたびに基準の差分が出て CI が落ち続ける。
        """
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_case_is_written_in_order(self):
        """例の文書の全部の例が、同じ並びで、要求の数も同じに書かれること（Rust のテストは並びのまま読む）。"""
        want = [(case["name"], len(case["steps"])) for case in self.document["cases"]]
        got = [(case["name"], len(case["steps"])) for case in self.output["cases"]]
        self.assertEqual(got, want)

    def test_the_oauth_url_carries_the_state_in_the_session(self):
        """認可の画面の URL が urlencode の形で、同じ state がセッションに入ること（state は決まった並び）。"""
        response = self._steps("auth_start_anonymous")[0]["response"]
        state = f"{STATE_BASE + 1:043x}"
        self.assertEqual(
            _headers(response, "location"),
            [
                "https://discord.com/api/oauth2/authorize?client_id=123456789012345678"
                "&redirect_uri=https%3A%2F%2Fadmin.example.com%2Fadmin%2Fcallback"
                f"&response_type=code&scope=identify+guilds&state={state}"
            ],
        )
        self.assertEqual(_session(response), {"oauth_state": state})

    def test_the_fake_discord_receives_the_token_exchange(self):
        """戻りで、トークンの交換（フォーム）・本人・本人のサーバー・Bot のサーバーの 4 つが偽物に届くこと。

        auth._API を偽物へ向けていないと、本物の Discord へ行こうとして失敗し、どの例も「認証に失敗」になる。
        """
        seen = self._steps("callback_success")[0]["discord"]
        self.assertEqual(
            sorted((item["method"], item["path"], item["authorization"]) for item in seen),
            [
                ("GET", "/users/@me", "Bearer user-access-token"),
                ("GET", "/users/@me/guilds", "Bearer user-access-token"),
                ("GET", "/users/@me/guilds", "Bot a3-bot-token"),
                ("POST", "/oauth2/token", None),
            ],
        )
        token = [item for item in seen if item["method"] == "POST"][0]
        self.assertEqual(token["content_type"], "application/x-www-form-urlencoded")
        self.assertEqual(
            token["body"],
            "client_id=123456789012345678&client_secret=a3-client-secret&grant_type=authorization_code"
            "&code=good-code&redirect_uri=https%3A%2F%2Fadmin.example.com%2Fadmin%2Fcallback",
        )

    def test_a_successful_login_rebuilds_the_session(self):
        """ログインが済むと、前のセッションを捨てて user・admin_guilds・取った時刻・新しい CSRF の印だけになること。"""
        step = self._steps("callback_success")[0]
        self.assertEqual(_headers(step["response"], "location"), ["/admin/guilds"])
        session = _session(step["response"])
        assert session is not None
        self.assertEqual(list(session), ["user", "admin_guilds", "admin_guilds_at", "_csrf_token"])
        self.assertEqual(
            [guild["id"] for guild in session["admin_guilds"]],
            ["900000000000000001", "900000000000000002", "900000000000000003"],
        )
        self.assertEqual(session["admin_guilds_at"], self.document["now"])
        self.assertEqual(session["_csrf_token"], f"{TOKEN_BASE + 1:064x}")

    def test_the_guild_count_is_kept_for_five_minutes(self):
        """公開トップのサーバー数は 300 秒のあいだ使い回し、ちょうど 300 秒で Discord に聞き直すこと。"""
        steps = self._steps("landing_count_cached")
        self.assertEqual([len(step["discord"]) for step in steps], [1, 0, 1])
        bodies = [step["response"]["body"] for step in steps]
        self.assertIn("3 サーバーに導入済み", bodies[0])
        self.assertIn("3 サーバーに導入済み", bodies[1])
        self.assertIn("5 サーバーに導入済み", bodies[2])

    def test_the_stored_count_is_asked_only_when_discord_gives_zero(self):
        """Discord が 0 のときだけ設定のあるサーバーの数を聞き、それも使い回すこと。"""
        steps = self._steps("landing_count_fallback")
        self.assertEqual([step["stored_guild_calls"] for step in steps], [1, 0])
        self.assertIn("2 サーバーに導入済み", steps[0]["response"]["body"])

    def test_crashes_are_recorded_as_incidents(self):
        """拾われない例外（本人のサーバーに id が無い）は 500 で、インシデントの行が増えること。"""
        found = [case for case in self.output["cases"] if case["name"] == "callback_user_guild_without_id"][0]
        self.assertEqual(found["steps"][0]["response"]["status"], 500)
        self.assertTrue(any("KeyError" in line for line in found["incidents"]), found["incidents"])

    def test_the_cookie_is_carried_between_steps(self):
        """持ち回りの Cookie が、前の答えの Set-Cookie の値そのものであること（ブラウザと同じ）。"""
        steps = self._steps("full_login_flow")
        written = _headers(steps[0]["response"], "set-cookie")[0].split(";", 1)[0]
        sent = [value for name, value in steps[1]["request"]["headers"] if name == "cookie"]
        self.assertEqual(sent, [written])
        self.assertEqual(steps[-1]["response"]["status"], 303)
        self.assertIsNone(_session(steps[-1]["response"]))


class AdminCheckFixtureTests(unittest.TestCase):
    """user_still_admin の基準（fixtures/admin_check）の道具。"""

    @classmethod
    def setUpClass(cls) -> None:
        """2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate("admin_check")
        cls.second, cls.second_text = _generate("admin_check")
        cls.output = json.loads(cls.first_text) if cls.first_text else {}

    def _case(self, name: str) -> dict:
        """その名前の例。"""
        found = [case for case in self.output.get("cases", []) if case["name"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。"""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_results_follow_the_permission_rules(self):
        """持ち主・404・障害・負の数の permissions・形の崩れた答えが、それぞれの答えになること。

        偽物の Discord へ向けていなければ、どの例も「分からない」（None）になって、この表が意味を持たない。
        """
        self.assertEqual(self._case("owner_string")["result"], {"value": True})
        self.assertEqual(len(self._case("owner_string")["discord"]), 2)
        self.assertEqual(self._case("guild_404")["result"], {"value": False})
        self.assertEqual(len(self._case("guild_404")["discord"]), 1)
        self.assertEqual(self._case("guild_500")["result"], {"value": None})
        self.assertEqual(self._case("no_bot_token")["discord"], [])
        self.assertEqual(self._case("permission_negative")["result"], {"value": True})
        self.assertEqual(
            self._case("guild_list")["result"],
            {"raises": {"type": "AttributeError", "message": "'list' object has no attribute 'get'"}},
        )


if __name__ == "__main__":
    unittest.main()
