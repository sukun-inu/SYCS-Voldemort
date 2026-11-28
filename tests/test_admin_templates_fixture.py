"""管理画面のテンプレートの基準を作る道具（rust/apps/admin/tests/fixtures/templates/generate.py）のテスト。

道具は CI の「基準」でしか回らず、そこで壊れても、何が壊れたかは基準の差分からしか読めない。ここでは、リポジトリの
cases.json をそのまま道具に 2 回通して、Rust のテストが頼りにする決めごと（偽物の static と CSRF の印とサーバー数が
効いている・本物の管理画面の経路を通している・描いたあとのセッションを読めている・何度作っても同じ）を確かめる。

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
FIXTURE = ROOT / "rust" / "apps" / "admin" / "tests" / "fixtures" / "templates"
GENERATOR = FIXTURE / "generate.py"
SHIPPED_CASES = FIXTURE / "cases.json"
STORED = FIXTURE / "expected.json"


def _generate() -> tuple[subprocess.CompletedProcess, str | None]:
    """リポジトリの cases.json を道具に通す（別のプロセスで）。書き出した基準の文字列も返す（失敗なら None）。"""
    with tempfile.TemporaryDirectory(prefix="admin-templates-fixture-test-") as tmp:
        output = Path(tmp) / "expected.json"
        done = subprocess.run(
            [sys.executable, str(GENERATOR), str(SHIPPED_CASES), str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            encoding="utf-8",
            timeout=300,
        )
        text = output.read_text(encoding="utf-8") if output.exists() else None
    return done, text


class AdminTemplatesFixtureTests(unittest.TestCase):
    """リポジトリの例の文書を 2 回道具に通し、書き出したものを確かめる。"""

    @classmethod
    def setUpClass(cls) -> None:
        """道具は重い（webapp_admin/app.py を読み込む）ので、2 回だけ回して使い回す。"""
        cls.first, cls.first_text = _generate()
        cls.second, cls.second_text = _generate()
        cls.output = json.loads(cls.first_text) if cls.first_text else {}
        cls.document = json.loads(SHIPPED_CASES.read_text(encoding="utf-8"))

    def _named(self, section: str, name: str) -> dict:
        """その節の、その名前の例。"""
        found = [item for item in self.output.get(section, []) if item["name"] == name]
        self.assertEqual(len(found), 1, f"{section} の {name}")
        return found[0]

    def _asset(self, filename: str, version: str | None = None) -> str:
        """functions の admin_asset_url の答え。"""
        for item in self.output["functions"]["admin_asset_url"]:
            if item["filename"] == filename and item["asset_version"] == version:
                return item["url"]
        raise AssertionError(f"admin_asset_url({filename!r}, {version!r}) の例が無い")

    def test_the_generator_succeeds_and_is_stable(self):
        """道具が最後まで回り、2 回作ってバイトまで同じであること。

        回らなければ、CI の「基準」は expected.json を作れない。同じにならなければ（時刻・乱数・一時ディレクトリの
        場所が答えに出る）、作り直すたびに基準の差分が出て CI が落ち続ける。
        """
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.assertEqual(self.second.returncode, 0, self.second.stderr)
        self.assertEqual(self.first_text, self.second_text)

    def test_every_case_is_written_in_order(self):
        """例の文書の節ごとに、全部の例が同じ並びで書かれること（Rust のテストは名前で読む）。"""
        for section in ("snippets", "pages", "cases"):
            want = [item["name"] for item in self.document[section]]
            got = [item["name"] for item in self.output[section]]
            self.assertEqual(got, want, section)
        self.assertEqual(self.output["issued_token"], self.document["issued_token"])
        self.assertEqual(self.output["static"], self.document["static"])

    def test_the_fake_static_decides_the_asset_version(self):
        """admin_asset_url の版が、偽物の static の更新時刻（ns）と大きさの 16 進になること。

        templating._static_root が偽物の置き場を向いていないと、本物の webapp_admin/static の時刻（チェックアウトの
        たびに変わる）が基準に入る。js/public.js は置いていないので版だけになる。
        """
        mtime = format(int(self.document["static"]["mtime_ns"]), "x")
        self.assertEqual(self._asset("favicon.png"), f"/static/favicon.png?v=admin-{mtime}-4d2")
        self.assertEqual(self._asset("css/motion.css"), f"/static/css/motion.css?v=admin-{mtime}-0")
        self.assertEqual(self._asset("js/public.js"), "/static/js/public.js?v=admin")
        self.assertEqual(self._asset("favicon.png", "v2"), f"/static/favicon.png?v=v2-{mtime}-4d2")
        self.assertEqual(self._asset("favicon.png", ""), f"/static/favicon.png?v=-{mtime}-4d2")

    def test_paths_are_resolved_like_pathlib(self):
        """パスの解き方が pathlib の resolve（無い名前でも字面で進む）であることを、基準が持っていること。

        Rust は std の canonicalize ではなく、これを写した python_realpath を使う。ここが変われば Rust も変える。
        """
        mtime = format(int(self.document["static"]["mtime_ns"]), "x")
        self.assertEqual(self._asset("nope/../favicon.png"), f"/static/nope/../favicon.png?v=admin-{mtime}-4d2")
        self.assertEqual(self._asset("../outside.css"), "/static/../outside.css?v=admin")
        self.assertEqual(self._asset("link-out.css"), "/static/link-out.css?v=admin")
        self.assertEqual(self._asset("loop-a"), "/static/loop-a?v=admin")

    def test_the_landing_page_goes_through_the_real_route(self):
        """GET / が本物の経路を通り、偽物のサーバー数・招待リンク・CSRF の印が本文とセッションに出ること。

        招待リンクの & は markupsafe の &amp; になる（minijinja の既定と違うところ。Rust が合わせる相手）。
        未ログインでも HTML を描くと CSRF の印ができ、Set-Cookie に出る。
        """
        case = self._named("cases", "landing_anonymous")
        body = case["response"]["body"]
        self.assertEqual(case["response"]["status"], 200)
        self.assertIn("client_id=123456789012345678&amp;permissions=8&amp;scope=bot+applications.commands", body)
        self.assertIn("7 サーバーに導入済み", body)
        self.assertEqual([call["fn"] for call in case["calls"]], ["get_bot_guild_count", "token_hex"])
        self.assertEqual(case["session_after"], {"_csrf_token": self.document["issued_token"]})

    def test_the_cookie_is_written_only_when_the_session_changes(self):
        """セッションを書き換えなかった要求には Set-Cookie が出ないこと（starlette 1.x。Rust の層も同じに決める）。

        知らせが無く CSRF の印もあり、admin_guilds（見張りの層が入れ直す）も無いセッションで描いても、Cookie は
        書き直さない。印を作ったときと、admin_guilds があるときは書く。ここが変われば、Rust のセッションの層の
        「書き換えた」の決め方も変える。
        """

        def wrote(name: str) -> bool:
            """その例の応答に Set-Cookie があるか。"""
            headers = self._named("cases", name)["response"]["headers"]
            return any(header == "set-cookie" for header, _ in headers)

        self.assertFalse(wrote("guide_in_iframe"))
        self.assertFalse(wrote("guild_select_without_list"))
        self.assertFalse(wrote("shell_null_user"))
        self.assertTrue(wrote("guide_anonymous"))
        self.assertTrue(wrote("shell_full"))
        self.assertTrue(wrote("landing_consumes_flashes"))

    def test_flashes_are_taken_out_by_the_page(self):
        """描いたページが知らせを取り出し、描いたあとのセッションから消えていること。"""
        case = self._named("cases", "login_with_flashes")
        self.assertIn("Discord 認証がキャンセルされました。", case["response"]["body"])
        self.assertNotIn("_flashes", case["session_after"])
        page = self._named("pages", "error_consumes_flashes")
        self.assertNotIn("_flashes", page["session_after"])
        self.assertIn("_flashes", page["session"])

    def test_error_pages_and_redirects_are_recorded(self):
        """エラーのページ（404・405・403）が HTML で、旧 URL が 301 で記録されること。"""
        for name, status in (("not_found_anonymous", 404), ("method_not_allowed", 405), ("csrf_rejected", 403)):
            response = self._named("cases", name)["response"]
            self.assertEqual(response["status"], status, name)
            self.assertIn(["content-type", "text/html; charset=utf-8"], response["headers"], name)
        redirect = self._named("cases", "legacy_terms_logged_in")["response"]
        self.assertEqual(redirect["status"], 301)
        self.assertIn(["location", "/terms"], redirect["headers"])

    def test_snippets_show_the_jinja2_way_of_writing(self):
        """短いテンプレートの答えが、Jinja2 の書き方（markupsafe のエスケープ・None・True）であること。"""
        self.assertEqual(
            self._named("snippets", "escape_five")["body"],
            "&lt;p class=&#34;a&#34;&gt;Tom &amp; &#39;Jerry&#39;&lt;/p&gt;/=",
        )
        self.assertEqual(self._named("snippets", "none")["body"], "[None]")
        self.assertEqual(self._named("snippets", "bools")["body"], "True False")
        self.assertEqual(self._named("snippets", "crlf")["body"], "a\nb\nc")

    def test_stored_fixture_matches_when_present(self):
        """リポジトリに expected.json があれば、いまの Python から作ったものと同じであること（「基準」と同じ）。"""
        if not STORED.exists():
            self.skipTest("expected.json はまだ無い（CI の「基準」が作ったものをコミットする）")
        self.assertEqual(STORED.read_text(encoding="utf-8"), self.first_text)


if __name__ == "__main__":
    unittest.main()
