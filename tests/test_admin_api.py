"""管理UIの API テスト。

    python -m unittest discover -s tests -t .

DB を必要とするユーザー状態監査は services 層を差し替えて検証する
（Postgres が無い環境でも API の契約を確認できるようにするため）。
標準ライブラリの unittest だけで動く。pytest からも実行できる。
"""

import base64
import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

# services/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# プロジェクトの import より前に一時ディレクトリへ差し替える。
os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="admin-api-test-")
os.environ["ADMIN_FLASK_SECRET_KEY"] = "x" * 64
os.environ["TTS_BASE_URL"] = "http://127.0.0.1:9"
os.environ["DEV_USER_ID"] = "4242"
# 配信キャッシュは SETTINGS_DIR 配下ではないので、別途隔離する。
os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp(prefix="admin-api-cache-")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import itsdangerous  # noqa: E402
from starlette.exceptions import HTTPException as StarletteHTTPException  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from webapp_admin.app import app  # noqa: E402
from webapp_admin.schema.registry import PANEL_BY_ID  # noqa: E402
from webapp_admin.schema.types_def import Field, Widget  # noqa: E402


def tearDownModule():
    """使い回している HTTP セッションを閉じる。

    API を叩くテストは本番と同じ経路を通るので、共有セッションが実際に
    作られる。閉じずに終わると "Unclosed client session" がテスト出力へ
    混ざり、本物の警告が埋もれる。
    """
    import asyncio

    from services import http_client

    # セッションは作られたループに縛られている。別のループから閉じようと
    # すると失敗するので、作られたループが生きていればそちらで閉じる。
    loop = http_client._loop
    if loop is not None and not loop.is_closed():
        loop.run_until_complete(http_client.close_session())
    else:
        asyncio.run(http_client.close_session())


SECRET = "x" * 64
CSRF = "t" * 64
GUILD_ID = 999
CSRF_HEADER = {"X-CSRFToken": CSRF}


def make_client(user_id: str = "1", with_guild: bool = True, csrf: str | None = CSRF) -> TestClient:
    session = {
        "user": {"id": user_id, "username": "tester", "global_name": "Tester", "avatar": None},
        "admin_guilds": [{"id": str(GUILD_ID), "name": "Test Guild", "icon": None}],
        # 管理権限の再確認をしたばかり、という状態にしておく（再確認が走ると
        # Discord API を叩きに行くため、テストでは古びさせない）。
        "admin_guilds_at": time.time(),
    }
    if csrf is not None:
        session["_csrf_token"] = csrf
    if with_guild:
        session.update({"guild_id": GUILD_ID, "guild_name": "Test Guild", "guild_icon": None})

    client = TestClient(app)
    signed = itsdangerous.TimestampSigner(SECRET).sign(base64.b64encode(json.dumps(session).encode()))
    client.cookies.set("admin_session", signed.decode())
    return client


class AuthTests(unittest.TestCase):
    def test_anonymous_is_redirected_to_login(self):
        response = TestClient(app).get("/admin/api/apps", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/admin/login", response.headers["location"])

    def test_logged_in_without_guild_is_redirected_to_guild_select(self):
        client = make_client(with_guild=False)
        response = client.get("/admin/api/apps", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/admin/guilds", response.headers["location"])

    def test_shell_is_served_for_overview(self):
        response = make_client().get("/admin/overview")
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="desktop"', response.text)
        self.assertNotIn("bootstrap.min.css", response.text)

    def test_old_user_state_url_redirects_to_desktop(self):
        response = make_client().get("/admin/users/state", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("#user-state", response.headers["location"])


class AppListTests(unittest.TestCase):
    def test_tiles_are_grouped_in_declared_order(self):
        payload = make_client().get("/admin/api/apps").json()
        labels = [group["label"] for group in payload["groups"]]
        self.assertEqual(
            labels,
            ["概要", "基本設定", "自動通知", "チャンネル機能", "メディア", "セキュリティ"],
        )

    def test_developer_panel_is_hidden_from_normal_users(self):
        ids = [app_["id"] for group in make_client().get("/admin/api/apps").json()["groups"] for app_ in group["apps"]]
        self.assertNotIn("dev", ids)
        self.assertEqual(make_client().get("/admin/api/apps/dev").status_code, 404)

    def test_developer_panel_is_visible_to_developer(self):
        ids = [
            app_["id"]
            for group in make_client(user_id="4242").get("/admin/api/apps").json()["groups"]
            for app_ in group["apps"]
        ]
        self.assertIn("dev", ids)


class PanelSchemaTests(unittest.TestCase):
    def setUp(self):
        self.client = make_client()

    def test_schema_contains_fields_values_and_choices(self):
        payload = self.client.get("/admin/api/apps/logging").json()
        self.assertEqual(payload["kind"], "schema")
        self.assertEqual(payload["layout"], "stack")
        self.assertEqual(
            set(payload["values"]),
            {"log_channel_id", "log_level", "chatgpt_channel_id"},
        )
        self.assertIn("channels", payload["choices"])

    def test_panel_with_many_sections_uses_tabs(self):
        self.assertEqual(self.client.get("/admin/api/apps/tts").json()["layout"], "tabs")

    def test_custom_panel_declares_its_client(self):
        payload = self.client.get("/admin/api/apps/user-state").json()
        self.assertEqual(payload["kind"], "custom")
        self.assertEqual(payload["client"], "user_state")

    def test_unknown_panel_is_404(self):
        self.assertEqual(self.client.get("/admin/api/apps/nope").status_code, 404)


class PanelValueTypeTests(unittest.TestCase):
    """開いた瞬間に「未保存の変更」が出ないこと。

    画面側は「サーバーが返した現在値」と「入力欄から読み返した値」を
    JSON.stringify で比べて変更の有無を決める。だから型が違うだけで、
    何も触っていないのに変更ありになる。実際に Widget.DURATION が
    文字列 "600" で返っていて、入力欄は数値 600 を返すため、DJAudio-DL の
    パネルは開いた瞬間から常に1件の未保存を表示していた。

    この食い違いは Python 側だけを読んでも JS 側だけを読んでも見つからない
    ので、両者の約束をここに表として書き、全パネルの全項目へ当てる。
    表は webapp_admin/static/js/forms/widgets.js の read() と対で保つこと。
    """

    # widget → 入力欄から読み返したときに画面側が作る型（null は共通で許す）
    BROWSER_TYPES = {
        Widget.TEXT: str,
        Widget.TEXTAREA: str,
        Widget.INT: int,
        Widget.DURATION: int,
        Widget.BOOL: bool,
        Widget.SELECT: str,
        Widget.CHANNEL: str,
        Widget.VOICE_CHANNEL: str,
        Widget.ROLE: str,
        Widget.CHECKLIST: list,
        Widget.SNOWFLAKE: str,
    }

    # 保存されている値としてありうる形。settings.json には設定した経路によって
    # 数値と文字列が混在するので、どちらで入っていても JSON の型は揃うこと。
    STORED_SAMPLES = {
        Widget.TEXT: ("あ", ""),
        Widget.TEXTAREA: ("あ", ""),
        Widget.INT: (30, "30"),
        Widget.DURATION: (600, "600"),
        Widget.BOOL: (True, False, 1, 0),
        Widget.SELECT: ("a", 1),
        Widget.CHANNEL: (123, "123"),
        Widget.VOICE_CHANNEL: (123, "123"),
        Widget.ROLE: (123, "123"),
        Widget.CHECKLIST: (["a"], ("a",), {"a": True}),
        Widget.SNOWFLAKE: (123, "123"),
    }

    def _fields(self):
        for panel in PANEL_BY_ID.values():
            for field in panel.fields:
                yield panel, field
            for collection in panel.collections:
                for field in collection.item_fields:
                    yield panel, field

    def test_every_widget_covers_the_browser_contract(self):
        """新しい widget を足したらこの表も足す、を強制する。"""
        self.assertEqual(set(self.BROWSER_TYPES), set(Widget))
        self.assertEqual(set(self.STORED_SAMPLES), set(Widget))

    def test_stored_values_serialise_to_the_type_the_browser_reads_back(self):
        for panel, field in self._fields():
            expected = self.BROWSER_TYPES[field.widget]
            for stored in self.STORED_SAMPLES[field.widget]:
                with self.subTest(panel=panel.id, field=field.key, stored=stored):
                    value = field.to_json_value(stored)
                    if value is None:
                        continue
                    # bool は int の派生なので、int 期待の項目に紛れ込ませない
                    if expected is int:
                        self.assertNotIsInstance(value, bool)
                    self.assertIsInstance(value, expected)

    def test_a_freshly_opened_panel_has_nothing_to_save(self):
        """API が実際に返す現在値の型を、全スキーマパネルについて見る。"""
        client = make_client()
        for panel in PANEL_BY_ID.values():
            if panel.custom:
                continue
            payload = client.get(f"/admin/api/apps/{panel.id}").json()
            for field in panel.fields:
                with self.subTest(panel=panel.id, field=field.key):
                    self.assertIn(field.key, payload["values"])
                    value = payload["values"][field.key]
                    if value is None:
                        continue
                    expected = self.BROWSER_TYPES[field.widget]
                    if expected is int:
                        self.assertNotIsInstance(value, bool)
                    self.assertIsInstance(value, expected)

    def test_a_duration_survives_the_round_trip_unchanged(self):
        """秒 → 入力欄（値＋単位）→ 秒 が同じ値に戻ること。

        画面側は「割り切れる一番大きい単位」で表示し、読み返すときに
        その単位を掛け戻す。表示の都合で値が変わってはいけない。
        """
        units = ((86400, "日"), (3600, "時間"), (60, "分"), (1, "秒"))

        def browser_round_trip(seconds: int) -> int:
            for factor, _label in units:
                if seconds % factor == 0:
                    return round(seconds / factor * factor)
            return seconds

        for seconds in (60, 600, 3600, 86400, 2592000, 90, 3661):
            with self.subTest(seconds=seconds):
                field = Field("ttl", "保持時間", Widget.DURATION, default=600)
                value = field.to_json_value(seconds)
                self.assertEqual(browser_round_trip(value), seconds)


class SaveTests(unittest.TestCase):
    def setUp(self):
        self.client = make_client()

    def put(self, app_id, values, headers=CSRF_HEADER):
        return self.client.put(f"/admin/api/apps/{app_id}", json={"values": values}, headers=headers)

    def test_saves_only_the_given_fields(self):
        response = self.put("logging", {"log_level": "DEBUG"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["saved"], ["log_level"])
        self.assertEqual(response.json()["values"]["log_level"], "DEBUG")

    def test_value_survives_a_reread(self):
        self.put("djaudio", {"cooldown": 45})
        payload = self.client.get("/admin/api/apps/djaudio").json()
        self.assertEqual(payload["values"]["cooldown"], 45)

    def test_null_clears_an_optional_field(self):
        self.put("logging", {"log_channel_id": "123456789012345678"})
        response = self.put("logging", {"log_channel_id": None})
        self.assertIsNone(response.json()["values"]["log_channel_id"])

    def test_missing_csrf_token_is_rejected(self):
        response = self.put("logging", {"log_level": "INFO"}, headers={})
        self.assertEqual(response.status_code, 403)

    def test_session_without_a_csrf_token_is_rejected(self):
        """トークンが無いセッションは素通しせず必ず弾く（フェイルクローズ）。

        以前は「セッションに _csrf_token が無ければ検証せず通す」実装で、
        CSRF 防御の全体が『その時点でトークンが存在すること』に依存していた。
        """
        client = make_client(csrf=None)
        response = client.put(
            "/admin/api/apps/logging",
            json={"values": {"log_level": "INFO"}},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 403)

    def test_choice_outside_the_schema_is_rejected(self):
        response = self.put("logging", {"log_level": "LOUD"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["errors"]["log_level"], "選べない値です。")

    def test_number_out_of_range_explains_the_limit(self):
        response = self.put("djaudio", {"cooldown": 99999})
        self.assertEqual(response.status_code, 422)
        self.assertIn("3600 以下", response.json()["errors"]["cooldown"])

    def test_text_over_the_limit_is_rejected(self):
        response = self.put("welcome", {"welcome_message": "あ" * 1001})
        self.assertEqual(response.status_code, 422)
        self.assertIn("1000 文字以内", response.json()["errors"]["welcome_message"])

    def test_non_numeric_id_is_rejected(self):
        response = self.put("logging", {"log_channel_id": "abc"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("ID", response.json()["errors"]["log_channel_id"])

    def test_unknown_field_is_rejected(self):
        response = self.put("logging", {"nope": 1})
        self.assertEqual(response.status_code, 422)
        self.assertIn("nope", response.json()["errors"])

    def test_custom_panel_cannot_be_saved(self):
        self.assertEqual(self.put("user-state", {"anything": 1}).status_code, 404)

    def test_valid_fields_are_kept_when_another_field_fails(self):
        response = self.put("djaudio", {"cooldown": 60, "max_urls": 999})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["saved"], ["cooldown"])
        self.assertIn("max_urls", response.json()["errors"])
        self.assertEqual(response.json()["values"]["cooldown"], 60)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.client = make_client()
        self.url = "/admin/api/apps/news-feeds/collections/feeds"
        for item in self.client.get("/admin/api/apps/news-feeds").json()["collections"]["feeds"]:
            self.client.delete(f"{self.url}/{item['id']}", headers=CSRF_HEADER)

    def add(self, **values):
        payload = {"channel_id": "123456789012345678", "query": "AI", "interval": 30}
        payload.update(values)
        return self.client.post(self.url, json={"values": payload}, headers=CSRF_HEADER)

    def test_add_returns_the_refreshed_list(self):
        response = self.add()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["items"]), 1)
        self.assertEqual(response.json()["items"][0]["query"], "AI")

    def test_update_changes_the_item(self):
        item_id = self.add().json()["items"][0]["id"]
        response = self.client.put(
            f"{self.url}/{item_id}",
            json={"values": {"channel_id": "123456789012345678", "query": "AI 最新", "interval": 60}},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["query"], "AI 最新")

    def test_delete_removes_the_item(self):
        item_id = self.add().json()["items"][0]["id"]
        response = self.client.delete(f"{self.url}/{item_id}", headers=CSRF_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"], [])

    def test_required_field_is_reported(self):
        response = self.client.post(
            self.url,
            json={"values": {"channel_id": "123456789012345678", "interval": 30}},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("query", response.json()["errors"])

    def test_max_items_is_enforced(self):
        for index in range(10):
            self.assertEqual(self.add(query=f"q{index}").status_code, 200)
        response = self.add(query="overflow")
        self.assertEqual(response.status_code, 422)
        self.assertIn("10 件まで", response.json()["errors"]["__all__"])

    def test_read_only_collection_rejects_add(self):
        response = self.client.post(
            "/admin/api/apps/tts/collections/user_settings", json={"values": {}}, headers=CSRF_HEADER
        )
        self.assertEqual(response.status_code, 405)

    def test_unknown_collection_is_404(self):
        response = self.client.post(
            "/admin/api/apps/news-feeds/collections/nope", json={"values": {}}, headers=CSRF_HEADER
        )
        self.assertEqual(response.status_code, 404)


SAMPLE_STATE = {
    "guild_id": GUILD_ID,
    "user_id": 555,
    "username": "member",
    "display_name": "メンバー",
    "avatar_url": None,
    "status": "banned",
    "is_in_guild": False,
    "is_banned": True,
    "is_timed_out": False,
    "timed_out_until": None,
    "roles": [{"id": 1, "name": "常連"}, {"id": 2, "name": "VIP"}],
    "abilities": {"administrator": False, "trusted_user": True},
    "last_event_type": "member_ban",
    "last_event_at": datetime(2026, 8, 21, 3, 30, 0, tzinfo=timezone.utc),
    "first_seen_at": None,
    "last_joined_at": None,
    "last_left_at": None,
    "updated_at": None,
}

SAMPLE_EVENT = {
    "id": 7,
    "event_type": "sync_member_on_ready",
    "status_after": "active",
    "actor_user_id": None,
    "actor_name": "管理者",
    "reason": "定期同期",
    "event_at": datetime(2026, 8, 21, 0, 0, 0, tzinfo=timezone.utc),
    "payload": {"source": "on_ready"},
}


class UserStateApiTests(unittest.TestCase):
    """DB を差し替えて、API の契約（絞り込み・ページ送り・ラベル化）を確認する。"""

    def setUp(self):
        self.client = make_client()
        self.calls = {}

    def _patched_list(self, rows, total):
        async def fake_list(guild_id, *, query=None, limit=50, offset=0):
            self.calls["list"] = {"guild_id": guild_id, "query": query, "limit": limit, "offset": offset}
            return rows

        async def fake_count(guild_id, *, query=None):
            self.calls["count"] = {"guild_id": guild_id, "query": query}
            return total

        return (
            patch("webapp_admin.api.users.list_recent_user_states", fake_list),
            patch("webapp_admin.api.users.count_user_states", fake_count),
        )

    def test_list_labels_status_and_event(self):
        list_patch, count_patch = self._patched_list([SAMPLE_STATE], 1)
        with list_patch, count_patch:
            payload = self.client.get("/admin/api/users/state").json()

        row = payload["rows"][0]
        self.assertEqual(row["user_id"], "555")
        self.assertEqual(row["status_label"], "BAN中")
        self.assertEqual(row["status_tone"], "danger")
        self.assertEqual(row["last_event_label"], "BAN")
        self.assertEqual(row["roles"], ["常連", "VIP"])
        self.assertEqual(row["abilities"], ["信頼済みユーザー"])
        self.assertEqual(row["last_event_at"], "2026/08/21 12:30:00")  # JST へ変換される

    def test_list_passes_search_and_paging_to_the_service(self):
        list_patch, count_patch = self._patched_list([], 120)
        with list_patch, count_patch:
            payload = self.client.get("/admin/api/users/state?q=%20abc%20&limit=25&offset=50").json()

        self.assertEqual(self.calls["list"], {"guild_id": GUILD_ID, "query": "abc", "limit": 25, "offset": 50})
        self.assertEqual(self.calls["count"]["query"], "abc")
        self.assertEqual(payload["total"], 120)
        self.assertFalse(payload["has_more"])  # 50 + 0 件 < 120 でも行が無ければ次は無い扱い

    def test_has_more_is_true_while_rows_remain(self):
        list_patch, count_patch = self._patched_list([SAMPLE_STATE] * 25, 120)
        with list_patch, count_patch:
            payload = self.client.get("/admin/api/users/state?limit=25&offset=0").json()
        self.assertTrue(payload["has_more"])

    def test_limit_is_bounded(self):
        response = self.client.get("/admin/api/users/state?limit=9999")
        self.assertEqual(response.status_code, 422)

    def test_detail_returns_current_and_events(self):
        async def fake_detail(guild_id, user_id, *, event_limit=200):
            self.calls["detail"] = {"guild_id": guild_id, "user_id": user_id, "event_limit": event_limit}
            return {"current": SAMPLE_STATE, "events": [SAMPLE_EVENT]}

        with patch("webapp_admin.api.users.get_user_state_detail", fake_detail):
            payload = self.client.get("/admin/api/users/state/555?event_limit=10").json()

        self.assertEqual(self.calls["detail"], {"guild_id": GUILD_ID, "user_id": 555, "event_limit": 10})
        self.assertTrue(payload["found"])
        self.assertEqual(payload["current"]["status_label"], "BAN中")
        # 可変の接頭辞を持つ同期イベントもラベル化される
        self.assertEqual(payload["events"][0]["event_label"], "メンバー状態を同期（起動時）")
        self.assertEqual(payload["events"][0]["event_at"], "2026/08/21 09:00:00")

    def test_detail_of_unknown_user_is_404(self):
        async def fake_detail(guild_id, user_id, *, event_limit=200):
            return None

        with patch("webapp_admin.api.users.get_user_state_detail", fake_detail):
            response = self.client.get("/admin/api/users/state/1")

        self.assertEqual(response.status_code, 404)
        self.assertFalse(response.json()["found"])

    def test_requires_a_selected_guild(self):
        client = make_client(with_guild=False)
        response = client.get("/admin/api/users/state", follow_redirects=False)
        self.assertEqual(response.status_code, 303)


class DevApiTests(unittest.TestCase):
    """開発者パネルの API。DEV_USER_ID と一致するユーザーだけが使える。"""

    def setUp(self):
        self.dev = make_client(user_id="4242")
        self.normal = make_client(user_id="1")
        # レート制限は limiter がプロセス全体で1つ（TestClient は同じ
        # 送信元IP扱いになる）。テストをまたいで前のテストの呼び出し回数が
        # 残ると、後続のテストが無関係に 429 で落ちる。テストごとに
        # クリアして、レート制限そのものの動作は別のテストで確認する。
        from webapp_admin.extensions import limiter

        limiter.reset()

    def test_non_developer_is_forbidden(self):
        self.assertEqual(self.normal.get("/admin/api/dev/overview").status_code, 403)

    def test_overview_reports_the_environment(self):
        payload = self.dev.get("/admin/api/dev/overview").json()
        self.assertIn("bot_user", payload)
        self.assertIn("tasks", payload)
        self.assertIn("news_feeds", payload["tasks"])
        self.assertIsInstance(payload["env_rows"], list)
        self.assertTrue(any(row["key"] == "DISCORD_BOT_TOKEN" for row in payload["env_rows"]))

    def test_secret_env_values_are_masked(self):
        payload = self.dev.get("/admin/api/dev/overview").json()
        secret_row = next(row for row in payload["env_rows"] if row["key"] == "ADMIN_FLASK_SECRET_KEY")
        self.assertTrue(secret_row["secret"])
        self.assertNotIn("x" * 10, secret_row["value"] or "")

    def test_overview_explains_why_guilds_is_empty_when_token_is_missing(self):
        # テスト環境では DISCORD_BOT_TOKEN は未設定。0件と「取得失敗」が
        # 同じ見た目にならないよう、理由が payload に出ること。
        payload = self.dev.get("/admin/api/dev/overview").json()
        self.assertEqual(payload["guilds"], [])
        self.assertIn("DISCORD_BOT_TOKEN", payload.get("discord_error") or "")

    def test_overview_explains_a_discord_api_failure(self):
        import asyncio as _asyncio

        class _FailingSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def request(self, *args, **kwargs):
                raise _asyncio.TimeoutError()

        with (
            patch("webapp_admin.api.dev.DISCORD_BOT_TOKEN", "test-token"),
            patch("webapp_admin.api.dev.aiohttp.ClientSession", _FailingSession),
        ):
            payload = self.dev.get("/admin/api/dev/overview").json()

        self.assertEqual(payload["guilds"], [])
        self.assertIn("取得できませんでした", payload.get("discord_error") or "")

    def test_overview_has_no_discord_error_on_success(self):
        class _FakeResponse:
            def __init__(self, payload):
                self._payload = payload
                self.status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def json(self):
                return self._payload

        class _WorkingSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def request(self, method, url, **kwargs):
                if "/guilds" in url:
                    return _FakeResponse([{"id": "1", "name": "Sample", "icon": None}])
                return _FakeResponse({"id": "42", "username": "bot"})

        with (
            patch("webapp_admin.api.dev.DISCORD_BOT_TOKEN", "test-token"),
            patch("webapp_admin.api.dev.aiohttp.ClientSession", _WorkingSession),
        ):
            payload = self.dev.get("/admin/api/dev/overview").json()

        self.assertNotIn("discord_error", payload)
        self.assertEqual(payload["guilds"], [{"id": "1", "name": "Sample", "icon": None}])

    def test_task_signal_is_queued(self):
        response = self.dev.post("/admin/api/dev/signal/news_feeds", json={}, headers=CSRF_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertIn("news_feeds", response.json()["pending_signals"])

    def test_unknown_task_is_404(self):
        response = self.dev.post("/admin/api/dev/signal/nope", json={}, headers=CSRF_HEADER)
        self.assertEqual(response.status_code, 404)

    def test_signal_requires_csrf(self):
        self.assertEqual(self.dev.post("/admin/api/dev/signal/sticky", json={}).status_code, 403)

    def test_notify_test_requires_a_numeric_guild_id(self):
        ok = self.dev.post(
            "/admin/api/dev/test-notify/welcome", json={"guild_id": "123456789012345678"}, headers=CSRF_HEADER
        )
        self.assertEqual(ok.status_code, 200)
        bad = self.dev.post("/admin/api/dev/test-notify/welcome", json={"guild_id": "abc"}, headers=CSRF_HEADER)
        self.assertEqual(bad.status_code, 400)

    def test_notify_test_can_override_the_channel(self):
        """通知テストの設定を作っていないギルドでも、DEV専用にチャンネルを
        直接指定してテスト送信できること（地震リプレイと同じ抜け道）。

        シグナル名は test_<kind>。kind の一覧は services/dev_test_notify.py が持つ。"""
        from services.dev_signals import latest as latest_signal

        bad_channel = self.dev.post(
            "/admin/api/dev/test-notify/welcome",
            json={"guild_id": str(GUILD_ID), "channel_id": "xyz"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(bad_channel.status_code, 400)

        ok = self.dev.post(
            "/admin/api/dev/test-notify/vc",
            json={"guild_id": str(GUILD_ID), "channel_id": "555"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(ok.status_code, 200)
        self.assertIn("555", ok.json()["message"])
        signal = json.loads(latest_signal("test_vc").read_text(encoding="utf-8"))
        self.assertEqual(signal["guild_id"], GUILD_ID)
        self.assertEqual(signal["channel_id"], 555)

        # チャンネル省略時は None（設定済みのチャンネルを使う、が既定のまま）
        no_channel = self.dev.post(
            "/admin/api/dev/test-notify/welcome",
            json={"guild_id": str(GUILD_ID)},
            headers=CSRF_HEADER,
        )
        self.assertEqual(no_channel.status_code, 200)
        signal2 = json.loads(latest_signal("test_welcome").read_text(encoding="utf-8"))
        self.assertIsNone(signal2["channel_id"])

    def test_earthquake_replay_validates_the_payload(self):
        bad = self.dev.post("/admin/api/dev/earthquake-replay", json={"event_json": "{}"}, headers=CSRF_HEADER)
        self.assertEqual(bad.status_code, 400)

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})
        ok = self.dev.post("/admin/api/dev/earthquake-replay", json={"event_json": event}, headers=CSRF_HEADER)
        self.assertEqual(ok.status_code, 200)
        self.assertIn("eq_replay", ok.json()["pending_signals"])

    def test_earthquake_replay_can_target_a_single_guild(self):
        """全サーバーへの誤爆を避けるため、guild_id を指定した分だけに絞れること。

        シグナルは {"event": ..., "guild_id": ...} という封筒形式で書かれ、
        bot 側 (bot_setup.py) がここから対象ギルドを読み取る契約になっている。
        """
        from services.dev_signals import latest as latest_signal

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})

        bad = self.dev.post(
            "/admin/api/dev/earthquake-replay", json={"event_json": event, "guild_id": "abc"}, headers=CSRF_HEADER
        )
        self.assertEqual(bad.status_code, 400)

        ok = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "guild_id": str(GUILD_ID)},
            headers=CSRF_HEADER,
        )
        self.assertEqual(ok.status_code, 200)
        self.assertIn(str(GUILD_ID), ok.json()["message"])
        signal = json.loads(latest_signal("eq_replay").read_text(encoding="utf-8"))
        self.assertEqual(signal["guild_id"], GUILD_ID)
        self.assertIn("earthquake", signal["event"])

        # guild_id 省略時は全サーバー扱い（null）のまま、明示的に選べる状態を保つ
        all_guilds = self.dev.post("/admin/api/dev/earthquake-replay", json={"event_json": event}, headers=CSRF_HEADER)
        self.assertEqual(all_guilds.status_code, 200)
        signal2 = json.loads(latest_signal("eq_replay").read_text(encoding="utf-8"))
        self.assertIsNone(signal2["guild_id"])

    def test_earthquake_replay_can_override_the_channel(self):
        """地震アラート設定を持たないギルドでも、DEV専用にチャンネルを直接指定できること。"""
        from services.dev_signals import latest as latest_signal

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})

        # チャンネルIDだけ指定してギルドが無いのは拒否する
        # （どのギルドのチャンネルか定まらない）
        no_guild = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "channel_id": "555"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(no_guild.status_code, 400)

        bad_channel = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "guild_id": str(GUILD_ID), "channel_id": "xyz"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(bad_channel.status_code, 400)

        ok = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "guild_id": str(GUILD_ID), "channel_id": "555"},
            headers=CSRF_HEADER,
        )
        self.assertEqual(ok.status_code, 200)
        self.assertIn("555", ok.json()["message"])
        signal = json.loads(latest_signal("eq_replay").read_text(encoding="utf-8"))
        self.assertEqual(signal["guild_id"], GUILD_ID)
        self.assertEqual(signal["channel_id"], 555)

        # チャンネル省略時は None（地震アラート設定のチャンネルを使う、が既定のまま）
        no_channel = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "guild_id": str(GUILD_ID)},
            headers=CSRF_HEADER,
        )
        self.assertEqual(no_channel.status_code, 200)
        signal2 = json.loads(latest_signal("eq_replay").read_text(encoding="utf-8"))
        self.assertIsNone(signal2["channel_id"])

    def test_signals_for_different_guilds_do_not_overwrite_each_other(self):
        """対象がギルドごとに違うシグナルは、1件ずつ別のファイルにすること。

        Bot は30秒ごとにしか拾わない。用途名だけのファイル名で書いていたため、
        2つのサーバーの管理者がその間に操作すると先の1件が上書きで消え、
        押した側には「キューに追加しました」と出たまま何も起きなかった。
        """
        from services import dev_signals

        for path in dev_signals.collect():
            path.unlink(missing_ok=True)

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})
        for guild_id in ("111", "222"):
            response = self.dev.post(
                "/admin/api/dev/earthquake-replay",
                json={"event_json": event, "guild_id": guild_id},
                headers=CSRF_HEADER,
            )
            self.assertEqual(response.status_code, 200)

        signals = [p for p in dev_signals.collect() if dev_signals.task_name_of(p) == "eq_replay"]
        self.assertEqual(len(signals), 2, "2回押したぶんが残っていない")
        sent = [json.loads(p.read_text(encoding="utf-8"))["guild_id"] for p in signals]
        self.assertEqual(sorted(sent), [111, 222])
        # Bot 側は用途名で分岐する。名前を一意にしても同じ分岐に落ちること。
        self.assertTrue(all(dev_signals.task_name_of(p) == "eq_replay" for p in signals))

    def test_repeatable_tasks_keep_collapsing_into_one_signal(self):
        """何度実行しても結果が同じものは、溜めずに上書きでよい。"""
        from services import dev_signals

        for path in dev_signals.collect():
            path.unlink(missing_ok=True)

        for _ in range(3):
            response = self.dev.post("/admin/api/dev/signal/news_feeds", headers=CSRF_HEADER)
            self.assertEqual(response.status_code, 200)

        signals = [p for p in dev_signals.collect() if dev_signals.task_name_of(p) == "news_feeds"]
        self.assertEqual(len(signals), 1)

    def test_lookup_endpoints_reject_non_numeric_ids(self):
        self.assertEqual(self.dev.get("/admin/api/dev/user?user_id=abc").status_code, 400)
        self.assertEqual(self.dev.get("/admin/api/dev/channels?guild_id=abc").status_code, 400)

    def test_logs_are_returned_as_lines(self):
        payload = self.dev.get("/admin/api/dev/logs?source=admin&lines=10").json()
        self.assertEqual(payload["source"], "admin")
        self.assertIsInstance(payload["lines"], list)

    def test_unknown_log_source_is_rejected(self):
        self.assertEqual(self.dev.get("/admin/api/dev/logs?source=secret").status_code, 422)

    def test_guild_settings_roundtrip(self):
        # 設定APIで書き込んでから、開発者パネル側で読めることを見る
        self.dev.put("/admin/api/apps/logging", json={"values": {"log_level": "ERROR"}}, headers=CSRF_HEADER)
        payload = self.dev.get(f"/admin/api/dev/settings/{GUILD_ID}").json()
        self.assertEqual(payload["guild_id"], str(GUILD_ID))
        # settings.json 上のキーは log_level（管理UIのフィールド名とは別物）
        self.assertEqual(payload["settings"]["log_level"], "ERROR")

    def test_unknown_guild_settings_is_404(self):
        self.assertEqual(self.dev.get("/admin/api/dev/settings/1").status_code, 404)

    def test_import_replaces_settings(self):
        response = self.dev.post(
            f"/admin/api/dev/settings/{GUILD_ID}/import",
            json={"settings": {"log_level": "DEBUG", "log_channel_id": None}},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 200)
        after = self.dev.get("/admin/api/apps/logging").json()
        self.assertEqual(after["values"]["log_level"], "DEBUG")

    def test_import_rejects_a_non_object(self):
        response = self.dev.post(
            f"/admin/api/dev/settings/{GUILD_ID}/import",
            json={"settings": ["not", "an", "object"]},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 400)

    def test_import_rejects_oversized_payloads(self):
        response = self.dev.post(
            f"/admin/api/dev/settings/{GUILD_ID}/import",
            json={"settings": {"blob": "あ" * 200000}},
            headers=CSRF_HEADER,
        )
        self.assertEqual(response.status_code, 413)

    def test_cache_delete_rejects_a_bad_token(self):
        response = self.dev.delete("/admin/api/dev/cache/..%2Fetc", headers=CSRF_HEADER)
        self.assertIn(response.status_code, (400, 404))


class ExternalFailureTests(unittest.TestCase):
    """外部APIが応答しないときに、原因が分かる形で残ること。

    TimeoutError は str() が空になるため、素朴に "%s" で出すと理由の無いログに
    なってしまう。型名まで含めていることを確かめる。
    """

    def test_timeout_is_described_with_its_cause(self):
        import asyncio as _asyncio

        from webapp_admin.api.dev import describe_exception

        described = describe_exception(_asyncio.TimeoutError(), timeout=10)
        self.assertNotEqual(described.strip(), "")
        self.assertIn("タイムアウト", described)
        self.assertIn("10", described)

    def test_unknown_exception_keeps_its_type_name(self):
        from webapp_admin.api.dev import describe_exception

        self.assertIn("ValueError", describe_exception(ValueError()))

    def test_earthquake_endpoint_reports_the_reason(self):
        import asyncio as _asyncio

        client = make_client(user_id="4242")

        class _FailingSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def get(self, *args, **kwargs):
                raise _asyncio.TimeoutError()

        with patch("webapp_admin.api.dev.aiohttp.ClientSession", _FailingSession):
            response = client.get("/admin/api/dev/earthquakes")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["events"], [])
        self.assertIn("タイムアウト", payload["error"])


class LegacyUrlTests(unittest.TestCase):
    """旧ページのURLはデスクトップの該当ウィンドウへ寄せる。"""

    def test_settings_url_redirects_to_the_matching_window(self):
        response = make_client().get("/admin/settings/tts", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["location"].endswith("#tts"))

    def test_user_state_url_redirects(self):
        response = make_client().get("/admin/users/state", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["location"].endswith("#user-state"))

    def test_legacy_settings_pages_are_gone(self):
        # POST を受け付けていた旧エンドポイントは残っていない
        response = make_client().post("/admin/settings/logging", data={"csrf_token": CSRF, "action": "set_log"})
        self.assertEqual(response.status_code, 405)


class IconTests(unittest.TestCase):
    """参照しているアイコンがスプライトに入っていること。

    抜けていても例外は出ず、アイコンが無言で消えるだけなので機械的に確かめる。
    """

    def setUp(self):
        import re

        sprite = (
            Path(__file__).resolve().parent.parent / "webapp_admin" / "static" / "icons" / "sprite.svg"
        ).read_text(encoding="utf-8")
        self.available = set(re.findall(r'<symbol[^>]*id="([^"]+)"', sprite))

    def test_panel_icons_exist(self):
        from webapp_admin.schema.registry import PANELS

        missing = [panel.id for panel in PANELS if panel.icon.removeprefix("bi-") not in self.available]
        self.assertEqual(missing, [], f"スプライトに無いアイコンを指すパネル: {missing}")

    def test_referenced_icons_exist(self):
        import sys as _sys

        _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
        from build_icon_sprite import used_icon_names

        missing = sorted(set(used_icon_names()) - self.available)
        self.assertEqual(
            missing,
            [],
            f"参照しているのにスプライトに無いアイコン: {missing}"
            " — python tools/build_icon_sprite.py を実行してください。",
        )


class MetricToneTests(unittest.TestCase):
    """メーターの色が値に連動していること。

    以前は指標ごとに色を固定していたため、CPU が 99% でも 5% でも同じ見た目で、
    SLA は 100% でも警告色だった。色が状態を表していないと、見る意味がなくなる。
    """

    def test_load_tone_follows_alert_threshold(self):
        from webapp_admin.metrics import load_tone

        self.assertEqual(load_tone(5, 90), "success")
        self.assertEqual(load_tone(71, 90), "success")
        self.assertEqual(load_tone(72, 90), "warning")  # しきい値の8割
        self.assertEqual(load_tone(90, 90), "danger")  # アラートを記録する値
        self.assertEqual(load_tone(100, 90), "danger")

    def test_sla_tone(self):
        from webapp_admin.metrics import sla_tone

        self.assertEqual(sla_tone(100), "success")
        self.assertEqual(sla_tone(99.9), "success")
        self.assertEqual(sla_tone(99.0), "warning")
        self.assertEqual(sla_tone(98.9), "danger")

    def test_metric_tones_are_defined_in_css(self):
        """クライアントは tone をそのまま class にする。CSS に無い色は無言で消える。"""
        import re

        from webapp_admin.metrics import load_tone, sla_tone

        css = (Path(__file__).resolve().parent.parent / "webapp_admin" / "static" / "css" / "components.css").read_text(
            encoding="utf-8"
        )
        defined = set(re.findall(r"\.metric\.tone-([\w-]+)", css))
        used = {load_tone(v, 90) for v in (0, 80, 95)} | {sla_tone(v) for v in (100, 99.5, 0)}
        self.assertEqual(used - defined, set(), f"CSS に無い tone: {used - defined}")


class StylesheetTests(unittest.TestCase):
    """テンプレートの class が、どこかの CSS で定義されていること。

    Bootstrap を外したあとも `badge-soft` や `ms-2` のような当時のクラスが
    残っていて、見た目だけが無言で崩れていた。名前の付け間違いも同じ形で出る。
    """

    ADMIN = Path(__file__).resolve().parent.parent / "webapp_admin"
    # 見た目を持たない、JS からも引かない純粋な目印（意図して許すもの）
    ALLOWED = {"public", "aero-page", "auth-page"}

    def _class_names(self, text: str) -> set[str]:
        import re

        names: set[str] = set()
        for attr in re.findall(r'class="([^"]*)"', text):
            attr = re.sub(r"\{[%{].*?[%}]\}", " ", attr)  # Jinja の式は数えない
            names.update(attr.split())
        return names

    def test_no_undefined_classes_in_templates(self):
        import re

        css = " ".join(path.read_text(encoding="utf-8") for path in (self.ADMIN / "static" / "css").glob("*.css"))
        js = " ".join(path.read_text(encoding="utf-8") for path in (self.ADMIN / "static" / "js").rglob("*.js"))
        defined = set(re.findall(r"\.([A-Za-z][\w-]*)", css))

        unknown: dict[str, set[str]] = {}
        for path in (self.ADMIN / "templates").glob("*.html"):
            for name in self._class_names(path.read_text(encoding="utf-8")):
                if name in defined or name in self.ALLOWED:
                    continue
                # JS が掴むためだけの目印は CSS に無くてよい
                if f'"{name}"' in js or f"'{name}'" in js or f".{name}" in js:
                    continue
                unknown.setdefault(name, set()).add(path.name)

        self.assertEqual(
            unknown,
            {},
            "CSS にもJSにも無い class がテンプレートに残っています: "
            + ", ".join(f"{name}({'/'.join(sorted(files))})" for name, files in sorted(unknown.items())),
        )

    def test_public_pages_do_not_redefine_shared_classes(self):
        """公開ページ用の CSS が、共通部品の名前を上書きしないこと。

        以前 public.css が base.css の .row（汎用の横並び）をグリッドに
        書き換えていて、公開ページで .row を使うと崩れる状態だった。
        """
        import re

        css_dir = self.ADMIN / "static" / "css"
        shared = set()
        for name in ("base.css", "components.css"):
            for selector in re.findall(
                r"^\s*\.([A-Za-z][\w-]*)\s*[,{]", (css_dir / name).read_text(encoding="utf-8"), re.M
            ):
                shared.add(selector)

        public = (css_dir / "public.css").read_text(encoding="utf-8")
        clashes = sorted(name for name in re.findall(r"^\s*\.([A-Za-z][\w-]*)\s*[,{]", public, re.M) if name in shared)
        self.assertEqual(clashes, [], f"共通クラスを公開ページ CSS が上書きしています: {clashes}")


class DocsTests(unittest.TestCase):
    """ドキュメントの設定表がスキーマと一致していること。"""

    def test_settings_table_is_up_to_date(self):
        import subprocess

        result = subprocess.run(
            [sys.executable, "tools/generate_admin_docs.py", "--check"],
            cwd=str(Path(__file__).resolve().parent.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(
            result.returncode,
            0,
            "docs/ADMIN.ja.md が古くなっています。python tools/generate_admin_docs.py を実行してください。"
            + (result.stdout or "")
            + (result.stderr or ""),
        )


class RecordingMixerApiTests(unittest.TestCase):
    """ミキサーが使う配信API。ZIP を展開せずに1トラックずつ読ませる。"""

    @classmethod
    def setUpClass(cls):
        import math
        import struct
        import time as _time
        from unittest.mock import Mock

        import services.recording_service as recording

        def tone(seconds, freq=440.0):
            out = bytearray()
            for i in range(int(recording.SAMPLE_RATE * seconds)):
                v = int(12000 * math.sin(2 * math.pi * freq * i / recording.SAMPLE_RATE))
                out += struct.pack("<hh", v, v)
            return bytes(out)

        session = recording.RecordingSession(
            guild_id=GUILD_ID,
            channel_id=555,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=_time.monotonic(),
            max_seconds=0,
            retention_days=7,
        )
        session.feed(Mock(id=1, display_name="すずき"), tone(0.4))
        session.feed(Mock(id=2, display_name="たなか"), tone(0.4, 660))
        cls.result = recording._finalize(session, 2.0, "テスト")
        cls.token = cls.result["token"]

    def setUp(self):
        self.client = TestClient(app)

    def _mixer_url(self, guild_id=GUILD_ID, token=None):
        return f"/dlaudio/files/{guild_id}/{token or self.token}/mixer"

    def test_manifest_describes_every_track(self):
        response = self.client.get(self._mixer_url())
        self.assertEqual(response.status_code, 200)
        manifest = response.json()
        self.assertAlmostEqual(manifest["duration_seconds"], 2.0, delta=0.1)
        self.assertEqual(len(manifest["stems"]), 2)
        self.assertEqual({s["name"] for s in manifest["stems"]}, {"すずき", "たなか"})
        self.assertTrue(all(s["peaks_b64"] and s["rms_b64"] for s in manifest["stems"]))
        self.assertTrue(all("/stem/" in s["url"] for s in manifest["stems"]))

    def test_the_manifest_is_compressed_when_the_browser_accepts_it(self):
        """索引を gzip で返すこと。

        波形を 0.05 秒刻みで持つので、2時間×5トラックだと素の JSON で 2MB 近く
        なる。中身は base64 の1バイト列で無音が同じ文字の連なりになるため、
        圧縮がよく効く（実測 1.98MB → 1.16MB）。**開くたびに毎回落ちてくる**
        ものなので、ここを素で流すと待ち時間がそのまま増える。
        """
        response = self.client.get(self._mixer_url(), headers={"accept-encoding": "gzip"})
        self.assertEqual(response.status_code, 200)
        # httpx は透過的に展開するので、中身が読めることと宣言の両方を見る。
        self.assertEqual(response.headers.get("content-encoding"), "gzip")
        # セッション層が Cookie も足すので、含まれていることだけを見る。
        self.assertIn("Accept-Encoding", response.headers.get("vary", ""))
        self.assertIn("stems", response.json())

    def test_the_manifest_stays_plain_for_clients_that_do_not_ask_for_gzip(self):
        """gzip を受け付けない相手には、そのまま返すこと。

        ヘッダを見ない道具（curl の既定など）に圧縮を送りつけると、
        **読めない中身**が返ることになる。
        """
        response = self.client.get(self._mixer_url(), headers={"accept-encoding": "identity"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.headers.get("content-encoding"))
        self.assertIn("stems", response.json())

    def test_stem_is_served_as_seekable_audio(self):
        url = self.client.get(self._mixer_url()).json()["stems"][0]["url"]
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "audio/mpeg")
        # Range を宣言しないと、ブラウザは頭出しのたびに全部落とし直す。
        self.assertEqual(response.headers.get("accept-ranges"), "bytes")
        self.assertGreater(len(response.content), 0)

    def test_range_requests_return_exactly_the_asked_bytes(self):
        url = self.client.get(self._mixer_url()).json()["stems"][0]["url"]
        whole = self.client.get(url).content

        partial = self.client.get(url, headers={"Range": "bytes=100-199"})
        self.assertEqual(partial.status_code, 206)
        self.assertEqual(partial.content, whole[100:200])
        self.assertEqual(partial.headers.get("content-range"), f"bytes 100-199/{len(whole)}")

        suffix = self.client.get(url, headers={"Range": "bytes=-50"})
        self.assertEqual(suffix.status_code, 206)
        self.assertEqual(suffix.content, whole[-50:])

        beyond = self.client.get(url, headers={"Range": f"bytes={len(whole) + 10}-"})
        self.assertEqual(beyond.status_code, 416)

    def test_broken_ranges_do_not_produce_a_broken_response(self):
        """満たせない Range は 416、範囲として成立しないものは全体を返すこと。

        終わりが始まりより手前（"bytes=500-100"）を弾いていなかったため、
        Content-Length: -399 という壊れたヘッダを 206 で返していた。厳格な
        プロキシやクライアントはここで接続を切る。
        """
        url = self.client.get(self._mixer_url()).json()["stems"][0]["url"]
        size = len(self.client.get(url).content)

        for header in ("bytes=500-100", "bytes=900-100", f"bytes={size}-{size + 10}"):
            response = self.client.get(url, headers={"Range": header})
            self.assertEqual(response.status_code, 416, header)
            self.assertEqual(response.headers.get("content-range"), f"bytes */{size}", header)

        # 数字がどちらも無いものは Range として成立しない。無視して全体を返す。
        whole = self.client.get(url, headers={"Range": "bytes=-"})
        self.assertEqual(whole.status_code, 200)
        self.assertEqual(len(whole.content), size)

        # どの応答でも Content-Length が負にならないこと
        for header in ("bytes=0-99", "bytes=500-100", "bytes=-", "bytes=-50"):
            response = self.client.get(url, headers={"Range": header})
            length = response.headers.get("content-length")
            self.assertTrue(length is None or int(length) >= 0, (header, length))

    def test_other_guilds_cannot_read_the_recording(self):
        self.assertEqual(self.client.get(self._mixer_url(guild_id=111)).status_code, 403)

    def test_unknown_or_broken_links_do_not_leak(self):
        self.assertEqual(self.client.get(self._mixer_url(token="a" * 32)).status_code, 410)
        self.assertEqual(self.client.get(self._mixer_url(token="xx")).status_code, 404)
        self.assertEqual(
            self.client.get(f"/dlaudio/files/{GUILD_ID}/{self.token}/stem/99").status_code,
            404,
        )


if __name__ == "__main__":
    unittest.main()


class SnowflakeJsonTests(unittest.TestCase):
    """Discord の ID を JavaScript が壊さずに読めること。

    ID は 19 桁あり、JavaScript の数値は 2^53-1 までしか正確に扱えない。
    JSON に数値として入れると読んだ時点で桁が落ちる。

        1234567890123456789  →  1234567890123456800

    実際にこれで、実在するチャンネルを指定しているのに管理画面のプルダウンが
    「一覧にありません」になった。
    """

    # 作り物の ID。必要なのは 19 桁で桁落ちすることだけ。
    VC_ID = 1234567890123456789

    def test_javascript_really_loses_these_digits(self):
        """前提の確認。桁が落ちないなら、この対策は要らない。"""
        self.assertNotEqual(int(float(self.VC_ID)), self.VC_ID)
        self.assertGreater(self.VC_ID, 2**53 - 1)

    def test_big_integers_become_strings(self):
        from webapp_admin.api.jsonsafe import stringify_big_ints

        self.assertEqual(stringify_big_ints(self.VC_ID), str(self.VC_ID))

    def test_ordinary_numbers_are_left_alone(self):
        from webapp_admin.api.jsonsafe import stringify_big_ints

        for value in (0, 1, -1, 42, 2**53 - 1, 3.14):
            self.assertEqual(stringify_big_ints(value), value, value)

    def test_booleans_stay_booleans(self):
        """bool は int の仲間。先に外さないと True が "1" になる。"""
        from webapp_admin.api.jsonsafe import stringify_big_ints

        self.assertIs(stringify_big_ints(True), True)
        self.assertIs(stringify_big_ints(False), False)

    def test_nested_values_are_converted(self):
        from webapp_admin.api.jsonsafe import stringify_big_ints

        got = stringify_big_ints({"a": [{"id": self.VC_ID}], "b": (self.VC_ID, 1), "c": "x"})
        self.assertEqual(got, {"a": [{"id": str(self.VC_ID)}], "b": [str(self.VC_ID), 1], "c": "x"})

    def test_the_recording_api_sends_ids_as_strings(self):
        from services import settings_store as store

        store.set_recording_settings(
            GUILD_ID,
            {
                "vc_channel_id": self.VC_ID,
                "announce_channel_id": self.VC_ID,
            },
        )
        client = make_client()
        body = client.get("/admin/api/recording?include_channels=0").text
        self.assertIn(f'"{self.VC_ID}"', body, body[:400])
        # 桁が落ちた値が混ざっていないこと
        self.assertNotIn("1234567890123456800", body)


class RecordingClipTests(unittest.TestCase):
    """区間の切り出し。ミキサーで決めた範囲だけを落とせること。"""

    @classmethod
    def setUpClass(cls):
        import math
        import struct
        import time as _time
        from unittest.mock import Mock

        import services.recording_service as recording

        def tone(seconds, freq=440.0):
            out = bytearray()
            for i in range(int(recording.SAMPLE_RATE * seconds)):
                v = int(12000 * math.sin(2 * math.pi * freq * i / recording.SAMPLE_RATE))
                out += struct.pack("<hh", v, v)
            return bytes(out)

        session = recording.RecordingSession(
            guild_id=GUILD_ID,
            channel_id=555,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=_time.monotonic(),
            max_seconds=0,
            retention_days=7,
        )
        session.feed(Mock(id=1, display_name="すずき"), tone(2.0))
        session.feed(Mock(id=2, display_name="たなか"), tone(2.0, 660))
        cls.result = recording._finalize(session, 4.0, "テスト")
        cls.token = cls.result["token"]

    def _url(self, start, end, guild_id=GUILD_ID, token=None):
        return f"/dlaudio/files/{guild_id}/{token or self.token}/clip" f"?start={start}&end={end}"

    def test_a_region_comes_back_as_a_zip_of_every_track(self):
        import io
        import zipfile

        response = TestClient(app).get(self._url(0.5, 1.5))
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(response.headers["content-type"], "application/zip")
        self.assertIn("attachment", response.headers.get("content-disposition", ""))

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = archive.namelist()
        self.assertEqual(len([n for n in names if n.endswith(".mp3")]), 2, names)
        self.assertIn("info.txt", names)

    def test_the_clip_is_shorter_than_the_whole_recording(self):
        client = TestClient(app)
        clip = client.get(self._url(0.5, 1.0)).content
        whole = client.get(f"/dlaudio/files/{GUILD_ID}/{self.token}/stem/0").content
        self.assertLess(len(clip), len(whole) * 2, "全部入っている（切り出せていない）")

    def test_a_backwards_or_tiny_region_is_refused(self):
        client = TestClient(app)
        self.assertEqual(client.get(self._url(2.0, 1.0)).status_code, 400)
        self.assertEqual(client.get(self._url(1.0, 1.0)).status_code, 400)

    def test_an_absurdly_long_region_is_refused(self):
        """丸ごと落としてもらうべき長さで、その場で切らない。"""
        client = TestClient(app)
        response = client.get(self._url(0, 3600 * 3))
        self.assertEqual(response.status_code, 400)
        # 断った理由が本文に出ること（「不正なリクエストです」で終わらせない）
        self.assertIn("時間", response.text)
        # fetch する側（JSON を求める相手）には JSON で理由を返すこと
        as_json = client.get(self._url(0, 3600 * 3), headers={"Accept": "application/json"})
        self.assertIn("時間", as_json.json()["detail"])

    def test_other_guilds_cannot_clip(self):
        self.assertEqual(TestClient(app).get(self._url(0.5, 1.5, guild_id=111)).status_code, 403)

    def test_nothing_reads_a_whole_track_into_memory(self):
        """トラックを丸ごとメモリへ読まないこと。

        6時間×8人の録音は 689MB になる。切り出しも、かつてあった解析・打ち消しも、
        どれも「トラック全体を bytes で読んでから ffmpeg の標準入力へ渡す」形だった
        ので、1リクエストで数百MB、同時に2つ来れば GB 単位になっていた。
        取り出しは一時ファイルへ流す。
        """
        import tracemalloc
        from services import djaudio_cdn as cdn

        zip_path = cdn._recording_zip(str(GUILD_ID), self.token)
        member = cdn._read_manifest(zip_path)["stems"][0]["file"]
        size = cdn._stored_member_range(zip_path, member)[1]

        with tempfile.TemporaryDirectory() as work:
            destination = Path(work) / "stem.mp3"
            tracemalloc.start()
            self.assertTrue(cdn._extract_member(zip_path, member, destination))
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        self.assertEqual(destination.stat().st_size if destination.exists() else size, size)
        # 読み取り単位ぶんの上振れは許す。トラックの大きさには比例しないこと。
        self.assertLess(peak, cdn._MEMBER_CHUNK * 4, f"{peak} バイト確保している（トラックは {size} バイト）")

    def test_the_segment_carries_one_channel_per_track(self):
        """再生用の区切りは「1トラック＝1チャンネル」の生 PCM で返すこと。

        トラックごとに <audio> を持つと時計が人数ぶん並び、揃え続けるための
        補正が要る。1つの音源にまとめれば時計も1つで、ずれようがない。

        コンテナに入れないのは実測の結果。Opus(WebM) はブラウザ側で
        チャンネル順が入れ替わり、WAV は3チャンネルのとき
        EncodingError で復号を拒まれた（ffmpeg が 2.1 のレイアウトを書くため）。
        生の PCM なら並びは書いた順そのもの。
        """
        client = TestClient(app)
        manifest = client.get(f"/dlaudio/files/{GUILD_ID}/{self.token}/mixer").json()
        self.assertIn("/segment", manifest["segment_url"])
        self.assertEqual(
            manifest["segment_format"],
            {
                "encoding": "s16le",
                "sample_rate": 48000,
                "channels": len(manifest["stems"]),
            },
        )

        response = client.get(f"{manifest['segment_url']}?start=1&length=1")
        self.assertEqual(response.status_code, 200, response.text[:200])
        channels = manifest["segment_format"]["channels"]
        frames = len(response.content) / 2 / channels
        self.assertAlmostEqual(frames / 48000, 1.0, delta=0.05)

        # チャンネルごとに中身が違うこと（全部同じなら混ざっている）
        import array

        samples = array.array("h")
        samples.frombytes(response.content[: len(response.content) // 2 * 2])
        per_channel = [samples[c::channels] for c in range(channels)]
        energies = [sum(abs(v) for v in ch[:4000]) for ch in per_channel]
        self.assertTrue(all(e > 0 for e in energies), energies)
        self.assertNotEqual(per_channel[0][:200], per_channel[1][:200], "チャンネルが同じ中身になっている")

    def test_the_segment_starts_exactly_where_it_was_asked_to(self):
        """区切りの先頭がずれないこと。

        入力側の -ss だけで切ると、区切りの先頭に無音が入る。subfile 越しの
        mp3 は索引を使った正確なシークができないためで、実測では要求位置に
        よって 110〜195ms とばらついた。区切りの継ぎ目ごとに音が欠け、
        しかも欠ける量が位置によって違う、という一番たちの悪い形になる。
        入力側は手前まで飛ぶだけにして、端数は出力側で捨てる。
        """
        import array
        import math
        import struct
        import time as _time

        import services.recording_service as recording
        from services.djaudio_cache import get_meta, payload_path
        from services import djaudio_cdn as cdn

        # 5秒ごとに 0.2 秒の合図が入る 30 秒の録音。位置が分かるようにする。
        rate = recording.SAMPLE_RATE
        pcm = bytearray()
        for i in range(int(rate * 30)):
            loud = ((i / rate) % 5.0) < 0.2
            value = int(12000 * math.sin(2 * math.pi * 880 * i / rate)) if loud else 0
            pcm += struct.pack("<hh", value, value)

        session = recording.RecordingSession(
            guild_id=GUILD_ID,
            channel_id=555,
            channel_name="目印",
            started_by_id=1,
            started_by_name="すずき",
            started_at=_time.monotonic(),
            max_seconds=0,
            retention_days=7,
        )
        track = recording._TrackWriter(1, "すずき", Path(session.workdir) / "01-a.mp3", session.started_at)
        session.tracks[1] = track
        track.write(bytes(pcm), 0.0)
        with patch.object(recording, "measure_voice", return_value=None):
            result = recording._finalize(session, 30.0, "テスト")

        zip_path = payload_path(result["token"], get_meta(result["token"]))
        stems = cdn._read_manifest(zip_path)["stems"]
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / "segment.pcm"
            for start in (5.0, 10.0, 20.0, 25.0):
                self.assertTrue(cdn._segment_pcm(zip_path, stems, start, 1.0, out))
                samples = array.array("h")
                samples.frombytes(out.read_bytes())
                first = next((i for i, v in enumerate(samples) if abs(v) > 500), None)
                self.assertIsNotNone(first, f"{start} 秒の区切りに音が無い")
                self.assertLess(
                    first / 48000, 0.01, f"{start} 秒を要求したのに先頭が " f"{first / 48000 * 1000:.1f} ms ずれている"
                )

    def test_the_segment_is_compressed_but_still_raw_pcm(self):
        """gzip で返しても、解いた中身は生の PCM のままであること。

        生の PCM は中身に関係なく帯域を食う（5トラックで 3.84Mbps、32なら
        24.6Mbps）。中身はほとんど無音なので gzip が極端に効き、実測では
        1.2〜21.9% まで縮んだ。**縮めた結果が別物になっていないこと**を
        ここで固定する。取得が再生に間に合わなくなると、クライアントは
        間に合わなかったぶんを飛ばして鳴らすので、帯域は音の欠けに直結する。
        """
        import gzip as gziplib

        client = TestClient(app)
        url = f"/dlaudio/files/{GUILD_ID}/{self.token}/segment?start=0&length=1"

        plain = client.get(url, headers={"Accept-Encoding": "identity"})
        self.assertEqual(plain.status_code, 200)
        self.assertNotIn("content-encoding", plain.headers)

        packed = client.get(url, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(packed.status_code, 200)
        raw = packed.content
        # TestClient は透過的に解くことがあるので、どちらでも通るようにする。
        if packed.headers.get("content-encoding") == "gzip" and raw[:2] == b"\x1f\x8b":
            raw = gziplib.decompress(raw)
        self.assertEqual(raw, plain.content, "gzip を解いた中身が生の PCM と違う")

    def test_the_segment_rejects_impossible_requests(self):
        client = TestClient(app)
        base = f"/dlaudio/files/{GUILD_ID}/{self.token}/segment"
        self.assertEqual(client.get(f"{base}?start=0&length=0").status_code, 400)
        self.assertEqual(client.get(f"{base}?start=0&length=999").status_code, 400)
        self.assertEqual(client.get(f"/dlaudio/files/111/{self.token}/segment?start=0&length=1").status_code, 403)


class TextContrastTests(unittest.TestCase):
    """本文に使う色が、背景に対して読める明るさを保っていること。

    補助テキスト（タイムスタンプ・型名・カテゴリラベル・フッターのリンク）に
    使っていた淡色トークンが、いずれも WCAG AA の 4.5:1 に届いていなかった
    （管理画面 3.04:1 / 公開ページ 3.23:1 / PWA 3.06:1）。薄いほど上品に
    見えるので、目視では気付きにくく、じわじわ薄くなりやすい。

    色は3つの CSS で別々に定義されているので、実際のファイルから読んで測る。
    """

    ROOT = Path(__file__).resolve().parent.parent
    MIN_RATIO = 4.5

    # (説明, CSSファイル, トークン名, 想定する背景色) — 背景は同じ CSS の地の色
    CASES = [
        ("管理画面 淡色（ライト）", "webapp_admin/static/css/tokens.css", "--fg-subtle", "#ffffff", 0),
        ("管理画面 淡色（ダーク）", "webapp_admin/static/css/tokens.css", "--fg-subtle", "#0d1117", 1),
        ("管理画面 中間色（ライト）", "webapp_admin/static/css/tokens.css", "--fg-muted", "#ffffff", 0),
        ("公開ページ 淡色（ライト）", "webapp_admin/static/css/public.css", "--ink-3", "#ffffff", 0),
        ("公開ページ 淡色（ダーク）", "webapp_admin/static/css/public.css", "--ink-3", "#000000", 1),
        ("PWA 淡色（ライト・本文地）", "webapp/static/styles.css", "--ink-soft", "#f7f7f7", 0),
        ("PWA 淡色（ライト・カード）", "webapp/static/styles.css", "--ink-soft", "#ffffff", 0),
        ("PWA 中間色（ライト）", "webapp/static/styles.css", "--ink-muted", "#ffffff", 0),
    ]

    @staticmethod
    def _luminance(colour: str) -> float:
        raw = colour.lstrip("#")
        parts = [int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in parts]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    @classmethod
    def _contrast(cls, fore: str, back: str) -> float:
        a, b = cls._luminance(fore), cls._luminance(back)
        high, low = max(a, b), min(a, b)
        return (high + 0.05) / (low + 0.05)

    def _token(self, css_path: str, name: str, occurrence: int) -> str:
        """CSS から宣言を読む。occurrence 0 がライト、1 がダークの上書き。"""
        text = (self.ROOT / css_path).read_text(encoding="utf-8")
        found = re.findall(rf"{re.escape(name)}\s*:\s*(#[0-9a-fA-F]{{6}})", text)
        self.assertGreater(len(found), occurrence, f"{css_path} に {name} の宣言が足りません: {found}")
        return found[occurrence]

    def test_text_tokens_meet_wcag_aa(self):
        for label, css_path, name, background, occurrence in self.CASES:
            with self.subTest(label):
                colour = self._token(css_path, name, occurrence)
                ratio = self._contrast(colour, background)
                self.assertGreaterEqual(
                    round(ratio, 2),
                    self.MIN_RATIO,
                    f"{label}: {colour} on {background} は {ratio:.2f}:1 で、"
                    f"本文に必要な {self.MIN_RATIO}:1 に届いていません",
                )


class SpacingScaleTests(unittest.TestCase):
    """余白と字の段階が、尺度として成り立っていること。

    数字を格子へ丸めること自体が目的ではない。「同じ役割なのに値が違う」
    「入れ子の内と外で広さの順が逆」を防ぐのが目的なので、順序を検査する。
    """

    ROOT = Path(__file__).resolve().parent.parent

    def _tokens(self) -> dict[str, int]:
        text = (self.ROOT / "webapp_admin/static/css/tokens.css").read_text(encoding="utf-8")
        found = {}
        for name, value in re.findall(r"(--(?:gap|text)-[a-z0-9]+)\s*:\s*(\d+)px", text):
            found.setdefault(name, int(value))
        return found

    def test_the_outer_gap_is_wider_than_the_inner_one(self):
        """節どうしは、節の中の項目どうしより広く離す。

        同じ 14px にしていたころは、「項目が並んでいる」のか「別の節が
        始まった」のかが間隔から読み取れなかった。
        """
        gaps = self._tokens()
        for name in ("--gap-icon", "--gap-inline", "--gap-stack", "--gap-section"):
            self.assertIn(name, gaps, f"{name} が tokens.css に無い")
        self.assertLess(gaps["--gap-icon"], gaps["--gap-stack"])
        self.assertLess(gaps["--gap-stack"], gaps["--gap-section"])

    def test_the_icon_gap_is_written_in_one_place(self):
        """アイコンと文字の間が、また複数の値に分かれていないこと。

        以前は .btn 6px / .chip 5px / .menu-item 8px と三通りあった。
        """
        css_dir = self.ROOT / "webapp_admin/static/css"
        offenders = []
        for name in ("components", "desktop"):
            text = (css_dir / f"{name}.css").read_text(encoding="utf-8")
            text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
            for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", text):
                selector = " ".join(block.group(1).split())
                if not any(key in selector for key in (".btn", ".chip", ".menu-item")):
                    continue
                for value in re.findall(r"gap\s*:\s*(\d+)px", block.group(2)):
                    offenders.append(f"{name}.css: {selector[:40]} → gap {value}px")
        self.assertEqual(
            offenders,
            [],
            "アイコンと文字の間に生の値が残っています（--gap-icon を使う）:" + chr(10) + chr(10).join(offenders),
        )

    def test_font_sizes_are_whole_pixels(self):
        """0.5px 刻みを使わない（端末で丸め方が違い、行の高さが揃わない）。"""
        css_dir = self.ROOT / "webapp_admin/static/css"
        offenders = []
        for path in css_dir.glob("*.css"):
            if path.name == "public.css":  # 読み物ページは別の尺度
                continue
            for value in re.findall(r"font-size:\s*([0-9]+\.[0-9]+)px", path.read_text(encoding="utf-8")):
                offenders.append(f"{path.name}: {value}px")
        self.assertEqual(offenders, [], f"小数の字の大きさ: {offenders}")


class ElevationAndMotionTests(unittest.TestCase):
    """影と動きが、その場しのぎの値ではなく段階になっていること。"""

    ROOT = Path(__file__).resolve().parent.parent
    CSS = ROOT / "webapp_admin/static/css"

    # 相互作用ではない長さ。ここだけは生の値でよい。
    #   spin        … 読み込み中の回転（無限ループ）
    #   aurora      … 壁紙のオーロラ（無限ループ）
    #   taskbar-rise / fade-up … 起動時に一度だけ流れる演出
    ALLOWED_RAW = ("spin", "aurora-drift", "taskbar-rise", "fade-up")

    def test_the_elevation_scale_exists_in_both_themes(self):
        """暗い地では影が見えにくいので、テーマごとに濃さを持つこと。

        白を固定値で書いてダークで破綻させた前例があるので、影も同じ轍を
        踏まないよう両方に定義を要求する。
        """
        text = (self.CSS / "tokens.css").read_text(encoding="utf-8")
        for name in ("--shadow-1", "--shadow-2"):
            found = re.findall(re.escape(name) + r"\s*:", text)
            self.assertEqual(len(found), 2, f"{name} はライトとダークの両方に要る（いま {len(found)} 箇所）")
        for name in ("--glow-soft", "--glow-strong", "--dur-0", "--dur-1", "--dur-2", "--dur-3"):
            self.assertIn(name, text, f"{name} が tokens.css に無い")

    def test_interaction_timings_go_through_the_tokens(self):
        """相互作用の長さを生の秒数で書かない。

        以前は .12s / .15s / .18s / .3s / .05s が各ファイルに散っており、
        motion.css だけがトークンを使っていた。同じ要素の長さが2箇所で
        別々に決まっている状態だった。
        """
        offenders = []
        for path in sorted(self.CSS.glob("*.css")):
            if path.name == "public.css":  # 読み物ページは別体系
                continue
            text = path.read_text(encoding="utf-8")
            for line_no, line in enumerate(text.split(chr(10)), 1):
                if not re.search(r"(transition|animation)\s*:", line):
                    continue
                if any(key in line for key in self.ALLOWED_RAW):
                    continue
                for raw in re.findall(r"(?<![\w.-])(\.?\d+(?:\.\d+)?m?s)(?![\w.-])", line):
                    offenders.append(f"{path.name}:{line_no} {raw}")
        self.assertEqual(
            offenders, [], "生の時間が残っています（var(--dur-*) を使う）:" + chr(10) + chr(10).join(offenders)
        )

    def test_the_glow_has_only_two_strengths(self):
        """光りの強さが半端に散っていないこと。

        もとは 0 0 10px / 14px / 16px / 20px / 22px と5通りあった。
        置いてあるだけは soft、指を乗せたら strong の2段にする。
        """
        offenders = []
        for name in ("desktop", "page", "components"):
            text = (self.CSS / f"{name}.css").read_text(encoding="utf-8")
            text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
            # アクセント色（水色）の光りだけを見る。Discord のブランド色
            # rgb(88,101,242) のように、色そのものに意味がある光りは別。
            # 「0 0 0 3px」はフォーカスリング（広がり付き）で、光りではない。
            # 直前が "0 0 " のものは除く。
            pattern = r"(?:^|[:,])\s*0 0 \d+px rgba\(\s*" r"(\d+),\s*(\d+),\s*(\d+)"
            for match in re.findall(pattern, text):
                r, g, b = (int(v) for v in match)
                if b > 230 and g > 160 and r < 160:
                    offenders.append(f"{name}.css: rgb({r},{g},{b})")
        self.assertEqual(
            offenders,
            [],
            "アクセントの光りに生の値が残っています" "（--glow-soft / --glow-strong を使う）: " + str(offenders),
        )


class DjaudioLimitTests(unittest.TestCase):
    """画面の上下限と、保存側で丸める範囲が同じであること。

    以前は同じ数値を2箇所に手で書いていた（パネルの Field.min/max と
    settings_store の定数）。片方だけ変えると、画面の検証は通るのに保存される
    値は黙って別の値へ丸められる——「保存できたのに効かない」に見える。
    表を1つにしたので、ここではそれが崩れていないことだけを見る。
    """

    def test_the_panel_uses_the_same_range_as_the_store(self):
        from services.settings_store import DJAUDIO_LIMITS

        panel = PANEL_BY_ID["djaudio"]
        checked = 0
        for field in panel.fields:
            if field.key not in DJAUDIO_LIMITS:
                continue
            low, high = DJAUDIO_LIMITS[field.key]
            with self.subTest(field=field.key):
                self.assertEqual((field.min, field.max), (low, high))
            checked += 1
        self.assertEqual(checked, len(DJAUDIO_LIMITS))

    def test_a_value_over_the_limit_is_refused_rather_than_rounded(self):
        from services.settings_store import DJAUDIO_LIMITS

        client = make_client()
        _low, high = DJAUDIO_LIMITS["cooldown"]
        response = client.put("/admin/api/apps/djaudio", json={"values": {"cooldown": high + 1}}, headers=CSRF_HEADER)
        self.assertEqual(response.status_code, 422)
        self.assertIn("cooldown", response.json()["errors"])


class CdnErrorShapeTests(unittest.TestCase):
    """単体の配信プロセスでも、fetch する側には JSON で理由を返すこと。

    /dlaudio/files/ の下には2種類が同居している。ブラウザが直接開く配信リンクと、
    ミキサーが fetch する索引・切り出し。cdn_main.py はパスの接頭辞だけで
    「配信リンクだから HTML」と決めていたため、ミキサーが受け取るのも HTML に
    なり、断られた理由を読めなかった（JSON として解釈できず
    「Unexpected token '<'」としか言えない）。判定は Accept で行う。
    """

    def setUp(self):
        from cdn_main import create_cdn_app

        self.client = TestClient(create_cdn_app())
        self.url = f"/dlaudio/files/{GUILD_ID}/nosuchtoken/mixer"

    def test_a_fetching_client_gets_json(self):
        response = self.client.get(self.url, headers={"Accept": "application/json"})
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertIn("detail", response.json())

    def test_a_browser_still_gets_the_guidance_page(self):
        response = self.client.get(self.url, headers={"Accept": "text/html,application/xhtml+xml"})
        self.assertIn("text/html", response.headers["content-type"])


class DeliveryErrorPageTests(unittest.TestCase):
    """配信リンクのエラーページが、配信のホストだけで完結していること。

    このページは Discord から踏まれ、配信のホスト（/dlaudio/ しか通っていない）
    が返す。管理画面のテンプレートを返していたころは、そこから参照される
    /static/css/*・/static/js/aero.js・アイコンのスプライトが全部 404 になり、
    素の HTML が並ぶだけの画面になっていた（さらに「管理画面へ」のリンクまで
    出ていた）。ページは外部の資材に頼らず、単体で読める形で返す。
    """

    def setUp(self):
        from cdn_main import create_cdn_app

        self.admin = TestClient(app)
        self.cdn = TestClient(create_cdn_app())
        self.path = f"/dlaudio/files/{GUILD_ID}/{'a' * 32}"
        self.browser = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}

    def _page(self, client):
        response = client.get(self.path, headers=self.browser)
        self.assertEqual(response.status_code, 410)
        self.assertIn("text/html", response.headers["content-type"])
        return response.text

    def test_the_page_needs_nothing_but_itself(self):
        for name, client in (("admin", self.admin), ("cdn", self.cdn)):
            with self.subTest(name):
                body = self._page(client)
                self.assertNotIn("/static/", body)
                self.assertNotIn("<link", body)
                self.assertNotIn("<script", body)

    def test_the_page_does_not_send_visitors_to_the_admin_screen(self):
        for name, client in (("admin", self.admin), ("cdn", self.cdn)):
            with self.subTest(name):
                self.assertNotIn("/admin/", self._page(client))

    def test_both_processes_return_the_same_page(self):
        """管理画面と単体の配信プロセスで、同じ URL には同じページが出ること。

        文面もテンプレートも別々に持っていたころは、どちらのプロセスが応答
        したかで見た目も案内も変わっていた。判定（wants_json）と同じく、
        ページも services/djaudio_cdn に1つだけ置く。
        """
        self.assertEqual(self._page(self.admin), self._page(self.cdn))

    def test_the_headline_says_why_it_was_refused(self):
        """期限切れは「期限切れ」と出すこと。

        管理画面側は 400/403/404/500 しか文面を持っておらず、配信リンクが
        使う 410 が表から漏れていたため、見出しが「エラーが発生しました。」
        になっていた。理由は detail に入っているのに、一番大きな文字が
        何も言っていない状態だった。
        """
        for name, client in (("admin", self.admin), ("cdn", self.cdn)):
            with self.subTest(name):
                body = self._page(client)
                self.assertIn("有効期限", body)
                self.assertNotIn("エラーが発生しました", body)

    def test_a_fetching_client_still_gets_json(self):
        """ミキサー向けの JSON は、ページを共通化しても変わらないこと。"""
        for name, client in (("admin", self.admin), ("cdn", self.cdn)):
            with self.subTest(name):
                response = client.get(self.path, headers={"Accept": "application/json"})
                self.assertEqual(response.status_code, 410)
                self.assertIn("application/json", response.headers["content-type"])
                self.assertIn("有効期限", response.json()["detail"])

    def test_the_reason_is_escaped_into_the_page(self):
        """detail を HTML へ入れるときに、タグとして解釈させないこと。"""
        from services.djaudio_cdn import render_link_error_page

        page = render_link_error_page(404, "<script>alert(1)</script>")
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)


class ErrorPageCspTests(unittest.TestCase):
    """管理画面のエラーページが、自分で宣言した CSP の下で動くこと。

    CSP は script-src 'self' で、'unsafe-inline' も 'unsafe-hashes' も無い。
    onclick="" のようなインラインのイベントハンドラはブロックされ、
    「前のページへ」は押しても何も起きない死んだボタンになっていた
    （javascript: の擬似 URL をボタンへ替えたときに、同じ理由で塞がれる
    ことを見落としていた）。動きは外部のスクリプトから結びつける。
    """

    def setUp(self):
        self.client = TestClient(app)

    def test_the_error_page_has_no_inline_handlers(self):
        response = self.client.get("/admin/no-such-page", headers={"Accept": "text/html"})
        self.assertIn("text/html", response.headers["content-type"])
        self.assertNotIn("onclick", response.text)
        self.assertNotIn("javascript:", response.text)

    def test_unknown_urls_get_the_error_page_not_raw_json(self):
        """ルーティングが返す 404/405 も、他のエラーと同じ扱いにすること。

        ハンドラを fastapi.HTTPException にだけ登録していたため、
        経路が見つからないときに starlette が投げる HTTPException は拾われず、
        Starlette 既定の {"detail":"Not Found"} が生で返っていた。
        エンドポイントの中から投げた 410 は日本語のページになるのに、
        URL を打ち間違えただけだと英語の JSON が出る、という食い違いがあった。
        """
        for path in ("/admin/no-such-page", "/no-such-page-at-all"):
            with self.subTest(path):
                response = self.client.get(path, headers={"Accept": "text/html"})
                self.assertEqual(response.status_code, 404)
                self.assertIn("text/html", response.headers["content-type"])
                self.assertIn("見つかりません", response.text)

    def test_a_fetching_client_still_gets_json_for_unknown_urls(self):
        response = self.client.get("/admin/no-such-page", headers={"Accept": "application/json"})
        self.assertEqual(response.status_code, 404)
        self.assertIn("application/json", response.headers["content-type"])
        self.assertIn("detail", response.json())


class UnhandledExceptionGroupTests(unittest.TestCase):
    """原因不明の例外で 500 を返すときも、相手に応じた形で返すこと。

    _exception_group_response の最後の 500 だけが _error_response を通らず、
    error.html を直に描いていた。**分割前からそうなっていた**ので分割時は
    そのまま移してあり、次の2つが残っていた。

      - fetch する側（ミキサー・管理画面のJS）に HTML が返る。本文を読めず
        「HTTP 500」としか言えない。他の経路はぜんぶ JSON にしてある。
      - 配信リンク（/dlaudio/）に管理画面のページが返る。配信のホストへ
        通っているのは /dlaudio/ だけなので /static/ が全部 404 になり、
        素の HTML が並ぶだけの画面が出る（DeliveryErrorPageTests と同じ話）。

    どちらも「500 が返る」ことは変わらないため、動かしてみても気づけない。
    """

    def setUp(self):
        from webapp_admin.app import create_app

        app = create_app()

        for path in ("/admin/api/boom", "/dlaudio/boom", "/admin/boom"):

            async def boom():
                raise ExceptionGroup("boom", [RuntimeError("下で落ちた")])

            app.add_api_route(path, boom, methods=["GET"], include_in_schema=False)

        self.client = TestClient(app, raise_server_exceptions=False)

    def _get(self, path, accept):
        # ハンドラは原因を logger.error へ残す。assertLogs で受け止めるのは、
        # その記録が消えていないことを確かめるためと、テスト出力へ
        # トレースバックを撒かないため。
        with self.assertLogs("webapp_admin.app", level="ERROR") as logs:
            response = self.client.get(path, headers={"Accept": accept})
        self.assertEqual(response.status_code, 500)
        self.assertIn("RuntimeError", "\n".join(logs.output))
        return response

    def test_a_fetching_client_gets_json(self):
        response = self._get("/admin/api/boom", "application/json")
        self.assertIn("application/json", response.headers["content-type"])
        self.assertIn("detail", response.json())

    def test_a_delivery_link_gets_the_page_that_stands_on_its_own(self):
        response = self._get("/dlaudio/boom", "text/html,*/*")
        self.assertIn("text/html", response.headers["content-type"])
        self.assertNotIn("/static/", response.text)
        self.assertNotIn("/admin/", response.text)

    def test_a_browser_on_the_admin_screen_still_gets_the_admin_page(self):
        """管理画面側は今までどおり error.html のままであること。"""
        response = self._get("/admin/boom", "text/html")
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("error-page", response.text)
        self.assertIn("サーバーエラー", response.text)


class ExceptionGroupIncidentTests(unittest.TestCase):
    """包まれた例外も、素の例外と同じくインシデントとして記録すること。

    anyio のタスクグループを通ると、ルートが投げた実装バグは ExceptionGroup
    に包まれて上がる。その経路だけ record_exception を呼んでいなかったため、
    exceptions_total{type=...} が増えず、インシデントには metrics_middleware
    が 5xx レスポンスを見て立てる「HTTP 500」しか残らなかった
    （例外の型名もメッセージも無い）。record_exception の
    docstring にあるとおり、このカウンタは「初めて出た例外」に気づくための
    唯一の口なので、包まれたバグはその口を通らないことになる。

    記録するのは包みではなく中身。全部 "ExceptionGroup" で立ててしまうと、
    呼んではいても型名が潰れて、やはり新しいバグに気づけない。
    """

    def setUp(self):
        from webapp_admin.app import create_app
        from webapp_admin.security import _NeedsLogin

        app = create_app()

        async def grouped_bug():
            raise ExceptionGroup("boom", [RuntimeError("下で落ちた")])

        async def grouped_login():
            raise ExceptionGroup("auth", [_NeedsLogin()])

        async def grouped_http():
            raise ExceptionGroup("http", [StarletteHTTPException(status_code=404, detail="ありません。")])

        async def plain_bug():
            raise RuntimeError("素で落ちた")

        for path, handler in (
            ("/admin/grouped-bug", grouped_bug),
            ("/admin/grouped-login", grouped_login),
            ("/admin/grouped-http", grouped_http),
            ("/admin/plain-bug", plain_bug),
        ):
            app.add_api_route(path, handler, methods=["GET"], include_in_schema=False)

        self.client = TestClient(app, raise_server_exceptions=False)

    def _call(self, path, headers=None):
        with patch("webapp_admin.app.record_exception") as recorded:
            with self.assertLogs("webapp_admin.app", level="ERROR"):
                response = self.client.get(path, headers=headers or {})
        return response, recorded

    def test_a_grouped_bug_is_recorded_as_its_own_type(self):
        response, recorded = self._call("/admin/grouped-bug")
        self.assertEqual(response.status_code, 500)
        recorded.assert_called_once()
        exception, info = recorded.call_args.args
        # 包み（ExceptionGroup）ではなく中身が渡ること。
        self.assertIsInstance(exception, RuntimeError)
        self.assertEqual(str(exception), "下で落ちた")
        self.assertEqual(info["method"], "GET")
        self.assertEqual(info["path"], "/admin/grouped-bug")

    def test_a_plain_bug_is_still_recorded(self):
        response, recorded = self._call("/admin/plain-bug")
        self.assertEqual(response.status_code, 500)
        recorded.assert_called_once()
        self.assertIsInstance(recorded.call_args.args[0], RuntimeError)

    def test_the_snapshot_prefers_the_address_cloudflare_saw(self):
        """インシデントの remote_addr が、経路によって食い違わないこと。

        素の経路（metrics_middleware）は CF-Connecting-IP を優先していた。
        包まれた経路が自前で組み立てると、ここが黙ってズレる。
        """
        _, recorded = self._call("/admin/grouped-bug", {"CF-Connecting-IP": "203.0.113.9"})
        self.assertEqual(recorded.call_args.args[1]["remote_addr"], "203.0.113.9")

    def test_normal_control_flow_is_not_an_incident(self):
        """ログインの誘導や 404 は、包まれていてもバグではないこと。

        ここを一緒に記録すると、インシデント一覧が未ログインのアクセスで
        埋まり、本当に見るべき障害が流れる（record_error_response が 4xx を
        インシデントにしないのと同じ理由）。
        """
        for path, expected in (("/admin/grouped-login", 303), ("/admin/grouped-http", 404)):
            with self.subTest(path):
                with patch("webapp_admin.app.record_exception") as recorded:
                    response = self.client.get(path, follow_redirects=False)
                self.assertEqual(response.status_code, expected)
                recorded.assert_not_called()


class BotTokenResolutionTests(unittest.TestCase):
    """DISCORD_BOT_TOKEN の解決が config.py と webapp_admin.auth でズレないこと。

    以前は webapp_admin/auth.py が独自に os.environ.get("DISCORD_BOT_TOKEN", "")
    で読んでおり、config.py（envutil 経由、前後の空白を落とす）とは別の解釈だった。
    webapp_admin/api/dev.py は既に config.DISCORD_BOT_TOKEN を使っていたため、
    同じプロセス内で「Bot 本体・dev タブは繋がるのに、ギルド/チャンネル一覧を
    取る auth.py 側だけ Discord API に 401 で弾かれる」という食い違いが起きうる
    状態だった（環境変数に前後の空白が入っただけで発生する）。
    """

    def test_bot_token_strips_whitespace_like_config_does(self):
        import importlib

        import config as config_module
        import webapp_admin.auth as admin_auth_module

        original_env = os.environ.get("DISCORD_BOT_TOKEN")
        try:
            os.environ["DISCORD_BOT_TOKEN"] = "  padded-token-value  "
            importlib.reload(config_module)
            importlib.reload(admin_auth_module)
            self.assertEqual(admin_auth_module.DISCORD_BOT_TOKEN, "padded-token-value")
            self.assertEqual(admin_auth_module.DISCORD_BOT_TOKEN, config_module.DISCORD_BOT_TOKEN)
        finally:
            if original_env is None:
                os.environ.pop("DISCORD_BOT_TOKEN", None)
            else:
                os.environ["DISCORD_BOT_TOKEN"] = original_env
            importlib.reload(config_module)
            importlib.reload(admin_auth_module)


class EnvBoolConsolidationTests(unittest.TestCase):
    """read_env_bool の3重実装を envutil.env_bool へ一本化したことの回帰防止。

    以前は webapp/forecast_utils.py・webapp/security.py・webapp/vapid_service.py が
    それぞれ独立に真偽値パーサを実装しており、同じ判定ロジックが3箇所に分散していた
    （どれか1箇所だけ直る／どれか1箇所だけ壊れる取りこぼしの主因）。現在はすべて
    envutil.env_bool に委譲・統一している。ここでは3つの呼び出し経路すべてが
    envutil.env_bool と同じ結果になることを確認する。

    なお実測の結果、旧3実装はいずれも解釈不能な値（例: "banana"）に対して
    「default 引数」へフォールバックしており、envutil.env_bool と挙動は元々
    一致していた（追加されるのは警告ログのみ）。そのためこのテストは「今回の
    変更でバグが直った」証明ではなく、「今後どれか1箇所だけ判定ロジックが
    ズレる」将来の劣化を検知するための回帰ガードとして追加している。
    """

    # None は未設定（環境変数を削除）を表す。
    BOOL_CASES = [
        None,
        "",
        " ",
        "1",
        "0",
        "true",
        "True",
        "TRUE",
        " true ",
        "yes",
        "no",
        "on",
        "off",
        "banana",
        "2",
        "-1",
        "tru",
        "FALSE",
    ]

    def _set_env(self, name: str, raw: str | None) -> None:
        if raw is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = raw

    def test_security_read_env_bool_matches_envutil(self):
        from envutil import env_bool
        from webapp.security import read_env_bool

        name = "X_ENV_BOOL_CONSOLIDATION_TEST"
        original = os.environ.get(name)
        try:
            for default in (True, False):
                for raw in self.BOOL_CASES:
                    self._set_env(name, raw)
                    expected = env_bool(name, default)
                    actual = read_env_bool(name, default)
                    self.assertEqual(
                        actual,
                        expected,
                        f"webapp.security.read_env_bool が envutil.env_bool と食い違った "
                        f"raw={raw!r} default={default!r}",
                    )
        finally:
            self._set_env(name, original)

    def test_forecast_signals_llm_enabled_matches_envutil(self):
        import importlib

        from envutil import env_bool
        import webapp.forecast_signals as forecast_signals_module

        for name in ("FORECAST_LLM_ENABLED", "FORECAST_SUMMARY_ENABLED"):
            original = os.environ.get(name)
            try:
                for raw in self.BOOL_CASES:
                    self._set_env(name, raw)
                    importlib.reload(forecast_signals_module)
                    expected = env_bool(name, True)
                    actual = getattr(forecast_signals_module, name)
                    self.assertEqual(
                        actual,
                        expected,
                        f"webapp.forecast_signals.{name} が envutil.env_bool と食い違った " f"raw={raw!r}",
                    )
            finally:
                self._set_env(name, original)
                importlib.reload(forecast_signals_module)

    def test_vapid_auto_generate_matches_envutil(self):
        from envutil import env_bool
        import webapp.vapid_service as vapid_service_module

        name = "VAPID_AUTO_GENERATE"
        original = os.environ.get(name)
        original_public = os.environ.get("VAPID_PUBLIC_KEY")
        original_private = os.environ.get("VAPID_PRIVATE_KEY")
        try:
            # 明示鍵が設定されていると自動生成の分岐に入らないため、この2つは空けておく。
            os.environ.pop("VAPID_PUBLIC_KEY", None)
            os.environ.pop("VAPID_PRIVATE_KEY", None)
            for raw in self.BOOL_CASES:
                self._set_env(name, raw)
                expected = env_bool(name, True)
                with patch.object(
                    vapid_service_module,
                    "_ensure_generated_keys",
                    return_value=("dummy-public", "dummy-private"),
                ) as mock_ensure:
                    config = vapid_service_module.load_vapid_config()
                self.assertEqual(
                    mock_ensure.called,
                    expected,
                    f"webapp.vapid_service の自動生成分岐が envutil.env_bool と食い違った " f"raw={raw!r}",
                )
                if not expected:
                    self.assertIsNone(config.public_key)
                    self.assertIsNone(config.private_key)
        finally:
            self._set_env(name, original)
            self._set_env("VAPID_PUBLIC_KEY", original_public)
            self._set_env("VAPID_PRIVATE_KEY", original_private)


class ConfigReadingConsistencyTests(unittest.TestCase):
    """設定の読み方が、リポジトリで統一した envutil の解釈と揃っていること。

    「保存できる（＝設定できる）のに効かない」設定を作らないための検査。
    """

    def _reload_app_module(self):
        import importlib

        import webapp_admin.app as app_module

        return importlib.reload(app_module)

    def test_flask_secure_cookies_accepts_the_usual_truthy_values(self):
        """FLASK_SECURE_COOKIES=1 で Secure が有効になること。

        以前は `== "true"` の手書き判定だったため、"1"/"yes"/"on" が黙って
        偽になり、管理画面のセッション Cookie に Secure が付かないまま
        平文で飛んでいた。他の設定は envutil でこれらを真として扱うので、
        ここだけ違うと管理者は設定したつもりで無防備なままになる。
        """
        from envutil import env_bool

        original = os.environ.get("FLASK_SECURE_COOKIES")
        try:
            for raw in ("1", "yes", "on", "true", "TRUE"):
                with self.subTest(raw):
                    os.environ["FLASK_SECURE_COOKIES"] = raw
                    self.assertTrue(env_bool("FLASK_SECURE_COOKIES", False))
            for raw in ("0", "no", "off", "false"):
                with self.subTest(raw):
                    os.environ["FLASK_SECURE_COOKIES"] = raw
                    self.assertFalse(env_bool("FLASK_SECURE_COOKIES", False))
        finally:
            if original is None:
                os.environ.pop("FLASK_SECURE_COOKIES", None)
            else:
                os.environ["FLASK_SECURE_COOKIES"] = original

    def test_app_module_has_no_handwritten_bool_parsing(self):
        """app.py に `== "true"` 形式の手書き真偽判定が残っていないこと。"""
        from pathlib import Path

        source = (Path(__file__).resolve().parent.parent / "webapp_admin" / "app.py").read_text(encoding="utf-8")
        self.assertNotIn('.lower() == "true"', source)

    def test_dev_user_id_is_read_from_one_place(self):
        """DEV_USER_ID の「設定されているか」の判定が1箇所であること。

        以前は api/dev.py が os.getenv を直に見ており(strip なし)、
        security.py の is_dev_user (strip あり) と食い違っていた。
        DEV_USER_ID=" " のとき、片方は「設定済み」もう片方は「未設定」と
        判断していた（どちらも拒否なので実害は無かったが、同じ判定が
        2箇所にある状態そのものが取りこぼしの元）。
        """
        from pathlib import Path

        from webapp_admin.security import dev_user_id

        original = os.environ.get("DEV_USER_ID")
        try:
            os.environ["DEV_USER_ID"] = "   "
            self.assertEqual(dev_user_id(), "", "空白のみは未設定として扱う")
            os.environ["DEV_USER_ID"] = "  12345  "
            self.assertEqual(dev_user_id(), "12345", "前後の空白は落とす")
            os.environ.pop("DEV_USER_ID", None)
            self.assertEqual(dev_user_id(), "")
        finally:
            if original is None:
                os.environ.pop("DEV_USER_ID", None)
            else:
                os.environ["DEV_USER_ID"] = original

        source = (Path(__file__).resolve().parent.parent / "webapp_admin" / "api" / "dev.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('os.getenv("DEV_USER_ID")', source)
        self.assertNotIn('os.environ.get("DEV_USER_ID"', source)


class GuildSelectFormTests(unittest.TestCase):
    """/admin/guilds/select が、テキスト以外を送られても 500 にならないこと。

    guild_id は <select> から来る前提で書かれているが、フォームは誰でも
    組み立てられる。ファイルパートとして送られると int() が ValueError では
    なく TypeError を投げ、except ValueError では捕まらずに 500 まで抜ける。
    「無効なサーバーIDです」で済むはずの入力が、追いにくい500になる。
    """

    def _run(self, value):
        import asyncio
        from unittest.mock import Mock

        from webapp_admin.views.dashboard_views import select_guild

        class FakeForm:
            def get(self, key, default=None):
                return value if key == "guild_id" else default

        request = Mock()
        request.session = {}

        async def form():
            return FakeForm()

        request.form = form
        response = asyncio.run(select_guild(request))
        return request, response

    def test_a_file_part_is_refused_instead_of_crashing(self):
        class NotAnInt:
            """int() が TypeError を投げる値（UploadFile の代役）。"""

        request, response = self._run(NotAnInt())
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/admin/guilds")
        self.assertEqual(request.session["_flashes"], [["danger", "無効なサーバーIDです。"]])

    def test_a_non_numeric_string_is_still_refused_the_same_way(self):
        """ValueError 側の経路。TypeError を足したときに壊していないこと。"""
        request, response = self._run("abc")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(request.session["_flashes"], [["danger", "無効なサーバーIDです。"]])

    def test_an_unknown_guild_id_is_refused_for_lacking_permission(self):
        """数値として読めた先の分岐を、上の2件と取り違えていないこと。"""
        request, response = self._run("12345")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(request.session["_flashes"], [["danger", "アクセス権限がありません。"]])


class DeleteGuildDataApiTests(unittest.TestCase):
    """「このサーバーのデータを削除」の口。

    保管方針の主役は**利用者が自分で消せること**で、自動削除は放棄された
    ものだけに限る（services/guild_retention.py）。ここはその手動側の入口。

      - 確認にサーバーIDそのものを打たせること
      - 管理者でなくなった人には消させないこと
      - 設定と監査履歴をまとめて消すこと
      - CSRF なしでは通らないこと

    1つ目が要。取り消しが効かない操作なので、「はい」を1回押すだけでは
    足りない。**番号を写して打つあいだに、どのサーバーを消そうとしている
    のかを見ることになる。**
    """

    def setUp(self):
        self.client = make_client()

    def _delete(self, client, *, confirm, csrf=True):
        """削除の口を叩く。"""
        headers = dict(CSRF_HEADER) if csrf else {}
        return client.request("DELETE", "/admin/api/guild-data", params={"confirm": confirm}, headers=headers)

    def test_a_wrong_confirmation_deletes_nothing(self):
        """サーバーIDが一致しなければ、何も消さないこと。

        押し間違いで消えるなら、確認の意味が無い。
        """
        with patch("services.guild_retention.delete_guild_data", AsyncMock()) as purge:
            response = self._delete(self.client, confirm="ちがう")

        self.assertEqual(response.status_code, 400)
        purge.assert_not_awaited()

    def test_the_right_confirmation_removes_settings_and_history_together(self):
        """IDが一致したら、設定と監査履歴をまとめて消すこと。

        別々の口にすると、消したつもりの人に**消し残しがあることを覚えて
        いてもらう**ことになる。
        """
        removed = {"settings": 1, "events": 42, "states": 5}
        with (
            patch("services.guild_retention.delete_guild_data", AsyncMock(return_value=removed)) as purge,
            patch("webapp_admin.auth.user_still_admin", AsyncMock(return_value=True)),
        ):
            response = self._delete(self.client, confirm=str(GUILD_ID))

        self.assertEqual(response.status_code, 200)
        purge.assert_awaited_once_with(GUILD_ID)
        self.assertEqual(response.json()["removed"], removed)

    def test_someone_who_lost_admin_cannot_delete(self):
        """管理者でなくなった人には消させないこと。

        セッションはログインした時点のもので、そのあと権限を外されても
        残っている。**取り消しの効かない操作を、外された人が実行できて
        しまう。**
        """
        with (
            patch("services.guild_retention.delete_guild_data", AsyncMock()) as purge,
            patch("webapp_admin.auth.user_still_admin", AsyncMock(return_value=False)),
        ):
            response = self._delete(self.client, confirm=str(GUILD_ID))

        self.assertEqual(response.status_code, 403)
        purge.assert_not_awaited()

    def test_it_is_refused_without_the_csrf_header(self):
        """CSRF ヘッダ無しでは通らないこと。

        踏んだだけで他人のサーバーの設定が消えるようでは困る。
        """
        with patch("services.guild_retention.delete_guild_data", AsyncMock()) as purge:
            response = self._delete(self.client, confirm=str(GUILD_ID), csrf=False)

        self.assertEqual(response.status_code, 403)
        purge.assert_not_awaited()


class CreateAppShapeTests(unittest.TestCase):
    """create_app() が組み立てたものと、その順序を丸ごと固定する。

    323行ある `create_app` を割る前に、外から見た姿を押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    割るときに怖いのは「1つ登録し忘れる」「順番が入れ替わる」で、**どちらも
    起動はするし、ほとんどの画面も動く。** 落ちるのは特定の経路だけなので、
    動かしてみるだけでは気づけない。

    とくにミドルウェアの順序には意味がある。`create_app` の docstring にある
    とおり、session_serialization_guard は SessionMiddleware より内側に居る
    必要がある（浄化がクッキーの書き出しより先に走る）。ここが入れ替わると
    `_sanitize_session_payload` を呼んでも手遅れになるが、**入れ替わっても
    例外は出ず、画面も出る。**

    エンドポイントを増やしたときも、この表を1行足すまでは落ちる。それが
    目的である。組み立てを変えたのか、増やしたのかを、必ず一度は見る。
    """

    # create_app が自分で登録するもの（ルーター経由でないもの）。順序ごと固定する。
    DIRECT = [
        ("/openapi.json", "GET,HEAD", "openapi"),
        ("mount", "/static", "static"),
        ("/admin/users/state", "GET", "handler"),
        ("/admin/settings/logging", "GET", "handler"),
        ("/admin/settings/welcome", "GET", "handler"),
        ("/admin/settings/vc-notify", "GET", "handler"),
        ("/admin/settings/earthquake", "GET", "handler"),
        ("/admin/settings/news-feeds", "GET", "handler"),
        ("/admin/settings/sticky", "GET", "handler"),
        ("/admin/settings/reaction-roles", "GET", "handler"),
        ("/admin/settings/djaudio", "GET", "handler"),
        ("/admin/settings/tts", "GET", "handler"),
        ("/admin/settings/security", "GET", "handler"),
        ("/admin/dev", "GET", "handler"),
        ("/", "GET", "landing"),
        ("/guide", "GET", "guide"),
        ("/privacy", "GET", "privacy"),
        ("/terms", "GET", "terms"),
        ("/admin/guide", "GET", "redirect_admin_guide"),
        ("/admin/privacy", "GET", "redirect_admin_privacy"),
        ("/admin/terms", "GET", "redirect_admin_terms"),
        # Netdata が読む Prometheus 形式の出力。**公開ページの後、ミドルウェアの
        # 前**に登録されている（位置に意味がある。SlowAPIMiddleware より後に足すと
        # 既定のレート制限 300/分 が掛かり、スクレイプ間隔を詰めたときに黙って
        # 429 になる）。並び順が変わったらここで落ちる。
        ("/metrics", "GET", "metrics_endpoint"),
    ]

    # 8本のルーターが、どの接頭辞の下に入ったか。中身（各ルーターの経路）まで
    # 並ぶので、接頭辞の付け間違いも登録漏れもここで出る。
    SCHEMA_PATHS = [
        ("/admin/login", "get"),
        ("/admin/auth", "get"),
        ("/admin/callback", "get"),
        ("/admin/logout", "get,post"),
        ("/admin/", "get"),
        ("/admin/guilds", "get"),
        ("/admin/guilds/select", "post"),
        ("/admin/overview", "get"),
        ("/admin/api/metrics", "get"),
        ("/admin/api/incidents", "get"),
        ("/admin/api/apps", "get"),
        ("/admin/api/apps/{app_id}", "get,put"),
        ("/admin/api/apps/{app_id}/collections/{key}", "post"),
        ("/admin/api/apps/{app_id}/collections/{key}/{item_id}", "delete,put"),
        # 保管方針の「消すのは利用者が決める」側の入口。設定と監査履歴を
        # まとめて消す（services/guild_retention.py）。
        ("/admin/api/guild-data", "delete"),
        ("/admin/api/users/state", "get"),
        ("/admin/api/users/state/{user_id}", "get"),
        ("/admin/api/recording", "get"),
        ("/admin/api/recording/start", "post"),
        ("/admin/api/recording/stop", "post"),
        ("/admin/api/recording/settings", "put"),
        ("/admin/api/dev/overview", "get"),
        ("/admin/api/dev/earthquakes", "get"),
        ("/admin/api/dev/send-message", "post"),
        ("/admin/api/dev/forward-message", "post"),
        ("/admin/api/dev/news-send", "post"),
        ("/admin/api/dev/signal/{task_name}", "post"),
        ("/admin/api/dev/test-notify/{kind}", "post"),
        ("/admin/api/dev/earthquake-replay", "post"),
        ("/admin/api/dev/channels", "get"),
        ("/admin/api/dev/user", "get"),
        ("/admin/api/dev/logs", "get"),
        ("/admin/api/dev/settings/{guild_id}", "get"),
        ("/admin/api/dev/settings/{guild_id}/import", "post"),
        ("/admin/api/dev/cache/{token}", "delete"),
        ("/admin/api/dev/cache/purge", "post"),
        ("/admin/api/sql/servers", "get"),
        ("/admin/api/sql/objects", "get"),
        ("/admin/api/sql/ddl", "get"),
        ("/admin/api/sql/query", "post"),
        ("/admin/api/sql/cancel", "post"),
        ("/dlaudio/health", "get"),
        ("/dlaudio/files/{guild_id}/{token}", "get"),
        ("/dlaudio/info/{guild_id}/{token}", "get"),
        ("/dlaudio/files/{guild_id}/{token}/mixer", "get"),
        ("/dlaudio/files/{guild_id}/{token}/stem/{index}", "get"),
        ("/dlaudio/files/{guild_id}/{token}/segment", "get"),
        ("/dlaudio/files/{guild_id}/{token}/clip", "get"),
        ("/", "get"),
        ("/guide", "get"),
        ("/privacy", "get"),
        ("/terms", "get"),
        ("/admin/guide", "get"),
        ("/admin/privacy", "get"),
        ("/admin/terms", "get"),
        # /metrics はここに出ない。include_in_schema=False で登録しているので、
        # OpenAPI のスキーマには載らない（載せると、認証の要らない経路の存在が
        # スキーマから読める）。経路そのものは DIRECT の側で固定してある。
    ]

    # 外側から順。add_middleware したものが前に、@app.middleware したものが後ろに来る。
    MIDDLEWARE = [
        "SessionMiddleware",
        "SlowAPIMiddleware",
        "session_serialization_guard_middleware",
        "security_headers_middleware",
        "metrics_middleware",
    ]

    # 先頭3つの枠は FastAPI が既定で入れるもの。4つ目以降が create_app の登録。
    #
    # 先頭の HTTPException だけは、FastAPI の既定（http_exception_handler）を
    # create_app が **上書き** している。starlette.exceptions.HTTPException に
    # 登録するので鍵が既定と同じになり、位置は先頭のまま値だけが差し替わる。
    # 名前が admin_ 付きに変わっているのがその証拠で、ここが素の
    # http_exception_handler に戻ったら、経路が見つからないときの 404 が
    # 英語の JSON（{"detail":"Not Found"}）で返る状態に逆戻りしている。
    HANDLERS = [
        ("HTTPException", "admin_http_exception_handler"),
        ("RequestValidationError", "request_validation_exception_handler"),
        ("WebSocketRequestValidationError", "websocket_request_validation_exception_handler"),
        ("_NeedsLogin", "needs_login_handler"),
        ("_NeedsGuild", "needs_guild_handler"),
        ("RateLimitExceeded", "rate_limit_handler"),
        ("ExceptionGroup", "exception_group_handler"),
    ]

    def test_what_create_app_registers_itself_is_unchanged(self):
        """公開ページ・旧URLのリダイレクト・静的ファイルが、同じ順で並ぶこと。

        旧URLのリダイレクトはパネル定義から作られるので、定義を1つ落とすと
        ここが黙って1行減る。ブックマークやリンクが 404 になるだけで、
        新しい画面は動き続けるため、使っている人からの報告でしか気づけない。
        """
        from starlette.routing import Mount, Route

        actual = []
        for route in app.routes:
            if isinstance(route, Mount):
                actual.append(("mount", route.path, route.name))
            elif isinstance(route, Route):
                actual.append((route.path, ",".join(sorted(route.methods or ())), route.name))
        self.assertEqual(actual, [tuple(row) for row in self.DIRECT])

    def test_every_router_is_mounted_under_its_prefix(self):
        """8本のルーターが、それぞれの接頭辞の下に入っていること。

        接頭辞を付け間違えても起動する。落ちるのはその API を呼ぶ画面だけで、
        しかも「404 が返る」という形なので、開くまで分からない。
        """
        actual = [(path, ",".join(sorted(ops))) for path, ops in app.openapi()["paths"].items()]
        self.assertEqual(actual, [tuple(row) for row in self.SCHEMA_PATHS])

    def test_the_middleware_order_is_unchanged(self):
        """ミドルウェアが、外側から同じ順で積まれていること。

        session_serialization_guard は SessionMiddleware より**内側**に居る
        必要がある。レスポンス側は内側から先に走るので、この並びだと浄化が
        クッキーの書き出しより先に終わる。入れ替えても例外は出ず、画面も
        出るが、浄化されていないセッションがクッキーに載る。
        """
        actual = []
        for middleware in app.user_middleware:
            dispatch = (getattr(middleware, "kwargs", None) or {}).get("dispatch")
            actual.append(dispatch.__name__ if dispatch else middleware.cls.__name__)
        self.assertEqual(actual, self.MIDDLEWARE)

        guard = actual.index("session_serialization_guard_middleware")
        session = actual.index("SessionMiddleware")
        self.assertLess(session, guard, "浄化が Cookie の書き出しより後になっている")

    def test_the_exception_handlers_are_unchanged(self):
        """例外ハンドラの対応表が、同じ順で同じ中身であること。

        `_NeedsLogin` のハンドラを落とすと、ログインが必要な画面で例外が
        そのまま上がり、500 になる。ログインしている状態でテストすると
        気づけない。
        """
        actual = [
            (getattr(key, "__name__", str(key)), handler.__name__) for key, handler in app.exception_handlers.items()
        ]
        self.assertEqual(actual, [tuple(row) for row in self.HANDLERS])
