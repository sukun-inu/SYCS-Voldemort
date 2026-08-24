"""管理UIの API テスト。

    python -m unittest discover -s tests -t .

DB を必要とするユーザー状態監査は services 層を差し替えて検証する
（Postgres が無い環境でも API の契約を確認できるようにするため）。
標準ライブラリの unittest だけで動く。pytest からも実行できる。
"""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

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
from starlette.testclient import TestClient  # noqa: E402

from webapp_admin.app import app  # noqa: E402

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
        ids = [
            app_["id"]
            for group in make_client().get("/admin/api/apps").json()["groups"]
            for app_ in group["apps"]
        ]
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
        ok = self.dev.post("/admin/api/dev/test-notify/welcome",
                           json={"guild_id": "123456789012345678"}, headers=CSRF_HEADER)
        self.assertEqual(ok.status_code, 200)
        bad = self.dev.post("/admin/api/dev/test-notify/welcome",
                            json={"guild_id": "abc"}, headers=CSRF_HEADER)
        self.assertEqual(bad.status_code, 400)

    def test_notify_test_can_override_the_channel(self):
        """通知テストの設定を作っていないギルドでも、DEV専用にチャンネルを
        直接指定してテスト送信できること（地震リプレイと同じ抜け道）。

        シグナル名は test_<kind>。kind の一覧は services/dev_test_notify.py が持つ。"""
        from webapp_admin.api.dev import _SIGNAL_DIR

        bad_channel = self.dev.post(
            "/admin/api/dev/test-notify/welcome",
            json={"guild_id": str(GUILD_ID), "channel_id": "xyz"}, headers=CSRF_HEADER,
        )
        self.assertEqual(bad_channel.status_code, 400)

        ok = self.dev.post(
            "/admin/api/dev/test-notify/vc",
            json={"guild_id": str(GUILD_ID), "channel_id": "555"}, headers=CSRF_HEADER,
        )
        self.assertEqual(ok.status_code, 200)
        self.assertIn("555", ok.json()["message"])
        signal = json.loads((_SIGNAL_DIR / "test_vc.signal").read_text(encoding="utf-8"))
        self.assertEqual(signal["guild_id"], GUILD_ID)
        self.assertEqual(signal["channel_id"], 555)

        # チャンネル省略時は None（設定済みのチャンネルを使う、が既定のまま）
        no_channel = self.dev.post(
            "/admin/api/dev/test-notify/welcome",
            json={"guild_id": str(GUILD_ID)}, headers=CSRF_HEADER,
        )
        self.assertEqual(no_channel.status_code, 200)
        signal2 = json.loads((_SIGNAL_DIR / "test_welcome.signal").read_text(encoding="utf-8"))
        self.assertIsNone(signal2["channel_id"])

    def test_earthquake_replay_validates_the_payload(self):
        bad = self.dev.post("/admin/api/dev/earthquake-replay",
                            json={"event_json": "{}"}, headers=CSRF_HEADER)
        self.assertEqual(bad.status_code, 400)

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})
        ok = self.dev.post("/admin/api/dev/earthquake-replay",
                           json={"event_json": event}, headers=CSRF_HEADER)
        self.assertEqual(ok.status_code, 200)
        self.assertIn("eq_replay", ok.json()["pending_signals"])

    def test_earthquake_replay_can_target_a_single_guild(self):
        """全サーバーへの誤爆を避けるため、guild_id を指定した分だけに絞れること。

        シグナルは {"event": ..., "guild_id": ...} という封筒形式で書かれ、
        bot 側 (bot_setup.py) がここから対象ギルドを読み取る契約になっている。
        """
        from webapp_admin.api.dev import _SIGNAL_DIR

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})

        bad = self.dev.post("/admin/api/dev/earthquake-replay",
                            json={"event_json": event, "guild_id": "abc"}, headers=CSRF_HEADER)
        self.assertEqual(bad.status_code, 400)

        ok = self.dev.post("/admin/api/dev/earthquake-replay",
                           json={"event_json": event, "guild_id": str(GUILD_ID)}, headers=CSRF_HEADER)
        self.assertEqual(ok.status_code, 200)
        self.assertIn(str(GUILD_ID), ok.json()["message"])
        signal = json.loads((_SIGNAL_DIR / "eq_replay.signal").read_text(encoding="utf-8"))
        self.assertEqual(signal["guild_id"], GUILD_ID)
        self.assertIn("earthquake", signal["event"])

        # guild_id 省略時は全サーバー扱い（null）のまま、明示的に選べる状態を保つ
        all_guilds = self.dev.post("/admin/api/dev/earthquake-replay",
                                   json={"event_json": event}, headers=CSRF_HEADER)
        self.assertEqual(all_guilds.status_code, 200)
        signal2 = json.loads((_SIGNAL_DIR / "eq_replay.signal").read_text(encoding="utf-8"))
        self.assertIsNone(signal2["guild_id"])

    def test_earthquake_replay_can_override_the_channel(self):
        """地震アラート設定を持たないギルドでも、DEV専用にチャンネルを直接指定できること。"""
        from webapp_admin.api.dev import _SIGNAL_DIR

        event = json.dumps({"earthquake": {"hypocenter": {"name": "テスト沖"}}})

        # チャンネルIDだけ指定してギルドが無いのは拒否する
        # （どのギルドのチャンネルか定まらない）
        no_guild = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "channel_id": "555"}, headers=CSRF_HEADER,
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
        signal = json.loads((_SIGNAL_DIR / "eq_replay.signal").read_text(encoding="utf-8"))
        self.assertEqual(signal["guild_id"], GUILD_ID)
        self.assertEqual(signal["channel_id"], 555)

        # チャンネル省略時は None（地震アラート設定のチャンネルを使う、が既定のまま）
        no_channel = self.dev.post(
            "/admin/api/dev/earthquake-replay",
            json={"event_json": event, "guild_id": str(GUILD_ID)}, headers=CSRF_HEADER,
        )
        self.assertEqual(no_channel.status_code, 200)
        signal2 = json.loads((_SIGNAL_DIR / "eq_replay.signal").read_text(encoding="utf-8"))
        self.assertIsNone(signal2["channel_id"])

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
        response = make_client().post(
            "/admin/settings/logging", data={"csrf_token": CSRF, "action": "set_log"}
        )
        self.assertEqual(response.status_code, 405)


class IconTests(unittest.TestCase):
    """参照しているアイコンがスプライトに入っていること。

    抜けていても例外は出ず、アイコンが無言で消えるだけなので機械的に確かめる。
    """

    def setUp(self):
        import re

        sprite = (
            Path(__file__).resolve().parent.parent
            / "webapp_admin" / "static" / "icons" / "sprite.svg"
        ).read_text(encoding="utf-8")
        self.available = set(re.findall(r'<symbol[^>]*id="([^"]+)"', sprite))

    def test_panel_icons_exist(self):
        from webapp_admin.schema.registry import PANELS

        missing = [
            panel.id for panel in PANELS
            if panel.icon.removeprefix("bi-") not in self.available
        ]
        self.assertEqual(missing, [], f"スプライトに無いアイコンを指すパネル: {missing}")

    def test_referenced_icons_exist(self):
        import sys as _sys

        _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
        from build_icon_sprite import used_icon_names

        missing = sorted(set(used_icon_names()) - self.available)
        self.assertEqual(
            missing, [],
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
        self.assertEqual(load_tone(72, 90), "warning")   # しきい値の8割
        self.assertEqual(load_tone(90, 90), "danger")    # アラートを記録する値
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

        css = (Path(__file__).resolve().parent.parent / "webapp_admin" / "static" / "css"
               / "components.css").read_text(encoding="utf-8")
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

        css = " ".join(
            path.read_text(encoding="utf-8")
            for path in (self.ADMIN / "static" / "css").glob("*.css")
        )
        js = " ".join(
            path.read_text(encoding="utf-8")
            for path in (self.ADMIN / "static" / "js").rglob("*.js")
        )
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
            unknown, {},
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
            for selector in re.findall(r"^\s*\.([A-Za-z][\w-]*)\s*[,{]", (css_dir / name).read_text(encoding="utf-8"), re.M):
                shared.add(selector)

        public = (css_dir / "public.css").read_text(encoding="utf-8")
        clashes = sorted(
            name for name in re.findall(r"^\s*\.([A-Za-z][\w-]*)\s*[,{]", public, re.M)
            if name in shared
        )
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
            result.returncode, 0,
            "docs/ADMIN.ja.md が古くなっています。python tools/generate_admin_docs.py を実行してください。"
            + (result.stdout or "") + (result.stderr or ""),
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
            guild_id=GUILD_ID, channel_id=555, channel_name="雑談VC",
            started_by_id=1, started_by_name="すずき",
            started_at=_time.monotonic(), max_seconds=0, retention_days=7,
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
        self.assertTrue(all(s["peaks"] for s in manifest["stems"]))
        self.assertTrue(all("/stem/" in s["url"] for s in manifest["stems"]))

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
        self.assertEqual(partial.headers.get("content-range"),
                         f"bytes 100-199/{len(whole)}")

        suffix = self.client.get(url, headers={"Range": "bytes=-50"})
        self.assertEqual(suffix.status_code, 206)
        self.assertEqual(suffix.content, whole[-50:])

        beyond = self.client.get(url, headers={"Range": f"bytes={len(whole) + 10}-"})
        self.assertEqual(beyond.status_code, 416)

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
