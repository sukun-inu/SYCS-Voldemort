"""Web app (FastAPI) API テスト。

    python -m unittest discover -s tests -t .

標準ライブラリの unittest だけで動く。pytest からも実行できる。
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from sqlalchemy.exc import IntegrityError

from services.url_safety import URLSafetyError

# webapp/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# プロジェクトの import より前に一時ディレクトリへ差し替える。
os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="webapp-test-")
os.environ["DISCORD_BOT_TOKEN"] = "dummy-token-for-testing"
os.environ["VAPID_PUBLIC_KEY"] = "dummy-public-key"
os.environ["VAPID_PRIVATE_KEY"] = "dummy-private-key"
os.environ["APP_ROOT_PATH"] = ""
os.environ["APP_PUBLIC_PATH"] = "/"
os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1,::1,testserver"
# スケジューラと自動修復はDBへ接続しに行くため、テストでは無効化する。
os.environ["WEB_SCHEDULER_ENABLED"] = "false"
os.environ["METAL_AUTO_REPAIR_ENABLED"] = "false"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.testclient import TestClient  # noqa: E402

from webapp.app import PUSH_MAX_SUBSCRIPTIONS, app, get_db_session  # noqa: E402


def make_client() -> TestClient:
    """TestClient を作成する。

    starlette.testclient は `with TestClient(app) as c:` のようにコンテキストへ
    入らない限り lifespan(DB初期化・VAPID設定読み込み・スケジューラ起動)を
    発火させない。ここで作るクライアントは常に lifespan 未実行の状態なので、
    DBやVAPID設定に触れる処理はテストごとに個別へ差し替える(override_db_session、
    もしくは webapp.app 内の各関数への patch。このファイルの他クラスの
    setUp を参照)。
    """
    return TestClient(app)


def override_db_session(mock_session) -> None:
    """`Depends(get_db_session)` を指定したモックセッションへ差し替える。

    各エンドポイントは `session: AsyncSession = Depends(get_db_session)` を
    モジュール読み込み時(=importの一度きり)に評価するため、関数オブジェクトを
    直接束縛している。そのため `patch("webapp.app.get_db_session")` で
    モジュール属性を差し替えても、既に登録済みのルートには一切効かない
    (FastAPIは束縛済みの元の関数オブジェクトを呼び続けるため、実際には
    本物のSessionLocal/実DBへ到達してしまう)。正しく差し替えるには
    FastAPI公式のオーバーライド機構である app.dependency_overrides を使う。
    """

    async def _fake_get_db_session():
        yield mock_session

    app.dependency_overrides[get_db_session] = _fake_get_db_session


def clear_db_session_override() -> None:
    app.dependency_overrides.pop(get_db_session, None)


class HealthTests(unittest.TestCase):
    def test_health_endpoint(self):
        client = make_client()
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


class StaticFileTests(unittest.TestCase):
    def test_index_served_with_no_store(self):
        client = make_client()
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("no-store", response.headers["cache-control"])

    def test_index_html_is_served_directly_without_redirect(self):
        """/index.html は /へのリダイレクトではなく、200で同じindexを直接返す。

        @app.get("/index.html") はHTMLResponseをその場で返す実装であり、
        リダイレクトは発生しない(以前のテスト名は"redirects_to_root"だったが、
        実際にはfollow_redirects=Falseのまま200を確認しているだけで、
        リダイレクトを検証してはいなかった)。
        """
        client = make_client()
        response = client.get("/index.html", follow_redirects=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])

    def test_service_worker_js(self):
        client = make_client()
        response = client.get("/sw.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/javascript", response.headers["content-type"])
        self.assertIn("no-store", response.headers["cache-control"])

    def test_manifest(self):
        client = make_client()
        response = client.get("/manifest.webmanifest")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/manifest+json", response.headers["content-type"])


class APIPriceHistoryTests(unittest.TestCase):
    """DBに触れず、価格履歴APIのレスポンス形とクエリパラメータの解釈を検証する。"""

    def setUp(self):
        self.client = make_client()
        self.mock_session = AsyncMock()
        override_db_session(self.mock_session)

        # Mock load_history
        self.load_history_patch = patch("webapp.app.load_history")
        self.mock_load_history = self.load_history_patch.start()
        self.mock_load_history.return_value = []

        # Mock _get_latest_prices
        self.get_latest_prices_patch = patch("webapp.app._get_latest_prices")
        self.mock_get_latest_prices = self.get_latest_prices_patch.start()
        self.mock_get_latest_prices.return_value = {}

        # Mock load_earliest_snapshot_date
        self.load_earliest_snapshot_date_patch = patch("webapp.app.load_earliest_snapshot_date")
        self.mock_load_earliest_snapshot_date = self.load_earliest_snapshot_date_patch.start()
        self.mock_load_earliest_snapshot_date.return_value = None

        # Mock history_cache
        self.history_cache_patch = patch("webapp.app.history_cache")
        self.mock_history_cache = self.history_cache_patch.start()
        self.mock_history_cache.get = AsyncMock(return_value=None)
        self.mock_history_cache.set = AsyncMock()

    def tearDown(self):
        clear_db_session_override()
        self.load_history_patch.stop()
        self.get_latest_prices_patch.stop()
        self.load_earliest_snapshot_date_patch.stop()
        self.history_cache_patch.stop()

    def test_price_history_default(self):
        response = self.client.get("/api/prices/history")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertIn("timezone", json_data)
        self.assertIn("metals", json_data)
        self.assertIn("latest", json_data)

    def test_price_history_with_params(self):
        """all=true指定時は最古スナップショット日から実効日数を動的に計算する経路を通る。

        load_earliest_snapshot_date がNone(最古日が取れない)を返す場合は、
        daysパラメータをそのまま実効日数として使うフォールバックを確認する。
        """
        response = self.client.get("/api/prices/history?days=30&all=true")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertTrue(json_data["all_time"])
        self.assertEqual(json_data["days"], 30)
        self.mock_load_earliest_snapshot_date.assert_called()
        self.mock_load_history.assert_called()


class APIForecastWeeklyTests(unittest.TestCase):
    """週間予測APIが、保存済み予測の有無で200/503を切り替えることを確認する。"""

    def setUp(self):
        self.client = make_client()
        self.mock_session = AsyncMock()
        override_db_session(self.mock_session)

        self.load_stored_weekly_forecast_patch = patch("webapp.app.load_stored_weekly_forecast")
        self.mock_load_stored = self.load_stored_weekly_forecast_patch.start()
        self.mock_load_stored.return_value = {"as_of_date": "2026-08-30"}

        self.forecast_cache_patch = patch("webapp.app.forecast_cache")
        self.mock_forecast_cache = self.forecast_cache_patch.start()
        self.mock_forecast_cache.get = AsyncMock(return_value=None)
        self.mock_forecast_cache.set = AsyncMock()

    def tearDown(self):
        clear_db_session_override()
        self.load_stored_weekly_forecast_patch.stop()
        self.forecast_cache_patch.stop()

    def test_weekly_forecast_success(self):
        response = self.client.get("/api/prices/forecast-weekly")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertIn("as_of_date", json_data)

    def test_weekly_forecast_not_yet_available(self):
        """まだ予測が保存されていない(load_stored_weekly_forecastがNoneを返す)場合は
        503とその理由を返す。"""
        self.mock_load_stored.return_value = None
        response = self.client.get("/api/prices/forecast-weekly")
        self.assertEqual(response.status_code, 503)
        self.assertIn("予測データがまだありません", response.json()["detail"])


class APIPurityOptionsTests(unittest.TestCase):
    """フロントの純度セレクタが必要とする形(display_name と purity の配列)を保証する。"""

    def test_purity_options(self):
        client = make_client()
        response = client.get("/api/purity/options")
        self.assertEqual(response.status_code, 200)
        metals = response.json()["metals"]
        for metal_key in ["gold", "silver", "platinum"]:
            self.assertIn(metal_key, metals)
            self.assertIsInstance(metals[metal_key]["display_name"], str)
            self.assertTrue(metals[metal_key]["purity"], "purityが空だと選択肢を出せない")
            for entry in metals[metal_key]["purity"]:
                self.assertIn("grade", entry)
                self.assertIn("ratio", entry)
        self.assertEqual(metals["gold"]["display_name"], "金")


class APIPushPublicKeyTests(unittest.TestCase):
    """VAPID設定の有無でPush通知の有効/無効を正しく切り替えることを確認する。"""

    def test_push_public_key_enabled(self):
        client = make_client()
        # Ensure VAPID keys are set (they are in os.environ)
        response = client.get("/api/push/public-key")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertTrue(json_data["enabled"])
        self.assertIsNotNone(json_data["public_key"])

    def test_push_public_key_disabled(self):
        """VAPID鍵が無い状態を再現する。

        push_service._cached_config はプロセス内でキャッシュされるため、
        os.environ を書き換えるだけでは既に読み込み済みの値は変わらない。
        is_push_enabled / get_vapid_public_key を直接差し替えて挙動を固定する。
        """
        with patch("webapp.app.is_push_enabled", return_value=False):
            with patch("webapp.app.get_vapid_public_key", return_value=None):
                client = make_client()
                response = client.get("/api/push/public-key")
                self.assertEqual(response.status_code, 200)
                json_data = response.json()
                self.assertFalse(json_data["enabled"])
                self.assertIsNone(json_data["public_key"])


class APIPushSubscribeTests(unittest.TestCase):
    """Push購読登録エンドポイントの分岐(新規/更新/上限/重複/無効/不正endpoint)を検証する。

    validate_public_http_url は実際にDNS解決を行う(services/url_safety.py)ため、
    ネットワークに出ないようモックする。DBセッションは override_db_session で
    差し替え、session.add/commit/rollback が正しい条件でだけ呼ばれることを
    分岐ごとに確認する。
    """

    def setUp(self):
        self.client = make_client()

        self.mock_session = AsyncMock()
        # session.add はSQLAlchemy上は同期メソッドなので、AsyncMockの自動生成に
        # 任せるとawaitされないcoroutineを作ってしまいRuntimeWarningになる。
        self.mock_session.add = Mock()
        override_db_session(self.mock_session)

        self.is_push_enabled_patch = patch("webapp.app.is_push_enabled")
        self.mock_is_push_enabled = self.is_push_enabled_patch.start()
        self.mock_is_push_enabled.return_value = True

        self.validate_public_http_url_patch = patch("webapp.app.validate_public_http_url")
        self.mock_validate_url = self.validate_public_http_url_patch.start()
        # By default, return normally (no exception) for valid endpoints
        self.mock_validate_url.return_value = None

        # デフォルトのシナリオ: 既存購読なし、購読数0件。
        self.mock_scalars_result = Mock()
        self.mock_scalars_result.first.return_value = None

        async def mock_scalars(*_args, **_kwargs):
            return self.mock_scalars_result

        self.mock_session.scalars = mock_scalars
        self.mock_session.scalar.return_value = 0

        self.mock_add = self.mock_session.add
        self.mock_commit = self.mock_session.commit
        self.mock_rollback = self.mock_session.rollback

    def tearDown(self):
        clear_db_session_override()
        self.is_push_enabled_patch.stop()
        self.validate_public_http_url_patch.stop()

    def _payload(self, **overrides):
        payload = {
            "endpoint": "https://example.com/push",
            "keys": {"p256dh": "key1", "auth": "key2"},
        }
        payload.update(overrides)
        return payload

    def test_push_subscribe_success(self):
        response = self.client.post("/api/push/subscribe", json=self._payload(expirationTime=12345))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.mock_add.assert_called()
        self.mock_commit.assert_called()

    def test_push_subscribe_updates_existing_subscription_instead_of_adding(self):
        """同じendpointが既にあるときはUPDATEし、新規追加(session.add)はしない。

        ここを取り違えると同一端末が再購読するたびに重複レコードが増える。
        """
        existing = Mock(p256dh_key="old-p256dh", auth_key="old-auth", user_agent=None)
        self.mock_scalars_result.first.return_value = existing

        response = self.client.post("/api/push/subscribe", json=self._payload())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(existing.p256dh_key, "key1")
        self.assertEqual(existing.auth_key, "key2")
        self.mock_add.assert_not_called()
        self.mock_commit.assert_called()

    def test_push_subscribe_rejects_when_at_capacity(self):
        """購読数がPUSH_MAX_SUBSCRIPTIONSに達していたら429で弾き、追加もcommitもしない。"""
        self.mock_session.scalar.return_value = PUSH_MAX_SUBSCRIPTIONS

        response = self.client.post("/api/push/subscribe", json=self._payload())

        self.assertEqual(response.status_code, 429)
        self.mock_add.assert_not_called()
        self.mock_commit.assert_not_called()

    def test_push_subscribe_ignores_duplicate_insert_race(self):
        """同時リクエストでUNIQUE制約違反(IntegrityError)が起きても、
        rollbackしたうえで200を返す(重複リクエストの競合をエラーにしない)。
        """
        self.mock_session.commit = AsyncMock(side_effect=IntegrityError("INSERT", {}, Exception("duplicate")))

        response = self.client.post("/api/push/subscribe", json=self._payload())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.mock_rollback.assert_called()

    def test_push_subscribe_disabled(self):
        self.mock_is_push_enabled.return_value = False
        response = self.client.post("/api/push/subscribe", json=self._payload())
        self.assertEqual(response.status_code, 503)
        self.assertIn("Push通知が無効です", response.json()["detail"])

    def test_push_subscribe_invalid_endpoint(self):
        self.mock_validate_url.side_effect = URLSafetyError("Invalid endpoint")
        response = self.client.post("/api/push/subscribe", json=self._payload(endpoint="invalid"))
        self.assertEqual(response.status_code, 400)


class APIPushUnsubscribeTests(unittest.TestCase):
    """Push購読解除エンドポイントの正常系と、rowcountをNoneで返すドライバへの耐性を確認する。"""

    def setUp(self):
        self.client = make_client()

        self.mock_session = AsyncMock()
        override_db_session(self.mock_session)

        # Configure the mock session methods
        self.mock_result = Mock()
        self.mock_result.rowcount = 1

        # Make session.execute return an awaitable that resolves to mock_result
        async def mock_execute(*_args, **_kwargs):
            return self.mock_result

        self.mock_execute = Mock(side_effect=mock_execute)
        self.mock_session.execute = self.mock_execute

        # Configure commit to return an awaitable that resolves to None
        async def mock_commit(*_args, **_kwargs):
            return None

        self.mock_commit = Mock(side_effect=mock_commit)
        self.mock_session.commit = self.mock_commit

    def tearDown(self):
        clear_db_session_override()

    def test_push_unsubscribe_success(self):
        payload = {"endpoint": "https://example.com/push"}
        response = self.client.post("/api/push/unsubscribe", json=payload)
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertTrue(json_data["ok"])
        self.assertEqual(json_data["deleted"], 1)
        self.mock_execute.assert_called()
        self.mock_commit.assert_called()

    def test_push_unsubscribe_when_driver_reports_no_rowcount(self):
        """rowcountがNoneを返すドライバでも `int(result.rowcount or 0)` の
        フォールバックでTypeErrorにならない。

        webapp.app.push_unsubscribe のコメントが警告している既知の落とし穴の回帰テスト。
        """
        self.mock_result.rowcount = None
        payload = {"endpoint": "https://example.com/push"}
        response = self.client.post("/api/push/unsubscribe", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted"], 0)


class APICalculateTests(unittest.TestCase):
    """グラム数×レートのDecimal計算と、価格未取得時の503を検証する。"""

    def setUp(self):
        self.client = make_client()
        self.mock_session = AsyncMock()
        override_db_session(self.mock_session)

        self.get_latest_prices_patch = patch("webapp.app._get_latest_prices")
        self.mock_get_latest_prices = self.get_latest_prices_patch.start()
        self.mock_get_latest_prices.return_value = {
            "gold": {"date": "2026-08-30", "price_per_gram": "100.0", "delta_from_previous": "1.0"}
        }

        self.calculate_cache_patch = patch("webapp.app.calculate_cache")
        self.mock_calculate_cache = self.calculate_cache_patch.start()
        self.mock_calculate_cache.get = AsyncMock(return_value=None)
        self.mock_calculate_cache.set = AsyncMock()

    def tearDown(self):
        clear_db_session_override()
        self.get_latest_prices_patch.stop()
        self.calculate_cache_patch.stop()

    def test_calculate_success(self):
        response = self.client.get("/api/prices/calculate?metal=gold&grams=10")
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertEqual(json_data["metal"], "gold")
        self.assertEqual(json_data["display_name"], "金")
        self.assertEqual(json_data["grams"], 10)
        self.assertEqual(json_data["price_per_gram"], 100.0)
        self.assertEqual(json_data["pure_value"], 1000)  # 100 * 10
        # 24K(純度1.0)はpure_valueと一致し、18K(純度0.75)は750になるはず。
        self.assertEqual(json_data["by_purity"]["24K"], 1000)
        self.assertEqual(json_data["by_purity"]["18K"], 750)

    def test_calculate_invalid_metal(self):
        response = self.client.get("/api/prices/calculate?metal=invalid&grams=10")
        self.assertEqual(response.status_code, 400)
        self.assertIn("metal は gold/silver/platinum のいずれか", response.json()["detail"])

    def test_calculate_no_price_data(self):
        self.mock_get_latest_prices.return_value = {}
        response = self.client.get("/api/prices/calculate?metal=gold&grams=10")
        self.assertEqual(response.status_code, 503)
        self.assertIn("価格データがまだありません", response.json()["detail"])


class FallbackPageTests(unittest.TestCase):
    """予約済みトップレベルパス以外はSPAのindex.htmlへフォールバックすることを確認する。"""

    def test_fallback_returns_index_for_non_reserved_path(self):
        client = make_client()
        # Any path not in RESERVED_TOP_LEVEL_PATHS should return index.html
        response = client.get("/some/random/path")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])

    def test_fallback_returns_404_for_reserved_path(self):
        client = make_client()
        # Paths like /api should return 404 (Not Found) because they are reserved
        response = client.get("/api")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Not Found", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
