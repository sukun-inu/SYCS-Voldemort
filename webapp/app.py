import logging
import os
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from config import METAL_COMMANDS
from envutil import env_int
from services.url_safety import URLSafetyError, validate_public_http_url
from .cache import TTLCache
from .asset_version import render_index_html, render_service_worker
from .db import SessionLocal, close_db, engine, init_db
from .forecast_accuracy_service import (
    load_recent_forecast_error,
    reconcile_forecast_accuracy,
)
from .forecast_service import load_stored_weekly_forecast, refresh_weekly_forecast_cache
from .models import NotificationDispatch, PushSubscription
from .push_service import (
    build_push_payload,
    get_vapid_public_key,
    is_push_enabled,
    refresh_vapid_config,
    send_push,
)
from .repair_service import repair_metalprice_integrity
from .security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    load_allowed_hosts,
    load_trusted_proxy_cidrs,
    read_env_bool,
)
from .snapshot_service import (
    JST,
    load_earliest_snapshot_date,
    load_history,
    load_latest_rows,
    store_today_snapshot,
)

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
SW_FILE = STATIC_DIR / "sw.js"
MANIFEST_FILE = STATIC_DIR / "manifest.webmanifest"
RESERVED_TOP_LEVEL_PATHS = {
    "api",
    "static",
    "health",
    "docs",
    "redoc",
    "openapi.json",
    "sw.js",
    "manifest.webmanifest",
}
API_RESPONSE_CACHE_SECONDS = env_int("API_RESPONSE_CACHE_SECONDS", 20, minimum=1)
PURITY_OPTIONS_CACHE_SECONDS = env_int("PURITY_OPTIONS_CACHE_SECONDS", 3600, minimum=60)
PUSH_PUBLIC_KEY_CACHE_SECONDS = env_int("PUSH_PUBLIC_KEY_CACHE_SECONDS", 3600, minimum=300)
FORECAST_CACHE_SECONDS = env_int("FORECAST_CACHE_SECONDS", 1800, minimum=60)
FORECAST_REFRESH_MINUTE_JST = env_int("FORECAST_REFRESH_MINUTE_JST", 5, minimum=0, maximum=59)
# JST 00:00の日次スナップショット直後は既にjst_daily_metal_snapshot_and_forecastが
# 予測を更新するため、ここには含めない。価格データ自体は1日1回しか変わらないため、
# 日中はニュース動向を拾う目的でこの時刻にだけ強制リフレッシュする(以前は毎時実行して
# いたが、Groq/ニュースRSS/為替APIを無駄に24回/日叩いていたため間引いた)。
FORECAST_REFRESH_EXTRA_HOURS_JST = [
    hour.strip() for hour in os.getenv("FORECAST_REFRESH_EXTRA_HOURS_JST", "6,12,18").split(",") if hour.strip()
]
PUSH_NOTIFY_HOUR_JST = env_int("PUSH_NOTIFY_HOUR_JST", 11, minimum=0, maximum=23)
PUSH_NOTIFY_MINUTE_JST = env_int("PUSH_NOTIFY_MINUTE_JST", 0, minimum=0, maximum=59)
NOTIFY_TOP_DELTA_TYPE = "daily_top_delta"
APP_PUBLIC_PATH = (os.getenv("APP_PUBLIC_PATH") or os.getenv("APP_ROOT_PATH") or "/").strip() or "/"
PUSH_MAX_SUBSCRIPTIONS = env_int("PUSH_MAX_SUBSCRIPTIONS", 50000, minimum=100)
_PUSH_ALLOWED_ENDPOINT_SUFFIXES = tuple(
    part.strip().lower() for part in os.getenv("PUSH_ALLOWED_ENDPOINT_SUFFIXES", "").split(",") if part.strip()
)


def _normalize_public_path(path: str) -> str:
    """先頭・末尾に必ず `/` を付ける。Push通知のurlやService-Worker-Allowedヘッダに使う値の形を揃える。"""
    if path in {"", "/"}:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    if not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _is_repairable_db_error(exc: Exception) -> bool:
    """再接続・再マイグレーションで直る見込みがあるDBエラーかを見る。

    OperationalError/ProgrammingError（接続断・スキーマ不一致など）は
    init_db() のやり直しで復旧しうる。IntegrityError等の他の例外は
    データそのものの問題なので、自己修復を試みても意味が無く、無駄な
    再試行でログとレイテンシを浪費するだけになる。
    """
    return isinstance(exc, (OperationalError, ProgrammingError))


async def _try_db_self_heal(*, context: str, exc: Exception) -> bool:
    """DB起因のエラーからの自動復旧を1回だけ試みる。バッチジョブ各所が同じ手順を呼ぶ。

    コンテナ再起動を待たず、アプリ内でDB再接続・再マイグレーションを
    試すことで、一時的なDB不調（再起動直後の接続断など）から自動で
    復帰できるようにする。直らない場合は False を返し、呼び出し元は
    そのジョブ回だけ諦めて次回実行に委ねる（無限リトライしない）。
    """
    if not _is_repairable_db_error(exc):
        return False
    logger.warning("[WEB] %s failed with DB error. trying self-heal: %s", context, exc)
    try:
        await init_db()
        return True
    except Exception:
        logger.exception("[WEB] DB self-heal failed at %s", context)
        return False


APP_PUBLIC_ROOT = _normalize_public_path(APP_PUBLIC_PATH)
STARTUP_TEST_MODE = read_env_bool("STARTUP_TEST_MODE", False)
STARTUP_TEST_REQUIRE_DOCKER = read_env_bool("STARTUP_TEST_REQUIRE_DOCKER", True)
STARTUP_TEST_RUN_PUSH_ON_BOOT = read_env_bool("STARTUP_TEST_RUN_PUSH_ON_BOOT", False)
STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT = read_env_bool("STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT", False)
STARTUP_TEST_FORCE_SNAPSHOT_REFRESH = read_env_bool("STARTUP_TEST_FORCE_SNAPSHOT_REFRESH", True)
WEB_SCHEDULER_ENABLED = read_env_bool("WEB_SCHEDULER_ENABLED", True)
METAL_AUTO_REPAIR_ENABLED = read_env_bool("METAL_AUTO_REPAIR_ENABLED", True)
METAL_AUTO_REPAIR_INTERVAL_MINUTES = env_int("METAL_AUTO_REPAIR_INTERVAL_MINUTES", 30, minimum=5)
METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH = read_env_bool("METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH", False)

history_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=64)
latest_prices_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=8)
calculate_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=API_RESPONSE_CACHE_SECONDS, max_items=1024)
forecast_cache: TTLCache[dict] = TTLCache(default_ttl_seconds=FORECAST_CACHE_SECONDS, max_items=32)
PURITY_OPTIONS_PAYLOAD = {
    "metals": {
        key: {
            "display_name": spec.display_name,
            "purity": [{"grade": grade, "ratio": ratio} for grade, ratio in spec.purity.items()],
        }
        for key, spec in METAL_COMMANDS.items()
    }
}


class PushSubscriptionKeys(BaseModel):
    p256dh: str = Field(min_length=1, max_length=2048)
    auth: str = Field(min_length=1, max_length=2048)


class PushSubscribeRequest(BaseModel):
    endpoint: str = Field(min_length=1, max_length=4096)
    keys: PushSubscriptionKeys
    expirationTime: int | None = None  # noqa: N815 - browser spec field


class PushUnsubscribeRequest(BaseModel):
    endpoint: str = Field(min_length=1, max_length=4096)


async def get_db_session():
    """FastAPIのDepends用セッションファクトリ。Depends()はここを読み込み時に束縛するので、
    差し替えたい場合は app.dependency_overrides を使うこと(モジュール属性のpatchは効かない)。
    """
    async with SessionLocal() as session:
        yield session


def _cache_headers(ttl_seconds: int) -> dict[str, str]:
    """CDN(Cloudflare等)とブラウザ双方に同じTTLを伝える。stale-while-revalidateで再検証中も即応答させる。"""
    return {
        "Cache-Control": f"public, max-age={ttl_seconds}, s-maxage={ttl_seconds}, stale-while-revalidate={ttl_seconds}",
    }


def _validate_push_endpoint(endpoint: str) -> str:
    """購読エンドポイントURLを検証する。SSRF対策と、任意ホストへの通知投稿を防ぐ許可リストの2段構え。

    validate_public_http_url はプライベート/内部アドレスを弾く（SSRF
    対策）。PUSH_ALLOWED_ENDPOINT_SUFFIXES を設定した環境ではさらに
    ホスト名を許可リストに限定する。両方を経て初めて受理する。
    """
    endpoint = endpoint.strip()
    try:
        validate_public_http_url(endpoint, allow_http=False)
    except URLSafetyError as e:
        raise HTTPException(status_code=400, detail=f"無効なPush endpointです: {e}") from e

    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="無効なPush endpointです: hostが不正です")

    if _PUSH_ALLOWED_ENDPOINT_SUFFIXES:
        if not any(host == suffix or host.endswith(f".{suffix}") for suffix in _PUSH_ALLOWED_ENDPOINT_SUFFIXES):
            raise HTTPException(status_code=400, detail="Push endpoint のホストが許可リスト外です")

    return endpoint


async def _clear_response_caches() -> None:
    """DBが更新された直後に全レスポンスキャッシュを破棄する。TTL満了を待つと古い値を配り続ける。"""
    await history_cache.clear()
    await latest_prices_cache.clear()
    await calculate_cache.clear()
    await forecast_cache.clear()


async def _get_latest_prices(session: AsyncSession) -> dict[str, dict[str, str | None]]:
    """全金属の最新価格をDecimal文字列のまま返す（float丸め誤差を持ち込まない内部表現）。

    キャッシュキーに日付を含めるのは、日付が変わったらTTLを待たず
    新しい「今日」のキャッシュ空間へ切り替えるため。price計算
    (calculate_by_purity)がこの文字列をDecimalへ戻して使うので、ここで
    floatにしてしまうと計算結果の桁がずれる。
    """
    cache_key = f"latest:{datetime.now(JST).date().isoformat()}"
    cached = await latest_prices_cache.get(cache_key)
    if cached is not None:
        return cached

    latest_rows = await load_latest_rows(session)
    snapshot: dict[str, dict[str, str | None]] = {}
    for metal_key in METAL_COMMANDS.keys():
        row = latest_rows.get(metal_key)
        if row is None:
            snapshot[metal_key] = {
                "date": None,
                "price_per_gram": None,
                "delta_from_previous": None,
            }
            continue
        snapshot[metal_key] = {
            "date": row.snapshot_date.isoformat(),
            "price_per_gram": str(row.price_per_gram),
            "delta_from_previous": (str(row.delta_from_previous) if row.delta_from_previous is not None else None),
        }

    await latest_prices_cache.set(cache_key, snapshot)
    return snapshot


def _latest_prices_public(snapshot: dict[str, dict[str, str | None]]) -> dict[str, dict[str, float | str | None]]:
    """_get_latest_prices が返すDecimal文字列を、JSONレスポンス用にfloatへ変換する。

    内部表現(str)と外部公開用(float)を分けているのは、キャッシュされた
    内部値を後で別の計算に再利用するときに丸め誤差を持ち込みたくない
    ため。API応答としてはfloatで十分。
    """
    latest: dict[str, dict[str, float | str | None]] = {}
    for metal_key in METAL_COMMANDS.keys():
        item = snapshot.get(metal_key, {})
        price = item.get("price_per_gram")
        delta = item.get("delta_from_previous")
        latest[metal_key] = {
            "date": item.get("date"),
            "price_per_gram": float(price) if price is not None else None,
            "delta_from_previous": float(delta) if delta is not None else None,
        }
    return latest


def _pick_top_delta(snapshot: dict[str, dict[str, str | None]]) -> tuple[str, Decimal, str] | None:
    """前日比の絶対値が最大の金属を選ぶ。日次Push通知1件に使う「今日いちばん動いた金属」の決定。

    delta_from_previous・date のどちらか欠けている金属は候補から除く
    （前日データが無い、または当日未取得）。全金属欠けていれば None を
    返し、呼び出し側は通知を送らない。
    """
    top_metal_key: str | None = None
    top_delta: Decimal | None = None
    top_date: str | None = None

    for metal_key in METAL_COMMANDS.keys():
        item = snapshot.get(metal_key)
        if not item:
            continue
        delta_raw = item.get("delta_from_previous")
        snapshot_date = item.get("date")
        if delta_raw is None or snapshot_date is None:
            continue

        delta = Decimal(delta_raw)
        if top_delta is None or abs(delta) > abs(top_delta):
            top_metal_key = metal_key
            top_delta = delta
            top_date = snapshot_date

    if top_metal_key is None or top_delta is None or top_date is None:
        return None
    return top_metal_key, top_delta, top_date


async def _claim_dispatch_slot(session: AsyncSession, *, snapshot_date: date) -> int | None:
    """通知送信スロットを先に確保して、多重インスタンスの重複送信を防ぐ。

    INSERT ... ON CONFLICT DO NOTHING を使うことで、競合時に PostgreSQL がエラーログを
    吐かない。複数ワーカーが同時実行した場合、後着はスロット取得失敗として None を返す。
    """
    stmt = (
        pg_insert(NotificationDispatch)
        .values(
            notification_type=NOTIFY_TOP_DELTA_TYPE,
            snapshot_date=snapshot_date,
            detail="pending",
        )
        .on_conflict_do_nothing(constraint="uq_notification_dispatch_type_date")
        .returning(NotificationDispatch.id)
    )
    result = await session.execute(stmt)
    # 行を取り出してから commit する。順番を入れ替えて commit 後に
    # result を読むと、結果が確定していない実装では取り出せなくなる。
    # 衝突して（＝既に配信済みで）行が返らなかったときは、commit せずに
    # 抜ける。ここは配信の重複を止める関門なので、何もしていないときに
    # トランザクションを閉じない。
    row = result.fetchone()
    if row is None:
        return None
    await session.commit()
    return int(row[0])


async def _send_push_to_subscriptions(
    subscriptions: list,
    payload: str,
    session: AsyncSession,
) -> tuple[int, list[str]]:
    """全購読へ順に送信し、404/410で無効と分かった購読はまとめてDBから削除する。

    session.commit() はここでは呼ばない。呼び出し元がNotificationDispatch
    の更新と同じトランザクションでまとめてcommitするため、ここで
    commitすると途中失敗時に「購読は削除済みだが配信記録は残っていない」
    半端な状態になりうる。
    """
    stale_endpoints: list[str] = []
    success_count = 0
    for sub in subscriptions:
        ok, should_remove = await send_push(
            {
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh_key, "auth": sub.auth_key},
            },
            payload,
        )
        if ok:
            success_count += 1
        elif should_remove:
            stale_endpoints.append(sub.endpoint)

    if stale_endpoints:
        await session.execute(delete(PushSubscription).where(PushSubscription.endpoint.in_(stale_endpoints)))

    return success_count, stale_endpoints


async def dispatch_top_delta_notification(*, enforce_schedule_time: bool = False) -> None:
    """日次Push通知を1日1回だけ送る。多重起動・時刻ずれ・途中失敗のいずれでも二重送信しない。

    _claim_dispatch_slot の ON CONFLICT DO NOTHING で、同じ
    (notification_type, snapshot_date) の枠を取れたインスタンスだけが
    送信する（複数ワーカー/複数インスタンス構成での重複防止）。送信中に
    例外が起きたら、確保したスロット自体を削除してロールバックする
    （enforce_schedule_time=True のcron経由なら次回の定期実行で再試行
    できるようにするため。中途半端な"pending"のまま残すと、二度と
    その日は送信されなくなる）。enforce_schedule_time はcron経由の
    定期実行と起動時の即時実行を区別するためのフラグで、Trueのときは
    指定時刻より前なら何もしない。
    """
    if not is_push_enabled():
        return

    now = datetime.now(JST)
    if enforce_schedule_time and (now.hour, now.minute) < (
        PUSH_NOTIFY_HOUR_JST,
        PUSH_NOTIFY_MINUTE_JST,
    ):
        return

    async with SessionLocal() as session:
        latest_snapshot = await _get_latest_prices(session)
        top = _pick_top_delta(latest_snapshot)
        if top is None:
            return

        metal_key, delta_value, snapshot_date = top
        subscriptions = list((await session.scalars(select(PushSubscription))).all())
        if not subscriptions:
            return

        snapshot_date_value = datetime.fromisoformat(snapshot_date).date()
        dispatch_id = await _claim_dispatch_slot(session, snapshot_date=snapshot_date_value)
        if dispatch_id is None:
            logger.info(
                "日次Push通知は別インスタンスで処理中/送信済みのためスキップ。snapshot=%s",
                snapshot_date,
            )
            return

        spec = METAL_COMMANDS[metal_key]
        delta_sign = "+" if delta_value >= 0 else ""
        payload = build_push_payload(
            title="本日の価格変動通知 (JST 11:00)",
            body=f"{spec.display_name}の前日差が最大: {delta_sign}{delta_value:.2f} 円/g ({snapshot_date})",
            url=APP_PUBLIC_ROOT,
        )

        try:
            success_count, stale_endpoints = await _send_push_to_subscriptions(subscriptions, payload, session)
            await session.execute(
                update(NotificationDispatch)
                .where(NotificationDispatch.id == dispatch_id)
                .values(detail=f"{metal_key}:{delta_value}:ok={success_count}:stale={len(stale_endpoints)}")
            )
            await session.commit()
        except Exception:
            await session.rollback()
            try:
                await session.execute(delete(NotificationDispatch).where(NotificationDispatch.id == dispatch_id))
                await session.commit()
            except Exception:
                await session.rollback()
            raise

        logger.info(
            "日次Push通知を送信した。snapshot=%s success=%s stale_removed=%s",
            snapshot_date,
            success_count,
            len(stale_endpoints),
        )


def _running_in_container() -> bool:
    """コンテナ内で実行中かを判定する。_startup_test_enabled がSTARTUP_TEST_REQUIRE_DOCKER=true
    のとき、この判定に使う。STARTUP_TEST_RUN_PUSH_ON_BOOTは実際の購読者にPushを送るため、
    開発機やステージング機でSTARTUP_TEST_MODEを立てたまま起動して誤爆させないための関門になる。
    """
    if Path("/.dockerenv").exists():
        return True
    cgroup_file = Path("/proc/1/cgroup")
    if not cgroup_file.exists():
        return False
    try:
        cgroup_text = cgroup_file.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False
    return "docker" in cgroup_text or "containerd" in cgroup_text or "kubepods" in cgroup_text


def _startup_test_enabled() -> bool:
    """起動テストジョブを本当に走らせてよいかを1箇所で判定する。

    STARTUP_TEST_MODE=falseなら他の実行フラグが立っていても常に無効化し、
    設定ミス(消し忘れ)に気付けるよう警告を出す。REQUIRE_DOCKER=trueのときは
    _running_in_container()で実行環境も確認し、本番相当のホストで誤って
    テストジョブ(実際のPush送信を含む)を起動しないようにする。
    """
    if not STARTUP_TEST_MODE:
        if STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT or STARTUP_TEST_RUN_PUSH_ON_BOOT:
            logger.warning("起動テスト設定を検出したが STARTUP_TEST_MODE=false のため無効化。")
        return False
    if STARTUP_TEST_REQUIRE_DOCKER and not _running_in_container():
        logger.warning("起動テストモードをスキップ: コンテナ外で STARTUP_TEST_REQUIRE_DOCKER=true")
        return False
    return True


async def _dispatch_startup_test_push_notification() -> None:
    """起動直後に実データで本物のPush通知を送り、疎通確認する。

    dispatch_top_delta_notificationと違い_claim_dispatch_slotを使わない
    (NotificationDispatchに記録しない)。起動テストは何度でも打てないと
    確認の意味が無いためで、その代わり多重起動環境では起動のたびに
    同じ通知が重複して届き得る。STARTUP_TEST_MODE経由でしか呼ばれない
    前提で、通常運用の重複防止・送信履歴には一切影響させない。
    """
    # 起動時テスト通知は通常運用の重複判定・送信履歴に影響させない。
    if not is_push_enabled():
        logger.warning("起動時テストPushをスキップ: Push通知が未設定")
        return

    async with SessionLocal() as session:
        latest_snapshot = await _get_latest_prices(session)
        top = _pick_top_delta(latest_snapshot)
        if top is None:
            logger.warning("起動時テストPushをスキップ: 送信対象データが未取得")
            return

        metal_key, delta_value, snapshot_date = top
        subscriptions = list((await session.scalars(select(PushSubscription))).all())
        if not subscriptions:
            logger.warning("起動時テストPushをスキップ: 購読ユーザーが存在しない")
            return

        spec = METAL_COMMANDS[metal_key]
        delta_sign = "+" if delta_value >= 0 else ""
        payload = build_push_payload(
            title="【テスト】起動時 Push 通知",
            body=f"{spec.display_name} 変動テスト: {delta_sign}{delta_value:.2f} 円/g ({snapshot_date})",
            url=APP_PUBLIC_ROOT,
        )

        success_count, stale_endpoints = await _send_push_to_subscriptions(subscriptions, payload, session)
        await session.commit()

        logger.warning(
            "起動時テストPushを送信した。snapshot=%s success=%s stale_removed=%s",
            snapshot_date,
            success_count,
            len(stale_endpoints),
        )


async def _run_startup_test_jobs() -> None:
    """STARTUP_TEST_*フラグに従って起動時ジョブを順に試走させる。

    各ジョブの例外はここで個別にログへ落として握りつぶす。テストジョブの
    1つが失敗しても他のテストジョブやアプリ本体の起動処理を止めないため
    (起動テストの失敗でサービス自体が上がらなくなっては本末転倒)。
    """
    if not _startup_test_enabled():
        return
    logger.warning(
        "起動テストモード有効: midnight_job=%s push=%s force_snapshot=%s",
        STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT,
        STARTUP_TEST_RUN_PUSH_ON_BOOT,
        STARTUP_TEST_FORCE_SNAPSHOT_REFRESH,
    )

    if STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT:
        try:
            await collect_daily_data(
                force_snapshot_refresh=STARTUP_TEST_FORCE_SNAPSHOT_REFRESH,
                force_forecast_refresh=STARTUP_TEST_FORCE_SNAPSHOT_REFRESH,
            )
            logger.warning("起動時テスト: 0時更新ジョブを即時実行した。")
        except Exception:
            logger.exception("起動時テスト: 0時更新ジョブの即時実行に失敗した。")

    if STARTUP_TEST_RUN_PUSH_ON_BOOT:
        try:
            await _dispatch_startup_test_push_notification()
        except Exception:
            logger.exception("起動時テスト: Push通知の即時送信に失敗した。")


async def collect_daily_snapshot(*, force_refresh: bool = False) -> None:
    """日次価格スナップショットを保存する。DBエラーなら自己修復して1回だけ再試行する。

    _try_db_self_heal経由の再試行は最大1回。コンテナ再起動を待たず、
    再接続直後などの一時的なDB不調から自動復帰させるためだが、直らなければ
    その回は諦めてログに残し、次回のスケジュール実行に委ねる(無限リトライで
    ジョブを詰まらせない)。
    """
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                await store_today_snapshot(session, skip_if_exists=not force_refresh)
                await _clear_response_caches()
                logger.info(
                    "日次価格スナップショットを保存した。force_refresh=%s",
                    force_refresh,
                )
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="collect_daily_snapshot", exc=e):
                    continue
                logger.exception("日次価格スナップショット保存に失敗した。")
                return


async def collect_weekly_forecast_cache(*, force_refresh: bool = False) -> None:
    """週次予測をDBとインプロセスキャッシュへ反映する。同日分はforce_refresh無指定なら再計算しない。

    予測計算はGroq/為替API/ニュースRSSを叩く重い処理で、いずれも呼び出し
    回数に実質的な上限がある。as_of_dateが今日と一致する既存データが
    あれば計算をスキップし、同じ日に何度も外部APIを無駄撃ちしないようにする。
    DBエラー時の再試行はcollect_daily_snapshotと同じく1回きりの自己修復。
    """
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                today_iso = datetime.now(JST).date().isoformat()
                if not force_refresh:
                    existing_payload = await load_stored_weekly_forecast(session, days=7)
                    if existing_payload and existing_payload.get("as_of_date") == today_iso:
                        logger.info(
                            "7日予測データは最新のため更新をスキップした。as_of_date=%s",
                            today_iso,
                        )
                        return
                await refresh_weekly_forecast_cache(session, horizon_days=7)
                await forecast_cache.clear()
                logger.info(
                    "7日予測データを更新し、DBに保存した。force_refresh=%s",
                    force_refresh,
                )
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="collect_weekly_forecast_cache", exc=e):
                    continue
                logger.exception("7日予測データの更新保存に失敗した。")
                return


async def auto_repair_metalprice_data(*, force_forecast_refresh: bool = False) -> None:
    """metalpriceテーブルの欠損・不整合を定期的に自己修復する。DBエラー時のみ1回だけ再試行する。

    実際の修復ロジック(コード修正・欠損補完・クールダウン管理)は
    repair_metalprice_integrity側にある。ここはcollect_daily_snapshotと
    同じDB自己修復付きの実行枠を提供し、結果統計をまとめてログに残す役割。
    """
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stats = await repair_metalprice_integrity(
                    session,
                    force_forecast_refresh=force_forecast_refresh,
                )
                await _clear_response_caches()
                logger.info(
                    "metalprice自動修復を実行した。rows_scanned=%s rows_fixed=%s code_fixed=%s delta_fixed=%s "
                    "missing_today_before=%s missing_today_after=%s forecast_refreshed=%s "
                    "repair_attempted=%s repair_skipped_cooldown=%s",
                    stats.get("rows_scanned", 0),
                    stats.get("rows_fixed", 0),
                    stats.get("metal_code_fixed", 0),
                    stats.get("delta_fixed", 0),
                    stats.get("missing_today_before", 0),
                    stats.get("missing_today_after", 0),
                    stats.get("forecast_refreshed", 0),
                    stats.get("missing_data_repair_attempted", 0),
                    stats.get("missing_data_repair_skipped_cooldown", 0),
                )
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="auto_repair_metalprice_data", exc=e):
                    continue
                logger.exception("metalprice自動修復に失敗した。")
                return


async def reconcile_forecast_accuracy_job() -> None:
    """前日までの予測と、直前に確定した実勢価格を突き合わせて答え合わせする。
    日次スナップショット保存の直後(新しい実勢価格が入った直後)に呼ぶ。"""
    for attempt in range(2):
        async with SessionLocal() as session:
            try:
                stats = await reconcile_forecast_accuracy(session)
                logger.info(
                    "予測精度の答え合わせを実行した。checked=%s matched=%s unmatched=%s",
                    stats.get("checked", 0),
                    stats.get("matched", 0),
                    stats.get("unmatched", 0),
                )
                # 為替・ニュース・AI判定による傾きが、何もしない場合より良い結果を
                # 出せているかをログに残す。これが常にマイナスなら傾きは外すべき。
                accuracy = await load_recent_forecast_error(session)
                for metal_key, effect in (accuracy.get("tilt_effect") or {}).items():
                    logger.info(
                        "シグナル有効性 metal=%s 予測MAE=%.3f%% 何もしない場合=%.3f%% 改善=%+.1f%% (n=%s)",
                        metal_key,
                        effect.get("model_mae_pct", 0.0),
                        effect.get("baseline_mae_pct", 0.0),
                        effect.get("improvement_pct", 0.0),
                        effect.get("samples", 0),
                    )
                return
            except Exception as e:
                await session.rollback()
                if attempt == 0 and await _try_db_self_heal(context="reconcile_forecast_accuracy_job", exc=e):
                    continue
                logger.exception("予測精度の答え合わせに失敗した。")
                return


async def collect_daily_data(*, force_snapshot_refresh: bool = False, force_forecast_refresh: bool = False) -> None:
    """JST 0時の日次ジョブ本体。スナップショット保存→答え合わせ→週次予測更新の順を守る。

    reconcile_forecast_accuracy_jobを予測更新より先に呼ぶのは、前日までの
    予測を「新しく確定した今日の実勢価格」と突き合わせるため。先に予測を
    更新してしまうと、答え合わせの対象が古い予測のままなのか新しい予測
    なのか区別できなくなる。
    """
    await collect_daily_snapshot(force_refresh=force_snapshot_refresh)
    await reconcile_forecast_accuracy_job()
    await collect_weekly_forecast_cache(force_refresh=force_forecast_refresh)


# uvicorn --workers での複数プロセス起動やマルチインスタンス構成で、日次スナップショット・
# 自動修復・週次予測などの定期ジョブが複数プロセスで重複実行されるのを防ぐためのロック。
# MetalpriceAPIが無料枠(月100回)のため、二重実行は外部API消費が単純に倍になり致命的。
SCHEDULER_ADVISORY_LOCK_KEY = 721045501
_scheduler_lock_conn: AsyncConnection | None = None


async def _try_acquire_scheduler_lock() -> bool:
    """PostgreSQLのsession-level advisory lockを取得できたプロセスだけが定期ジョブを担当する。
    取得に使った接続を保持し続けている間だけロックが有効。"""
    global _scheduler_lock_conn
    conn = await engine.connect()
    try:
        result = await conn.execute(
            text("SELECT pg_try_advisory_lock(:key)"),
            {"key": SCHEDULER_ADVISORY_LOCK_KEY},
        )
        acquired = bool(result.scalar())
    except Exception:
        await conn.close()
        raise
    if acquired:
        _scheduler_lock_conn = conn
    else:
        await conn.close()
    return acquired


async def _release_scheduler_lock() -> None:
    """_try_acquire_scheduler_lockで確保したadvisory lockを解放する。lifespanのfinallyから呼ぶ。

    lockを取れなかった(=他プロセスが定期ジョブを担当している)ワーカーでは
    _scheduler_lock_connがNoneなので何もしない。解放処理自体が失敗しても
    例外は外に投げない。ここで送出するとlifespanのfinally内で後続の
    close_db()まで巻き込んで止めてしまうため、失敗はログに残すだけにして
    確実にconn.close()まで進める。
    """
    global _scheduler_lock_conn
    conn = _scheduler_lock_conn
    _scheduler_lock_conn = None
    if conn is None:
        return
    try:
        await conn.execute(
            text("SELECT pg_advisory_unlock(:key)"),
            {"key": SCHEDULER_ADVISORY_LOCK_KEY},
        )
    except Exception:
        logger.exception("[WEB] スケジューラのadvisory lock解放に失敗した。")
    finally:
        await conn.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """DB初期化とスケジューラ起動を行い、終了時に後始末する。

    advisory lockを取れたワーカーだけが日次ジョブの登録・スケジューラ起動・
    起動時ジョブ実行を行う。uvicorn --workersや複数インスタンス構成で
    全ワーカーが同じジョブを重複実行すると、MetalpriceAPIの無料枠(月100回)
    を単純に人数倍消費してしまうため、実行担当を1プロセスに絞るのが目的。
    lockを取れなかったワーカーはAPIリクエストの処理だけを担当し、
    スケジューラを一切持たない。finally節はyield前の初期化失敗でも安全に
    通れるよう、scheduler/has_scheduler_lockのNoneチェックを先に行う。
    """
    await init_db()
    refresh_vapid_config()
    scheduler: AsyncIOScheduler | None = None
    has_scheduler_lock = False

    if WEB_SCHEDULER_ENABLED:
        has_scheduler_lock = await _try_acquire_scheduler_lock()

    if WEB_SCHEDULER_ENABLED and has_scheduler_lock:
        await collect_daily_data()
        if METAL_AUTO_REPAIR_ENABLED:
            await auto_repair_metalprice_data(force_forecast_refresh=METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH)
        await dispatch_top_delta_notification(enforce_schedule_time=True)
        await _run_startup_test_jobs()

        scheduler = AsyncIOScheduler(timezone=JST)
        scheduler.add_job(
            collect_daily_data,
            CronTrigger(hour=0, minute=0, timezone=JST),
            id="jst_daily_metal_snapshot_and_forecast",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            misfire_grace_time=3600,
        )
        if FORECAST_REFRESH_EXTRA_HOURS_JST:
            # JST 00:00分はjst_daily_metal_snapshot_and_forecastで既にカバー済みのため、
            # ここでは日中の追加リフレッシュ(既定6/12/18時)のみを強制更新する。
            scheduler.add_job(
                collect_weekly_forecast_cache,
                CronTrigger(
                    hour=",".join(FORECAST_REFRESH_EXTRA_HOURS_JST),
                    minute=FORECAST_REFRESH_MINUTE_JST,
                    timezone=JST,
                ),
                kwargs={"force_refresh": True},
                id="jst_intraday_forecast_refresh",
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=1800,
            )
        scheduler.add_job(
            dispatch_top_delta_notification,
            CronTrigger(hour=PUSH_NOTIFY_HOUR_JST, minute=PUSH_NOTIFY_MINUTE_JST, timezone=JST),
            id="jst_daily_top_delta_push_notify",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            misfire_grace_time=7200,
        )
        if METAL_AUTO_REPAIR_ENABLED:
            scheduler.add_job(
                auto_repair_metalprice_data,
                IntervalTrigger(minutes=METAL_AUTO_REPAIR_INTERVAL_MINUTES, timezone=JST),
                kwargs={"force_forecast_refresh": METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH},
                id="jst_metalprice_auto_repair",
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=max(300, METAL_AUTO_REPAIR_INTERVAL_MINUTES * 60),
            )
        scheduler.start()
        logger.info("WEB_SCHEDULER_ENABLED=true: background scheduler started (advisory lock acquired)")
    elif WEB_SCHEDULER_ENABLED:
        logger.info(
            "WEB_SCHEDULER_ENABLED=true だが他プロセスが定期ジョブのadvisory lockを保持しているため、"
            "このワーカーではスケジューラを起動しない。"
        )
    else:
        logger.info("WEB_SCHEDULER_ENABLED=false: startup jobs and scheduler are disabled")

    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=False)
        if has_scheduler_lock:
            await _release_scheduler_lock()
        await close_db()


app = FastAPI(
    title="Metal Price Tracker",
    description="JST midnight snapshots for gold, silver, and platinum.",
    version="1.0.0",
    lifespan=lifespan,
    root_path=os.getenv("APP_ROOT_PATH", ""),
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=load_allowed_hosts())
app.add_middleware(
    RateLimitMiddleware,
    requests_per_window=env_int("API_RATE_LIMIT_PER_MINUTE", 120),
    calculate_requests_per_window=env_int("API_CALCULATE_RATE_LIMIT_PER_MINUTE", 60),
    window_seconds=60,
    trust_cf_headers=read_env_bool("TRUST_CF_HEADERS", False),
    require_cf_connecting_ip=read_env_bool("REQUIRE_CF_CONNECTING_IP", False),
    trusted_proxy_cidrs=load_trusted_proxy_cidrs(),
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=500)

# Cloudflare配下では、originがCache-Controlを返さないとCF側が独自のTTLを勝手に
# 付与してしまい(実測で max-age=300 が注入され Age がそれを超える状態になっていた)、
# キャッシュ挙動が読めなくなる。ここでoriginが明示することで、ブラウザ・CFとも
# 意図した通りに振る舞わせる。
#   ?v= 付き … 内容ハッシュ入りURLなので中身が変わればURLも変わる。永久キャッシュ可。
#   ?v= 無し … sw.jsのプリキャッシュ等が使う素のURL。短命にして取り直させる。
STATIC_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
STATIC_DEFAULT_CACHE_CONTROL = "public, max-age=300, must-revalidate"


class VersionedStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        """静的ファイル配信にCache-Controlをoriginから明示的に付ける。

        StaticFilesを素のままmountするとCache-Controlを返さず、
        Cloudflare配下では独自TTL(実測でmax-age=300、Ageがそれを
        はるかに超える不整合)を勝手に注入され、更新が反映されずService
        Workerの手動Unregisterが必要になる事故が起きた。?v=付き(内容ハッシュ)は
        1年キャッシュ可能、?v=無しの素のURL(sw.jsのプリキャッシュ等が使う)
        は短命+must-revalidateにして、originが常に鮮度の主導権を握る。
        """
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            query = scope.get("query_string", b"").decode("latin-1", "ignore")
            versioned = any(part.startswith("v=") and len(part) > 2 for part in query.split("&"))
            response.headers["Cache-Control"] = (
                STATIC_IMMUTABLE_CACHE_CONTROL if versioned else STATIC_DEFAULT_CACHE_CONTROL
            )
        return response


app.mount("/static", VersionedStaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """422バリデーションエラーを全エンドポイント共通で人間向けの1文字列に畳み込む。

    アプリ全体に対する例外ハンドラなので、新しいエンドポイントを追加しても
    個別にエラー整形を書く必要がない。畳み込みの中身(なぜ配列のままだと
    フロントで壊れるか)は直下のコメント参照。
    """
    # FastAPI/Pydanticの既定422レスポンスは detail がオブジェクト配列になり、
    # フロント側でそのまま文字列化すると "[object Object]" のように壊れて見える。
    # ここで常に人間向けの一文字列へ畳み込んでから返す。
    errors = exc.errors()
    if errors:
        first = errors[0]
        field = ".".join(str(p) for p in first.get("loc", []) if p not in ("query", "body", "path"))
        msg = first.get("msg") or "入力値が不正です。"
        message = f"{field}: {msg}" if field else msg
    else:
        message = "入力値が不正です。"
    return JSONResponse({"detail": message}, status_code=422)


NO_STORE_CACHE_CONTROL = "no-store, no-cache, must-revalidate, max-age=0"

APP_JS_FILE = STATIC_DIR / "app.js"
STYLES_CSS_FILE = STATIC_DIR / "styles.css"


def _index_response() -> HTMLResponse:
    """index.html配信の共通処理。index/index_html/fallback_pageの3ルートから呼ぶ。

    3つの入口が同じヘッダ・同じレンダリングを共有することで、SPAへどこから
    入っても挙動が揃う(1箇所だけno-storeを付け忘れる、といった食い違いを
    構造的に防ぐ)。ヘッダの理由自体は直下のコメント参照。
    """
    # index.html自体は常にno-storeで配らせ、その中に埋め込む app.js / styles.css の
    # `?v=` を内容ハッシュへ差し替える。手動でのバージョン更新が不要になり、
    # 「中身は新しいのにURLが同じでキャッシュが効き続ける」事故を構造的に防ぐ。
    return HTMLResponse(
        render_index_html(INDEX_FILE, APP_JS_FILE, STYLES_CSS_FILE),
        headers={"Cache-Control": NO_STORE_CACHE_CONTROL},
    )


@app.get("/", include_in_schema=False)
async def index() -> HTMLResponse:
    """SPAのエントリーポイント。ルート `/` は常にindex.htmlを返す。"""
    return _index_response()


@app.get("/index.html", include_in_schema=False)
async def index_html() -> HTMLResponse:
    """`/index.html` への直リンク・ブックマークも `/` と同じindex.htmlを返す。"""
    return _index_response()


@app.get("/sw.js", include_in_schema=False)
async def service_worker() -> PlainTextResponse:
    """Service WorkerのJSを配信する。ビルド成果物ではなく、配信時にCACHE_NAME等を差し込んで生成する。

    no-storeで配ることで、sw.js自体の更新をブラウザのService Worker更新
    チェックに必ず新しい中身として見せる。CACHE_NAMEをハッシュから生成する
    理由は直下のコメント参照(手動更新忘れで古いキャッシュが破棄されない
    事故が過去に起きている)。
    """
    # CACHE_NAME も内容ハッシュから生成する。アセットが変わったときだけ名前が変わり、
    # activate時に古いキャッシュが確実に破棄される(手動更新漏れが起きない)。
    return PlainTextResponse(
        render_service_worker(SW_FILE, APP_JS_FILE, STYLES_CSS_FILE),
        media_type="application/javascript",
        headers={
            "Cache-Control": NO_STORE_CACHE_CONTROL,
            "Service-Worker-Allowed": APP_PUBLIC_ROOT,
        },
    )


@app.get("/manifest.webmanifest", include_in_schema=False)
async def manifest() -> FileResponse:
    """PWAのWebアプリマニフェストを配信する。

    キャッシュ秒数はPURITY_OPTIONS_CACHE_SECONDSを流用する。マニフェスト・
    純度区分のどちらも実行中に変わらない静的な設定値という点で性質が同じ
    ため専用の環境変数を増やさなかった。裏を返すと、片方だけキャッシュ期間を
    変えたいつもりでこの変数を触ると、もう一方の配信も一緒に変わる。
    """
    return FileResponse(
        MANIFEST_FILE,
        media_type="application/manifest+json",
        headers=_cache_headers(PURITY_OPTIONS_CACHE_SECONDS),
    )


@app.get("/health")
async def health() -> dict[str, str]:
    """死活監視用の固定応答。DBやキャッシュには一切触れない。

    Depends(get_db_session)を使わないのは意図的。DBが落ちている間も
    プロセス自体は生きていることを区別できるようにするためで、ここに
    DB疎通チェックを足すとDB障害時にアプリごと再起動される側の判断材料が
    失われる。
    """
    return {"status": "ok"}


@app.get("/api/prices/history")
async def price_history(
    days: int = Query(default=365, ge=7, le=3650),
    all_time: bool = Query(default=False, alias="all"),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """価格履歴を返す。プリセット日数モードとstart/endのカスタム範囲モードを1本の関数で扱う。

    カスタム範囲は未来日・前後逆転・過大なスパンをここで安全な範囲へ丸める。
    フロント側にも同等のバリデーションはあるが、それはUXのためのものに
    過ぎず、ここでの丸めが実際の安全装置になる(クライアントを経由しない
    直接リクエストは丸めを素通りできない)。cache_keyの形式がモードごとに
    違う(custom:開始:終了 / all / 日数)のは、同じ日に別条件のリクエストが
    互いのキャッシュを踏まないようにするため。
    """
    today = datetime.now(JST).date()
    is_custom_range = start is not None or end is not None

    if is_custom_range:
        # 「いつからいつまで」を自由に指定して遡れるようにするカスタム範囲。
        # 未来日・開始/終了の前後逆転・過大なスパンはここで安全な範囲に丸める。
        range_end = min(end, today) if end is not None else today
        range_start = start if start is not None else (range_end - timedelta(days=364))
        if range_start > range_end:
            range_start, range_end = range_end, range_start
        range_end = min(range_end, today)
        earliest_allowed = range_end - timedelta(days=3649)
        if range_start < earliest_allowed:
            range_start = earliest_allowed
        effective_days = (range_end - range_start).days + 1
        cache_key = f"history:{today.isoformat()}:custom:{range_start.isoformat()}:{range_end.isoformat()}"
    else:
        range_end = today
        effective_days = days
        if all_time:
            earliest = await load_earliest_snapshot_date(session)
            if earliest is not None:
                # サーバが記録している最古のスナップショットまでを1回のクエリで
                # 取得できるようdaysを動的に計算する(取得可能な全期間を参照したい、
                # というユーザー要望への対応)。
                effective_days = min(3650, max(7, (today - earliest).days + 1))
        range_start = range_end - timedelta(days=effective_days - 1)
        cache_key = f"history:{today.isoformat()}:{'all' if all_time else effective_days}"

    cached = await history_cache.get(cache_key)
    if cached is not None:
        return JSONResponse(cached, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))

    history = await load_history(session, effective_days, end_date=range_end)
    latest_snapshot = await _get_latest_prices(session)
    latest = _latest_prices_public(latest_snapshot)
    payload = {
        "timezone": "Asia/Tokyo",
        "snapshot_policy": "daily_at_jst_midnight",
        "range_start": range_start.isoformat(),
        "range_end": range_end.isoformat(),
        "days": effective_days,
        "all_time": all_time,
        "custom_range": is_custom_range,
        "metals": history,
        "latest": latest,
    }
    await history_cache.set(cache_key, payload)
    return JSONResponse(payload, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))


@app.get("/api/prices/forecast-weekly")
async def weekly_forecast(
    days: int = Query(default=7, ge=1, le=7),
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """週次予測を返す。鮮度管理はforecast_cacheに任せ、HTTP層は常にno-storeにする。

    予測はJST 0時の他、FORECAST_REFRESH_EXTRA_HOURS_JSTの時刻にも日中
    強制更新され、更新のたびcollect_weekly_forecast_cacheがforecast_cacheを
    clearする。ここでブラウザ/CDNにTTL付きキャッシュを許すと、intraday更新
    が反映されるまでその分だけ古い予測を見せ続けることになるため、
    price_historyの_cache_headersとは違いno-storeで固定している。
    """
    cache_key = f"forecast:{datetime.now(JST).date().isoformat()}:{days}"
    cached = await forecast_cache.get(cache_key)
    if cached is not None:
        return JSONResponse(
            cached,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
        )

    payload = await load_stored_weekly_forecast(session, days=days)
    if payload is None:
        raise HTTPException(
            status_code=503,
            detail="予測データがまだありません。次回の予測更新後に利用できます。",
        )

    await forecast_cache.set(cache_key, payload)
    return JSONResponse(
        payload,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/api/purity/options")
async def purity_options() -> JSONResponse:
    """金属ごとの純度区分一覧を返す。PURITY_OPTIONS_PAYLOADはMETAL_COMMANDS由来でモジュール読込時に組み立て済み。

    リクエストのたびに辞書内包表記をやり直さない(値は起動中変わらない)。
    キャッシュ秒数manifest()と共有している点はそちらのdocstring参照。
    """
    return JSONResponse(PURITY_OPTIONS_PAYLOAD, headers=_cache_headers(PURITY_OPTIONS_CACHE_SECONDS))


@app.get("/api/push/public-key")
async def push_public_key() -> JSONResponse:
    """VAPID公開鍵とPush通知の有効可否をクライアントに伝える。

    enabledはis_push_enabled()とpublic_key is not Noneの両方を見て決める。
    どちらか一方だけで判定すると、鍵はあるのに機能自体が無効(または鍵の
    生成に失敗しているだけで機能自体は有効)という食い違った状態で購読
    ボタンが誤って有効/無効に見えてしまう。
    """
    public_key = get_vapid_public_key()
    enabled = is_push_enabled() and public_key is not None
    reason = None if enabled else "vapid_not_configured_or_generation_failed"
    return JSONResponse(
        {
            "enabled": enabled,
            "public_key": public_key if enabled else None,
            "notify_time_jst": f"{PUSH_NOTIFY_HOUR_JST:02d}:{PUSH_NOTIFY_MINUTE_JST:02d}",
            "reason": reason,
        },
        headers=_cache_headers(PUSH_PUBLIC_KEY_CACHE_SECONDS),
    )


@app.post("/api/push/subscribe")
async def push_subscribe(
    payload: PushSubscribeRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, bool]:
    """ブラウザのPush購読を登録/更新する。同一endpointへの競合登録はIntegrityErrorを無害化して吸収する。

    存在チェック(SELECT)と新規挿入の間に、別リクエストが同じendpointを
    先に挿入すると、endpointのUNIQUE制約(uq_push_subscription_endpoint)に
    ぶつかる。ページ再読み込み・複数タブ・Service Workerの購読再試行では
    同一endpointへの同時リクエストが実際に起こり得るため、ここで
    IntegrityErrorを握りつぶして成功扱いにする(再度呼ばれればSELECTで
    拾えるようになる)。
    """
    if not is_push_enabled():
        raise HTTPException(status_code=503, detail="Push通知が無効です。VAPID設定を確認してください。")

    endpoint = _validate_push_endpoint(payload.endpoint)
    existing = (await session.scalars(select(PushSubscription).where(PushSubscription.endpoint == endpoint))).first()
    if existing:
        existing.p256dh_key = payload.keys.p256dh
        existing.auth_key = payload.keys.auth
        existing.user_agent = request.headers.get("user-agent")
    else:
        current_count = await session.scalar(select(func.count(PushSubscription.id)))
        if int(current_count or 0) >= PUSH_MAX_SUBSCRIPTIONS:
            raise HTTPException(status_code=429, detail="Push購読数が上限に達しています。")
        session.add(
            PushSubscription(
                endpoint=endpoint,
                p256dh_key=payload.keys.p256dh,
                auth_key=payload.keys.auth,
                user_agent=request.headers.get("user-agent"),
            )
        )

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        logger.debug("push_subscribe: 同一エンドポイントの重複リクエストを無視")
    return {"ok": True}


@app.post("/api/push/unsubscribe")
async def push_unsubscribe(
    payload: PushUnsubscribeRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, int | bool]:
    """指定endpointのPush購読を解除する。存在しない/既に削除済みのendpointでも成功扱いにする冪等な操作。

    rowcountの扱いについては直下のコメント参照。
    """
    result = await session.execute(
        delete(PushSubscription).where(PushSubscription.endpoint == payload.endpoint.strip())
    )
    await session.commit()
    # rowcount は返さないドライバがある。or 0 を外すと int(None) で
    # TypeError になり、購読解除が 500 で落ちる。型検査を黙らせるために
    # 外してよい保険ではない。
    return {"ok": True, "deleted": int(result.rowcount or 0)}  # type: ignore[attr-defined]


@app.get("/api/prices/calculate")
async def calculate_by_purity(
    metal: str = Query(..., min_length=1),
    grams: float = Query(..., gt=0, le=100000),
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """指定した金属とグラム数から地金価値を純度区分ごとに計算する。

    最新価格はDB由来のDecimal文字列のまま取り出し、掛け算もDecimalで
    行ってから最後にintへ切り捨てる。floatを一度でも経由すると桁落ちが
    起きうるため、_get_latest_pricesが内部表現をstrに保っているのと同じ
    理由でここでもfloat変換を最後まで遅らせる。円に小数単位が無いため
    int()で切り捨てる(四捨五入ではないので、表示額が実勢よりわずかに
    高く見えることはない)。
    """
    metal_key = metal.strip().lower()
    spec = METAL_COMMANDS.get(metal_key)
    if spec is None:
        raise HTTPException(
            status_code=400,
            detail="metal は gold/silver/platinum のいずれかを指定してください。",
        )

    latest_snapshot = await _get_latest_prices(session)
    latest_row = latest_snapshot.get(metal_key, {})
    snapshot_date = latest_row.get("date")
    price_per_gram_raw = latest_row.get("price_per_gram")
    if snapshot_date is None or price_per_gram_raw is None:
        raise HTTPException(
            status_code=503,
            detail="価格データがまだありません。日次取得完了後に再実行してください。",
        )

    grams_decimal = Decimal(str(grams))
    grams_key = f"{grams_decimal:.4f}"
    cache_key = f"calculate:{snapshot_date}:{metal_key}:{grams_key}"
    cached = await calculate_cache.get(cache_key)
    if cached is not None:
        return JSONResponse(cached, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))

    price_per_gram = Decimal(price_per_gram_raw)
    pure_value = int(price_per_gram * grams_decimal)
    by_purity = {
        grade: int(price_per_gram * grams_decimal * Decimal(str(ratio))) for grade, ratio in spec.purity.items()
    }

    payload = {
        "metal": metal_key,
        "display_name": spec.display_name,
        "snapshot_date": snapshot_date,
        "price_per_gram": float(price_per_gram),
        "grams": grams,
        "pure_value": pure_value,
        "by_purity": by_purity,
    }
    await calculate_cache.set(cache_key, payload)
    return JSONResponse(payload, headers=_cache_headers(API_RESPONSE_CACHE_SECONDS))


@app.get("/{page_path:path}", include_in_schema=False)
async def fallback_page(page_path: str) -> HTMLResponse:
    """SPAのクライアントサイドルーティング用フォールバック。予約パス以外は全てindex.htmlを返す。

    フロントのJSルーターが処理する/settingsや/historyのようなパスは
    サーバ側にルートが無いため、ここで拾ってSPAシェルを返す。api/static/
    health等のRESERVED_TOP_LEVEL_PATHS配下でマッチしなかったURL(例:
    存在しないAPIパスの typo)まで無条件にindex.htmlを返すと、クライアント
    が本物の404と区別できず原因不明の挙動になるため、予約済みの先頭
    セグメントだけは通常の404を返す。
    """
    first = page_path.split("/", 1)[0] if page_path else ""
    if first in RESERVED_TOP_LEVEL_PATHS:
        raise HTTPException(status_code=404, detail="Not Found")
    return _index_response()
