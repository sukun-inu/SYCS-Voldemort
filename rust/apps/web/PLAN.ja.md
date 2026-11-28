# Web（貴金属の公開サイト。rust-05）を Rust へ移す計画（W3）

読んだ元: `snapshot-main6`（main 57ea39c）の `web_main.py`・`webapp/`（app.py・asset_version.py・cache.py・db.py・
security.py・snapshot_service.py・repair_service.py・forecast_*.py・push_service.py・vapid_service.py・models.py・
static/）・`services/`（shared_cache・metal_service・groq_client・url_safety・log_setup・metrics_reporter）・
`config.py`・`docker-compose.yml`・`migrations/`・`tests/test_webapp*.py`。親の計画 `staging\WEB_PLAN.md`、
管理画面の計画 `staging\w2prep\ADMIN_PLAN.md`、並んで動いている w01（`sycs-web`・nginx）の置き場も読んだ。
手元では何も動かしていない。**「見立て」と書いたところは、読んだコードと記憶からの推定で、基準（CI）で確かめる。**

## 0. 要約

- Python の Web は、経路 13 本（`/`・`/index.html`・SPA の受け皿・`/sw.js`・`/manifest.webmanifest`・`/health`・
  API 7 本）と `/static`、FastAPI が自動で出す文書 3 本（`/docs`・`/redoc`・`/openapi.json`）。背景の処理は 4 本の
  定期の仕事（JST 0:00 の取り込みと予測・6/12/18 時の予測の作り直し・11:00 のプッシュ通知・30 分ごとの修復）と
  起動時の仕事で、Postgres の advisory lock を取れた 1 つのワーカーだけが受け持つ
- **nginx が直接返せるもの**: `/static/*`・`/manifest.webmanifest` はそのまま返せる。`/sw.js` と index.html（`/`・
  `/index.html`・SPA の受け皿）は Python が中身を書き換えて返しているので、実行時の nginx だけでは返せない。
  ただし書き換えの結果は 3 つのファイル（app.js・styles.css・sw.js）の中身だけで決まるので、**nginx のイメージを
  作るときに書き換えておけば nginx が返せる**（推す。7.）。そうすると Rust に残るのは `/api/*`・`/health` と背景の処理
- Rust で難しいのは見た目より「同じ数を出す」ところ: Python の Decimal（28 桁の文脈）・float の書き方（repr）・
  `round(x, n)`・`statistics.pstdev`（分数で正確に計算する）・pydantic の 422 の言葉・FastAPI の経路の選び方
  （HEAD を受けない・% を戻してから選ぶ）。どれも基準で確かめる
- 塊は 9 つ（9.）。段ごとに 2 体で並べる。この塊で、API の基準の作り方の型（`rust/apps/web/tests/fixtures/
  web_harness.py` と最初の 1 つ `prices_calculate/`）を作った（8.）

---

## 1. いまの作り（Python）

### 1.1 プロセスと起動

- `web_main.py` → `uvicorn webapp.app:app`。`WEB_WORKERS`（既定 2）のプロセス、`WEB_PORT`（既定 8000）、
  `proxy_headers=True`・`forwarded_allow_ips=TRUSTED_PROXY_CIDRS`（既定 `127.0.0.1/32,::1/128,172.16.0.0/12`）。
  **アプリが見る `request.client` は、uvicorn が X-Forwarded-For で直したあとのもの**（直し方は w01 の
  `sycs-web::proxy::resolve` と、その基準 `sycs-web/tests/fixtures/proxy/` が決める）
- ログ: `SETTINGS_DIR/logs/web.log` と `web.jsonl`。`webapp.*` のロガーはカテゴリ `web`（services/log_setup.py）
- compose: ホストの `WEB_HOST_PORT`（既定 8001）→ 8000。`read_only: true`、tmpfs `/tmp`、ボリュームは
  `app_data:/app/data` と `shared_secrets:/shared`（VAPID の鍵と Postgres のパスワード）。Postgres（healthy）と
  Valkey（started）のあと
- ワーカーごとの lifespan（`webapp/app.py` の `lifespan`）。順に意味がある:
  1. `loop_watchdog.install()`（イベントループの停止の見張り。Rust では要らない）
  2. `init_db()`（Alembic の upgrade head。advisory lock 721045777 で直列）
  3. `refresh_vapid_config()`（VAPID の鍵を読み、無ければ作る。6.1）
  4. `WEB_SCHEDULER_ENABLED`（既定 true）なら advisory lock 721045501 を取りに行く（`pg_try_advisory_lock`。
     取った接続を持ち続ける）。取れたワーカーだけ **起動時の仕事（`_run_startup_jobs`）を await してから**
     スケジューラを動かす（その間このワーカーは要求を受けない。もう 1 つのワーカーが受ける）
  5. 見張り（`_watch_scheduler_lock`。60 秒ごと〔`WEB_SCHEDULER_LOCK_CHECK_SECONDS`〕に `SELECT 1`。切れていたら
     スケジューラを止め、接続を `invalidate()` で捨てて取り直す。持っていないワーカーも取りに行く〔引き継ぎ〕。
     引き継いだときは起動時の仕事を走らせない）
  6. メトリクスの報告（`report_forever("web-<pid>", 30 秒, ゲージ web_cache_items_{history,latest,calculate,forecast}`）
     ＝一次キャッシュの件数）。全ワーカーで
  - 終わり: メトリクス → 見張り → スケジューラ（`shutdown(wait=False)`）→ lock を外す → `close_db()`
- **Rust は 1 プロセス**でよい（tokio のスレッドで足りる。ワーカーを分ける理由が無い）。ただし advisory lock は
  同じ鍵のまま残す（切り替えの間に Python の Web と Rust の Web が同時に動いても、定期の仕事は片方だけになる。
  MetalpriceAPI の無料枠〔月 100 回〕を倍に使わない）

### 1.2 ミドルウェアの順（外から内へ）

`app.add_middleware` は前へ差し込むので、書いた順の逆が外側になる:

```text
ServerErrorMiddleware（starlette。素の 500）
 └ GZipMiddleware（minimum_size=500）
    └ SecurityHeadersMiddleware（見出し 8 つ。1.4）
       └ RateLimitMiddleware（/api/ だけ。1.6）
          └ TrustedHostMiddleware（ALLOWED_HOSTS）
             └ ExceptionMiddleware（HTTPException と RequestValidationError の係）
                └ 経路（FastAPI の router。/static は mount）
```

ここから出てくること（どれも基準 `prices_calculate` に例がある）:

- 許さない Host の要求（400）にも見出しが付き、**/api/ ならレート制限の数えに入る**（制限が外側にあるため）
- 429 にも見出しが付く。500 には付かない（ServerErrorMiddleware が一番外）
- GZip は 500 バイト以上の本文だけ。圧縮しないときも 500 バイト以上なら `Vary: Accept-Encoding` を付ける
  （starlette の版による。見立て。history の基準で確かめる）

### 1.3 エラーの応答

| 場合 | 状態 | 本文 | 見出し |
|---|---|---|---|
| 入力の検証（RequestValidationError） | 422 | `{"detail":"<loc>: <msg>"}`（最初の誤りだけ。loc から query・body・path を除いて `.` で繋ぐ。loc が空なら msg だけ。誤りが無ければ「入力値が不正です。」） | 8 つ |
| HTTPException（400・404・429・503 など） | その数 | `{"detail":"…"}` | 8 つ（405 は Allow も） |
| 予約の先頭（api・static・health・docs・redoc・openapi.json・sw.js・manifest.webmanifest）で経路が無い | 404 | `{"detail":"Not Found"}` | 8 つ |
| 経路はあるがメソッドが違う（HEAD も。FastAPI の GET は HEAD を足さない。見立て） | 405 | `{"detail":"Method Not Allowed"}` | 8 つ＋`Allow` |
| 許さない Host | 400 | `Invalid host header`（text/plain） | 8 つ |
| レート制限 | 429 | `{"detail":"Too Many Requests"}` | 8 つ＋`Retry-After: 60` |
| `REQUIRE_CF_CONNECTING_IP` で CF-Connecting-IP が無い（本番は false） | 403 | `{"detail":"Forbidden"}` | 8 つ |
| 捕まえていない例外 | 500 | `Internal Server Error`（text/plain） | 無し |

JSON の書き方は starlette の JSONResponse（`ensure_ascii=False`・`separators=(",", ":")`・`allow_nan=False`）。
**float は Python の repr で書く**（`1e-05`・`10.0`・`0.30000000000000004`。serde_json は `1e-5` と書く）。
NaN が入ると 500（`allow_nan=False`）。

### 1.4 見出し（`SecurityHeadersMiddleware`。全部の応答に。500 以外）

```text
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; …
```

CSP の全文は `webapp/security.py` のとおり（基準の応答にも全文が出る）。Cache-Control は経路ごと（2.）:
`_cache_headers(n)` ＝ `public, max-age=n, s-maxage=n, stale-while-revalidate=n`、no-store ＝
`no-store, no-cache, must-revalidate, max-age=0`。

### 1.5 応答のキャッシュ（`webapp/cache.py` の TTLCache。一次＝プロセス内、二次＝Valkey）

| 名前 | 名前空間 | 鍵 | 期限 | 件数 | 消す時 |
|---|---|---|---|---|---|
| history_cache | `web:history` | `history:<今日>:<custom:<始め>:<終わり>｜all｜<日数>>` | 20 秒（`API_RESPONSE_CACHE_SECONDS`） | 64 | 取り込み・修復のあと |
| latest_prices_cache | `web:latest` | `latest:<今日>` | 20 秒 | 8 | 同上 |
| calculate_cache | `web:calculate` | `calculate:<行の日付>:<金属>:<grams を Decimal(str) にして .4f>` | 20 秒 | 1024 | 同上 |
| forecast_cache | `web:forecast` | `forecast:<今日>:<日数>` | 1800 秒（`FORECAST_CACHE_SECONDS`） | 32 | 予測を作り直したあと・取り込み・修復のあと |

- 「今日」は JST（`datetime.now(JST).date()`）
- 一次を見て、無ければ二次、二次で見つかれば一次へ既定の期限で書き戻す。書くときは一次 → 二次。
  消すときは一次を全部と、二次の名前空間を SCAN＋DEL
- Valkey の鍵は `sycs:<名前空間>:<鍵>`（例 `sycs:web:latest:latest:2026-11-28`）、値は JSON
  （`separators=(",", ":")`・`ensure_ascii=False`）、`SET … EX <期限>`。Valkey が落ちたら 30 秒は使わない（遮断器）
- latest の中身は **値段を文字列のまま**（`{"gold":{"date":"2026-11-27","price_per_gram":"21345.6789",
  "delta_from_previous":"-123.4500"},…}`）。計算がこれを Decimal に戻して使う。ほかの 3 つは応答の JSON そのもの
- **Rust も同じ名前空間・同じ鍵・同じ JSON の形にする**（推す。切り替えの間に両方が動いても、互いの値を読んで
  食い違わない。11. の 8）

### 1.6 レート制限（`RateLimitMiddleware`）

- パスが `/api/` で始まる要求だけ。枠は 2 つ: `/api/prices/calculate` は calculate（`API_CALCULATE_RATE_LIMIT_PER_MINUTE`、
  既定 60）、ほかは default（`API_RATE_LIMIT_PER_MINUTE`、既定 120）。窓は 60 秒の移動窓。**断った回は数えない**
- 数える相手（`_extract_client_ip`）: 接続元（`request.client.host`。ポートと角括弧を外して ipaddress の書き方に
  揃える。読めなければ `unknown`）が信頼するプロキシの帯域に入るときだけ、`TRUST_CF_HEADERS`（本番 false）なら
  CF-Connecting-IP → X-Real-IP → X-Forwarded-For の先頭、の順に見る。帯域の外から X-Forwarded-For が来たら、
  接続元ごとに 1 回だけ警告のログ
- 数える場所: Valkey が使えれば ZSET（`sycs:ratelimit:api:<calculate|default>:<IP>`。古いものを ZREMRANGEBYSCORE で
  落とし、ZCARD、ZADD〔member は `<時刻>:<uuid4 の hex>`〕、EXPIRE 61 を 1 往復。上限を超えたら足した 1 件を ZREM）。
  **score は `time.monotonic()`**（同じホストの全プロセスで同じ時計）。使えなければプロセス内の deque
- Rust: Valkey の ZSET も同じ鍵・同じ手順にする。score の時計は Linux の CLOCK_MONOTONIC を rustix で読む（推す。
  `std::time::Instant` は値を外に出せない。Python と同時に動いても同じ窓になる。11. の 5）

### 1.7 DB（Postgres の `metal_prices`）

- 接続先は `webapp/db.py` の `_build_database_url`: `POSTGRES_DSN` → `POSTGRES_USER`（postgres）・`POSTGRES_PASSWORD` か
  `POSTGRES_PASSWORD_FILE`（無ければ postgres）・`POSTGRES_HOST`（localhost）・`POSTGRES_PORT`（5432）・`POSTGRES_DB`
  （metal_prices）。**`sycs_core::db`（USER_STATE_* が先、既定の DB は user_state_audit）とは順も既定も違う**ので、
  Web 用の組み立てを別に書く。プールは 5＋10、recycle 1800 秒、pre_ping
- 表: `metal_price_daily`（金属・日付で一意。値段と前日差は numeric(18,4)）・`push_subscription`・
  `notification_dispatch`（種類・日付で一意）・`weekly_forecast_meta`・`weekly_forecast_daily`・`forecast_accuracy_log`
  （ほかに 0002 の user_state_* もあるが Web は使わない）。`updated_at` は SQLAlchemy の `onupdate=func.now()`
  （**ORM が UPDATE に足している**。Rust の UPDATE は `updated_at = now()` を自分で書く）
- 移行は Alembic（0001〜0005。head は `0005`）。Rust は移行をしない（11. の 3）
- numeric は SQL で `::text` にして読む（Postgres の numeric の文字列は桁を保つ。asyncpg の Decimal を str にした
  ものと同じ `21345.6789`・`7123.0000`）

---

## 2. 経路の一覧

GET の経路はどれも HEAD を受けない（見立て。基準 `prices_calculate` の `head_request`）。

| 経路 | 入力 | 出力 | Cache-Control など | サーバーのキャッシュ | 制限の枠 | 使うもの |
|---|---|---|---|---|---|---|
| `GET /`・`GET /index.html`・`GET /{page_path:path}`（予約の先頭は 404） | — | index.html の `static/app.js?v=…`・`static/styles.css?v=…` を、app.js と styles.css の中身の sha256 の頭 12 桁に書き換えたもの（`render_index_html`） | text/html; charset=utf-8、no-store | 書き換えの結果を、ファイルの mtime・大きさが変わるまで覚える | 無し | asset_version.py |
| `GET /sw.js` | — | `const CACHE_NAME = "…"` を `metal-tracker-<sha256(app.js・styles.css・sw.js)[:12]>` に（`render_service_worker`） | application/javascript、no-store、`Service-Worker-Allowed: <APP_PUBLIC_PATH を / で挟んだもの>` | 同上 | 無し | 同上 |
| `GET /manifest.webmanifest` | — | ファイルそのまま（FileResponse） | application/manifest+json、`_cache_headers(PURITY_OPTIONS_CACHE_SECONDS＝3600)`、ETag・Last-Modified | — | 無し | — |
| `/static/{path}`（mount。GET・HEAD） | — | ファイルそのまま（StaticFiles。Range も） | **200 のときだけ**: クエリを `&` で割った中に `v=` で始まり 3 文字以上のものがあれば `public, max-age=31536000, immutable`、無ければ `public, max-age=300, must-revalidate` | — | 無し | VersionedStaticFiles |
| `GET /health` | — | `{"status":"ok"}`（DB に触らない） | — | — | 無し | — |
| `GET /api/prices/history` | `days` int 7〜3650（365）・`all` bool（false）・`start`・`end` date | timezone・snapshot_policy・range_start・range_end・days・all_time・custom_range・metals（金属ごとの日次）・latest | `_cache_headers(20)` | history・latest | default | `load_earliest_snapshot_date`・`load_history`・`load_latest_rows` |
| `GET /api/prices/forecast-weekly` | `days` int 1〜7（7） | 保存済みの予測（日数で切る）／503「予測データがまだありません。次回の予測更新後に利用できます。」 | no-store | forecast | default | `load_stored_weekly_forecast` |
| `GET /api/purity/options` | — | 金属ごとの表示名と純度の並び（import のときに作った定数） | `_cache_headers(3600)` | — | default | config.METAL_COMMANDS |
| `GET /api/push/public-key` | — | `{"enabled","public_key","notify_time_jst":"HH:MM","reason"}`（無効なら public_key は null、reason は `vapid_not_configured_or_generation_failed`） | `_cache_headers(PUSH_PUBLIC_KEY_CACHE_SECONDS＝3600、下限 300)` | VAPID の設定をプロセスで 1 回読む | default | vapid_service |
| `POST /api/push/subscribe` | JSON: endpoint 1〜4096・keys.p256dh 1〜2048・keys.auth 1〜2048・expirationTime int/null。User-Agent | `{"ok":true}`／503（無効）／400（URL）／429（上限 `PUSH_MAX_SUBSCRIPTIONS`＝50000） | 無し | — | default | url_safety（DNS を引く）・push_subscription |
| `POST /api/push/unsubscribe` | JSON: endpoint 1〜4096 | `{"ok":true,"deleted":n}` | 無し | — | default | push_subscription |
| `GET /api/prices/calculate` | `metal` str 1 文字以上・`grams` float 0 より大きく 100000 以下 | metal・display_name・snapshot_date・price_per_gram（float）・grams（受けた float）・pure_value・by_purity（int） | `_cache_headers(20)` | latest・calculate | calculate | `load_latest_rows` |
| `/docs`・`/docs/oauth2-redirect`・`/redoc`・`/openapi.json`（FastAPI の自動） | — | Swagger UI・ReDoc・OpenAPI の JSON | — | — | 無し | FastAPI |

細かいところ:

- **calculate**: `metal.strip().lower()`（Python の strip は U+3000・U+001C〜U+001F も落とす）。値段は latest の
  文字列を Decimal に戻し、`int(price × Decimal(str(grams)))`、純度は `int(price × grams × Decimal(str(ratio)))`
  （**左から順に掛け、掛けるたびに 28 桁へ丸める**。int は 0 へ切り捨て）。行が無い・値段が無いと 503
  「価格データがまだありません。日次取得完了後に再実行してください。」、金属が無いと 400
  「metal は gold/silver/platinum のいずれかを指定してください。」
- **history**: 範囲の指定（start か end があれば custom）: 終わり＝min(end, 今日)（無ければ今日）、始め＝start
  （無ければ終わり−364 日）、逆なら入れ替え、終わりをもう一度 min(…, 今日)、始めは終わり−3649 日より前にしない、
  日数＝差＋1。custom でないとき: all なら `min(3650, max(7, 今日−最古の日＋1))`（最古が無ければ days のまま）。
  **custom のときも days の検証は効く**（days=1 は 422）。metals は gold・silver・platinum の順に空の並びを作り、
  知らない金属の行は後ろに足す。値段は float、前日差は float か null
- **forecast-weekly**: 保存済みが無いと 503。キャッシュの中身は切ったあとのもの
- **push/subscribe**: 無効（鍵が無い）なら先に 503。endpoint は strip してから URL の確かめ
  （`validate_public_http_url_async(allow_http=False)`。公開でない IP を弾く。名前を引く）、host が無ければ 400、
  `PUSH_ALLOWED_ENDPOINT_SUFFIXES` があればその内だけ。同じ endpoint があれば鍵と User-Agent を書き換え、無ければ
  数えて上限なら 429、足す。commit が IntegrityError（同時の登録）なら rollback して成功にする
- **push/unsubscribe**: 有効かどうかも URL も確かめない。strip した endpoint で DELETE。rowcount が無いドライバでも 0

---

## 3. 入力の検証（pydantic と同じ言葉）

- 422 の本文は「最初の誤り 1 つ」。pydantic 2 の言葉そのまま（`Field required`・`Input should be greater than 0`・
  `Input should be less than or equal to 100000`・`String should have at least 1 character`・
  `Input should be a valid number, unable to parse string as a number`・`Input should be a valid integer, …`・
  `Input should be a valid boolean, …`・`Input should be a valid date or datetime, …` など）。JSON の本文の誤りは
  loc が `("body", 位置)` なので `"<位置>: JSON decode error"` のような形になる（見立て。push の基準で確かめる）
- クエリの読み方は starlette（`parse_qsl`。`+` は空白、`%xx` を戻す、同じ名前が 2 つあれば `QueryParams.get` の
  1 つ〔見立てでは後ろ〕）。空の値（`metal=`）は「無い」ではなく空文字として検証する（Form だけが例外）
- Rust は pydantic を丸ごと写さない。**基準に出てくる入力の形について、同じ状態と同じ言葉を返す**小さな検証を
  型ごと（int の範囲・float の範囲・str の長さ・bool・date）に書く。float の読み方（`nan`・`inf`・`1_000`・
  前後の空白・`+10`・`0x10`・`10.`・`.5`）と date の読み方（`2026-11-28` 以外に何を受けるか）は基準で決まる
  （`prices_calculate` に float の例を入れてある。date は history の基準で入れる）

---

## 4. 相場（取り込み・修復・履歴）

### 4.1 取り込み（`store_snapshot`。JST の今日）

1. その日の行を読む。`skip_if_exists`（既定）で 3 つ揃っていれば何もしない（API を呼ばない）
2. `fetch_metal_prices_per_gram(["XAU","XAG","XPT"])`（`services/metal_service.py`）: プロセス内のキャッシュ
   （`METALPRICE_CACHE_TTL_SECONDS`、既定 1800 秒）に無いものだけ、**1 回の要求で**
   `GET https://api.metalpriceapi.com/v1/latest?api_key=…&base=JPY&currencies=XAU,XAG,XPT`（12 秒）。
   値段＝`rates["JPY<code>"] / 31.1035`。まとめて取れなければ 1 つずつ取り直す。全部だめなら例外
3. 値段は `Decimal(str(float)).quantize(0.0001, ROUND_HALF_UP)`（**str(float) は repr**）。前日差は
   「その日より前で直近の行」との差を同じく丸める（無ければ null）
4. あれば書き換え（値段・前日差・金属のコード）、無ければ足す。commit。取れなかった金属は飛ばす（全部だめなら例外）

- Rust の Bot の `metal.rs` は 1 つずつ取る道だけを移してある（「まとめて取る道は Web の側のもの」と書いてある）。
  W3-5 で共有の crate へ移し、まとめて取る道と個別への逃げ道を足す（Bot は同じ名前で使い続ける）

### 4.2 修復（`repair_metalprice_integrity`。30 分ごと）

1. 今日の行が揃っていなければ、クールダウン（`METAL_REPAIR_RETRY_COOLDOWN_HOURS`、既定 6 時間。プロセス内の時刻）が
   明けていれば `store_snapshot(今日, skip_if_exists=False)`
2. 全履歴を（金属・日付の順に）見て、金属のコードと前日差（1 つ前の行との差を丸めたもの）を直す（API は呼ばない）
3. 数え直す。最新の日付が全金属で同じなら、保存済みの予測の `as_of_date` と比べ、ずれ（日付が違う・必須の項目が
   無い）か `METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH` なら予測を作り直す
4. commit。stats（9 つの数）をログに

### 4.3 読み方（`snapshot_service.py`）

- `load_latest_rows`: 金属ごとの最大の日付の行（GROUP BY のサブクエリと JOIN）
- `load_history(days, end_date)`: 終わり−(days−1) 〜 終わりの行を日付の昇順。値段は float
- `load_earliest_snapshot_date`: `min(snapshot_date)`

### 4.4 小数（Rust で同じ数を出すために）

- Python の Decimal は掛け算ごとに **28 桁（有効数字）へ偶数への丸め**。calculate の掛け算は、値段 18 桁×グラム
  17 桁（float の repr）＝最大 35 桁、28 桁に丸めてから純度（最大 5 桁）を掛けて最大 33 桁。**どれも i128（38 桁）に
  収まる**ので、Rust は整数の仮数と指数で「正確に掛ける → 28 桁へ丸める → 0 へ切り捨てる」を書けば足りる
  （新しい crate は要らない）。基準 `prices_calculate` の `decimal_context_rounds_at_28_digits` が、正確に掛けた
  ときと答えが変わる例（見立て）
- `format(Decimal, ".4f")`（calculate の鍵）と `f"{Decimal:.2f}"`（プッシュの本文）も偶数への丸め。
  `quantize(…, ROUND_HALF_UP)`（取り込み）は四捨五入
- `str(float)`（repr）は Bot の `python_repr::repr_float` がある。`float(Decimal)` は 10 進の文字列から最も近い
  f64（Rust の `str::parse::<f64>` と同じ）

---

## 5. 予測（forecast_*）

### 5.1 いつ作るか

| 時 | 仕事 | 作り直すか |
|---|---|---|
| JST 0:00（`jst_daily_metal_snapshot_and_forecast`、misfire 3600 秒） | 取り込み → 答え合わせ → 予測 | 保存済みの `as_of_date` が今日なら作らない |
| JST 6・12・18 時の 5 分（`FORECAST_REFRESH_EXTRA_HOURS_JST`・`FORECAST_REFRESH_MINUTE_JST`。`jst_intraday_forecast_refresh`、misfire 1800 秒） | 予測 | 必ず作る |
| 修復のとき | 予測 | ずれがあるとき（4.2） |
| 起動時（lock を取れたとき） | 0:00 と同じ | 同上 |

どの仕事も DB の誤り（OperationalError・ProgrammingError）なら `init_db()` をやり直して 1 回だけ再試行する。

### 5.2 材料

- 履歴: `load_history(max(120〔FORECAST_HISTORY_WINDOW_MIN_DAYS〕, 7×20))`＝140 日
- 直近の精度（`load_recent_forecast_error`。14 日）: 金属ごとの平均絶対誤差（MAE%）・傾き無しの MAE・傾きの改善・
  区間の被覆率（SQL の avg・count・sum）
- 為替（`fetch_usdjpy_signal`）: `GET https://api.frankfurter.dev/v1/<UTC の今日−45日>..<UTC の今日>?from=USD&to=JPY`。
  最新と 6 つ前（無ければ最初）の比が週の変化、日の係数＝週の変化÷5、日付つきの日次リターン
- ニュース（`fetch_news_signals`）: 金属ごとの英語の検索語で Google News RSS（3 本を同時に）。先頭 18 件の
  title＋description に、決めた語（`POSITIVE_TOKENS`・`NEGATIVE_TOKENS`。語の境目つきの正規表現）が出た数の差、
  `tanh(差 ÷ max(2, 件数×1.4))`。見出しは先頭 8 件
- HTTP は aiohttp（全体 max(LLM の秒数＋10, 30)・接続 8・読み max(LLM の秒数, 20)。Chrome の User-Agent）

### 5.3 Groq に何を渡し、何を決めさせるか

呼ぶのは 2 回（bucket `forecast`。`services/groq_client.py` の同時の数・間隔・再試行の決まりの中で）。どちらも
`create_json_chat_completion`: モデル `FORECAST_LLM_MODEL`（既定 `openai/gpt-oss-120b`）、
`response_format={"type":"json_object"}`・`reasoning_format="hidden"`・`reasoning_effort`（既定 low）・
`max_completion_tokens`（既定 3000）。**400 が返ったら、この 3 つを外して送り直す**。答えは
`extract_first_json_object`（全体を読み、だめなら最初の `{` 〜最後の `}`）。

1. **判定（`fetch_llm_signal`、temperature 0.15、時間切れ `FORECAST_LLM_TIMEOUT_SECONDS`＝20）**: system は英語の
   固定文（`_llm_prompts`）、user は `Inputs JSON:\n<JSON>\nReturn JSON schema:\n…`。JSON は
   `{"fx":{"usd_jpy_weekly_change_pct","usd_jpy_latest","available"},"metals":{金属:{"latest_price_per_gram"
   （round 2）,"trend_14d_pct_per_day"（round 4）,"volatility_14d_pct"（round 4）,"news_sentiment","news_article_count",
   "headlines"（140 字に切った 8 件まで）,"recent_forecast_mean_abs_error_pct"（round 3 か null）}}}`
   （`json_dumps`＝`separators=(",", ":")`・`ensure_ascii=False`）。
   決めさせるもの: 金属ごとの score（[-1,1] に丸めて round 4）・confidence（[0,1]、round 4）・rationale（140 字）・
   global_comment（180 字）。**使い道は中心の傾きの 1 項だけ**: `score × confidence × FORECAST_LLM_WEIGHT（0.008）`
   （1 日あたり）。傾き全体は ±`FORECAST_TILT_MAX_PCT_PER_DAY`（0.15%/日）に丸める。rationale は根拠の「AI判定所見」。
   無効・鍵が無い・失敗・読めない、のどれでも全金属 0 と `available=false`（global_comment に理由）
2. **要約（`fetch_forecast_summaries`、temperature 0.3）**: 予測ができた金属のうち、根拠（drivers）と区間がある
   ものだけ。user の JSON は `{"metals":{金属:{"conclusion":{"range_low_pct_over_next_7_days"（round 2）,
   "range_high_pct_over_next_7_days","interval_probability","direction"（up/down/flat/unclear。±0.3% で決める）,
   "confidence_0_to_1"},"supporting_notes":[drivers]}}}`。返った文が向きと食い違えば捨てる（日本語の上がる語・
   下がる語の有無。両方あれば捨てない）。200 字に切る。入力が空なら呼ばない

### 5.4 計算（`forecast_for_metal`。純粋な関数）

1. 履歴を（日付, 価格>0）の昇順に。2 点未満なら作らない
2. 1 日あたりの対数リターン（欠けた日をまたぐと経過日数で割る）。σ＝連続したリターン（10 本以上あれば）の
   MAD×1.4826（MAD が 0 なら pstdev）
3. 区間: 7 日先の対数リターン（ちょうど 7 日離れた組だけ）が 20 本以上あれば、平均を引いて線形補間の分位点
   （10%・90%）×補正係数。補正係数＝本数 43 以下 1.35、150 以上 1.10、間は線形、被覆率があれば
   `1 − 0.5×(被覆率 − 0.8)` を 0.85〜1.20 に丸めて掛ける。幅が潰れていれば（1e-6 以下）正規近似
   `z(0.9)×σ×√7×係数`（z は Acklam の近似）、片側 0.005 以上
4. 傾き＝為替の日の係数×β（日付を突き合わせた OLS。40 日未満・分散が 0 なら金属ごとの既定、−0.5〜1.5）
   ＋ニュース×0.0025＋AI（5.3）。±0.0015 に丸める
5. 日ごと（1〜7 日）: 中心＝今の値段×exp(傾き×日)、上下＝中心×exp(区間×√(日/7))、どれも round 2
6. 信頼度: 0.25＋0.45×（1−片側幅%÷12 を 0〜1 に）、履歴 60 点以上 +0.10（30 以上 +0.05）、区間が経験分位 +0.08、
   為替あり +0.04、記事 8 件以上 +0.04、欠け 1 つにつき −0.02（−0.10 まで）、MAE の補正（1.5% 以下 +0.05、6% 以上
   −0.30、間は線形）、被覆率の補正（−min(0.15, ずれ×0.5)）、答え合わせの実績が無ければ 0.75 まで、0.1〜0.95
7. 根拠の内訳（primary 2・signal 3〔効いた順〕・reference 0〜6）と drivers（`f"{値:+.3f}%/日 "` などの日本語の
   1 行）。返す辞書の鍵の並びは `_payload` が唯一の定義

### 5.5 保存と読み出し

- `store_weekly_forecast`: as_of より後・horizon 以内の日の行を (金属, 日) で置き換え（無い行は消す）、meta は
  id の最も古い 1 行を使い回して書き、ほかを消す。数は `as_decimal`（`Decimal(str(float))` を 4 桁か 6 桁へ
  四捨五入）、JSON の列は `json_dumps`。`news_headlines_json` に見出し・LLM・区間・精度・要約・内訳を相乗り
- `record_forecast_snapshot`: (金属, as_of, 予測日) で UPSERT（予測・上下・傾き無し＝今の値段・傾き・モデル名）
- `reconcile_forecast_accuracy`（0:00 の取り込みの直後）: 予測日が今日以前で実績が空の行（500 行まで）に、実績・
  誤差%・傾き無しの誤差%・区間に入ったか、を書く
- `load_stored_weekly_forecast(days)`: generated_at の新しい meta 1 つと、その as_of の行から形を組み直す
  （`news_headlines_json` は新旧 2 つの形を読み分ける。区間の列が無い古い行は null）。days が短ければ JSON で
  写してから切り、最終日に合わせて中心と変化率を作り直す

### 5.6 Python と同じ答えをどう確かめるか

1. **純粋な関数の基準**（W3-4）: `forecast_for_metal` を、合成した履歴（欠けあり・なし、20 本の境目、平らな値段、
   上げ相場・下げ相場、点が 2 つだけ）× シグナルの組（為替あり・なし、β の推定ができる・できない、AI の
   score/confidence、被覆率・MAE あり・なし、tilt_effect）で 40〜60 例、Python の出力をそのまま基準にする
   （tests の `ForecastForMetalGoldenTests` の入力も入れる）。部品（`horizon_interval`・`robust_daily_sigma`・
   `_normal_quantile`・`interval_width_multiplier`・`estimate_fx_beta`・`_percentile`・`daily_trend`・
   `daily_volatility`）も個別に。**float は repr の文字列で、ビットまで比べる**
2. **材料の読み方の基準**（W3-6）: Frankfurter の JSON・RSS の XML（壊れたもの・空・18 件超）→ シグナル、
   LLM の答えの文字列 → score など（`_llm_scores`・`extract_first_json_object`・`_accepted_summaries`）、
   **プロンプトの文字列そのもの**（`_llm_prompts`・`_summary_prompts` の出力）
3. **保存の基準**（W3-6、空の Postgres。`needs_pg=True`）: payload → `store_weekly_forecast` → 表の行、
   → `load_stored_weekly_forecast(days)` の JSON。答え合わせの UPSERT・reconcile・集計も
4. **通しの基準**（W3-6）: 偽の Frankfurter・Google News・Groq を立て（決めた答えを返す）、時計を止めて
   Python の `refresh_weekly_forecast_cache` を回し、偽物に届いた要求（URL・見出し・本文）と表の中身を基準にする。
   Rust も同じ偽物に向けて回し、届いた要求と表を比べる

数で気をつけること（どれも基準で決まる。食い違ったら Rust を直す）:

- Python の `round(x, n)` は 2 進の値を正確に 10 進にしてから丸める（2.675→2.67）。Rust は `format!("{:.n}")`
  （正確な 10 進から丸める）で文字列にしてから読み戻す。ちょうど半分のときの向き（Python は偶数へ）は基準で確かめる
- `statistics.pstdev` は分数で正確に分散を出し、平方根を正しく丸める。`statistics.fmean` は fsum。`median` は
  並べた真ん中（偶数なら 2 つの平均）。Rust は素直な f64 の計算だと最後の桁がずれうる（ずれは round のあとで
  消えることが多いが、ちょうど境目のときに表に出る）
- `math.exp`・`log`・`sqrt`・`tanh` は C の libm。Rust の f64 も Linux では同じ glibc の関数を呼ぶ（見立て）。
  Python のイメージ（python:3.13-slim）と Rust のイメージの glibc の版が違えば最後の桁がずれうる
- f-string の書式（`+.3f`・`.2f`・`.0%`・`.3f`）も Python の丸め。`.0%` は 100 倍して `f` に % を付ける

---

## 6. プッシュ通知

### 6.1 鍵（VAPID。`webapp/vapid_service.py`）

- 決める順: 環境変数 `VAPID_PUBLIC_KEY` と `VAPID_PRIVATE_KEY` が**両方**あればそれ → `VAPID_AUTO_GENERATE`（既定 true）
  なら `VAPID_KEYS_DIR`（既定 `/shared/vapid`。compose も同じ）のファイル → 無効
- ファイル: `private_key.pem`（P-256 の PKCS8 PEM、暗号化なし、0600）・`public_key.txt`（非圧縮の点 0x04‖X‖Y を
  base64url〔`=` 無し〕＋改行、0644）。秘密鍵が無ければ作る。公開鍵のファイルが空でなければそれを読み、無ければ
  秘密鍵から作って書く。**作り直さないこと**（購読は公開鍵に結びついている。作り直すと全員が届かなくなる）
- subject: `VAPID_SUBJECT`。空なら `mailto:admin@example.com`、`:` が無く `@` があれば `mailto:` を付け、
  決めた正規表現（mailto: か https:）に合わなければ警告して既定へ
- 有効＝公開鍵・秘密鍵・subject が全部ある。プロセスで 1 回読んで覚える（起動時に読み直す）
- 秘密鍵は「PEM のファイルのパス」（作った場合）か「環境変数の文字列」（pywebpush の `Vapid.from_string`。
  base64url の生の 32 バイトか DER）。Rust は両方を読む
- Rust: 同じボリューム（`shared_secrets:/shared`）を同じ場所に。p256 crate（Cargo.lock に 0.13.2 がある）の
  PKCS8 の読み書きで同じファイルを作る

### 6.2 購読の表と API

- `push_subscription`: endpoint varchar(1024) 一意・p256dh_key varchar(512)・auth_key varchar(512)・
  user_agent varchar(512) null・created_at・updated_at
- API は 2.。**検証の上限（4096・2048）が列の長さ（1024・512）より長い**ので、長い値は DB の誤りで 500 になる
  （User-Agent が 512 を超えても。12.）。Rust も同じ DB に入れれば同じ 500 になる

### 6.3 日次の配信（`dispatch_top_delta_notification`。JST 11:00、misfire 7200 秒）

1. 無効なら何もしない。起動時（`enforce_schedule_time=True`）は 11:00 より前なら何もしない（定期の仕事は False）
2. latest（1.5 の `_get_latest_prices`。キャッシュも使う）から、前日差の絶対値が最大の金属（同じなら
   gold・silver・platinum の順で先のもの。日付と前日差が両方ある金属だけ）。無ければ何もしない
3. 購読を全部読む。無ければ何もしない
4. `INSERT INTO notification_dispatch (daily_top_delta, 日付, 'pending') ON CONFLICT DO NOTHING RETURNING id`。
   行が返ったときだけ commit して進む（別のプロセスが送った・送っている）
5. 本文: `{"title":"本日の価格変動通知 (JST 11:00)","body":"<表示名>の前日差が最大: <+ か ''><前日差 .2f> 円/g (<日付>)",
   "url":"<APP_PUBLIC_PATH を / で挟んだもの>","tag":"metal-daily-delta"}`（`json.dumps(…, ensure_ascii=False)`。
   **区切りは既定の `", "`・`": "`**。前日差は Decimal の `.2f`＝偶数への丸め。0 以上なら `+`）
6. 1 件ずつ順に送る。404・410 は消す（同じトランザクションで DELETE）。detail を
   `<金属>:<前日差の str>:ok=<数>:stale=<数>` にして commit。途中で例外なら rollback し、取った行を消して commit
   （次の回に送り直せるように）
- 起動時のテスト（`STARTUP_TEST_MODE` など。既定は無効。コンテナの中だけ）: 行を取らずに「【テスト】起動時 Push 通知」を送る

### 6.4 送り方（pywebpush 2.5.0）

- 暗号は aes128gcm（RFC 8291・RFC 8188。乱数の salt と使い捨ての鍵。レコード 4096）、VAPID（RFC 8292）の JWT
  （ES256。claims は `sub`＝subject、`aud`＝endpoint の scheme://netloc、`exp`＝今＋12 時間）
- 見出し: `TTL: 0`（pywebpush の既定）、`Content-Encoding: aes128gcm`、Authorization（見立てでは
  `vapid t=<JWT>,k=<公開鍵>`。py_vapid の既定の版による）。**時間切れが無い**（requests の timeout=None。12.）
- 202 を超える状態は失敗。404・410 は購読を消す。ほかは警告のログだけ
- Rust: Cargo.lock にある p256（ECDH・ECDSA）・aes-gcm・hkdf・sha2・base64 と reqwest で書ける（新しい crate は
  要らない）。鍵の型は W3-7 と W3-8 で先に決める（9. の注）

### 6.5 確かめ方

- 偽の Push サービス（基準の道具の中の小さな HTTP サーバー）に、Python の `send_push` から送らせ、届いた要求の
  見出し（TTL・Content-Encoding・Content-Type・Authorization の形）、JWT のヘッダと claims（exp は「今」との差）、
  **購読の秘密鍵で復号した平文**を基準にする（購読の鍵の組は道具が決めた値で作る）。Rust も同じ偽物に送り、
  同じ平文・同じ見出し（乱数の部分は形だけ）・JWT が公開鍵で検証できることを確かめる
- 配信の順（slot・本文・stale の削除・失敗の後始末）は、空の Postgres に購読と値段を入れて Python の
  `dispatch_top_delta_notification` を回した前後の表を基準にする

---

## 7. 静的なものと nginx（w01 と揃えること）

| 経路 | Python がしていること | nginx だけで返せるか | 条件・合わせること |
|---|---|---|---|
| `/static/*` | ファイルをそのまま。Cache-Control は 2 通り（2.）、200 のときだけ | **返せる** | `?v=` の判定を Python と同じに（`map $args` で `(^|&)v=[^&]` を大小を区別して見る。Python は % を戻さずに見る）。型（.js は Python 3.13 では `text/javascript; charset=utf-8`、.css は `text/css; charset=utf-8`、.svg・.woff2・.webmanifest など）を Python に合わせる（見立て。基準で確かめる） |
| `/manifest.webmanifest` | ファイルをそのまま | **返せる** | `application/manifest+json`、`_cache_headers(3600)` |
| `/sw.js` | CACHE_NAME を中身のハッシュで書き換え | 実行時は返せない。**イメージを作るときに書き換えれば返せる** | `application/javascript`、no-store、`Service-Worker-Allowed: /` |
| `/`・`/index.html`・SPA の受け皿 | `?v=` を中身のハッシュで書き換え | 同上 | text/html; charset=utf-8、no-store。予約の先頭（api・static・health・docs・redoc・openapi.json・sw.js・manifest.webmanifest）は受け皿にしない |
| `/health` | 固定の JSON | 返せるが、Rust に置く | アプリの生死を見るため |
| `/api/purity/options` | 固定の JSON | 返せるが、Rust に置く | /api/ のレート制限の数えに入っているため |

**推す形: nginx のイメージを作るときに index.html と sw.js を書き換える。** 理由:

- 書き換えの結果は、app.js・styles.css・sw.js の中身だけで決まる（`_content_hash` は中身を `\0` で区切って
  sha256 の頭 12 桁）。イメージに焼くファイルと同じものから作れば、実行時に作るのと同じバイトになる
- **版と中身がいつも同じイメージから来る**。Rust の Web が実行時に書き換える形だと、Rust のイメージの app.js と
  nginx のイメージの app.js が別の版になりうる（片方だけ取ってきた場合）。そのとき index.html の `?v=` は Rust の
  中身のハッシュなのに、nginx は別の中身を「1 年変わらない」として配り、ブラウザが古いものを持ち続ける
- 書き換えは alpine の sh・sha256sum・sed でできる（`{ cat app.js; printf '\0'; cat styles.css; printf '\0'; } |
  sha256sum | cut -c1-12`、sed で `static/app\.js(\?v=[^"']*)?` を置き換える）。Python の正規表現は `[^"']*` が
  改行もまたぐが、sed は行ごと。いまの index.html の 2 か所はどちらも引用符で閉じているので同じになる。
  **食い違いは CI で捕まえる**（tests/ に、書き換えの script を写しの static で回し、`render_index_html`・
  `render_service_worker` の出力とバイトまで比べるテストを置く。sh は ubuntu の runner にある）

nginx で合わせること（w01 の設定に足す。W3-2）:

- 全部の応答に 1.4 の見出し（`add_header … always`）。許すホストの確かめ（ALLOWED_HOSTS から server_name を作り、
  ほかは 400 `Invalid host header` text/plain）。gzip（500 バイト以上、gzip_proxied any、JSON・JS・CSS・SVG・
  manifest・text）
- 予約の先頭で経路の無いもの（`/docs`・`/redoc`・`/openapi.json`〔出さないと決めたとき〕・`/sw.js/…`・`/static`
  など）は 404 `{"detail":"Not Found"}`（application/json）。`/api` と `/api/…` は Rust へ（`~ ^/api(/|$)`。
  `/apix` は受け皿）。`/health` は Rust へ
- Python と変わってよい（よくなる）こと: HEAD に 200 を返す（Python は 405）、POST で受け皿に来たら 405 の中身が
  nginx の HTML、304 にも Cache-Control が付く、ETag の形（再検証が 1 回起きるだけ）

**もう 1 つの形（推さない）**: Rust の Web が実行時に書き換える（Python と同じ。mtime と大きさで覚える）。nginx は
`/`・`/index.html`・`/sw.js`・受け皿を Rust へ渡す。基準は Python の書き換えをそのまま比べられるので作りやすいが、
上の「版と中身が別のイメージ」の危険が残る。

---

## 8. 基準の作り方の型（この塊で作った `prices_calculate` が手本）

### 8.1 API の基準（HTTP の層）

1. **例の文書 `cases.json`**（`rust/apps/web/tests/fixtures/<名前>/`）: `now`（時差つき）・`library`（行などの部品）・
   例の並び。例は「名前・note・service（偽物が返すもの。鍵は webapp/app.py が import した関数の名前）・requests
   （method・target〔パスとクエリ。% で書く〕・headers・client・json か content・repeat・expect_status）」。
   JSON に無い型は印で書く（`$date`・`$decimal`・`$row`・`$datetime`・`$int`・`$ref`/`with`・`$raise`）
2. **道具 `generate.py`**: `../web_harness.py` を使う。`_patches` は `harness.service_patches(WEB_SERVICES, …)` の
   1 行。`build` は `harness.load_web(extra)` → `harness.run_cases`。DB や外へ行く関数が増えたら
   `WEB_SERVICES` に足す（書いていない関数が呼ばれたら止まるので、足し忘れは道具が教える）。時計を止める
   モジュールを足すなら `run_cases(…, clock_modules=…)`
3. **`tools/fixtures/regen.py` の GENERATORS に 1 行**（標準出力は None、Postgres が要らなければ False）。
   expected は手で作らない（CI の「基準」が作り、差分を成果物で返す）
4. **Rust のテスト**（その塊で書く）: `expected.json` だけを読む。例ごとに:
   - app を組む: 設定は `env`（基準の先頭）から、時計は `now` に止めたもの、store は「例の service を返し、
     呼び出しを控える」偽物（Rust の trait の実装）、キャッシュとレート制限は空（Valkey は使わない）
   - 要求ごとに `oneshot`: method・target・headers（`host` が無ければ base_url の host）・json があれば本文と
     `content-type: application/json`、接続元は `client`（sycs-web の proxy の層の**あと**の値として差し込む）
   - 比べる: 状態、見出し（Python の見出しが全部、同じ値で出ていること。名前の順。`content-length` は本文の長さと
     比べる〔oneshot では hyper が付けない〕）、本文（**バイトまで**）、呼び出し（関数の名前と引数）
   - 例の中では状態を持ち越す（2 回目はキャッシュ・6 回目は 429）。次の例で作り直す

決めごと（`web_harness.py` の先頭にも書いた）: 圧縮しない応答を比べる（`accept-encoding: identity` を既定で
送る）・接続元は uvicorn が直したあとの値・500 も記録する・環境変数は全部消して決めた値だけを入れる・
DB の接続先は使われない番地・見出しは名前の順。

### 8.2 ほかの基準の型

| 型 | 中身 | 例 | Postgres |
|---|---|---|---|
| API（8.1） | 偽物の services → 応答 | prices_calculate・purity_options・prices_history・forecast_weekly_api・push_api | 要らない |
| 純粋な関数 | 入力の JSON → Python の関数の戻り値（float は repr の文字列も添える） | forecast_pure・forecast_signals（読み方とプロンプト）・asset_version（index と sw の書き換え）・scheduler（APScheduler の CronTrigger・IntervalTrigger の次の時刻） | 要らない |
| DB | 空の Postgres に行を入れ、Python の関数を回した前後の表と戻り値 | store_pg（取り込み・修復・読み方）・forecast_store_pg・push_dispatch_pg | 要る（`needs_pg=True`。`PG_ADMIN_DSN` から毎回新しい DB。bot の user_state と同じ） |
| 偽のサーバー | 偽物に届いた要求と、そのあとの表 | forecast_e2e（Frankfurter・News・Groq）・webpush（Push サービス）・metalprice（MetalpriceAPI） | 要るものもある |

- 時刻に頼るもの（いまの JST の日付・11:00 より前か）は時計を止めて例にする。間隔を測るテストは「下限だけ」
  （RULES の 6.）
- advisory lock の引き継ぎは基準にしない（Python の振る舞いは tests の `SchedulerLockWatchTests` が固定している）。
  Rust は `#[ignore]` の Postgres のテスト（2 つの app、片方の接続を切る → もう片方が取る・切れた側は止まる）

---

## 9. 塊の案（1 塊 = プルリク 1 本。段ごとに 2 体で並べる）

```text
段 1:  W3-1 骨組み・ミドルウェア・計算（A）        ∥ W3-2 静的と版・nginx の合わせ（B）
段 2:  W3-3 相場の読み方と履歴（A）               ∥ W3-4 予測の計算（純粋な関数）（B）
段 3:  W3-5 取り込み・修復・背景の処理（A）        ∥ W3-6 予測の材料・保存・予測の API（B）
段 4:  W3-7 VAPID の鍵と /api/push/*（A）         ∥ W3-8 Web Push の送り方と日次の配信（B）
段 5:  W3-9 切り替え（親）
```

| 塊 | 中身（Python → Rust） | 基準（新しい generate） | 先に要るもの |
|---|---|---|---|
| **W3-1** | `rust/apps/web` の起動（sycs-web の serve・proxy・health・ログ・メトリクスのゲージ 4 つ）、設定（1.・2. の環境変数を Python と同じ既定と下限で）、ミドルウェア 4 つ（1.2 の順。許すホスト〔`*.` の形も〕・レート制限〔Valkey の ZSET とプロセス内〕・見出し・500）、422・404・405（HEAD を含む）、2 段のキャッシュ（1.5）、Python の JSON の書き方（repr の float）、Decimal の写し（4.4）、`/api/purity/options`、`/api/prices/calculate`（store の trait と偽物）。Bot の `python_repr`・`python_chars` を共有の crate へ（Bot は同じ名前で使う） | prices_calculate（この塊）・purity_options | w01（sycs-web） |
| **W3-2** | nginx のイメージで index.html・sw.js を書き換える script、Python の書き換えとバイトまで比べるテスト（tests/）、nginx の Web の設定に 7. の合わせ（見出し・許すホスト・gzip・予約の 404・/api と /health を Rust へ）。`/static` の基準（Python の VersionedStaticFiles の型・Cache-Control・404・`..`）。Rust のコードはほぼ無い | asset_version・static_files | w01（nginx） |
| **W3-3** | Postgres の読み方（`load_latest_rows`・`load_history`・`load_earliest_snapshot_date`。sqlx、numeric は `::text`）と Web 用の接続先の組み立て（1.7）、alembic_version の確かめ（起動時に `0005` でなければ定期の仕事を止めてログ）、`/api/prices/history`（範囲の計算・date の検証・時計） | store_pg・prices_history | W3-1 |
| **W3-4** | forecast_series・forecast_models・forecast_utils の写し（f64 の丸め・pstdev・fmean・正規分位点・β・信頼度・根拠の日本語）。DB も外も使わない | forecast_pure | 無し（crate の中の module として先に置ける） |
| **W3-5** | MetalpriceAPI のまとめ取り（Bot の `metal.rs` を共有の crate へ移して足す）、`store_snapshot`、修復、スケジューラ（cron と interval の次の時刻・misfire・coalesce・max_instances=1）、advisory lock と見張りと引き継ぎ、起動時の仕事の順、DB の誤りでの 1 回の再試行、キャッシュの消し方（二次の SCAN＋DEL） | metalprice・store_pg（取り込み・修復）・scheduler | W3-3 |
| **W3-6** | 為替・ニュース・Groq（Bot の `groq.rs` に JSON の求め方と 400 の逃げ道を足して共有の crate へ）、プロンプト、`build_weekly_forecast`・`store_weekly_forecast`・`load_stored_weekly_forecast`・答え合わせ、`/api/prices/forecast-weekly`。W3-5 のスケジューラから呼ぶ口（trait）に差す | forecast_signals・forecast_store_pg・forecast_weekly_api・forecast_e2e | W3-3・W3-4（W3-5 とは口だけ先に決める） |
| **W3-7** | VAPID の鍵（6.1。読み・作り・subject）、`/api/push/public-key`・`/api/push/subscribe`（URL の確かめは sycs-core の url_safety）・`/api/push/unsubscribe` | push_api（購読の表は偽物。VAPID の設定を例ごとに読み直すため `push_service._cached_config` を空にする） | W3-1・W3-3 |
| **W3-8** | RFC 8291 の暗号と RFC 8292 の署名、送り方（6.4）、日次の配信（6.3）と起動時のテスト | webpush・push_dispatch_pg | W3-5（スケジューラ）。鍵の型は W3-7 と先に決める |
| **W3-9** | compose の profile・GHCR のイメージ（web-rs）・nginx の上流の切り替え・UPGRADE.ja.md の手順と戻し方・本番の確かめ（本人） | — | 全部 |

注:

- W3-5 と W3-6 は段 3 で並べる。スケジューラ（W3-5）は「予測を作り直す」口を trait で持ち、W3-6 が実装を差す。
  W3-6 が入るまでは、口は「まだ無い」とログに出して何もしない（本番に出すのは W3-9 なので害は無い）
- W3-7 と W3-8 は、鍵の型（例 `VapidKeys { public_b64url: String, signing: p256::ecdsa::SigningKey,
  subject: String }`）を計画の段で決めてから並べる
- どの塊も、変異の一覧 `tools/mutate/lists/w3_<塊>.py`（15〜30 通り）と、Python の該当の関数名を書いたコメント
- 共有の crate へ移すもの（`python_repr`・`python_chars`・`metal`・`groq`）は、Bot のテストがそのまま通ることを
  その塊で確かめる

---

## 10. 切り替えと戻し方（考え方。手順は W3-9 で UPGRADE に書く）

- compose の既定は Python のまま。Rust の Web は profile の中のサービス（`sycs-voldemort-web-rs`）、nginx の Web の
  上流は環境変数で `sycs-voldemort-web:8000` ↔ `sycs-voldemort-web-rs:8000` を切り替える（w01 の形）
- 同じ DB・同じ表・同じ Valkey の鍵・同じ VAPID のファイル・同じ advisory lock なので、**両方が同時に動いても
  定期の仕事は片方だけ**、キャッシュは互いに読める、購読はそのまま届く
- 切り替え: Rust を起動 → nginx の上流を Rust へ → Python の Web を止める（lock が外れ、Rust が 60 秒以内に
  引き継ぐ。引き継いだときは起動時の仕事を走らせない）。戻し: 上流を Python へ → Rust を止める
- 移行（Alembic）は Python に残す。切り替えの前に DB が `0005` であること（本番は Python の Web が動いているので
  そうなっている）。新しく建てるときは Python の Web を 1 回起動するか、移行だけを流す

---

## 11. 親か本人に決めてほしいこと（推す答えつき）

1. **`/docs`・`/redoc`・`/openapi.json`（FastAPI が自動で出している）を Rust で出すか** → 出さない（404 の JSON）を
   推す。公開サイトに API の文書を出す意図はコードに見当たらず、`/docs` は CSP で外の JS が止まって画面が出ない。
   出すなら OpenAPI の JSON を手で写すことになる。**いまは 200 を返しているので、振る舞いが変わる**
2. **index.html・sw.js の書き換えをどこでするか** → nginx のイメージを作るとき（7.）を推す
3. **移行（Alembic）** → Python に残し、Rust は版を確かめるだけ（推す）。Rust で DDL を書くと、2 つの定義が食い違う
4. **gzip** → nginx に任せる（推す）。Rust の応答は圧縮しない。Python の GZipMiddleware の細部（小さい本文は
   圧縮しない・Vary）は nginx の設定で近づける
5. **レート制限の時計** → CLOCK_MONOTONIC を rustix で読む（推す。1.6）
6. **起動時の仕事** → Python は終わるまでそのワーカーが要求を受けない（もう 1 つのワーカーが受ける）。Rust は
   1 プロセスなので、**要求を受けながら裏で回す**（推す。外から見える振る舞いは「サイトは開いている」で同じ）
7. **Push の送信に時間切れを付けるか** → Python と同じ（付けない）で写し、見直しの候補に置く（RULES の「振る舞いを
   そのまま写す」）。付けるなら 30 秒など
8. **Valkey の名前空間と JSON の形** → Python と同じにする（推す。1.5）
9. **`APP_ROOT_PATH`・`APP_PUBLIC_PATH` を `/` 以外で使うか** → 本番は空と `/`。Rust は `/` だけを受け、ほかが
   来たら起動を止める（推す）

---

## 12. 見直しの候補（Python は凍結中なので直さない。気づいたことだけ）

- calculate のキャッシュの鍵は grams を小数 4 桁に丸めるので、`grams=10` のあとの `grams=10.00004` は 1 回目の答え
  （grams は 10.0）をそのまま返す（入力と答えの grams が食い違う。基準 `caches_within_a_case`）
- push/subscribe の検証の上限（endpoint 4096・鍵 2048）が列（1024・512）より長く、長い値は 500。User-Agent が
  512 を超えても 500
- Push の送信に時間切れが無い（`requests` の timeout=None）。送り先が応答しないと配信の仕事がその回止まり、
  `max_instances=1` なので次の回も走らない
- 許すホストは `Host` を `:` で割った前で比べるので、IPv6 の Host（`[::1]:8000`）は読めない（ALLOWED_HOSTS の
  `::1` は効いていない）
- `/docs`・`/redoc`・`/openapi.json` が公開されている（11. の 1）
- 500 にセキュリティの見出しが付かない（ServerErrorMiddleware が一番外）
- 許さない Host の要求も /api/ のレート制限を使う（制限が外側）
- アプリは、uvicorn が X-Forwarded-For で直したあとの接続元が信頼するプロキシの帯域に入るとき、もう一度
  X-Real-IP・X-Forwarded-For を読む（二重の解釈。ふつうは帯域の外になるので効かない）
- 通知の題は「(JST 11:00)」と書いてあるが、送る時刻は `PUSH_NOTIFY_HOUR_JST` で変えられる
- 為替の「今日」は UTC、ほかは JST
- `reconcile_forecast_accuracy` の 500 行の LIMIT に ORDER BY が無い（500 行を超えたときに毎回同じ行とは限らない）
- `//api/…` は先頭の段が空になって予約に当たらず、index.html を返す

---

## 13. 確かめていないこと

- 何も動かしていない。`prices_calculate` の基準は CI の「基準」で初めて作られる。例の `expect_status` は道具の
  確かめに使う分だけ付けた（自信のある例だけ）。付けていない例（float の読み方・同じ名前が 2 つ・HEAD・
  % を戻した経路）は、出たものがそのまま基準になる
- FastAPI 0.165・starlette・pydantic の細部（HEAD を受けないこと、405 の Allow、空のクエリの扱い、同じ名前の
  どちらを使うか、GZip の Vary、TestClient が HEAD の本文を捨てること）は見立て
- pywebpush 2.5.0 の Authorization の形・Content-Type、nginx の型の表、Python 3.13 の mimetypes の .webmanifest
- python:3.13-slim に tzdata があること（`webapp/snapshot_service.py` の `ZoneInfo("Asia/Tokyo")`。公式のイメージは
  入れている見立て。無ければ道具が import の時点で落ちる）
- 計画の中の Rust の crate（rustix で CLOCK_MONOTONIC・p256 の PKCS8・sqlx の numeric）は Cargo.lock の名前と版を
  見ただけで、feature までは確かめていない
