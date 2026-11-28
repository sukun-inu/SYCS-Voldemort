# 管理画面（rust-06）を Rust へ移す計画（W2）

書いた日: 2026-11-28。読んだ元: main 57ea39c の写し（`snapshot-main6`）。

読み切ったもの: `webapp_admin/` の全部（`app.py`・`auth.py`・`security.py`・`templating.py`・`extensions.py`・
`metrics.py`・`prometheus_view.py`・`core/config.py`・`views/`・`api/`・`schema/`・`templates/`）と `admin_main.py`。
services は管理画面から呼ぶ入口（`settings_store`・`tts_store`・`logging_service`・`user_state_service` の読み出し・
`dev_signals`・`guild_retention`・`djaudio_cache`・`metrics_registry`・`log_setup.trusted_proxies`）。配信
（`services/djaudio_cdn.py`）は W1 の担当なので、管理画面との境目（`wants_json`）だけ読んだ。

この文書は 4 つに分かれる。

1. いまの作り（Python）: 起動・ミドルウェアの順・セッション・権限・エラー・見出し・制限・背景の処理
2. 経路の一覧（60 本）: 入力・出力・権限・使う services・Postgres／Valkey／Discord／Bot への依頼
3. Rust で守ること（認証とセッション・テンプレート・/static・/metrics・設定パネル）
4. 基準の作り方の型と、塊の案（1 塊 = プルリク 1 本。依存の順。2 体で並べる分け方）

---

## 1. いまの作り（Python）

### 1.1 プロセスと起動

- `admin_main.py` → uvicorn（`webapp_admin.app:app`、`0.0.0.0:ADMIN_PORT`〔既定 5001〕、`ADMIN_WORKERS`〔既定 1〕、
  `proxy_headers=True`、`forwarded_allow_ips=TRUSTED_PROXY_CIDRS`〔既定 `127.0.0.1/32,::1/128,172.16.0.0/12`〕）。
  ワーカーを増やすと、TPS・監視の巡回・レート制限・SQL の実行中の印（取り消し用）がワーカーごとに割れる。
  **Rust も 1 プロセスの前提をそのまま写す**（memory の netdata-metrics-endpoint: ADMIN_WORKERS は 1 固定）
- 起動のとき（import のとき）: `SETTINGS_DIR/logs/admin.log` と `admin.jsonl` にログ。セッションの秘密鍵を決める
  （下の 3.1）。監視の巡回のスレッドを立てる（1.8）
- 起動の処理（startup）: イベントループの見張り、設定の置き場が Postgres なら読み込みを裏で始める（待たない）、
  メトリクスの報告（`report_forever("admin")`、`METRICS_REPORT_INTERVAL_SECONDS` 既定 30 秒）
- 止めるとき: 報告を止める、共有の HTTP セッションを閉じる

### 1.2 ミドルウェアの順（外から内へ）

```text
SessionMiddleware → SlowAPIMiddleware → session_serialization_guard → security_headers → metrics → 例外の係 → 経路
```

- 応答の帰り道は内から外。**この順に意味がある**（`_register_middleware` の docstring、`CreateAppShapeTests` が固定）
  - `metrics`: 計数（/static 以外）と 5xx のインシデント。どの係も拾わなかった例外をここで 500 の応答にする
  - `security_headers`: 全部の応答に見出し（1.6）。500 にも付く
  - `session_serialization_guard`: Cookie に書く前にセッションを削る（`admin_guilds` を id・name・icon だけにし、
    壊れた要素を捨てる。それでも JSON にできなければ文字列にする）
  - `SessionMiddleware`: Cookie を読み、帰りに書き直す（3.1）
- Rust（tower の層）でも同じ順にする。外れると「500 に見出しが付かない」「削る前の Cookie が出る」のように、
  画面は出るのに一部だけ違う形で壊れる

### 1.3 権限の確かめ（4 つ）

| 名前 | 通さないとき |
|---|---|
| `check_login` | セッションに `user` が無い → 303 `/admin/login` |
| `check_guild` | `user` が無い → 303 `/admin/login`。`guild_id` が無い → 303 `/admin/guilds`（いまも管理者かは見ない） |
| `check_dev` | `DEV_USER_ID` が空 → 404。`user` が無い → 303 `/admin/login`。`user.id` が違う → 403「開発者専用です。」 |
| `check_csrf` | POST・PUT・PATCH・DELETE で、ログイン中なのに、フォームの `csrf_token` もヘッダ `X-CSRFToken` も セッションの `_csrf_token` と一致しない（どちらかが空でも）→ 403。未ログインは素通し（他の確かめに任せる） |

- 経路ごとに、書いた順に確かめる（`check_guild` → `check_csrf`）。**クエリやパスの検証（422）は、確かめのあと**
  （未ログインで `?limit=9999` なら 422 ではなく 303。基準の `list_without_cookie_and_bad_limit`）
- 405（受け付けない操作）と 404（無い経路）は、確かめより前に決まる（未ログインでも 405。基準の
  `list_post_is_not_allowed`）

### 1.4 エラーの応答

- JSON にする相手: パスが `/admin/api/` で始まるか、Accept に `application/json` があって `text/html` が無いとき
  （`services/djaudio_cdn.wants_json`）。本文は `{"detail": "…"}`
- HTML: `error.html`（`code`・`message`・`description`）。配信（`/dlaudio/`）は W1 の別のページ（Rust の管理画面には
  来ない。nginx が `apps/cdn` へ渡す）
- HTTPException の見出しの文言（`_http_exception_response`）:

  | 状態 | 文言 |
  |---|---|
  | 400 | 不正なリクエストです。 |
  | 403 | アクセス権限がありません。 |
  | 404 | ページが見つかりません。 |
  | 405 | このURLでは受け付けていない操作です。 |
  | 409 | この内容では処理できません。 |
  | 410 | リンクの有効期限が切れています。 |
  | 416 | 要求された範囲を返せません。 |
  | 429 | リクエストが多すぎます。 |
  | 500 | サーバーエラーが発生しました。 |
  | ほか | エラーが発生しました。 |

  `detail` が文字列で、そのコードの英語の既定の言い回し（`Not Found` など）でなく、文言と同じでもなければ、
  JSON の `detail` にはそれを、HTML の `description` にもそれを出す。JSON の `detail` は「理由があれば理由、無ければ
  文言」。HTTPException の見出し（405 の `Allow` など）は **JSON のときだけ** 付ける（HTML の `render()` には
  渡していない）
- レート制限を超えた（`RateLimitExceeded`）: 429、文言「リクエストが多すぎます。しばらく待ってから再試行してください。」
- `_NeedsLogin`・`_NeedsGuild`（ExceptionGroup に包まれていても）: 303
- どの係も拾わない例外: インシデント（`incidents.jsonl`）と `exceptions_total{type=…}` を数え、500「サーバーエラーが
  発生しました。」
- パラメータの検証（FastAPI の `RequestValidationError`）: **経路の種類に関係なく** 422 の JSON
  （`{"detail": [{"type", "loc", "msg", "input", "ctx"}…]}`。pydantic の文言）

### 1.5 セッション（要点。細部は 3.1）

- Cookie `admin_session`。中身は JSON を base64 にして itsdangerous の `TimestampSigner` で署名したもの（暗号化は
  しない）。期限 3600 秒、`path=/`、`httponly`、`samesite=lax`、`FLASK_SECURE_COOKIES` が真なら `secure`
- セッションが空でなければ、**どの応答でも書き直す**（期限が毎回 3600 秒延びる）。空になったら消す Cookie を出す
- 入れているもの: `user`（id・username・global_name・avatar）、`admin_guilds`（id・name・icon）、`admin_guilds_at`
  （取った時刻）、`guild_id`・`guild_name`・`guild_icon`、`_csrf_token`、`oauth_state`（ログインの途中）、`_flashes`
  （次のページで 1 回だけ出す知らせ。`[種類, 文]` の並び）

### 1.6 見出し（`_apply_security_headers`）

- 全部の応答: `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
  `Referrer-Policy: strict-origin-when-cross-origin`、`Content-Security-Policy`（下）。`FLASK_SECURE_COOKIES` が真なら
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- CSP: `default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self';
  img-src 'self' https://cdn.discordapp.com data:; font-src 'self'; connect-src 'self'
  https://static.cloudflareinsights.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`（1 行）
- `/static` だけ `Cache-Control: no-cache, max-age=0, must-revalidate`・`Pragma: no-cache`・`Expires: 0`（nginx へ。5.）

### 1.7 レート制限（slowapi）

- 接続元（uvicorn が転送ヘッダで直したあとの `request.client.host`）ごと。既定は全経路 1 分 300 回
  （`SlowAPIMiddleware`）。経路ごとの上限は表（2.）の「制限」の列。置き場は `ADMIN_LIMITER_STORAGE_URI`
  （本番は Valkey の db 1。落ちたらプロセスの中で数える）
- Rust は同じ数・同じ窓（固定窓、1 分）で数える。置き場の鍵の形は Python と揃えなくてよい（同時には動かさない）

### 1.8 背景の処理

- 監視の巡回（`metrics.start_background_monitor`。`ADMIN_MONITOR_INTERVAL_SECONDS` 既定 30 秒）: 心拍のファイル
  （`SETTINGS_DIR/admin_monitor/heartbeat.json`、`ADMIN_MONITOR_DIR` で変えられる）、起動のときに前の心拍からの空白が
  `ADMIN_DOWNTIME_GRACE_SECONDS`（既定 120 秒）を超えていれば停止のインシデント、CPU・メモリ・TPS がしきい値を超えたら
  警告のインシデント（同じ種類は `ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS` 既定 300 秒あける）
- インシデントは `incidents.jsonl`（2000 行・512 KB を超えたら古いほうを捨てる）。**Python と Rust が同じファイルを
  読み書きする**ので、形を揃える（切り替えても SLA の履歴が続くように）
- メトリクスの報告: Valkey に `hb:admin`・`g:admin:*`・`c:*`（sycs-core の `metrics::Reporter` がある）

---

## 2. 経路の一覧（60 本）

記号: 🔑=ログインが要る（`check_login`）、🏠=サーバーを選んでいる（`check_guild`）、🛡=CSRF（`check_csrf`）、
👩‍💻=開発者（`check_dev`）、—=要らない。制限は経路ごとの上限（無ければ既定の 1 分 300 回）。

### 2.1 ログイン・サーバー選択・シェル（`views/auth_views.py`・`views/dashboard_views.py`）

| 経路 | 権限 | 入力 → 出力 | 使うもの | 制限 |
|---|---|---|---|---|
| GET /admin/login | — | ログイン中なら 303（サーバーを選んでいれば /admin/overview、無ければ /admin/guilds）。でなければ `login.html`（招待リンク・知らせ） | — | 30/分 |
| GET /admin/auth | — | `state`（token_urlsafe(32)）をセッションへ → 303 Discord の認可画面 | — | 10/分 |
| GET /admin/callback | — | `error`・`state`・`code` → 確かめて、セッションを作り直し → 303 /admin/guilds。どこで失敗しても知らせを積んで 303 /admin/login | Discord: トークン交換・`/users/@me`・`/users/@me/guilds`（利用者と Bot の両方） | 10/分 |
| POST /admin/logout | 🛡 | セッションを空にして知らせ → 303 /admin/login | — | — |
| GET /admin/logout | — | 未ログインなら 303 /admin/login。でなければ `logout_confirm.html` | — | — |
| GET /admin/ | 🔑 | 303 /admin/guilds か /admin/overview | — | — |
| GET /admin/guilds | 🔑 | `guild_select.html`（セッションの admin_guilds） | — | — |
| POST /admin/guilds/select | 🔑🛡 | フォーム `guild_id` → 一覧に無ければ知らせて 303 /admin/guilds。取った時刻が `ADMIN_GUILDS_MAX_AGE_SECONDS`（既定 300、最小 60）より古ければ、いまも管理者かを Discord で確かめる（違えば一覧から外して 303 /admin/guilds、確かめられなければそのまま通す）→ guild_id・name・icon を入れて 303 /admin/overview | Discord（Bot）: `/guilds/{id}`・`/guilds/{id}/members/{uid}` | — |
| GET /admin/overview | 🏠 | `shell.html` | — | — |
| GET /admin/api/metrics | 🏠 | ホストの CPU（0.1 秒待って測る）・メモリ・TPS・SLA の JSON | psutil、`incidents.jsonl` | — |
| GET /admin/api/incidents | 🏠 | 直近 30 件のインシデント | `incidents.jsonl` | — |

### 2.2 設定パネル（`api/apps.py`）

| 経路 | 権限 | 入力 → 出力 | 使うもの |
|---|---|---|---|
| GET /admin/api/apps | 🏠 | タイルの一覧（グループ分け。開発者でなければ dev_only を隠す）。バッジは数える | `schema/registry.app_groups`、バッジの関数（settings） |
| GET /admin/api/apps/{app_id} | 🏠 | 無い・開発者専用は 404。custom は `Panel.to_json()` だけ。それ以外は＋`choices`・`values`・`collections`（1 項目の失敗は既定値で埋めて `errors`） | 選択肢（Discord: チャンネル〔60 秒の使い回し、429 なら待つ〕・ロール、TTS: 声〔3 秒で見切る〕）、getter・list（settings・tts_store・logging_service） |
| PUT /admin/api/apps/{app_id} | 🏠🛡 | JSON `{"values": {…}}`（変えた項目だけ）→ 検証して setter を別のスレッドで → `{"saved", "values"}`（失敗があれば ＋`errors` で 422）。custom は 404、JSON でなければ 400 | 選択肢（変えた項目の分だけ）、setter |
| POST /admin/api/apps/{app_id}/collections/{key} | 🏠🛡 | 一覧へ 1 件足す。add が無ければ 405、上限を超えていれば 422、検証に落ちれば 422 → `{"id", "items"}` | list・add |
| PUT /admin/api/apps/{app_id}/collections/{key}/{item_id} | 🏠🛡 | 1 件を変える → `{"id", "items"}` | list・update |
| DELETE /admin/api/apps/{app_id}/collections/{key}/{item_id} | 🏠🛡 | 1 件を消す → `{"items"}` | list・remove |
| DELETE /admin/api/guild-data?confirm= | 🏠🛡 | `confirm` がサーバーの ID と違えば 400。いまも管理者でないと分かれば 403 → 設定・履歴・現在の状態を消して `{"removed": {settings, events, states}}` | Discord（Bot）で管理者か、`guild_retention.delete_guild_data`（Postgres の設定・user_state_audit） |

### 2.3 利用者の状態（`api/users.py`）— 基準はこの塊で作った（`rust/apps/admin/tests/fixtures/users_state/`）

| 経路 | 権限 | 入力 → 出力 | 使うもの |
|---|---|---|---|
| GET /admin/api/users/state | 🏠 | `q`（128 文字まで、前後の空白を落とし、空なら絞らない）・`limit`（1〜200、既定 25）・`offset`（0〜）→ `{"rows", "total", "limit", "offset", "has_more"}`。行は表示用に整える（状態・イベントの日本語、JST の時刻、ロールの名前、権限の日本語を並べたもの、いまタイムアウト中か） | `user_state_service.list_recent_user_states`・`count_user_states`（Postgres の user_state_current） |
| GET /admin/api/users/state/{user_id} | 🏠 | `event_limit`（1〜500、既定 100）→ `{"found", "user_id", "current", "events"}`。記録が無ければ 404 `{"found": false}` | `get_user_state_detail`（user_state_current・user_state_event） |

### 2.4 開発者パネル（`api/dev.py`。全部 👩‍💻、書くものは 🛡 も）

| 経路 | 入力 → 出力 | 使うもの | 制限 |
|---|---|---|---|
| GET /admin/api/dev/overview | Bot の参加サーバー・Bot 自身・設定のあるサーバー・配信のキャッシュ・待っている依頼・環境変数（秘密は先頭 4 文字だけ）・スティッキーの一覧 | Discord（Bot）、settings、`DJAUDIO_CACHE_DIR`、`dev_signals.pending` | — |
| GET /admin/api/dev/earthquakes?limit= | P2P地震情報の直近（1〜20） | api.p2pquake.net | 10/分 |
| POST /admin/api/dev/send-message | JSON `channel_id`・`content` → Discord に送る | Discord（Bot） | 10/分 |
| POST /admin/api/dev/forward-message | JSON `message_url`・`target_channel_id` → 本文だけ転記 | Discord（Bot） | 10/分 |
| POST /admin/api/dev/news-send | JSON `channel_id`・`query` → 記事を探し、要約して送る | ニュースの RSS、Groq、Discord | 5/分 |
| POST /admin/api/dev/signal/{task} | 定期の処理を今すぐ（5 種） | **Bot への依頼**（`dev_signal` 表。同じ用途は 1 行に畳む） | 10/分 |
| POST /admin/api/dev/test-notify/{kind} | JSON `guild_id`・`channel_id` → 通知のテスト | **Bot への依頼**（サーバーごとに別の行） | 10/分 |
| POST /admin/api/dev/earthquake-replay | JSON `event_json`・`guild_id`・`channel_id` | **Bot への依頼**（別の行） | 5/分 |
| GET /admin/api/dev/channels?guild_id= | テキストとボイスのチャンネル（名前順） | Discord（Bot。設定パネルと同じ使い回し） | 30/分 |
| GET /admin/api/dev/user?user_id= | 利用者の情報（作られた時刻は ID から） | Discord（Bot） | 20/分 |
| GET /admin/api/dev/logs | `source`（bot・admin・web・cdn）・`lines`・`level`・`category`・`q` → JSONL を絞る（無ければテキストの末尾） | `SETTINGS_DIR/logs/*.jsonl`・`*.log` | 20/分 |
| GET /admin/api/dev/settings/{guild_id} | 1 サーバーの設定を丸ごと | settings | 20/分 |
| POST /admin/api/dev/settings/{guild_id}/import | JSON `settings`（512 KB まで）で丸ごと置き換え | settings（`replace_guild_settings`） | 5/分 |
| DELETE /admin/api/dev/cache/{token} | 配信のキャッシュを 1 件消す（token は英数字と `_-` だけ） | `DJAUDIO_CACHE_DIR` | 20/分 |
| POST /admin/api/dev/cache/purge | 期限切れを全部消す | `DJAUDIO_CACHE_DIR` | 5/分 |

### 2.5 SQL エディタ（`api/sql.py`。全部 👩‍💻、書くものは 🛡 も）

| 経路 | 入力 → 出力 | 制限 |
|---|---|---|
| GET /admin/api/sql/servers | 接続先（貴金属・利用者の状態の DSN。同じ host:port/user は 1 つ）とデータベースの一覧・版 | 30/分 |
| GET /admin/api/sql/objects?server=&database= | スキーマ → 表 → 列の木 | 60/分 |
| GET /admin/api/sql/ddl?server=&database=&schema=&table= | CREATE TABLE 相当の文 | 30/分 |
| POST /admin/api/sql/query | JSON `sql`・`server`・`database`・`write`・`limit`・`timeout`・`token` → 文に分けて、読み取り専用（または書き込み）のトランザクションで流す。VACUUM などは書き込みで 1 文のときだけトランザクションの外 | 60/分 |
| POST /admin/api/sql/cancel | JSON `token` → 別の接続から `pg_cancel_backend` | 30/分 |

### 2.6 公開ページ・旧 URL・/metrics（`app.py`）

| 経路 | 権限 | 出力 |
|---|---|---|
| GET / | — | `landing.html`（招待リンク、Bot のサーバー数〔Discord に聞き 5 分使い回す。0 か失敗なら設定のあるサーバーの数〕） |
| GET /guide・/privacy・/terms | — | それぞれのテンプレート（招待リンク） |
| GET /admin/guide・/admin/privacy・/admin/terms | — | 301 → /guide・/privacy・/terms |
| GET（パネルの旧 URL 12 本: /admin/users/state、/admin/settings/{logging・vc-notify・welcome・earthquake・news-feeds・sticky・reaction-roles・djaudio・tts・security}、/admin/dev） | 🏠 | 303 → `/admin/overview#{パネルの id}` |
| GET /metrics（`METRICS_PATH`） | 接続元で絞る（6.） | Prometheus のテキスト |

Rust の管理画面に入れないもの: `/static`（nginx。5.）と `/dlaudio`（W1 の `apps/cdn`）。

---

## 3. Rust で守ること — 認証とセッション

### 3.1 Cookie の形（starlette の SessionMiddleware と itsdangerous 2.2.0）

**Python と Rust で同じ Cookie を読み書きできれば、切り替えても戻しても、ログインが切れない。** そのために:

- 値 = `base64(json.dumps(session))` ＋ `.` ＋ 時刻 ＋ `.` ＋ 署名
  - `json.dumps` は既定の書き方（区切り `", "`・`": "`、ASCII 以外は `\uXXXX`〔BMP の外はサロゲートの組〕、キーは
    入れた順）。base64 は標準の字（`+/`）で `=` の詰め物あり
  - 時刻は秒の整数を、前の 0 を落とした big-endian のバイト列にして、URL 用の base64（`-_`）で `=` を落としたもの
  - 署名は HMAC-SHA1。鍵は `SHA1(b"itsdangerous.Signer" + b"signer" + 秘密鍵)`（itsdangerous の django-concat）、
    対象は「値 ＋ `.` ＋ 時刻」。URL 用の base64 で `=` を落とす
- 読むとき: 署名が合わない・期限（3600 秒）を過ぎた・未来の時刻 → 空のセッション。**期限ちょうど（3600 秒前）は
  まだ読める**（基準の `list_with_cookie_at_max_age`）。base64 や JSON が壊れているのに署名が合うもの（秘密鍵を
  知っている人しか作れない）は Python では 500 になる
- 書くとき: 空でなければ毎回 `admin_session=<値>; path=/; Max-Age=3600; httponly; samesite=lax`（＋`; secure`）。
  読んだときは空でなかったのに空になったら `admin_session=null; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT;
  httponly; samesite=lax`。**正確な文字列は基準の Set-Cookie で確かめる**（上は読んだコードからの見立て）
- 署名の時計を差し替えられるようにする（テストで「今」を決めるため。基準は `now` を固定して作ってある）
- 秘密鍵: `ADMIN_FLASK_SECRET_KEY`（前後の空白を落とす）→ 無ければ `SETTINGS_DIR/.admin_session_secret`
  （前後の空白を落として 32 文字以上）→ 無ければ `token_hex(32)` を O_EXCL で作って書く（0600）。先に誰かが作って
  いたらそれを読む。書けなければその場限りの鍵（再起動でログインが切れる）。**Rust も同じ順・同じファイル**

### 3.2 Discord OAuth（`/admin/auth`・`/admin/callback`）

- 認可画面: `https://discord.com/api/oauth2/authorize?` ＋ `client_id`・`redirect_uri`
  （`DISCORD_REDIRECT_URI`、既定 `http://localhost:5001/admin/callback`）・`response_type=code`・
  `scope=identify guilds`・`state`（＋`DISCORD_OAUTH_PROMPT` が none か consent なら `prompt`）。
  `urlencode`（空白は `+`、`:` や `/` も % にする）
- 戻り（順に、どこで失敗しても知らせを積んで 303 /admin/login）:
  1. `error` があれば「Discord 認証がキャンセルされました。」（**このとき oauth_state は残る**）
  2. `oauth_state` を取り出して（消して）、`state` と時間の揺れない比べ方で比べる。違えば「不正なリクエストです（state 不一致）。」
  3. `code` が無ければ「認証コードが取得できませんでした。」
  4. トークン交換（POST `/api/v10/oauth2/token`、フォーム、10 秒）。失敗か `access_token` 無し →「Discord 認証に失敗しました。」
  5. `/users/@me`（Bearer）。失敗 →「ユーザー情報の取得に失敗しました。」
  6. 利用者のサーバー（Bearer）と Bot のサーバー（`Bot` トークン。**limit を付けていない**）を並べて取り、管理者
     （permissions の 0x8）で Bot もいるものだけ。0 件 →「管理者権限を持つサーバーが見つかりませんでした。…」（warning）
  7. セッションを空にしてから `user`・`admin_guilds`・`admin_guilds_at`（いまの時刻、小数）・`_csrf_token` を入れて
     303 /admin/guilds
- いまも管理者か（`user_still_admin`）: Bot トークンが無ければ「分からない」。`/guilds/{id}` か
  `/guilds/{id}/members/{uid}` が 404 なら「違う」、ほかの失敗は「分からない」。持ち主なら「管理者」。でなければ
  @everyone（ロールの ID = サーバーの ID）と持っているロールの permissions を OR して 0x8 を見る

### 3.3 CSRF

- 発行: セッションに無ければ `token_hex(32)`（HTML を返すたび＝`render()` と、ログインの確定のとき）
- 確かめ: 1.3 の表。フォームは `application/x-www-form-urlencoded`（サーバー選択・ログアウト）、JS は JSON ＋ ヘッダ
- 比べ方は時間の揺れないもの（Rust は `subtle` がロックにある）

---

## 4. Rust で守ること — テンプレート（Jinja2 → minijinja）

### 4.1 いま使っている書き方（`templates/` の 10 枚）

- 使っている: `{% if %}`・`{% else %}`・`{% for a, b in xs %}`（組をほどく）・`{% include "_site_footer.html" %}`・
  `{# … #}`・`x if c else y`・`a or b`・`c in ('danger', 'error')`（組の書き方）・`s[0]`（文字列の 1 文字目）・
  属性（`session.user.avatar`、辞書の鍵として引く）・関数の呼び出し
- 使っていない: `{% extends %}`・`{% block %}`・`{% macro %}`・フィルタ（`tojson` を上書きしているが、どのテンプレートも
  使っていない）
- グローバル: `admin_asset_url(path)`・`icon(name, css_class="icon")`。文脈: `request`・`session`・`messages`
  （取り出した知らせ）・`csrf_token`・`url_for`（表引き。4.3）・`is_embedded`（`Sec-Fetch-Dest: iframe` か。どの
  テンプレートも使っていない）と、経路ごとの値（`invite_url`・`guild_count`・`guilds`・`code`・`message`・`description`）
- 自動エスケープは有効（starlette の Jinja2Templates）。`icon()` は Markup（エスケープしない）

### 4.2 minijinja で気をつけること（**A2 の最初に基準で確かめる**。どれも記憶からの見立て）

- **エスケープの書き方が違う**: markupsafe は `& < > " '` を `&amp; &lt; &gt; &#34; &#39;` にする。minijinja の既定は
  `"` を `&quot;`、`'` を `&#x27;`、`/` を `&#x2f;` にする（はず）。招待リンク（`&` と `/` を含む）などがバイト単位で
  変わるので、**minijinja の出力の書き方（formatter）を markupsafe に合わせる**
- `None` の出し方: Jinja2 は `None`、minijinja は `none`（はず）。いまのテンプレートで None を出す場所は無さそうだが、
  formatter で `None` にそろえておく
- 文字列の添字 `s[0]`（`guild.name[0]`・`session.guild_name[0]`）が minijinja で 1 文字を返すか
- 末尾の改行: Jinja2 の既定は最後の改行 1 つを落とす（`keep_trailing_newline=False`）。minijinja も既定で落とす（はず）
- 未定義の扱い: Jinja2 の既定（表示は空、属性を引くとエラー）。minijinja は Lenient が近い

### 4.3 グローバルの中身

- `admin_asset_url(name)`: `/static/{name}?v={ADMIN_ASSET_VERSION（既定 admin）}-{更新時刻 ns の 16 進}-{大きさの 16 進}`。
  static の外を指す・読めないときは `?v={ADMIN_ASSET_VERSION}` だけ。**Rust の管理画面のイメージにも
  `webapp_admin/static` を入れる**（nginx が返すものと同じファイルの時刻と大きさを見るため。w01 の nginx の
  イメージと同じ中身にする）
- `icon(name)`: 先頭の `bi-` を落とし、`^[a-z0-9-]+$` でなければ空。`<svg class="{css_class}" aria-hidden="true"
  focusable="false"><use href="/static/icons/sprite.svg#{name}"></use></svg>`
- `url_for(name)`: 表引き（`landing`→`/`、`guide`→`/guide`、`privacy`・`terms`、`login`→`/admin/login`、
  `oauth_start`→`/admin/auth`、`callback`、`logout`→`/admin/logout`、`index`・`admin_root`→`/admin/`、
  `guild_select`→`/admin/guilds`、`select_guild`→`/admin/guilds/select`、`overview`、`static`→`/static/{path}`）。
  `auth.login` のような点つきは最後の部分で引く。無い名前は `/{name}`
- 知らせ（flash）: `_flashes` に `[種類, 文]` を積み、次の `render()` で取り出す（取り出すとセッションが変わるので
  Set-Cookie が出る）

---

## 5. /static と nginx（w01 と揃えること）

- nginx が `webapp_admin/static` を返す（w01）。見出しは Python の `/static` と同じ（1.6 の `Cache-Control` など）＋
  セキュリティの見出し
- Python と変わるところ（害は無い）: Python は `/static` の応答にも Set-Cookie を出していた（SessionMiddleware が
  外側にあるため）。nginx は出さない。`/static` が既定のレート制限に数えられていたか（slowapi）は確かめていない

---

## 6. /metrics（Netdata が読む）

- `METRICS_PATH`（既定 `/metrics`）。接続元が `METRICS_ALLOWED_CIDRS`（既定 `127.0.0.1/32,::1/128,172.16.0.0/12`）に
  入っていなければ `403`・本文 `Forbidden\n`（text/plain）。入っていれば
  `Content-Type: text/plain; version=0.0.4; charset=utf-8` で、Valkey の `metrics` の下（心拍・ゲージ・カウンタ）と
  その場で測るもの（`sycs_admin_request_tps`・`sycs_admin_uptime_seconds`、バックアップの状態ファイル
  `BACKUP_STATUS_FILE` が置いてあるなら `sycs_backup_age_seconds`・`sycs_backup_status`）
- **接続元の判定に注意（いちばん大事）**: `prometheus_view.client_allowed` は `request.client.host` を見る。これは
  TCP の相手そのものではなく、**uvicorn が `X-Forwarded-For` で直したあとの値**（直接の相手が
  `TRUSTED_PROXY_CIDRS` に入っているときだけ、XFF を右から見て、信頼する帯域でない最初のものに直す。全部が
  信頼する帯域なら左端）。Cloudflare のトンネルから来た要求は、ここで外の利用者の IP に直るので 403 になる。
  **nginx の後ろの Rust で TCP の相手（nginx のコンテナ、172.16.0.0/12 の中）を見ると、外から /metrics が読める。**
  Rust は sycs-web の「信頼するプロキシで直した接続元」を使い、uvicorn と同じ規則にする（w01 と揃える。A7 で、
  Python の uvicorn の規則から作った接続元の表を基準にする）
- Python では `_register_metrics_endpoint` の docstring が「既定のレート制限が掛からない位置に足した」と書いている。
  Rust では /metrics に制限を掛けない

---

## 7. 設定パネル（`webapp_admin/schema/` → `schema.json`）

- この塊で、宣言を JSON に書き出す道具を作った（`rust/apps/admin/tests/fixtures/schema/generate.py`。CI の
  「基準」が `schema.json` を作る）。中身は道具の先頭に書いた（パネルごとの `wire`＝`Panel.to_json()` そのもの、
  タイル、入力欄・一覧ごとの関数の名前、関数の手がかり〔呼ぶ services の関数・鍵らしい文字列・閉じ込めた値・定数〕）
- **決めたこと（推す形）**: Rust は `schema.json` をビルドのときに読み込む（`include_str!`。スラッシュコマンドの
  definitions.json と同じ）。画面へ返す形は `wire` をそのまま（キーの並びも同じなので、本文がバイトまで同じになる）。
  検証（`validation.py`）・選択肢の解決（`choices.py`）・`to_json_value`・`coerce` は Rust で書く（宣言の値を読むだけで
  済むので、`wire` から作れる）
- getter・setter は Rust の関数で書き、`schema.json` の名前で引く（名前 → Rust の関数の表）。名前の表に無いもの・
  余ったものがあればテストで落とす（宣言に入力欄が増えたのに Rust が知らない、を CI で気づく）
- getter・setter が同じ値を出すかの確かめは、A5・A6 の基準（設定の JSON を決めて Python の getter を呼んだ値、
  setter を呼んだあとの設定の JSON）でする。`identifiers` は手がかりで、確かめの代わりにはならない
- 検証は純粋な関数なので、基準は表（入力欄 × 入力 → 値かエラーの文）にできる（A6）

---

## 8. 基準の作り方の型（この塊で作った `users_state` が手本）

API の塊は、どれも次の 4 つで作る。

1. **例の文書 `cases.json`**（`rust/apps/admin/tests/fixtures/<名前>/`）: 秘密鍵・`now`・セッションの名前つきの
   一覧・`library`（行などの部品）・例の並び。例は「要求（method・target〔パスとクエリ、% で書く〕・headers・json・
   form）、どのセッションで・どの Cookie で（fresh・edge・expired・future・tampered）、偽物の services が返すもの」。
   JSON に無い型は印で書く（`$datetime`・`$int`・`$ref`/`with`・`$raise`）。道具の確かめに `expect_status`
2. **道具 `generate.py`**: `../admin_harness.py` を使う。差し替える services の関数（API のモジュールが import した
   名前）と、例の service の鍵の対応（`SERVICES`）を書き、`_patches` を作るだけ。本物の管理画面の app に
   TestClient で通し、例ごとに「送った要求（実際の target と見出し・Cookie）・偽物に届いた呼び出し（引数まで）・
   応答（状態・見出し〔名前の順〕・本文〔文字列のまま〕・読んだ JSON）」を `expected.json` に書く
3. **`tools/fixtures/regen.py` の GENERATORS に 1 行**（道具が自分で書き出すので標準出力は None。空の Postgres が
   要るものは最後を True）。expected は手で作らない（CI の「基準」が作り、差分を成果物で返す）
4. **Rust のテスト**（その塊で書く）: 両方を読み、API の層に「偽物の services」（Rust の trait の実装。例の service を
   返し、呼び出しを控える）を渡して app を組み、署名の時計を `now` に合わせ、例ごとに `oneshot` で送る。比べるのは
   状態・見出し（Python の見出しが全部、同じ値で出ていること。名前の順で比べる）・本文（**バイトまで**）・呼び出し
   （関数の名前と引数）

決めごと:

- services の層（SQL など）は API の基準とは別の基準にする（空の Postgres に行を入れて Python の関数の戻り値を
  書く。bot の `user_state` の基準と同じやり方）。API の基準は「services が返したもの → 応答」だけを決める
- 時刻に頼るもの（いまタイムアウト中か）は、遠い過去（2001 年）と遠い未来（2999 年）だけを例にする
- 地方時は JST に固定（本番の TZ と同じ）。時差の無い datetime は本番の Postgres（timestamptz）からは来ないが、
  Python の分岐としてあるので例に入れてある。Rust の型で表せないなら、その例だけ理由を書いて飛ばしてよい
- 外へ出る API（Discord・P2P地震情報・ニュース・Groq・TTS）を使う塊は、偽物のサーバーを立てるか、services の関数を
  差し替えるかを塊ごとに決める（HTTP の形まで揃えたいものは偽物のサーバー）

---

## 9. 塊の案（1 塊 = プルリク 1 本）

| 塊 | 中身 | 基準（Python から作るもの） | 先に要る塊 | 列 |
|---|---|---|---|---|
| A0 | **この塊**: 計画・設定パネルの書き出し・API の基準の型（利用者の状態の HTTP の層） | `schema/schema.json`・`users_state/expected.json` | — | 済 |
| A1 | `apps/admin` の骨組み: 起動（sycs-web）、秘密鍵の解決、Cookie（3.1）、4 つの確かめ、CSRF、JSON のエラー（1.4）、見出し（1.6）、404・405・末尾の `/`、レート制限、要求の計数と 5xx のインシデント | `session/`（秘密鍵・時刻・中身 → Cookie の文字列、読めるか。〔署名のずれ・期限・未来・壊れた中身〕）、`errors/`（経路の種類 × Accept × 状態 → 応答。HTML の本文は A2 で） | W0（sycs-web・nginx） | 1 |
| A2 | テンプレートと公開ページ: minijinja（4.）、`admin_asset_url`・`icon`・`url_for`・知らせ・`csrf_token`、エラーのページ（HTML）、`/`・`/guide`・`/privacy`・`/terms`・301 の 3 本、ログイン画面・ログアウトの確認・サーバー選択・シェル | `templates/`（例ごとの文脈 → HTML。static は時刻と大きさを決めた偽物の置き場） | 描く関数は単独で作れる（経路は A1 のあとでつなぐ） | 2 |
| A3 | ログインとサーバー選択: /admin/login・/auth・/callback・/logout（GET・POST）・/admin/・/admin/guilds・/guilds/select、招待リンク、サーバー数（5 分） | `auth/`（偽物の Discord で、各段の失敗・成功の応答とセッション）、`admin_check/`（`user_still_admin` の権限の組み立て。純粋な表） | A1・A2 | 1 |
| A4 | 利用者の状態: 2 本の API（HTTP の層は A0 の基準）と、読み出しの SQL（`_apply_state_filter`・並び・件数） | `users_state/`（A0）、`users_state_db/`（空の Postgres に行を入れ、3 つの関数の戻り値） | A1 | 2 |
| A5 | 設定パネル（読む側）: /admin/api/apps・/apps/{id}（`schema.json`、タイルとバッジ、選択肢〔チャンネル・ロールの使い回しと 429 の待ち、TTS の声〕、getter） | `apps_read/`（偽物の Discord・TTS、設定を決めて GET）、`getters/`（設定の JSON → 各 getter の値） | A1 | 1 |
| A6 | 設定パネル（書く側）: PUT /apps/{id}、一覧の追加・更新・削除、DELETE /guild-data（検証・setter・サーバーのデータの削除） | `validation/`（純粋な表）、`apps_write/`（Postgres の設定 → 要求 → 応答と書いたあとの設定） | A5 | 1 |
| A7 | 監視: /admin/api/metrics・/incidents、監視の巡回（心拍・停止・しきい値）、/metrics（Valkey → 本文、接続元の判定 6.）、メトリクスの報告 | `monitor/`（インシデントのファイル → 一覧・SLA、整形の関数）、`prometheus/`（Valkey の中身 → 本文、接続元 × XFF → 通すか） | A1 | 2 |
| A8 | 開発者パネル（中で済むもの）: overview・logs・settings の書き出しと取り込み・cache（一覧・削除・掃除）・signal・test-notify・earthquake-replay（`dev_signal` 表へ。sycs-core の signals に「置く」「待っている用途」を足す） | `dev_local/`（偽物のログ・設定・キャッシュの置き場、置いた dev_signal の行） | A1 | 2 |
| A9 | 開発者パネル（外へ出るもの）: send-message・forward-message・news-send・earthquakes・channels・user | `dev_remote/`（偽物の Discord・P2P地震情報・ニュース・Groq） | A8・A3（偽物の Discord） | 1 |
| A10 | SQL エディタ: servers・objects・ddl・query・cancel | `sql_split/`（`split_statements` の表。純粋）、`sql_cells/`（型ごとのセルの変換。Postgres）、読み取り専用・打ち切り・止める | A1 | 2 |
| A11 | 切り替え: compose の profile、nginx の上流を Rust の管理画面へ、CI のイメージ（GHCR）、UPGRADE の行、戻し方 | — | 全部 | 親 |

並べ方（2 体。各段の 2 つは同時に進めてよい。同じ段の 2 つが触る既存のファイルは `apps/admin` の経路の組み立て
〔1 行ずつ足す〕と Cargo.toml だけになるように分ける）:

```text
段 1:  A1（列 1） ∥ A2（列 2）
段 2:  A3（列 1） ∥ A4（列 2）
段 3:  A5（列 1） ∥ A7（列 2）
段 4:  A6（列 1） ∥ A8（列 2）
段 5:  A9（列 1） ∥ A10（列 2）
段 6:  A11（親）
```

- 重いのは A6（setter の数が多い）と A10（任意の SQL の結果の型を JSON にする。sqlx は型を知らないと読めないので、
  型の OID ごとに読み分けるか、テキストで受けて Python と同じ形に直すかを A10 の最初に決める）
- 新しく要りそうな crate: `minijinja`（A2）、ホストの CPU・メモリ（A7。`/proc` を読むか `sysinfo`）。`hmac`・`sha1`・
  `base64`・`subtle`・`ipnet`・`serde_urlencoded` はロックに既にある（A1・A7）

---

## 10. 切り替えと戻し方（考え方。手順は A11 で UPGRADE に書く）

- Bot と同じく安全側: compose の既定は Python のまま。Rust の管理画面は CI がイメージを作って GHCR に置き、本番は
  取ってくるだけ。nginx の上流（w01 の環境変数）を Python から Rust へ変えると切り替わり、戻すと戻る
- **ログインが切れない条件**: 同じ秘密鍵（`ADMIN_FLASK_SECRET_KEY` か同じ `SETTINGS_DIR` の鍵のファイル）と、
  同じ Cookie の形（3.1。A1 の基準で確かめる）
- 同じ置き場を読み書きするもの: 設定（Postgres の bot_settings。sycs-core の settings）、`dev_signal` 表、
  `incidents.jsonl`・`heartbeat.json`、ログ（`admin.log`・`admin.jsonl`）、Valkey のメトリクスの鍵。同時に両方を
  動かさない（監視の巡回が二重になる）

---

## 11. 親か本人に決めてほしいこと（推す答えつき）

1. `schema.json` を Rust に焼き込むか、実行時に読むか → **焼き込む**（7.）
2. 422 の本文（pydantic の文言）まで揃えるか → **揃える**（基準で比べる。種類は数えるほど）。ただし pydantic は
   requirements.txt で版を決めていない（fastapi の依存）。上がると文言が変わりうるが、そのときは CI の「基準」が
   落ちて気づける
3. 64 ビットを超える `user_id`（`/admin/api/users/state/99999999999999999999`）→ Python はそのまま services に渡す。
   Discord の ID にはありえないので、Rust で 422 にしてよいか（基準の `detail_id_beyond_64_bits` を「Rust では変える」
   として飛ばす）。**推す: 変える**（u64 で持つ）
4. 末尾の `/` の 307（`/admin/api/users/state/` → `/admin/api/users/state`）を写すか → **写す**（基準で比べる）

## 12. 見直しの候補（Python は凍結中なので直さない。気づいたことだけ）

- `prometheus_view.py` の冒頭「転送ヘッダは一切見ていない」は、uvicorn が先に XFF で直した接続元を見ているので、
  言い方が実態と違う（守りは効いている。6.）。Rust ではここを取り違えると穴になる
- Bot のサーバーの一覧（`_get_bot_guild_ids`）は `limit` を付けていない（Discord の既定は 200 件）。Bot が 200 を超える
  サーバーに入ると、管理できるサーバーが欠ける（いまは 7）。`get_bot_guild_count` は `limit=200` で数えるので、
  数も 200 で頭打ち
- 戻り（callback）で `error` が来たとき `oauth_state` を消さない（次の /auth で上書きされるので害は無い）
- 一覧の行の `user_id` は、無いと文字列の `"None"` になる（`str(None)`。Postgres の行には必ずある）
- パネルの旧 URL の `/admin/dev` は、開発者でなくても 303 で `#dev` へ送る（開発者パネルがあることがログイン済みの
  人には分かる。API は 404 で隠している）
- 既定のレート制限（SlowAPIMiddleware）で返る 429 は、見出しの係より外で作られるので、CSP などが付かないかもしれない
  （確かめていない。A1 の基準で見る）

## 13. 確かめていないこと

- この塊の道具は、手元で一度も動かしていない（手元で python を動かさない決まり）。CI の「テスト」「基準」で初めて動く
- starlette・FastAPI・itsdangerous・uvicorn の細部（Set-Cookie の文字列、405 の Allow、末尾の `/`、422 の本文、
  XFF の読み方、429 の見出し）は、読んだコードと記憶からの見立て。どれも基準で確かめる形にしてある
- minijinja の振る舞い（4.2）は記憶。A2 の最初に確かめる
