# デプロイと環境変数

[← README.ja.md に戻る](../README.ja.md)

---

## 4. Docker Compose

```bash
docker compose up -d --build
```

主要公開ポート:
- 管理 UI: `5001`
- Web トラッカー: `8001`

---

---

## 5. 環境変数（最低限）

### 5.1 Discord Bot（`main.py`）

| 変数 | 必須 | 説明 |
|---|---|---|
| `DISCORD_BOT_TOKEN` | Yes | Bot トークン |
| `METALPRICE_API_KEY` | 推奨 | 金属価格 API |
| `GROQ_API_KEY` | 任意 | AI 会話/モデレーション。metalprice の週次予測AI判定にも使用（`sycs-voldemort-web`にも設定要） |
| `NEWS_SUMMARY_MODEL` | 任意 | ニュース要約用モデル（既定 `openai/gpt-oss-120b`） |
| `GROQ_MAX_CONCURRENT_REQUESTS` | 任意 | Groq呼び出しの用途別(会話/モデレーション/ニュース要約/metalprice予測)同時実行数上限（既定 `3`）。`services/groq_client.py`が共通で使用 |
| `GROQ_MIN_REQUEST_INTERVAL_SECONDS` | 任意 | Groq呼び出しの用途別最小間隔秒（既定 `0.25`） |
| `GROQ_MAX_RETRIES` | 任意 | Groqが429(レート制限)を返した際の最大リトライ回数（既定 `2`） |
| `GROQ_RETRY_BASE_DELAY_SECONDS` | 任意 | 429リトライの基準待機秒(指数バックオフ、`Retry-After`ヘッダが無い場合に使用、既定 `2.0`) |
| `GROQ_RETRY_MAX_DELAY_SECONDS` | 任意 | 429リトライ待機秒の上限（既定 `20.0`） |
| `VIRUSTOTAL_API_KEY` | 任意 | URL/ファイルスキャン |
| `VT_MAX_DOWNLOAD_BYTES` | 任意 | VTスキャン時の最大ダウンロードサイズ（既定 `20971520` = 20MB） |
| `SETTINGS_DIR` | 任意 | `settings.json` 保存先 |
| `SETTINGS_LOCK_TIMEOUT_SECONDS` | 任意 | `settings.json` 更新ロック待機秒数（既定 `10`） |
| `SETTINGS_LOCK_STALE_SECONDS` | 任意 | 古いロックファイルを破棄する閾値秒数（既定 `30`） |
| `BOT_BACKGROUND_WORKER` | 任意 | `true/false`。定期ジョブ実行ノードかどうか（既定 `true`） |
| `USER_STATE_POSTGRES_DSN` | 任意 | ユーザー状態監査DB接続先をDSNで直指定 |
| `USER_STATE_POSTGRES_HOST`/`USER_STATE_POSTGRES_PORT`/`USER_STATE_POSTGRES_DB`/`USER_STATE_POSTGRES_USER` | 任意 | ユーザー状態監査DB接続先（既定DB名: `user_state_audit`） |
| `USER_STATE_POSTGRES_PASSWORD` or `USER_STATE_POSTGRES_PASSWORD_FILE` | 任意 | ユーザー状態監査DBパスワード |
| `USER_STATE_SYNC_ON_READY` | 任意 | 起動時にDiscord状態をDBへ同期（既定 `true`） |
| `USER_STATE_SYNC_DELAY_SECONDS` | 任意 | 起動時同期の遅延秒（既定 `20`） |
| `USER_STATE_SYNC_GUILD_PAUSE_SECONDS` | 任意 | ギルド間同期の待機秒（既定 `1.0`） |
| `USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD` | 任意 | 同期時の取得メンバー上限（`0`で無制限） |
| `USER_STATE_AUTO_REPAIR_ENABLED` | 任意 | 定期自動修復ループを有効化（既定 `true`） |
| `USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS` | 任意 | 定期修復の実行間隔秒（既定 `1800`） |
| `USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS` | 任意 | 起動後、最初の定期修復までの待機秒（既定 `180`） |
| `USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD` | 任意 | 1ギルドあたりの整合性修復対象上限（既定 `50000`） |
| `USER_STATE_AUTO_REPAIR_WRITE_EVENTS` | 任意 | 定期修復時にも同期イベントを書き込む（既定 `false`） |
| `USER_STATE_RETENTION_DAYS` | 任意 | 状態監査履歴の保持日数（既定 `3650`） |
| `USER_STATE_CLEANUP_INTERVAL_SECONDS` | 任意 | 古い履歴削除の実行間隔秒（既定 `21600`） |
| `DJAUDIO_BASE_URL` | DJAudio時推奨 | MP3 配信 URL ベース。未設定時は `http://localhost:5001` になり配信リンクが外部から開けなくなるため、本番では必ず外部到達可能な URL を設定すること（未設定/localhostのままだと起動時ログと `/djaudio_status` に警告が出る） |
| `DJAUDIO_FFMPEG_PATH` | 任意 | ffmpeg 実行ファイルを明示指定 |
| `DJAUDIO_AUTO_INSTALL_FFMPEG` | 任意 | `true/false`（既定 `true`） |
| `TTS_BASE_URL` | TTS使用時必須 | macOS TTS API サーバーの URL（既定 `http://localhost:8080`） |
| `METALPRICE_CACHE_TTL_SECONDS` | 任意 | 金属価格APIの呼び出し結果をキャッシュする秒数（既定 `1800` = 30分）。無料枠APIの呼び出し過多を防ぐ |

### 5.2 管理 UI（`admin_main.py`）

| 変数 | 必須 | 説明 |
|---|---|---|
| `DISCORD_BOT_TOKEN` | Yes | Bot API 呼び出しに使用 |
| `DISCORD_CLIENT_ID` | Yes | OAuth クライアントID |
| `DISCORD_CLIENT_SECRET` | Yes | OAuth クライアントシークレット |
| `DISCORD_REDIRECT_URI` | Yes | OAuth リダイレクトURL |
| `DISCORD_OAUTH_PROMPT` | 任意 | `none` / `consent` を明示したい場合に指定（未指定時はDiscord既定挙動） |
| `ADMIN_FLASK_SECRET_KEY` | 推奨 | セッション署名キー。未設定時は初回起動時に自動生成し `SETTINGS_DIR/.admin_session_secret` に保存（再起動後も同一キーを継続使用）。複数コンテナ構成では全ノードで同一値を明示設定してください |
| `ADMIN_PORT` | 任意 | デフォルト `5001` |
| `ADMIN_LIMITER_STORAGE_URI` | 任意 | レート制限ストレージ（既定 `memory://`、分散時はRedis推奨） |
| `USER_STATE_POSTGRES_DSN` | 任意 | ユーザー状態監査DB接続先をDSNで直指定 |
| `USER_STATE_POSTGRES_HOST`/`USER_STATE_POSTGRES_PORT`/`USER_STATE_POSTGRES_DB`/`USER_STATE_POSTGRES_USER` | 任意 | ユーザー状態監査DB接続先（既定DB名: `user_state_audit`） |
| `USER_STATE_POSTGRES_PASSWORD` or `USER_STATE_POSTGRES_PASSWORD_FILE` | 任意 | ユーザー状態監査DBパスワード |
| `DEV_USER_ID` | 任意 | 開発者パネル（`/admin/dev`）にアクセスできる Discord ユーザーID。**未設定時はパネル全体が 404 で無効化される** |

### 5.3 Web トラッカー（`web_main.py`）

| 変数 | 必須 | 説明 |
|---|---|---|
| `WEB_PORT` | 任意 | デフォルト `8000` |
| `WEB_SCHEDULER_ENABLED` | 任意 | `true/false`。日次更新/Push通知ジョブを実行するか（既定 `true`） |
| `METAL_AUTO_REPAIR_ENABLED` | 任意 | `true/false`。metalprice DBの定期自動修復を実行するか（既定 `true`） |
| `METAL_AUTO_REPAIR_INTERVAL_MINUTES` | 任意 | 自動修復の実行間隔（分、既定 `30`）。delta_from_previous・metal_codeの整合性チェックは外部APIを消費しない純粋なローカル計算のため、範囲を絞らず常に全履歴が対象 |
| `METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH` | 任意 | 各修復時に予測キャッシュ再生成を強制（既定 `false`） |
| `METAL_REPAIR_RETRY_COOLDOWN_HOURS` | 任意 | 本日分の価格データ欠損を検知した際、API再取得を再試行するまでのクールダウン時間（時間、既定 `6`）。MetalpriceAPIの無料枠(月100回)を無条件リトライで食いつぶさないための制限 |
| `FORECAST_REFRESH_EXTRA_HOURS_JST` | 任意 | 週次予測を日中に強制リフレッシュするJST時刻（カンマ区切り、既定 `6,12,18`）。0時分はJST 00:00の日次スナップショットジョブが既にカバーしているため対象外。以前は毎時(1日24回)リフレッシュしGroq/ニュースRSS/為替APIを浪費していたため間引いた |
| `FORECAST_LLM_WEIGHT` | 任意 | AI(Groq)判定のスコア×確信度が予測日次リターンに反映される係数（既定 `0.008`）。heuristic_daily_returnのclamp(±4%/日)は別途維持される |
| `FORECAST_HISTORY_WINDOW_MIN_DAYS` | 任意 | SARIMAX予測に与える価格履歴の最小日数（既定 `120`）。長いほど季節性・トレンドを学習しやすいが、DBクエリ・計算コストは増える |
| `FORECAST_SUMMARY_ENABLED` | 任意 | `true/false`。「予測の根拠」の専門的な箇条書きをGroqで平易な要約文に言い換えるか（既定 `true`）。scoring用のGroq呼び出しとは別に、予測リフレッシュ1回につき+1回呼び出す |
| `FORECAST_SUMMARY_TIMEOUT_SECONDS` | 任意 | 上記要約呼び出しのタイムアウト秒数（既定 `20`） |
| `TRUST_CF_HEADERS` | 任意 | `true/false`。CFヘッダを信頼するか（既定 `false`） |
| `REQUIRE_CF_CONNECTING_IP` | 任意 | `true/false`。CFヘッダ必須化（既定 `false`） |
| `TRUSTED_PROXY_CIDRS` | 任意 | Forwardedヘッダを信頼するプロキシCIDR（既定 `127.0.0.1/32,::1/128`） |
| `ALLOWED_HOSTS` | 推奨 | 受け付けるHost（例: `example.com,www.example.com`） |
| `PUSH_MAX_SUBSCRIPTIONS` | 任意 | Push購読上限（既定 `50000`） |
| `PUSH_ALLOWED_ENDPOINT_SUFFIXES` | 任意 | Push endpoint 許可ドメインサフィックス（カンマ区切り） |
| `POSTGRES_*` | 通常必要 | DB 接続設定 |

詳細な環境変数は `config.py` と `docker-compose.yml` を参照してください。

metalprice 側の定期処理（日次更新/予測更新/自動修復）は `sycs-voldemort-web` コンテナ内の `webapp/app.py` のスケジューラで実行されます。
`WEB_WORKERS`（既定 `2`）で複数ワーカーを起動している場合でも、PostgreSQLのadvisory lockを取得できた
ワーカー1つだけが定期ジョブを担当するため、同一コンテナ内での二重実行は自動的に防止されます
（`webapp/app.py` の `_try_acquire_scheduler_lock`）。これは**別コンテナ/別ホストの複数インスタンス**
までは排他できないため、その場合は下記の通り `WEB_SCHEDULER_ENABLED` を明示的に1台だけ有効にしてください。

### 5.4 マルチインスタンス運用の推奨

- Discord Bot を複数インスタンスで動かす場合:
  - 定期ジョブ担当 1台だけ `BOT_BACKGROUND_WORKER=true`
  - それ以外は `BOT_BACKGROUND_WORKER=false`
- Web トラッカーを複数インスタンス（別コンテナ/別ホスト）で動かす場合:
  - スケジューラ担当 1台だけ `WEB_SCHEDULER_ENABLED=true`
  - それ以外は `WEB_SCHEDULER_ENABLED=false`
- Reverse Proxy 配下で運用する場合:
  - `TRUSTED_PROXY_CIDRS` にプロキシCIDRを設定
  - Cloudflare 直下構成のみ `TRUST_CF_HEADERS=true` を有効化
  - 公開ドメインを `ALLOWED_HOSTS` に明示設定
- 管理UIを複数インスタンスで動かす場合:
  - 同一コンテナ内の複数ワーカーはシークレットキーを自動共有するため追加設定不要
  - 複数コンテナ（ロードバランサ構成）では全ノードで同じ `ADMIN_FLASK_SECRET_KEY` を明示設定
  - `ADMIN_LIMITER_STORAGE_URI` に Redis を設定
- DJAudio-DL を複数ノードで使う場合:
  - `DJAUDIO_CACHE_DIR` を共有ストレージにする（または配信ノードを固定）

---
