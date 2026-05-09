# SYCS Voldemort

Discord Bot（運用支援）+ FastAPI 管理 UI + FastAPI Web トラッカーをまとめたプロジェクトです。

## 1. 機能一覧（具体）

### 1.1 金属価格コマンド
- `/metal_gold` `/metal_silver` `/metal_platinum` `/metal_all`
- JPY ベースで価格取得し、グラム指定で合計額を表示
- Embed で見やすく出力

### 1.2 AI 会話（チャンネル制御あり）
- 指定チャンネルのみ AI 応答（`/chat_channel_set` / `/chat_channel_clear`）
- ユーザーごとに会話コンテキストを保持
- モデレーション連携あり

### 1.3 監査ログ
- ログチャンネルとログレベルを設定可能（`NONE/ERROR/INFO/DEBUG`）
- 主な対象イベント:
  - メッセージ削除/編集
  - VC 参加/退出/移動
  - メンバー参加/退出
  - ニックネーム変更、ロール変更
  - タイムアウト、BAN/UNBAN

### 1.3.1 ユーザー状態監査DB（10年保持）
- `user_state_current`: 各ユーザーの最新状態（在籍/BAN/Timeout/ロール/権限）を保持
- `user_state_event`: 参加/退出、BAN/KICK、VC入退室、ロール変更などを時系列保存
- 保持期間は既定10年（`USER_STATE_RETENTION_DAYS=3650`）で、古い履歴は定期削除
- 価格データDB（`POSTGRES_DB`）とは別DB（既定 `USER_STATE_POSTGRES_DB=user_state_audit`）で管理可能
- DB不整合時はテーブル再生成を試み、定期突合で同期ズレ（在籍/BAN/Timeout/JSON破損）を自動補正
- 管理UIの `/admin/users/state` で検索・閲覧可能

### 1.4 ウェルカム / グッバイ
- 参加/退出時の自動メッセージ
- テンプレート変数対応: `{user}` `{username}` `{server}` `{count}`

### 1.5 VC 通知
- VC 参加/退出/移動を専用チャンネルへ通知
- 退出時は通話時間を表示
- ロールメンション通知（間隔制限あり）

### 1.6 スティッキーメッセージ
- チャンネルごとに固定メッセージを維持
- 新規投稿に追従して再掲

### 1.7 リアクションロール
- メッセージID + 絵文字ごとにロール付与/解除
- Unicode 絵文字 / カスタム絵文字対応

### 1.8 Google News フィード
- キーワード検索を定期実行して新着を投稿
- `GROQ_API_KEY` がある場合、本文を 400 文字以内で要約して添付
- フィード上限: 1サーバー最大10件
- 間隔: 5〜1440分
- 重複抑止（既出記事ハッシュ管理）

### 1.9 地震アラート（P2PQuake）
- WebSocket 常時接続で地震情報を配信
- 通知タイプの ON/OFF 切り替え:
  - `eew_forecast`, `eew_warning`, `tsunami`, `quake_info`, `bot_news`
- 最小震度フィルタ設定あり

### 1.10 DJAudio-DL
- 監視チャンネルに投稿された URL から MP3 を生成して配信リンクを送信
- 期限付き配信リンク（TTL）で提供し、期限後に自動削除
- 対応例: YouTube / SoundCloud / Bandcamp / ニコニコ動画 / TikTok / 汎用URL
- 非対応例: Spotify / Apple Music / Amazon Music
- 設定可能:
  - 監視チャンネル（URL を投稿するチャンネル）
  - 出力チャンネル（MP3 リンクを送信するチャンネル。未設定時は監視チャンネルに返信）
  - TTL
  - クールダウン
  - 1メッセージあたりのURL上限

### 1.11 セキュリティ検知
- スパム判定
- Unicode トリック検知
- VirusTotal URL/添付スキャン
- GPT モデレーション
- VC レイド検知
- 信頼済みユーザー / バイパスロールによる除外設定

### 1.12 管理 UI（FastAPI）
- Discord OAuth ログイン
- サーバー単位設定
- Web 上で以下を管理:
  - ログ設定、AI 応答、ウェルカム/グッバイ、VC 通知
  - スティッキー、リアクションロール、ニュース
  - 地震アラート、DJAudio、セキュリティ
  - ユーザー状態監査（参加/退出、BAN/KICK、アビリティ履歴）
- 開発者パネル（`/admin/dev`）— 特定ユーザー専用:
  - メッセージ直接送信・転送 / ニュース手動配信 / 地震速報リプレイ
  - 定期タスクの即時実行（シグナル）
  - ギルド設定 JSON 閲覧・エクスポート・インポート
  - 通知テスト送信（ウェルカム / VC 通知）
  - Discord ユーザー検索（Snowflake → アカウント情報）
  - スティッキーメッセージ全件一覧
  - 環境変数チェッカー（秘密情報はマスク表示、デフォルト値がある変数は `DEFAULT` で表示）
  - DJAudio MP3 キャッシュ管理
  - bot / admin ログビューア（自動更新対応）

### 1.13 Web トラッカー（FastAPI）
- 金属価格 API
- 価格予測
- Push 通知（PWA）

### 1.14 機能と管理導線（早見表）
| 機能 | Discord 側 | 管理 UI 側 |
|---|---|---|
| ログ / AI 応答チャンネル | `/log_channel_set` `/log_level_set` `/chat_channel_set` `/chat_channel_clear` | `/admin/settings/logging` |
| ウェルカム / グッバイ | `/welcome_*` `/goodbye_*` `/welcome_goodbye_status` | `/admin/settings/welcome` |
| VC 通知 | `/vc_notify_channel_set` `/vc_notify_channel_clear` | `/admin/settings/vc-notify` |
| スティッキー | `/sticky_set` `/sticky_clear` `/sticky_list` | `/admin/settings/sticky` |
| リアクションロール | `/reaction_role_add` `/reaction_role_remove` `/reaction_role_list` | `/admin/settings/reaction-roles` |
| Google News | `/news_feed_add` `/news_feed_remove` `/news_feed_list` | `/admin/settings/news-feeds` |
| 地震アラート | `/quake_channel_set` `/quake_min_scale_set` `/quake_notify_type` `/quake_status` | `/admin/settings/earthquake` |
| セキュリティ除外設定 | `/trusted_member_*` `/bypass_role_*` | `/admin/settings/security` |
| DJAudio-DL | `/djaudio_channel_set` `/djaudio_output_set` `/djaudio_status` | `/admin/settings/djaudio` |
| ユーザー状態監査 | （イベント自動収集） | `/admin/users/state` |

---

## 2. 全体構成

| プロセス | エントリーポイント | 役割 |
|---|---|---|
| Discord Bot | `main.py` | Discord イベント処理とスラッシュコマンド |
| Admin UI | `admin_main.py` | 管理画面（FastAPI） |
| Web App | `web_main.py` | 金属価格トラッカー（FastAPI） |

設定は `services/settings_store.py` が `settings.json` に永続化します。

---

## 3. クイックスタート（ローカル）

### 3.1 依存インストール

```bash
pip install -r requirements.txt
```

DJAudio で必要な `ffmpeg` は、未検出時に自動取得されます（`imageio-ffmpeg`）。
手動指定したい場合は `DJAUDIO_FFMPEG_PATH` を設定してください。

### 3.2 起動

```bash
# 1) Discord Bot
python main.py

# 2) 管理 UI
python admin_main.py

# 3) Web トラッカー
python web_main.py
```

---

## 4. Docker Compose

```bash
docker compose up -d --build
```

主要公開ポート:
- 管理 UI: `5001`
- Web トラッカー: `8001`

---

## 5. 環境変数（最低限）

### 5.1 Discord Bot（`main.py`）

| 変数 | 必須 | 説明 |
|---|---|---|
| `DISCORD_BOT_TOKEN` | Yes | Bot トークン |
| `METALPRICE_API_KEY` | 推奨 | 金属価格 API |
| `GROQ_API_KEY` | 任意 | AI 会話/モデレーション |
| `NEWS_SUMMARY_MODEL` | 任意 | ニュース要約用モデル（既定 `llama-3.3-70b-versatile`） |
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
| `DJAUDIO_BASE_URL` | DJAudio時推奨 | MP3 配信 URL ベース |
| `DJAUDIO_FFMPEG_PATH` | 任意 | ffmpeg 実行ファイルを明示指定 |
| `DJAUDIO_AUTO_INSTALL_FFMPEG` | 任意 | `true/false`（既定 `true`） |

### 5.2 管理 UI（`admin_main.py`）

| 変数 | 必須 | 説明 |
|---|---|---|
| `DISCORD_BOT_TOKEN` | Yes | Bot API 呼び出しに使用 |
| `DISCORD_CLIENT_ID` | Yes | OAuth クライアントID |
| `DISCORD_CLIENT_SECRET` | Yes | OAuth クライアントシークレット |
| `DISCORD_REDIRECT_URI` | Yes | OAuth リダイレクトURL |
| `DISCORD_OAUTH_PROMPT` | 任意 | `none` / `consent` を明示したい場合に指定（未指定時はDiscord既定挙動） |
| `ADMIN_FLASK_SECRET_KEY` | Yes | セッション署名キー |
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
| `METAL_AUTO_REPAIR_INTERVAL_MINUTES` | 任意 | 自動修復の実行間隔（分、既定 `30`） |
| `METAL_AUTO_REPAIR_LOOKBACK_DAYS` | 任意 | 自動修復で整合性チェックする履歴日数（既定 `60`） |
| `METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH` | 任意 | 各修復時に予測キャッシュ再生成を強制（既定 `false`） |
| `TRUST_CF_HEADERS` | 任意 | `true/false`。CFヘッダを信頼するか（既定 `false`） |
| `REQUIRE_CF_CONNECTING_IP` | 任意 | `true/false`。CFヘッダ必須化（既定 `false`） |
| `TRUSTED_PROXY_CIDRS` | 任意 | Forwardedヘッダを信頼するプロキシCIDR（既定 `127.0.0.1/32,::1/128`） |
| `ALLOWED_HOSTS` | 推奨 | 受け付けるHost（例: `example.com,www.example.com`） |
| `PUSH_MAX_SUBSCRIPTIONS` | 任意 | Push購読上限（既定 `50000`） |
| `PUSH_ALLOWED_ENDPOINT_SUFFIXES` | 任意 | Push endpoint 許可ドメインサフィックス（カンマ区切り） |
| `POSTGRES_*` | 通常必要 | DB 接続設定 |

詳細な環境変数は `config.py` と `docker-compose.yml` を参照してください。

metalprice 側の定期処理（日次更新/予測更新/自動修復）は `sycs-voldemort-web` コンテナ内の `webapp/app.py` のスケジューラで実行されます。

### 5.4 マルチインスタンス運用の推奨

- Discord Bot を複数インスタンスで動かす場合:
  - 定期ジョブ担当 1台だけ `BOT_BACKGROUND_WORKER=true`
  - それ以外は `BOT_BACKGROUND_WORKER=false`
- Web トラッカーを複数インスタンスで動かす場合:
  - スケジューラ担当 1台だけ `WEB_SCHEDULER_ENABLED=true`
  - それ以外は `WEB_SCHEDULER_ENABLED=false`
- Reverse Proxy 配下で運用する場合:
  - `TRUSTED_PROXY_CIDRS` にプロキシCIDRを設定
  - Cloudflare 直下構成のみ `TRUST_CF_HEADERS=true` を有効化
  - 公開ドメインを `ALLOWED_HOSTS` に明示設定
- 管理UIを複数インスタンスで動かす場合:
  - 全インスタンスで同じ `ADMIN_FLASK_SECRET_KEY` を設定
  - `ADMIN_LIMITER_STORAGE_URI` に Redis を設定
- DJAudio-DL を複数ノードで使う場合:
  - `DJAUDIO_CACHE_DIR` を共有ストレージにする（または配信ノードを固定）

---

## 6. スラッシュコマンド

命名は `機能_操作` で統一しています（例: `log_channel_set`, `news_feed_add`）。
この一覧は現行実装（`commands/*.py`）にある全コマンドを反映しています。

### 6.1 一般ユーザー向け

| コマンド | 説明 |
|---|---|
| `/metal_gold` | 金の価格 |
| `/metal_silver` | 銀の価格 |
| `/metal_platinum` | プラチナの価格 |
| `/metal_all` | 金・銀・プラチナをまとめて表示 |
| `/server_info` | サーバー情報 |
| `/user_info` | ユーザー情報 |
| `/bot_help` | コマンド一覧 |

### 6.2 管理系（ログ / AI）

| コマンド | 説明 |
|---|---|
| `/log_channel_set` | ログチャンネル設定 |
| `/log_level_set` | ログレベル設定 |
| `/chat_channel_set` | AI 応答チャンネル設定 |
| `/chat_channel_clear` | AI 応答チャンネル解除 |
| `/bot_settings` | 設定表示 |

### 6.3 サーバー運用

| コマンド | 説明 |
|---|---|
| `/welcome_channel_set` | ウェルカム送信チャンネル設定 |
| `/welcome_message_set` | ウェルカム本文設定 |
| `/goodbye_channel_set` | グッバイ送信チャンネル設定 |
| `/goodbye_message_set` | グッバイ本文設定 |
| `/welcome_goodbye_status` | ウェルカム/グッバイ設定表示 |
| `/vc_notify_channel_set` | VC 通知チャンネル設定 |
| `/vc_notify_channel_clear` | VC 通知チャンネル解除 |
| `/sticky_set` | スティッキー設定 |
| `/sticky_clear` | スティッキー解除 |
| `/sticky_list` | スティッキー一覧 |
| `/reaction_role_add` | リアクションロール追加 |
| `/reaction_role_remove` | リアクションロール削除 |
| `/reaction_role_list` | リアクションロール一覧 |
| `/news_feed_add` | ニュースフィード追加 |
| `/news_feed_remove` | ニュースフィード削除 |
| `/news_feed_list` | ニュースフィード一覧 |
| `/quake_channel_set` | 地震アラートチャンネル設定 |
| `/quake_min_scale_set` | 最小震度設定 |
| `/quake_status` | 地震設定表示 |
| `/quake_notify_type` | 地震通知タイプ ON/OFF |

### 6.4 セキュリティ管理

| コマンド | 説明 |
|---|---|
| `/trusted_member_add` | 信頼済みユーザー追加 |
| `/trusted_member_remove` | 信頼済みユーザー削除 |
| `/trusted_member_list` | 信頼済みユーザー一覧 |
| `/bypass_role_add` | バイパスロール追加 |
| `/bypass_role_remove` | バイパスロール削除 |
| `/bypass_role_list` | バイパスロール一覧 |

### 6.5 DJAudio

| コマンド | 説明 |
|---|---|
| `/djaudio_channel_set` | DJAudio 監視チャンネル設定（未指定で解除） |
| `/djaudio_output_set` | MP3 リンクの送信先チャンネル設定（未指定で解除→監視チャンネルに返信） |
| `/djaudio_status` | DJAudio 設定表示 |

---

## 7. 管理 UI の使い方

1. `/admin` にアクセス
2. Discord OAuth でログイン
3. 管理するサーバーを選択
4. サイドバーから設定ページを編集

主要ページ:

| ページ | できること |
|---|---|
| `/admin/overview` | 現在の設定サマリー確認（ログ、AI、地震、DJAudio、件数統計など） |
| `/admin/settings/logging` | ログチャンネル/ログレベル、AI応答チャンネル設定 |
| `/admin/settings/welcome` | ウェルカム/グッバイのチャンネルと本文設定 |
| `/admin/settings/vc-notify` | VC通知チャンネル、通知ロール設定 |
| `/admin/settings/sticky` | スティッキーメッセージ追加・更新・解除 |
| `/admin/settings/reaction-roles` | リアクションロール追加・削除 |
| `/admin/settings/news-feeds` | ニュースフィード追加・更新・削除 |
| `/admin/settings/earthquake` | 地震通知チャンネル、最小震度、通知タイプ設定 |
| `/admin/settings/security` | 信頼済みユーザー / バイパスロール管理 |
| `/admin/settings/djaudio` | DJAudio 監視チャンネル・出力チャンネル・TTL・クールダウン・URL上限設定 |
| `/admin/users/state` | ユーザー状態監査（現在状態 + 時系列履歴） |
| `/admin/dev` | 開発者専用デバッグパネル（特定ユーザーのみアクセス可） |

---

## 8. データ保存先

- `settings.json`: ギルドごとの Bot 設定
- `data/logs/bot.log`: Discord Bot のログ（最大 1MB × 3世代）
- `data/logs/admin.log`: 管理 UI のログ（最大 1MB × 3世代）
- `data/djaudio_cache`: DJAudio の一時 MP3 キャッシュ
- `migrations/` + DB（`POSTGRES_DB`）: Web トラッカーの永続データ
- DB（`USER_STATE_POSTGRES_DB`）: ユーザー状態監査データ

> `data/` の保存先は環境変数 `SETTINGS_DIR` で変更できます。Docker 運用時は Bot と管理 UI でボリュームを共有することでログビューアが機能します。

---

## 9. よくある詰まりどころ

### DJAudio が動かない
- `DJAUDIO_AUTO_INSTALL_FFMPEG=false` にしていないか
- `DJAUDIO_FFMPEG_PATH` が不正なパスになっていないか
- `yt-dlp` が実行できるか
- `DJAUDIO_BASE_URL` が外部アクセス可能な URL か
- `/djaudio_channel_set` で監視チャンネルを設定済みか

### 管理 UI にログインできない
- `DISCORD_CLIENT_ID/SECRET/REDIRECT_URI` が一致しているか
- Discord Developer Portal の Redirect URL と同じか

### コマンドが見えない
- Bot 再起動後に `bot.tree.sync()` が完了しているか
- 古いコマンド名（旧命名）を使っていないか

---

## 10. ディレクトリ概要

```text
commands/      # スラッシュコマンド定義
services/      # Bot/Web 共通サービスロジック
webapp_admin/  # FastAPI 管理 UI
webapp/        # FastAPI Web トラッカー
migrations/    # DB マイグレーション
```
