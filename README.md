# Discord Voldemort Bot 仕様書

**金属価格・LLM 会話・サーバー管理・セキュリティ・音楽ダウンロード・各種自動化** を 1 つに統合した  
運用向け Discord Bot + Web 管理 UI の実装です。

---

## 1. 機能概要

### 1.1 金属価格コマンド
- `/gold` `/silver` `/platinum` `/all`
- JPY ベースのリアルタイム金属価格を取得（MetalPriceAPI）
- グラム数指定に対応
- Embed 形式で視認性の高い表示

---

### 1.2 LLM 会話 Bot（Groq）
- 日本語限定・ヴォルデモート人格
- ユーザーごとに会話履歴を保持し、文脈を継続
- 指定チャンネル以外では応答しない（未設定時は全チャンネル）

| 項目 | 内容 |
|---|---|
| API | Groq（`AsyncGroq`） |
| 会話モデル | `llama-3.3-70b-versatile` |
| モデレーションモデル | `llama-3.1-8b-instant` |
| Temperature | `0.45` |
| Timeout | `30.0` 秒 |

---

### 1.3 サーバーアクティビティログ
指定ログチャンネルへ Embed 形式（JST 時刻付き）で出力します。

| イベント | 詳細 |
|---|---|
| メッセージ削除 | 送信日時・内容・ユーザーID・添付ファイル |
| メッセージ編集 | 編集前後の内容・チャンネル |
| VC 参加/退出/移動 | チャンネル名 |
| メンバー参加 | アカウント作成日・参加日時・メンバー数 |
| メンバー退出 | 保有ロール・メンバー数 |
| ニックネーム変更 | 旧→新 |
| ロール変更 | 追加・削除されたロール |
| タイムアウト付与/解除 | 解除日時 |
| BAN / BAN 解除 | ユーザーID・ユーザー名 |

ログレベル: `NONE / ERROR / INFO / DEBUG`

---

### 1.4 ウェルカム / グッバイメッセージ
メンバーの参加・退出時に指定チャンネルへメッセージを送信します。

**テンプレート変数:**

| 変数 | 展開内容 |
|---|---|
| `{user}` | メンション（`@ユーザー名`） |
| `{username}` | ユーザー名（文字列） |
| `{server}` | サーバー名 |
| `{count}` | 現在のメンバー数 |

---

### 1.5 VC 通知チャンネル
VC 参加・退出・移動をユーザー向けに通知する専用チャンネルを設定できます。  
ログチャンネル（管理者向け）とは独立して動作します。

| イベント | 詳細 |
|---|---|
| 参加 | 🔊 **チャンネル名** に参加しました（JST タイムスタンプ付き） |
| 退出 | 🔊 **チャンネル名** から退出しました + **通話時間**（JST タイムスタンプ付き） |
| 移動 | 🔊 **旧チャンネル** → **新チャンネル**（JST タイムスタンプ付き） |

- Embed にユーザーのアバターをサムネイルとして表示
- 退出時は参加からの経過時間を「通話時間」として本文に表示

---

### 1.6 スティッキーメッセージ
チャンネルに新しいメッセージが投稿されるたびに、設定したメッセージを自動で最下部に再投稿します。

- チャンネルごとに独立して設定可能
- 旧スティッキーを自動削除してから新規投稿
- asyncio.Lock によるレース条件防止

---

### 1.7 リアクションロール
指定メッセージへのリアクションに連動してロールを自動付与・解除します。

- メッセージキャッシュ不要の `on_raw_reaction_add/remove` 対応
- 1 メッセージに複数の絵文字→ロール設定が可能
- カスタム絵文字（絵文字ID）・Unicode 絵文字の両方に対応

---

### 1.8 Google News フィード
キーワードで Google News を定期検索し、新着記事を Discord チャンネルへ Embed 投稿します。

- MD5 ハッシュによる URL 重複排除（最新 100 件）
- チェック間隔は 5〜1440 分でフィードごとに個別設定
- 1 サーバーあたり最大 10 フィード
- Bot 起動 5 分ごとにバックグラウンドで実行
- 記事の説明文（HTML タグ除去・最大 300 文字）を Embed に表示
- 記事のソース（メディア名）を表示
- 公開日時を JST（`YYYY年M月D日 H:MM`）に変換して表示
- 管理 UI でフィードの設定を後から編集（チャンネル・キーワード・間隔）可能

---

### 1.9 地震アラート（P2PQuake）
P2PQuake WebSocket API に常時接続し、日本の地震情報をリアルタイムで通知します。

**受信するイベント:**

| P2PQuake コード | 種別 | 通知タイプキー |
|---|---|---|
| 551 | 地震情報（確定） | `quake_info` |
| 552 | 津波予報 | `tsunami` |
| 554 | 緊急地震速報（警報） | `eew_warning` |
| 556 | 緊急地震速報（予報） | `eew_forecast` |

**主な機能:**
- WebSocket による常時接続（切断時は 10 秒後に自動再接続）
- 通知タイプごとにサーバー単位でオン/オフ切り替え可能
- 最小震度フィルタで通知量を調整可能
- Kiwi Monitor カラースキーム 第2版 に基づく震度別カラー
- Pillow で震度バッジ（Apple スタイル・120×120px）を動的生成し Embed に添付
- CartoDB Dark Matter タイルによるダーク地図を生成し震度分布を可視化
- 津波情報は大津波警報 / 津波警報 / 津波注意報 / 解除を色分けして通知
- EEW は同一イベントの重複送信を抑制（第 1 報・最終報のみ通知）
- 各通知に気象庁情報ページへのリンクボタンを付与

**震度対応表:**

| 内部値 | 震度表記 |
|---|---|
| 10 | 1 |
| 20 | 2 |
| 30 | 3 |
| 40 | 4 |
| 45 | 4強 |
| 50 | 5弱 |
| 55 | 5強 |
| 60 | 6弱 |
| 65 | 6強 |
| 70 | 7 |

---

### 1.10 DJAudio-DL（音楽ダウンロード配信）
指定チャンネルに投稿された URL を自動検知し、yt-dlp で MP3 に変換して時限配信リンクを返信します。

**対応サービス:**

| サービス | 備考 |
|---|---|
| YouTube / YouTube Music | 音楽メタデータの自動補完に対応 |
| SoundCloud | |
| Bandcamp | |
| ニコニコ動画 | |
| TikTok | |
| 直リンク（汎用） | |
| Spotify / Apple Music / Amazon Music | ❌ 著作権保護のためダウンロード不可 |

**主な機能:**
- 監視チャンネルへの URL 投稿を自動検知し `⏳` → `✅` / `❌` でリアクション通知
- yt-dlp + ffmpeg による高品質 MP3 変換（最高音質・サムネイル埋め込み）
- Deezer API による ID3 タグ自動補完（タイトル・アーティスト・アルバム・カバー画像）
  - ISRC 完全一致検索 → 媒体別クエリ最適化検索にフォールバック
- guild ごとに独立した配信 URL（`/dlaudio/files/<guild_id>/<token>`）でアクセス制御
- TTL 経過後にキャッシュファイルと Discord 返信メッセージを自動削除
- ユーザーごとのクールダウンで連続投稿を制限
- 同時ダウンロード数・タイムアウトはグローバル設定で制御

**設定項目（Web 管理 UI / スラッシュコマンドで変更可能）:**

| 設定 | 説明 | デフォルト |
|---|---|---|
| 監視チャンネル | URL を監視するテキストチャンネル | 未設定（無効） |
| キャッシュ有効期間 | MP3 配信リンクの有効時間（60〜86400 秒） | 600 秒（10 分） |
| ユーザークールダウン | 同一ユーザーの連続リクエスト待機時間（0=無制限） | 30 秒 |
| 最大 URL 数 / メッセージ | 1 メッセージあたりの処理 URL 上限（1〜10） | 3 |

---

### 1.11 セキュリティ対策

チェック除外条件（以下に該当するユーザーはスキップ）:
- 信頼済みユーザー
- バイパスロール保持者

| チェック | 内容 |
|---|---|
| レート監視 | 1 秒以内に 3 件以上でスパム判定 |
| Unicode 異常検出 | 長文・同一文字連続・制御文字多用 |
| LLM モデレーション | Groq で危険コンテンツを JSON 判定 |
| VirusTotal 連携 | URL・添付ファイルをスキャン（キャッシュ付き） |
| VC レイド検知 | 20 秒以内に同一 VC へ類似名 5 人以上で検知 |

**危険判定時の挙動:**
1. メッセージ削除
2. `@everyone` 以外のロール剥奪
3. ログ出力（赤 Embed）
4. チャンネルへ注意喚起メッセージ送信

---

### 1.12 設定の JSON 永続化
ギルドごとに以下の設定を `settings.json` に保存します（Bot 再起動後も保持）。

- ログチャンネル ID / ログレベル
- ChatGPT 応答チャンネル
- 信頼済みユーザー ID リスト
- セキュリティバイパスロール ID リスト
- ウェルカム / グッバイ チャンネル・メッセージ
- VC 通知チャンネル
- スティッキーメッセージ（チャンネルごと）
- リアクションロール（メッセージ × 絵文字 × ロール）
- ニュースフィード（フィード ID × 設定）
- 地震アラート設定
- DJAudio-DL 設定（監視チャンネル・TTL・クールダウン・最大 URL 数）

**実装:** アトミック書き込み（`.tmp` ファイル → rename）によりクラッシュ時の破損を防止。  
インメモリライトスルーキャッシュで毎回ディスク読み込みを回避。

---

### 1.13 Web 管理 UI（Flask）
Discord OAuth 認証によって管理者のみがアクセスできる Web 管理ダッシュボードです。

**認証フロー:**
1. Discord でログイン（OAuth2 `identify guilds` スコープ）
2. `administrator` 権限を持ち、Bot が参加しているサーバーのみ管理可能
3. サーバーを選択してダッシュボードへ

**管理できる機能:**
- ログ設定（チャンネル・レベル）
- ChatGPT 応答チャンネル
- ウェルカム / グッバイ設定
- VC 通知チャンネル
- スティッキーメッセージ（追加・削除）
- リアクションロール（追加・削除）
- ニュースフィード（追加・編集・削除）
- 地震アラート（チャンネル・最小震度・通知タイプ切り替え）
- DJAudio-DL（監視チャンネル・TTL・クールダウン・最大 URL 数）
- セキュリティ設定（信頼済みユーザー・バイパスロール）
- サーバー情報・ユーザー情報表示
- ダッシュボードでチャンネル ID をチャンネル名に変換して表示（設定画面全体に適用）

**セキュリティ対策:**

| 対策 | 実装内容 |
|---|---|
| CSRF | Flask-WTF `CSRFProtect`（全フォームにトークン） |
| XSS | Jinja2 自動エスケープ + 厳格 CSP ヘッダー |
| クリックジャッキング | `X-Frame-Options: DENY` |
| セッション固定 | OAuth コールバック後に `session.clear()` |
| OAuth CSRF | `state` パラメータ + `compare_digest` 検証 |
| レートリミット | Flask-Limiter（ログイン系 10 回 / 分） |
| 入力検証 | チャンネルID・震度・ログレベルのホワイトリスト検証 |
| エラーハンドラ | 400/403/429/500 に統一エラーページ |

---

### 1.14 貴金属 Web トラッカー（FastAPI）
金・銀・プラチナの価格を JST 0:00 に日次保存し、チャート表示・Web Push 通知を提供します。

- 純度別価格計算 API（`/api/prices/calculate`）
- SARIMAX + Groq シグナルによる価格予測
- PWA 対応・Web Push 通知（JST 11:00）
- VAPID 鍵の自動生成

---

## 2. プロジェクト構成

```text
/
├── main.py                         # Discord Bot エントリーポイント
├── admin_main.py                   # Flask 管理 UI エントリーポイント
├── web_main.py                     # FastAPI Web トラッカーエントリーポイント
├── config.py
├── bot_setup.py                    # イベントハンドラ・バックグラウンドタスク
├── commands/
│   ├── metal_commands.py
│   ├── chat_commands.py
│   ├── logging_commands.py
│   ├── server_commands.py          # 新機能スラッシュコマンド
│   ├── djaudio_commands.py         # DJAudio-DL スラッシュコマンド
│   └── guards.py                   # コマンド権限チェック
├── services/
│   ├── metal_service.py
│   ├── chatgpt_service.py
│   ├── discord_utils.py
│   ├── logging_service.py
│   ├── settings_store.py           # JSON 永続化（全設定）
│   ├── security_service.py
│   ├── welcome_service.py          # ウェルカム / グッバイ
│   ├── sticky_service.py           # スティッキーメッセージ
│   ├── reaction_role_service.py    # リアクションロール
│   ├── news_service.py             # Google News フィード
│   ├── earthquake_service.py       # 地震アラート（P2PQuake）・バッジ画像生成
│   ├── djaudio_service.py          # DJAudio-DL コアロジック（URL検知・ダウンロード）
│   ├── djaudio_cache.py            # DJAudio-DL MP3 キャッシュ管理
│   ├── djaudio_site_detection.py   # DJAudio-DL サービス判定ユーティリティ
│   ├── djaudio_isrc_meta.py        # DJAudio-DL Deezer ID3 タグ補完
│   ├── virustotal_service.py       # URL・ファイルセキュリティスキャン
│   ├── raid_detection.py           # VC レイド検知
│   ├── spam_detection.py           # スパム判定
│   └── content_moderation.py      # LLM ベースコンテンツモデレーション
├── webapp_admin/                   # Flask 管理 UI
│   ├── app.py
│   ├── auth.py
│   ├── extensions.py
│   ├── security.py
│   ├── views/
│   │   ├── auth_views.py
│   │   ├── dashboard_views.py
│   │   ├── settings_views.py
│   │   └── djaudio_views.py        # DJAudio-DL 設定 + MP3 配信 Blueprint
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── guild_select.html
│   │   ├── dashboard.html
│   │   ├── error.html
│   │   └── settings/
│   │       ├── logging.html
│   │       ├── welcome.html
│   │       ├── vc_notify.html
│   │       ├── sticky.html
│   │       ├── reaction_roles.html
│   │       ├── news_feeds.html
│   │       ├── earthquake.html
│   │       ├── djaudio.html        # DJAudio-DL 設定ページ
│   │       └── security.html
│   └── static/
│       ├── admin.css
│       └── admin.js
├── webapp/                         # FastAPI Web トラッカー
│   └── ...
├── migrations/
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## 3. 環境変数

### 3.1 Discord Bot

| 変数 | 必須 | 説明 |
|---|---|---|
| `DISCORD_BOT_TOKEN` | ✅ | Bot トークン |
| `GROQ_API_KEY` | ☑ | LLM 会話・モデレーション用。未設定で無効化 |
| `VIRUSTOTAL_API_KEY` | ☑ | URL/ファイルスキャン用。未設定で無効化 |
| `METALPRICE_API_KEY` | ☑ | 金属価格取得用 |
| `SETTINGS_DIR` | ☑ | 設定 JSON 保存先（デフォルト: `./data`） |

### 3.2 Flask 管理 UI

| 変数 | 必須 | 説明 |
|---|---|---|
| `DISCORD_CLIENT_ID` | ✅ | Discord OAuth2 クライアント ID |
| `DISCORD_CLIENT_SECRET` | ✅ | Discord OAuth2 クライアントシークレット |
| `DISCORD_REDIRECT_URI` | ✅ | OAuth2 リダイレクト URI（例: `https://yourdomain/admin/callback`） |
| `ADMIN_FLASK_SECRET_KEY` | ✅ | Flask セッション署名キー（ランダム長文字列） |
| `FLASK_SECURE_COOKIES` | ☑ | `true` に設定すると Secure Cookie（HTTPS 環境で推奨） |
| `ADMIN_HOST_PORT` | ☑ | ホスト側ポート（デフォルト: `5001`） |

### 3.3 DJAudio-DL

| 変数 | 必須 | 説明 |
|---|---|---|
| `DJAUDIO_BASE_URL` | ✅ | MP3 配信 URL のベース（例: `https://yourdomain:5001`）。管理サーバーの公開 URL を指定 |
| `DJAUDIO_CACHE_DIR` | ☑ | MP3 キャッシュ保存先（デフォルト: `./data/djaudio_cache`） |
| `DJAUDIO_CACHE_TTL_SECONDS` | ☑ | グローバルデフォルト TTL（デフォルト: `600`）。Web 管理 UI でサーバーごとに上書き可能 |
| `DJAUDIO_COOLDOWN_SECONDS` | ☑ | グローバルデフォルトクールダウン（デフォルト: `30`）。Web 管理 UI でサーバーごとに上書き可能 |
| `DJAUDIO_MAX_URLS_PER_MSG` | ☑ | グローバルデフォルト最大 URL 数（デフォルト: `3`）。Web 管理 UI でサーバーごとに上書き可能 |
| `DJAUDIO_DL_CONCURRENCY` | ☑ | 同時ダウンロード処理数（デフォルト: `3`） |
| `DJAUDIO_DL_TIMEOUT_SECONDS` | ☑ | ダウンロードタイムアウト（デフォルト: `120`） |
| `DJAUDIO_FFMPEG_PATH` | ☑ | ffmpeg 実行ファイルのパス（デフォルト: `ffmpeg`） |

### 3.4 FastAPI Web トラッカー

| 変数 | 必須 | 説明 |
|---|---|---|
| `POSTGRES_HOST` | ☑ | デフォルト: `localhost` |
| `POSTGRES_PORT` | ☑ | デフォルト: `5432` |
| `POSTGRES_DB` | ☑ | デフォルト: `metal_prices` |
| `POSTGRES_USER` | ☑ | デフォルト: `metal_user` |
| `POSTGRES_PASSWORD_FILE` | ☑ | パスワードファイルパス |
| `API_RATE_LIMIT_PER_MINUTE` | ☑ | デフォルト: `120` |
| `API_CALCULATE_RATE_LIMIT_PER_MINUTE` | ☑ | デフォルト: `60` |
| `API_RESPONSE_CACHE_SECONDS` | ☑ | デフォルト: `20` |
| `FORECAST_REFRESH_MINUTE_JST` | ☑ | 毎時の予測再計算タイミング（デフォルト: `5`） |
| `FORECAST_SARIMAX_ENABLED` | ☑ | デフォルト: `true` |
| `FORECAST_SARIMAX_MIN_HISTORY` | ☑ | SARIMAX 最小履歴件数（デフォルト: `24`） |
| `PUSH_NOTIFY_HOUR_JST` | ☑ | Push 通知時刻・時（デフォルト: `11`） |
| `PUSH_NOTIFY_MINUTE_JST` | ☑ | Push 通知時刻・分（デフォルト: `0`） |
| `VAPID_AUTO_GENERATE` | ☑ | デフォルト: `true` |
| `VAPID_KEYS_DIR` | ☑ | デフォルト: `/shared/vapid` |
| `VAPID_PUBLIC_KEY` | ☑ | 手動指定する場合 |
| `VAPID_PRIVATE_KEY` | ☑ | 手動指定する場合 |
| `VAPID_SUBJECT` | ☑ | デフォルト: `mailto:admin@example.com` |
| `TRUST_CF_HEADERS` | ☑ | デフォルト: `true`（Cloudflare 経由の場合） |
| `REQUIRE_CF_CONNECTING_IP` | ☑ | デフォルト: `false` |
| `ALLOWED_HOSTS` | ☑ | カンマ区切り（デフォルト: `*`） |
| `APP_ROOT_PATH` | ☑ | サブパス配信時のみ（例: `/metal`） |
| `APP_PUBLIC_PATH` | ☑ | Push 通知クリック先ベース（デフォルト: `/`） |

---

## 4. インストールと実行

```bash
pip install -r requirements.txt

# Discord Bot
python main.py

# Flask 管理 UI（別ターミナル）
python admin_main.py

# FastAPI Web トラッカー（別ターミナル）
python web_main.py
```

---

## 5. Docker Compose 起動

```bash
docker compose up -d --build
```

**定義済みサービス:**

| サービス | 役割 | ポート |
|---|---|---|
| `postgres-secret-init` | 初回のみパスワード自動生成 | — |
| `postgres` | PostgreSQL 16 | — |
| `sycs-voldemort` | Discord Bot | — |
| `sycs-voldemort-admin` | Flask 管理 UI | `5001` |
| `sycs-voldemort-web` | FastAPI Web トラッカー | `8001` |

**PostgreSQL パスワード自動生成:**
- 初回起動時に `postgres-secret-init` がランダムパスワードを生成
- Docker Volume `shared_secrets` 内の `/shared/postgres_password` に保存
- 以降の再起動でも同じパスワードを再利用

---

## 6. Discord OAuth2 設定手順（管理 UI 用）

1. [Discord Developer Portal](https://discord.com/developers/applications) → 対象アプリを選択
2. **OAuth2** → **Redirects** に `DISCORD_REDIRECT_URI` を追加  
   例: `http://localhost:5001/admin/callback`
3. `Client ID` と `Client Secret` を `.env` に設定

---

## 7. Slash コマンド一覧

起動後に `bot.tree.sync()` で自動同期。`/help` で Embed 一覧表示。

### 7.1 ログ・設定系（管理者専用）

| コマンド | 説明 |
|---|---|
| `/set_log_channel` | ログ送信チャンネルを設定 |
| `/set_log_level` | ログレベル設定（NONE/ERROR/INFO/DEBUG） |
| `/set_response_channel` | ChatGPT 応答チャンネルを設定 |
| `/clear_response_channel` | ChatGPT 応答チャンネルを解除 |
| `/settings` | 現在の全設定を Embed で表示 |
| `/help` | コマンド一覧を表示 |

### 7.2 セキュリティ管理（管理者専用）

| コマンド | 説明 |
|---|---|
| `/add_trusted_members` | 信頼済みユーザーに追加（最大 5 名同時） |
| `/remove_trusted_members` | 信頼済みユーザーから削除 |
| `/list_trusted_members` | 信頼済みユーザー一覧表示 |
| `/add_bypass_roles` | バイパスロール追加（最大 3 個同時） |
| `/remove_bypass_roles` | バイパスロール削除 |
| `/list_bypass_roles` | バイパスロール一覧表示 |

### 7.3 ウェルカム / グッバイ（管理者専用）

| コマンド | 説明 |
|---|---|
| `/set_welcome_channel` | ウェルカムメッセージ送信チャンネルを設定 |
| `/set_welcome_message` | ウェルカムメッセージテンプレートを設定 |
| `/set_goodbye_channel` | グッバイメッセージ送信チャンネルを設定 |
| `/set_goodbye_message` | グッバイメッセージテンプレートを設定 |
| `/welcome_settings` | 現在のウェルカム / グッバイ設定を表示 |

### 7.4 VC 通知（管理者専用）

| コマンド | 説明 |
|---|---|
| `/set_vc_notify_channel` | VC 通知チャンネルを設定 |
| `/clear_vc_notify_channel` | VC 通知チャンネルを解除 |

### 7.5 スティッキーメッセージ（管理者専用）

| コマンド | 説明 |
|---|---|
| `/sticky` | このチャンネルにスティッキーを設定 |
| `/unsticky` | このチャンネルのスティッキーを解除 |
| `/list_stickies` | スティッキー一覧を表示 |

### 7.6 リアクションロール（管理者専用）

| コマンド | 説明 |
|---|---|
| `/add_reaction_role` | リアクションロールを追加 |
| `/remove_reaction_role` | リアクションロールを削除 |
| `/list_reaction_roles` | リアクションロール一覧を表示 |

### 7.7 ニュースフィード（管理者専用）

| コマンド | 説明 |
|---|---|
| `/add_news_feed` | Google News フィードを追加 |
| `/remove_news_feed` | ニュースフィードを削除 |
| `/list_news_feeds` | フィード一覧を表示 |

### 7.8 地震アラート（管理者専用）

| コマンド | 説明 |
|---|---|
| `/set_earthquake_channel` | 地震アラートチャンネルを設定 |
| `/set_earthquake_min_scale` | 最小震度を設定 |
| `/earthquake_settings` | 地震アラート設定・通知タイプ一覧を表示 |
| `/earthquake_notify_type` | 通知タイプをボタン UI でオン/オフ切り替え |

### 7.9 DJAudio-DL（管理者専用）

| コマンド | 説明 |
|---|---|
| `/djaudio_setchannel [channel]` | URL 監視チャンネルを設定（省略で解除） |
| `/djaudio_status` | DJAudio 現在の設定を表示 |

### 7.10 情報表示（全員）

| コマンド | 説明 |
|---|---|
| `/gold g:<数値>` | 金の現在価格 |
| `/silver g:<数値>` | 銀の現在価格 |
| `/platinum g:<数値>` | プラチナの現在価格 |
| `/all g:<数値>` | 全金属の価格一覧 |
| `/serverinfo` | サーバー情報を表示 |
| `/userinfo [member]` | ユーザー情報を表示 |

---

## 8. バックグラウンドタスク

| タスク | 間隔 | 説明 |
|---|---|---|
| `update_status` | 5 秒 | Ping・CPU・MEM をステータスに表示 |
| `news_feed_task` | 5 分 | 全サーバーのニュースフィードをチェック |
| `run_earthquake_ws` | 常時 | P2PQuake WS に接続し地震情報をリアルタイム受信（切断時 10 秒で再接続） |
| `djaudio_cache_cleanup` | 60 秒 | 有効期限切れ MP3 キャッシュを削除し、Discord 返信メッセージも合わせて削除 |

---

## 9. 初期運用手順

### 9.1 管理 UI でまとめて設定する場合

1. `http://サーバーアドレス:5001/admin/` にアクセス
2. **Discord でログイン** → サーバーを選択
3. サイドバーから各機能を設定

### 9.2 スラッシュコマンドで設定する場合

```
/set_log_channel       → ログチャンネルを指定
/set_log_level         → INFO に設定
/set_response_channel  → ChatGPT 応答チャンネルを指定
/add_bypass_roles      → Mod ロールをバイパスに追加
/set_welcome_channel   → ウェルカムチャンネルを指定
/set_earthquake_channel   → 地震アラートチャンネルを指定
/set_earthquake_min_scale → 最小震度を設定（例: 30 = 震度3）
/earthquake_notify_type   → 通知タイプをボタン UI で切り替え
/add_news_feed         → キーワードとチャンネルを設定
/djaudio_setchannel    → MP3 自動変換を有効にするチャンネルを指定
```

> **DJAudio-DL 動作要件:** `yt-dlp` / `ffmpeg` が実行環境にインストールされている必要があります。  
> キャッシュ TTL・クールダウン・最大 URL 数は管理 UI → **DJAudio-DL** から変更できます。

---

## 10. settings.json 構造

```json
{
  "guilds": {
    "<guild_id>": {
      "log_channel_id": 123456789,
      "log_level": "INFO",
      "response_channel_id": 123456789,
      "trusted_user_ids": [111, 222],
      "bypass_role_ids": [333],
      "welcome": {
        "channel_id": 123456789,
        "message": "{user} がサーバーに参加しました！"
      },
      "goodbye": {
        "channel_id": 123456789,
        "message": null
      },
      "vc_notify_channel_id": 123456789,
      "sticky_messages": {
        "<channel_id>": { "content": "テキスト", "message_id": 123456789 }
      },
      "reaction_roles": {
        "<message_id>": { "👍": 444555 }
      },
      "news_feeds": {
        "ab12cd34": {
          "channel_id": 123456789,
          "query": "AI技術",
          "interval": 60,
          "last_run": 1700000000.0,
          "seen_hashes": ["md5hash..."]
        }
      },
      "earthquake": {
        "channel_id": 123456789,
        "min_scale": 30,
        "last_event_id": "abc123",
        "notify_types": {
          "eew_forecast": true,
          "eew_warning": true,
          "tsunami": true,
          "quake_info": true,
          "bot_news": true
        }
      },
      "djaudio_watch_channel_id": 123456789,
      "djaudio": {
        "cache_ttl": 600,
        "cooldown": 30,
        "max_urls": 3
      }
    }
  }
}
```
