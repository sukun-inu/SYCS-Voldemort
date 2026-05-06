# Discord Voldemort Bot 仕様書

このリポジトリは、**金属価格コマンド・ChatGPT 会話 Bot・サーバーアクティビティログ・高度なセキュリティ対策**を  
**1 つに統合した Discord ボット実装**です。

単なる娯楽 Bot ではなく、  
> *「情報取得」「会話」「監査」「防衛」*  

を同時に担う **運用向け Bot** として設計されています。

---

## 1. 機能概要

### 1.1 金属価格コマンド
- `/gold` `/silver` `/platinum` `/all`
- JPY ベースのリアルタイム金属価格を取得
- グラム指定に対応
- Embed 形式で視認性の高い表示

---

### 1.2 LLM 会話 Bot
- 日本語限定・ヴォルデモート人格
- ユーザーごとに会話履歴を保持し、文脈の続いた会話が可能
- Groq API を使用（OpenAI 互換エンドポイント）

使用モデル:
- `llama-3.3-70b-versatile`（会話・予測シグナル）
- `llama-3.1-8b-instant`（セキュリティ補助判定）

---

### 1.3 サーバーアクティビティログ
以下のイベントを **指定ログチャンネルへ Embed 形式** で出力します（JST 時刻付き）。

- メッセージ送信 / 削除 / 編集
- ボイスチャンネル参加 / 退出 / 移動 / 状態変化
- メンバー参加 / 退出
- ロール変更 / ニックネーム変更
- チャンネル作成 / 削除
- Bot コマンド実行 / エラー

---

### 1.4 設定の JSON 永続化
ギルドごとに以下の設定を `settings.json` に保存します。

- ログチャンネル ID
- ログレベル（`NONE / ERROR / INFO / DEBUG`）
- ChatGPT 応答チャンネル
- 信頼済みユーザー ID リスト
- セキュリティバイパスロール ID リスト

すべて **Slash コマンド経由で安全に操作可能**です。

---

### 1.5 セキュリティ対策（中核機能）
- メッセージレート監視
- Unicode 異常検出
- GPT による危険コンテンツ判定
- VirusTotal 連携（URL / ファイル）
- VC レイド検知
- 危険時の自動ロール剥奪 + 注意喚起

---

## 2. プロジェクト構成

```text
/
├── main.py
├── config.py
├── bot_setup.py
├── commands/
│   ├── metal_commands.py
│   ├── chat_commands.py
│   └── logging_commands.py
├── services/
│   ├── metal_service.py
│   ├── chatgpt_service.py
│   ├── discord_utils.py
│   ├── logging_service.py
│   ├── settings_store.py
│   └── security_service.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## 3. 環境変数

```bash
DISCORD_BOT_TOKEN=your_bot_token
METALPRICE_API_KEY=your_metalprice_api_key
GROQ_API_KEY=your_groq_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

※ VirusTotal / Groq を使用しない場合は未設定でも可。Groq 未設定時は LLM 機能が無効化されます。

---

## 4. インストールと実行

```bash
pip install -r requirements.txt
python main.py
```

起動後、Slash コマンドは自動同期されます。

---

## 5. Slash コマンド一覧

`/help` を実行すると、登録済みコマンドが Embed で表示されます。

### 管理・設定系
- `/set_log_channel`
- `/set_log_level`
- `/set_response_channel`
- `/clear_response_channel`

### セキュリティ管理
- `/add_trusted_members`
- `/remove_trusted_members`
- `/list_trusted_members`
- `/add_bypass_roles`
- `/remove_bypass_roles`
- `/list_bypass_roles`

### 金属価格
- `/gold g:<number>`
- `/silver g:<number>`
- `/platinum g:<number>`
- `/all g:<number>`

---

## 6. LLM 会話仕様

- 指定された応答チャンネルでのみ反応
- ユーザー ID ごとに会話履歴を保持
- システムプロンプトに以下を含む:
  - ヴォルデモート人格
  - 日本語限定
  - 威圧的・尊大な口調
  - 現在日時（JST）

Groq SDK（`groq` パッケージ）:
- Client: `AsyncGroq`
- Model: `llama-3.3-70b-versatile`
- Temperature: `0.45`
- Timeout: `30.0` 秒

---

## 7. ログ機能の詳細

- すべて `logging_service.log_action` 経由
- Embed Author にユーザー名とアイコン表示
- 通常ログはアイコン色から Embed 色を自動抽出
- セキュリティ関連ログは **常に赤色で強調**
- フッターに JST 時刻を表示

---

## 8. セキュリティ仕様

### 8.1 チェック除外条件
以下に該当するユーザーは **全セキュリティチェックをスキップ**。

- 信頼済みユーザー
- バイパスロール保持者

---

### 8.2 メッセージセキュリティ

非除外ユーザーに対し、以下を順に評価します。

1. **レート監視**
   - 1 秒以内に 3 件以上でスパム判定

2. **Unicode 異常検出**
   - 極端な長文
   - 同一文字の連続
   - ゼロ幅 / Bidi / 制御文字の大量使用

3. **LLM モデレーション**
   - Groq SDK `AsyncGroq` を使用
   - モデル: `llama-3.1-8b-instant`
   - 危険判定・理由・カテゴリを JSON で取得

4. **VirusTotal**
   - URL / 添付ファイルをスキャン
   - キャッシュによる API 節約

---

### 8.3 危険判定時の挙動

- メッセージ削除
- `@everyone` 以外のロール剥奪
- ログ出力
- チャンネルで注意喚起メッセージ送信

---

### 8.4 VC レイド検知

- 20 秒以内
- 同一 VC
- 名前の先頭が類似したユーザーが 5 人以上

→ レイドと判定しロール剥奪 + 警告

---

## 9. 運用のすすめ

1. 初期設定
   - `/set_log_channel`
   - `/set_log_level`
   - `/set_response_channel`

2. 信頼設定
   - `/add_trusted_members`
   - `/add_bypass_roles`

3. 定期確認
   - `/list_trusted_members`
   - `/list_bypass_roles`

---

## 10. 貴金属Webトラッカー（追加機能）

Discord Bot とは別に、金・銀・プラチナの価格を **JST 0:00 に日次保存** し、  
Web画面でチャート表示できる機能を追加しています。
さらに、Bot ロジック準拠で金属の純度別価格計算も可能です。
PWA 対応により、Web Push 通知で日次の価格変動を受け取れます。

### 10.1 追加技術スタック
- FastAPI
- PostgreSQL（`asyncpg` + SQLAlchemy）
- APScheduler（JST 0:00 実行）
- Chart.js（価格推移 + 前日差）
- 純度計算 API（`/api/prices/calculate`）
- Web Push（JST 11:00 に前日差最大の金属を通知）

### 10.2 保存データ
`metal_price_daily` テーブルに以下を保存します。

- 金属キー（`gold/silver/platinum`）
- 取得日（JST 日付）
- 1gあたり価格（円）
- 前日差分（円）

### 10.3 Web 起動

```bash
python web_main.py
```

アクセス先:
- `http://localhost:${WEB_HOST_PORT:-8001}/`
- API: `http://localhost:${WEB_HOST_PORT:-8001}/api/prices/history?days=365`

### 10.4 必須環境変数（Web）
- `METALPRICE_API_KEY`

`POSTGRES_DSN` は任意です。未指定時は以下を組み合わせて自動構成します。

- `POSTGRES_HOST`（デフォルト: `localhost`）
- `POSTGRES_PORT`（デフォルト: `5432`）
- `POSTGRES_DB`（デフォルト: `metal_prices`）
- `POSTGRES_USER`（デフォルト: `postgres`）
- `POSTGRES_PASSWORD` または `POSTGRES_PASSWORD_FILE`

任意:
- `API_RATE_LIMIT_PER_MINUTE`（デフォルト: 120）
- `API_CALCULATE_RATE_LIMIT_PER_MINUTE`（デフォルト: 60）
- `API_RESPONSE_CACHE_SECONDS`（デフォルト: 20）
- `PURITY_OPTIONS_CACHE_SECONDS`（デフォルト: 3600）
- `PUSH_PUBLIC_KEY_CACHE_SECONDS`（デフォルト: 3600）
- `FORECAST_REFRESH_MINUTE_JST`（デフォルト: 5。毎時この分に予測のみ再計算）
- `FORECAST_SARIMAX_ENABLED`（デフォルト: true。統計モデルを有効化）
- `FORECAST_SARIMAX_MIN_HISTORY`（デフォルト: 24。SARIMAXを使う最小履歴件数）
- `FORECAST_LLM_MODEL`（デフォルト: `llama-3.3-70b-versatile`。Groq モデルを変更する場合に指定）
- `FORECAST_LLM_TIMEOUT_SECONDS`（デフォルト: 20。Groq API タイムアウト秒数）
- `PUSH_NOTIFY_HOUR_JST`（デフォルト: 11）
- `PUSH_NOTIFY_MINUTE_JST`（デフォルト: 0）
- `APP_ROOT_PATH`（サブパス配信時のみ。例: `/metal`）
- `APP_PUBLIC_PATH`（Push通知クリック先のベース。デフォルト: `/`）
- `VAPID_AUTO_GENERATE`（デフォルト: true）
- `VAPID_KEYS_DIR`（デフォルト: `/shared/vapid`）
- `VAPID_PUBLIC_KEY`（手動指定する場合）
- `VAPID_PRIVATE_KEY`（手動指定する場合）
- `VAPID_SUBJECT`（デフォルト: `mailto:admin@example.com`。`admin@example.com` を指定した場合は `mailto:` を自動補完。不正形式はデフォルトへフォールバック）
- `TRUST_CF_HEADERS`（デフォルト: true）
- `REQUIRE_CF_CONNECTING_IP`（デフォルト: false）
- `ALLOWED_HOSTS`（カンマ区切り）
- `WEB_HOST_PORT`（デフォルト: 8001）
- `STARTUP_TEST_MODE`（デフォルト: false）
- `STARTUP_TEST_REQUIRE_DOCKER`（デフォルト: true）
- `STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT`（デフォルト: false）
- `STARTUP_TEST_FORCE_SNAPSHOT_REFRESH`（デフォルト: true）
- `STARTUP_TEST_RUN_PUSH_ON_BOOT`（デフォルト: false）

起動テスト機能の注意:
- `STARTUP_TEST_MODE=true` かつ各実行フラグが有効なときのみ、コンテナ起動時にテスト処理を実行します。
- `STARTUP_TEST_REQUIRE_DOCKER=true` の場合、コンテナ外プロセスではテスト処理を強制的に無効化します。
- テスト起動処理はサーバー起動フック内のみで実行し、HTTP API は提供しません。
  そのためブラウザの JS コンソールや外部リクエストからは実行できません。

### 10.5 Docker Compose 起動
`docker-compose.yml` には以下サービスを定義済みです。

- `postgres-secret-init`（初回のみランダムパスワード生成）
- `postgres`
- `sycs-voldemort`（Discord Bot）
- `sycs-voldemort-web`（Webトラッカー）

```bash
docker compose up -d --build
```

起動時テストを有効化する例（必要なときだけ設定）:

```bash
STARTUP_TEST_MODE=true \
STARTUP_TEST_RUN_MIDNIGHT_JOB_ON_BOOT=true \
STARTUP_TEST_RUN_PUSH_ON_BOOT=true \
docker compose up -d --build sycs-voldemort-web
```

### 10.6 PostgreSQL パスワード自動生成
- 初回起動時、`postgres-secret-init` がランダムな PostgreSQL パスワードを生成します。
- パスワードは Docker Volume `shared_secrets` 内の `/shared/postgres_password` に保存されます。
- `postgres` / `sycs-voldemort-web` は毎回このファイルを読み込むため、再起動後も同じパスワードで動作します。

### 10.7 PWA と Push 通知
- `manifest.webmanifest` と `service worker` を実装済みです。
- ブラウザで「Push通知を有効化」を押すと購読登録されます。
- 価格スナップショット取得（MetalPriceAPI）は JST 0:00 の日次実行です。
- 価格予測は毎時 `FORECAST_REFRESH_MINUTE_JST` 分に再計算し、最新結果を API に反映します。
- 予測は USD/JPY・ニュース・AI判定を合算した外生シグナルを含む SARIMAX で算出します（履歴不足時は自動フォールバック）。
- ニュースシグナルは Google News RSS を取得します。User-Agent を設定しブロック回避済み。XML は bytes のままパースし encoding 宣言を正しく処理します。
- フロントは予測APIを約5分間隔で自動再フェッチし、生成時刻が更新されると表示を自動反映します。
- サーバーは JST 毎日 11:00 に「前日差が最大の金属」を通知します。
- 通知は `notification_dispatch` テーブルで同日重複送信を防止します。
- `VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY` が未設定でも、初回起動時に `/shared/vapid` へ自動生成して再利用します。
