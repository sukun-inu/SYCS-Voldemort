# Discord Voldemort Bot 仕様書

**金属価格・LLM 会話・サーバー管理・セキュリティ・各種自動化** を 1 つに統合した  
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
P2PQuake API を使用して日本の地震情報をリアルタイムで通知します。

- 1 分ごとに新着確認
- 最小震度を設定して通知量を調整可能
- 震度に応じた Embed カラー（緑→黄→橙→赤）
- 初回起動時はサイレント（最新 ID を記録するだけで投稿しない）
- Pillow で震度バッジ画像を動的生成（震度値・配色を画像として Embed に添付）
- 津波警報・注意報を検出して別メッセージで通知（Watch / Warning）

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

### 1.10 セキュリティ対策

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

### 1.11 設定の JSON 永続化
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

**実装:** アトミック書き込み（`.tmp` ファイル → rename）によりクラッシュ時の破損を防止。  
インメモリライトスルーキャッシュで毎回ディスク読み込みを回避。

---

### 1.12 Web 管理 UI（Flask）
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
- 地震アラート（チャンネル・最小震度）
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

### 1.13 貴金属 Web トラッカー（FastAPI）
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
│   │   └── settings_views.py
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

### 3.3 FastAPI Web トラッカー

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
| `/earthquake_settings` | 地震アラート設定を表示 |

### 7.9 情報表示（全員）

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
| `earthquake_task` | 1 分 | P2PQuake から地震情報を取得・通知 |

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
/set_earthquake_channel → 地震アラートチャンネルを指定
/set_earthquake_min_scale → 最小震度を設定（例: 30 = 震度3）
/add_news_feed         → キーワードとチャンネルを設定
```

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
        "last_event_id": "abc123"
      }
    }
  }
}
```
