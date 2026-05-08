# SYCS Voldemort

Discord Bot（運用支援）+ Flask 管理 UI + FastAPI Web トラッカーをまとめたプロジェクトです。

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
- フィード上限: 1サーバー最大10件
- 間隔: 5〜1440分
- 重複抑止（既出記事ハッシュ管理）

### 1.9 地震アラート（P2PQuake）
- WebSocket 常時接続で地震情報を配信
- 通知タイプの ON/OFF 切り替え:
  - `eew_forecast`, `eew_warning`, `tsunami`, `quake_info`, `bot_news`
- 最小震度フィルタ設定あり

### 1.10 DJAudio-DL
- 監視チャンネルに投稿された URL から MP3 を生成して返信
- 期限付き配信リンク（TTL）で提供し、期限後に自動削除
- 対応例: YouTube / SoundCloud / Bandcamp / ニコニコ動画 / TikTok / 汎用URL
- 非対応例: Spotify / Apple Music / Amazon Music
- 設定可能:
  - 監視チャンネル
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

### 1.12 管理 UI（Flask）
- Discord OAuth ログイン
- サーバー単位設定
- Web 上で以下を管理:
  - ログ設定、AI 応答、ウェルカム/グッバイ、VC 通知
  - スティッキー、リアクションロール、ニュース
  - 地震アラート、DJAudio、セキュリティ

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
| DJAudio-DL | `/djaudio_channel_set` `/djaudio_status` | `/admin/settings/djaudio` |

---

## 2. 全体構成

| プロセス | エントリーポイント | 役割 |
|---|---|---|
| Discord Bot | `main.py` | Discord イベント処理とスラッシュコマンド |
| Admin UI | `admin_main.py` | 管理画面（Flask） |
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
| `VIRUSTOTAL_API_KEY` | 任意 | URL/ファイルスキャン |
| `SETTINGS_DIR` | 任意 | `settings.json` 保存先 |
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
| `ADMIN_FLASK_SECRET_KEY` | Yes | セッション署名キー |
| `ADMIN_PORT` | 任意 | デフォルト `5001` |

### 5.3 Web トラッカー（`web_main.py`）

| 変数 | 必須 | 説明 |
|---|---|---|
| `WEB_PORT` | 任意 | デフォルト `8000` |
| `POSTGRES_*` | 通常必要 | DB 接続設定 |

詳細な環境変数は `config.py` と `docker-compose.yml` を参照してください。

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
| `/admin/settings/djaudio` | DJAudio監視チャンネル、TTL、クールダウン、URL上限設定 |

---

## 8. データ保存先

- `settings.json`: ギルドごとの Bot 設定
- `data/djaudio_cache`: DJAudio の一時 MP3 キャッシュ
- `migrations/` + DB: Web トラッカーの永続データ

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
webapp_admin/  # Flask 管理 UI
webapp/        # FastAPI Web トラッカー
migrations/    # DB マイグレーション
```
