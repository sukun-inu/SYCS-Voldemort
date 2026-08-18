# 管理UIとデータ保存先

[← README.ja.md に戻る](../README.ja.md)

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
| `/admin/settings/tts` | TTS 有効化、VC・読み上げチャンネル設定、デフォルト声、辞書管理、ユーザー設定リセット |
| `/admin/users/state` | ユーザー状態監査（現在状態 + 時系列履歴） |
| `/admin/dev` | 開発者専用デバッグパネル（特定ユーザーのみアクセス可） |

---

---

## 8. データ保存先

- `settings.json`: ギルドごとの Bot 設定
- `data/.admin_session_secret`: 管理UI セッション署名キー（`ADMIN_FLASK_SECRET_KEY` 未設定時に初回起動で自動生成）
- `data/logs/bot.log`: Discord Bot のログ（最大 1MB × 3世代）
- `data/logs/admin.log`: 管理 UI のログ（最大 1MB × 3世代）
- `data/djaudio_cache`: DJAudio の一時 MP3 キャッシュ
- `migrations/` + DB（`POSTGRES_DB`）: Web トラッカーの永続データ
- DB（`USER_STATE_POSTGRES_DB`）: ユーザー状態監査データ

> `data/` の保存先は環境変数 `SETTINGS_DIR` で変更できます。Docker 運用時は Bot と管理 UI でボリュームを共有することでログビューアが機能します。

---
