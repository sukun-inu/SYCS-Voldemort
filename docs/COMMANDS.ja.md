# スラッシュコマンド一覧

[← README.ja.md に戻る](../README.ja.md)

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
| `/trusted_member_add` | 信頼済みユーザー追加（実行後に表示されるユーザー選択メニューで複数選択可） |
| `/trusted_member_remove` | 信頼済みユーザー削除（同上） |
| `/trusted_member_list` | 信頼済みユーザー一覧 |
| `/bypass_role_add` | バイパスロール追加（実行後に表示されるロール選択メニューで複数選択可） |
| `/bypass_role_remove` | バイパスロール削除（同上） |
| `/bypass_role_list` | バイパスロール一覧 |

### 6.5 DJAudio

| コマンド | 説明 |
|---|---|
| `/djaudio_channel_set` | DJAudio 監視チャンネル設定（未指定で解除） |
| `/djaudio_output_set` | MP3 リンクの送信先チャンネル設定（未指定で解除→監視チャンネルに返信） |
| `/djaudio_status` | DJAudio 設定表示 |

### 6.6 TTS 読み上げ（管理者専用）

| コマンド | 説明 |
|---|---|
| `/tts enable` | TTS 読み上げを有効化 |
| `/tts disable` | TTS 読み上げを無効化 |
| `/tts add_watch` | 読み上げ対象のテキストチャンネルを追加 |
| `/tts remove_watch` | 読み上げ対象からテキストチャンネルを削除 |
| `/tts vc` | Bot が入る VC チャンネルを設定 |
| `/tts default_voice` | サーバーデフォルトの声を設定（オートコンプリート対応） |
| `/tts default_rate` | サーバーデフォルトの速度を設定（100〜400語/分） |
| `/tts read_name` | メッセージ読み上げ時に発言者名を読み上げるか設定 |
| `/tts status` | 現在の TTS 設定を表示 |
| `/tts join` | 指定 VC に一時参加し、そのVCのコメント欄を優先読み上げ対象にする |
| `/tts leave` | Bot を VC から退出させキューをクリア（`/tts join` 中なら元の設定に戻る） |

### 6.7 TTS 声設定（全ユーザー）

| コマンド | 説明 |
|---|---|
| `/voice set [voice] [rate]` | 自分の声と速度を設定（オートコンプリート対応） |
| `/voice reset` | 自分の声設定をデフォルトに戻す |
| `/voice info` | 自分の現在の声設定を表示 |

### 6.8 TTS 辞書（全ユーザー）

| コマンド | 説明 |
|---|---|
| `/dict add word reading` | 辞書に単語→読みを登録（例: `Discord` → `ディスコード`） |
| `/dict remove word` | 辞書から単語を削除 |
| `/dict list` | 辞書の一覧を表示（最大50件） |

---
