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
| `/tts join` | 指定 VC に一時参加し、そのVCのコメント欄を優先読み上げ対象にする（**管理者が実行した場合のみ**、条件が揃えば録音も開始） |
| `/tts leave` | Bot を VC から退出させキューをクリア（`/tts join` 中なら元の設定に戻る）。**管理者が実行した場合のみ**、録音中なら締めてリンクを出す。管理者以外は読み上げだけ止まり、録音は続く |

### 6.6.1 VC録音（管理者専用 / `/record exclude` のみ全ユーザー）

読み上げとは独立したスイッチで、両方オンなら同じ接続で両方動きます。

| コマンド | 説明 |
|---|---|
| `/record start [channel]` | 録音を開始（未指定なら自分が今いる VC）。参加者へ録音中である旨が通知される |
| `/record stop` | 録音を停止し、ユーザー別マルチトラックの ZIP へのリンクを出す |
| `/record status` | 録音中かどうか、経過時間、参加者ごとの発話時間を表示 |
| `/record auto enabled [channel]` | 自動録音のオン／オフ。対象 VC 未指定なら読み上げの対象 VC に従う |
| `/record config [enabled] [limit_minutes] [retention_days] [announce_channel]` | 設定の表示・変更（引数なしで現在の設定を表示） |
| `/record exclude [exclude]` | **全ユーザー**。自分を録音対象から外す／戻す。進行中の録音にも即時反映 |

`/record config` で指定できる値:

| 引数 | 範囲 | 既定 | 説明 |
|---|---|---|---|
| `enabled` | 真偽 | 有効 | 録音機能そのもののオン／オフ。オフなら自動録音も手動開始もできない |
| `limit_minutes` | 0〜720 | 360 | 自動停止までの分数。**0 で無制限**（VC から全員が退出するまで録り続ける） |
| `retention_days` | 1〜30 | 7 | ダウンロードリンクの保存日数。経過後は自動削除 |
| `announce_channel` | テキストch | 未設定 | 開始・完了の通知先。未設定なら VC のチャット欄 |

録音の開始・停止は、次のいずれでも起こります。

- 開始 … 対象 VC への入室 / `/record start` / `/tts join`（管理者のみ）/ 読み上げの自動参加
- 停止 … `/record stop` / `/tts leave`（管理者のみ）/ VC が無人になる / 上限時間に到達 / Bot の停止

> 録音の開始・停止は管理者に限られます。`/tts join` と `/tts leave` は誰でも打てるコマンドですが、
> 録音に触れる部分だけは管理者権限を確認します。

録り終えた録音は、管理画面の **VC録音** から「ミキサー」を開くと、トラックごとの波形を
同じ時間軸に並べて再生・確認できます（ミュート／ソロ／音量、波形クリックで頭出し）。

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
