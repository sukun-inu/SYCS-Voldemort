# スラッシュコマンド一覧

[← README.ja.md に戻る](../README.ja.md)

---

## 6. スラッシュコマンド

すべてグループ配下にまとめてあります（例: `/log channel`, `/news add`）。
Discord で `/` を押したときに並ぶのは **18 個のグループ**で、その下に全 64 コマンドが入ります。
この一覧は現行実装（`commands/*.py`）と一致していることをテストで検証しています
（`tests/test_commands.py` の `CommandTreeTests`）。

<details>
<summary>旧名からの対応表（2026-08-25 に変更）</summary>

平坦な名前を 62 個並べると、`/` の一覧が長くなり、関連するコマンドが隣り合う保証もありません。
そのため同じ話題ごとにグループへまとめました。**旧名は使えません。**

| 旧 | 新 |
|---|---|
| `/welcome_channel_set` | `/greeting welcome channel` |
| `/welcome_message_set` | `/greeting welcome message` |
| `/goodbye_channel_set` | `/greeting goodbye channel` |
| `/goodbye_message_set` | `/greeting goodbye message` |
| `/welcome_goodbye_status` | `/greeting status` |
| `/vc_notify_channel_set` | `/vcnotify set` |
| `/vc_notify_channel_clear` | `/vcnotify clear` |
| `/sticky_set` `/sticky_clear` `/sticky_list` | `/sticky set` `/sticky clear` `/sticky list` |
| `/reaction_role_add` ほか | `/reactionrole add` ほか |
| `/news_feed_add` ほか | `/news add` ほか |
| `/quake_channel_set` | `/quake channel` |
| `/quake_min_scale_set` | `/quake min_scale` |
| `/quake_notify_type` | `/quake type` |
| `/quake_status` | `/quake status` |
| `/server_info` | `/info server` |
| `/user_info` | `/info user` |
| `/log_channel_set` `/log_level_set` | `/log channel` `/log level` |
| `/chat_channel_set` `/chat_channel_clear` | `/chat set` `/chat clear` |
| `/trusted_member_add` ほか | `/trusted add` ほか |
| `/bypass_role_add` ほか | `/bypass add` ほか |
| `/bot_settings` `/bot_help` | `/bot settings` `/bot help` |
| `/djaudio_channel_set` | `/djaudio channel` |
| `/djaudio_output_set` | `/djaudio output` |
| `/djaudio_status` | `/djaudio status` |
| `/metal_gold` ほか | `/metal gold` ほか |

`/tts` `/voice` `/dict` `/record` は元からグループなので変わっていません。

</details>

### 6.1 一般ユーザー向け

| コマンド | 説明 |
|---|---|
| `/metal gold` | 金の価格 |
| `/metal silver` | 銀の価格 |
| `/metal platinum` | プラチナの価格 |
| `/metal all` | 金・銀・プラチナをまとめて表示 |
| `/info server` | サーバー情報 |
| `/info user` | ユーザー情報 |
| `/bot help` | コマンド一覧 |

### 6.2 管理系（ログ / AI）

| コマンド | 説明 |
|---|---|
| `/log channel` | ログチャンネル設定 |
| `/log level` | ログレベル設定 |
| `/chat set` | AI 応答チャンネル設定 |
| `/chat clear` | AI 応答チャンネル解除 |
| `/bot settings` | 設定表示 |

### 6.3 サーバー運用

| コマンド | 説明 |
|---|---|
| `/greeting welcome channel` | ウェルカム送信チャンネル設定 |
| `/greeting welcome message` | ウェルカム本文設定 |
| `/greeting goodbye channel` | グッバイ送信チャンネル設定 |
| `/greeting goodbye message` | グッバイ本文設定 |
| `/greeting status` | ウェルカム/グッバイ設定表示 |
| `/vcnotify set` | VC 通知チャンネル設定 |
| `/vcnotify clear` | VC 通知チャンネル解除 |
| `/sticky set` | スティッキー設定 |
| `/sticky clear` | スティッキー解除 |
| `/sticky list` | スティッキー一覧 |
| `/reactionrole add` | リアクションロール追加 |
| `/reactionrole remove` | リアクションロール削除 |
| `/reactionrole list` | リアクションロール一覧 |
| `/news add` | ニュースフィード追加 |
| `/news remove` | ニュースフィード削除 |
| `/news list` | ニュースフィード一覧 |
| `/quake channel` | 地震アラートチャンネル設定 |
| `/quake min_scale` | 最小震度設定 |
| `/quake status` | 地震設定表示 |
| `/quake type` | 地震通知タイプ ON/OFF |

### 6.4 セキュリティ管理

| コマンド | 説明 |
|---|---|
| `/trusted add` | 信頼済みユーザー追加（実行後に表示されるユーザー選択メニューで複数選択可） |
| `/trusted remove` | 信頼済みユーザー削除（同上） |
| `/trusted list` | 信頼済みユーザー一覧 |
| `/bypass add` | バイパスロール追加（実行後に表示されるロール選択メニューで複数選択可） |
| `/bypass remove` | バイパスロール削除（同上） |
| `/bypass list` | バイパスロール一覧 |

### 6.5 DJAudio

| コマンド | 説明 |
|---|---|
| `/djaudio channel` | DJAudio 監視チャンネル設定（未指定で解除） |
| `/djaudio output` | MP3 リンクの送信先チャンネル設定（未指定で解除→監視チャンネルに返信） |
| `/djaudio status` | DJAudio 設定表示 |

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
