# 機能の詳細

[← README.ja.md に戻る](../README.ja.md)

---

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
- 管理UIの「ユーザー状態監査」アプリで検索・閲覧可能（旧URL `/admin/users/state` からも開けます）

### 1.4 ウェルカム / グッバイ
- 参加/退出時の自動メッセージ
- テンプレート変数対応: `{user}` `{username}` `{server}` `{count}`

### 1.5 VC 通知
- VC 参加/退出/移動を専用チャンネルへ通知
- 退出時は通話時間を表示
- ロールメンション通知（参加・移動時のみ。退出時はメンションしない。間隔制限あり）

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

### 1.11 TTS 読み上げ

- 指定テキストチャンネルに投稿されたメッセージを、指定 VC で自動読み上げ
- 外部 macOS TTS API（[OSX-tts.api.server](https://github.com/sukun-inu/OSX-tts.api.server)）を利用して音声合成し、FFmpeg 経由で VC 再生
- 読み上げ前の自動テキスト前処理:
  - URL → `URL`、メンション → `メンション`、チャンネルリンク → `チャンネル`、カスタム絵文字 → 絵文字名
  - 最大文字数（既定 100 文字）を超えた部分は「以下省略」に置換
- **辞書機能**: 単語 → 読み替えテキストの変換表をサーバーごとに管理
- **ユーザー個別設定**: 声の名前・速度をユーザーごとに保存
- **自動 VC 参加**: 設定済み VC に人間が入ると Bot も自動接続、全員退出で自動退出
- **タイムアウト退出**: 5 分間メッセージがなければ自動で VC から退出
- 複数メッセージはキューで順番に再生（同時再生なし）
- 設定可能:
  - 読み上げ対象テキストチャンネル（複数可）
  - Bot が入る VC チャンネル
  - サーバーデフォルトの声と速度
  - 最大読み上げ文字数

### 1.11.1 VC録音（Craig の代用）

- ボイスチャンネルの音声を**参加者ごとに別トラック**で録り、ZIP でまとめて配布
- 各トラックは同じ時間軸に揃えてあるので、そのまま重ねれば同期する
  （受信できるのは発話中のパケットだけなので、経過時間を基準に不足分を無音で埋めている）
- ZIP には各人の mp3 に加えて `info.txt` / `info.json`（チャンネル・開始者・長さ・発話時間）と、
  ミキサー用の索引 `mixer.json`（トラックの並び・波形・長さ）が入る
- 配布は DJAudio と同じトークン方式（guild 照合＋期限つき）
- **読み上げとの併用**: bot は1ギルドにつき音声接続を1本しか持てないため、
  `services/voice_session.py` で接続を共有する。録音中は占有を立て、読み上げ側の
  「VC が空になったら切る」で接続ごと落とされないようにしている
- **独立したスイッチ**: 録音と読み上げはそれぞれオン／オフでき、両方オンなら同じ接続で両方動く
- **自動録音**: 対象 VC に人が入った時点で録り始める（既定はオフ）。
  対象 VC 未指定なら読み上げの対象 VC に従う
- **停止条件**: 上限時間（既定6時間、0 で無制限）／ VC が無人 ／ `/record stop` ／
  `/tts leave` ／ Bot の停止。どの経路でも書き出してからリンクを出す
- **参加者への告知**: 開始時に対象チャンネルへ録音中である旨を必ず通知（無効化不可）。
  各自 `/record exclude` で自分を対象から外せる（進行中の録音にも即時反映）
- **ミキサー（管理画面）**: 録音を DAW のように stem ごとの時系列で並べて確認・再生できる
  - トラックごとの波形と共通の時間目盛り。途中参加は冒頭が、途中退出は末尾が無音になるので、
    「誰がいつ居たか」がそのまま見える
  - 再生／一時停止／停止、波形クリックで頭出し、トラックごとのミュート・ソロ・音量
  - 全トラックを同時に鳴らして先頭に追従させる（ずれたら黙って引き戻す）
  - 数時間×人数ぶんを丸ごとメモリへ展開せずに済むよう、`<audio>` のストリーミング再生に
    Web Audio の GainNode を挟む構成にしている。ZIP 内の mp3 は**無圧縮**で格納し、
    展開せずに Range リクエストで途中から読めるようにしてある
- 取りこぼした音声パケットがあれば数を記録し、結果に添える
- 音声受信は discord.py 本体に無いため `discord-ext-voice-recv` を使用。
  入っていない環境では読み上げは通常どおり動き、録音だけが理由付きで断られる
- **受信パケットの組み立て**: 拡張のジッタバッファは、順番待ちの穴が空いた瞬間に
  バッファ全体を捨てて1つだけ返す（router 側が `timeout=0` で pop するため）。
  大量に落ちるうえ順不同で出てくるので、そのまま Opus に渡すと音が壊れる。
  そのため受信側でもう一度並べ直してから復号している
  - デコーダは **SSRC ごと**に持つ（Opus は直前の状態を使って復号するので、
    別ストリームを1つのデコーダに入れると音が壊れる）
  - 位置合わせは到着時刻ではなく **RTP タイムスタンプ**（48kHz 刻み）で行う。
    到着時刻で置くと、ジッタのぶんだけ無音が挟まって時間軸が歪む
  - 落ちたフレームは Opus の欠落補間に任せる（黙って飛ばすと継ぎ目が濁る）

> 音声は個人情報保護法上の個人情報に該当し得ます。運用は各サーバーの責任において
> 法令に則って行ってください。運営者は政府機関への提供が必要な場合を除き録音データを使用しません。
> 詳細は[プライバシーポリシー](../webapp_admin/templates/privacy.html)を参照してください。

### 1.12 セキュリティ検知
- スパム判定
- Unicode トリック検知
- VirusTotal URL/添付スキャン
- GPT モデレーション
- **バイパス判定に失敗したときは強制措置を行わない** — 信頼済みユーザー／
  バイパスロールの設定を読めなかった場合、「バイパスなし」とはみなさず、
  メッセージ削除・全ロール剥奪を見送ってログチャンネルへ「要確認」を出す。
  ロール剥奪は元に戻せないため、見逃すより取り返しがつかないほうを避ける
- VC レイド検知
- 信頼済みユーザー / バイパスロールによる除外設定

### 1.13 管理 UI（FastAPI）
- Discord OAuth ログイン
- サーバー単位設定
- Web 上で以下を管理:
  - ログ設定、AI 応答、ウェルカム/グッバイ、VC 通知
  - スティッキー、リアクションロール、ニュース
  - 地震アラート、DJAudio、TTS 読み上げ、セキュリティ
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

### 1.14 Web トラッカー（FastAPI）
- 金属価格 API
- 価格予測
- Push 通知（PWA）

### 1.15 機能と管理導線（早見表）

管理 UI 側の URL は、開くとデスクトップ上の該当ウィンドウが立ち上がります
（`/admin/overview#tts` のようにハッシュでも同じ画面を直接開けます）。

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
| TTS 読み上げ | `/tts *` `/voice *` `/dict *` | `/admin/settings/tts` |
| ユーザー状態監査 | （イベント自動収集） | `/admin/users/state` |

---
