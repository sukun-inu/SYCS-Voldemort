# WebAdmin 引継ぎメモ

## 1. 現在の実装方針
- 実装基盤は Flask ではなく `FastAPI` です。
- セッションは `SessionMiddleware`（cookie: `admin_session`）で管理しています。
- 画面は `Jinja2Templates` + `webapp_admin/templates/` を使用しています。
- 設定の永続化は `services/settings_store.py` の `settings.json` です。

## 2. 起動エントリ
- 管理UI: `admin_main.py`
- アプリ本体: `webapp_admin/app.py`

## 3. 主要ルート
- `/admin/login`: ログイン画面
- `/admin/auth`: Discord OAuth 開始
- `/admin/callback`: Discord OAuth コールバック
- `/admin/guilds`: 管理対象サーバー選択
- `/admin/overview`: ダッシュボード
- `/admin/settings/*`: 各種設定画面（logging / welcome / vc-notify / sticky / reaction-roles / news-feeds / earthquake / security / djaudio / **tts**）

## 4. ロジックの責務分担
- `webapp_admin/views/*.py`
  - フォーム入力の受け取りとバリデーション
  - `services/settings_store.py` または専用 store への保存
- `services/settings_store.py`
  - guild単位設定の読み書き
  - 旧データとの互換（主に DJAudio）
- `services/tts_store.py`
  - TTS 専用設定の読み書き（settings.json の `guilds[id].tts` を操作）
  - ユーザー個別声設定・辞書・デフォルト声/速度を管理
- `services/tts_service.py`
  - OSX-tts.api.server への HTTP 音声合成リクエスト
  - ギルドごとの VC 接続・再生キュー管理（asyncio.Queue）
  - 自動参加・自動退出・タイムアウト退出ロジック
- `bot_setup.py` / `commands/*.py` / `services/*.py`
  - 実際の Bot 挙動（設定値の参照先）

## 5. TTS 機能の追加概要（2026-05-16）

### 追加ファイル
- `services/tts_store.py`: settings.json 内の `tts` キー配下を操作する読み書きヘルパー
- `services/tts_service.py`: TTS API 呼び出し・VC 接続・再生キュー（asyncio.Queue による順次再生）
- `commands/tts_commands.py`: `/tts`（管理者専用）・`/voice`・`/dict` スラッシュコマンド
- `webapp_admin/views/tts_views.py`: `/admin/settings/tts` のルーター
- `webapp_admin/templates/settings/tts.html`: TTS 管理画面テンプレート

### 変更ファイル
- `config.py`: `TTS_BASE_URL` 環境変数を追加（既定 `http://localhost:8080`）
- `requirements.txt`: `discord.py` → `discord.py[voice]`（PyNaCl を含む）
- `docker-compose.yml`: `sycs-voldemort` コンテナに `TTS_BASE_URL` 環境変数を追加
- `webapp_admin/auth.py`: `get_guild_voice_channels()` を追加（type=2 VC のみ）
- `webapp_admin/app.py`: `tts_router` を `/admin/settings` プレフィックスで登録
- `webapp_admin/templates/base.html`: サイドバーの「メディア」グループに TTS リンクを追加
- `webapp_admin/templates/landing.html`: TTS 機能カード追加・meta 説明更新
- `webapp_admin/templates/guide.html`: TTS 節・コマンド説明追加
- `commands/__init__.py`: `register_tts_commands` を登録
- `bot_setup.py`:
  - `on_message` に TTS ハンドラを追加（watch_channel_ids に含まれるチャンネルで発火）
  - `on_voice_state_update` の VC 通知ロジックを内部関数 `_vc_notify_handler()` に切り出し（早期 return が TTS 自動参加をスキップするバグ修正）
  - `on_voice_state_update` に自動参加・自動退出ロジックを追加

### settings.json のスキーマ（TTS部分）
```json
"tts": {
  "enabled": false,
  "watch_channel_ids": [123456789],
  "vc_channel_id": 987654321,
  "default_voice": "Kyoko",
  "default_rate": 200,
  "max_length": 100,
  "speak_max_length": 200,
  "user_settings": {
    "USER_ID": { "voice": "Otoya", "rate": 250 }
  },
  "dictionary": {
    "Discord": "ディスコード",
    "w": "わらい"
  }
}
```

### 追加修正時の注意
- `watch_channel_ids` は `int` のリストとして保存するが、JSON 経由では文字列になる場合があるため `int(cid)` でキャストして比較すること
- TTS API へのリクエストは `format=wav` で送信する（サーバー側に ffmpeg が不要）。`discord.FFmpegPCMAudio` が WAV を PCM に変換する
- TTS API の `/api/v1/voices` は `locale=ja` でフィルタしている。英語音声も使いたい場合は `fetch_voices()` の引数を変更するか別途呼び出すこと
- 管理 UI の声選択は GET 時に `fetch_voices()` を呼び出してドロップダウンを生成する。API が落ちている場合はテキスト入力にフォールバックする
- `max_length`（本文上限）と `speak_max_length`（名前プレフィックス込み全体上限）は管理画面の「デフォルト声設定」フォームから変更可能
- `_player_loop` は `asyncio.wait_for(..., timeout=300)` でアイドル退出する。Bot 再起動後はキューが消えるため再投稿が必要
- 管理 UI の `action=reset_user` はユーザーIDを整数で受け取ること（`sanitize` → `int()` の順でバリデーション）
- `on_voice_state_update` の VC 通知ブロックは内部関数化されており、VC 通知が無効でも TTS 自動参加・退出が動作する（旧実装では早期 return でスキップされていた）

## 7. 過去の修正不整合
- ChatGPT 応答チャンネルが未設定 (`0`) のときは「無効」として扱う仕様に統一（Bot / WebUI / 表示文言）。
- サーバー選択 POST (`/admin/guilds/select`) に CSRF 検証を追加。
- Discord OAuth URL の `prompt=none` 固定を廃止。
  - 既定は `prompt` 指定なし（通常のOAuth挙動）。
  - `DISCORD_OAUTH_PROMPT=none|consent` のときのみ明示指定。
- セッション保存前に `admin_guilds` を軽量化し、JSON 非対応値のガードを追加。
- `ExceptionGroup` を分解して root/leaves をログへ出すようにし、見切れログでも原因追跡しやすくした。

## 8. 運用時に確認する環境変数
- `ADMIN_FLASK_SECRET_KEY`: セッション署名キー（全インスタンス共通にする）
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`
- `DISCORD_BOT_TOKEN`
- `ADMIN_LIMITER_STORAGE_URI`（複数台構成は Redis 推奨）
- `TTS_BASE_URL`: macOS TTS API サーバーの URL（TTS 機能使用時）

## 9. 追加修正時の注意
- WebAdmin の保存キーと Bot 側の参照キーを必ず同時確認すること。
- 画面側の `action` 値と `views/*.py` の `if action == ...` を一致させること。
- 設定変更後は、`commands` と `services` の参照ロジックも同時に追うこと。
- `request.session` には JSON シリアライズ可能な値のみ保存すること（巨大・複雑なオブジェクトは避ける）。
- TTS 設定は `settings_store.py` の汎用関数ではなく `tts_store.py` 専用関数を使うこと（watch_channel_ids の整合性維持のため）。
