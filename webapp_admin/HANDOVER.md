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
- `/admin/settings/*`: 各種設定画面

## 4. ロジックの責務分担
- `webapp_admin/views/*.py`
  - フォーム入力の受け取りとバリデーション
  - `services/settings_store.py` への保存
- `services/settings_store.py`
  - guild単位設定の読み書き
  - 旧データとの互換（主に DJAudio）
- `bot_setup.py` / `commands/*.py` / `services/*.py`
  - 実際の Bot 挙動（設定値の参照先）

## 5. 今回修正した不整合
- ChatGPT 応答チャンネルが未設定 (`0`) のときは「無効」として扱う仕様に統一（Bot / WebUI / 表示文言）。
- サーバー選択 POST (`/admin/guilds/select`) に CSRF 検証を追加。
- Discord OAuth URL の `prompt=none` 固定を廃止。
  - 既定は `prompt` 指定なし（通常のOAuth挙動）。
  - `DISCORD_OAUTH_PROMPT=none|consent` のときのみ明示指定。
- セッション保存前に `admin_guilds` を軽量化し、JSON 非対応値のガードを追加。
- `ExceptionGroup` を分解して root/leaves をログへ出すようにし、見切れログでも原因追跡しやすくした。

## 6. 運用時に確認する環境変数
- `ADMIN_FLASK_SECRET_KEY`: セッション署名キー（全インスタンス共通にする）
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`
- `DISCORD_BOT_TOKEN`
- `ADMIN_LIMITER_STORAGE_URI`（複数台構成は Redis 推奨）

## 7. 追加修正時の注意
- WebAdmin の保存キーと Bot 側の参照キーを必ず同時確認すること。
- 画面側の `action` 値と `views/*.py` の `if action == ...` を一致させること。
- 設定変更後は、`commands` と `services` の参照ロジックも同時に追うこと。
- `request.session` には JSON シリアライズ可能な値のみ保存すること（巨大・複雑なオブジェクトは避ける）。
