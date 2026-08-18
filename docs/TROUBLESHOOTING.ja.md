# 詰まったときは

[← README.ja.md に戻る](../README.ja.md)

---

## 9. よくある詰まりどころ

### DJAudio が動かない
- `DJAUDIO_AUTO_INSTALL_FFMPEG=false` にしていないか
- `DJAUDIO_FFMPEG_PATH` が不正なパスになっていないか
- `yt-dlp` が実行できるか
- `DJAUDIO_BASE_URL` が外部アクセス可能な URL か
- `/djaudio_channel_set` で監視チャンネルを設定済みか

### TTS が動かない
- `TTS_BASE_URL` が TTS API サーバーの正しい URL を指しているか
- TTS API サーバー（OSX-tts.api.server）が起動しているか（`GET /api/v1/health` で確認）
- `/tts enable` / 管理 UI で TTS が有効になっているか
- `/tts vc` または管理 UI で VC チャンネルが設定されているか
- `/tts add_watch` または管理 UI で読み上げチャンネルが設定されているか
- Bot に VC への接続権限があるか
- `ffmpeg` が Bot の実行環境でアクセス可能か（音声再生に使用）

### 管理 UI にログインできない
- `DISCORD_CLIENT_ID/SECRET/REDIRECT_URI` が一致しているか
- Discord Developer Portal の Redirect URL と同じか

### ログイン後にサーバー選択でログイン画面に戻る
- `ADMIN_FLASK_SECRET_KEY` を設定していない場合は `data/.admin_session_secret` が正常に作成されているか確認
- `data/` ディレクトリ（`SETTINGS_DIR`）が書き込み可能か確認（Docker では `app_data` ボリュームのマウントを確認）

### コマンドが見えない
- Bot 再起動後に `bot.tree.sync()` が完了しているか
- 古いコマンド名（旧命名）を使っていないか

---

---

## 10. ディレクトリ概要

```text
commands/      # スラッシュコマンド定義
services/      # Bot/Web 共通サービスロジック
webapp_admin/  # FastAPI 管理 UI
webapp/        # FastAPI Web トラッカー
migrations/    # DB マイグレーション
```
