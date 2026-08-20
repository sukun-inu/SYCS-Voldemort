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

---

## 11. Web トラッカーのキャッシュ設計（Cloudflare 配下）

キャッシュ層は「ブラウザ / Cloudflare エッジ / Service Worker」の3段になっている。
更新が反映されない場合はこの表の想定と実際のレスポンスヘッダを突き合わせること。

| 対象 | origin が返す Cache-Control | 意図 |
|---|---|---|
| `/`, `/index.html` | `no-store, no-cache, must-revalidate, max-age=0` | 常に最新を配り、中の `?v=` で他アセットを制御する |
| `/sw.js` | 同上 | Service Worker 自体が古いまま固定されるのを防ぐ |
| `/static/*?v=...` | `public, max-age=31536000, immutable` | 内容ハッシュ付きURLなので永久キャッシュしてよい |
| `/static/*`（クエリ無し） | `public, max-age=300, must-revalidate` | sw.js のプリキャッシュ等が使う素のURL |
| `/api/*` | `no-store, no-cache, must-revalidate, max-age=0` | 価格・予測データは常に最新 |

### バージョンは自動生成される（手動更新は不要）

`webapp/asset_version.py` が `static/app.js` と `static/styles.css` の内容から
SHA-256 の短縮ハッシュを計算し、配信時に以下を差し込む。

- `index.html` 内の `static/app.js?v=...` / `static/styles.css?v=...`
- `sw.js` 内の `CACHE_NAME`

**ソースファイル自体は書き換えず、レスポンスを組み立てるときだけ差し替える。**
中身が1バイトでも変われば必ず URL とキャッシュ名が変わるため、「コードは新しいのに
配信は古いまま」という事故が構造的に起きない。逆に中身が同じならバージョンも変わらず、
不要な再ダウンロードも発生しない。

> 以前は `?v=YYYYMMDD-N` と `CACHE_NAME` を手作業で更新する運用だったが、更新漏れで
> 本番に旧アセットが配信され続ける事故が実際に発生したため自動化した。

### origin が Cache-Control を返さないと何が起きるか

Cloudflare は origin が Cache-Control を返さない場合、独自の TTL を勝手に付与する。
実際に `/static/*` で `max-age=300` が注入され、しかも `Age` がそれを超える
（= エッジ側の TTL は別物）という読めない状態になっていた。origin 側で明示することで
ブラウザ・CF 双方の挙動を確定させている。

### 反映されないときの切り分け

```bash
# 1. origin が意図した Cache-Control を返しているか
curl -sD - -o /dev/null https://<host>/static/app.js?v=test | grep -i cache-control

# 2. Cloudflare がクエリ文字列を区別しているか（未知の ?v= が MISS になれば正常）
curl -sD - -o /dev/null "https://<host>/static/app.js?v=bogus-$(date +%s)" | grep -i cf-cache-status

# 3. 実際に配信されている中身が最新か
curl -s https://<host>/static/app.js | grep -c "<期待する新しい識別子>"
```

3 が最新なのに画面が古い場合はブラウザ側（Service Worker 含む）が原因。
`Ctrl+Shift+R`、それでも直らなければ DevTools → Application → Service Workers → Unregister。
