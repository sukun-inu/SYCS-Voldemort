# SYCS Voldemort

Discord サーバーの運営を楽にするための Bot と、その管理画面をまとめたものです。

金や銀の相場を調べる、AI と雑談する、入退室を記録する、地震が来たら知らせる、
音楽を流す、メッセージを読み上げる — こうした機能が1つの Bot に入っています。

設定は **Discord のスラッシュコマンドからでも、ブラウザで開く管理画面からでも**
変更できます。どの機能をどちらから触れるかは
[docs/FEATURES.ja.md](docs/FEATURES.ja.md) の早見表にまとめてあります。

English: [README.md](README.md)

## 入っている機能

- 貴金属（金・銀・プラチナ）の価格照会
- AI との会話（応答するチャンネルを指定可能）
- 監査ログ、ユーザー状態の長期保存
- 入退室のあいさつ、ボイスチャンネルの参加通知
- スティッキーメッセージ、リアクションロール
- Google ニュースの配信、地震アラート（P2PQuake）
- 音楽のダウンロード再生（DJAudio-DL）
- テキスト読み上げ（声設定・辞書つき）
- VC録音（参加者ごとの別トラック・読み上げと併用可・管理画面のミキサーで波形表示と再生）
- 不審な動きの検知
- 管理画面（FastAPI）と、貴金属価格の Web トラッカー

## 2. 全体構成

| プロセス | エントリーポイント | 役割 |
|---|---|---|
| Discord Bot | `main.py` | Discord イベント処理とスラッシュコマンド |
| Admin UI | `admin_main.py` | 管理画面（FastAPI） |
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

## 4. 開発時の確認

```bash
python -m unittest discover -s tests -t .   # 管理UIの API テスト（DB 不要）
python tools/check_admin_schema.py          # 設定スキーマと services の噛み合わせ
python tools/check_admin_ui.py              # 管理画面を実ブラウザで操作して確認
python tools/generate_admin_docs.py         # docs/ADMIN.ja.md の設定表を再生成
```

いずれも一時ディレクトリを `SETTINGS_DIR` にして動くため、本物の `settings.json` は変更しません。

`main` への push と pull request では、`.github/workflows/tests.yml` がこのうち
`python -m unittest`・`check_admin_schema.py`・`check_requirements.py`・
`generate_admin_docs.py --check` を自動で実行します（`check_admin_ui.py` は
実ブラウザが要るため CI には含めていません）。

### カバレッジを測る

```bash
pip install -r requirements-dev.txt          # coverage を追加インストール
python -m coverage run -m unittest discover -s tests -t .
python -m coverage report -m                  # ファイルごとの実行率を表示
python -m coverage html && start htmlcov/index.html   # 行単位で見たいとき
```

対象は本体コード（ルート直下の `.py`、`services/`、`commands/`、`webapp/`、
`webapp_admin/` など）のみで、`tests/`・`tools/`・`migrations/`・`scripts/`
は `.coveragerc` の `omit` で除外しています。一度も import されないモジュールも
0% として数えるように `source = .` を使っているため、テストが薄い場所ほど
数字が正直に低く出ます。

---

## ドキュメント

| | |
|---|---|
| [docs/DESIGN.ja.md](docs/DESIGN.ja.md) | 全体の設計。どう作られているか、なぜそうしたか |
| [docs/FEATURES.ja.md](docs/FEATURES.ja.md) | 全機能の詳細と、機能ごとの管理導線の早見表 |
| [docs/COMMANDS.ja.md](docs/COMMANDS.ja.md) | スラッシュコマンド一覧（一般 / 管理 / セキュリティ / DJAudio / TTS） |
| [docs/SETUP.ja.md](docs/SETUP.ja.md) | Docker Compose、環境変数、マルチインスタンス運用 |
| [docs/ADMIN.ja.md](docs/ADMIN.ja.md) | 管理UIの使い方、データの保存先 |
| [docs/TROUBLESHOOTING.ja.md](docs/TROUBLESHOOTING.ja.md) | よくある詰まりどころ、ディレクトリ概要 |
| [CONTRIBUTING.ja.md](CONTRIBUTING.ja.md) | 手を入れるときの約束ごと。コミットの書き方、テストの検証の仕方、型検査で防御を外さないこと |
