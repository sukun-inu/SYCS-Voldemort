# WebAdmin 引継ぎメモ

管理UIの構造と、触るときに知っておくべきことをまとめる。
画面の使い方と設定項目の一覧は [docs/ADMIN.ja.md](../docs/ADMIN.ja.md)（設定表はスキーマから自動生成）。

---

## 1. 全体の形

```text
ブラウザ                     サーバ
┌──────────────┐            ┌────────────────────────────┐
│ shell.html   │ ← 1枚だけ  │ web: シェルと公開ページ     │
│  + ES modules│            ├────────────────────────────┤
│              │ ←─ JSON ─→ │ api/: /admin/api/*          │
│  ウィンドウ  │            ├────────────────────────────┤
│  フォーム    │            │ schema/: 何が設定できるか   │
└──────────────┘            ├────────────────────────────┤
                            │ services/: 値の読み書き     │
                            └────────────────────────────┘
```

- 基盤は `FastAPI`。セッションは `SessionMiddleware`（cookie: `admin_session`）。
- サーバが返す HTML は **シェル1枚**（`templates/shell.html`）。設定画面はクライアントが
  `/admin/api/apps/{id}` のスキーマから DOM を組み立てる。iframe は使わない。
- 設定の永続化は `services/settings_store.py` の `settings.json`。TTS だけは
  `services/tts_store.py` を経由する。
- ユーザー状態監査は Postgres（`USER_STATE_POSTGRES_DB`）。

## 2. 起動エントリ

- 管理UI: `admin_main.py` → `webapp_admin/app.py`
- `ADMIN_WORKERS` の既定は **1**。メトリクス・監視スレッド・レート制限はプロセス
  ローカルなので、増やすなら `ADMIN_LIMITER_STORAGE_URI` に Redis を設定すること。

## 3. ディレクトリ

| 場所 | 役割 |
|---|---|
| `core/config.py` | 環境変数とセッション鍵の解決（ここ以外で鍵を作らない） |
| `schema/types.py` | `Field` / `Collection` / `Section` / `Panel` の定義 |
| `schema/panels/*.py` | **設定の宣言。ここが単一の情報源** |
| `schema/registry.py` | 全パネルの登録。タイルの並び・旧URLの逆引き表 |
| `schema/validation.py` | 入力検証（widget と min/max/choices から導く） |
| `schema/choices.py` | チャンネル・ロール・声の実行時解決 |
| `api/apps.py` | スキーマ駆動の取得・保存・一覧操作 |
| `api/users.py` | ユーザー状態監査（検索・ページングはサーバ側） |
| `api/dev.py` | 開発者パネル（`DEV_USER_ID` 一致者のみ） |
| `views/` | シェルとギルド選択の HTML だけ |
| `static/css/` | tokens / base / components / desktop / motion / page / public |
| `static/js/wm/` | ウィンドウマネージャ |
| `static/js/lib/motion.js` | 位置を測ってから動かすアニメーション（最小化・最大化・開閉） |
| `static/js/forms/` | スキーマ → DOM のレンダラと明示保存 |
| `static/js/apps/` | 専用画面（monitor / user_state / dev / sql / recording / mixer / guild_data） |

## 4. 設定を1つ増やすとき

`schema/panels/<機能>.py` の `Section` に `Field` を1つ足すだけ。
フォーム・検証・API・ドキュメントはそこから派生する。**テンプレートは書かない。**

```python
Field(
    "notify_role_id", "通知するロール", Widget.ROLE,
    get=lambda gid: get_notify_role(gid) or None,   # 未設定は None に寄せる
    set=set_notify_role,
    help="未設定ならメンションしません。",
)
```

- `get` / `set` は **必ず `services/` の関数を指す**。`settings.json` を直接書かない。
  Bot 側が同じ関数を読んでいるため、直接書くと解釈がズレる。
- 追加したら次を実行する。
  - `python tools/check_admin_schema.py` — get/set の往復と、未設定に戻せるかを実際に確認
  - `python tools/generate_admin_docs.py` — docs/ADMIN.ja.md の設定表を更新
  - アイコンを増やした場合は `python tools/build_icon_sprite.py`

## 5. 決めごと

- **明示保存**。変更された項目だけを `PUT /admin/api/apps/{id}` で送る。
  一覧への追加・削除だけは即時実行する（まとめ保存に混ぜると反映範囲が見えなくなるため）。
- **検証はサーバが最終判断**。クライアントの入力制限は補助でしかない。
  エラーはフィールド単位で返し、該当欄の直下に出す。
- **未設定は `None`**。`settings.json` 上は 0 / null / キー欠落が混在するので、
  スキーマの `to_json_value()` で `None` に正規化してからクライアントへ渡す。
- **選択肢が取れないときも操作できるようにする**。Discord API や TTS API が落ちている
  ときは ID / 名前の直接入力へフォールバックする。サーバ側は「一覧が取得できたときだけ
  その中の値か検証する」ので安全側に働く。
- **セクションが4つ以上のパネルはウィンドウ内タブ**（`Panel.layout="auto"` が判断）。
- **CSRF は `X-CSRFToken` ヘッダ**。書き込み系 API はすべて検証する。
- CSP は `script-src 'self'` / `style-src 'self'`。**インライン style / script は使えない**。
  スタイルは CSS クラスに、イベントは `addEventListener` に書く。
- アイコンは同梱スプライト（`static/icons/sprite.svg`）を `<use>` で参照する。
  JS からは `lib/dom.js` の `icon()`、テンプレートからは `{{ icon('name') }}`。
- **動きは transform と opacity だけ**。長さとイージングは `tokens.css` の `--dur-*` /
  `--ease-*` に揃え、CSS で書けるものは `motion.css`、終点の座標を測る必要があるものだけ
  `lib/motion.js` の `play()` に置く。`prefers-reduced-motion: reduce` では
  base.css が CSS を潰し、`play()` は待たずに解決する（**両方直さないと片方だけ動く**）。
- **色は状態を表す**。固定色のバッジやメーターを置かない（例: 監視のメーターは
  `metrics.py` の `load_tone()` がしきい値と同じ物差しで色を決める）。

## 6. 確認コマンド

```bash
python -m unittest discover -s tests -t .   # API テスト（DB不要）
python tools/check_admin_schema.py          # スキーマと services の噛み合わせ
python tools/check_admin_ui.py              # 実ブラウザで開く・保存する・閉じる
```

`tools/check_admin_ui.py` は Chromium（playwright）が要る。無ければスキップされる。
どちらのツールも一時ディレクトリを `SETTINGS_DIR` にして動くので、本物の設定は触らない。

## 7. 実装の履歴で知っておくと良いこと

- ChatGPT 応答チャンネルが未設定 (`0`) のときは「無効」として扱う（Bot / WebUI 共通）。
- Discord OAuth の `prompt` は既定で指定なし。`DISCORD_OAUTH_PROMPT=none|consent` のときだけ明示。
- セッションには JSON シリアライズ可能な値だけを入れる（`admin_guilds` は軽量化して保存）。
- `ExceptionGroup` は分解して root / leaves をログに出す（見切れログでも原因を追えるように）。
- TTS の `watch_channel_ids` は `int` のリストで保存する。JSON 経由で文字列になることがあるため、
  比較の前に `int()` へ寄せる（`tts_store.py` が担保している）。
- TTS API へのリクエストは `format=wav`（サーバ側に ffmpeg を要求しないため）。
- 「サーバーのデータ」（`guild_data`）は設定項目ではなく操作なので、Field では表せない。
  custom パネルにして、`DELETE /admin/api/guild-data` を叩く画面を JS で組む。確認は
  **サーバーIDを打たせる**。はい/いいえの窓を重ねない（読まずに押す確認を足しても強く
  ならない）。押せるかどうかの判定は補助で、突き合わせは API 側がやり直す。
- シェルは `<meta name="guild-id">` / `<meta name="guild-name">` にいま選んでいる
  サーバーを埋める。**表示のためだけの値**で、API はセッションの guild_id しか見ない。
- 旧UI（Bootstrap + サイドバー + iframe + autosave）は 2026-08 に全廃した。
  `admin.css` / `admin.js` / `base.html` / `views/settings_views.py` などは存在しない。

## 8. 運用時に確認する環境変数

- `ADMIN_FLASK_SECRET_KEY`: セッション署名キー（全インスタンスで同一に）
- `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` / `DISCORD_REDIRECT_URI` / `DISCORD_BOT_TOKEN`
- `DEV_USER_ID`: 開発者パネルを使えるユーザー。未設定ならパネルごと 404
- `ADMIN_WORKERS`（既定 1）/ `ADMIN_LIMITER_STORAGE_URI`（複数台なら Redis）
- `TTS_BASE_URL`: macOS TTS API の URL（TTS 機能を使う場合）
- `SETTINGS_DIR`: 設定・ログ・監視データの保存先
