# rust/

discord.py をやめて serenity へ移すための置き場です（2026-11-25〜）。移行が終わるまでは
Python と Rust のプロセスが本番で共存します。進め方と順番は、リポジトリの外の
移行トラッカーと `docs/UPGRADE.ja.md` にあります。

| 場所 | 中身 |
|---|---|
| `crates/sycs-core` | Rust のプロセスが共通で使う土台。環境変数の読み方・接続先・ログ・メトリクス・設定の読み込み・Bot への依頼の取り出し |
| `tools/voice-check` | serenity + songbird の Bot が、DAVE 必須の VC で音を届けられるかを人の耳で確かめる道具 |

## Python と揃えているもの

共存している間は、同じ環境変数を読み、同じデータベースにつなぎ、同じディレクトリへ
ログを書きます。規則が違うと、片方だけが別の値で動いたり、管理画面で片方のログだけ
絞り込めなかったりします。揃っていることはテストで確かめています。

| もの | Python | Rust | 揃っていることの確かめ方 |
|---|---|---|---|
| 環境変数の読み方 | `envutil.py` | `sycs_core::env` | 同じ規則のテスト（空文字は未設定、読めない値は既定値、範囲外は丸める、NaN は弾く） |
| `user_state_audit` への接続先 | `services/user_state_db.py` | `sycs_core::db` | 同じ環境変数から同じ接続先になるかを、両方で組み立てて突き合わせた（変更のコミットに記録） |
| ログの形 | `services/log_setup.py` | `sycs_core::log` | Rust が書いた JSONL を管理画面の絞り込みの関数に読ませた。カテゴリの名前は Python の表にあるものだけを使う（テストが Python のファイルを読んで確かめる） |
| メトリクス（Valkey への心拍・ゲージ・カウンタ） | `services/metrics_registry.py` / `metrics_reporter.py` | `sycs_core::metrics` | Rust が本物の Valkey へ報告したものを、管理画面の `/metrics` の組み立て（Python）で出した。`sycs_up` が 1、ゲージが出る、カウンタは Python の分と同じ鍵で足し合わさる、心拍とカウンタに期限が無くゲージには有る。カウンタの名前に `sycs_` を付けない（`/metrics` が付ける） |
| ギルドごとの設定の読み込み | `services/settings_pg.py` | `sycs_core::settings` | 本物の Python（settings_store）が作って書いた表を Rust が読み、Python の変更が通知で同じ瞬間に届いた。CI でも Postgres 16 を立てて、通知・つなぎ直し・版番号の確認を毎回確かめる。書き込みは Bot を移す塊で足す |
| 管理画面から Bot への依頼の取り出し | `services/dev_signals.py` | `sycs_core::signals` | Python が置いた依頼を、Rust が置いた順・畳まれた形で取り出した。ロック中の行は待たずに飛ばす（Python と Rust の Bot が並んでも二重に実行しない） |
| ログのレベルの名前 | `WARNING` | `WARN` を `WARNING` と書く | 管理画面は `WARNING` で比べる。`WARN` のままだと「警告以上」で警告が全部消える |
| ログのファイル名 | `bot.log` / `bot.log.2026-11-24.gz` | 同じ | 移行中に同じディレクトリで 2 通りの名前が混ざると、片方の掃除が相手を見つけられない |

## 守ること

- **版は `=` で固定し、`Cargo.lock` をコミットする。** Rust 本体は `rust-toolchain.toml`。
- **本番の CPU は Sandy Bridge（AVX2 無し）。** ビルドは `.cargo/config.toml` で
  `target-cpu=sandybridge` に絞っている。`native` にしないこと。CI はテストも
  Sandy Bridge のふりで動かす。
- **本番のイメージは Debian 系にする。** Ubuntu 26.04 系は glibc が x86-64-v3 を要求し、
  本番では起動しない。
- **イメージに tzdata を入れること。** 無いと `TZ=Asia/Tokyo` が効かず、ログの時刻が
  UTC になる（Python と並べて読むとずれる）。
- `unsafe` は書かない（ワークスペースで禁止してある）。公開するものには説明を書く。
- **Postgres を使うテストは `#[ignore]` を付け、CI が `--include-ignored` で必ず回す。**
  手元では `SYCS_TEST_DATABASE_URL` に Postgres を渡して回す。SQLite での代用はしない
  （LISTEN/NOTIFY と FOR UPDATE SKIP LOCKED が無く、効いているかを確かめられない）。
- 表を作るのは今は Python 側。Python を外すときに、表の作り方（マイグレーション）を Rust へ移す。
