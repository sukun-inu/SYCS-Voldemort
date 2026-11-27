# rust/

discord.py をやめて serenity へ移すための置き場です（2026-11-25〜）。移行が終わるまでは
Python と Rust のプロセスが本番で共存します。進め方と順番は、リポジトリの外の
移行トラッカーと `docs/UPGRADE.ja.md` にあります。

| 場所 | 中身 |
|---|---|
| `apps/bot` | Discord の Bot（serenity）。discord.py の Bot を置き換える。今は骨組み（ログ・心拍・設定のキャッシュと起動時の null の掃除・依頼の巡回・止め方）と、ログチャンネルへの書き方、メンバーの参加・退出・変更・BAN のログと歓迎・お別れ、メッセージの削除・編集のログ、スティッキー、リアクションロール、VC の出入りのログと通知、セキュリティの部品と VC の荒らし対策、VirusTotal によるリンクと添付の検査（メッセージの検査の流れ・読み上げ・利用者の状態の記録は別の塊で足す）。部品はライブラリ（`src/lib.rs`）に置き、イベントにつなぐ前から突き合わせとテストで呼べるようにしてある。イメージは `docker/bot-rs.Dockerfile` |
| `crates/sycs-core` | Rust のプロセスが共通で使う土台。環境変数の読み方・接続先・ログ・メトリクス・設定の読み書き・Bot への依頼の取り出し・URL の安全確認（SSRF 対策）・期限つきキャッシュ |
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
| ギルドごとの設定の読み書き | `services/settings_pg.py` / `settings_store.py` | `sycs_core::settings` | 本物の Python（settings_store）が作って書いた表を Rust が読み、Python の変更が通知で同じ瞬間に届いた。本物の Python と Rust が同じ時刻から同じギルドの数を 200 回ずつ増やして 400 になった（排他の鍵が同じ）。互いが押した「最後に触られた時刻」を読めた（Python の掃除の読み方で）。null の落とし方は 11 例で中身・鍵の並び・落とした数まで一致した。鍵・時刻の鍵・通知の名前はテストが Python のソースと突き合わせる。CI でも Postgres 16 を立てて、通知・つなぎ直し・版番号の確認・同時の書き込み・待ちの上限を毎回確かめる |
| 管理画面から Bot への依頼の取り出し | `services/dev_signals.py` | `sycs_core::signals` | Python が置いた依頼を、Rust が置いた順・畳まれた形で取り出した。ロック中の行は待たずに飛ばす（Python と Rust の Bot が並んでも二重に実行しない） |
| ログチャンネルの Embed（題・本文・色・作者・項目・時刻、上限の切り詰め、送るレベル） | `services/logging_service.py` | `sycs_bot::log_channel` | 同じ入力から Python の `build_log_embed(...).to_dict()` と Rust の Embed の JSON を作って 5 例とも一致（長い本文・作者名・項目、絵文字・結合文字）。違いは discord.py 2.7 が付ける `flags: 0` だけ（付けないのと同じ）。チャンネルは**ログのギルドの中だけ**から探す（Python はキャッシュ全体から引くので、設定に別のサーバーのチャンネルが入っていると、そこへ書いてしまう） |
| アバターの代表色（Embed の色） | colorthief 0.2.1 | `sycs_bot::colorthief` | Pillow で作った画像 16 種（透過・パレット・グレー・GIF・動く GIF・ほぼ白・全部透明など）で本物の colorthief と一致。基準の画像と答えを `apps/bot/tests/fixtures/colorthief/` に置き、CI で毎回確かめる。安定ソート・0 を偽とみなす判定・浮動小数の計算順・パレットの並びまで写してある |
| 名前・アバターの URL・mention | discord.py 2.7.1 の `str(user)`・`display_avatar.url`・`mention` | `sycs_bot::compat` | 同じ Discord の JSON を discord.py と serenity に読ませて 10 例とも一致（Bot の `#番号`・動くアバター・サーバーごとのアバター・既定のアバター）。serenity の `face()` は webp を返すが、色が変わるので使わない |
| メンバーの参加・退出・ニックネーム・ロール・タイムアウト・BAN のログ、歓迎・お別れの文面 | `events/members.py` / `services/welcome_service.py` | `sycs_bot::members` / `sycs_bot::welcome` | 同じ Discord の JSON から discord.py の Member を作って Python の処理に渡し、log_action に渡った中身（レベル・本文・項目の名前と値と順・色）と差し込みの結果が 19 例とも一致。ロールの並び（位置の低い順、同じ位置なら ID の大きい順）・作成日（ID から）・日本時間の書き方・「(なし)」「なし」「(不明)」まで。起動時に全メンバーを読み込む（discord.py の既定。読み込まないと、起動後に一度も見ていない人の退出でログもお別れも出ない） |
| メッセージの削除・編集のログ、スティッキー | `events/messages.py` / `services/sticky_service.py` | `sycs_bot::message_logs` / `message_cache` / `sticky` | 同じ Discord のメッセージの JSON から discord.py と serenity のメッセージを作り、Python の処理が log_action に渡した中身（作者の名前とアイコンまで）と 9 例とも一致。スティッキーの書き戻し・削除は本物の settings_store と 5 例とも一致。メッセージの控えは discord.py と同じく全体で直近 1000 件（DM・Bot の発言も数える。serenity のキャッシュはチャンネルごとの件数なので使わない）。Bot 自身のメッセージの削除もログに出す（Python と同じ。スティッキーを貼り直すたびに出る） |
| リアクションロール（絵文字の照合とロールの引き当て） | `services/reaction_role_service.py` | `sycs_bot::reaction_roles` | 絵文字の鍵（文字列 30 種・discord.py の PartialEmoji 5 種）とロールの引き当て（対応表 8 種・13 例）が本物の Python と 48 例とも一致。カスタム絵文字の書き方（`<:name:123>`・`<a:name:123>`・`name:123`・`123`）は Python と同じ正規表現をそのまま使う（テストが Python のソースと突き合わせる。手で書いた比べ方では全角の数字だけ答えが違った） |
| VC の出入りのログと通知（在室時間・非公開の VC の絞り込み・ロールのメンション） | `events/voice.py` | `sycs_bot::vc_notify` | 本物の Python（discord.py の権限の計算を含む）と 36 例とも一致。在室時間（移動をはさむ・2 回目の退出・ミュートだけ）・絞り込み（@everyone とロールの上書き・管理者・メンバーの上書きは数えない・ロールが無ければ止める）・壊れた設定の値（小数は切り捨て・真偽値は 1・負の数と読めない値）・Embed・10 分に 1 回のメンション |
| セキュリティの部品（スパム・VC の荒らしの判定、URL の抜き出し、文字の向きの細工、新規メンバー、バイパス、結果の Embed）と VC の荒らし対策 | `services/spam_detection.py` / `raid_detection.py` / `security_service.py` | `sycs_bot::security` | 時刻を固定した列と同じ入力で、本物の Python と 77 例とも一致（スパムは 15 秒で 4 回・荒らしは 20 秒で先頭 4 文字が同じ名前が 5 回・窓の境・URL の記号と重複・大文字の http・新規の 7 日の境と未来の参加日時・バイパスの読めない要素・判定できないものを緑にしない Embed）。バイパスの判定の失敗で措置を見送る分岐は持ち込まない（設定はメモリから引くので失敗しない） |
| URL の安全確認（SSRF 対策）と期限つきキャッシュ | `services/url_safety.py` / `ttl_cache.py` | `sycs_core::url_safety` / `ttl_cache` | 本物の Python 3.13 と 1416 例とも一致（URL の分解 67・公開アドレスの表の範囲の端と乱数 1325・名前を引く全体 6・キャッシュの操作 18）。URL の分解は Python の urlsplit と同じ決まり、公開アドレスは Python 3.13 の ipaddress の表。表の端と URL の答えは `crates/sycs-core/tests/fixtures/url_safety/` の基準で CI が毎回確かめる。ASCII 以外のホスト名は UTS46（reqwest と同じ）で、Python の IDNA2003 とまれな文字で違う |
| VirusTotal によるリンクと添付の検査 | `services/virustotal_service.py`（＋ vt-py 0.22.0 の送り方） | `sycs_bot::virustotal` | 偽物の VirusTotal と配布元を立て、本物の Python と Rust の両方を当てて 28 例とも一致（状態・種類・数・理由。画像・ページ・ファイル・既知のファイル・同時スキャン中の取り直し・回数制限・サーバーの失敗と失敗を覚える動き・上限超え〔長さあり・なし〕・相対／絶対／終わらない／行き先なし／禁止の行き先へのリダイレクト・HEAD の拒否・404・大文字の Image/PNG・種類なし・安全でない URL）。同じ流れを `apps/bot/tests/virustotal_fake.rs` が偽物をテストの中に立てて CI で毎回確かめる。解析の待ちに全体の上限が無いのは Python と同じ（見直しの候補） |
| ログのレベルの名前 | `WARNING` | `WARN` を `WARNING` と書く | 管理画面は `WARNING` で比べる。`WARN` のままだと「警告以上」で警告が全部消える |
| ログのファイル名 | `bot.log` / `bot.log.2026-11-24.gz` | 同じ | 移行中に同じディレクトリで 2 通りの名前が混ざると、片方の掃除が相手を見つけられない |

## 守ること

- **版は `=` で固定し、`Cargo.lock` をコミットする。** 依存の版は `Cargo.toml` の
  `[workspace.dependencies]` で 1 回だけ決め、各 crate は `{ workspace = true }` で受け取る。
  Rust 本体は `rust-toolchain.toml`。
- **本番の CPU は Sandy Bridge（AVX2 無し）。** ビルドは `.cargo/config.toml` で
  `target-cpu=sandybridge` に絞っている。`native` にしないこと。CI はテストも
  Sandy Bridge のふりで動かす。
- **本番のイメージは Debian 系にする。** Ubuntu 26.04 系は glibc が x86-64-v3 を要求し、
  本番では起動しない。
- **移している間、Rust の Bot は本番の compose に入れない。** 入れるのは切り替えの塊。
  手元で動かすときは `BOT_PROCESS_NAME=bot-rs` にし、本番の Python の Bot と並べるなら
  `BOT_DEV_SIGNALS_ENABLED=false`（依頼を取り合うと、Python 側に届かなくなる）。
- **本番の Bot のトークンで手元から確かめるときは `BOT_ONLY_GUILD_ID` を付ける。** 本番の Bot は
  複数のサーバーに入っているので、絞らないと他のサーバーの出入りに反応して、本番の利用者がいる
  チャンネルへ書いてしまう。本番では付けない。
- **イメージに tzdata を入れること。** 無いと `TZ=Asia/Tokyo` が効かず、ログの時刻が
  UTC になる（Python と並べて読むとずれる）。
- `unsafe` は書かない（ワークスペースで禁止してある）。公開するものには説明を書く。
- **Postgres を使うテストは `#[ignore]` を付け、CI が `--include-ignored` で必ず回す。**
  手元では `SYCS_TEST_DATABASE_URL` に Postgres を渡して回す。SQLite での代用はしない
  （LISTEN/NOTIFY と FOR UPDATE SKIP LOCKED が無く、効いているかを確かめられない）。
- 表を作るのは今は Python 側。Python を外すときに、表の作り方（マイグレーション）を Rust へ移す。
