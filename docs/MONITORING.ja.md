# 監視（Netdata）

[← README.ja.md に戻る](../README.ja.md)

ホストの Netdata が管理画面の `/metrics` を読みます。CPU・メモリ・ディスク・
ネットワークは Netdata が自分で測るので、こちらからは**アプリしか知らないこと**
だけを出します。

---

## 1. なぜ 1 つのエンドポイントに集めているか

アプリは 3 つのプロセスで動き、`web` は既定で 2 ワーカーです。素直に作ると各
プロセスが自分の `/metrics` を出すことになりますが、それだと 2 つ困ります。

- **web は同じポートを複数プロセスで受けるので、スクレイプがワーカー 1 個にしか
  当たりません。** どのワーカーに当たるかは毎回変わるため、カウンタなのに値が
  上下するという、いちばん読みにくい壊れ方をします
- bot は HTTP サーバーを持っていません

そのため全プロセスが Valkey へ書き、管理画面の `/metrics` が読んで出します。
スクレイプ先は 1 つで、ワーカー数にも依存しません。

```
bot ──┐
web ──┼──> Valkey ──> 管理画面 /metrics ──> Netdata（ホスト）
admin ┘
```

**`ADMIN_WORKERS` は 1 のままにしてください。** `/metrics` は管理画面のプロセスから
出るので、2 以上にするとスクレイプがワーカー 1 個にしか当たらなくなります
（Valkey に集めた値はどのワーカーからでも同じに見えますが、
`sycs_admin_request_tps` だけはそのワーカーぶんになります）。

---

## 2. 設定（ホスト側で 1 回）

```bash
# 既に /etc/netdata/go.d/prometheus.conf がある場合は、jobs: の中身だけを足す。
# 丸ごと置き換えると他の収集対象の設定が消える。
sudo cp docker/netdata-go.d-prometheus.conf /etc/netdata/go.d/prometheus.conf
sudo systemctl restart netdata
```

読めているかを確かめます。

```bash
sudo -u netdata /usr/libexec/netdata/plugins.d/go.d.plugin -d -m prometheus
```

`sycs_up` が出れば成功です。`403` が返る場合は 5. を見てください。

---

## 3. 何が出るか

| メトリクス | 種別 | 意味 |
|---|---|---|
| `sycs_up{app}` | gauge | **1 なら報告が届いている、0 なら止まっている** |
| `sycs_heartbeat_age_seconds{app}` | gauge | 最後の報告からの経過秒数 |
| `sycs_shared_cache_available` | gauge | Valkey へ書き読みできているか |
| `sycs_backup_status` | gauge | **1 なら最後のバックアップが成功、0 ならそれ以外**（失敗・1 度も動いていない・状態ファイルが読めない）。バックアップを見る構成でだけ出る |
| `sycs_backup_age_seconds` | gauge | 最後に**成功した**バックアップからの経過秒数。`sycs_backup_status == 1` のときだけ出る |
| `sycs_exceptions_total{app,type}` | counter | 未捕捉例外の型ごとの累積 |
| `sycs_http_responses_total{app,code}` | counter | 応答コードごとの累積 |
| `sycs_requests_total{app}` | counter | リクエストの累積 |
| `sycs_admin_request_tps` | gauge | 管理画面の秒間リクエスト数 |
| `sycs_bot_guilds` | gauge | 参加サーバー数 |
| `sycs_bot_members_visible` | gauge | 見えている人数 |
| `sycs_bot_voice_clients` | gauge | 声の接続数 |
| `sycs_bot_gateway_latency_seconds` | gauge | Discord ゲートウェイまでの往復（秒） |
| `sycs_web_cache_items_*` | gauge | ワーカーごとの一次キャッシュ件数 |

`app` に入る値は `bot`、`admin`、`web-<PID>` です。web はワーカーごとに別系列に
なるので、どのワーカーが落ちたかが分かります。

### 生存を「消える」ではなく 0 で表している理由

死んだプロセスの `sycs_up` は 0 になります。系列が消える形にすると、Netdata 側で
「無くなったこと」を条件に書く必要があり、値を見るより難しくなります。そのため
心拍の時刻には期限を付けず、読むときに現在時刻との差から 0/1 を決めています。

`sycs_up` が 0 になるのは、心拍が `METRICS_STALE_AFTER_SECONDS`（既定 90 秒）
より古くなったときです。報告間隔は既定 30 秒なので、3 回続けて報告できなければ
落ちたと判断されます。

---

## 4. 立てておきたいアラーム

Netdata 側（`/etc/netdata/health.d/` か Netdata Cloud）で設定します。最低この 3 つを
勧めます。

| 条件 | なぜ |
|---|---|
| `sycs_up == 0` が 2 分続く | プロセスが死んでいる。**これが無いと、落ちたことに誰も気づかない** |
| `sycs_backup_status == 0` が 48 時間続く | バックアップが取れていない。**`sycs_backup_age_seconds` ではなくこちらで鳴らすこと**（下記） |
| `sycs_exceptions_total` の増加 | 例外が出ている。今までログファイルに埋もれていて誰も見ていなかった |

**バックアップは `sycs_backup_status` で見ます。** `sycs_backup_age_seconds` は
成功した回があるときしか出ないので、1 度も成功していない間は「値が大きい」では
なく**系列が存在しない**状態になり、閾値の条件が成立しません。2026-09-04 に
バックアップのコンテナが exit 0 で 18 回再起動し続けたのを誰も検知できなかった
のがこれです。`sycs_backup_status` は 0 か 1 が必ず出るので、欠測そのものを
捕まえられます。

`sycs_shared_cache_available == 0` も見る価値があります。0 の間はキャッシュが
ワーカーごとに分かれ、レート制限も緩くなりますが、**アプリは動き続けます**
（[docs/SETUP.ja.md](SETUP.ja.md) の Valkey の項）。急ぎではありません。

---

## 5. 読めないとき

### 403 が返る

`/metrics` には認証がありません。代わりに接続元 IP で絞っています
（Netdata はログインできないため）。

**転送ヘッダ（`X-Forwarded-For` など）は一切見ていません。** 見ると、ヘッダを 1 つ
付けてリクエストするだけで誰でもアプリの内部状態を読めるようになります。見ているのは
TCP の接続元だけです。

許可範囲は `METRICS_ALLOWED_CIDRS`（既定 `127.0.0.1/32,::1/128,172.16.0.0/12`）。
Netdata はホスト上で動き、公開ポート経由で来るので、コンテナから見た接続元は
Docker のブリッジのゲートウェイになります。既定がそれを含んでいるのはこのためです。

実際の接続元を確かめます。

```bash
docker compose logs sycs-voldemort-admin | grep metrics
```

### 本文が `sycs_shared_cache_available 0` だけになる

Valkey へ繋がっていません。それ以外のメトリクスは Valkey 経由なので出なくなります。
**この 1 行が出ること自体に意味があります** ——「Valkey が落ちてメトリクスが空に
なった」のか「本当に静かだった」のかを区別するための行です。

```bash
docker compose ps valkey
docker compose logs sycs-voldemort-web | grep 共有キャッシュ
```

### `sycs_up{app="bot"}` だけ出ない

bot の報告ループ（`events/background_tasks.py` の `metrics_task`）が回っていません。
`on_ready` で起動されるので、Discord へ接続できていない場合も出ません。

```bash
docker compose logs sycs-voldemort | tail -30
```

---

## 6. 設定

| 変数 | 既定 | 意味 |
|---|---|---|
| `METRICS_ALLOWED_CIDRS` | `127.0.0.1/32,::1/128,172.16.0.0/12` | `/metrics` を読める接続元 |
| `METRICS_REPORT_INTERVAL_SECONDS` | `30` | 各プロセスが報告する間隔 |
| `METRICS_STALE_AFTER_SECONDS` | `90` | これより古い心拍は `sycs_up=0`。報告間隔の 3 倍が目安 |
| `METRICS_GAUGE_TTL_SECONDS` | `120` | ゲージの寿命。過ぎると系列が消える |
| `METRICS_PATH` | `/metrics` | 公開パス |
| `BACKUP_STATUS_FILE` | `/backups/status.json` | `sycs_backup_status` と `sycs_backup_age_seconds` の元。**置き場のディレクトリが無いときは、どちらも出さない**（バックアップを見ない構成で鳴らしようのないアラートを作らないため） |
