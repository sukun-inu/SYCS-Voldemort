# バックアップと復元

[← README.ja.md に戻る](../README.ja.md)

`docker-compose.yml` の `postgres-backup` が毎日 4 時（JST）に取ります。中身は
[`docker/postgres-backup.sh`](../docker/postgres-backup.sh) で、なぜその作りに
したかはスクリプトのコメントに書いてあります。

**戻したことがない手順は、戻せる手順ではありません。** 4. の復元リハーサルを
一度通してから、この文書を信用してください。

---

## 1. 何が入っていて、何が入っていないか

1 回の実行で 4 ファイルできます。

| ファイル | 中身 | 無いと何が困るか |
|---|---|---|
| `metal_prices-<日時>.dump` | 本体 DB（金属価格・予測・Push 購読） | 価格履歴と予測を作り直せない。購読者一覧が消える |
| `user_state_audit-<日時>.dump` | 利用者状態の監査 DB | 参加履歴・ロール変遷の記録が消える |
| `globals-<日時>.sql` | ロール（利用者と権限） | 空のクラスタへ戻すときに所有者を復元できない |
| `files-<日時>.tar.gz` | `settings.json` と VAPID の鍵 | **サーバーごとの設定が全部消える。Push は購読者全員に取り直してもらう以外に戻す道が無い** |

4 番目が要る理由は、`settings.json` が Postgres ではなく `app_data` ボリューム、
VAPID の鍵が `shared_secrets` ボリュームに置かれているからです。DB だけ戻しても
運用は再開できません。

**入っていないもの**（意図的に外しています）

| 外したもの | 理由 |
|---|---|
| `logs/` | 保持 10 年で巨大。消えても運用は続けられる |
| `djaudio_cache/` | 再取得できる |
| `postgres_password` | 空のクラスタへ戻すときは新しいものを振るので要らない。持ち出す tar に秘密を増やすだけになる |
| 録音した音声 | そもそも永続化していない（`/tmp` に書いて Discord へ送ったら捨てる） |

> **`files-*.tar.gz` には VAPID の秘密鍵が入ります。** ホストの外へ持ち出すときは、
> それを踏まえた置き場所にしてください。

---

## 2. 今の状態を見る

```bash
# 一覧（新しい順）
docker compose exec postgres-backup ls -lht /backups

# 最後の実行がどうだったか
docker compose exec postgres-backup cat /backups/status.json
```

`status.json` の `result` が `error` なら `error` に失敗したものの名前が入って
います。`finished_at_epoch` は Netdata が `sycs_backup_age_seconds` として読み、
「48 時間バックアップが取れていない」で鳴らせるようにするために置いてあります
（[docs/MONITORING.ja.md](MONITORING.ja.md)）。

失敗した回でも、**成功したファイルはそのまま残ります。** 3 つ取れて 1 つ落ちた
なら、その 3 つは使えます。`status.json` の `files` に入っているものが、その回に
検証まで通ったものです。

---

## 3. 戻す

### 3.1 データベースを 1 つ丸ごと戻す

書き込む側を止めてから戻します。止めずに戻すと、復元中の中途半端な状態を
Bot と Web が読みます。

```bash
# 1. 書き込む側だけ止める（postgres と postgres-backup は動かしたまま）
docker compose stop sycs-voldemort sycs-voldemort-admin sycs-voldemort-web

# 2. 戻す（ファイル名は 2. の一覧から選ぶ）
docker compose exec postgres-backup sh -c '
  export PGPASSWORD="$(cat /shared/postgres_password)"
  pg_restore -h postgres -U metal_user -d metal_prices \
    --clean --if-exists --no-owner --single-transaction \
    /backups/metal_prices-20260904-040000.dump'

# 3. 起こす
docker compose start sycs-voldemort sycs-voldemort-admin sycs-voldemort-web
```

各オプションの意味です。

| オプション | なぜ付けるか |
|---|---|
| `--clean --if-exists` | 既存のテーブルを落としてから入れ直す。付けないと既存の行が残ったまま重なる |
| `--single-transaction` | 途中で失敗したときに何も適用されない状態で終わる。**これが無いと「半分戻った DB」ができ、元の状態にも復元後の状態にもならない** |
| `--no-owner` | ダンプ時の所有者を無視して、今の接続ユーザーのものにする。所有者ごと完全に戻したいときだけ外す |

`--single-transaction` と `-j`（並列復元）は同時に使えません。速さより「失敗して
も壊れない」を取っています。

### 3.2 `settings.json` と VAPID の鍵を戻す

```bash
# 中身を確認してから
docker compose exec postgres-backup tar tzf /backups/files-20260904-040000.tar.gz

# 取り出す（コンテナ内の /tmp へ展開して、必要なものだけ写す）
docker compose stop sycs-voldemort sycs-voldemort-admin sycs-voldemort-web
docker compose exec postgres-backup sh -c '
  rm -rf /tmp/restore && mkdir -p /tmp/restore
  tar xzf /backups/files-20260904-040000.tar.gz -C /tmp/restore
  ls -R /tmp/restore'
```

`postgres-backup` は `app_data` を**読み取り専用**でマウントしているので、ここから
直接は書き戻せません（バックアップを取る側が本番を壊せないようにしています）。
書き戻しは、書ける側のコンテナから行います。

```bash
# 展開したものをホストへ出す
docker compose cp postgres-backup:/tmp/restore ./restore

# settings.json を書ける側へ入れる
docker compose cp ./restore/data/settings.json sycs-voldemort-admin:/app/data/settings.json

# VAPID の鍵（web が shared_secrets を書ける側で持っている）
docker compose cp ./restore/secrets/private_key.pem sycs-voldemort-web:/shared/vapid/private_key.pem
docker compose cp ./restore/secrets/public_key.txt  sycs-voldemort-web:/shared/vapid/public_key.txt

docker compose start sycs-voldemort sycs-voldemort-admin sycs-voldemort-web
rm -rf ./restore   # 秘密鍵が入っているので消す
```

### 3.3 まっさらなホストへ全部戻す

持ち出した tar（5. の手順で作ったもの）が手元にある前提です。

```bash
# 1. リポジトリと .env を用意し、DB とバックアップ用コンテナだけ先に起こす。
#    この時点で postgres は空、user_state_audit は init コンテナが作る。
docker compose up -d postgres postgres-backup

# 2. 持ち出した tar を postgres_backups ボリュームへ戻す
docker run --rm \
  -v sycs-voldemort_postgres_backups:/backups \
  -v "$PWD:/in:ro" \
  alpine:3.21 \
  tar xzf /in/sycs-backups-20260904.tar.gz -C /backups

# 3. ロールを入れる。既にあるロールについては "already exists" が出るが、
#    このファイルは CREATE ROLE の羅列なので、その行だけ飛ばされて問題ない。
docker compose exec postgres-backup sh -c '
  export PGPASSWORD="$(cat /shared/postgres_password)"
  psql -h postgres -U metal_user -d postgres \
    -f "$(ls -t /backups/globals-*.sql | head -n 1)"'

# 4. 中身を戻す。metal_prices と user_state_audit は image と init コンテナが
#    作っているので createdb は要らない（3.1 と同じコマンド）。
docker compose exec postgres-backup sh -c '
  export PGPASSWORD="$(cat /shared/postgres_password)"
  for db in metal_prices user_state_audit; do
    f="$(ls -t /backups/$db-*.dump | head -n 1)"
    echo "戻す: $f"
    pg_restore -h postgres -U metal_user -d "$db" \
      --clean --if-exists --no-owner --single-transaction "$f"
  done'

# 5. settings.json と VAPID の鍵を戻す（3.2 の手順）。ここを飛ばすと、
#    DB は戻ったのにサーバーごとの設定が全部初期状態になる。

# 6. 残りを起こす
docker compose up -d
```

---

## 4. 復元リハーサル（**これを一度やること**）

本番を触らずに「戻せる」ことを確かめます。使い捨ての DB へ復元して、行数を
突き合わせます。

```bash
docker compose exec postgres-backup sh -c '
  set -eu
  export PGPASSWORD="$(cat /shared/postgres_password)"
  LATEST="$(ls -t /backups/metal_prices-*.dump | head -n 1)"
  echo "検証するファイル: $LATEST"

  dropdb -h postgres -U metal_user --if-exists restore_test
  createdb -h postgres -U metal_user restore_test
  pg_restore -h postgres -U metal_user -d restore_test --no-owner "$LATEST"

  echo "--- 本番 ---"
  psql -h postgres -U metal_user -d metal_prices -c "
    SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY relname;"
  echo "--- 復元したもの ---"
  psql -h postgres -U metal_user -d restore_test -c "
    SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY relname;"

  dropdb -h postgres -U metal_user restore_test'
```

テーブルの並びと行数が概ね一致すれば復元できています（バックアップを取った時刻
以降に増えた行のぶんはずれます）。

`pg_stat_user_tables.n_live_tup` は統計情報なので概数です。厳密に数えたいときは
`ANALYZE` してから、あるいは主要なテーブルを `SELECT count(*)` で突き合わせて
ください。

---

## 5. ホストの外へ持ち出す

**同じディスクにしか無いバックアップは、ディスクが死んだ日に一緒に死にます。**
`postgres_backups` ボリュームはホスト内にあるので、これだけでは足りません。

```bash
# ボリューム名を確認する（compose のプロジェクト名が前に付く）
docker volume ls | grep postgres_backups

# tar にして手元へ出す
docker run --rm \
  -v sycs-voldemort_postgres_backups:/backups:ro \
  -v "$PWD:/out" \
  alpine:3.21 \
  tar czf "/out/sycs-backups-$(date +%Y%m%d).tar.gz" -C /backups .
```

これを Tailscale 越しの別ホストか、外部のストレージへ置いてください。持ち出す
tar には VAPID の秘密鍵が入っています（1. 参照）。

---

## 6. 設定

`.env` で変えられます。既定のままで運用できます。

| 変数 | 既定 | 意味 |
|---|---|---|
| `BACKUP_HOUR_JST` | `4` | 毎日この時刻（JST）に取る |
| `BACKUP_RETENTION_DAYS` | `14` | これより古い世代を消す。**消すのは、その回のバックアップが成功したときだけ**（失敗が続く間に最後の正常なバックアップまで削らないため） |
| `BACKUP_RUN_ON_START` | `if-stale` | `always` は起動ごとに取る。`never` は取らない。`if-stale` は最新が `BACKUP_STALE_HOURS` より古いときだけ取る |
| `BACKUP_STALE_HOURS` | `20` | `if-stale` の判定に使う |
| `BACKUP_FILES` | `true` | `settings.json` と VAPID の鍵も取るか |
