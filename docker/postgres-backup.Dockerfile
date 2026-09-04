# postgres-backup サービスのイメージ。中身は docker/postgres-backup.sh。
#
# ■ なぜイメージに焼くのか（以前はホストのファイルをバインドマウントしていた）
#
# 2026-09-04、本番でこのコンテナが18回再起動し続けていた。compose に
#     - ./docker/postgres-backup.sh:/usr/local/bin/postgres-backup.sh:ro
# と書いていて、デプロイ先にそのファイルが無かったのが原因。**Docker はバインド
# 元が存在しないとき、そこに空のディレクトリを作って黙ってマウントする。**
# busybox の ash はディレクトリを渡されると何も実行せず exit 0 で終わるので、
#
#   - ログが1行も出ない（スクリプトの1行目すら動いていない）
#   - 終了コードが 0（restart: unless-stopped は 0 でも再起動する）
#   - status.json が書かれないので sycs_backup_age_seconds が「古い」ではなく
#     「そもそも出ない」状態になり、閾値のアラートにも掛からない
#
# という、どこからも見えない形で止まっていた。バックアップが一度も取れて
# いないことに気づく手段が無かった。
#
# COPY にすれば、ファイルが無いときはビルドが落ちる。再デプロイのたびに
# その時点のスクリプトが必ず入るので、ホスト側に何が置いてあるかに依存しない。
#
# ■ なぜ postgres:16-alpine を土台にするか
#
# docker/postgres-backup.sh の冒頭に書いた通り、pg_dump の版をサーバーと必ず
# 一致させるため。pg_dump は「サーバーより新しい」ぶんは動くが「古い」と拒否
# するので、ここがずれると本番の Postgres を上げた日にバックアップだけが
# 静かに止まる。**土台の版は docker-compose.yml の postgres と揃えること。**
FROM postgres:16-alpine

COPY docker/postgres-backup.sh /usr/local/bin/postgres-backup.sh

# 土台の entrypoint（docker-entrypoint.sh）は「サーバーを起動する」ための
# ものなので、command だけ差し替えても意図通りにならない。
ENTRYPOINT ["/bin/sh", "/usr/local/bin/postgres-backup.sh"]

# **空にしておくこと。** 土台が CMD ["postgres"] を持っているため、消さないと
# ENTRYPOINT の引数として渡り、main が "postgres" を受け取る。今の main は
# 引数を見ないので実害は無いが、見るようにした日に静かに壊れる。
CMD []
