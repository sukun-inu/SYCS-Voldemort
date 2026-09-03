#!/bin/sh
# Postgres の日次バックアップ。docker-compose.yml の postgres-backup が実行する。
#
# ■ なぜ要るか
#
# 設定・利用者状態・録音のメタデータ・金属価格と予測まで、消えると作り直せない
# ものが全部 postgres_data ボリューム1本に載っている。しかも guild_retention.py
# で「サーバーのデータを消す」機能を自分で持っているので、ボリューム破損だけで
# なく誤操作でも失われる。戻す手段が無い状態だった。
#
# ■ なぜ compose の中に直接書かず、ファイルにしたか
#
# postgres-secret-init と postgres-user-state-init は YAML の中にシェルを直接
# 書いている。あれは10行程度なので読めるが、こちらは検証と世代管理があって
# 40行を超える。YAML 内のシェルは `$$` の二重エスケープが要るうえ、構文検査に
# かけられない。ファイルにしておけば CI で `sh -n` を通せる。
#
# ■ なぜ postgres:16-alpine を使い回すか
#
# バックアップ専用イメージ（prodrigestivill/postgres-backup-local など）を使うと
# 依存が1つ増え、THIRD_PARTY_NOTICES.md への追記も要る。それより、既に取得済みの
# サーバーと同じイメージを使うほうが pg_dump の版がサーバーと必ず一致する。
# pg_dump は「サーバーより新しい」ぶんは動くが「古い」と拒否するため、ここが
# ずれると本番を上げた日にバックアップだけ静かに止まる。
set -eu

POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-metal_user}"
POSTGRES_DB="${POSTGRES_DB:-metal_prices}"
USER_STATE_POSTGRES_DB="${USER_STATE_POSTGRES_DB:-user_state_audit}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
BACKUP_HOUR_JST="${BACKUP_HOUR_JST:-4}"
BACKUP_RUN_ON_START="${BACKUP_RUN_ON_START:-if-stale}"
BACKUP_STALE_HOURS="${BACKUP_STALE_HOURS:-20}"
POSTGRES_PASSWORD_FILE="${POSTGRES_PASSWORD_FILE:-/shared/postgres_password}"
DATA_DIR="${DATA_DIR:-/app/data}"
SECRETS_DIR="${SECRETS_DIR:-/shared}"
BACKUP_FILES="${BACKUP_FILES:-true}"

STATUS_FILE="$BACKUP_DIR/status.json"

log() {
	echo "[postgres-backup] $(date '+%Y-%m-%d %H:%M:%S') $*"
}

warn() {
	echo "[postgres-backup] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

# 1つのデータベースを取る。成功したら標準出力にファイル名を返す。
#
# **この関数の中で log() を呼ばないこと。** 呼び出し側は標準出力を $( ) で
# 捕まえてファイル名として使うので、log の1行がファイル名に混ざる。進捗を
# 出したいときは warn（標準エラー）を使う。
#
# -Fc（独自形式）にしている。平文 SQL だと戻すときに「全部か無か」しか選べず、
# 1テーブルだけ戻したい場面で使えない。独自形式なら pg_restore -t で選べるうえ、
# 既定で圧縮も掛かる。
#
# --no-owner / --no-acl は付けない。付けるとダンプの側で所有者情報が落ちるので、
# 「そのまま完全に戻す」選択肢が永久に失われる。所有者を無視するかどうかは
# 戻すときに pg_restore 側で決められる（docs/BACKUP.ja.md に書いてある）。
dump_one() {
	db="$1"
	stamp="$2"
	out="$BACKUP_DIR/$db-$stamp.dump"
	part="$out.part"

	if ! pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$db" -Fc -f "$part"; then
		warn "pg_dump が失敗した: $db"
		rm -f "$part"
		return 1
	fi

	# 「取れたつもりで中身が壊れている」が、バックアップでいちばん危ない失敗。
	# 気づくのは戻そうとした当日で、そのときには元も無い。TOC が読めるかどうかを
	# ここで必ず確かめる。データの中身までは保証しないが、切り詰められたファイルと
	# 途中で落ちたダンプはこれで捕まる。
	if ! pg_restore --list "$part" >/dev/null 2>&1; then
		warn "ダンプを読み返せなかった（壊れている）: $db"
		rm -f "$part"
		return 1
	fi

	# 検証を通ってから正式な名前にする。書いている途中のファイルは .part の
	# ままなので、この関数が途中で死んでも「バックアップに見えるゴミ」は残らない。
	mv "$part" "$out"
	echo "$out"
}

# ロール（利用者と権限）だけを別に取る。
#
# データベースの中身は dump_one で取れるが、ロールはデータベースの外側にあるので
# pg_dump には入らない。空のクラスタへ戻すとき、ロールが無いと所有者を復元できない。
dump_globals() {
	stamp="$1"
	out="$BACKUP_DIR/globals-$stamp.sql"
	part="$out.part"

	if ! pg_dumpall -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" --globals-only -f "$part"; then
		warn "pg_dumpall --globals-only が失敗した"
		rm -f "$part"
		return 1
	fi
	mv "$part" "$out"
	echo "$out"
}

# Postgres に入っていない状態ファイルを取る。
#
# ■ なぜ「Postgres の」バックアップがファイルまで見るのか
#
# 消えると作り直せないものが、Postgres の外に2つある。
#
#   settings.json（app_data）  サーバーごとの設定が全部ここ。DB には無い。
#   vapid/（shared_secrets）   Push の鍵。失うと購読済みの全端末が無効になり、
#                              利用者に取り直してもらう以外に戻す道が無い。
#
# DB だけ戻せても、この2つが無ければ運用は再開できない。同じ時刻の組で
# 揃っていないと突き合わせられないので、別の仕組みに分けずここで一緒に取る。
#
# ■ 何を外すか（残すものを選ばず、外すものを選ぶ）
#
# logs/ と djaudio_cache/ だけ外す。前者は10年保持で巨大、後者は再取得できる。
# 逆に「残すものを名指しする」形にすると、あとで状態ファイルが増えたときに
# 黙ってバックアップから漏れる。増えたものは既定で入るほうが安全。
#
# postgres_password は意図的に入れていない。空のクラスタへ戻すときは新しい
# パスワードを振るので要らず、持ち出す tar に入れる意味が無いのに漏えい面だけ
# 増える。vapid の鍵は代わりが無いので、こちらは入れる（tar が秘密を含むことは
# docs/BACKUP.ja.md に明記した）。
dump_files() {
	stamp="$1"
	out="$BACKUP_DIR/files-$stamp.tar.gz"
	part="$out.part"
	stage="/tmp/files-$stamp"

	rm -rf "$stage"
	mkdir -p "$stage/data"

	# tar の --exclude ではなく find で選んでいる。busybox の tar は
	# --exclude のパターン解釈が GNU と揃っておらず、除外したつもりの
	# logs/ が入って毎日数GBのバックアップになる形の失敗をしうる。
	# find の -prune はどちらの実装でも同じ意味になる。
	(
		cd "$DATA_DIR" || exit 1
		find . -path ./logs -prune -o -path ./djaudio_cache -prune -o -type f ! -name '*.lock' -print
	) | while IFS= read -r rel; do
		mkdir -p "$stage/data/$(dirname "$rel")"
		cp -p "$DATA_DIR/$rel" "$stage/data/$rel"
	done

	if [ -d "$SECRETS_DIR/vapid" ]; then
		mkdir -p "$stage/secrets"
		cp -p "$SECRETS_DIR/vapid"/* "$stage/secrets/" 2>/dev/null || true
	fi

	if ! tar czf "$part" -C "$stage" .; then
		warn "状態ファイルの tar が失敗した"
		rm -rf "$stage"
		rm -f "$part"
		return 1
	fi
	rm -rf "$stage"

	# ダンプと同じ理由で、読み返せることまで確かめてから正式な名前にする。
	if ! tar tzf "$part" >/dev/null 2>&1; then
		warn "状態ファイルの tar を読み返せなかった（壊れている）"
		rm -f "$part"
		return 1
	fi
	mv "$part" "$out"
	echo "$out"
}

# 古い世代を消す。
#
# **成功したダンプが今回あったときだけ呼ぶこと。** 失敗が続いている間も消しに
# 行くと、最後の正常なバックアップまで保持期間で削れてしまう。「壊れてから
# 保持期間ぶん経つと、何も残っていない」が起きる。
prune_old() {
	find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.dump' -mtime "+$BACKUP_RETENTION_DAYS" -print -delete
	find "$BACKUP_DIR" -maxdepth 1 -type f -name 'globals-*.sql' -mtime "+$BACKUP_RETENTION_DAYS" -print -delete
	find "$BACKUP_DIR" -maxdepth 1 -type f -name 'files-*.tar.gz' -mtime "+$BACKUP_RETENTION_DAYS" -print -delete
	# .part は検証に落ちたときに消しているが、コンテナが kill された場合は残る。
	# 1日以上前のものは、その回のバックアップがもう終わっているので消してよい。
	find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.part' -mtime +1 -print -delete
}

# 最新のダンプが古いかどうか。起動時に取るかの判断に使う。
#
# 別に「最後に成功した時刻」のファイルを持つ作りにはしていない。実ファイルの
# 更新時刻を見れば、状態ファイルと実体がずれる余地が無い。
is_stale() {
	newest="$(ls -t "$BACKUP_DIR"/*.dump 2>/dev/null | head -n 1)" || true
	[ -n "$newest" ] || return 0
	age=$(($(date +%s) - $(date -r "$newest" +%s)))
	[ "$age" -ge $((BACKUP_STALE_HOURS * 3600)) ]
}

# 次の実行時刻までの秒数。
#
# `date +%H` を使っていない。0 埋めされた "08" "09" が算術展開で8進数として
# 扱われ、朝8時台と9時台だけシェルが落ちる（dash と bash の両方で再現する。
# 前者は Illegal number、後者は value too great for base）。エポック秒に固定の
# 時差を足して剰余を取れば、この罠を踏まずに済む。JST は夏時間が無いので
# +9時間の固定で常に正しい。
seconds_until_target() {
	now="$(date +%s)"
	elapsed_today=$(((now + 32400) % 86400))
	target=$((BACKUP_HOUR_JST * 3600))
	wait=$((target - elapsed_today))
	[ "$wait" -gt 0 ] || wait=$((wait + 86400))
	echo "$wait"
}

# status.json を書く。Netdata と管理画面がここを読んで「最後に成功した時刻」を
# 見るので、失敗したときも last_error を入れて必ず書く（書かないと、古い成功が
# そのまま残って「まだ生きている」ように見える）。
write_status() {
	result="$1"
	error="$2"
	files="$3"
	tmp="$STATUS_FILE.part"
	{
		echo '{'
		echo "  \"result\": \"$result\","
		echo "  \"finished_at\": \"$(date '+%Y-%m-%dT%H:%M:%S%z')\","
		echo "  \"finished_at_epoch\": $(date +%s),"
		echo "  \"retention_days\": $BACKUP_RETENTION_DAYS,"
		echo "  \"error\": \"$error\","
		echo "  \"files\": [$files]"
		echo '}'
	} >"$tmp"
	mv "$tmp" "$STATUS_FILE"
}

# ファイル1件を status.json の files 要素にする。JSON を組み立てるのに使える
# 道具（jq）がイメージに入っていないので、必要な2項目だけを手で組む。
# データベース名は compose 側で [A-Za-z0-9_] に制限済みなので、これで壊れない。
status_entry() {
	path="$1"
	printf '{"name": "%s", "bytes": %s}' "$(basename "$path")" "$(wc -c <"$path" | tr -d ' ')"
}

run_backup() {
	stamp="$(date '+%Y%m%d-%H%M%S')"
	log "バックアップを開始する（$stamp）"

	entries=""
	failed=""

	for db in "$POSTGRES_DB" "$USER_STATE_POSTGRES_DB"; do
		if path="$(dump_one "$db" "$stamp")"; then
			log "取得した: $(basename "$path")"
			[ -z "$entries" ] || entries="$entries, "
			entries="$entries$(status_entry "$path")"
		else
			failed="$failed $db"
		fi
	done

	if path="$(dump_globals "$stamp")"; then
		log "取得した: $(basename "$path")"
		[ -z "$entries" ] || entries="$entries, "
		entries="$entries$(status_entry "$path")"
	else
		failed="$failed globals"
	fi

	if [ "$BACKUP_FILES" = "true" ]; then
		if path="$(dump_files "$stamp")"; then
			log "取得した: $(basename "$path")"
			[ -z "$entries" ] || entries="$entries, "
			entries="$entries$(status_entry "$path")"
		else
			failed="$failed files"
		fi
	fi

	if [ -n "$failed" ]; then
		warn "失敗したものがある:$failed"
		write_status "error" "failed:$failed" "$entries"
		return 1
	fi

	prune_old
	write_status "ok" "" "$entries"
	log "バックアップを完了した"
}

main() {
	if [ ! -s "$POSTGRES_PASSWORD_FILE" ]; then
		warn "パスワードファイルが空か存在しない: $POSTGRES_PASSWORD_FILE"
		exit 1
	fi
	PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"
	export PGPASSWORD

	mkdir -p "$BACKUP_DIR"
	log "保存先 $BACKUP_DIR / 毎日 ${BACKUP_HOUR_JST}時（JST）/ ${BACKUP_RETENTION_DAYS}日保持"

	# マウントを忘れた場合に黙って DB だけのバックアップにならないようにする。
	# 「バックアップは取れている」と思っている状態でこれが欠けているのが最悪なので、
	# 気づけるように毎回警告を出す。ただし DB のほうは止めない。
	if [ "$BACKUP_FILES" = "true" ] && [ ! -d "$DATA_DIR" ]; then
		warn "DATA_DIR が見つからない: $DATA_DIR（settings.json が保護されない。compose のマウントを確認すること）"
		BACKUP_FILES="false"
	fi

	case "$BACKUP_RUN_ON_START" in
	always)
		run_backup || true
		;;
	never)
		log "起動時のバックアップは行わない（BACKUP_RUN_ON_START=never）"
		;;
	*)
		# 既定。コンテナが何度も再起動する状況でダンプが連続して走るのを避けつつ、
		# 長く止まっていたあとは必ず1本取る。
		if is_stale; then
			log "最新のダンプが ${BACKUP_STALE_HOURS} 時間より古いので、起動時に1本取る"
			run_backup || true
		else
			log "最新のダンプが十分新しいので、起動時のバックアップは省略する"
		fi
		;;
	esac

	while :; do
		wait="$(seconds_until_target)"
		log "次のバックアップまで ${wait} 秒待つ"
		sleep "$wait"
		# 失敗しても抜けない。restart: unless-stopped と組み合わせると、抜けた
		# 瞬間に再起動して数秒おきにダンプを試し続ける形になり、Postgres に
		# 負荷を掛けたうえログが埋まって原因が見えなくなる。失敗は status.json に
		# 残し、次の時刻まで待って取り直す。
		run_backup || true
	done
}

main "$@"
