#!/bin/sh
# 偽物の yt-dlp（DJAudio の基準を作るときと、Rust のテストの両方が使う）。
#
# 置き場（このスクリプトの 1 つ上のディレクトリ）の steps/<何回目>/ の台本どおりに動く:
#   out/    … -o の置き場へ写すファイル
#   stderr  … 標準エラーに書く文
#   exit    … 終了コード（無ければ 0）
# 呼ばれた引数は、1 つ 1 行で args.log に書き足す（呼び出しの区切りは ----）。
plan=$(dirname "$0")/..
count=$(cat "$plan/count" 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > "$plan/count"
for a in "$@"; do
	printf '%s\n' "$a" >> "$plan/args.log"
done
printf '%s\n' '----' >> "$plan/args.log"
out=""
prev=""
for a in "$@"; do
	if [ "$prev" = "-o" ]; then
		out="$a"
	fi
	prev="$a"
done
step="$plan/steps/$count"
if [ -d "$step/out" ]; then
	cp -R "$step/out/." "$(dirname "$out")/"
fi
if [ -f "$step/stderr" ]; then
	cat "$step/stderr" >&2
fi
exit "$(cat "$step/exit" 2>/dev/null || echo 0)"
