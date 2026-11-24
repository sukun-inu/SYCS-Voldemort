#!/bin/sh
# voice-check を Docker でビルドして起動する（手元の WSL などから）。
#
#   sh rust/tools/voice-check/run.sh [設定ファイル]
#
# 設定ファイル（既定 $HOME/.sycs-voice-check.env）には次の 2 行を書く。
#   DISCORD_BOT_TOKEN=<試験用アプリのトークン>
#   TEST_GUILD_ID=<試験用サーバーの ID>
#
# トークンをコマンドラインや環境変数で渡さず、ファイルから --env-file で読む。
# コマンドラインに書くと、シェルの履歴と ps の出力に残るため。
#
# ビルドには本番の Rust と同じ版を使う（rust/rust-toolchain.toml と揃えること）。
# 取ってきた依存とビルド結果は Docker のボリュームに残し、2 回目以降を速くする。
# 止めるときは Ctrl+C か `docker rm -f sycs-voice-check`。
set -eu

ENV_FILE="${1:-$HOME/.sycs-voice-check.env}"
IMAGE="rust:1.100.0-slim-bookworm"
RUST_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ ! -s "$ENV_FILE" ]; then
	echo "$ENV_FILE がありません。次の 2 行を書いて保存してください:" >&2
	echo "  DISCORD_BOT_TOKEN=<試験用アプリのトークン>" >&2
	echo "  TEST_GUILD_ID=<試験用サーバーの ID>" >&2
	exit 1
fi
chmod 600 "$ENV_FILE"

docker run --rm \
	-v "$RUST_DIR":/src:ro \
	-v sycs-voice-check-cargo:/usr/local/cargo/registry \
	-v sycs-voice-check-target:/target \
	-e CARGO_TARGET_DIR=/target \
	"$IMAGE" sh -c '
		set -e
		apt-get update -qq >/dev/null
		apt-get install -y -qq --no-install-recommends pkg-config cmake libopus-dev >/dev/null
		cd /src && cargo build --release --locked -p voice-check
	'

docker rm -f sycs-voice-check >/dev/null 2>&1 || true
exec docker run --rm --name sycs-voice-check \
	--env-file "$ENV_FILE" \
	-v sycs-voice-check-target:/target:ro \
	"$IMAGE" sh -c '
		apt-get update -qq >/dev/null
		apt-get install -y -qq --no-install-recommends libopus0 ca-certificates >/dev/null
		exec /target/release/voice-check
	'
