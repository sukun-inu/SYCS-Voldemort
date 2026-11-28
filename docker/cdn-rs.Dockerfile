# Rust の配信（rust/apps/cdn。/dlaudio/）のイメージ。ビルドの文脈はリポジトリの直下。
#
#   docker build -f docker/cdn-rs.Dockerfile -t sycs-cdn-rs .
#
# CI がビルドし、下の cpu-check の段で本番の CPU（Sandy Bridge）のふりをして起動し、自分に 1 回尋ねられることを
# 確かめ、nginx とつないで確かめてから（docker/nginx/smoke.sh）、main の版を GHCR
# （ghcr.io/<持ち主>/sycs-voldemort-cdn-rs）に置く（.github/workflows/rust.yml）。本番はそれを取ってくるだけで、
# 本番のサーバーでは Rust をコンパイルしない。compose では profile nginx のときだけ起動する（docs/UPGRADE.ja.md の 6.）。
#
# ■ 版
#
# ビルドの Rust は rust/rust-toolchain.toml と揃えること。動かす段は Debian 12（Bot と同じ。Ubuntu 26.04 系は glibc が
# x86-64-v3 を要求し、本番の Sandy Bridge では起動しない）。

FROM rust:1.100.0-slim-bookworm AS build
WORKDIR /src
# rust/ だけを持ち込む。.cargo/config.toml（target-cpu=sandybridge）もここに入っている。
COPY rust/ ./
RUN cargo build --release --locked -p sycs-cdn

FROM debian:bookworm-slim AS runtime
# tzdata が無いと TZ=Asia/Tokyo が効かず、ログの時刻が UTC になる（Python のログと並べて読むとずれる）。
# ca-certificates は Valkey への TLS を使うときのため（いまは使っていない）。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sycs-cdn /usr/local/bin/sycs-cdn
ENV TZ=Asia/Tokyo
EXPOSE 5002
# いまは root で動かす。Bot（root）と同じ app_data ボリュームの置き場を消し（期限切れ）、ログを書くので、
# 別の利用者にすると書けない（Bot の Rust のイメージと同じ）。
ENTRYPOINT ["/usr/local/bin/sycs-cdn"]

# CI だけが使う段。動かす段と同じ中身のまま、QEMU で本番の CPU（Sandy Bridge）のふりをして、待ち受けて自分に
# 尋ねるところまで通す（--self-check）。Illegal instruction で落ちると、この文言は出ない（grep が落ちて失敗する）。
FROM runtime AS cpu-check
RUN apt-get update \
    && apt-get install -y --no-install-recommends qemu-user \
    && rm -rf /var/lib/apt/lists/*
RUN qemu-x86_64 -cpu SandyBridge /usr/local/bin/sycs-cdn --self-check > /tmp/out 2>&1; \
    status=$?; cat /tmp/out; echo "終了コード $status"; \
    [ "$status" = "0" ] && grep -q "配信の確かめ: 応答を受け取りました" /tmp/out

# 何も指定せずにビルドしたとき（compose で作り直すとき）はこの段になる。中身は動かす段そのもの。
FROM runtime AS final
