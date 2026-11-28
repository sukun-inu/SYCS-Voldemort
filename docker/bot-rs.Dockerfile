# Rust の Bot（rust/apps/bot）のイメージ。ビルドの文脈はリポジトリの直下。
#
#   docker build -f docker/bot-rs.Dockerfile -t sycs-bot-rs .
#
# 移行中は本番の compose に入れていない（入れるのは切り替えの塊）。CI がビルドし、
# 下の cpu-check の段で、本番の CPU（Sandy Bridge）のふりで起動できることを確かめる。
#
# ■ 版
#
# ビルドの Rust は rust/rust-toolchain.toml と揃えること（そちらに揃える場所の一覧がある）。
# 動かす段は Debian 12。**Ubuntu 26.04 系にしないこと**（glibc が x86-64-v3 を要求し、
# 本番の Sandy Bridge では起動すらしない。Dockerfile の FROM の上にも同じことを書いた）。

FROM rust:1.100.0-slim-bookworm AS build
# songbird（読み上げ）を足したときに libopus が要る。今のうちから入れておき、足した日に
# ビルドの段が変わらないようにする。
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config cmake libopus-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# rust/ だけを持ち込む。.cargo/config.toml（target-cpu=sandybridge）もここに入っている。
COPY rust/ ./
RUN cargo build --release --locked -p sycs-bot

FROM debian:bookworm-slim AS runtime
# tzdata が無いと TZ=Asia/Tokyo が効かず、ログの時刻が UTC になる（Python のログと
# 並べて読むと 9 時間ずれる）。ca-certificates は Discord・Postgres・Valkey への TLS 用。
# libopus0 は読み上げの音声（songbird が Opus に符号化する。ビルドの段の libopus-dev と対）。
# fonts-noto-cjk は地震の震度の札の文字（NotoSansCJK-Bold.ttc）。Python の本番のイメージの apt と
# 同じファイル（bookworm と trixie で同じハッシュ。crates/sycs-text の tests/golden.rs が確かめる）。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata fonts-noto-cjk libopus0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sycs-bot /usr/local/bin/sycs-bot
ENV TZ=Asia/Tokyo
# いまは root で動かす。Python のコンテナ（root）と同じ app_data ボリュームへログを書くので、
# 別の利用者にすると書けない。root をやめてボリュームの持ち主を揃えるのは、切り替えの塊で扱う。
ENTRYPOINT ["/usr/local/bin/sycs-bot"]

# CI だけが使う段。動かす段と同じ中身のまま、QEMU で本番の CPU（Sandy Bridge）のふりをして
# 起動する。トークンを渡さないので「DISCORD_BOT_TOKEN が設定されていません」と出して止まる
# ところまで進めば、実行ファイル・ライブラリ・命令セットのどれも本番で起動できる。
#
# Illegal instruction で落ちると、この文言は出ない（grep が落ちてビルドが失敗する）。
FROM runtime AS cpu-check
RUN apt-get update \
    && apt-get install -y --no-install-recommends qemu-user \
    && rm -rf /var/lib/apt/lists/*
RUN qemu-x86_64 -cpu SandyBridge /usr/local/bin/sycs-bot > /tmp/out 2>&1; \
    status=$?; cat /tmp/out; echo "終了コード $status"; \
    [ "$status" = "1" ] && grep -q "DISCORD_BOT_TOKEN が設定されていません" /tmp/out
