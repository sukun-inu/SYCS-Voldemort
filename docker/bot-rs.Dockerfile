# Rust の Bot（rust/apps/bot）のイメージ。ビルドの文脈はリポジトリの直下。
#
#   docker build -f docker/bot-rs.Dockerfile -t sycs-bot-rs .
#
# 本番の compose では、Bot のサービス（sycs-voldemort）が BOT_DOCKERFILE でこのファイルを選んだときだけ使う
# （既定は Python の Dockerfile。切り替えと戻し方は docs/UPGRADE.ja.md の 5.）。CI がビルドし、下の cpu-check の
# 段で、本番の CPU（Sandy Bridge）のふりで起動できることを確かめる。
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
# ffmpeg は DJAudio（yt-dlp が MP3 に変換し、カバー画像とメタデータを埋め込む）。Python のイメージと同じく apt のもの。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata fonts-noto-cjk libopus0 ffmpeg \
    && rm -rf /var/lib/apt/lists/*
# yt-dlp は DJAudio が URL を落とすのに使う。Python のイメージと同じく、イメージを作るときの最新の GitHub の
# リリース（動画サイトの変更に追いつくため、版は固定しない）。Python のイメージは Python で動く zipapp
# （`yt-dlp`）を入れているが、ここには Python が無いので、Python ごと固めた実行ファイル（`yt-dlp_linux`）にする。
ADD --chmod=0755 https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_linux /usr/local/bin/yt-dlp
# deno は、yt-dlp が YouTube の問題（署名・n パラメータ）を解くのに使う JavaScript の実行環境。無いと yt-dlp は
# YouTube を非推奨の取り方で取り、形式が欠けることがある（その警告は --no-warnings で出ない）。yt-dlp は PATH の
# deno を自分で見つける（解く部品の yt_dlp_ejs は yt-dlp_linux に入っている）。yt-dlp と同じく最新にする。
COPY --from=denoland/deno:bin /deno /usr/local/bin/deno
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
# DJAudio の yt-dlp・ffmpeg・deno も、本番の CPU で動くこと（版を出せれば動いている。deno は JavaScript を
# 実際に走らせる）。yt-dlp が deno を見つけられることも確かめる（JS runtimes に deno が出る）。
RUN qemu-x86_64 -cpu SandyBridge /usr/local/bin/yt-dlp --version \
    && qemu-x86_64 -cpu SandyBridge /usr/bin/ffmpeg -hide_banner -version | head -1 \
    && qemu-x86_64 -cpu SandyBridge /usr/local/bin/deno eval 'console.log("deno", 1 + 1)' \
    && /usr/local/bin/yt-dlp -v 2>&1 | grep "JS runtimes: deno"
RUN qemu-x86_64 -cpu SandyBridge /usr/local/bin/sycs-bot > /tmp/out 2>&1; \
    status=$?; cat /tmp/out; echo "終了コード $status"; \
    [ "$status" = "1" ] && grep -q "DISCORD_BOT_TOKEN が設定されていません" /tmp/out

# 何も指定せずにビルドしたとき（本番の compose が BOT_DOCKERFILE でこのファイルを選んだとき）は、この段になる。
# 中身は動かす段（runtime）そのもの。最後の段がビルドの既定なので、CI だけの段（cpu-check。qemu-user 入り）が
# 本番のイメージにならないよう、最後に置き直す。
FROM runtime AS final
