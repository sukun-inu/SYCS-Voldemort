# 管理画面（5001）・Web（8000）・配信（/dlaudio/）の前に立つ nginx のイメージ。ビルドの文脈はリポジトリの直下。
#
#   docker build -f docker/nginx/Dockerfile -t sycs-nginx .
#
# CI がビルドし、下の cpu-check の段で本番の CPU（Sandy Bridge）のふりをして設定を読ませ、つないで確かめてから
# （docker/nginx/smoke.sh）、main の版を GHCR（ghcr.io/<持ち主>/sycs-voldemort-nginx）に置く（.github/workflows/rust.yml）。
# 本番はそれを取ってくるだけ。compose では profile nginx のときだけ起動する（既定はいまのまま。docs/UPGRADE.ja.md の 6.）。
#
# ■ 焼き込むもの
#
#   webapp_admin/static → /srv/admin/static   Python のイメージと同じく、CSS と JS を最小化してから（scripts/minify_assets.py。
#                                             版は requirements.txt の rcssmin・rjsmin。このビルドの段の写しにだけ当てる）
#   webapp/static       → /srv/web/static     Python のイメージも最小化していないので、そのまま
#   static-types.conf   → /etc/nginx/          拡張子ごとの Content-Type を Python の mimetypes に聞いて作る（static_types.py）
#
# ■ 版
#
# nginx は公式の alpine の版を決め打ち。上げるときは、この行を書き換えるコミットとして行う。

FROM python:3.13-slim AS assets
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir $(grep -E '^(rcssmin|rjsmin)==' requirements.txt)
COPY scripts/minify_assets.py scripts/minify_assets.py
COPY docker/nginx/static_types.py docker/nginx/static_types.py
COPY webapp_admin/static webapp_admin/static
COPY webapp/static webapp/static
RUN python scripts/minify_assets.py \
    && python docker/nginx/static_types.py webapp_admin/static webapp/static > static-types.conf \
    && cat static-types.conf

FROM nginx:1.28.0-alpine AS runtime
# 公式イメージの既定の server（80 番の welcome ページ）は使わない。
RUN rm -f /etc/nginx/conf.d/default.conf
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/nginx/sycs.conf.template /etc/nginx/templates/sycs.conf.template
COPY --chmod=0755 docker/nginx/05-sycs-tmp-dirs.sh /docker-entrypoint.d/05-sycs-tmp-dirs.sh
COPY --from=assets /app/static-types.conf /etc/nginx/sycs-static-types.conf
COPY --from=assets /app/webapp_admin/static /srv/admin/static
COPY --from=assets /app/webapp/static /srv/web/static
# 設定のテンプレートの埋め方（公式イメージの入口が読む）と、上流などの既定。compose の環境変数で上書きする。
ENV NGINX_ENVSUBST_OUTPUT_DIR=/tmp/nginx \
    NGINX_ENVSUBST_FILTER=^SYCS_ \
    SYCS_ADMIN_UPSTREAM=sycs-voldemort-admin:5001 \
    SYCS_WEB_UPSTREAM=sycs-voldemort-web:8000 \
    SYCS_CDN_UPSTREAM=sycs-voldemort-cdn:5002 \
    SYCS_DJAUDIO_CACHE_DIR=/app/data/djaudio_cache \
    SYCS_RESOLVER=127.0.0.11 \
    SYCS_SECURE_COOKIES=false \
    TZ=Asia/Tokyo
EXPOSE 5001 8000

# CI だけが使う段。動かす段と同じ中身のまま、テンプレートを埋めて設定を読ませ（nginx -t）、同じことを QEMU で
# 本番の CPU（Sandy Bridge）のふりをして繰り返す。Illegal instruction で落ちれば、ビルドが失敗する。
FROM runtime AS cpu-check
RUN apk add --no-cache qemu-x86_64
RUN /docker-entrypoint.sh nginx -t \
    && cat /tmp/nginx/sycs.conf \
    && qemu-x86_64 -cpu SandyBridge /usr/sbin/nginx -t

# 何も指定せずにビルドしたとき（compose で作り直すとき）はこの段になる。中身は動かす段そのもの
# （CI だけの段〔qemu 入り〕が本番のイメージにならないよう、最後に置き直す）。
FROM runtime AS final
