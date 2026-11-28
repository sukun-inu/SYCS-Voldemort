#!/bin/sh
# 公式イメージの入口（/docker-entrypoint.sh）が、起動のたびに番号の順に走らせる。
#
# compose ではルートを読み取り専用にし、/tmp だけを tmpfs にしている。テンプレートから作る設定の置き場
# （NGINX_ENVSUBST_OUTPUT_DIR）は、無いと 20-envsubst-on-templates.sh が「書けない」と言って何もしない
# （nginx は server の無いまま起動し、どの口にも応えない）。その前に作っておく。
set -eu
mkdir -p "${NGINX_ENVSUBST_OUTPUT_DIR:-/tmp/nginx}"
