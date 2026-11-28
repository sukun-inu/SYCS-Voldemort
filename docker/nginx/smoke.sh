#!/bin/sh
# nginx と Rust の配信をつないで、配信のリンク・内側の場所・静的ファイルの見出しが思ったとおりかを確かめる。
# CI（.github/workflows/rust.yml の web-images）が、作ったばかりのイメージで回す。**手元の PC では回さない。**
#
#   sh docker/nginx/smoke.sh <nginx のイメージ> <配信のイメージ>
#
# 管理画面と Web のアプリは立てない（上流が居ないときは nginx が 502 を返す。nginx が自分で返すものと、
# 上流へ回すものの振り分けを、その 502 で見分ける）。
set -eu

NGINX_IMAGE=$1
CDN_IMAGE=$2
NAME=sycs-smoke
TOKEN=0123456789abcdef0123456789abcdef
ADMIN=http://127.0.0.1:18501
WEB=http://127.0.0.1:18502

work=$(mktemp -d)

cleanup() {
    docker rm -fv "$NAME-nginx" "$NAME-cdn" >/dev/null 2>&1 || true
    docker network rm "$NAME" >/dev/null 2>&1 || true
    rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "NG: $*"
    echo "--- nginx のログ"
    docker logs "$NAME-nginx" 2>&1 | tail -n 40 || true
    echo "--- 配信のログ"
    docker logs "$NAME-cdn" 2>&1 | tail -n 40 || true
    exit 1
}

# 置き場（Bot が書くのと同じ形）。nginx の働き手（nginx という利用者）が読めるように、誰でも読めるようにする。
mkdir -p "$work/data/djaudio_cache"
printf 'ID3-smoke-0123456789' > "$work/data/djaudio_cache/$TOKEN.mp3"
expires=$(($(date +%s) + 3600))
printf '{"token": "%s", "guild_id": "999", "title": "t", "filename": "Smoke Test.mp3", "extension": ".mp3", "expires_at": %s}' \
    "$TOKEN" "$expires" > "$work/data/djaudio_cache/$TOKEN.json"
chmod -R a+rwX "$work"

docker network create "$NAME" >/dev/null
# 配信のログは tmpfs に書かせる（置き場に root のファイルを作らない。終わったあと runner の利用者で消せるように）。
docker run -d --name "$NAME-cdn" --network "$NAME" --read-only --tmpfs /tmp \
    -v "$work/data:/app/data" -e SETTINGS_DIR=/tmp "$CDN_IMAGE" >/dev/null
docker run -d --name "$NAME-nginx" --network "$NAME" --read-only --tmpfs /tmp \
    -v "$work/data:/app/data:ro" \
    -e SYCS_CDN_UPSTREAM="$NAME-cdn:5002" \
    -e SYCS_ADMIN_UPSTREAM="$NAME-no-admin:5001" \
    -e SYCS_WEB_UPSTREAM="$NAME-no-web:8000" \
    -p 127.0.0.1:18501:5001 -p 127.0.0.1:18502:8000 "$NGINX_IMAGE" >/dev/null

# 起きるまで待つ（配信の /dlaudio/health が nginx を通って 200 になるまで）。
i=0
until curl -fsS -o /dev/null "$ADMIN/dlaudio/health" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || fail "nginx か配信が起きない"
    sleep 1
done

# fetch <URL> [curl の引数...]: 状態・見出し・本文を $work/status・$work/headers・$work/body に置く。
fetch() {
    url=$1
    shift
    curl -sS -o "$work/body" -D "$work/headers" -w '%{http_code}' "$@" "$url" > "$work/status" \
        || fail "$url に尋ねられない"
}

status_is() {
    [ "$(cat "$work/status")" = "$1" ] || fail "$2: 状態が $(cat "$work/status")（$1 のはず）"
}

# 見出しの名前は大文字小文字を問わない。値は行末の CR を落として比べる。
header_is() {
    got=$(grep -i "^$1:" "$work/headers" | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    [ "$got" = "$2" ] || fail "$3: $1 が「$got」（「$2」のはず）"
}

header_has() {
    grep -qi "^$1:" "$work/headers" || fail "$2: $1 が無い"
}

header_absent() {
    if grep -qi "^$1:" "$work/headers"; then
        fail "$2: $1 が付いている"
    fi
}

# 1. 配信のリンク: 中身は nginx が置き場から送り、見出しは配信の答えのもの。X-Accel-Redirect は外に漏らさない。
fetch "$ADMIN/dlaudio/files/999/$TOKEN"
status_is 200 "配信"
[ "$(cat "$work/body")" = "ID3-smoke-0123456789" ] || fail "配信: 中身が置き場のファイルと違う"
header_is content-type "audio/mpeg" "配信"
header_is content-disposition "attachment; filename*=utf-8''Smoke%20Test.mp3" "配信"
header_is x-frame-options "DENY" "配信"
header_is x-content-type-options "nosniff" "配信"
header_is referrer-policy "strict-origin-when-cross-origin" "配信"
header_has content-security-policy "配信"
header_absent x-accel-redirect "配信"
header_is vary "Cookie" "配信"
header_absent strict-transport-security "配信"

# 2. Range は nginx が返す。
fetch "$ADMIN/dlaudio/files/999/$TOKEN" -H 'Range: bytes=0-2'
status_is 206 "配信の Range"
[ "$(cat "$work/body")" = "ID3" ] || fail "配信の Range: 中身が違う"

# 3. 断るときは、配信の案内のページがそのまま返る。
fetch "$ADMIN/dlaudio/files/999/short"
status_is 404 "形の違うリンク"
grep -q "リンクが正しくありません" "$work/body" || fail "形の違うリンク: 案内のページではない"
header_is x-frame-options "DENY" "形の違うリンク"

# 4. 情報（JSON）。
fetch "$ADMIN/dlaudio/info/999/$TOKEN"
status_is 200 "情報"
grep -q '"remaining_seconds":' "$work/body" || fail "情報: 残り時間が無い"

# 5. 内側の場所は外から開けない。
fetch "$ADMIN/_sycs_djaudio/$TOKEN.mp3"
status_is 404 "内側の場所"

# 6. /dlaudio（末尾の / 無し）は管理画面へ回す（nginx が自分で 301 を返さない）。管理画面は居ないので 502。
fetch "$ADMIN/dlaudio"
status_is 502 "/dlaudio"

# 7. 管理画面の静的ファイル: 焼き込んだもの（最小化済み）を、管理画面と同じ見出しで返す。
fetch "$ADMIN/static/css/base.css"
status_is 200 "管理画面の静的ファイル"
header_is content-type "text/css; charset=utf-8" "管理画面の静的ファイル"
header_is cache-control "no-cache, max-age=0, must-revalidate" "管理画面の静的ファイル"
header_is pragma "no-cache" "管理画面の静的ファイル"
header_is expires "0" "管理画面の静的ファイル"
header_is x-frame-options "DENY" "管理画面の静的ファイル"
header_is referrer-policy "strict-origin-when-cross-origin" "管理画面の静的ファイル"
header_has content-security-policy "管理画面の静的ファイル"
header_is vary "Cookie" "管理画面の静的ファイル"
header_absent content-encoding "管理画面の静的ファイル"
[ "$(head -c 2 "$work/body")" != "/*" ] || fail "管理画面の静的ファイル: 最小化されていない（先頭に注釈が残っている）"
fetch "$ADMIN/static/js/main.js"
status_is 200 "管理画面の JS"
header_is content-type "text/javascript; charset=utf-8" "管理画面の JS"

# 8. 無い静的ファイルは管理画面へ回す（404 のページを Python と同じにするため。管理画面は居ないので 502）。
fetch "$ADMIN/static/no-such-file.css"
status_is 502 "無い静的ファイル"

# 9. Web の静的ファイル: 版の無い URL は 5 分、版つきは 1 年。圧縮は 500 バイト以上。
fetch "$WEB/static/styles.css"
status_is 200 "Web の静的ファイル"
header_is content-type "text/css; charset=utf-8" "Web の静的ファイル"
header_is cache-control "public, max-age=300, must-revalidate" "Web の静的ファイル"
header_is permissions-policy "geolocation=(), microphone=(), camera=()" "Web の静的ファイル"
header_is cross-origin-opener-policy "same-origin" "Web の静的ファイル"
header_is strict-transport-security "max-age=31536000; includeSubDomains" "Web の静的ファイル"
fetch "$WEB/static/styles.css?v=abc"
header_is cache-control "public, max-age=31536000, immutable" "Web の版つきの静的ファイル"
fetch "$WEB/static/styles.css?v="
header_is cache-control "public, max-age=300, must-revalidate" "Web の空の版"
fetch "$WEB/static/styles.css" -H 'Accept-Encoding: gzip'
header_is content-encoding "gzip" "Web の静的ファイルの圧縮"

# 10. Web のほかの経路は Web のアプリへ回す（居ないので 502）。
fetch "$WEB/"
status_is 502 "Web の /"

echo "nginx と配信: 全部思ったとおり"
