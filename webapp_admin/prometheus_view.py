"""Netdata が読む /metrics（Prometheus 形式）。

■ なぜ管理画面から出すのか

3つのアプリのメトリクスは Valkey に集めてある（services/metrics_registry.py の
冒頭）。読み出し口は1つあればよく、既に HTTP サーバーを持っていて、しかもワーカー
数を1に固定してある管理画面がいちばん都合がよい。

■ 認証ではなく、接続元で守る

Netdata はログインできないので、この経路には Discord OAuth を通せない。代わりに
接続元 IP で絞る。

**X-Forwarded-For などの転送ヘッダは一切見ていない。** 見ると、ヘッダを1つ付けて
リクエストするだけで誰でも通れてしまう。管理画面は他の経路では
TRUSTED_PROXY_CIDRS を見て転送ヘッダを信じるが、ここでその作法を真似ると
「信頼できるプロキシの一覧」が守りの根拠になり、そこを広げた瞬間に穴になる。
ここが見るのは request.client.host（TCP の接続元）だけ。

Netdata はホスト上で動き、ホストへ公開したポート経由で来るので、コンテナから見た
接続元は Docker のブリッジのゲートウェイ（172.16.0.0/12 の中）になる。既定の
許可範囲がそれを含んでいるのはこのため。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from pathlib import Path

from fastapi import Request
from fastapi.responses import PlainTextResponse, Response

from envutil import env_path, env_str
from services.metrics_registry import metrics_registry
from webapp_admin.metrics import request_tps, uptime_seconds

logger = logging.getLogger(__name__)

# 既定の許可範囲。ループバックと Docker の既定ブリッジ帯。
# services/log_setup.py の DEFAULT_TRUSTED_PROXIES と同じ値だが、意味が違うので
# 共有していない（あちらは「転送ヘッダを信じる相手」、こちらは「読ませる相手」）。
DEFAULT_ALLOWED_CIDRS = "127.0.0.1/32,::1/128,172.16.0.0/12"

# Prometheus のテキスト形式の Content-Type。これを付けないと、収集器が
# HTML として扱って何も読まないことがある。
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """許可する接続元の一覧。書式が壊れた1件は無視して、他は活かす。

    ここで例外を上げると、設定の書式ミス1つで管理画面が起動しなくなる
    （webapp/security.py の _parse_proxy_cidrs と同じ方針）。
    """
    raw = env_str("METRICS_ALLOWED_CIDRS", DEFAULT_ALLOWED_CIDRS) or DEFAULT_ALLOWED_CIDRS
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning("METRICS_ALLOWED_CIDRS に読めない値があります（無視します）: %s", token)
    return networks


def client_allowed(request: Request) -> bool:
    """この接続元に /metrics を見せてよいか。

    **転送ヘッダを見ないこと。** モジュール冒頭に理由がある。接続元が取れない
    場合（client が None）は拒否する。取れないものを通すと、判定を空振りさせる
    だけで通れる道になる。
    """
    client = request.client
    if client is None or not client.host:
        return False
    try:
        peer = ipaddress.ip_address(client.host)
    except ValueError:
        return False
    return any(peer in network for network in allowed_networks())


def backup_age_seconds() -> float | None:
    """最後に成功したバックアップからの経過秒数。読めなければ None。

    docker/postgres-backup.sh が書く status.json を読む。**result が ok の
    ときだけ値を返す。** 失敗した回の finished_at_epoch を返すと、「バックアップは
    最近動いている」ように見えてしまう（動いてはいるが、成功していない）。
    """
    status_file = env_path("BACKUP_STATUS_FILE", Path("/backups/status.json"))
    try:
        with open(status_file, "r", encoding="utf-8") as handle:
            status = json.load(handle)
    except (OSError, ValueError):
        # マウントしていない構成では毎回ここに来る。警告を出すと通常運用で
        # ログが埋まるので、debug に留める。
        logger.debug("バックアップの状態ファイルを読めません: %s", status_file, exc_info=True)
        return None
    if not isinstance(status, dict) or status.get("result") != "ok":
        return None
    finished = status.get("finished_at_epoch")
    if not isinstance(finished, (int, float)):
        return None
    return max(0.0, time.time() - float(finished))


def _extra_series() -> list[tuple[str, dict[str, str] | None, float, str, str]]:
    """このプロセスでその場で測れるものを組み立てる。

    Valkey を経由させると、スクレイプのたびに書き込みが走る。読むだけで済む
    ものはここで足す。

    ホストの CPU・メモリ・ディスクは入れていない。**Netdata が自分で測るものを
    重ねて出す意味は無く、しかも psutil.cpu_percent は 0.1 秒ブロックする**
    （webapp_admin/metrics.py の request_tps のコメント参照）。
    """
    extra: list[tuple[str, dict[str, str] | None, float, str, str]] = [
        (
            "admin_request_tps",
            None,
            request_tps(),
            "gauge",
            "管理画面の直近の秒間リクエスト数",
        ),
        (
            "admin_uptime_seconds",
            None,
            uptime_seconds(),
            "gauge",
            "管理画面のプロセスが起きてからの秒数",
        ),
    ]
    age = backup_age_seconds()
    if age is not None:
        extra.append(
            (
                "backup_age_seconds",
                None,
                age,
                "gauge",
                "最後に成功した Postgres バックアップからの経過秒数",
            )
        )
    return extra


async def render_metrics(request: Request) -> Response:
    """/metrics の本体。許可されない接続元には 403 を返す。

    本文が空になることは無い（共有キャッシュが落ちていても
    sycs_shared_cache_available と extra は出る）。空を返すと Netdata 側は
    「収集器が壊れた」と扱い、「Valkey が落ちている」という本当の情報が
    伝わらない。
    """
    if not client_allowed(request):
        # 何が許可されているかは返さない。返すと、外から許可範囲を探れる。
        return PlainTextResponse("Forbidden\n", status_code=403)
    body = await metrics_registry().render(extra=_extra_series())
    return PlainTextResponse(body, media_type=CONTENT_TYPE)


def metrics_path() -> str:
    """/metrics の公開パス。既定は /metrics。

    環境変数で変えられるようにしてあるのは、接続元の制限とは別に、既定の
    パスを避けたい構成もありうるため（当てにする守りではない）。
    """
    return os.getenv("METRICS_PATH", "/metrics").strip() or "/metrics"
