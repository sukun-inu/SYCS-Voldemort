import asyncio
import ipaddress
import uuid
import os
import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from envutil import env_bool

from services.log_setup import DEFAULT_TRUSTED_PROXIES, warn_if_forwarded_ignored
from services.shared_cache import shared_cache


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        """全レスポンスへセキュリティヘッダを一律付与する。

        CSP の script-src に `'unsafe-inline'` を残しているのは、
        `index.html` がインラインの `<script>` を直接埋め込んでいるため
        （nonce/hash 化していない）。cloudflareinsights.com を許可して
        いるのは Cloudflare 側が自動で差し込む解析ビーコン用で、
        アプリのコードには現れない。どちらも外すとブラウザ側で読み込みが
        ブロックされ、機能や解析が静かに止まる。
        """
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; "
            "script-src-elem 'self' 'unsafe-inline' https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https: https://cloudflareinsights.com https://static.cloudflareinsights.com; "
            "manifest-src 'self'; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response


# 共有のレート制限を置く名前空間。管理画面の slowapi は Valkey の 1 番 DB を
# 使い、こちらは共有キャッシュと同じ 0 番の中の別の名前空間を使う。
# 混ぜないのは、キャッシュを消したいときにレート制限まで消さないため。
RATE_LIMIT_NAMESPACE = "ratelimit:api"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        requests_per_window: int = 120,
        calculate_requests_per_window: int = 60,
        window_seconds: int = 60,
        trust_cf_headers: bool = True,
        require_cf_connecting_ip: bool = False,
        trusted_proxy_cidrs: list[str] | None = None,
    ):
        """/api/ 配下だけをレート制限する。それ以外の静的ファイル配信は対象外。

        `/api/prices/calculate` にだけ別枠（既定で通常の半分）を設けて
        いるのは、他の read 系APIより重い処理（DBアクセス＋計算）を
        伴うため。共通の上限にすると、この重いエンドポイントへの
        連打を軽いAPIと同じ回数まで許してしまい、負荷対策として緩すぎる。
        """
        super().__init__(app)
        self.requests_per_window = requests_per_window
        self.calculate_requests_per_window = calculate_requests_per_window
        self.window_seconds = window_seconds
        self.trust_cf_headers = trust_cf_headers
        self.require_cf_connecting_ip = require_cf_connecting_ip
        self.trusted_proxy_networks = self._parse_proxy_cidrs(trusted_proxy_cidrs or [])
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.monotonic()

    @staticmethod
    def _parse_proxy_cidrs(
        cidrs: list[str],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """設定文字列をCIDRへ変換する。壊れた1件は無視し、他の設定は活かす。

        ここで例外を上げると起動時の設定読み込みが丸ごと失敗するため、
        書式ミス1件でアプリが立ち上がらなくなるのを避けている。
        """
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        return nets

    @staticmethod
    def _parse_ip_token(token: str | None) -> str | None:
        """ヘッダやsocketから来た値からIPだけを取り出す。ポート・角括弧が付いていても剥がす。

        `request.client.host` や `X-Forwarded-For` は "1.2.3.4:5678" や
        "[::1]:5678" のようにポート付きで来ることがある。剥がさずに
        `ipaddress.ip_address()` へ渡すと必ず失敗し、信頼できるはずの
        プロキシ経由の接続まで「不明なIP」扱いになってしまう。
        """
        if not token:
            return None
        raw = token.strip()
        if not raw:
            return None

        if raw.startswith("[") and "]" in raw:
            raw = raw[1 : raw.index("]")]
        elif raw.count(":") == 1 and "." in raw:
            # IPv4 with port (e.g. 203.0.113.10:443)
            host, _, port = raw.rpartition(":")
            if host and port.isdigit():
                raw = host

        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None

    def _is_trusted_proxy(self, remote_ip: str | None) -> bool:
        """直接つないできたIPが、設定済みの信頼プロキシ帯域に入っているか。

        ここが false のリクエストでは CF-Connecting-IP や
        X-Forwarded-For を一切信用しない（_extract_client_ip 参照）。
        信頼判定を省いてヘッダを鵜呑みにすると、攻撃者が
        `X-Forwarded-For: 1.1.1.1` を自分で送るだけでレート制限の
        カウント先を偽装でき、実質ノーリミットになる。
        """
        if not remote_ip:
            return False
        parsed = self._parse_ip_token(remote_ip)
        if not parsed:
            return False
        try:
            ip_obj = ipaddress.ip_address(parsed)
        except ValueError:
            return False
        return any(ip_obj in net for net in self.trusted_proxy_networks)

    def _cleanup(self, now: float) -> None:
        """呼ぶのは1ウィンドウに1回だけに抑える。毎リクエストで全IPを
        走査すると、多数の送信元から叩かれる攻撃時ほど重くなる
        （守るための処理が一番効いてほしい場面で遅くなる）。
        """
        # 攻撃時にIPキーが増え続けないよう、期限切れエントリを間引く。
        if now - self._last_cleanup < self.window_seconds:
            return
        self._last_cleanup = now
        expired_ips: list[str] = []
        for client_ip, queue in self._hits.items():
            while queue and now - queue[0] > self.window_seconds:
                queue.popleft()
            if not queue:
                expired_ips.append(client_ip)
        for client_ip in expired_ips:
            del self._hits[client_ip]

    def _extract_client_ip(self, request: Request) -> tuple[str, bool]:
        """レート制限のキーにするIPを決める。信頼できないヘッダは無視する。

        直接つないできたIP（TCP接続のIP。偽装不能）が信頼プロキシ帯域に
        入っている場合に限り、そのプロキシが付けたヘッダを見る。
        CF-Connecting-IP を X-Forwarded-For より先に見るのは、
        Cloudflare 経由の構成では前者の方が改ざんされにくいため
        （後者は複数プロキシを経由すると先頭以外の値も混じりうる）。
        戻り値の bool は「CF-Connecting-IP を使えたか」で、
        require_cf_connecting_ip の判定に使う。
        """
        remote_ip = self._parse_ip_token(request.client.host if request.client else None) or "unknown"
        from_trusted_proxy = self._is_trusted_proxy(remote_ip)
        if not from_trusted_proxy:
            # 設定の間違いは黙って元に戻る形で失敗する。何を足せばよいかを出す。
            warn_if_forwarded_ignored(remote_ip, request.headers.get("x-forwarded-for"))

        if from_trusted_proxy and self.trust_cf_headers:
            cf_ip = self._parse_ip_token(request.headers.get("cf-connecting-ip"))
            if cf_ip:
                return cf_ip, True

        if from_trusted_proxy:
            x_real_ip = self._parse_ip_token(request.headers.get("x-real-ip"))
            if x_real_ip:
                return x_real_ip, False

            forwarded_for = request.headers.get("x-forwarded-for")
            if forwarded_for:
                first_hop = forwarded_for.split(",")[0]
                forwarded_ip = self._parse_ip_token(first_hop)
                if forwarded_ip:
                    return forwarded_ip, False

        return remote_ip, False

    async def _allow_shared(self, bucket_key: str, now: float, limit: int) -> bool | None:
        """Valkey で数えて通すか決める。使えなければ None（プロセス内へ落ちる）。

        **WEB_WORKERS の既定は 2 なので、これが無いと上限が実質2倍になる。**
        ワーカーごとに別のプロセスが別の deque で数えていた。

        member に uuid4 を足しているのは、同じ時刻に来た複数のリクエストを
        別物として数えるため。時刻だけだと、同じ score の同じメンバーとして
        上書きされ、1件しか数えられない。

        断るときは足した1件を取り消す。取り消さないと、断られたリクエストが
        窓を押し続けて、叩いている相手がいつまでも解除されない（元の実装は
        上限に達した時点で deque へ積まずに返していた）。
        """
        shared = shared_cache()
        if not shared.available:
            return None
        member = f"{now}:{uuid.uuid4().hex}"
        count = await shared.sliding_window_hit(
            RATE_LIMIT_NAMESPACE,
            bucket_key,
            window_seconds=self.window_seconds,
            now=now,
            member=member,
        )
        if count is None:
            return None
        if count > limit:
            await shared.sliding_window_undo(RATE_LIMIT_NAMESPACE, bucket_key, member)
            return False
        return True

    async def _allow_local(self, bucket_key: str, now: float, limit: int) -> bool:
        """プロセス内の deque で数えて通すか決める。Valkey が使えないときの受け皿。

        Valkey を入れたあとも残してある。**共有だけにすると、Valkey が落ちた
        瞬間にレート制限が丸ごと無くなる。** 緩くはなるが効いている状態を保つ
        （管理画面側の slowapi に in_memory_fallback を付けたのと同じ考え方）。

        中身は元の実装のまま。上限に達していたら deque へ積まずに False を返す。
        """
        async with self._lock:
            self._cleanup(now)
            queue = self._hits[bucket_key]
            while queue and now - queue[0] > self.window_seconds:
                queue.popleft()
            if len(queue) >= limit:
                return False
            queue.append(now)
            return True

    async def dispatch(self, request: Request, call_next):
        """スライディングウィンドウ方式でIPごとに件数を数え、上限超過なら429を返す。

        require_cf_connecting_ip を有効にした環境で CF-Connecting-IP が
        取れなかった場合は、レート制限をすり抜けさせず 403 で弾く
        （Cloudflareを必ず経由する構成のとき、直アクセスや偽装を
        締め出す用途）。

        数える場所は Valkey（全ワーカー共通）を優先し、使えないときだけ
        プロセス内へ落ちる。**どちらの経路も「通した件数」だけを窓に残す**
        （断ったぶんは残さない）。片方だけ残す作りにすると、Valkey が落ちた
        前後で解除までの時間が変わる。
        """
        if request.url.path.startswith("/api/"):
            now = time.monotonic()
            client_ip, used_cf_header = self._extract_client_ip(request)

            if self.require_cf_connecting_ip and not used_cf_header:
                return JSONResponse({"detail": "Forbidden"}, status_code=403)

            is_calculate = request.url.path == "/api/prices/calculate"
            limit = self.calculate_requests_per_window if is_calculate else self.requests_per_window
            bucket_key = f"{'calculate' if is_calculate else 'default'}:{client_ip}"

            allowed = await self._allow_shared(bucket_key, now, limit)
            if allowed is None:
                allowed = await self._allow_local(bucket_key, now, limit)

            if not allowed:
                return JSONResponse(
                    {"detail": "Too Many Requests"},
                    status_code=429,
                    headers={"Retry-After": str(self.window_seconds)},
                )

        return await call_next(request)


def read_env_bool(name: str, default: bool = False) -> bool:
    """envutil.env_bool への薄いラッパー。webapp/app.py がこの名前で import している。"""
    # 実装は envutil.env_bool に一本化している(旧実装との差分は解釈不能値でも
    # 警告ログを残す点のみで、返り値の挙動は同一であることを確認済み)。
    # webapp/app.py がこの名前で import しているため、関数名はそのまま残す。
    return env_bool(name, default)


def load_allowed_hosts() -> list[str]:
    """未設定・空なら localhost系のみを許可する既定値に倒す。空リストは返さない。

    呼び出し先の TrustedHostMiddleware は allowed_hosts=[] を渡すと
    「一致するホストが無い」ため全リクエストを400で拒否する
    （allow-any に倒れるのは allowed_hosts を省略するか None を渡した
    ときだけで、この関数は常に具体的なリストを返すのでその経路には
    乗らない）。空リストのまま渡すと ALLOWED_HOSTS の設定ミス1つで
    アプリ全体が丸ごとアクセス不能になる。
    """
    raw = os.getenv("ALLOWED_HOSTS", "").strip()
    if not raw:
        return ["localhost", "127.0.0.1", "::1"]
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    return hosts or ["localhost", "127.0.0.1", "::1"]


def load_trusted_proxy_cidrs() -> list[str]:
    """既定はループバックのみ信頼する。空文字を明示指定すれば「誰も信頼しない」にできる。

    既定はループバックに加えて Docker のブリッジ帯域（172.16.0.0/12）。
    ループバックだけにしていたときは、compose 構成でプロキシから見た接続元が
    ブリッジゲートウェイ（172.19.0.1 など）になり、**X-Forwarded-For が
    捨てられてアクセスログもレート制限もそのIP1つに寄っていた。**

    LAN でよく使う 192.168.0.0/16 と 10.0.0.0/8 は入れない——このアプリは
    ポートを公開するので、同じ LAN から直接叩いてヘッダを偽装できてしまう。
    逆にデフォルトを甘く（例えば0.0.0.0/0)すると、外部から直接
    X-Forwarded-For を偽装したリクエストがそのまま信頼され、
    レート制限もIP偽装で回避できてしまう。

    services/log_setup.py の trusted_proxies() と同じ環境変数・同じ既定。
    片方だけ変えると、レート制限とアクセスログが別のIPを見ることになる。
    """
    raw = os.getenv("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_PROXIES).strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]
