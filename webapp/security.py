import asyncio
import ipaddress
import os
import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
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
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        return nets

    @staticmethod
    def _parse_ip_token(token: str | None) -> str | None:
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
        remote_ip = self._parse_ip_token(request.client.host if request.client else None) or "unknown"
        from_trusted_proxy = self._is_trusted_proxy(remote_ip)

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

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            now = time.monotonic()
            client_ip, used_cf_header = self._extract_client_ip(request)

            if self.require_cf_connecting_ip and not used_cf_header:
                return JSONResponse({"detail": "Forbidden"}, status_code=403)

            is_calculate = request.url.path == "/api/prices/calculate"
            limit = self.calculate_requests_per_window if is_calculate else self.requests_per_window
            bucket_key = f"{'calculate' if is_calculate else 'default'}:{client_ip}"

            async with self._lock:
                self._cleanup(now)
                queue = self._hits[bucket_key]
                while queue and now - queue[0] > self.window_seconds:
                    queue.popleft()
                if len(queue) >= limit:
                    return JSONResponse(
                        {"detail": "Too Many Requests"},
                        status_code=429,
                        headers={"Retry-After": str(self.window_seconds)},
                    )
                queue.append(now)

        return await call_next(request)


def read_env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def load_allowed_hosts() -> list[str]:
    raw = os.getenv("ALLOWED_HOSTS", "").strip()
    if not raw:
        return ["localhost", "127.0.0.1", "::1"]
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    return hosts or ["localhost", "127.0.0.1", "::1"]


def load_trusted_proxy_cidrs() -> list[str]:
    raw = os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]
