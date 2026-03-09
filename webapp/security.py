import asyncio
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
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
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
    ):
        super().__init__(app)
        self.requests_per_window = requests_per_window
        self.calculate_requests_per_window = calculate_requests_per_window
        self.window_seconds = window_seconds
        self.trust_cf_headers = trust_cf_headers
        self.require_cf_connecting_ip = require_cf_connecting_ip
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.monotonic()

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
        cf_ip = request.headers.get("cf-connecting-ip")
        if self.trust_cf_headers and cf_ip:
            return cf_ip.strip(), True

        x_real_ip = request.headers.get("x-real-ip")
        if x_real_ip:
            return x_real_ip.strip(), False

        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip(), False

        return (request.client.host if request.client else "unknown"), False

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
        return ["*"]
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    return hosts or ["*"]
