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
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, requests_per_window: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
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

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            now = time.monotonic()
            client_ip = request.headers.get("x-forwarded-for")
            if client_ip:
                client_ip = client_ip.split(",")[0].strip()
            else:
                client_ip = request.client.host if request.client else "unknown"

            async with self._lock:
                self._cleanup(now)
                queue = self._hits[client_ip]
                while queue and now - queue[0] > self.window_seconds:
                    queue.popleft()
                if len(queue) >= self.requests_per_window:
                    return JSONResponse({"detail": "Too Many Requests"}, status_code=429)
                queue.append(now)

        return await call_next(request)


def load_allowed_hosts() -> list[str]:
    raw = os.getenv("ALLOWED_HOSTS", "").strip()
    if not raw:
        return ["*"]
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    return hosts or ["*"]
