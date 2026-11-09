"""
HTTP hardening (roadmap S6.6): rate limits and security headers.

Rate limits are per client address (behind the frontend's nginx, uvicorn
takes the address from X-Forwarded-For, trusting it only from
FORWARDED_ALLOW_IPS):

  every API request    RATE_LIMIT_PER_MINUTE (300), token bucket, burst = the
                       same number; agents' /api/agents/ingest is exempt (each
                       agent has its own token and the server caps batch size)
  failed logins        LOGIN_ATTEMPTS_PER_MINUTE (5) per address and per
                       username, so neither guessing many passwords for one
                       user nor one password for many users is fast

Over the limit: 429 with Retry-After. State is in memory (one process).
"""

import math
import time
from collections import deque
from typing import Deque, Dict, Tuple

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse

from .config import settings

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

RATE_LIMIT_EXEMPT = ("/api/agents/ingest", "/api/health/")
MAX_TRACKED = 10_000


class TokenBuckets:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last refill)

    def take(self, key: str, now: float = None) -> float:
        """0 if allowed, else seconds until a request would be"""
        if self.per_minute <= 0:
            return 0.0
        now = time.monotonic() if now is None else now
        rate = self.per_minute / 60.0
        tokens, last = self.buckets.get(key, (float(self.per_minute), now))
        tokens = min(float(self.per_minute), tokens + (now - last) * rate)
        if tokens < 1:
            self.buckets[key] = (tokens, now)
            return (1 - tokens) / rate
        self.buckets[key] = (tokens - 1, now)
        if len(self.buckets) > MAX_TRACKED:
            self._prune(now)
        return 0.0

    def _prune(self, now: float) -> None:
        # A bucket idle for a minute is full again; forget it
        for key, (_, last) in list(self.buckets.items()):
            if now - last > 60:
                del self.buckets[key]


class LoginThrottle:
    """Failed logins in the last minute, per address and per username"""

    WINDOW = 60.0

    def __init__(self):
        self.failures: Dict[str, Deque[float]] = {}

    def _recent(self, key: str, now: float) -> Deque[float]:
        times = self.failures.setdefault(key, deque())
        while times and now - times[0] > self.WINDOW:
            times.popleft()
        return times

    def retry_after(self, client: str, username: str, now: float = None) -> float:
        limit = settings.login_attempts_per_minute
        if limit <= 0:
            return 0.0
        now = time.monotonic() if now is None else now
        wait = 0.0
        for key in (f"ip:{client}", f"user:{username.lower()}"):
            times = self._recent(key, now)
            if len(times) >= limit:
                wait = max(wait, self.WINDOW - (now - times[0]))
        return wait

    def failed(self, client: str, username: str, now: float = None) -> None:
        now = time.monotonic() if now is None else now
        for key in (f"ip:{client}", f"user:{username.lower()}"):
            self._recent(key, now).append(now)
        if len(self.failures) > MAX_TRACKED:
            for key in [k for k, v in self.failures.items() if not v or now - v[-1] > self.WINDOW]:
                del self.failures[key]

    def succeeded(self, username: str) -> None:
        self.failures.pop(f"user:{username.lower()}", None)

    def reset(self) -> None:
        self.failures.clear()


login_throttle = LoginThrottle()


def too_many_requests(retry_after: float, what: str = "Too many requests") -> JSONResponse:
    return JSONResponse(status_code=429, content={"detail": f"{what}; try again later"},
                        headers={"Retry-After": str(max(1, math.ceil(retry_after)))})


class SecurityMiddleware:
    """Adds security headers to every HTTP response and applies the API rate limit"""

    def __init__(self, app):
        self.app = app
        self.limiter = TokenBuckets(settings.rate_limit_per_minute)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        path = scope.get("path", "")
        limited = path.startswith("/api/") and not path.startswith(RATE_LIMIT_EXEMPT)
        if limited and scope.get("method") != "OPTIONS":
            client = scope.get("client")
            wait = self.limiter.take(client[0] if client else "unknown")
            if wait:
                await too_many_requests(wait)(scope, receive, send_with_headers)
                return
        await self.app(scope, receive, send_with_headers)


def security_problems() -> list:
    """Settings the backend refuses to start with"""
    from .services.auth import secret_key_problem

    problems = []
    key_problem = secret_key_problem(settings.secret_key)
    if key_problem:
        problems.append(f"{key_problem} (generate one with: openssl rand -hex 32)")
    if "*" in settings.allowed_origins:
        problems.append("ALLOWED_ORIGINS must list origins, not '*'")
    if "*" in settings.allowed_hosts:
        problems.append("ALLOWED_HOSTS must list host names, not '*'")
    return problems
