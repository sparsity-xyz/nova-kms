"""
=============================================================================
Rate Limiter (rate_limiter.py)
=============================================================================

Rate limiting and request size limiting middleware for FastAPI.

Uses a simple in-memory token bucket approach (no external dependencies).
"""

from __future__ import annotations

import logging
import time
import threading
from typing import Dict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

import config

logger = logging.getLogger("nova-kms.rate_limiter")


# =============================================================================
# Token Bucket Rate Limiter
# =============================================================================

class TokenBucket:
    """Simple token bucket for rate limiting by key."""

    def __init__(self, rate_per_minute: int):
        self._rate = rate_per_minute
        self._interval = 60.0 / rate_per_minute if rate_per_minute > 0 else 0
        self._buckets: Dict[str, tuple] = {}  # key -> (tokens, last_refill)
        self._lock = threading.Lock()
        self._max_tokens = rate_per_minute

    def allow(self, key: str) -> bool:
        """Return True if the request should be allowed."""
        if self._rate <= 0:
            return True

        now = time.monotonic()
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = (self._max_tokens - 1, now)
                return True

            tokens, last_refill = self._buckets[key]
            # Refill tokens based on elapsed time
            elapsed = now - last_refill
            new_tokens = min(self._max_tokens, tokens + elapsed * (self._rate / 60.0))

            if new_tokens >= 1:
                self._buckets[key] = (new_tokens - 1, now)
                return True
            else:
                self._buckets[key] = (new_tokens, last_refill)
                return False

    def cleanup(self, max_age: float = 300.0):
        """Remove stale entries older than max_age seconds."""
        now = time.monotonic()
        with self._lock:
            stale = [k for k, (_, t) in self._buckets.items() if now - t > max_age]
            for k in stale:
                del self._buckets[k]


# =============================================================================
# Rate Limit Middleware
# =============================================================================

_rate_limiter = TokenBucket(config.RATE_LIMIT_PER_MINUTE)
_last_cleanup_time: float = 0.0
_CLEANUP_INTERVAL_SECONDS: float = 60.0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that enforces per-IP rate limiting and request
    body size limits.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        # 1. Rate limit by client IP
        client_ip = request.client.host if request.client else "unknown"
        if not _rate_limiter.allow(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "code": "rate_limited",
                    "message": "Rate limit exceeded. Try again later.",
                },
            )

        # 2. Request body size limit — H2 fix: read actual body bytes from
        #    the stream instead of trusting the Content-Length header.
        #    A malicious client can lie about Content-Length or use
        #    Transfer-Encoding: chunked to bypass a header-only check.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            max_size = (
                config.MAX_SYNC_PAYLOAD_BYTES
                if request.url.path == "/sync"
                else config.MAX_REQUEST_BODY_BYTES
            )

            # Read the raw body via the ASGI receive channel so we can
            # count bytes AND re-inject the verified body for downstream
            # handlers.  Using request.stream() would mark the body as
            # consumed, preventing FastAPI from parsing it.
            body_chunks: list[bytes] = []
            body_len = 0
            exceeded = False

            while True:
                message = await request._receive()
                chunk = message.get("body", b"")
                if chunk:
                    body_len += len(chunk)
                    if body_len > max_size:
                        exceeded = True
                        break
                    body_chunks.append(chunk)
                if not message.get("more_body", False):
                    break

            if exceeded:
                return JSONResponse(
                    status_code=413,
                    content={
                        "code": "payload_too_large",
                        "message": f"Request body too large (>{max_size} bytes)",
                    },
                )

            # Reassemble the body so downstream handlers can still read it.
            body_bytes = b"".join(body_chunks)

            # Replace the receive callable so that Starlette / FastAPI
            # sees the *already-validated* body bytes when it parses the
            # request.  This also works when the body was delivered in
            # multiple chunks (Transfer-Encoding: chunked).
            async def _receive():
                return {"type": "http.request", "body": body_bytes, "more_body": False}

            request._receive = _receive

        # Periodic cleanup of stale rate limit entries (time-based)
        global _last_cleanup_time
        now = time.monotonic()
        if now - _last_cleanup_time > _CLEANUP_INTERVAL_SECONDS:
            _last_cleanup_time = now
            _rate_limiter.cleanup()

        return await call_next(request)
