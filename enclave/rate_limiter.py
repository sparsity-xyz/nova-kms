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
from typing import Dict, Optional

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
_cleanup_counter = 0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that enforces per-IP rate limiting and request
    body size limits.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        global _cleanup_counter

        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        # 1. Rate limit by client IP
        client_ip = request.client.host if request.client else "unknown"
        if not _rate_limiter.allow(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )

        # 2. Request body size limit (non-sync endpoints)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                body_size = int(content_length)
                if request.url.path == "/sync":
                    max_size = config.MAX_SYNC_PAYLOAD_BYTES
                else:
                    max_size = config.MAX_REQUEST_BODY_BYTES
                if body_size > max_size:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body too large ({body_size} bytes, max {max_size})"},
                    )
            except ValueError:
                pass

        # Periodic cleanup of stale rate limit entries
        _cleanup_counter += 1
        if _cleanup_counter % 100 == 0:
            _rate_limiter.cleanup()

        return await call_next(request)
