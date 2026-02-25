"""
Tests for url_validator.py, rate_limiter.py, chain.py, and cross-cutting
security concerns.

Covers:
  - validate_peer_url (SSRF protection, scheme, port, hostname, private IPs)
  - TokenBucket (rate limiting, cleanup)
  - Chain (eth_call_finalized with confirmation depth, fallback)
  - Clock skew protection (DataStore)
  - MAX_NONCES eviction (auth._NonceStore)
  - CachedNovaRegistry TTL expiry
"""

import socket
import time
from unittest.mock import MagicMock, patch

import pytest

import config


# =============================================================================
# URL Validator — SSRF Protection
# =============================================================================


class TestURLValidator:
    @pytest.fixture(autouse=True)
    def _allow_http(self, monkeypatch):
        monkeypatch.setattr(config, "IN_ENCLAVE", False)
        monkeypatch.setattr(config, "ALLOWED_PEER_URL_SCHEMES", ["http", "https"])

    def test_valid_https(self):
        from url_validator import validate_peer_url
        url = validate_peer_url("https://kms1.example.com:8443/health", allow_private_ips=True)
        assert url == "https://kms1.example.com:8443/health"

    def test_valid_http_dev(self):
        from url_validator import validate_peer_url
        url = validate_peer_url("http://kms.dev.example.com", allow_private_ips=True)
        assert "http" in url

    def test_empty_url_rejected(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="Empty"):
            validate_peer_url("")

    def test_none_url_rejected(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError):
            validate_peer_url(None)

    def test_bad_scheme_rejected(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="scheme"):
            validate_peer_url("ftp://evil.com/file", allow_private_ips=True)

    def test_no_hostname_rejected(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="hostname"):
            validate_peer_url("http://", allow_private_ips=True)

    def test_hostname_accept_without_resolution(self):
        from url_validator import validate_peer_url
        # Should NOT raise URLValidationError anymore.
        # It should log a warning and return the cleaned URL.
        url = "http://this-hostname-does-not-exist-xyz123.example.invalid"
        validated = validate_peer_url(
            url,
            allow_private_ips=False,
        )
        assert validated == url

    def test_private_ips_allowed_now(self):
        """Verify that private IPs are now allowed (responsibility shifted to proxy)."""
        from url_validator import validate_peer_url
        # Previously blocked IPs should now pass
        assert validate_peer_url("http://127.0.0.1:8000", allow_private_ips=False) == "http://127.0.0.1:8000"
        assert validate_peer_url("http://169.254.169.254/latest/meta-data", allow_private_ips=False) == "http://169.254.169.254/latest/meta-data"


# =============================================================================
# Token Bucket Rate Limiter
# =============================================================================


class TestTokenBucket:
    def test_allows_within_rate(self):
        from rate_limiter import TokenBucket
        tb = TokenBucket(rate_per_minute=10)
        assert tb.allow("ip1") is True

    def test_exhausts_bucket(self):
        from rate_limiter import TokenBucket
        tb = TokenBucket(rate_per_minute=2)
        tb.allow("ip")
        tb.allow("ip")
        # Third should be rejected
        assert tb.allow("ip") is False

    def test_separate_keys(self):
        from rate_limiter import TokenBucket
        tb = TokenBucket(rate_per_minute=1)
        assert tb.allow("a") is True
        assert tb.allow("b") is True  # different key

    def test_zero_rate_allows_all(self):
        from rate_limiter import TokenBucket
        tb = TokenBucket(rate_per_minute=0)
        for _ in range(100):
            assert tb.allow("x") is True

    def test_cleanup(self):
        from rate_limiter import TokenBucket
        tb = TokenBucket(rate_per_minute=10)
        tb.allow("stale")
        # Manually age the entry
        key = "stale"
        tokens, _ = tb._buckets[key]
        tb._buckets[key] = (tokens, time.monotonic() - 999)
        tb.cleanup(max_age=300)
        assert key not in tb._buckets


class TestRateLimitMiddlewareCleanup:
    """Verify that the middleware triggers cleanup based on elapsed time."""

    def test_cleanup_triggered_after_interval(self, monkeypatch):
        import rate_limiter

        # Force _last_cleanup_time to the distant past so cleanup triggers
        monkeypatch.setattr(rate_limiter, "_last_cleanup_time", 0.0)
        monkeypatch.setattr(rate_limiter, "_CLEANUP_INTERVAL_SECONDS", 1.0)

        cleanup_calls = {"count": 0}
        original_cleanup = rate_limiter._rate_limiter.cleanup

        def _counting_cleanup(*args, **kwargs):
            cleanup_calls["count"] += 1
            return original_cleanup(*args, **kwargs)

        monkeypatch.setattr(rate_limiter._rate_limiter, "cleanup", _counting_cleanup)

        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/test", homepage)])
        app.add_middleware(rate_limiter.RateLimitMiddleware)

        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert cleanup_calls["count"] == 1

    def test_cleanup_not_triggered_within_interval(self, monkeypatch):
        import rate_limiter

        # Set _last_cleanup_time to now so cleanup should NOT trigger
        monkeypatch.setattr(rate_limiter, "_last_cleanup_time", time.monotonic())
        monkeypatch.setattr(rate_limiter, "_CLEANUP_INTERVAL_SECONDS", 9999.0)

        cleanup_calls = {"count": 0}
        original_cleanup = rate_limiter._rate_limiter.cleanup

        def _counting_cleanup(*args, **kwargs):
            cleanup_calls["count"] += 1
            return original_cleanup(*args, **kwargs)

        monkeypatch.setattr(rate_limiter._rate_limiter, "cleanup", _counting_cleanup)

        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/test", homepage)])
        app.add_middleware(rate_limiter.RateLimitMiddleware)

        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert cleanup_calls["count"] == 0


# =============================================================================
# Chain — eth_call_finalized
# =============================================================================


class TestChainFinality:
    def test_eth_call_finalized_uses_confirmed_block(self):
        from chain import Chain

        chain = Chain.__new__(Chain)
        chain.endpoint = "mock"
        mock_w3 = MagicMock()
        mock_w3.eth.block_number = 100
        mock_w3.eth.call.return_value = b"\x01" * 32
        chain.w3 = mock_w3

        result = chain.eth_call_finalized("0x" + "AA" * 20, "0x12345678")
        assert len(result) == 32
        # Should have been called with confirmed block = 100 - CONFIRMATION_DEPTH
        call_args = mock_w3.eth.call.call_args
        # call_args is ((tx_dict, block_id), {}) — positional args
        confirmed_block = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("block_identifier")
        from chain import CONFIRMATION_DEPTH
        assert confirmed_block == max(0, 100 - CONFIRMATION_DEPTH)

    def test_eth_call_finalized_fallback_on_error(self):
        from chain import Chain

        chain = Chain.__new__(Chain)
        chain.endpoint = "mock"
        mock_w3 = MagicMock()
        mock_w3.eth.block_number = 100
        # First call (finalized) raises, second (latest) succeeds
        mock_w3.eth.call.side_effect = [Exception("not found"), b"\x02" * 32]
        chain.w3 = mock_w3

        result = chain.eth_call_finalized("0x" + "AA" * 20, "0x12345678")
        assert result == b"\x02" * 32
        assert mock_w3.eth.call.call_count == 2

    def test_function_selector(self):
        from chain import function_selector
        sel = function_selector("getOperators()")
        assert sel.startswith("0x")
        assert len(sel) == 10  # 0x + 8 hex chars

    def test_encode_uint256(self):
        from chain import encode_uint256
        assert len(encode_uint256(42)) == 64
        assert encode_uint256(0) == "0" * 64

    def test_encode_address(self):
        from chain import encode_address
        enc = encode_address("0xAbCd1234567890ABcDeF1234567890aBCdEf1234")
        assert len(enc) == 64
        assert "0x" not in enc


# =============================================================================
# Clock Skew Protection (DataStore)
# =============================================================================


class TestClockSkewProtection:
    def test_future_record_rejected(self, monkeypatch):
        monkeypatch.setattr(config, "IN_ENCLAVE", False)
        monkeypatch.setattr(config, "MAX_CLOCK_SKEW_MS", 5000)
        from data_store import DataRecord, DataStore, VectorClock

        ds = DataStore(node_id="n")
        far_future = int(time.time() * 1000) + 999_999
        rec = DataRecord(key="k", value=b"v", version=VectorClock({"peer": 1}),
                         updated_at_ms=far_future, tombstone=False, ttl_ms=0)
        merged = ds.merge_record(42, rec)
        assert not merged

    def test_normal_skew_accepted(self, monkeypatch):
        monkeypatch.setattr(config, "IN_ENCLAVE", False)
        monkeypatch.setattr(config, "MAX_CLOCK_SKEW_MS", 30000)
        from data_store import DataRecord, DataStore, VectorClock

        ds = DataStore(node_id="n")
        now_ms = int(time.time() * 1000) + 1000  # 1 second ahead
        rec = DataRecord(key="k", value=b"v", version=VectorClock({"peer": 1}),
                         updated_at_ms=now_ms, tombstone=False, ttl_ms=0)
        merged = ds.merge_record(42, rec)
        assert merged


# =============================================================================
# Nonce Store Eviction (MAX_NONCES)
# =============================================================================


class TestNonceStoreEviction:
    def test_eviction_under_pressure(self, monkeypatch):
        from auth import _NonceStore

        store = _NonceStore(max_nonces=5)
        nonces = []
        for _ in range(6):
            n = store.issue()
            nonces.append(n)

        # The oldest nonce should have been evicted
        assert not store.validate_and_consume(nonces[0])
        # Recent nonces should still be valid
        assert store.validate_and_consume(nonces[-1])


# =============================================================================
# CachedNovaRegistry TTL
# =============================================================================


class TestCachedNovaRegistryTTL:
    def test_cache_returns_without_calling_inner(self, monkeypatch):
        monkeypatch.setattr(config, "REGISTRY_CACHE_TTL_SECONDS", 60)
        from nova_registry import CachedNovaRegistry

        inner = MagicMock()
        inner.get_app.return_value = MagicMock(app_id=1, status=1)
        cached = CachedNovaRegistry(inner)

        cached.get_app(1)
        cached.get_app(1)
        # Should have called the inner only once
        assert inner.get_app.call_count == 1

    def test_cache_expires(self, monkeypatch):
        from nova_registry import CachedNovaRegistry

        inner = MagicMock()
        inner.get_app.return_value = MagicMock(app_id=1, status=1)
        cached = CachedNovaRegistry(inner, ttl=0)

        cached.get_app(1)
        time.sleep(0.01)
        cached.get_app(1)
        assert inner.get_app.call_count == 2


# =============================================================================
# Probe helpers
# =============================================================================


class TestProbe:
    def test_probe_node_success(self):
        from probe import probe_node
        with patch("probe.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            assert probe_node("http://localhost:4000") is True

    def test_probe_node_failure(self):
        from probe import probe_node
        with patch("probe.requests.get", side_effect=ConnectionError):
            assert probe_node("http://localhost:4000") is False

    def test_probe_nodes(self):
        from probe import probe_nodes
        nodes = [
            {"node_url": "http://a:8000", "tee_wallet_address": "0xA"},
            {"node_url": "http://b:8000", "tee_wallet_address": "0xB"},
        ]
        with patch("probe.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            results = probe_nodes(nodes)
        assert len(results) == 2
        assert all(r["healthy"] for r in results)
        assert all("probe_ms" in r for r in results)

    def test_find_healthy_peer(self):
        from probe import find_healthy_peer
        nodes = [
            {"node_url": "http://a:8000", "tee_wallet_address": "0xA"},
            {"node_url": "http://b:8000", "tee_wallet_address": "0xB"},
        ]
        with patch("probe.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            peer = find_healthy_peer(nodes, exclude_wallet="0xA")
        assert peer["tee_wallet_address"] == "0xB"
