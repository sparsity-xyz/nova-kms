"""
Tests for auth.py — Authentication + Authorization.

Covers:
  - identity_from_headers (dev mode)
  - identity_from_headers blocked in production
  - _NonceStore (issue, validate, replay, expiry, capacity)
  - AppAuthorizer.verify (all authorization steps and branches)
  - authenticate_app (production vs dev routing)
  - verify_wallet_signature / recover_wallet_from_signature
  - _require_fresh_timestamp
"""

import time
import pytest
from unittest.mock import MagicMock, patch

from auth import (
    AppAuthorizer,
    AuthResult,
    ClientIdentity,
    _NonceStore,
    _require_fresh_timestamp,
    authenticate_app,
    identity_from_headers,
    issue_nonce,
    recover_wallet_from_signature,
    verify_wallet_signature,
)
from nova_registry import (
    App,
    AppStatus,
    AppVersion,
    InstanceStatus,
    NovaRegistry,
    RuntimeInstance,
    VersionStatus,
)


# =============================================================================
# Fixtures
# =============================================================================

def _make_instance(
    *,
    instance_id=1,
    app_id=100,
    version_id=1,
    status=InstanceStatus.ACTIVE,
    zk_verified=True,
    wallet="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
) -> RuntimeInstance:
    return RuntimeInstance(
        instance_id=instance_id,
        app_id=app_id,
        version_id=version_id,
        operator="0x0000000000000000000000000000000000000000",
        instance_url="https://app.example.com",
        tee_pubkey=b"\x04" * 65,
        tee_wallet_address=wallet,
        zk_verified=zk_verified,
        status=status,
        registered_at=1700000000,
    )


def _make_app(*, app_id=100, status=AppStatus.ACTIVE) -> App:
    return App(
        app_id=app_id,
        owner="0x0000000000000000000000000000000000000000",
        tee_arch=b"\x00" * 32,
        dapp_contract="0x0000000000000000000000000000000000000000",
        metadata_uri="",
        latest_version_id=1,
        created_at=1700000000,
        status=status,
        app_wallet="0x0000000000000000000000000000000000000000",
    )


def _make_version(
    *, version_id=1, status=VersionStatus.ENROLLED
) -> AppVersion:
    return AppVersion(
        version_id=version_id,
        version_name="v1.0",
        code_measurement=b"\xab" * 32,
        image_uri="",
        audit_url="",
        audit_hash="",
        github_run_id="",
        status=status,
        enrolled_at=1700000000,
        enrolled_by="0x0000000000000000000000000000000000000000",
    )


def _mock_registry(instance=None, app=None, version=None) -> MagicMock:
    reg = MagicMock(spec=NovaRegistry)
    if instance is not None:
        reg.get_instance_by_wallet.return_value = instance
    if app is not None:
        reg.get_app.return_value = app
    if version is not None:
        reg.get_version.return_value = version
    return reg


# =============================================================================
# identity_from_headers
# =============================================================================


class TestIdentityFromHeaders:
    def test_basic(self):
        with patch("auth.config.IN_ENCLAVE", False):
            att = identity_from_headers({"x-tee-wallet": "0xABCD"})
            assert att.tee_wallet == "0xabcd"

    def test_missing_headers(self):
        with patch("auth.config.IN_ENCLAVE", False):
            att = identity_from_headers({})
            assert att.tee_wallet == ""


    def test_disabled_in_production(self):
        """When IN_ENCLAVE is True, header-based identity should be disabled."""
        with patch("auth.config.IN_ENCLAVE", True):
            with pytest.raises(RuntimeError, match="disabled in production"):
                identity_from_headers({"x-tee-wallet": "0xAA"})


# =============================================================================
# _NonceStore
# =============================================================================


class TestNonceStore:
    def test_issue_returns_bytes(self):
        store = _NonceStore(ttl_seconds=60)
        nonce = store.issue()
        assert isinstance(nonce, bytes)
        assert len(nonce) == 16

    def test_validate_and_consume(self):
        store = _NonceStore(ttl_seconds=60)
        nonce = store.issue()
        assert store.validate_and_consume(nonce) is True

    def test_replay_rejected(self):
        store = _NonceStore(ttl_seconds=60)
        nonce = store.issue()
        store.validate_and_consume(nonce)
        # Second use is rejected
        assert store.validate_and_consume(nonce) is False

    def test_expired_nonce_rejected(self):
        store = _NonceStore(ttl_seconds=0)  # instant expiry
        nonce = store.issue()
        time.sleep(0.01)
        assert store.validate_and_consume(nonce) is False

    def test_none_nonce_rejected(self):
        store = _NonceStore(ttl_seconds=60)
        assert store.validate_and_consume(None) is False

    def test_unknown_nonce_rejected(self):
        store = _NonceStore(ttl_seconds=60)
        assert store.validate_and_consume(b"unknown_nonce_00") is False

    def test_max_capacity_evicts_oldest(self):
        store = _NonceStore(ttl_seconds=60, max_nonces=2)
        n1 = store.issue()
        n2 = store.issue()
        n3 = store.issue()
        # n1 should have been evicted
        assert store.validate_and_consume(n1) is False
        assert store.validate_and_consume(n3) is True

    def test_issue_nonce_global(self):
        """issue_nonce() returns a fresh nonce from the global store."""
        n = issue_nonce()
        assert isinstance(n, bytes)
        assert len(n) == 16


# =============================================================================
# AppAuthorizer
# =============================================================================


class TestAppAuthorizer:
    def test_success(self):
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)

        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert result.authorized
        assert result.app_id == 100
        assert result.version_id == 1

    def test_missing_wallet(self):
        reg = _mock_registry()
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=""))
        assert not result.authorized
        assert "Missing" in result.reason

    def test_instance_not_found_zero_id(self):
        inst = _make_instance(instance_id=0)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet="0x1234"))
        assert not result.authorized
        assert "not found" in result.reason

    def test_instance_lookup_exception(self):
        reg = MagicMock(spec=NovaRegistry)
        reg.get_instance_by_wallet.side_effect = Exception("RPC error")
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet="0x1234"))
        assert not result.authorized
        assert "not found" in result.reason

    def test_instance_not_active(self):
        inst = _make_instance(status=InstanceStatus.STOPPED)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "not active" in result.reason

    def test_instance_failed(self):
        inst = _make_instance(status=InstanceStatus.FAILED)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized

    def test_instance_not_zk_verified(self):
        inst = _make_instance(zk_verified=False)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "zkVerified" in result.reason

    def test_app_not_active(self):
        inst = _make_instance()
        app_obj = _make_app(status=AppStatus.REVOKED)
        reg = _mock_registry(instance=inst, app=app_obj)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "App not active" in result.reason

    def test_app_inactive(self):
        inst = _make_instance()
        app_obj = _make_app(status=AppStatus.INACTIVE)
        reg = _mock_registry(instance=inst, app=app_obj)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized

    def test_app_lookup_exception(self):
        inst = _make_instance()
        reg = MagicMock(spec=NovaRegistry)
        reg.get_instance_by_wallet.return_value = inst
        reg.get_app.side_effect = Exception("RPC error")
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "lookup failed" in result.reason

    def test_version_revoked(self):
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version(status=VersionStatus.REVOKED)
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "revoked" in result.reason

    def test_deprecated_version_accepted(self):
        """DEPRECATED versions are allowed for existing instances."""
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version(status=VersionStatus.DEPRECATED)
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert result.authorized

    def test_version_lookup_exception(self):
        inst = _make_instance()
        app_obj = _make_app()
        reg = MagicMock(spec=NovaRegistry)
        reg.get_instance_by_wallet.return_value = inst
        reg.get_app.return_value = app_obj
        reg.get_version.side_effect = Exception("RPC error")
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "lookup failed" in result.reason

    def test_returns_tee_pubkey(self):
        """Successful auth returns the app's teePubkey for E2E encryption."""
        inst = _make_instance()
        inst.tee_pubkey = b"\x04" + b"\xAB" * 96  # 97 bytes P-384 uncompressed
        app_obj = _make_app()
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert result.authorized
        assert result.tee_pubkey == inst.tee_pubkey

    def test_require_app_id_success(self):
        """require_app_id=100 should accept instance with app_id=100."""
        inst = _make_instance(app_id=100)
        app_obj = _make_app(app_id=100)
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg, require_app_id=100)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert result.authorized
        assert result.app_id == 100

    def test_require_app_id_mismatch(self):
        """require_app_id=100 should reject instance with app_id=200."""
        inst = _make_instance(app_id=200)
        app_obj = _make_app(app_id=200)
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg, require_app_id=100)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert not result.authorized
        assert "app_id 200 != required 100" in result.reason

    def test_require_app_id_zero_accepts_any(self):
        """require_app_id=0 (default) should accept any valid app."""
        inst = _make_instance(app_id=999)
        app_obj = _make_app(app_id=999)
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg, require_app_id=0)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert result.authorized
        assert result.app_id == 999

    def test_kms_peer_authorization(self):
        """KMS peer authorization uses require_app_id=KMS_APP_ID."""
        import config
        kms_app_id = config.KMS_APP_ID
        inst = _make_instance(app_id=kms_app_id)
        app_obj = _make_app(app_id=kms_app_id)
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg, require_app_id=kms_app_id)
        result = auth.verify(ClientIdentity(tee_wallet=inst.tee_wallet_address))
        assert result.authorized
        assert result.app_id == kms_app_id


# =============================================================================
# Signature helpers
# =============================================================================


class TestSignatureHelpers:
    def test_verify_wallet_signature_valid(self):
        from eth_account import Account
        from eth_account.messages import encode_defunct

        acct = Account.create()
        msg = "test message"
        sig = acct.sign_message(encode_defunct(text=msg))
        assert verify_wallet_signature(acct.address, msg, sig.signature.hex()) is True

    def test_verify_wallet_signature_wrong_wallet(self):
        from eth_account import Account
        from eth_account.messages import encode_defunct

        acct = Account.create()
        other = Account.create()
        msg = "test message"
        sig = acct.sign_message(encode_defunct(text=msg))
        assert verify_wallet_signature(other.address, msg, sig.signature.hex()) is False

    def test_verify_wallet_signature_empty(self):
        assert verify_wallet_signature("", "msg", "sig") is False
        assert verify_wallet_signature("0xAA", "msg", "") is False
        assert verify_wallet_signature("0xAA", "", "sig") is False

    def test_recover_wallet_from_signature(self):
        from eth_account import Account
        from eth_account.messages import encode_defunct

        acct = Account.create()
        msg = "test recovery"
        sig = acct.sign_message(encode_defunct(text=msg))
        recovered = recover_wallet_from_signature(msg, sig.signature.hex())
        assert recovered.lower() == acct.address.lower()

    def test_recover_returns_none_on_empty(self):
        assert recover_wallet_from_signature("msg", "") is None
        assert recover_wallet_from_signature("", "sig") is None


# =============================================================================
# Timestamp freshness
# =============================================================================


class TestTimestampFreshness:
    def test_fresh_timestamp_ok(self):
        _require_fresh_timestamp(str(int(time.time())))

    def test_stale_timestamp_raises(self):
        old = str(int(time.time()) - 300)
        with pytest.raises(RuntimeError, match="Stale"):
            _require_fresh_timestamp(old)

    def test_future_timestamp_raises(self):
        future = str(int(time.time()) + 300)
        with pytest.raises(RuntimeError, match="Stale"):
            _require_fresh_timestamp(future)

    def test_missing_timestamp_raises(self):
        with pytest.raises(RuntimeError, match="Missing"):
            _require_fresh_timestamp("")

    def test_invalid_timestamp_raises(self):
        with pytest.raises(RuntimeError, match="Invalid"):
            _require_fresh_timestamp("not_a_number")


# =============================================================================
# authenticate_app
# =============================================================================


class TestAuthenticateApp:
    def test_dev_mode_uses_headers(self):
        with patch("auth.config.IN_ENCLAVE", False):
            req = MagicMock()
            headers = {"x-tee-wallet": "0xDEV"}
            result = authenticate_app(req, headers)
            assert result.tee_wallet == "0xdev"

    def test_production_mode_requires_pop(self):
        with patch("auth.config.IN_ENCLAVE", True):
            req = MagicMock()
            req.headers = {}  # empty dict — no PoP headers present
            with pytest.raises(RuntimeError):
                authenticate_app(req, {})
