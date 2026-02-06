"""
Tests for auth.py — AppAuthorizer and KMSNodeVerifier.

Uses mocked NovaRegistry / KMSRegistryClient to avoid on-chain calls.
"""

import pytest
from unittest.mock import MagicMock, patch

from auth import AppAuthorizer, ClientAttestation, KMSNodeVerifier, attestation_from_headers
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
    )


def _make_version(
    *, version_id=1, status=VersionStatus.ENROLLED, measurement=b"\xab" * 32
) -> AppVersion:
    return AppVersion(
        version_id=version_id,
        version_name="v1.0",
        code_measurement=measurement,
        image_uri="",
        audit_url="",
        audit_hash="",
        github_run_id="",
        status=status,
        enrolled_at=1700000000,
        enrolled_by="0x0000000000000000000000000000000000000000",
    )


def _mock_registry(
    instance=None, app=None, version=None
) -> MagicMock:
    reg = MagicMock(spec=NovaRegistry)
    if instance is not None:
        reg.get_instance_by_wallet.return_value = instance
    if app is not None:
        reg.get_app.return_value = app
    if version is not None:
        reg.get_version.return_value = version
    return reg


# =============================================================================
# attestation_from_headers
# =============================================================================


class TestAttestationFromHeaders:
    def test_basic(self):
        att = attestation_from_headers({
            "x-tee-wallet": "0xABCD",
            "x-tee-measurement": "ab" * 32,
        })
        assert att.tee_wallet == "0xABCD"
        assert att.measurement == b"\xab" * 32

    def test_missing_headers(self):
        att = attestation_from_headers({})
        assert att.tee_wallet == ""
        assert att.measurement is None


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

        att = ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=ver.code_measurement)
        result = auth.verify(att)
        assert result.authorized
        assert result.app_id == 100

    def test_missing_wallet(self):
        reg = _mock_registry()
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet="", measurement=None))
        assert not result.authorized
        assert "Missing" in result.reason

    def test_instance_not_found(self):
        inst = _make_instance(instance_id=0)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet="0x1234", measurement=None))
        assert not result.authorized
        assert "not found" in result.reason

    def test_instance_not_active(self):
        inst = _make_instance(status=InstanceStatus.STOPPED)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=None))
        assert not result.authorized
        assert "not active" in result.reason

    def test_instance_not_zk_verified(self):
        inst = _make_instance(zk_verified=False)
        reg = _mock_registry(instance=inst)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=None))
        assert not result.authorized
        assert "zkVerified" in result.reason

    def test_app_not_active(self):
        inst = _make_instance()
        app_obj = _make_app(status=AppStatus.REVOKED)
        reg = _mock_registry(instance=inst, app=app_obj)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=None))
        assert not result.authorized
        assert "App not active" in result.reason

    def test_version_revoked(self):
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version(status=VersionStatus.REVOKED)
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=None))
        assert not result.authorized
        assert "not allowed" in result.reason

    def test_measurement_mismatch(self):
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version(measurement=b"\xab" * 32)
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)

        wrong = b"\xff" * 32
        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=wrong))
        assert not result.authorized
        assert "mismatch" in result.reason

    def test_skip_measurement_if_none(self):
        """If client doesn't provide measurement, skip that check."""
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version()
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)

        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=None))
        assert result.authorized

    def test_deprecated_version_ok(self):
        inst = _make_instance()
        app_obj = _make_app()
        ver = _make_version(status=VersionStatus.DEPRECATED)
        reg = _mock_registry(instance=inst, app=app_obj, version=ver)
        auth = AppAuthorizer(registry=reg)
        result = auth.verify(ClientAttestation(tee_wallet=inst.tee_wallet_address, measurement=None))
        assert result.authorized


# =============================================================================
# KMSNodeVerifier
# =============================================================================


class TestKMSNodeVerifier:
    def test_valid_peer(self):
        mock_client = MagicMock()
        mock_client.is_operator.return_value = True
        verifier = KMSNodeVerifier(kms_registry_client=mock_client)
        ok, reason = verifier.verify_peer("0xBBBB")
        assert ok
        assert reason is None

    def test_non_operator_peer(self):
        mock_client = MagicMock()
        mock_client.is_operator.return_value = False
        verifier = KMSNodeVerifier(kms_registry_client=mock_client)
        ok, reason = verifier.verify_peer("0xCCCC")
        assert not ok
        assert "not a registered" in reason.lower()

    def test_missing_wallet(self):
        verifier = KMSNodeVerifier(kms_registry_client=MagicMock())
        ok, reason = verifier.verify_peer("")
        assert not ok
