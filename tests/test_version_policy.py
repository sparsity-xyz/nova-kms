import pytest
from unittest.mock import MagicMock
from auth import AppAuthorizer, ClientIdentity, AuthResult
from nova_registry import AppStatus, InstanceStatus, VersionStatus, App, AppVersion, RuntimeInstance

@pytest.fixture
def mock_registry():
    return MagicMock()

@pytest.fixture
def authorizer(mock_registry):
    return AppAuthorizer(registry=mock_registry)

def test_authorizer_allows_enrolled(authorizer, mock_registry):
    mock_registry.get_instance_by_wallet.return_value = RuntimeInstance(
        instance_id=1, app_id=42, version_id=1, operator="0xOp", instance_url="",
        tee_pubkey=b"", tee_wallet_address="0xApp", zk_verified=True, status=InstanceStatus.ACTIVE, registered_at=0
    )
    mock_registry.get_app.return_value = App(
        app_id=42, owner="0xOwn", tee_arch=b"", dapp_contract="", metadata_uri="",
        latest_version_id=1, created_at=0, status=AppStatus.ACTIVE
    )
    mock_registry.get_version.return_value = AppVersion(
        version_id=1, version_name="v1", code_measurement=b"", image_uri="", audit_url="",
        audit_hash="", github_run_id="", status=VersionStatus.ENROLLED, enrolled_at=0, enrolled_by=""
    )
    
    identity = ClientIdentity(tee_wallet="0xApp")
    result = authorizer.verify(identity)
    assert result.authorized is True

def test_authorizer_allows_deprecated(authorizer, mock_registry):
    mock_registry.get_instance_by_wallet.return_value = RuntimeInstance(
        instance_id=1, app_id=42, version_id=1, operator="0xOp", instance_url="",
        tee_pubkey=b"", tee_wallet_address="0xApp", zk_verified=True, status=InstanceStatus.ACTIVE, registered_at=0
    )
    mock_registry.get_app.return_value = App(
        app_id=42, owner="0xOwn", tee_arch=b"", dapp_contract="", metadata_uri="",
        latest_version_id=1, created_at=0, status=AppStatus.ACTIVE
    )
    mock_registry.get_version.return_value = AppVersion(
        version_id=1, version_name="v1", code_measurement=b"", image_uri="", audit_url="",
        audit_hash="", github_run_id="", status=VersionStatus.DEPRECATED, enrolled_at=0, enrolled_by=""
    )
    
    identity = ClientIdentity(tee_wallet="0xApp")
    result = authorizer.verify(identity)
    assert result.authorized is True

def test_authorizer_rejects_revoked(authorizer, mock_registry):
    mock_registry.get_instance_by_wallet.return_value = RuntimeInstance(
        instance_id=1, app_id=42, version_id=1, operator="0xOp", instance_url="",
        tee_pubkey=b"", tee_wallet_address="0xApp", zk_verified=True, status=InstanceStatus.ACTIVE, registered_at=0
    )
    mock_registry.get_app.return_value = App(
        app_id=42, owner="0xOwn", tee_arch=b"", dapp_contract="", metadata_uri="",
        latest_version_id=1, created_at=0, status=AppStatus.ACTIVE
    )
    mock_registry.get_version.return_value = AppVersion(
        version_id=1, version_name="v1", code_measurement=b"", image_uri="", audit_url="",
        audit_hash="", github_run_id="", status=VersionStatus.REVOKED, enrolled_at=0, enrolled_by=""
    )
    
    identity = ClientIdentity(tee_wallet="0xApp")
    result = authorizer.verify(identity)
    assert result.authorized is False
    assert "revoked" in result.reason.lower()
