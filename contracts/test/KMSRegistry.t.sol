// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";
import {INovaAppRegistryView} from "../src/interfaces/INovaAppRegistryView.sol";

contract MockNovaAppRegistryView is INovaAppRegistryView {
    mapping(address => RuntimeInstance) internal _instances;
    mapping(uint256 => mapping(uint256 => AppVersion)) internal _versions;

    bool internal _revertInstance;
    bool internal _revertVersion;

    function setInstance(
        address wallet,
        uint256 instanceId,
        uint256 appId,
        uint256 versionId,
        InstanceStatus status_
    ) external {
        _instances[wallet] = RuntimeInstance({
            instanceId: instanceId,
            appId: appId,
            versionId: versionId,
            operator: wallet,
            instanceUrl: "",
            teePubkey: "",
            teeWalletAddress: wallet,
            zkVerified: true,
            status: status_,
            registeredAt: block.timestamp
        });
    }

    function setVersion(
        uint256 appId,
        uint256 versionId,
        VersionStatus status_
    ) external {
        _versions[appId][versionId] = AppVersion({
            versionId: versionId,
            versionName: "v1",
            codeMeasurement: bytes32(0),
            imageUri: "",
            auditUrl: "",
            auditHash: "",
            githubRunId: "",
            status: status_,
            enrolledAt: block.timestamp,
            enrolledBy: address(this)
        });
    }

    function setRevertFlags(bool revertInstance, bool revertVersion) external {
        _revertInstance = revertInstance;
        _revertVersion = revertVersion;
    }

    function getApp(uint256) external pure returns (App memory) {
        revert("unused");
    }

    function getVersion(
        uint256 appId,
        uint256 versionId
    ) external view returns (AppVersion memory) {
        if (_revertVersion) revert("version revert");
        return _versions[appId][versionId];
    }

    function getInstanceByWallet(
        address wallet
    ) external view returns (RuntimeInstance memory) {
        if (_revertInstance) revert("instance revert");
        return _instances[wallet];
    }
}

contract KMSRegistryTest is Test {
    KMSRegistry public registry;
    MockNovaAppRegistryView public mockRegistryView;

    address public mockAppRegistry;
    address public admin = address(0xAD);
    address public kmsWallet1 = address(0x1001);
    address public kmsWallet2 = address(0x1002);
    address public kmsWallet3 = address(0x1003);
    address public randomUser = address(0x9999);

    uint256 public constant KMS_APP_ID = 42;

    function setUp() public {
        mockRegistryView = new MockNovaAppRegistryView();
        mockAppRegistry = address(mockRegistryView);

        registry = new KMSRegistry(admin, mockAppRegistry);
        vm.prank(admin);
        registry.setKmsAppId(KMS_APP_ID);

        mockRegistryView.setVersion(
            KMS_APP_ID,
            1,
            INovaAppRegistryView.VersionStatus.ENROLLED
        );
    }

    // ========== Helpers ==========

    function _addOperator(address wallet, uint256 instanceId) internal {
        vm.prank(mockAppRegistry);
        registry.addOperator(wallet, KMS_APP_ID, 1, instanceId);
    }

    function _setEligibleHashSetter(address wallet, uint256 instanceId) internal {
        mockRegistryView.setInstance(
            wallet,
            instanceId,
            KMS_APP_ID,
            1,
            INovaAppRegistryView.InstanceStatus.ACTIVE
        );
    }

    // ========== Initialization Tests ==========

    function test_constructor_setsState() public view {
        assertEq(registry.novaAppRegistry(), mockAppRegistry);
        assertEq(registry.kmsAppId(), KMS_APP_ID);
        assertEq(registry.OWNER(), admin);
        assertEq(registry.operatorCount(), 0);
    }

    // ========== setNovaAppRegistry Tests ==========

    function test_setNovaAppRegistry_byOwner() public {
        address newRegistry = address(0xBEEF);
        vm.prank(admin);
        registry.setNovaAppRegistry(newRegistry);
        assertEq(registry.novaAppRegistry(), newRegistry);
    }

    function test_setNovaAppRegistry_revert_notOwner() public {
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("NotOwner()"));
        registry.setNovaAppRegistry(address(0xBEEF));
    }

    // ========== setKmsAppId Tests ==========

    function test_setKmsAppId_revert_alreadySet() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSignature("AppIdAlreadySet()"));
        registry.setKmsAppId(999);
    }

    function test_setKmsAppId_revert_notOwner() public {
        KMSRegistry freshRegistry = new KMSRegistry(admin, mockAppRegistry);
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("NotOwner()"));
        freshRegistry.setKmsAppId(999);
    }

    // ========== addOperator / removeOperator Tests ==========

    function test_addOperator_success() public {
        _addOperator(kmsWallet1, 100);

        assertTrue(registry.isOperator(kmsWallet1));
        assertEq(registry.operatorCount(), 1);
        assertEq(registry.operatorAt(0), kmsWallet1);
    }

    function test_addOperator_emitsEvent() public {
        vm.prank(mockAppRegistry);
        vm.expectEmit(true, false, false, true);
        emit KMSRegistry.OperatorAdded(kmsWallet1, KMS_APP_ID, 1, 100);
        registry.addOperator(kmsWallet1, KMS_APP_ID, 1, 100);
    }

    function test_addOperator_revert_appIdMismatch() public {
        vm.prank(mockAppRegistry);
        vm.expectRevert(abi.encodeWithSignature("AppIdMismatch()"));
        registry.addOperator(kmsWallet1, KMS_APP_ID + 1, 1, 100);
    }

    function test_removeOperator_success() public {
        _addOperator(kmsWallet1, 100);
        assertTrue(registry.isOperator(kmsWallet1));

        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);

        assertFalse(registry.isOperator(kmsWallet1));
        assertEq(registry.operatorCount(), 0);
    }

    function test_removeOperator_revert_appIdMismatch() public {
        _addOperator(kmsWallet1, 100);
        vm.prank(mockAppRegistry);
        vm.expectRevert(abi.encodeWithSignature("AppIdMismatch()"));
        registry.removeOperator(kmsWallet1, KMS_APP_ID + 1, 1, 100);
    }

    // ========== Master Secret Hash Tests ==========

    function test_setMasterSecretHash_success_forEligibleNode() public {
        _setEligibleHashSetter(kmsWallet1, 100);
        bytes32 hash = keccak256("secret");

        vm.prank(kmsWallet1);
        registry.setMasterSecretHash(hash);

        assertEq(registry.masterSecretHash(), hash);
    }

    function test_setMasterSecretHash_revert_notAuthorized() public {
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("NotAuthorizedToSetHash()"));
        registry.setMasterSecretHash(keccak256("secret"));
    }

    function test_setMasterSecretHash_revert_alreadySet() public {
        _setEligibleHashSetter(kmsWallet1, 100);
        bytes32 hash = keccak256("secret");

        vm.prank(kmsWallet1);
        registry.setMasterSecretHash(hash);

        vm.prank(kmsWallet1);
        vm.expectRevert(abi.encodeWithSignature("MasterSecretHashAlreadySet()"));
        registry.setMasterSecretHash(hash);
    }

    function test_setMasterSecretHash_revert_when_version_not_enrolled() public {
        _setEligibleHashSetter(kmsWallet1, 100);
        mockRegistryView.setVersion(
            KMS_APP_ID,
            1,
            INovaAppRegistryView.VersionStatus.DEPRECATED
        );

        vm.prank(kmsWallet1);
        vm.expectRevert(abi.encodeWithSignature("NotAuthorizedToSetHash()"));
        registry.setMasterSecretHash(keccak256("secret"));
    }

    function test_resetMasterSecretHash_byOwner() public {
        _setEligibleHashSetter(kmsWallet1, 100);
        bytes32 hash = keccak256("secret");

        vm.prank(kmsWallet1);
        registry.setMasterSecretHash(hash);
        assertEq(registry.masterSecretHash(), hash);

        vm.prank(admin);
        registry.resetMasterSecretHash();
        assertEq(registry.masterSecretHash(), bytes32(0));
    }

    function test_resetMasterSecretHash_revert_notOwner() public {
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("NotOwner()"));
        registry.resetMasterSecretHash();
    }

    // ========== View Tests ==========

    function test_getOperators_empty() public view {
        address[] memory ops = registry.getOperators();
        assertEq(ops.length, 0);
    }

    // ========== Full Lifecycle Test ==========

    function test_fullLifecycle() public {
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet2, 101);
        _addOperator(kmsWallet3, 102);
        assertEq(registry.operatorCount(), 3);

        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet2, KMS_APP_ID, 1, 101);
        assertEq(registry.operatorCount(), 2);
        assertFalse(registry.isOperator(kmsWallet2));

        assertTrue(registry.isOperator(kmsWallet1));
        assertTrue(registry.isOperator(kmsWallet3));
    }
}
