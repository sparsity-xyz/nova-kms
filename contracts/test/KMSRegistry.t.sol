// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract KMSRegistryTest is Test {
    KMSRegistry public implementation;
    KMSRegistry public registry; // This will be the proxy cast to KMSRegistry

    address public mockAppRegistry = address(0xABCD);
    address public admin = address(0xAD);
    address public kmsWallet1 = address(0x1001);
    address public kmsWallet2 = address(0x1002);
    address public kmsWallet3 = address(0x1003);
    address public randomUser = address(0x9999);

    uint256 public constant KMS_APP_ID = 42;

    function setUp() public {
        // 1. Deploy Implementation
        implementation = new KMSRegistry();

        // 2. Deploy Proxy and Initialize
        bytes memory initData = abi.encodeCall(
            KMSRegistry.initialize,
            (admin, mockAppRegistry, KMS_APP_ID)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );

        // 3. Cast Proxy to KMSRegistry for testing
        registry = KMSRegistry(address(proxy));
    }

    // ========== Helper ==========

    function _addOperator(address wallet, uint256 instanceId) internal {
        vm.prank(mockAppRegistry);
        registry.addOperator(wallet, KMS_APP_ID, 1, instanceId);
    }

    // ========== Initialization Tests ==========

    function test_initialize_setsState() public view {
        assertEq(registry.novaAppRegistry(), mockAppRegistry);
        assertEq(registry.kmsAppId(), KMS_APP_ID);
        assertEq(registry.owner(), admin);
        assertEq(registry.operatorCount(), 0);
    }

    function test_initialize_revert_alreadyInitialized() public {
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        registry.initialize(admin, mockAppRegistry, KMS_APP_ID);
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
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                randomUser
            )
        );
        registry.setNovaAppRegistry(address(0xBEEF));
    }

    // ========== addOperator Tests ==========

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

    // ========== removeOperator Tests ==========

    function test_removeOperator_success() public {
        _addOperator(kmsWallet1, 100);
        assertTrue(registry.isOperator(kmsWallet1));

        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);

        assertFalse(registry.isOperator(kmsWallet1));
        assertEq(registry.operatorCount(), 0);
    }

    // ========== Admin/Ownership Tests ==========

    function test_transferOwnership() public {
        vm.prank(admin);
        registry.transferOwnership(randomUser);
        // Ownable2Step requires acceptance
        vm.prank(randomUser);
        registry.acceptOwnership();
        assertEq(registry.owner(), randomUser);
    }

    function test_upgrade_authorized() public {
        KMSRegistry newImp = new KMSRegistry();
        vm.prank(admin);
        registry.upgradeToAndCall(address(newImp), "");
    }

    function test_upgrade_revert_unauthorized() public {
        KMSRegistry newImp = new KMSRegistry();
        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                randomUser
            )
        );
        registry.upgradeToAndCall(address(newImp), "");
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
