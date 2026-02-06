// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import "forge-std/Test.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";
import {INovaAppInterface} from "../src/interfaces/INovaAppInterface.sol";

contract KMSRegistryTest is Test {
    KMSRegistry public registry;

    address public mockAppRegistry = address(0xABCD);
    address public admin = address(0xAD);
    address public kmsWallet1 = address(0x1001);
    address public kmsWallet2 = address(0x1002);
    address public kmsWallet3 = address(0x1003);
    address public randomUser = address(0x9999);

    uint256 public constant KMS_APP_ID = 42;

    function setUp() public {
        vm.prank(admin);
        registry = new KMSRegistry(mockAppRegistry, KMS_APP_ID);
    }

    // ========== Helper ==========

    function _addOperator(address wallet, uint256 instanceId) internal {
        vm.prank(mockAppRegistry);
        registry.addOperator(wallet, KMS_APP_ID, 1, instanceId);
    }

    // ========== Constructor Tests ==========

    function test_constructor_setsState() public view {
        assertEq(registry.novaAppRegistry(), mockAppRegistry);
        assertEq(registry.kmsAppId(), KMS_APP_ID);
        assertEq(registry.admin(), admin);
        assertEq(registry.operatorCount(), 0);
    }

    function test_constructor_revert_zeroRegistry() public {
        vm.prank(admin);
        vm.expectRevert(KMSRegistry.InvalidRegistryAddress.selector);
        new KMSRegistry(address(0), KMS_APP_ID);
    }

    // ========== setNovaAppRegistry Tests ==========

    function test_setNovaAppRegistry_byAdmin() public {
        address newRegistry = address(0xBEEF);
        vm.prank(admin);
        registry.setNovaAppRegistry(newRegistry);
        assertEq(registry.novaAppRegistry(), newRegistry);
    }

    function test_setNovaAppRegistry_revert_notAdmin() public {
        vm.prank(randomUser);
        vm.expectRevert(KMSRegistry.NotAdmin.selector);
        registry.setNovaAppRegistry(address(0xBEEF));
    }

    function test_setNovaAppRegistry_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(KMSRegistry.InvalidRegistryAddress.selector);
        registry.setNovaAppRegistry(address(0));
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

    function test_addOperator_multipleOperators() public {
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet2, 101);

        assertEq(registry.operatorCount(), 2);

        address[] memory ops = registry.getOperators();
        assertEq(ops.length, 2);
        assertEq(ops[0], kmsWallet1);
        assertEq(ops[1], kmsWallet2);
    }

    function test_addOperator_idempotent() public {
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet1, 100); // duplicate – no-op

        assertEq(registry.operatorCount(), 1);
    }

    function test_addOperator_revert_notRegistry() public {
        vm.prank(randomUser);
        vm.expectRevert(KMSRegistry.OnlyNovaAppRegistry.selector);
        registry.addOperator(kmsWallet1, KMS_APP_ID, 1, 100);
    }

    function test_addOperator_revert_appIdMismatch() public {
        vm.prank(mockAppRegistry);
        vm.expectRevert(KMSRegistry.AppIdMismatch.selector);
        registry.addOperator(kmsWallet1, 999, 1, 100);
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

    function test_removeOperator_emitsEvent() public {
        _addOperator(kmsWallet1, 100);

        vm.prank(mockAppRegistry);
        vm.expectEmit(true, false, false, true);
        emit KMSRegistry.OperatorRemoved(kmsWallet1, KMS_APP_ID, 1, 100);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);
    }

    function test_removeOperator_idempotent() public {
        // Remove non-existent operator – should not revert
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);

        assertFalse(registry.isOperator(kmsWallet1));
    }

    function test_removeOperator_revert_notRegistry() public {
        vm.prank(randomUser);
        vm.expectRevert(KMSRegistry.OnlyNovaAppRegistry.selector);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);
    }

    function test_removeOperator_swapAndPop_preservesOrder() public {
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet2, 101);
        _addOperator(kmsWallet3, 102);

        assertEq(registry.operatorCount(), 3);

        // Remove kmsWallet1 (index 0) – kmsWallet3 (last) should take its place
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);

        assertEq(registry.operatorCount(), 2);
        assertEq(registry.operatorAt(0), kmsWallet3);
        assertEq(registry.operatorAt(1), kmsWallet2);
    }

    function test_removeOperator_removeMiddle() public {
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet2, 101);
        _addOperator(kmsWallet3, 102);

        // Remove middle (index 1)
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet2, KMS_APP_ID, 1, 101);

        assertEq(registry.operatorCount(), 2);
        assertEq(registry.operatorAt(0), kmsWallet1);
        assertEq(registry.operatorAt(1), kmsWallet3);
    }

    function test_removeOperator_removeLast() public {
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet2, 101);

        // Remove last (index 1) – no swap needed
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet2, KMS_APP_ID, 1, 101);

        assertEq(registry.operatorCount(), 1);
        assertEq(registry.operatorAt(0), kmsWallet1);
    }

    // ========== Admin Tests ==========

    function test_setAdmin() public {
        vm.prank(admin);
        registry.setAdmin(randomUser);
        assertEq(registry.admin(), randomUser);
    }

    function test_setAdmin_revert_notAdmin() public {
        vm.prank(randomUser);
        vm.expectRevert(KMSRegistry.NotAdmin.selector);
        registry.setAdmin(randomUser);
    }

    // ========== View Tests ==========

    function test_getOperators_empty() public view {
        address[] memory ops = registry.getOperators();
        assertEq(ops.length, 0);
    }

    function test_operatorAt_revert_outOfBounds() public {
        vm.expectRevert("Index out of bounds");
        registry.operatorAt(0);
    }

    function test_isOperator_false_for_nonOperator() public view {
        assertFalse(registry.isOperator(randomUser));
    }

    // ========== Full Lifecycle Test ==========

    function test_fullLifecycle() public {
        // 1. NovaAppRegistry adds 3 operators
        _addOperator(kmsWallet1, 100);
        _addOperator(kmsWallet2, 101);
        _addOperator(kmsWallet3, 102);
        assertEq(registry.operatorCount(), 3);

        // 2. Verify all are operators
        assertTrue(registry.isOperator(kmsWallet1));
        assertTrue(registry.isOperator(kmsWallet2));
        assertTrue(registry.isOperator(kmsWallet3));

        // 3. getOperators returns all 3
        address[] memory ops = registry.getOperators();
        assertEq(ops.length, 3);

        // 4. Remove one (instance stopped)
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet2, KMS_APP_ID, 1, 101);
        assertEq(registry.operatorCount(), 2);
        assertFalse(registry.isOperator(kmsWallet2));

        // 5. Remaining operators still valid
        assertTrue(registry.isOperator(kmsWallet1));
        assertTrue(registry.isOperator(kmsWallet3));

        // 6. Re-add same wallet (re-registered instance)
        _addOperator(kmsWallet2, 201);
        assertEq(registry.operatorCount(), 3);
        assertTrue(registry.isOperator(kmsWallet2));

        // 7. Remove all
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet1, KMS_APP_ID, 1, 100);
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet2, KMS_APP_ID, 1, 201);
        vm.prank(mockAppRegistry);
        registry.removeOperator(kmsWallet3, KMS_APP_ID, 1, 102);
        assertEq(registry.operatorCount(), 0);
    }

    // ========== setNovaAppRegistry changes the caller gate ==========

    function test_addOperator_afterRegistryChange() public {
        // Change registry address
        address newRegistry = address(0xBEEF);
        vm.prank(admin);
        registry.setNovaAppRegistry(newRegistry);

        // Old registry can no longer add
        vm.prank(mockAppRegistry);
        vm.expectRevert(KMSRegistry.OnlyNovaAppRegistry.selector);
        registry.addOperator(kmsWallet1, KMS_APP_ID, 1, 100);

        // New registry can
        vm.prank(newRegistry);
        registry.addOperator(kmsWallet1, KMS_APP_ID, 1, 100);
        assertTrue(registry.isOperator(kmsWallet1));
    }
}
