// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";

/**
 * @title DeployKMSRegistry
 * @notice Deploys the KMSRegistry contract (implements INovaAppInterface).
 * @dev Post-deployment steps:
 *      1. On NovaAppRegistry, set `dappContract` for the KMS app to the deployed KMSRegistry address.
 *         This routes addOperator/removeOperator callbacks to this contract.
 *      2. (Optional) Transfer admin via setAdmin() if the deployer is not the long-term admin.
 */
contract DeployKMSRegistry is Script {
    function run() external {
        address novaAppRegistryProxy = vm.envAddress("NOVA_APP_REGISTRY_PROXY");
        uint256 kmsAppId = vm.envUint("KMS_APP_ID");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        KMSRegistry registry = new KMSRegistry(novaAppRegistryProxy, kmsAppId);

        console.log("KMSRegistry deployed at:", address(registry));
        console.log("NovaAppRegistry proxy:", novaAppRegistryProxy);
        console.log("KMS App ID:", kmsAppId);
        console.log("");
        console.log("NEXT: Set dappContract on NovaAppRegistry for appId", kmsAppId, "to", address(registry));

        vm.stopBroadcast();
    }
}
