// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";

/**
 * @title DeployKMSRegistry
 * @notice Deploys KMSRegistry implementation (Non-Upgradeable).
 */
contract DeployKMSRegistry is Script {
    function run() external {
        address novaAppRegistryProxy = vm.envAddress("NOVA_APP_REGISTRY_PROXY");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployerAddr = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // 1. Deploy Implementation
        // Passing owner and registry to the constructor
        KMSRegistry implementation = new KMSRegistry(
            deployerAddr,
            novaAppRegistryProxy
        );

        console.log("KMSRegistry deployed at:", address(implementation));
        console.log("NovaAppRegistry proxy:", novaAppRegistryProxy);
        console.log("");
        console.log("CRITICAL POST-DEPLOYMENT STEPS:");
        console.log("1. Set dappContract on NovaAppRegistry for your KMS App.");
        console.log(
            "2. Call setKmsAppId(YOUR_APP_ID) on the contract to enable operator callbacks."
        );
        console.log("");
        console.log("Example using cast:");
        console.log(
            'cast send %s "setKmsAppId(uint256)" <APP_ID> --private-key <KEY> --rpc-url <URL>',
            address(implementation)
        );

        vm.stopBroadcast();
    }
}
