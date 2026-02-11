// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title UpgradeKMSRegistry
 * @notice Deploys a new KMSRegistry implementation and upgrades the proxy.
 */
contract UpgradeKMSRegistry is Script {
    function run() external {
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        // 1. Deploy New Implementation
        KMSRegistry newImplementation = new KMSRegistry();
        console.log(
            "New KMSRegistry Implementation deployed at:",
            address(newImplementation)
        );

        // 2. Upgrade Proxy
        // We cast the proxy address to UUPSUpgradeable to call upgradeToAndCall
        UUPSUpgradeable proxy = UUPSUpgradeable(proxyAddress);
        proxy.upgradeToAndCall(address(newImplementation), "");

        console.log("Proxy at %s upgraded to new implementation", proxyAddress);

        vm.stopBroadcast();
    }
}
