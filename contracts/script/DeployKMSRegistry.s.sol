// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";
import {KMSRegistry} from "../src/KMSRegistry.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployKMSRegistry
 * @notice Deploys KMSRegistry implementation and UUPS proxy.
 */
contract DeployKMSRegistry is Script {
    function run() external {
        address novaAppRegistryProxy = vm.envAddress("NOVA_APP_REGISTRY_PROXY");
        uint256 kmsAppId = vm.envUint("KMS_APP_ID");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployerAddr = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // 1. Deploy Implementation
        KMSRegistry implementation = new KMSRegistry();

        // 2. Deploy Proxy and Initialize
        // Initializing with owner and registry. kmsAppId defaults to 0.
        // Owner must call setKmsAppId() later.
        bytes memory initData = abi.encodeCall(
            KMSRegistry.initialize,
            (deployerAddr, novaAppRegistryProxy)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );

        console.log(
            "KMSRegistry Implementation deployed at:",
            address(implementation)
        );
        console.log(
            "KMSRegistry Proxy (USE THIS ONE) deployed at:",
            address(proxy)
        );
        console.log("NovaAppRegistry proxy:", novaAppRegistryProxy);
        console.log("Initial KMS App ID set to 0. Owner must update this.");
        console.log("");
        console.log(
            "NEXT: 1. Set dappContract on NovaAppRegistry for your AppId to",
            address(proxy)
        );
        console.log(
            "      2. Call setKmsAppId(%s) on the proxy if assigned.",
            kmsAppId
        );

        vm.stopBroadcast();
    }
}
