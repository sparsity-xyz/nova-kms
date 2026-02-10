// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

/// @title INovaAppInterface
/// @notice Interface that Nova-compatible dApps must implement to receive operator callbacks from NovaAppRegistry.
/// @dev The registry calls addOperator when a TEE instance registers, and removeOperator when it stops/fails.
interface INovaAppInterface {
    /// @notice Called by NovaAppRegistry when a TEE instance registers.
    /// @dev Only callable by the configured NovaAppRegistry address. Adds the TEE wallet as an authorized operator.
    /// @param teeWalletAddress The wallet address of the TEE instance.
    /// @param appId The app ID (for multi-app contracts).
    /// @param versionId The version ID of the code running in this instance.
    /// @param instanceId The unique instance ID from the registry.
    function addOperator(address teeWalletAddress, uint256 appId, uint256 versionId, uint256 instanceId) external;

    /// @notice Called by NovaAppRegistry when a TEE instance is stopped or failed.
    /// @dev Only callable by the configured NovaAppRegistry address. Removes the TEE wallet from authorized operators.
    /// @param teeWalletAddress The wallet address of the TEE instance to remove.
    /// @param appId The app ID.
    /// @param versionId The version ID.
    /// @param instanceId The instance ID being deactivated.
    function removeOperator(address teeWalletAddress, uint256 appId, uint256 versionId, uint256 instanceId) external;

    /// @notice Sets the NovaAppRegistry address that is allowed to call addOperator/removeOperator.
    /// @dev Should only be callable by the contract owner/admin.
    /// @param registry The address of the NovaAppRegistry contract.
    function setNovaAppRegistry(address registry) external;

    /// @notice Returns the configured NovaAppRegistry address.
    function novaAppRegistry() external view returns (address);
}
