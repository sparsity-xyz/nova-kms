// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

/// @title INovaAppRegistryView
/// @notice Minimal interface to query required NovaAppRegistry views.
interface INovaAppRegistryView {
    enum AppStatus {
        ACTIVE,
        INACTIVE,
        REVOKED
    }

    enum VersionStatus {
        ENROLLED,
        DEPRECATED, // historical, cannot register new instances
        REVOKED
    }

    enum InstanceStatus {
        ACTIVE,
        STOPPED,
        FAILED
    }

    struct App {
        uint256 appId;
        address owner;
        bytes32 teeArch;
        address dappContract;
        string metadataUri;
        uint256 latestVersionId;
        uint256 createdAt;
        AppStatus status;
    }

    struct AppVersion {
        uint256 versionId;
        string versionName;
        bytes32 codeMeasurement;
        string imageUri;
        string auditUrl;
        string auditHash;
        string githubRunId;
        VersionStatus status;
        uint256 enrolledAt;
        address enrolledBy;
    }

    struct RuntimeInstance {
        uint256 instanceId;
        uint256 appId;
        uint256 versionId;
        address operator;
        string instanceUrl;
        bytes teePubkey;
        address teeWalletAddress;
        bool zkVerified;
        InstanceStatus status;
        uint256 registeredAt;
    }

    function getApp(uint256 appId) external view returns (App memory);

    function getVersion(
        uint256 appId,
        uint256 versionId
    ) external view returns (AppVersion memory);

    function getInstanceByWallet(
        address wallet
    ) external view returns (RuntimeInstance memory);
}
