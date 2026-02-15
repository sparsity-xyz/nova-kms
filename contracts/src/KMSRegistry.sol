// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {INovaAppInterface} from "./interfaces/INovaAppInterface.sol";
import {INovaAppRegistryView} from "./interfaces/INovaAppRegistryView.sol";

/**
 * @title KMSRegistry
 * @notice On-chain operator list for KMS nodes, implementing INovaAppInterface.
 * @dev Non-upgradeable version. Managed by NovaAppRegistry callbacks.
 */
contract KMSRegistry is INovaAppInterface {
    // ========== State Variables ==========

    address public immutable OWNER;
    address private _novaAppRegistryAddr;
    uint256 public kmsAppId;

    /// @notice Master secret hash for the KMS cluster (keccak256(masterSecret)).
    ///         0x0 means unset (not yet initialized or reset by owner).
    bytes32 public masterSecretHash;

    struct OperatorInfo {
        bool exists;
        uint96 index;
    }

    /// @notice Operator set – managed by addOperator / removeOperator callbacks
    mapping(address => OperatorInfo) private _operatorData;
    address[] private _operatorList;

    // ========== Errors ==========

    error NotOwner();
    error OnlyNovaAppRegistry();
    error InvalidRegistryAddress();
    error AppIdMismatch();
    error MasterSecretHashAlreadySet();
    error NotAuthorizedToSetHash();
    error AppIdAlreadySet();

    // ========== Events ==========

    event NovaAppRegistrySet(address indexed registry);
    event KmsAppIdSet(uint256 indexed appId);
    event MasterSecretHashSet(bytes32 indexed hash, address indexed setter);
    event MasterSecretHashReset(address indexed resetter);
    event OperatorAdded(
        address indexed operator,
        uint256 indexed appId,
        uint256 versionId,
        uint256 instanceId
    );
    event OperatorRemoved(
        address indexed operator,
        uint256 indexed appId,
        uint256 versionId,
        uint256 instanceId
    );

    // ========== Modifiers ==========

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view {
        if (msg.sender != OWNER) revert NotOwner();
    }

    modifier onlyNovaAppRegistryMod() {
        _checkOnlyNovaAppRegistry();
        _;
    }

    function _checkOnlyNovaAppRegistry() internal view {
        if (msg.sender != _novaAppRegistryAddr) revert OnlyNovaAppRegistry();
    }

    // ========== Constructor ==========

    constructor(address initialOwner, address appRegistry_) {
        if (appRegistry_ == address(0)) revert InvalidRegistryAddress();
        OWNER = initialOwner;
        _novaAppRegistryAddr = appRegistry_;
    }

    // ========== INovaAppInterface Implementation ==========

    /// @inheritdoc INovaAppInterface
    function setNovaAppRegistry(address registry) external onlyOwner {
        if (registry == address(0)) revert InvalidRegistryAddress();
        _novaAppRegistryAddr = registry;
        emit NovaAppRegistrySet(registry);
    }

    /// @inheritdoc INovaAppInterface
    function novaAppRegistry() external view returns (address) {
        return _novaAppRegistryAddr;
    }

    /**
     * @notice Updates the KMS App ID. Can only be set once.
     * @param newAppId The new application ID assigned by Nova.
     */
    function setKmsAppId(uint256 newAppId) external onlyOwner {
        if (kmsAppId != 0) revert AppIdAlreadySet();
        kmsAppId = newAppId;
        emit KmsAppIdSet(newAppId);
    }

    /**
     * @notice Reset the master secret hash back to 0x0.
     * @dev Owner-only emergency/maintenance action.
     */
    function resetMasterSecretHash() external onlyOwner {
        masterSecretHash = bytes32(0);
        emit MasterSecretHashReset(msg.sender);
    }

    /**
     * @notice Set the master secret hash once, when it is currently unset (0x0).
     * @dev Caller must be an ACTIVE KMS node for this appId and an ENROLLED version
     *      according to NovaAppRegistry.
     */
    function setMasterSecretHash(bytes32 newHash) external {
        if (masterSecretHash != bytes32(0)) revert MasterSecretHashAlreadySet();

        // Validate msg.sender is an ACTIVE instance of this app and its version is ENROLLED.
        if (!_isEligibleHashSetter(msg.sender)) revert NotAuthorizedToSetHash();

        masterSecretHash = newHash;
        emit MasterSecretHashSet(newHash, msg.sender);
    }

    /// @inheritdoc INovaAppInterface
    function addOperator(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external onlyNovaAppRegistryMod {
        if (appId != kmsAppId) revert AppIdMismatch();
        _addOperatorInternal(teeWalletAddress);
        emit OperatorAdded(teeWalletAddress, appId, versionId, instanceId);
    }

    /// @inheritdoc INovaAppInterface
    function removeOperator(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external onlyNovaAppRegistryMod {
        if (appId != kmsAppId) revert AppIdMismatch();
        _removeOperatorInternal(teeWalletAddress);
        emit OperatorRemoved(teeWalletAddress, appId, versionId, instanceId);
    }

    // ========== Operator View Functions ==========

    function isOperator(address account) public view returns (bool) {
        return _operatorData[account].exists;
    }

    function operatorCount() public view returns (uint256) {
        return _operatorList.length;
    }

    function operatorAt(uint256 index) public view returns (address) {
        require(index < _operatorList.length, "Index out of bounds");
        return _operatorList[index];
    }

    function getOperators() public view returns (address[] memory) {
        return _operatorList;
    }

    // ========== NovaAppRegistry Validation ==========

    function _isEligibleHashSetter(
        address sender
    ) internal view returns (bool) {
        if (_novaAppRegistryAddr == address(0) || kmsAppId == 0) return false;

        INovaAppRegistryView registry = INovaAppRegistryView(
            _novaAppRegistryAddr
        );

        // Standard interface call (struct return avoids stack-too-deep)
        try registry.getInstanceByWallet(sender) returns (
            INovaAppRegistryView.RuntimeInstance memory inst
        ) {
            if (
                inst.teeWalletAddress != sender ||
                inst.appId != kmsAppId ||
                inst.status != INovaAppRegistryView.InstanceStatus.ACTIVE
            ) return false;

            // Standard interface call for version status
            try registry.getVersion(inst.appId, inst.versionId) returns (
                INovaAppRegistryView.AppVersion memory ver
            ) {
                return
                    ver.status == INovaAppRegistryView.VersionStatus.ENROLLED;
            } catch {
                return false;
            }
        } catch {
            return false;
        }
    }

    // ========== Internal Functions ==========

    function _addOperatorInternal(address operator) internal {
        if (_operatorData[operator].exists) return;
        // casting to 'uint96' is safe because operator count will not exceed 2^96
        // forge-lint: disable-next-line(unsafe-typecast)
        uint96 index = uint96(_operatorList.length);
        _operatorData[operator] = OperatorInfo({exists: true, index: index});
        _operatorList.push(operator);
    }

    function _removeOperatorInternal(address operator) internal {
        OperatorInfo storage info = _operatorData[operator];
        if (!info.exists) return;

        uint256 index = info.index;
        uint256 lastIndex = _operatorList.length - 1;

        if (index != lastIndex) {
            address lastOperator = _operatorList[lastIndex];
            _operatorList[index] = lastOperator;
            // casting to 'uint96' is safe because index is derived from array length
            // forge-lint: disable-next-line(unsafe-typecast)
            _operatorData[lastOperator].index = uint96(index);
        }

        _operatorList.pop();
        delete _operatorData[operator];
    }
}
