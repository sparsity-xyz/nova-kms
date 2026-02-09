// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {INovaAppInterface} from "./interfaces/INovaAppInterface.sol";
import {
    Initializable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    Ownable2StepUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/**
 * @title KMSRegistry
 * @notice On-chain operator list for KMS nodes, implementing INovaAppInterface.
 * @dev UUPS Upgradeable version. Managed by NovaAppRegistry callbacks.
 */
contract KMSRegistry is
    INovaAppInterface,
    Initializable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable
{
    // ========== State Variables ==========

    address private _novaAppRegistryAddr;
    uint256 public kmsAppId;

    /// @notice Operator set – managed by addOperator / removeOperator callbacks
    mapping(address => bool) private _operators;
    address[] private _operatorList;
    mapping(address => uint256) private _operatorIndex;

    // ========== Errors ==========

    error OnlyNovaAppRegistry();
    error InvalidRegistryAddress();
    error AppIdMismatch();

    // ========== Events ==========

    event NovaAppRegistrySet(address indexed registry);
    event KmsAppIdSet(uint256 indexed appId);
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

    modifier onlyNovaAppRegistryMod() {
        _checkOnlyNovaAppRegistry();
        _;
    }

    function _checkOnlyNovaAppRegistry() internal view {
        if (msg.sender != _novaAppRegistryAddr) revert OnlyNovaAppRegistry();
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ========== Initializer ==========

    function initialize(
        address initialOwner,
        address appRegistry_
    ) public initializer {
        __Ownable_init(initialOwner);

        if (appRegistry_ == address(0)) revert InvalidRegistryAddress();
        _novaAppRegistryAddr = appRegistry_;
    }

    // ========== Upgrade Authorization ==========

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

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
     * @notice Updates the KMS App ID.
     * @param newAppId The new application ID assigned by Nova.
     */
    function setKmsAppId(uint256 newAppId) external onlyOwner {
        kmsAppId = newAppId;
        emit KmsAppIdSet(newAppId);
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
        return _operators[account];
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

    // ========== Internal Functions ==========

    function _addOperatorInternal(address operator) internal {
        if (_operators[operator]) return;
        _operators[operator] = true;
        _operatorIndex[operator] = _operatorList.length;
        _operatorList.push(operator);
    }

    function _removeOperatorInternal(address operator) internal {
        if (!_operators[operator]) return;

        uint256 index = _operatorIndex[operator];
        uint256 lastIndex = _operatorList.length - 1;

        if (index != lastIndex) {
            address lastOperator = _operatorList[lastIndex];
            _operatorList[index] = lastOperator;
            _operatorIndex[lastOperator] = index;
        }

        _operatorList.pop();
        delete _operatorIndex[operator];
        delete _operators[operator];
    }

    /**
     * @dev Reserved storage space to allow for layout changes in the future.
     */
    uint256[45] private _gap;
}
