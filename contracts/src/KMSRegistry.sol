// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {INovaAppInterface} from "./interfaces/INovaAppInterface.sol";

/**
 * @title KMSRegistry
 * @notice On-chain operator list for KMS nodes, implementing INovaAppInterface.
 * @dev The KMSRegistry is purely managed by NovaAppRegistry callbacks:
 *      - addOperator()    → TEE wallet added to operator set
 *      - removeOperator() → TEE wallet removed from operator set
 *
 *      KMS nodes do NOT submit any on-chain transactions.
 *
 *      Clients and KMS nodes query `getOperators()` to discover cluster members,
 *      then look up each operator's instance details (instanceUrl, teePubkey, etc.)
 *      from NovaAppRegistry via `getInstanceByWallet(operator)`.
 */
contract KMSRegistry is INovaAppInterface {
    // ========== State Variables ==========

    address private _novaAppRegistryAddr;
    uint256 public kmsAppId;
    address public admin;

    /// @notice Operator set – managed by addOperator / removeOperator callbacks
    mapping(address => bool) private _operators;
    address[] private _operatorList;
    mapping(address => uint256) private _operatorIndex;

    // ========== Errors ==========

    error NotAdmin();
    error OnlyNovaAppRegistry();
    error InvalidRegistryAddress();
    error AppIdMismatch();

    // ========== Events ==========

    event NovaAppRegistrySet(address indexed registry);
    event OperatorAdded(address indexed operator, uint256 appId, uint256 versionId, uint256 instanceId);
    event OperatorRemoved(address indexed operator, uint256 appId, uint256 versionId, uint256 instanceId);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    // ========== Modifiers ==========

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyNovaAppRegistryMod() {
        if (msg.sender != _novaAppRegistryAddr) revert OnlyNovaAppRegistry();
        _;
    }

    // ========== Constructor ==========

    constructor(address appRegistry_, uint256 kmsAppId_) {
        if (appRegistry_ == address(0)) revert InvalidRegistryAddress();
        _novaAppRegistryAddr = appRegistry_;
        kmsAppId = kmsAppId_;
        admin = msg.sender;
    }

    // ========== INovaAppInterface Implementation ==========

    /// @inheritdoc INovaAppInterface
    function setNovaAppRegistry(address registry) external onlyAdmin {
        if (registry == address(0)) revert InvalidRegistryAddress();
        _novaAppRegistryAddr = registry;
        emit NovaAppRegistrySet(registry);
    }

    /// @inheritdoc INovaAppInterface
    function novaAppRegistry() external view returns (address) {
        return _novaAppRegistryAddr;
    }

    /// @inheritdoc INovaAppInterface
    /// @dev Called by NovaAppRegistry when a TEE instance registers for the KMS app.
    ///      Validates appId matches kmsAppId, then adds the wallet to the operator set.
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
    /// @dev Called by NovaAppRegistry when a TEE instance is stopped/failed.
    ///      Removes the wallet from the operator set.
    function removeOperator(
        address teeWalletAddress,
        uint256 appId,
        uint256 versionId,
        uint256 instanceId
    ) external onlyNovaAppRegistryMod {
        _removeOperatorInternal(teeWalletAddress);
        emit OperatorRemoved(teeWalletAddress, appId, versionId, instanceId);
    }

    // ========== Admin Functions ==========

    function setAdmin(address newAdmin) external onlyAdmin {
        address old = admin;
        admin = newAdmin;
        emit AdminChanged(old, newAdmin);
    }

    // ========== Operator View Functions ==========

    /// @notice Check if an address is a registered operator
    function isOperator(address account) public view returns (bool) {
        return _operators[account];
    }

    /// @notice Get the total number of operators
    function operatorCount() public view returns (uint256) {
        return _operatorList.length;
    }

    /// @notice Get operator address at a specific index
    function operatorAt(uint256 index) public view returns (address) {
        require(index < _operatorList.length, "Index out of bounds");
        return _operatorList[index];
    }

    /// @notice Get all operator addresses
    function getOperators() public view returns (address[] memory) {
        return _operatorList;
    }

    // ========== Internal Functions ==========

    /// @dev Add an operator to the set (idempotent)
    function _addOperatorInternal(address operator) internal {
        if (_operators[operator]) return;
        _operators[operator] = true;
        _operatorIndex[operator] = _operatorList.length;
        _operatorList.push(operator);
    }

    /// @dev Remove an operator from the set using swap-and-pop for O(1) removal (idempotent)
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
}
