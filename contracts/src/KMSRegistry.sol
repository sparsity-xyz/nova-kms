// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.33;

import {INovaAppInterface} from "./interfaces/INovaAppInterface.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

// Minimal interface to query required NovaAppRegistry views.
interface INovaAppRegistryView {
    function getInstanceByWallet(address wallet)
        external
        view
        returns (
            uint256 id,
            uint256 appId,
            uint256 versionId,
            address operator,
            string memory instanceUrl,
            bytes memory teePubkey,
            address teeWalletAddress,
            bool zkVerified,
            uint8 status,
            uint256 registeredAt
        );

    function getVersion(uint256 appId, uint256 versionId)
        external
        view
        returns (
            uint256 id,
            string memory versionName,
            bytes32 codeMeasurement,
            string memory imageUri,
            string memory auditUrl,
            string memory auditHash,
            string memory githubRunId,
            uint8 status,
            uint256 enrolledAt,
            address enrolledBy
        );
}

/**
 * @title KMSRegistry
 * @notice On-chain operator list for KMS nodes, implementing INovaAppInterface.
 * @dev UUPS Upgradeable version. Managed by NovaAppRegistry callbacks.
 */
contract KMSRegistry is INovaAppInterface, Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    // ========== State Variables ==========

    address private _novaAppRegistryAddr;
    uint256 public kmsAppId;

    /// @notice Master secret hash for the KMS cluster (keccak256(masterSecret)).
    ///         0x0 means unset (not yet initialized or reset by owner).
    bytes32 public masterSecretHash;

    /// @notice Operator set – managed by addOperator / removeOperator callbacks
    mapping(address => bool) private _operators;
    address[] private _operatorList;
    mapping(address => uint256) private _operatorIndex;

    // ========== Errors ==========

    error OnlyNovaAppRegistry();
    error InvalidRegistryAddress();
    error AppIdMismatch();
    error MasterSecretHashAlreadySet();
    error NotAuthorizedToSetHash();

    // ========== Events ==========

    event NovaAppRegistrySet(address indexed registry);
    event KmsAppIdSet(uint256 indexed appId);
    event MasterSecretHashSet(bytes32 indexed hash, address indexed setter);
    event MasterSecretHashReset(address indexed resetter);
    event OperatorAdded(address indexed operator, uint256 indexed appId, uint256 versionId, uint256 instanceId);
    event OperatorRemoved(address indexed operator, uint256 indexed appId, uint256 versionId, uint256 instanceId);

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

    function initialize(address initialOwner, address appRegistry_) public initializer {
        __Ownable_init(initialOwner);

        if (appRegistry_ == address(0)) revert InvalidRegistryAddress();
        _novaAppRegistryAddr = appRegistry_;
    }

    // ========== Upgrade Authorization ==========

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

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
    function addOperator(address teeWalletAddress, uint256 appId, uint256 versionId, uint256 instanceId)
        external
        onlyNovaAppRegistryMod
    {
        if (appId != kmsAppId) revert AppIdMismatch();
        _addOperatorInternal(teeWalletAddress);
        emit OperatorAdded(teeWalletAddress, appId, versionId, instanceId);
    }

    /// @inheritdoc INovaAppInterface
    function removeOperator(address teeWalletAddress, uint256 appId, uint256 versionId, uint256 instanceId)
        external
        onlyNovaAppRegistryMod
    {
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

    // ========== NovaAppRegistry Validation ==========

    // VersionStatus.ENROLLED == 0, InstanceStatus.ACTIVE == 0 (per NovaAppRegistry enums)
    uint8 private constant _VERSION_STATUS_ENROLLED = 0;
    uint8 private constant _INSTANCE_STATUS_ACTIVE = 0;

    bytes4 private constant _SEL_GET_INSTANCE_BY_WALLET = bytes4(keccak256("getInstanceByWallet(address)"));
    bytes4 private constant _SEL_GET_VERSION = bytes4(keccak256("getVersion(uint256,uint256)"));

    function _loadWord(bytes memory data, uint256 index) private pure returns (uint256 v) {
        assembly {
            v := mload(add(data, add(32, mul(index, 32))))
        }
    }

    function _isEligibleHashSetter(address sender) internal view returns (bool) {
        if (_novaAppRegistryAddr == address(0)) return false;
        if (kmsAppId == 0) return false;

        // getInstanceByWallet(address) returns a tuple with 10 head words.
        // We only need:
        //   word[1] appId
        //   word[2] versionId
        //   word[6] teeWalletAddress
        //   word[8] instanceStatus
        (bool ok1, bytes memory instRet) =
            _novaAppRegistryAddr.staticcall(abi.encodeWithSelector(_SEL_GET_INSTANCE_BY_WALLET, sender));
        if (!ok1 || instRet.length < 32 * 10) return false;

        uint256 appId = _loadWord(instRet, 1);
        uint256 versionId = _loadWord(instRet, 2);
        address teeWallet = address(uint160(_loadWord(instRet, 6)));
        uint8 instanceStatus = uint8(_loadWord(instRet, 8));

        if (teeWallet != sender) return false;
        if (appId != kmsAppId) return false;
        if (instanceStatus != _INSTANCE_STATUS_ACTIVE) return false;

        // getVersion(appId, versionId) head word[7] is version status.
        (bool ok2, bytes memory verRet) =
            _novaAppRegistryAddr.staticcall(abi.encodeWithSelector(_SEL_GET_VERSION, appId, versionId));
        if (!ok2 || verRet.length < 32 * 10) return false;

        uint8 versionStatus = uint8(_loadWord(verRet, 7));
        return versionStatus == _VERSION_STATUS_ENROLLED;
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
    uint256[44] private _gap;
}
