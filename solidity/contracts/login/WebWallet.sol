// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

interface IWalletFactory {
    function latestImplementation() external view returns (address);
}

/// @title WebWallet — Per-user social identity wallet (SnapshotProxy instance)
/// @notice One instance is deployed per user via WalletFactory.
///         Groups the user's social platform identities and configures
///         the multisig threshold.
///
/// @dev General multisig executor: any on-chain action (transfers, withdrawals,
///      identity linking, etc.) goes through execute(). The wallet verifies that
///      enough distinct (platform, userId) identities have signed, then forwards
///      the call to the target contract.
///
///      Session keys are stored per (platform, userId) identity as addresses.
///      The identity key is keccak256(abi.encode(platform, userId)) — keyed by the
///      immutable platform id, NOT the mutable handle, so a rename never moves a
///      session (revoke/threshold stay stable). Registry is the sole caller of
///      register_session().
contract WebWallet is Initializable, UUPSUpgradeable {
    address public registry;
    address public factory;

    /// @notice M-of-N approval threshold for multisig.
    /// Threshold counts distinct (platform, userId) identities, not distinct keys.
    uint8 public threshold;

    /// @notice Replay-protection nonce for execute().
    uint256 public nonce;

    // ─── Identity tracking ──────────────────────────────────────────

    /// @dev Set of active identity keys (platformHandleKey). An identity is active
    ///      when it has at least one session in _sessionList.
    bytes32[] private _identityKeys;
    mapping(bytes32 => uint256) private _identityKeyIndex; // key → index in _identityKeys (valid when key is in array)

    // ─── Session storage (address-based) ────────────────────────────

    /// @notice Maps session address → keccak256(abi.encode(platform, userId)).
    ///         Zero means not a session. (Field name kept for storage-layout
    ///         compatibility across the UUPS upgrade; the value is now the id key.)
    mapping(address => bytes32) private _sessionPlatformHandle;

    /// @notice identityKey → array of session addresses.
    mapping(bytes32 => address[]) private _sessionList;

    /// @notice identityKey → sessionAddr → index+1 in _sessionList (0 = not present).
    mapping(bytes32 => mapping(address => uint256)) private _sessionIndex;

    // ─── Events ─────────────────────────────────────────────────────

    event SessionRegistered(string platform, string handle, address indexed sessionAddr);
    event SessionRevoked(string platform, string handle, address indexed sessionAddr);
    event Executed(address indexed target, uint256 value, uint256 nonce);
    event NativeReceived(address indexed from, uint256 amount);
    event NativeSent(address indexed to, uint256 amount);

    // ─── Errors ─────────────────────────────────────────────────────

    error InvalidSignature();
    error ThresholdNotMet();
    error OnlyRegistry();
    error OnlySelf();
    error ExecutionFailed(bytes returnData);
    error SessionNotFound();
    error ThresholdExceedsIdentityCount();
    error SessionAlreadyRegistered();

    // ─── Initializer ────────────────────────────────────────────────

    /// @notice Initialize this wallet. Called by WalletFactory after proxy deployment.
    /// @param _registry      Registry contract address (sole caller of register_session).
    /// @param _factory       WalletFactory address (used for opt-in upgrades).
    /// @param firstPlatform  Platform domain of the user's first identity.
    /// @param firstHandle    Handle/username of the user's first identity.
    function initialize(address _registry, address _factory, string calldata firstPlatform, string calldata firstHandle)
        external
        initializer
    {
        registry = _registry;
        factory = _factory;
        threshold = 1;
        // Identity will be added to _identityKeys when the first session is registered
        // via register_session (which checks _sessionList[key].length == 0).
    }

    receive() external payable {
        emit NativeReceived(msg.sender, msg.value);
    }

    // ─── Session registration (Registry only) ───────────────────────

    /// @notice Register a session address for a (platform, userId) identity. Only callable by Registry.
    /// @param platform    Platform domain (e.g. "x.com").
    /// @param handle      Current handle — emitted for display only; NOT part of the key.
    /// @param userId      Immutable platform id — the identity key is keccak(platform, userId).
    /// @param sessionAddr The session address derived from ecrecover.
    function register_session(
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address sessionAddr
    ) external {
        if (msg.sender != registry) revert OnlyRegistry();
        require(sessionAddr != address(0), "zero session");
        require(bytes(userId).length != 0, "empty userId");

        // Prevent duplicate session registration
        if (_sessionPlatformHandle[sessionAddr] != bytes32(0)) revert SessionAlreadyRegistered();

        _addSession(_identityKey(platform, userId), sessionAddr);

        emit SessionRegistered(platform, handle, sessionAddr);
    }

    // ─── Session revocation (self-call via execute) ─────────────────

    /// @notice Revoke a session. Only callable by this contract (via execute with multisig).
    /// @param platform    Platform domain.
    /// @param handle      Current handle — emitted for display only; NOT part of the key.
    /// @param userId      Immutable platform id — the identity key is keccak(platform, userId).
    /// @param sessionAddr The session address to revoke.
    function revokeSession(
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address sessionAddr
    ) external {
        if (msg.sender != address(this)) revert OnlySelf();

        _removeSession(_identityKey(platform, userId), sessionAddr);

        emit SessionRevoked(platform, handle, sessionAddr);
    }

    /// @notice One-time migration: move a session from the legacy (platform, handle)
    ///         key to the (platform, userId) key. Registry-gated, idempotent. Used to
    ///         re-key sessions that were registered before the id-keying upgrade.
    /// @dev No-op when the session is already under the id key. Emits SessionRegistered
    ///      (unchanged signature) so indexers pick the session up under the id key.
    function reregisterSessionById(
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address sessionAddr
    ) external {
        if (msg.sender != registry) revert OnlyRegistry();
        require(bytes(userId).length != 0, "empty userId");

        bytes32 newKey = _identityKey(platform, userId);
        bytes32 current = _sessionPlatformHandle[sessionAddr];
        if (current == newKey) return; // already id-keyed
        bytes32 oldKey = keccak256(abi.encode(platform, handle));
        if (current != oldKey || _sessionIndex[oldKey][sessionAddr] == 0) revert SessionNotFound();

        _removeSession(oldKey, sessionAddr); // clears _sessionPlatformHandle[sessionAddr]
        _addSession(newKey, sessionAddr);

        emit SessionRegistered(platform, handle, sessionAddr);
    }

    // ─── Session storage helpers ────────────────────────────────────

    function _identityKey(string calldata platform, string calldata userId) internal pure returns (bytes32) {
        return keccak256(abi.encode(platform, userId));
    }

    /// @dev Add `sessionAddr` under `key`, tracking the identity on first session.
    function _addSession(bytes32 key, address sessionAddr) internal {
        if (_sessionList[key].length == 0) {
            _identityKeyIndex[key] = _identityKeys.length;
            _identityKeys.push(key);
        }
        _sessionPlatformHandle[sessionAddr] = key;
        _sessionList[key].push(sessionAddr);
        _sessionIndex[key][sessionAddr] = _sessionList[key].length; // 1-indexed
    }

    /// @dev Remove `sessionAddr` from `key` (swap-pop), untracking the identity on
    ///      its last session. Reverts SessionNotFound if not present under `key`.
    function _removeSession(bytes32 key, address sessionAddr) internal {
        uint256 oneIndexed = _sessionIndex[key][sessionAddr];
        if (oneIndexed == 0) revert SessionNotFound();

        uint256 idx = oneIndexed - 1;
        uint256 lastIdx = _sessionList[key].length - 1;

        if (idx != lastIdx) {
            address lastAddr = _sessionList[key][lastIdx];
            _sessionList[key][idx] = lastAddr;
            _sessionIndex[key][lastAddr] = oneIndexed;
        }

        _sessionList[key].pop();
        delete _sessionIndex[key][sessionAddr];
        delete _sessionPlatformHandle[sessionAddr];

        // If last session for this identity was removed, clean up identity tracking
        if (_sessionList[key].length == 0) {
            uint256 keyIdx = _identityKeyIndex[key];
            uint256 lastKeyIdx = _identityKeys.length - 1;
            if (keyIdx != lastKeyIdx) {
                bytes32 lastKey = _identityKeys[lastKeyIdx];
                _identityKeys[keyIdx] = lastKey;
                _identityKeyIndex[lastKey] = keyIdx;
            }
            _identityKeys.pop();
            delete _identityKeyIndex[key];
        }
    }

    // ─── General executor ───────────────────────────────────────────

    /// @notice Execute an arbitrary call after verifying multisig threshold.
    /// @param target   Contract to call.
    /// @param value    ETH value to send.
    /// @param data     Calldata for the target.
    /// @param sigs     Signatures over the execute digest. Signer addresses are
    ///                 recovered via ecrecover — no need to pass them separately.
    /// @return result  Return data from the call.
    function execute(address target, uint256 value, bytes calldata data, bytes[] calldata sigs)
        external
        payable
        returns (bytes memory result)
    {
        uint256 currentNonce = nonce;
        bytes32 digest =
            keccak256(abi.encode(target, value, keccak256(data), currentNonce, block.chainid, address(this)));

        _requireMultiSig(sigs, digest);

        nonce = currentNonce + 1;

        bool success;
        (success, result) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed(result);

        emit Executed(target, value, currentNonce);
        if (value > 0) emit NativeSent(target, value);
    }

    // ─── Batch executor ───────────────────────────────────────────────

    /// @notice Execute multiple calls atomically after verifying multisig threshold once.
    /// @param targets  Array of contracts to call.
    /// @param values   Array of ETH values to send per call.
    /// @param datas    Array of calldata per call.
    /// @param sigs     Signatures over the batch digest.
    /// @return results Array of return data from each call.
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes[] calldata sigs
    ) external payable returns (bytes[] memory results) {
        require(targets.length == values.length && values.length == datas.length, "length mismatch");

        uint256 currentNonce = nonce;
        bytes32 dataHashes = keccak256(abi.encode(datas));
        bytes32 digest = keccak256(abi.encode(targets, values, dataHashes, currentNonce, block.chainid, address(this)));

        _requireMultiSig(sigs, digest);

        nonce = currentNonce + 1;

        results = new bytes[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            bool success;
            (success, results[i]) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) revert ExecutionFailed(results[i]);
            if (values[i] > 0) emit NativeSent(targets[i], values[i]);
        }

        emit Executed(address(0), 0, currentNonce);
    }

    // ─── Upgrade ─────────────────────────────────────────────────────

    /// @notice Upgrade this wallet to the latest implementation from the factory.
    ///         Must be called via execute() (self-call with multisig).
    function upgradeToLatest() external {
        require(msg.sender == address(this), "only via execute()");
        address newImpl = IWalletFactory(factory).latestImplementation();
        upgradeToAndCall(newImpl, "");
    }

    /// @dev Authorize UUPS upgrades — only via self-call (execute with multisig).
    function _authorizeUpgrade(address) internal override {
        require(msg.sender == address(this), "only via execute()");
    }

    // ─── Self-callable setters (called via execute → self-call) ────

    /// @notice Set the multisig threshold. Only callable by this contract (via execute).
    function setThreshold(uint8 newThreshold) external {
        if (msg.sender != address(this)) revert OnlySelf();
        require(newThreshold > 0, "zero threshold");
        if (newThreshold > _identityKeys.length) revert ThresholdExceedsIdentityCount();
        threshold = newThreshold;
    }

    // ─── Views ──────────────────────────────────────────────────────

    /// @notice Check if an identity hash has at least one active session.
    function isIdentity(bytes32 identityHash) external view returns (bool) {
        return _sessionList[identityHash].length > 0;
    }

    function identityCount() external view returns (uint256) {
        return _identityKeys.length;
    }

    function identityAt(uint256 index) external view returns (bytes32) {
        return _identityKeys[index];
    }

    function sessionCount(bytes32 platformHandleKey) external view returns (uint256) {
        return _sessionList[platformHandleKey].length;
    }

    function sessionAt(bytes32 platformHandleKey, uint256 index) external view returns (address) {
        return _sessionList[platformHandleKey][index];
    }

    function isSession(address addr) external view returns (bool) {
        return _sessionPlatformHandle[addr] != bytes32(0);
    }

    function sessionIdentity(address addr) external view returns (bytes32) {
        return _sessionPlatformHandle[addr];
    }

    // ─── Internal helpers ───────────────────────────────────────────

    /// @dev Verify that >= threshold distinct (platform, userId) identities have signed
    ///      digest. Recovers signer addresses from signatures via ecrecover.
    function _requireMultiSig(bytes[] calldata sigs, bytes32 digest) internal view {
        uint256 len = sigs.length;
        bytes32[] memory seenPairs = new bytes32[](len);
        uint256 distinctCount = 0;

        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));

        for (uint256 i = 0; i < len; i++) {
            address signer = _recoverSigner(sigs[i], ethHash);

            bytes32 key = _sessionPlatformHandle[signer];
            if (key == bytes32(0)) continue; // not an active session — skip

            // Deduplicate by (platform, handle) key
            bool isDup = false;
            for (uint256 j = 0; j < distinctCount; j++) {
                if (seenPairs[j] == key) {
                    isDup = true;
                    break;
                }
            }
            if (isDup) continue;

            seenPairs[distinctCount++] = key;
        }

        if (distinctCount < threshold) revert ThresholdNotMet();
    }

    /// @dev Recover signer address from a 65-byte signature.
    function _recoverSigner(bytes calldata sig, bytes32 ethHash) internal pure returns (address) {
        require(sig.length == 65, "bad sig");

        uint8 v = uint8(sig[64]);
        bytes32 r;
        bytes32 s;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
        }

        address recovered = ecrecover(ethHash, v, r, s);
        if (recovered == address(0)) revert InvalidSignature();
        return recovered;
    }
}
