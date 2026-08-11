// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {SnapshotProxy} from "./SnapshotProxy.sol";
import {WebWallet} from "./WebWallet.sol";

/// @title WalletFactory — Factory for WebWallet instances
/// @notice Deploys WebWallet instances behind SnapshotProxy using CREATE.
///         Each wallet snapshots the current beacon implementation at deploy time
///         and is NOT automatically upgraded when the beacon changes.
///         Users can optionally upgrade via WebWallet.upgrade_to_latest().
///
/// @dev The beacon tracks the latest WebWallet implementation. New deployments
///      read beacon.implementation() and freeze that address in the proxy.
///      Upgrading the beacon only affects future deployments (and wallets whose
///      users explicitly opt in via upgrade_to_latest).
contract WalletFactory is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    UpgradeableBeacon public beacon;
    address public registry;

    /// @notice True if `wallet` was deployed by this factory.
    mapping(address => bool) public isRegisteredWallet;

    // ─── Events ─────────────────────────────────────────────────────

    event WalletCreated(address indexed wallet, bytes32 indexed firstIdentity);
    event WalletImplementationUpgraded(address indexed newImplementation);

    // ─── Errors ─────────────────────────────────────────────────────

    error OnlyRegistry();

    // ─── Initializer ────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param owner_       Factory owner (governance / Dyaka multisig).
    /// @param walletImpl_  Initial WebWallet implementation address.
    /// @param registry_    Registry contract address.
    function initialize(address owner_, address walletImpl_, address registry_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        beacon = new UpgradeableBeacon(walletImpl_, address(this));
        registry = registry_;
    }

    // ─── Wallet deployment ──────────────────────────────────────────

    /// @notice Deploy a new WebWallet for a user's first social identity.
    ///         Uses CREATE opcode — address is non-deterministic.
    ///         The wallet's implementation is snapshotted from the beacon at deploy time.
    ///         Only callable by Registry.
    ///
    /// @param firstPlatform Platform domain of the user's first identity.
    /// @param firstHandle   Handle/username of the user's first identity (display).
    /// @param firstUserId   Immutable platform id of the user's first identity.
    /// @return wallet       Address of the deployed SnapshotProxy.
    function deploy_web_wallet(string calldata firstPlatform, string calldata firstHandle, string calldata firstUserId)
        external
        returns (address wallet)
    {
        if (msg.sender != registry) revert OnlyRegistry();

        // Snapshot current implementation from beacon.
        address impl = beacon.implementation();

        // Deploy SnapshotProxy with CREATE (non-deterministic address).
        SnapshotProxy proxy = new SnapshotProxy(impl);
        wallet = address(proxy);

        // Initialize the wallet through the proxy.
        WebWallet(payable(wallet)).initialize(registry, address(this), firstPlatform, firstHandle);

        // Key the identity by the immutable id (matches WebWallet session keys), so
        // a later handle rename/recycle can't make indexers mis-associate the wallet.
        bytes32 firstIdentity = keccak256(abi.encode(firstPlatform, firstUserId));
        isRegisteredWallet[wallet] = true;
        emit WalletCreated(wallet, firstIdentity);
    }

    // ─── Latest implementation ─────────────────────────────────────

    /// @notice Returns the current WebWallet implementation from the beacon.
    ///         Used by WebWallet.upgradeToLatest() for opt-in upgrades.
    function latestImplementation() external view returns (address) {
        return beacon.implementation();
    }

    // ─── Beacon upgrade ─────────────────────────────────────────────

    /// @notice Upgrade the WebWallet implementation in the beacon.
    ///         Only affects future deployments and wallets that opt in.
    function upgradeWalletImplementation(address newImplementation) external onlyOwner {
        beacon.upgradeTo(newImplementation);
        emit WalletImplementationUpgraded(newImplementation);
    }

    function setRegistry(address newRegistry) external onlyOwner {
        registry = newRegistry;
    }

    // ─── Internal ───────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
