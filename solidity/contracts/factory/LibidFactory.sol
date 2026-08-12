// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {Create3} from "./Create3.sol";

/// @title LibidFactory — the deterministic deployment factory.
///
/// @notice Every protocol proxy is deployed through this factory via CREATE3
///         with `salt = keccak256(bytes(name))`, so its address is a function
///         of (factory address, name) ONLY — independent of bytecode, of
///         transaction order, and of deployer nonces. Since the factory
///         itself lives at the same address on every chain (see
///         `FactoryDeployer`), `predict(name)` answers the same address on
///         every EVM network, before anything is deployed there.
///
///         Deploy PROXIES through the factory. Implementations go via plain
///         CREATE — their addresses don't matter, and protocol evolution (new
///         impl versions, changed initData) then never moves an address.
///
/// @dev UUPS + Ownable2Step behind an ERC1967 proxy, like every other
///      upgradeable contract in the stack. Two things are special here:
///
///      - The canonical deployment path does NOT choose an owner per network.
///        The proxy init code is FROZEN with `initialize(FACTORY_GENESIS_ADMIN)`
///        baked in (see `FactoryGenesis.sol` / `FactoryDeployer.proxyInitCode()`),
///        so deployment and initialization are one atomic CREATE2 — no
///        front-run window — and the init code (hence the address) is
///        identical on every chain. `initialize` exists per UUPS convention
///        and for tests; on the canonical path nobody ever calls it manually.
///      - Upgrading this factory keeps its address and its deployment
///        records; everything deployed through it stays where it is.
contract LibidFactory is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// Name-hash (`keccak256(bytes(name))`) → deployed address, for every
    /// deployment that went through the factory. Enumerate via the
    /// `Deployed` events; look up via `deployedAt`.
    mapping(bytes32 nameHash => address addr) public deployments;

    event Deployed(bytes32 indexed nameHash, string name, address addr);

    error EmptyName();
    error AlreadyDeployed(string name, address addr);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param owner_ Address that will own the factory (deploy + upgrade
    ///               authority; should be a multisig / KMS key). The
    ///               canonical path bakes `FACTORY_GENESIS_ADMIN` here via
    ///               the frozen proxy init code.
    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
    }

    /// @notice CREATE3-deploy `creationCode` under `name`. The resulting
    ///         address is `predict(name)`, whatever the code is.
    /// @dev A name is single-use: the CREATE3 slot for its salt is occupied
    ///      forever after, so reuse is refused up front with a clear error.
    function deploy(string calldata name, bytes calldata creationCode) external onlyOwner returns (address addr) {
        if (bytes(name).length == 0) revert EmptyName();
        bytes32 nameHash = keccak256(bytes(name));
        address existing = deployments[nameHash];
        if (existing != address(0)) revert AlreadyDeployed(name, existing);

        addr = Create3.deploy(nameHash, creationCode);
        deployments[nameHash] = addr;
        emit Deployed(nameHash, name, addr);
    }

    /// @notice The address `deploy(name, ·)` lands on — answerable before the
    ///         deployment, and identical on every chain where the factory
    ///         lives at its canonical address.
    function predict(string calldata name) external view returns (address) {
        return Create3.addressOf(keccak256(bytes(name)), address(this));
    }

    /// @notice Where `name` was deployed, or zero if it wasn't yet.
    function deployedAt(string calldata name) external view returns (address) {
        return deployments[keccak256(bytes(name))];
    }

    /// @dev Required by UUPS — only the owner can upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would freeze the protocol's deployment authority.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
