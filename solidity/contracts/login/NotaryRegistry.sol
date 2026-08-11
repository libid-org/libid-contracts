// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/// @title NotaryRegistry — PoA notary set management
/// @notice Maintains the set of authorized TLSNotary notary addresses.
///         Used by Registry and WebTransfer instead of hardcoded immutable addresses,
///         allowing notary key rotation without contract redeployment.
///
///         Upgrade authority: owner (intended to be a multisig / Dyaka governance).
contract NotaryRegistry is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @dev notary address => authorized
    mapping(address => bool) public isNotary;

    event NotaryAdded(address indexed notary);
    event NotaryRemoved(address indexed notary);

    error NotaryAlreadyRegistered();
    error NotaryNotRegistered();
    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param owner_         Address that will own the registry (should be a multisig).
    /// @param initialNotary  First authorized notary address.
    function initialize(address owner_, address initialNotary) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _addNotary(initialNotary);
    }

    // ─────────────────────────────────────────────────────────────
    //  Notary management
    // ─────────────────────────────────────────────────────────────

    function addNotary(address notary) external onlyOwner {
        _addNotary(notary);
    }

    function removeNotary(address notary) external onlyOwner {
        if (!isNotary[notary]) revert NotaryNotRegistered();
        isNotary[notary] = false;
        emit NotaryRemoved(notary);
    }

    // ─────────────────────────────────────────────────────────────
    //  Internal
    // ─────────────────────────────────────────────────────────────

    function _addNotary(address notary) internal {
        if (notary == address(0)) revert ZeroAddress();
        if (isNotary[notary]) revert NotaryAlreadyRegistered();
        isNotary[notary] = true;
        emit NotaryAdded(notary);
    }

    /// @dev Required by UUPS — only owner can upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
