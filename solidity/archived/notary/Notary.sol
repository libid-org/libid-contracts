// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {INotary} from "./INotary.sol";

/// @title Notary — the single notary-attestation verifier.
///
/// @notice Every contract that accepts notary attestations holds a pointer to
///         this proxy and calls `verify(digest, proof)`. The digest is the
///         caller's own (each consumer keeps its domain separation exactly
///         where it was); what lives HERE is the one thing they all shared:
///         which notary is trusted, and how an attestation is checked.
///
/// @dev V1 stores a single signer address and checks a secp256k1 signature
///      over the EIP-191-prefixed digest. Rotation is `setNotary`; a change of
///      proof system is a UUPS upgrade of this contract alone — consumers keep
///      calling the same `verify(bytes32, bytes)`.
///
///      Upgrade authority: owner (intended to be a multisig / governance).
contract Notary is INotary, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @inheritdoc INotary
    address public notary;

    event NotaryChanged(address indexed previousNotary, address indexed newNotary);

    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param owner_  Address that will own the contract (should be a multisig).
    /// @param notary_ The initial notary signer.
    function initialize(address owner_, address notary_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setNotary(notary_);
    }

    /// @notice Rotate the notary signer.
    function setNotary(address notary_) external onlyOwner {
        _setNotary(notary_);
    }

    /// @inheritdoc INotary
    /// @dev EIP-191 prefix + ECDSA recover + compare. `tryRecover` rejects
    ///      wrong-length, malleable (high-s), and unrecoverable signatures by
    ///      returning an error, so a malformed proof answers false rather than
    ///      reverting — the consumer surfaces its own error.
    function verify(bytes32 digest, bytes calldata proof) external view returns (bool) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethHash, proof);
        return err == ECDSA.RecoverError.NoError && recovered == notary;
    }

    function _setNotary(address notary_) internal {
        if (notary_ == address(0)) revert ZeroAddress();
        emit NotaryChanged(notary, notary_);
        notary = notary_;
    }

    /// @dev Required by UUPS — only the owner can upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to rotate the notary or upgrade.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
