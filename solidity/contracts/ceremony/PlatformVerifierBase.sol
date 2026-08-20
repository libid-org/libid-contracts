// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {ICeremony} from "./ICeremony.sol";
import {INotaryService} from "./INotaryService.sol";

/// @dev The bb-generated proof verifier for this platform's circuit.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @title PlatformVerifierBase
/// @notice What every Platform Verifier owes, whichever platform it serves.
///
/// @dev Three things live here because they are the same everywhere: getting an
///      attestation authenticated and its pinned tags checked, holding the
///      trust roots and governance parameters, and turning an attestation's
///      signed creation time into a validity window.
///
///      What does NOT live here is every field check. Those differ per platform
///      by where the bytes are, and REQ-COMMON-19E gives each field exactly one
///      authoritative reader; a shared implementation would blur which role
///      owns what.
abstract contract PlatformVerifierBase is ICeremony, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    using CeremonyAttestation for bytes;

    /// @custom:storage-location erc7201:libid.storage.PlatformVerifier
    struct PlatformVerifierStorage {
        /// Authenticates an attestation and charges for it. Pinned by the
        /// profile: a profile whose Attestation Count is nonzero must pin the
        /// exact Notary Service it accepts (REQ-COMMON-18).
        INotaryService notary;
        /// The exact artifact governance selected for this platform and
        /// version. Never a caller-supplied one (REQ-COMMON-45).
        IHonkVerifier honkVerifier;
        /// Maximum age of this platform's token attestation.
        uint64 proofLifetime;
        /// Maximum lead over Block Time an attestation may carry.
        uint64 maxFutureAttestationSkew;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.PlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PLATFORM_VERIFIER_STORAGE =
        0xfd6bfa775d4a790b2a39afc6490b76805795bc7d3963618ec6b2ee0a55986900;

    function _base() internal pure returns (PlatformVerifierStorage storage $) {
        assembly {
            $.slot := PLATFORM_VERIFIER_STORAGE
        }
    }

    event TrustRootsChanged(address notary, address honkVerifier);
    event ProtocolParametersChanged(uint64 proofLifetime, uint64 maxFutureAttestationSkew);

    error WrongValue(uint256 required, uint256 provided);
    error WrongAttestationCount(uint256 required, uint256 provided);
    error WrongFormatTag(bytes32 expected, bytes32 found);
    error WrongPlatform(bytes32 expected, bytes32 found);
    error WrongOperationTag(bytes32 expected, bytes32 found);
    error WrongAuthority(bytes32 expected, bytes32 found);
    error AttestationAhead(uint64 createdAt, uint64 blockTime, uint64 allowance);
    error ProofExpired(uint64 validUntil, uint64 blockTime);
    error BadProof();
    error ZeroAddress();

    // solhint-disable-next-line func-name-mixedcase
    function __PlatformVerifierBase_init(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_
    ) internal onlyInitializing {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setTrustRoots(notary_, honkVerifier_);
        _setProtocolParameters(proofLifetime_, maxFutureAttestationSkew_);
    }

    // ─── Trust roots and parameters ─────────────────────────────────

    function notaryService() external view returns (address) {
        return address(_base().notary);
    }

    function honkVerifier() external view returns (address) {
        return address(_base().honkVerifier);
    }

    function protocolParameters() external view returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew) {
        return (_base().proofLifetime, _base().maxFutureAttestationSkew);
    }

    function setTrustRoots(INotaryService notary_, IHonkVerifier honkVerifier_) external onlyOwner {
        _setTrustRoots(notary_, honkVerifier_);
    }

    /// @dev Governance-owned. The Platform Verifier reads the current value
    ///      when it verifies and accepts no caller-supplied substitute
    ///      (REQ-PARAM-02). Lowering one may reject an outstanding proof;
    ///      raising one may extend an outstanding proof.
    function setProtocolParameters(uint64 proofLifetime_, uint64 maxFutureAttestationSkew_) external onlyOwner {
        _setProtocolParameters(proofLifetime_, maxFutureAttestationSkew_);
    }

    function _setTrustRoots(INotaryService notary_, IHonkVerifier honkVerifier_) private {
        if (address(notary_) == address(0) || address(honkVerifier_) == address(0)) {
            revert ZeroAddress();
        }
        _base().notary = notary_;
        _base().honkVerifier = honkVerifier_;
        emit TrustRootsChanged(address(notary_), address(honkVerifier_));
    }

    function _setProtocolParameters(uint64 proofLifetime_, uint64 maxFutureAttestationSkew_) private {
        _base().proofLifetime = proofLifetime_;
        _base().maxFutureAttestationSkew = maxFutureAttestationSkew_;
        emit ProtocolParametersChanged(proofLifetime_, maxFutureAttestationSkew_);
    }

    // ─── Shared duties ──────────────────────────────────────────────

    /// @dev Authenticate one attestation and check the constants its profile
    ///      pins. The Notary Service's decision is final (REQ-COMMON-05D): this
    ///      never second-guesses it, and never compares the attested data
    ///      against a transcript it does not hold.
    function _authenticate(
        Attestation calldata attestation,
        bytes32 expectedPlatform,
        bytes32 expectedOperationTag,
        bytes32 expectedAuthority,
        uint256 fee
    ) internal returns (CeremonyAttestation.AttestedData memory data) {
        _base().notary.verify{value: fee}(attestation.attestedData, attestation.signature);

        data = CeremonyAttestation.decode(attestation.attestedData);

        // A change to the field list, a field's width, or a field's meaning
        // takes a new format version rather than another field, so a mismatch
        // here means the bytes are not the layout this verifier reads.
        if (data.formatTag != CeremonyProfile.FORMAT_TAG) {
            revert WrongFormatTag(CeremonyProfile.FORMAT_TAG, data.formatTag);
        }
        if (data.platformId != expectedPlatform) {
            revert WrongPlatform(expectedPlatform, data.platformId);
        }
        // One ceremony notarizes more than one session, and two attestations
        // differing only in which session they came from would otherwise be
        // interchangeable.
        if (data.operationTag != expectedOperationTag) {
            revert WrongOperationTag(expectedOperationTag, data.operationTag);
        }
        // The authority is what the notary authenticated in the handshake, not
        // a revealed range: the transcript holds it only in a prover-composed
        // `Host` header, which says nothing about which server answered.
        if (data.authorityId != expectedAuthority) {
            revert WrongAuthority(expectedAuthority, data.authorityId);
        }
    }

    /// @dev Turn the token attestation's signed creation time into the window
    ///      section 2.2 fixes. That attestation is the one-time PKCE and
    ///      digest binding, so it alone supplies evidence time; the identity
    ///      attestation opens the same bearer and does not refresh anything.
    function _requireFresh(uint64 createdAt) internal view returns (uint64 metadataObservedAt) {
        uint64 blockTime = uint64(block.timestamp);
        uint64 skew = _base().maxFutureAttestationSkew;

        // Checked arithmetic throughout (REQ-COMMON-28).
        if (createdAt > blockTime + skew) {
            revert AttestationAhead(createdAt, blockTime, skew);
        }
        uint64 validUntil = createdAt + _base().proofLifetime;
        if (blockTime >= validUntil) revert ProofExpired(validUntil, blockTime);

        return createdAt;
    }

    /// @dev Verify the proof under the artifact governance selected. Without
    ///      this, every public input the surrounding checks compare is a number
    ///      the caller wrote down (REQ-COMMON-45).
    function _requireProof(bytes calldata proof, bytes32[] calldata publicInputs) internal view {
        if (!_base().honkVerifier.verify(proof, publicInputs)) revert BadProof();
    }

    /// @dev Required by UUPS -- only the owner can upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to rotate a trust root or move a
    ///      parameter.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
