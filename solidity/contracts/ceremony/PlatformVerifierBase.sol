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
///      owns what. Nor does the payload's shape: each verifier declares and
///      decodes its own, because the shapes differ and nothing above a verifier
///      reads them.
abstract contract PlatformVerifierBase is ICeremony, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
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
        /// How far ahead of Block Time this profile's evidence time may run.
        ///
        /// Profiles do not agree on what "now" is. Google's evidence time is a
        /// signed `exp`, an hour ahead; a TLSNotary profile's is an attestation
        /// creation time, which is roughly now. A Consumer comparing the two
        /// raw would let one platform's proof always beat the other's, so each
        /// verifier subtracts its own allowance and returns a time on one
        /// shared scale. It is also the ceiling: evidence dated further ahead
        /// than this is refused rather than normalised.
        uint64 futureObservationAllowance;
        /// The code hash of the artifact above, recorded when it was wired.
        ///
        /// bb-generated Honk verifiers embed their verification key as code
        /// constants and expose no getter, so the code hash is the only handle
        /// on WHICH circuit a deployed verifier answers for.
        bytes32 honkVerifierCodehash;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.PlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PLATFORM_VERIFIER_STORAGE =
        0xfd6bfa775d4a790b2a39afc6490b76805795bc7d3963618ec6b2ee0a55986900;

    function _base() internal pure returns (PlatformVerifierStorage storage $) {
        assembly {
            $.slot := PLATFORM_VERIFIER_STORAGE
        }
    }

    event TrustRootsChanged(address notary, address honkVerifier, bytes32 honkVerifierCodehash);
    event ProtocolParametersChanged(
        uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance
    );

    /// @notice Ceilings on the three governance parameters.
    ///
    /// @dev Two jobs. They keep each value meaningful -- the specification's own defaults
    ///      are an hour, five minutes and an hour -- and they keep the verifier
    ///      from reverting on its own arithmetic. `blockTime + skew` and
    ///      `blockTime + allowance` are checked sums, so a value near
    ///      `type(uint64).max` would panic EVERY verification through this
    ///      contract rather than widen its window, and only an upgrade could
    ///      undo it.
    uint64 public constant MAX_PROOF_LIFETIME = 30 days;
    uint64 public constant MAX_FUTURE_ATTESTATION_SKEW = 1 days;
    uint64 public constant MAX_FUTURE_OBSERVATION_ALLOWANCE = 1 days;

    /// @dev A profile that verifies no attestation holds a Notary Service, or
    ///      one that verifies some holds none.
    error WrongNotaryForProfile(bytes32 platformId, address notary);
    error ParameterTooLarge(uint64 provided, uint64 limit);
    error WrongValue(uint256 required, uint256 provided);
    /// @dev The payload claims a ceremony version this verifier does not
    ///      implement. Checked before any fee moves: rebuilding the digest
    ///      under the wrong version would surface as a code-verifier or digest
    ///      mismatch after both sessions had been paid for, and say nothing
    ///      about which field was wrong.
    error WrongCeremonyVersion(uint16 expected, uint16 found);
    error WrongAuthority(bytes32 expected, bytes32 found);
    error AttestationAhead(uint64 createdAt, uint64 blockTime, uint64 allowance);
    error ProofExpired(uint64 validUntil, uint64 blockTime);
    error ObservedInTheFuture(uint64 observedAt, uint64 limit);
    error BadProof();
    error ZeroAddress();
    /// @dev The verifier at that address is not the artifact governance named.
    error WrongVerifierArtifact(bytes32 expected, bytes32 found);

    // solhint-disable-next-line func-name-mixedcase
    function __PlatformVerifierBase_init(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        bytes32 honkVerifierCodehash_,
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_,
        uint64 futureObservationAllowance_
    ) internal onlyInitializing {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setTrustRoots(notary_, honkVerifier_, honkVerifierCodehash_);
        _setProtocolParameters(proofLifetime_, maxFutureAttestationSkew_, futureObservationAllowance_);
    }

    // ─── Trust roots and parameters ─────────────────────────────────

    function notaryService() external view returns (address) {
        return address(_base().notary);
    }

    function honkVerifier() external view returns (address) {
        return address(_base().honkVerifier);
    }

    /// @notice The code hash of the artifact currently wired, so a reader can
    ///         tell which circuit release this verifier answers for.
    function honkVerifierCodehash() external view returns (bytes32) {
        return _base().honkVerifierCodehash;
    }

    function protocolParameters()
        external
        view
        returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance)
    {
        return (_base().proofLifetime, _base().maxFutureAttestationSkew, _base().futureObservationAllowance);
    }

    /// @dev The caller names the artifact it means to wire, by code hash, and
    ///      the call fails if the address does not hold it. REQ-COMMON-45 asks
    ///      for the EXACT artifact governance selected; an address alone does
    ///      not say which circuit answers behind it, and a mismatch found at
    ///      the first user's proof is found in production.
    function setTrustRoots(INotaryService notary_, IHonkVerifier honkVerifier_, bytes32 honkVerifierCodehash_)
        external
        onlyOwner
    {
        _setTrustRoots(notary_, honkVerifier_, honkVerifierCodehash_);
    }

    /// @dev Governance-owned. The Platform Verifier reads the current value
    ///      when it verifies and accepts no caller-supplied substitute
    ///      (REQ-PARAM-02). Lowering one may reject an outstanding proof;
    ///      raising one may extend an outstanding proof. Each is capped, so
    ///      neither can be raised to a value that breaks the verifier.
    function setProtocolParameters(
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_,
        uint64 futureObservationAllowance_
    ) external onlyOwner {
        _setProtocolParameters(proofLifetime_, maxFutureAttestationSkew_, futureObservationAllowance_);
    }

    /// @dev The platform this verifier answers for. Asked during
    ///      initialization, so it must not read storage.
    function _platform() internal pure virtual returns (bytes32);

    /// @dev The ceremony version this verifier implements: the protocol
    ///      revision the Authorization Digest binds, hardcoded here because it
    ///      is a property of the code, not of a deployment. Unrelated to the
    ///      verifier version the Proof Verifier routes on, which is this
    ///      chain's slot number.
    function _ceremonyVersion() internal pure virtual returns (uint16);

    /// @dev Refuse a payload made for another ceremony version, by name.
    function _requireCeremonyVersion(uint16 claimed) internal pure {
        uint16 expected = _ceremonyVersion();
        if (claimed != expected) revert WrongCeremonyVersion(expected, claimed);
    }

    function _setTrustRoots(INotaryService notary_, IHonkVerifier honkVerifier_, bytes32 honkVerifierCodehash_)
        private
    {
        if (address(honkVerifier_) == address(0)) revert ZeroAddress();

        // The profile decides whether a Notary Service belongs here at all.
        // A profile whose Attestation Count is zero must not reach one
        // (REQ-COMMON-05D), so requiring a live address from it would make a
        // deployer supply a dependency purely to satisfy a check --
        // `notaryService()` would then report a collaborator that does not
        // exist, and `setTrustRoots` could rotate a root nothing reads.
        bytes32 platform = _platform();
        bool wantsNotary = CeremonyProfile.attestationCount(platform) != 0;
        if (wantsNotary != (address(notary_) != address(0))) {
            revert WrongNotaryForProfile(platform, address(notary_));
        }
        // An account with no code hashes to zero (EIP-1052) and an account
        // with empty code to keccak256(""), so either as the EXPECTED value
        // turns this comparison into one that any such address satisfies --
        // and the mis-wiring surfaces at the first user's proof, which is the
        // production failure the check exists to prevent.
        if (honkVerifierCodehash_ == bytes32(0) || honkVerifierCodehash_ == keccak256("")) {
            revert WrongVerifierArtifact(honkVerifierCodehash_, honkVerifierCodehash_);
        }
        bytes32 found = address(honkVerifier_).codehash;
        if (found != honkVerifierCodehash_) revert WrongVerifierArtifact(honkVerifierCodehash_, found);

        _base().notary = notary_;
        _base().honkVerifier = honkVerifier_;
        _base().honkVerifierCodehash = honkVerifierCodehash_;
        emit TrustRootsChanged(address(notary_), address(honkVerifier_), honkVerifierCodehash_);
    }

    function _setProtocolParameters(
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_,
        uint64 futureObservationAllowance_
    ) private {
        if (proofLifetime_ > MAX_PROOF_LIFETIME) {
            revert ParameterTooLarge(proofLifetime_, MAX_PROOF_LIFETIME);
        }
        if (maxFutureAttestationSkew_ > MAX_FUTURE_ATTESTATION_SKEW) {
            revert ParameterTooLarge(maxFutureAttestationSkew_, MAX_FUTURE_ATTESTATION_SKEW);
        }
        if (futureObservationAllowance_ > MAX_FUTURE_OBSERVATION_ALLOWANCE) {
            revert ParameterTooLarge(futureObservationAllowance_, MAX_FUTURE_OBSERVATION_ALLOWANCE);
        }
        _base().proofLifetime = proofLifetime_;
        _base().maxFutureAttestationSkew = maxFutureAttestationSkew_;
        _base().futureObservationAllowance = futureObservationAllowance_;
        emit ProtocolParametersChanged(proofLifetime_, maxFutureAttestationSkew_, futureObservationAllowance_);
    }

    // ─── Shared duties ──────────────────────────────────────────────

    /// @dev Authenticate one attestation and check the constants its profile
    ///      pins. The Notary Service's decision is final (REQ-COMMON-05D): this
    ///      never second-guesses it, and never compares the attested data
    ///      against a transcript it does not hold.
    function _authenticate(Attestation memory attestation, bytes32 expectedAuthority, uint256 fee)
        internal
        returns (CeremonyAttestation.AttestedData memory data)
    {
        // Authenticated and decoded in one call, deliberately. The Notary
        // Service owns the format its key vouches for, and handing back the
        // decoded view rather than a bare accept is what makes "read only what
        // was authenticated" a property of the call rather than of two
        // statements staying next to each other.
        data = _base().notary.verify{value: fee}(attestation.attestedData, attestation.signature);

        // The one comparison left, and the only one the notary could honestly
        // have supplied: the TLS server name it authenticated in the handshake.
        // It is not a revealed range -- the transcript holds the authority only
        // in a prover-composed `Host` header, which says nothing about which
        // server answered.
        //
        // The format, the platform and the session used to be compared here
        // too. None of them was ever observed: the notary was handed all three
        // and wrote them down. The format is fixed by the notary key this
        // profile pins alongside it (REQ-COMMON-18), the platform is whichever
        // host answered, and which session this is, is the request line the
        // caller of this function goes on to check.
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

        // And the ceiling. `maxFutureAttestationSkew` above is a different
        // number for a different job -- how far ahead a notary's clock may
        // legitimately read -- so passing it says nothing about how far ahead
        // the WATERMARK may sit. Without this the two could be configured
        // apart and an attestation dated inside the skew but past the allowance
        // would write a watermark in the future, making every honest later
        // proof of that name read as stale until the clock caught up.
        _requireNotAhead(createdAt);

        // Onto the shared scale, so a Consumer can compare this against a
        // profile whose evidence time runs further ahead without one of them
        // always winning.
        return _onSharedScale(createdAt, _base().futureObservationAllowance);
    }

    /// @dev Saturates at zero rather than reverting: reaching it needs an
    ///      evidence time below the allowance, which no live chain will see,
    ///      and a zero beats no watermark -- so the degenerate case fails
    ///      closed instead of wrapping into a huge one.
    function _onSharedScale(uint64 observedAt, uint64 allowance) internal pure returns (uint64) {
        return observedAt > allowance ? observedAt - allowance : 0;
    }

    /// @dev Evidence dated further ahead than the profile allows is refused
    ///      rather than normalised: without a ceiling a longer-lived token
    ///      would buy a proportionally longer lock on a name, and re-proving --
    ///      the remedy for a lost name -- would stop working for that long.
    function _requireNotAhead(uint64 observedAt) internal view {
        uint64 limit = uint64(block.timestamp) + _base().futureObservationAllowance;
        if (observedAt > limit) revert ObservedInTheFuture(observedAt, limit);
    }

    /// @dev Verify the proof under the artifact governance selected. Without
    ///      this, every public input the surrounding checks compare is a number
    ///      the caller wrote down (REQ-COMMON-45).
    function _requireProof(bytes memory proof, bytes32[] memory publicInputs) internal view {
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
