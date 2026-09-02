// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {ICeremony} from "./ICeremony.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {IProofVerifier} from "./IProofVerifier.sol";

/// @title CeremonyProofVerifier
/// @notice Dispatch, and only dispatch.
///
/// @dev This is deliberately a contract of its own rather than something each
///      Consumer carries. The Supported Version Set decides which proof
///      statements this chain accepts, and a second Consumer implementing its
///      own dispatch would be a second version-governance surface that could
///      drift from this one silently.
///
///      The concentration that buys is real and the specification names it: a
///      compromise here authorises arbitrary transactions at every Consumer at
///      once. That is the price of one entry point, and it is why this contract
///      holds no platform constant, decodes nothing -- not the payload, not the
///      transaction data inside it -- and applies no effect. There is nothing
///      here to compromise except dispatch itself.
///
///      Two versions, and this contract knows only one of them. The VERIFIER
///      version is the key a payload is routed on: this chain's slot number,
///      assigned by governance here, on this chain's own upgrade cadence. The
///      CEREMONY version is the protocol revision a verifier implements and
///      the Authorization Digest binds; each verifier holds its own as a
///      constant. A browser needs the second to start a ceremony and the first
///      to submit one, and nothing here ties them together -- that is what
///      lets one proof outlive a verifier upgrade, and what lets Solana run
///      its slot numbers without matching this chain's.
contract CeremonyProofVerifier is IProofVerifier, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @custom:storage-location erc7201:libid.storage.CeremonyProofVerifier
    struct ProofVerifierStorage {
        /// platformId -> verifier version -> the Platform Verifier for that
        /// pair.
        ///
        /// More than one version of one platform is supported at a time
        /// (REQ-COMMON-05B): that is what lets a deployment run a new version
        /// beside the one it replaces while holders migrate.
        mapping(bytes32 => mapping(uint16 => IPlatformVerifier)) verifiers;
        /// platformId -> how many versions it has registered.
        ///
        /// A platform with none can verify nothing, and a Consumer asking
        /// "does anyone hold this name" needs to tell that from "nobody does".
        mapping(bytes32 => uint256) versionCount;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.CeremonyProofVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PROOF_VERIFIER_STORAGE =
        0x128443dce113885ee8c5806bf38d25bc0d69e6c9a5ceda8792c21c106d531700;

    function _s() private pure returns (ProofVerifierStorage storage $) {
        assembly {
            $.slot := PROOF_VERIFIER_STORAGE
        }
    }

    event VerifierConfigured(bytes32 indexed platformId, uint16 indexed verifierVersion, address verifier);

    error UnknownVersion(bytes32 platformId, uint16 verifierVersion);
    error WrongValue(uint256 required, uint256 provided);
    error VerifierPlatformMismatch(bytes32 expected, bytes32 found);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
    }

    /// @notice This chain's identifier, as the digest construction takes it.
    /// @dev A convenience for callers building a digest off chain against this
    ///      deployment. The verifiers do not read it from here: they take it
    ///      from `CeremonyAuthorization.digestFor`, which reads the chain
    ///      itself.
    function chainId() public view returns (bytes32) {
        return CeremonyAuthorization.chainId();
    }

    /// @inheritdoc IProofVerifier
    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return _requireVerifier(platformId, verifierVersion).quote();
    }

    /// @inheritdoc IProofVerifier
    function verifiesPlatform(bytes32 platformId) external view returns (bool) {
        return _s().versionCount[platformId] != 0;
    }

    /// @notice The Platform Verifier registered for a pair, or the zero address.
    function verifierOf(bytes32 platformId, uint16 verifierVersion) external view returns (IPlatformVerifier) {
        return _s().verifiers[platformId][verifierVersion];
    }

    /// @inheritdoc IProofVerifier
    function verify(bytes32 platformId, uint16 verifierVersion, bytes calldata payload)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        IPlatformVerifier verifier = _requireVerifier(platformId, verifierVersion);

        // Exact value at every hop: no refund path, so no partial-failure rule
        // is needed and nothing can be captured in transit (REQ-COMMON-06D).
        uint256 required = verifier.quote();
        if (msg.value != required) revert WrongValue(required, msg.value);

        // Forwarded whole and returned whole. The payload is the verifier's to
        // decode and the claim is the Consumer's to act on; this hop reads
        // neither (REQ-COMMON-06B).
        return verifier.verify{value: required}(payload);
    }

    /// @notice Add or remove a Platform Verifier from the Supported Version Set.
    ///
    /// @dev Governance owns every addition and removal (REQ-COMMON-05C): the
    ///      set decides which proof statements this chain accepts, so it is
    ///      authority rather than configuration. Removing one strands no name
    ///      already bound under it -- a name does not belong to the proof that
    ///      established it -- and a stranded ceremony is re-runnable under a
    ///      supported version.
    function setVerifier(bytes32 platformId, uint16 verifierVersion, IPlatformVerifier verifier) external onlyOwner {
        // A verifier registered under a platform it does not serve would take
        // submissions it cannot check and reject every one of them.
        if (address(verifier) != address(0)) {
            bytes32 serves = verifier.platformId();
            if (serves != platformId) revert VerifierPlatformMismatch(platformId, serves);
        }

        bool had = address(_s().verifiers[platformId][verifierVersion]) != address(0);
        bool has = address(verifier) != address(0);
        if (had && !has) --_s().versionCount[platformId];
        if (!had && has) ++_s().versionCount[platformId];

        _s().verifiers[platformId][verifierVersion] = verifier;
        emit VerifierConfigured(platformId, verifierVersion, address(verifier));
    }

    function _requireVerifier(bytes32 platformId, uint16 verifierVersion) private view returns (IPlatformVerifier) {
        IPlatformVerifier verifier = _s().verifiers[platformId][verifierVersion];
        // Never a caller-supplied address: a caller-selected verifier verifies
        // nothing (REQ-COMMON-05A).
        if (address(verifier) == address(0)) revert UnknownVersion(platformId, verifierVersion);
        return verifier;
    }

    /// @dev Required by UUPS -- only the owner can upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to move the Supported Version Set.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
