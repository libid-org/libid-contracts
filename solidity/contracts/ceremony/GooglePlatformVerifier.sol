// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {IHonkVerifier, PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @dev Where the deployment keeps the Google signing keys it trusts.
interface IJwksRoots {
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
}

/// @title GooglePlatformVerifier — the `google/v1` profile.
///
/// @notice A different shape from the other two: no notarized session, no
///         Notary Service, no fee.
///
/// @dev Google uses direct authentication-only OIDC. There is no token
///      exchange, no client secret, no PKCE and no TLSNotary session; the
///      evidence is a signed ID Token, and the whole ceremony reduces to one
///      proof over it. So this profile's Attestation Count is ZERO, its path
///      stops here rather than reaching a Notary Service, and it quotes and
///      accepts no value at all. A path with nothing to verify carries none.
///
///      The Authorization Digest is bound the other way round from X and
///      GitHub. They carry it through the PKCE verifier and the Platform
///      Verifier recomputes it; Google carries it as the signed OIDC `nonce`
///      and exposes it as a public proof input, which this contract compares
///      against the digest recomputed one hop above (REQ-COMMON-02A). Exactly
///      one of the two methods, never both and never neither.
///
///      Evidence time comes from the signed `exp` alone. It supplies BOTH
///      `metadataObservedAt` and `proofValidUntil` (section 2.2), so the
///      governance lifetime and skew the other profiles read do not apply
///      here — a Google proof is bounded by what Google signed.
contract GooglePlatformVerifier is IPlatformVerifier, PlatformVerifierBase {
    /// @dev The public inputs REQ-PLAT-16B fixes, in the order it lists them.
    ///      The digest is 32 field elements of one byte each; the rest are
    ///      packed Fields.
    uint256 private constant OFF_DIGEST = 0;
    uint256 private constant OFF_AUDIENCE = 32; // 2 fields, 16 bytes each
    uint256 private constant OFF_SUB = 34; // 1 field, 31 bytes
    uint256 private constant OFF_EMAIL = 35; // 2 fields, 31 bytes each
    uint256 private constant OFF_EXP = 37;
    uint256 private constant OFF_MODULUS = 38; // 18 limbs
    uint256 private constant MODULUS_LIMBS = 18;
    uint256 private constant PUBLIC_INPUTS = 56;

    /// @custom:storage-location erc7201:libid.storage.GooglePlatformVerifier
    struct GoogleStorage {
        IJwksRoots jwksRoots;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.GooglePlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GOOGLE_STORAGE = 0x92a7c997eeb454ceeeb8ef2d99ba7d4b830287ff966f129f9049c466a8342400;

    function _g() private pure returns (GoogleStorage storage $) {
        assembly {
            $.slot := GOOGLE_STORAGE
        }
    }

    event JwksRootsChanged(address roots);

    error WrongPublicInputCount(uint256 expected, uint256 provided);
    error DigestMismatch(bytes32 proved, bytes32 recomputed);
    error AudienceMismatch();
    error MissingClientIdentifier();
    /// @dev The signing key is not in the active trusted set, or its trust has
    ///      lapsed (REQ-PLAT-23).
    error UntrustedModulus(bytes32 modulusHash);
    /// @dev `Block Time >= proofValidUntil`, where the ceiling is the signed
    ///      `exp` itself (REQ-PLAT-22).
    error TokenExpired(uint64 exp, uint64 blockTime);
    error EmptyUserId();
    /// @dev A public input the circuit declares as a byte carried more.
    error PublicInputNotAByte(uint256 index, uint256 value);
    /// @dev The signed expiry does not fit the width every timestamp uses.
    error ExpiryNotAUint64(uint256 value);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` is still required by the base, and is deliberately never
    ///      called: a profile whose Attestation Count is zero must not reach a
    ///      Notary Service (REQ-COMMON-05D).
    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        bytes32 honkVerifierCodehash_,
        IJwksRoots jwksRoots_
    ) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_, honkVerifierCodehash_, 0, 0);
        _setJwksRoots(jwksRoots_);
    }

    function jwksRoots() external view returns (address) {
        return address(_g().jwksRoots);
    }

    /// @dev Google rotates signing keys weekly, and every ceremony fails closed
    ///      while an active modulus is untrusted (REQ-PLAT-24).
    function setJwksRoots(IJwksRoots roots) external onlyOwner {
        _setJwksRoots(roots);
    }

    function _setJwksRoots(IJwksRoots roots) private {
        if (address(roots) == address(0)) revert ZeroAddress();
        _g().jwksRoots = roots;
        emit JwksRootsChanged(address(roots));
    }

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return CeremonyProfile.PLATFORM_GOOGLE;
    }

    /// @inheritdoc IPlatformVerifier
    /// @dev Zero. Its Attestation Count is zero, so it verifies nothing that
    ///      charges (REQ-COMMON-06E).
    function quote() public pure returns (uint256) {
        return 0;
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes32 authorizationDigest, Submission calldata submission)
        external
        payable
        returns (PlatformFields memory fields)
    {
        // Not merely "no fee required" but "no value accepted": there is
        // nothing downstream to forward it to, and value left here would be
        // captured in transit.
        if (msg.value != 0) revert WrongValue(0, msg.value);
        if (submission.attestations.length != 0) {
            revert WrongAttestationCount(0, submission.attestations.length);
        }
        if (submission.publicInputs.length != PUBLIC_INPUTS) {
            revert WrongPublicInputCount(PUBLIC_INPUTS, submission.publicInputs.length);
        }

        // REQ-COMMON-02A. Google's binding: the digest the ceremony committed
        // as the signed `nonce` must equal the one recomputed a hop above.
        bytes32 proved = _digestFromInputs(submission.publicInputs);
        if (proved != authorizationDigest) revert DigestMismatch(proved, authorizationDigest);

        // REQ-PLAT-19A. The digest authenticates the bytes without the circuit
        // packing a variable-length string into public inputs, and the Consumer
        // still receives the readable value.
        if (submission.clientIdentifier.length == 0) revert MissingClientIdentifier();
        bytes32 audience = sha256(submission.clientIdentifier);
        if (audience != _audienceFromInputs(submission.publicInputs)) revert AudienceMismatch();
        fields.clientIdentifier = submission.clientIdentifier;

        // REQ-PLAT-23. The circuit exposes the modulus that verified the JWS
        // but decides no trust; that decision is here alone.
        _requireTrustedModulus(submission.publicInputs);

        // REQ-PLAT-22. The signed `exp` is the whole validity ceiling, so a
        // field element that does not fit `u64` must not become one that does.
        uint256 rawExp = uint256(submission.publicInputs[OFF_EXP]);
        if (rawExp > type(uint64).max) revert ExpiryNotAUint64(rawExp);
        uint64 exp = uint64(rawExp);
        if (block.timestamp >= exp) revert TokenExpired(exp, uint64(block.timestamp));

        _requireProof(submission.proof, submission.publicInputs);

        fields.userId = string(_unpack(submission.publicInputs, OFF_SUB, 1));
        if (bytes(fields.userId).length == 0) revert EmptyUserId();
        // RAW bytes. Normalization is the Consumer's derivation on its own
        // write path (REQ-PLAT-16B).
        fields.handle = string(_unpack(submission.publicInputs, OFF_EMAIL, 2));
        fields.metadataObservedAt = exp;
    }

    // ─── Reading the public inputs ──────────────────────────────────

    /// @dev 32 field elements, one byte each.
    function _digestFromInputs(bytes32[] calldata publicInputs) private pure returns (bytes32 out) {
        for (uint256 i = 0; i < 32; ++i) {
            uint256 element = uint256(publicInputs[OFF_DIGEST + i]);
            // Truncating here would rest the ONLY thing binding a Google
            // ceremony to its transaction (REQ-COMMON-02A) on a range
            // constraint this contract cannot see.
            if (element > 0xff) revert PublicInputNotAByte(OFF_DIGEST + i, element);
            out |= bytes32(element << (8 * (31 - i)));
        }
    }

    /// @dev The full SHA-256 of the signed `aud`, as two big-endian 16-byte
    ///      Fields.
    function _audienceFromInputs(bytes32[] calldata publicInputs) private pure returns (bytes32) {
        uint256 high = uint256(publicInputs[OFF_AUDIENCE]);
        uint256 low = uint256(publicInputs[OFF_AUDIENCE + 1]);
        return bytes32((high << 128) | low);
    }

    /// @dev The circuit packs 31 bytes per Field, big-endian, zero-padded past
    ///      the real length. Unpacking and dropping the padding recovers the
    ///      bytes without the caller supplying a copy to be checked against —
    ///      one fewer value for a caller to choose.
    function _unpack(bytes32[] calldata publicInputs, uint256 offset, uint256 count)
        private
        pure
        returns (bytes memory out)
    {
        bytes memory full = new bytes(count * 31);
        for (uint256 f = 0; f < count; ++f) {
            uint256 v = uint256(publicInputs[offset + f]);
            for (uint256 i = 0; i < 31; ++i) {
                full[f * 31 + (30 - i)] = bytes1(uint8(v >> (8 * i)));
            }
        }
        uint256 len = full.length;
        while (len > 0 && full[len - 1] == 0) {
            --len;
        }
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = full[i];
        }
    }

    function _requireTrustedModulus(bytes32[] calldata publicInputs) private view {
        bytes memory packed = new bytes(MODULUS_LIMBS * 32);
        for (uint256 i = 0; i < MODULUS_LIMBS; ++i) {
            bytes32 limb = publicInputs[OFF_MODULUS + i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), limb)
            }
        }
        bytes32 modulusHash = keccak256(packed);
        uint256 expiresAt = _g().jwksRoots.trustedHashExpiresAt(modulusHash);
        if (expiresAt == 0 || block.timestamp >= expiresAt) revert UntrustedModulus(modulusHash);
    }
}
