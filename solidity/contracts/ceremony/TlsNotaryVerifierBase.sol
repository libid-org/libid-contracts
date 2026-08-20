// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyFields} from "./CeremonyFields.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @title TlsNotaryVerifierBase
/// @notice The shape both TLSNotary profiles share: two notarized sessions, one
///         hidden bearer linking them, one proof binding that link.
///
/// @dev `x/v1` and `github/v1` state the same relation and differ only in
///      constants and two reads, so the flow lives here once. What a subclass
///      supplies is exactly what genuinely differs:
///
///        the platform id and its two authorities — GitHub's exchange is served
///        by one host and its identity read by another, so an authority is per
///        SESSION rather than per profile;
///        the two request lines;
///        any extra check on the token body — X compares `grant_type`, GitHub
///        has none to compare;
///        how the identity fields are read — X's `id` is a JSON string, GitHub's
///        a bare integer.
///
///      Order matters in one place. The proof is verified LAST, once the
///      commitments it links are known to be the ones the attestations carried;
///      verifying it earlier would prove a relation between numbers nobody had
///      tied to a session yet.
abstract contract TlsNotaryVerifierBase is IPlatformVerifier, PlatformVerifierBase {
    /// @dev Two 32-byte commitments as 64 public inputs, one byte each.
    uint256 internal constant PUBLIC_INPUTS = 64;
    uint256 internal constant OFF_TOKEN_COMMITMENT = 0;
    uint256 internal constant OFF_IDENTITY_COMMITMENT = 32;

    /// @dev What frames the committed bearer in the token response. Every other
    ///      response byte is hidden, so without these the committed range is
    ///      indistinguishable from a `refresh_token` value (REQ-PLAT-57,
    ///      REQ-PLAT-58).
    bytes internal constant ACCESS_TOKEN_PREFIX = '"access_token":"';
    bytes internal constant ACCESS_TOKEN_SUFFIX = '"';

    error UnexpectedClientIdentifier();
    error WrongPublicInputCount(uint256 expected, uint256 provided);
    error WrongRequestLine();
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    error CommitmentMismatch(bytes32 proved, bytes32 attested);

    // ─── What a profile supplies ────────────────────────────────────

    function _platform() internal pure virtual returns (bytes32);
    function _tokenAuthority() internal pure virtual returns (bytes32);
    function _identityAuthority() internal pure virtual returns (bytes32);
    function _tokenRequestLine() internal pure virtual returns (bytes memory);
    function _identityRequestLine() internal pure virtual returns (bytes memory);

    /// @dev Anything the profile checks in the token body beyond the fields
    ///      every profile reads. Default: nothing.
    function _checkTokenBody(bytes memory body) internal pure virtual {}

    /// @dev Read the two identity fields from the revealed response bytes.
    function _readIdentityFields(bytes memory revealed)
        internal
        pure
        virtual
        returns (string memory userId, string memory handle);

    // ─── The flow ───────────────────────────────────────────────────

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return _platform();
    }

    /// @inheritdoc IPlatformVerifier
    function quote() public view returns (uint256) {
        // Two attestations, so two Notary Fees.
        return 2 * _base().notary.fee();
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes32 authorizationDigest, Submission calldata submission)
        external
        payable
        returns (PlatformFields memory fields)
    {
        uint256 fee = _base().notary.fee();
        // Exact value at every hop needs no refund path, so no partial-failure
        // or reentrancy rule is required and no value can be captured in
        // transit (REQ-COMMON-06D).
        if (msg.value != 2 * fee) revert WrongValue(2 * fee, msg.value);
        if (submission.attestations.length != 2) {
            revert WrongAttestationCount(2, submission.attestations.length);
        }
        // Both profiles read the client identifier from a revealed range, so a
        // caller-supplied copy would duplicate a value the attested data
        // already carries (REQ-COMMON-52).
        if (submission.clientIdentifier.length != 0) revert UnexpectedClientIdentifier();
        if (submission.publicInputs.length != PUBLIC_INPUTS) {
            revert WrongPublicInputCount(PUBLIC_INPUTS, submission.publicInputs.length);
        }

        uint64 observedAt = _tokenSession(authorizationDigest, submission, fee, fields);
        _identitySession(submission, fee, fields);

        _requireProof(submission.proof, submission.publicInputs);
        fields.metadataObservedAt = observedAt;
    }

    function _tokenSession(
        bytes32 authorizationDigest,
        Submission calldata submission,
        uint256 fee,
        PlatformFields memory fields
    ) private returns (uint64 observedAt) {
        CeremonyAttestation.AttestedData memory data = _authenticate(
            submission.attestations[0], _platform(), CeremonyProfile.TOKEN_SESSION_TAG, _tokenAuthority(), fee
        );

        if (!_startsWith(_revealedAt(data.sent, 0), _tokenRequestLine())) revert WrongRequestLine();

        // The revealed body. GitHub's `client_secret` is ordered last and
        // committed, so this is a prefix there and the whole body on X; either
        // way every field a verifier reads is inside it.
        bytes memory body = _revealedAt(data.sent, 1);
        _checkTokenBody(body);

        // REQ-COMMON-15A. This is the whole binding between the evidence and
        // the transaction: retargeting an attestation to another digest would
        // take a second preimage of the revealed verifier.
        bytes memory revealedVerifier = CeremonyFields.formField(body, "code_verifier");
        bytes memory expected = CeremonyAuthorization.codeVerifier(authorizationDigest, submission.pkceNonce);
        if (keccak256(revealedVerifier) != keccak256(expected)) revert CodeVerifierMismatch();

        bytes memory clientId = CeremonyFields.formField(body, "client_id");
        if (!CeremonyFields.isSerializerSafe(clientId)) {
            revert ClientIdentifierNotSerializerSafe(clientId);
        }
        fields.clientIdentifier = clientId;

        // The bearer is identified by its framing, not by being the only
        // commitment: the response hides every other byte behind one of its own.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireFramedCommitment(data.received, ACCESS_TOKEN_PREFIX, ACCESS_TOKEN_SUFFIX);
        _requireCommitmentValue(bearer.commitment, submission.publicInputs, OFF_TOKEN_COMMITMENT);

        // The token attestation is the one-time PKCE and digest binding, so it
        // alone supplies evidence time (section 2.2).
        return _requireFresh(data.createdAt);
    }

    function _identitySession(Submission calldata submission, uint256 fee, PlatformFields memory fields) private {
        CeremonyAttestation.AttestedData memory data = _authenticate(
            submission.attestations[1], _platform(), CeremonyProfile.IDENTITY_SESSION_TAG, _identityAuthority(), fee
        );

        // REQ-COMMON-21A: the path separates operations on the same server.
        if (!_startsWith(_revealedAt(data.sent, 0), _identityRequestLine())) {
            revert WrongRequestLine();
        }

        // Coverage, the line-anchored uniqueness scan and the framing bytes,
        // together. They are one property: the scan reads only revealed bytes,
        // so without coverage a prover hides a second authorization header in a
        // gap and the count still says one.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        _requireCommitmentValue(bearer.commitment, submission.publicInputs, OFF_IDENTITY_COMMITMENT);

        (fields.userId, fields.handle) = _readIdentityFields(_concatRevealed(data.received));
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// @dev Match a proved commitment against the one the attestation carried.
    ///      Without this the circuit could prove a link between two
    ///      attestations other than the ones submitted (REQ-PLAT-32C,
    ///      REQ-PLAT-52B).
    function _requireCommitmentValue(bytes32 attested, bytes32[] calldata publicInputs, uint256 offset) internal pure {
        bytes32 proved;
        for (uint256 i = 0; i < 32; ++i) {
            proved |= bytes32(uint256(uint8(uint256(publicInputs[offset + i]))) << (8 * (31 - i)));
        }
        if (proved != attested) revert CommitmentMismatch(proved, attested);
    }

    function _revealedAt(CeremonyAttestation.DirectionBlock memory block_, uint256 index)
        internal
        pure
        returns (bytes memory)
    {
        if (index >= block_.revealed.length) revert WrongRequestLine();
        return block_.revealed[index].value;
    }

    function _startsWith(bytes memory data, bytes memory prefix) internal pure returns (bool) {
        if (data.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    function _concatRevealed(CeremonyAttestation.DirectionBlock memory block_)
        internal
        pure
        returns (bytes memory out)
    {
        uint256 total;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            total += block_.revealed[i].value.length;
        }
        out = new bytes(total);
        uint256 n;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            bytes memory v = block_.revealed[i].value;
            for (uint256 j = 0; j < v.length; ++j) {
                out[n++] = v[j];
            }
        }
    }
}
