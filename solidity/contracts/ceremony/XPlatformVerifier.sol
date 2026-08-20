// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyFields} from "./CeremonyFields.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @title XPlatformVerifier — the `x/v1` profile.
///
/// @notice Two notarized sessions, both authenticated, one hidden bearer
///         linking them, and one proof binding that link to the transaction.
///
/// @dev The proof proves exactly one thing: one hidden bearer opens both
///      attestations' blinded commitments. Everything else is checked here,
///      where it can be seen — the digest by recomputing the PKCE verifier, the
///      client identifier and identity fields by reading revealed bytes, the
///      authority from what the notary authenticated. A fact checkable in the
///      open does not belong in a proof.
///
///      THE REVEALED LAYOUT IS A PROFILE DECISION. REQ-COMMON-17A requires the
///      profile to list the exact ranges a session reveals but does not fix
///      them, so `x/v1` pins them here:
///
///        token request  — two revealed sent ranges: the request line at offset
///                         0, then the whole form body. X hides no body field,
///                         so the body is contiguous and every field in it is
///                         readable.
///        identity request — the bearer committed, every other byte revealed and
///                         tiled exactly, per REQ-COMMON-35.
///        identity response — the `id` and `username` fields with their full
///                         delimiters revealed; everything else committed.
///
///      A notary emitting a different layout produces attestations this
///      verifier rejects, so the layout must be agreed with the notary before
///      either ships.
contract XPlatformVerifier is IPlatformVerifier, PlatformVerifierBase {
    // ─── Profile constants ──────────────────────────────────────────

    bytes32 private constant PLATFORM = CeremonyProfile.PLATFORM_X;
    bytes32 private constant AUTHORITY = CeremonyProfile.AUTHORITY_X_API;

    bytes private constant TOKEN_REQUEST_LINE = "POST /2/oauth2/token ";
    bytes private constant GRANT_TYPE = "authorization_code";

    /// @dev The circuit exposes two 32-byte commitments as 64 public inputs,
    ///      one byte each.
    uint256 private constant PUBLIC_INPUTS = 64;
    uint256 private constant OFF_TOKEN_COMMITMENT = 0;
    uint256 private constant OFF_IDENTITY_COMMITMENT = 32;

    error UnexpectedClientIdentifier();
    error WrongPublicInputCount(uint256 expected, uint256 provided);
    error WrongRequestLine();
    error WrongGrantType(bytes found);
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    error CommitmentMismatch(bytes32 proved, bytes32 attested);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_
    ) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_, proofLifetime_, maxFutureAttestationSkew_);
    }

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return PLATFORM;
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
        // X reads its client identifier from a revealed range, so a
        // caller-supplied copy would be a duplicate of a value the attested
        // data already carries (REQ-COMMON-52).
        if (submission.clientIdentifier.length != 0) revert UnexpectedClientIdentifier();
        if (submission.publicInputs.length != PUBLIC_INPUTS) {
            revert WrongPublicInputCount(PUBLIC_INPUTS, submission.publicInputs.length);
        }

        uint64 observedAt = _checkTokenSession(authorizationDigest, submission, fee, fields);
        _checkIdentitySession(submission, fee, fields);

        // Only now is the proof worth verifying: the commitments it links are
        // the ones the attestations carried.
        _requireProof(submission.proof, submission.publicInputs);

        fields.metadataObservedAt = observedAt;
    }

    // ─── The token session ──────────────────────────────────────────

    function _checkTokenSession(
        bytes32 authorizationDigest,
        Submission calldata submission,
        uint256 fee,
        PlatformFields memory fields
    ) private returns (uint64 observedAt) {
        CeremonyAttestation.AttestedData memory data = _authenticate(
            submission.attestations[0], PLATFORM, CeremonyProfile.TOKEN_SESSION_TAG, AUTHORITY, fee
        );

        bytes memory line = _revealedAt(data.sent, 0);
        if (!_startsWith(line, TOKEN_REQUEST_LINE)) revert WrongRequestLine();

        bytes memory body = _revealedAt(data.sent, 1);

        // REQ-PLAT-56. The runtime's own comparison runs in software the prover
        // chooses whether to run, and `grant_type` is the one revealed field
        // that changes what X did with the request: a body sending
        // `refresh_token` while still carrying a code, a redirect_uri and a
        // digest-derived verifier is processed as a refresh, returns a fresh
        // bearer, and passes every other check — so an application holding a
        // user's refresh token could mint identity proofs at arbitrary
        // addresses indefinitely from one consent.
        bytes memory grantType = CeremonyFields.formField(body, "grant_type");
        if (keccak256(grantType) != keccak256(GRANT_TYPE)) revert WrongGrantType(grantType);

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

        _requireCommitment(data.received, submission.publicInputs, OFF_TOKEN_COMMITMENT);

        return _requireFresh(data.createdAt);
    }

    // ─── The identity session ───────────────────────────────────────

    function _checkIdentitySession(Submission calldata submission, uint256 fee, PlatformFields memory fields) private {
        CeremonyAttestation.AttestedData memory data =
            _authenticate(submission.attestations[1], PLATFORM, CeremonyProfile.IDENTITY_SESSION_TAG, AUTHORITY, fee);

        // Coverage, the line-anchored uniqueness scan, and the framing bytes,
        // together. They are one property: the scan reads only revealed bytes,
        // so without coverage a prover hides a second authorization header in a
        // gap and the count still says one.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        _requireCommitmentValue(bearer.commitment, submission.publicInputs, OFF_IDENTITY_COMMITMENT);

        // REQ-PLAT-31: read both fields by their full delimiters, refusing a
        // transcript where either matches twice.
        bytes memory recv = _concatRevealed(data.received);
        fields.userId = string(CeremonyFields.jsonString(recv, "id"));
        fields.handle = string(CeremonyFields.jsonString(recv, "username"));
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// @dev Match a proved commitment against the one the attestation carried.
    ///      Without this the circuit could prove a link between two
    ///      attestations other than the ones submitted (REQ-PLAT-32C).
    function _requireCommitment(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes32[] calldata publicInputs,
        uint256 offset
    ) private pure {
        if (block_.commitments.length != 1) {
            revert CeremonyAttestation.NotOneCommitment(block_.commitments.length);
        }
        _requireCommitmentValue(block_.commitments[0].commitment, publicInputs, offset);
    }

    function _requireCommitmentValue(bytes32 attested, bytes32[] calldata publicInputs, uint256 offset) private pure {
        bytes32 proved;
        for (uint256 i = 0; i < 32; ++i) {
            proved |= bytes32(uint256(uint8(uint256(publicInputs[offset + i]))) << (8 * (31 - i)));
        }
        if (proved != attested) revert CommitmentMismatch(proved, attested);
    }

    function _revealedAt(CeremonyAttestation.DirectionBlock memory block_, uint256 index)
        private
        pure
        returns (bytes memory)
    {
        if (index >= block_.revealed.length) revert WrongRequestLine();
        return block_.revealed[index].value;
    }

    function _startsWith(bytes memory data, bytes memory prefix) private pure returns (bool) {
        if (data.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    function _concatRevealed(CeremonyAttestation.DirectionBlock memory block_) private pure returns (bytes memory out) {
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
