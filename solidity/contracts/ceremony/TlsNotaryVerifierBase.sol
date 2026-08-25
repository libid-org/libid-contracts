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
    /// @dev The caller supplied public inputs. This verifier derives them.
    error UnexpectedPublicInputs();
    error WrongRequestLine();
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    /// @dev A field was found in no revealed range, or in more than one.
    error FieldNotUnique(string name, uint256 rangesMatching);
    /// @dev The first revealed range does not begin the transcript, so nothing
    ///      says the bytes read as a request line ARE the request line.
    error RequestLineNotAtOrigin(uint32 start);
    /// @dev The last revealed range does not reach the signed transcript end.
    error BodyNotAtTranscriptEnd(uint32 end, uint32 length);
    /// @dev The token request does not have the exact shape the profile fixes.
    error WrongTokenRequestLayout(uint256 revealedRanges, uint256 commitments);
    /// @dev The head/body separator is missing or ambiguous, so the body cannot
    ///      be located by the framing the server itself parsed.
    error NoHeadBoundary(uint256 occurrences);

    // ─── What a profile supplies ────────────────────────────────────

    function _platform() internal pure virtual returns (bytes32);
    function _tokenAuthority() internal pure virtual returns (bytes32);
    function _identityAuthority() internal pure virtual returns (bytes32);
    function _tokenRequestLine() internal pure virtual returns (bytes memory);
    function _identityRequestLine() internal pure virtual returns (bytes memory);

    /// @dev How many committed ranges the token request carries. X hides no
    ///      body field and uses a public client, so zero; GitHub commits its
    ///      `client_secret`, ordered last, so one.
    function _tokenSentCommitments() internal pure virtual returns (uint256);

    /// @dev Anything the profile checks in the token body beyond the fields
    ///      every profile reads. Default: nothing.
    function _checkTokenBody(bytes memory body) internal pure virtual {}

    /// @dev Which shape a platform's immutable identifier takes in its identity
    ///      response. X quotes it; GitHub sends a bare integer, whose
    ///      terminator is what proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one.
    enum IdShape {
        JsonString,
        JsonInteger
    }

    /// @dev The two identity members this profile reads, as DATA rather than as
    ///      a reading routine.
    ///
    ///      A hook handed the direction block could concatenate its revealed
    ///      ranges, index them positionally, or read `revealed[0]` -- and each
    ///      of those has broken this verifier before. Concatenation discards
    ///      every offset, so a prover revealing disjoint fragments gets them
    ///      joined into a document that never crossed the wire. Positional
    ///      reads take whichever range the prover put first.
    ///
    ///      Declaring the field names and leaving the reading to the base makes
    ///      all three unwritable rather than forbidden by a comment. A new
    ///      profile supplies two strings and a shape; it never touches an
    ///      attestation.
    function _identityFields()
        internal
        pure
        virtual
        returns (string memory idField, IdShape idShape, string memory handleField);

    /// @dev How many times a field's full delimiter appears across the whole
    ///      revealed set, seams included.
    ///
    ///      Counting and reading want opposite things. A READ must stay inside
    ///      one authenticated range, or a prover splices a document that never
    ///      crossed the wire. A COUNT must not miss, or a prover cuts a range
    ///      through a second delimiter and the duplicate REQ-COMMON-19A exists
    ///      to reject becomes invisible to it. So the value is read per range
    ///      and the occurrences are counted over the concatenation -- where a
    ///      seam can only over-count, which fails closed.
    function _delimiterCount(CeremonyAttestation.DirectionBlock memory block_, bytes memory delimiter)
        private
        pure
        returns (uint256 count)
    {
        uint256 total;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            total += block_.revealed[i].value.length;
        }
        bytes memory joined = new bytes(total);
        uint256 at;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            bytes memory v = block_.revealed[i].value;
            for (uint256 j = 0; j < v.length; ++j) {
                joined[at++] = v[j];
            }
        }
        for (uint256 i = 0; i + delimiter.length <= joined.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < delimiter.length; ++j) {
                if (joined[i + j] != delimiter[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) ++count;
        }
    }

    /// @dev Find a JSON string field in exactly one revealed range.
    ///
    ///      Reading from a concatenation of the revealed ranges is what this
    ///      exists to prevent. Concatenation discards every offset, so a prover
    ///      revealing disjoint fragments -- the opening of one member, the
    ///      middle of a display name, the tail of another member -- gets them
    ///      joined into a document that never existed on the wire, and the
    ///      duplicate-delimiter check of REQ-COMMON-19A has nothing to fire on
    ///      because the genuine member is simply not in the buffer.
    ///
    ///      Requiring the whole match to sit inside one authenticated range
    ///      means every byte of it came from one contiguous run the notary
    ///      signed, at the offsets it signed them at.
    function _uniqueJsonString(CeremonyAttestation.DirectionBlock memory block_, string memory name)
        private
        pure
        returns (bytes memory value)
    {
        uint256 matches;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            (CeremonyFields.Found found, bytes memory v) = CeremonyFields.tryJsonString(block_.revealed[i].value, name);
            if (found == CeremonyFields.Found.Several) revert FieldNotUnique(name, 2);
            if (found == CeremonyFields.Found.One) {
                ++matches;
                value = v;
            }
        }
        if (matches != 1) revert FieldNotUnique(name, matches);
        // And the delimiter appears once across the whole revealed set, so a
        // second copy cannot hide under a range boundary.
        uint256 seen = _delimiterCount(block_, abi.encodePacked('"', name, '":"'));
        if (seen != 1) revert FieldNotUnique(name, seen);
    }

    /// @dev The same, for a bare JSON integer.
    function _uniqueJsonInteger(CeremonyAttestation.DirectionBlock memory block_, string memory name)
        private
        pure
        returns (bytes memory digits)
    {
        uint256 matches;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            (CeremonyFields.Found found, bytes memory v) = CeremonyFields.tryJsonInteger(block_.revealed[i].value, name);
            if (found == CeremonyFields.Found.Several) revert FieldNotUnique(name, 2);
            if (found == CeremonyFields.Found.One) {
                ++matches;
                digits = v;
            }
        }
        if (matches != 1) revert FieldNotUnique(name, matches);
        uint256 seen = _delimiterCount(block_, abi.encodePacked('"', name, '":'));
        if (seen != 1) revert FieldNotUnique(name, seen);
    }

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
        // Nor any public input. They are not the caller's to state: both are
        // commitments this verifier has just read out of attestations it
        // authenticated, so accepting a copy would be accepting a second
        // representation of a fact it already holds -- and then having to
        // check the two agree.
        if (submission.publicInputs.length != 0) revert UnexpectedPublicInputs();

        (uint64 observedAt, bytes32 tokenCommitment) = _tokenSession(authorizationDigest, submission, fee, fields);
        bytes32 identityCommitment = _identitySession(submission, fee, fields);

        // Built, not compared. The proof verifies against the commitments the
        // notary signed and nothing else can be substituted for them.
        _requireProof(submission.proof, _publicInputs(tokenCommitment, identityCommitment));
        fields.metadataObservedAt = observedAt;
    }

    function _tokenSession(
        bytes32 authorizationDigest,
        Submission calldata submission,
        uint256 fee,
        PlatformFields memory fields
    ) private returns (uint64 observedAt, bytes32 tokenCommitment) {
        CeremonyAttestation.AttestedData memory data = _authenticate(submission.attestations[0], _tokenAuthority(), fee);

        // REQ-COMMON-18A applies to THIS direction too. Without tiling, a
        // prover reveals two header values it composed itself and this verifier
        // reads them as the request line and the body -- every field below then
        // comes from bytes the prover typed rather than from the request the
        // platform answered.
        CeremonyAttestation.requireExactCoverage(data.sent, data.sentTranscriptLength);

        // Range 0 must BEGIN the transcript. Indexing the list is not enough:
        // the lowest-offset revealed range is wherever the prover put it. An
        // empty list passes coverage against a zero signed length, so it is
        // named here rather than left to an out-of-bounds panic that tells an
        // operator nothing.
        if (data.sent.revealed.length == 0) revert RequestLineNotAtOrigin(type(uint32).max);
        if (data.sent.revealed[0].start != 0) {
            revert RequestLineNotAtOrigin(data.sent.revealed[0].start);
        }
        if (!_startsWith(data.sent.revealed[0].value, _tokenRequestLine())) revert WrongRequestLine();

        bytes memory body = _tokenBody(data.sent);
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

        // Tiled, like every other direction. The profile says every byte
        // outside the anchors is committed; this is what makes that true rather
        // than stated, and it is what leaves the framing below nothing to work
        // around -- a byte that is neither revealed nor committed is a byte the
        // notary never signed a position for.
        CeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);

        // The bearer is identified by its framing, not by being the only
        // commitment: the response hides every other byte behind one of its own.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireFramedCommitment(data.received, ACCESS_TOKEN_PREFIX, ACCESS_TOKEN_SUFFIX);
        tokenCommitment = bearer.commitment;

        // The token attestation is the one-time PKCE and digest binding, so it
        // alone supplies evidence time (section 2.2).
        observedAt = _requireFresh(data.createdAt);
    }

    function _identitySession(Submission calldata submission, uint256 fee, PlatformFields memory fields)
        private
        returns (bytes32 identityCommitment)
    {
        CeremonyAttestation.AttestedData memory data =
            _authenticate(submission.attestations[1], _identityAuthority(), fee);

        // REQ-COMMON-21A: the path separates operations on the same server.
        // Anchored at the origin for the same reason as the token request --
        // the lowest-offset revealed range is wherever the prover put it.
        if (data.sent.revealed.length == 0 || data.sent.revealed[0].start != 0) {
            revert RequestLineNotAtOrigin(data.sent.revealed.length == 0
                    ? type(uint32).max
                    : data.sent.revealed[0].start);
        }
        if (!_startsWith(data.sent.revealed[0].value, _identityRequestLine())) {
            revert WrongRequestLine();
        }

        // Coverage, the line-anchored uniqueness scan and the framing bytes,
        // together. They are one property: the scan reads only revealed bytes,
        // so without coverage a prover hides a second authorization header in a
        // gap and the count still says one.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        identityCommitment = bearer.commitment;

        // The response direction is tiled too, so no byte of it is invisible.
        CeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);
        (string memory idField, IdShape idShape, string memory handleField) = _identityFields();
        fields.userId = string(
            idShape == IdShape.JsonString
                ? _uniqueJsonString(data.received, idField)
                : _uniqueJsonInteger(data.received, idField)
        );
        fields.handle = string(_uniqueJsonString(data.received, handleField));
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// @dev Match a proved commitment against the one the attestation carried.
    ///      Without this the circuit could prove a link between two
    ///      attestations other than the ones submitted (REQ-PLAT-32C,
    ///      REQ-PLAT-52B).
    /// @dev The circuit's public inputs, as this verifier derives them.
    ///
    ///      Two 32-byte commitments as 64 field elements of one byte each,
    ///      token first. The circuit fixes that order; this contract fixes
    ///      where the bytes come from -- the attestations it just
    ///      authenticated, never the caller.
    ///
    ///      There used to be a comparison here instead, against inputs the
    ///      caller supplied. It cost 64 words of calldata to say something the
    ///      verifier already knew, and it could be got wrong: reconstructing a
    ///      byte with `uint8(...)` accepted a field element of 0x0101 as 0x01,
    ///      so the binding rested on the circuit range-constraining outputs
    ///      this contract cannot see. Derived, there is nothing to constrain
    ///      and nothing to disagree with.
    function _publicInputs(bytes32 tokenCommitment, bytes32 identityCommitment)
        private
        pure
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](PUBLIC_INPUTS);
        for (uint256 i = 0; i < 32; ++i) {
            inputs[OFF_TOKEN_COMMITMENT + i] = bytes32(uint256(uint8(tokenCommitment[i])));
            inputs[OFF_IDENTITY_COMMITMENT + i] = bytes32(uint256(uint8(identityCommitment[i])));
        }
    }

    /// @dev The HTTP message body of the token request.
    ///
    ///      Located by the framing the SERVER parsed -- the `\r\n\r\n` that ends
    ///      the head -- and not by a position in the range list. That
    ///      distinction is the whole point: a prover who can choose which run
    ///      counts as "the body" simply reveals a decoy after committing the
    ///      real one, and every field below is then read from bytes the
    ///      platform never saw while the platform executed something else.
    ///
    ///      So the profile fixes the shape exactly: ONE revealed run beginning
    ///      at offset 0, and exactly the committed ranges the profile expects.
    ///      X carries none, because it hides no body field and authenticates
    ///      with a public client; GitHub carries one, its `client_secret`,
    ///      ordered last under REQ-COMMON-22 and reaching the transcript end.
    function _tokenBody(CeremonyAttestation.DirectionBlock memory block_) internal pure returns (bytes memory body) {
        if (block_.revealed.length != 1 || block_.commitments.length != _tokenSentCommitments()) {
            revert WrongTokenRequestLayout(block_.revealed.length, block_.commitments.length);
        }
        bytes memory whole = block_.revealed[0].value;

        // Exactly one head boundary. A well-formed request has one; requiring
        // it removes any question of which run of bytes the body is.
        uint256 at = type(uint256).max;
        uint256 seen;
        for (uint256 i = 0; i + 4 <= whole.length; ++i) {
            if (whole[i] == 0x0d && whole[i + 1] == 0x0a && whole[i + 2] == 0x0d && whole[i + 3] == 0x0a) {
                ++seen;
                if (at == type(uint256).max) at = i;
            }
        }
        if (seen != 1) revert NoHeadBoundary(seen);

        at += 4;
        body = new bytes(whole.length - at);
        for (uint256 i = 0; i < body.length; ++i) {
            body[i] = whole[at + i];
        }
    }

    function _startsWith(bytes memory data, bytes memory prefix) internal pure returns (bool) {
        if (data.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }
}
