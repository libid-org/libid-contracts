// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CeremonyAttestation
/// @notice Decoder for the attested-data layout of ceremony-common section 9.1.
/// @dev The verifying side holds no transcript. It rebuilds these exact bytes
///      from what it was handed and derives the signing key from them, so a
///      field read differently here than the notary wrote it derives a key
///      nobody trusts. Every boundary is derivable from the bytes before it,
///      which is what lets this be one forward pass (REQ-COMMON-48).
///
///      This library reads and shape-checks. It decides nothing
///      profile-specific: which ranges a profile expects and what their bytes
///      must contain belong to the Platform Verifier (REQ-COMMON-51).
///
///      IT DOES NOT CHECK COVERAGE. `decode` accepts a transcript byte covered
///      by neither a revealed range nor a commitment, because REQ-COMMON-35 is
///      conditional: it governs an identity-session request that commits a
///      credential in an `Authorization` header, and REQ-COMMON-43 explicitly
///      withholds it from a credential committed in a request body, which is
///      GitHub's `client_secret`. A library that tiled unconditionally would
///      reject every valid GitHub token exchange.
///
///      A gap is where a prover hides bytes, so the Platform Verifier of an
///      identity session MUST call `requireExactCoverage` and MUST run the
///      needle scan of REQ-COMMON-39 and the framing check of REQ-COMMON-40
///      itself. Those three together are what make the committed range the one
///      region nobody can read and everything else visible.
library CeremonyAttestation {
    /// @dev The authority, `createdAt`, and the two transcript lengths.
    uint256 internal constant HEADER_LEN = 48;

    struct RevealedRange {
        uint32 start;
        uint32 end;
        bytes value;
    }

    struct RangeCommitment {
        uint32 start;
        uint32 end;
        bytes32 commitment;
    }

    struct DirectionBlock {
        RevealedRange[] revealed;
        RangeCommitment[] commitments;
    }

    struct AttestedData {
        /// @dev The TLS server name the notary authenticated, hashed. The only
        ///      identity in the record, and the one thing here the notary
        ///      observed rather than was told. Which platform that host belongs
        ///      to, and which session of a ceremony this is, are read from the
        ///      revealed request line by the verifier that pins those
        ///      constants.
        bytes32 authorityId;
        uint64 createdAt;
        uint32 sentTranscriptLength;
        uint32 recvTranscriptLength;
        DirectionBlock sent;
        DirectionBlock received;
    }

    error Truncated();
    error TrailingBytes(uint256 count);
    error EmptyRange(uint32 start);
    error OutOfOrder(uint32 start, uint32 previousEnd);
    error PastTranscriptEnd(uint32 end, uint32 length);
    error CommitmentOverlapsRevealed(uint32 start, uint32 end);
    /// @dev Transcript bytes `[from, to)` are covered by neither a revealed
    ///      range nor a commitment.
    error CoverageGap(uint32 from, uint32 to);
    /// @dev Spans overlap. `decode` rejects this already; naming it here beats
    ///      reporting a backwards gap to a caller that built a block by hand.
    error SpansOverlap(uint32 at);
    /// @dev This request commits exactly one credential, so several
    ///      commitments would leave the framed range and the proved range
    ///      unrelated.
    error NotOneCommitment(uint256 count);
    /// @dev An obsolete line fold in the revealed request bytes.
    error ObsoleteLineFold(uint256 at);
    /// @dev A line feed not preceded by a carriage return. The needle is
    ///      CRLF-anchored, so a bare LF starts a header line the count cannot
    ///      see -- and a platform parser that accepts it would honour that
    ///      header.
    error BareLineFeed(uint256 at);
    error NotOneAuthorizationHeader(uint256 count);
    error BadBearerFraming();
    /// @dev No commitment in this direction is framed by the delimiters the
    ///      profile pins, so nothing identifies which range holds the bearer.
    error NoFramedCommitment();
    /// @dev More than one is, so the framing identifies nothing.
    error AmbiguousFraming();

    /// @notice Parse and shape-check the attested data.
    /// @dev Trailing bytes are refused: the layout accounts for every byte, so
    ///      a suffix is a second message hiding behind the first.
    function decode(bytes calldata data) internal pure returns (AttestedData memory attested) {
        uint256 at = 0;

        attested.authorityId = _bytes32(data, at);
        attested.createdAt = uint64(_uint(data, at + 32, 8));
        attested.sentTranscriptLength = uint32(_uint(data, at + 40, 4));
        attested.recvTranscriptLength = uint32(_uint(data, at + 44, 4));
        at = HEADER_LEN;

        (attested.sent, at) = _direction(data, at);
        (attested.received, at) = _direction(data, at);

        if (at != data.length) revert TrailingBytes(data.length - at);

        _check(attested.sent, attested.sentTranscriptLength);
        _check(attested.received, attested.recvTranscriptLength);
    }

    /// @notice Require the revealed ranges and commitments of one direction to
    ///         tile `[0, length)` exactly, with no gap and no overlap
    ///         (REQ-COMMON-35).
    /// @dev Only for a direction whose profile demands exact coverage. Both
    ///      lists arrive ascending and internally non-overlapping from
    ///      `decode`, so this walks them as one merge: every step must begin
    ///      where the previous ended, and the last must end at the signed
    ///      transcript length. That leaves the committed range as the only
    ///      region the verifier cannot read, and makes its offset and length
    ///      follow from the ranges around it.
    /// @dev `\r\nauthorization: Bearer ` -- the raw bytes REQ-COMMON-40 wants
    ///      immediately before the committed range.
    bytes internal constant BEARER_PREFIX = "\r\nauthorization: Bearer ";
    /// @dev And immediately after it.
    bytes internal constant BEARER_SUFFIX = "\r\n";
    /// @dev The normalized, line-anchored needle REQ-COMMON-39 counts.
    bytes internal constant AUTHORIZATION_NEEDLE = "\r\nauthorization:bearer";

    /// @notice The one commitment framed by exactly these revealed bytes.
    ///
    /// @dev For a direction that is NOT exactly covered, where several ranges
    ///      are hidden and only the anchors around one of them are revealed.
    ///      The X token response is that case: the bearer is committed, the
    ///      `"access_token":"` delimiter and its closing quote are revealed,
    ///      and every other response byte sits behind a commitment of its own.
    ///
    ///      The framing is what IDENTIFIES the bearer, not its being the only
    ///      commitment. Without it a received direction revealing nothing at
    ///      all leaves the committed range indistinguishable from a
    ///      `refresh_token` value, or any other substring the prover chose to
    ///      commit (REQ-PLAT-57, REQ-PLAT-58).
    ///
    ///      Exactly one commitment may carry the framing. Two would leave
    ///      nothing to say which the circuit opened.
    function requireFramedCommitment(DirectionBlock memory block_, bytes memory prefix, bytes memory suffix)
        internal
        pure
        returns (RangeCommitment memory framed)
    {
        uint256 found = type(uint256).max;
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            RangeCommitment memory c = block_.commitments[i];
            if (c.start < prefix.length) continue;
            bytes memory before_ = _revealedSlice(block_, c.start - uint32(prefix.length), c.start);
            if (keccak256(before_) != keccak256(prefix)) continue;
            bytes memory after_ = _revealedSlice(block_, c.end, c.end + uint32(suffix.length));
            if (keccak256(after_) != keccak256(suffix)) continue;

            if (found != type(uint256).max) revert AmbiguousFraming();
            found = i;
        }
        if (found == type(uint256).max) revert NoFramedCommitment();
        return block_.commitments[found];
    }

    /// @notice Every check REQ-COMMON-35, -39 and -40 require of an
    ///         identity-session request that commits a credential in an HTTP
    ///         `Authorization` header.
    ///
    /// @dev At launch that is X's `/2/users/me` request and GitHub's `/user`
    ///      request, and nothing else. REQ-COMMON-43 forbids applying these to
    ///      a credential committed in a request body -- GitHub's token
    ///      exchange commits `client_secret` in a form body, so demanding a
    ///      CRLF-framed header around it would reject every valid exchange.
    ///
    ///      The three are one call because they are one property, and two of
    ///      them are worthless alone. The uniqueness scan counts the needle
    ///      across REVEALED bytes only, so a byte covered by nothing is a byte
    ///      it never reads: without coverage a prover hides a second
    ///      authorization header in a gap, the count stays at one, and the
    ///      platform honours whichever header it likes.
    ///
    /// @return commitment The committed bearer range, which the caller then
    ///         matches against the circuit's identity-bearer public input.
    function requireBearerHeaderRequest(DirectionBlock memory block_, uint32 length)
        internal
        pure
        returns (RangeCommitment memory commitment)
    {
        // One committed range, so the range REQ-COMMON-40 frames and the
        // commitment the circuit opens are the same object. REQ-COMMON-60
        // permits several per direction, and nothing else here would tie them.
        if (block_.commitments.length != 1) revert NotOneCommitment(block_.commitments.length);
        commitment = block_.commitments[0];

        requireExactCoverage(block_, length);

        // Obsolete line folding is illegal in HTTP/1.1 and defeats the needle:
        // `authorization:\r\n Bearer x` normalizes to
        // `authorization:\r\nbearer`, because normalization strips the space
        // but keeps the CRLF the fold introduced. The header is then never
        // counted, and a server honouring the fold authenticates with it.
        bytes memory revealed = _concatRevealed(block_);
        for (uint256 i = 0; i + 2 < revealed.length; ++i) {
            if (revealed[i] == 0x0d && revealed[i + 1] == 0x0a && (revealed[i + 2] == 0x20 || revealed[i + 2] == 0x09))
            {
                revert ObsoleteLineFold(i);
            }
        }
        // Every LF must be part of a CRLF. Otherwise
        // `...\nauthorization: Bearer <victim>\r\n` starts a header line the
        // CRLF-anchored needle never counts, while a lenient platform parser
        // honours it.
        for (uint256 i = 0; i < revealed.length; ++i) {
            if (revealed[i] == 0x0a && (i == 0 || revealed[i - 1] != 0x0d)) {
                revert BareLineFeed(i);
            }
        }

        // Counted per range rather than over the concatenation, so joining two
        // regions cannot manufacture a match at the seam.
        uint256 count;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            count += _countNeedle(_normalizeHeaderBytes(block_.revealed[i].value));
        }
        if (count != 1) revert NotOneAuthorizationHeader(count);

        // Framing, on RAW bytes at known offsets. Two fixed comparisons make
        // the committed range one header line's value by construction.
        if (commitment.start < BEARER_PREFIX.length) revert BadBearerFraming();
        bytes memory before_ = _revealedSlice(block_, commitment.start - uint32(BEARER_PREFIX.length), commitment.start);
        bytes memory after_ = _revealedSlice(block_, commitment.end, commitment.end + uint32(BEARER_SUFFIX.length));
        if (keccak256(before_) != keccak256(BEARER_PREFIX) || keccak256(after_) != keccak256(BEARER_SUFFIX)) {
            revert BadBearerFraming();
        }
    }

    /// @dev Lowercase ASCII and drop every space and horizontal tab, keeping CR
    ///      and LF (REQ-COMMON-39). Field names and the scheme token are
    ///      case-insensitive and the colon admits whitespace, so a literal
    ///      search over raw bytes is evadable. Removing only bytes absent from
    ///      the needle can create a spurious match, which over-rejects and is
    ///      safe, but can never hide a real one.
    function _normalizeHeaderBytes(bytes memory raw) private pure returns (bytes memory out) {
        out = new bytes(raw.length);
        uint256 n;
        for (uint256 i = 0; i < raw.length; ++i) {
            bytes1 c = raw[i];
            if (c == 0x20 || c == 0x09) continue;
            if (c >= 0x41 && c <= 0x5a) c = bytes1(uint8(c) + 0x20);
            out[n++] = c;
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function _countNeedle(bytes memory haystack) private pure returns (uint256 count) {
        bytes memory needle = AUTHORIZATION_NEEDLE;
        if (haystack.length < needle.length) return 0;
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) ++count;
        }
    }

    function _concatRevealed(DirectionBlock memory block_) private pure returns (bytes memory out) {
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

    /// @dev Read `[from, to)` of the transcript out of the revealed ranges.
    ///      Returns an empty result if any byte of it is not revealed, which
    ///      the caller treats as a framing failure.
    function _revealedSlice(DirectionBlock memory block_, uint32 from, uint32 to)
        private
        pure
        returns (bytes memory out)
    {
        if (to <= from) return "";
        out = new bytes(to - from);
        uint256 n;
        uint32 at = from;
        while (at < to) {
            bool found;
            for (uint256 i = 0; i < block_.revealed.length; ++i) {
                RevealedRange memory r = block_.revealed[i];
                if (r.start <= at && at < r.end) {
                    uint256 offset = at - r.start;
                    uint256 take = r.value.length - offset;
                    if (take > to - at) take = to - at;
                    for (uint256 j = 0; j < take; ++j) {
                        out[n++] = r.value[offset + j];
                    }
                    at += uint32(take);
                    found = true;
                    break;
                }
            }
            if (!found) return "";
        }
    }

    function requireExactCoverage(DirectionBlock memory block_, uint32 length) internal pure {
        uint256 r = 0;
        uint256 c = 0;
        uint32 at = 0;

        while (r < block_.revealed.length || c < block_.commitments.length) {
            bool takeRevealed;
            if (r < block_.revealed.length && c < block_.commitments.length) {
                takeRevealed = block_.revealed[r].start <= block_.commitments[c].start;
            } else {
                takeRevealed = r < block_.revealed.length;
            }

            uint32 start;
            uint32 end;
            if (takeRevealed) {
                start = block_.revealed[r].start;
                end = block_.revealed[r].end;
                ++r;
            } else {
                start = block_.commitments[c].start;
                end = block_.commitments[c].end;
                ++c;
            }

            if (start < at) revert SpansOverlap(start);
            if (start != at) revert CoverageGap(at, start);
            at = end;
        }

        if (at != length) revert CoverageGap(at, length);
    }

    /// @notice `keccak256(attestedData)` -- the only preimage the notary signs.
    function digest(bytes calldata data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    // --- Reading -----------------------------------------------------------

    function _direction(bytes calldata data, uint256 at)
        private
        pure
        returns (DirectionBlock memory block_, uint256 next)
    {
        // Counts are eight bytes: the encoder writes a `Vec` length, and a
        // length that cannot be represented is not a shorter length.
        uint256 count = _uint(data, at, 8);
        at += 8;
        block_.revealed = new RevealedRange[](count);
        for (uint256 i = 0; i < count; ++i) {
            uint32 start = uint32(_uint(data, at, 4));
            // The range's length is its bytes. There is no separate `end` to
            // disagree with it, so `end` here is arithmetic rather than a claim.
            uint256 len = _uint(data, at + 4, 8);
            at += 12;
            if (at + len > data.length) revert Truncated();
            if (start + len > type(uint32).max) revert Truncated();
            block_.revealed[i] = RevealedRange({start: start, end: uint32(start + len), value: data[at:at + len]});
            at += len;
        }

        count = _uint(data, at, 8);
        at += 8;
        block_.commitments = new RangeCommitment[](count);
        for (uint256 i = 0; i < count; ++i) {
            block_.commitments[i] = RangeCommitment({
                start: uint32(_uint(data, at, 4)),
                end: uint32(_uint(data, at + 4, 4)),
                commitment: _bytes32(data, at + 8)
            });
            at += 40;
        }
        next = at;
    }

    function _bytes32(bytes calldata data, uint256 at) private pure returns (bytes32 out) {
        if (at + 32 > data.length) revert Truncated();
        out = bytes32(data[at:at + 32]);
    }

    /// @dev Big-endian read of `width` bytes, `width <= 32`.
    function _uint(bytes calldata data, uint256 at, uint256 width) private pure returns (uint256 out) {
        if (at + width > data.length) revert Truncated();
        for (uint256 i = 0; i < width; ++i) {
            out = (out << 8) | uint8(data[at + i]);
        }
    }

    // --- Shape -------------------------------------------------------------

    /// @dev Ranges ascend, are nonempty, do not overlap, and end inside the
    ///      signed transcript length; commitments additionally never overlap a
    ///      revealed range (REQ-COMMON-59, REQ-COMMON-60).
    function _check(DirectionBlock memory block_, uint32 length) private pure {
        uint32 previousEnd = 0;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            RevealedRange memory range = block_.revealed[i];
            _span(range.start, range.end, length, previousEnd);
            previousEnd = range.end;
        }

        previousEnd = 0;
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            RangeCommitment memory commitment = block_.commitments[i];
            _span(commitment.start, commitment.end, length, previousEnd);
            previousEnd = commitment.end;
        }

        // Cross-overlap as one merge rather than a nested scan: both lists are
        // ascending and internally disjoint by the checks above, so a single
        // pass sees every adjacent pair. The nested form was quadratic in
        // attacker-chosen counts.
        uint256 r = 0;
        uint256 c = 0;
        while (r < block_.revealed.length && c < block_.commitments.length) {
            RevealedRange memory range = block_.revealed[r];
            RangeCommitment memory commitment = block_.commitments[c];
            if (commitment.start < range.end && range.start < commitment.end) {
                revert CommitmentOverlapsRevealed(commitment.start, commitment.end);
            }
            if (range.end <= commitment.end) ++r;
            else ++c;
        }
    }

    function _span(uint32 start, uint32 end, uint32 length, uint32 previousEnd) private pure {
        if (end <= start) revert EmptyRange(start);
        if (start < previousEnd) revert OutOfOrder(start, previousEnd);
        if (end > length) revert PastTranscriptEnd(end, length);
    }
}
