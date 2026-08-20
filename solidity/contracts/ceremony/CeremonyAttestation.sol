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
library CeremonyAttestation {
    /// @dev Four 32-byte tags, `createdAt`, and the two transcript lengths.
    uint256 internal constant HEADER_LEN = 144;

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
        bytes32 formatTag;
        bytes32 platformId;
        bytes32 operationTag;
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

    /// @notice Parse and shape-check the attested data.
    /// @dev Trailing bytes are refused: the layout accounts for every byte, so
    ///      a suffix is a second message hiding behind the first.
    function decode(bytes calldata data) internal pure returns (AttestedData memory attested) {
        uint256 at = 0;

        attested.formatTag = _bytes32(data, at);
        attested.platformId = _bytes32(data, at + 32);
        attested.operationTag = _bytes32(data, at + 64);
        attested.authorityId = _bytes32(data, at + 96);
        attested.createdAt = uint64(_uint(data, at + 128, 8));
        attested.sentTranscriptLength = uint32(_uint(data, at + 136, 4));
        attested.recvTranscriptLength = uint32(_uint(data, at + 140, 4));
        at = HEADER_LEN;

        (attested.sent, at) = _direction(data, at);
        (attested.received, at) = _direction(data, at);

        if (at != data.length) revert TrailingBytes(data.length - at);

        _check(attested.sent, attested.sentTranscriptLength);
        _check(attested.received, attested.recvTranscriptLength);
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
        uint256 count = _uint(data, at, 2);
        at += 2;
        block_.revealed = new RevealedRange[](count);
        for (uint256 i = 0; i < count; ++i) {
            uint32 start = uint32(_uint(data, at, 4));
            uint32 end = uint32(_uint(data, at + 4, 4));
            at += 8;
            // A start past its end would underflow a length; the shape check
            // rejects it, so read nothing here rather than compute a huge one.
            uint256 len = end > start ? end - start : 0;
            if (at + len > data.length) revert Truncated();
            block_.revealed[i] = RevealedRange({start: start, end: end, value: data[at:at + len]});
            at += len;
        }

        count = _uint(data, at, 2);
        at += 2;
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

            for (uint256 j = 0; j < block_.revealed.length; ++j) {
                RevealedRange memory range = block_.revealed[j];
                if (commitment.start < range.end && range.start < commitment.end) {
                    revert CommitmentOverlapsRevealed(commitment.start, commitment.end);
                }
            }
        }
    }

    function _span(uint32 start, uint32 end, uint32 length, uint32 previousEnd) private pure {
        if (end <= start) revert EmptyRange(start);
        if (start < previousEnd) revert OutOfOrder(start, previousEnd);
        if (end > length) revert PastTranscriptEnd(end, length);
    }
}
