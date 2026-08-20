// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Builds section 9.1 attested data, for tests only.
///
/// @dev The inverse of `CeremonyAttestation.decode`. Rust-versus-Solidity
///      agreement on these bytes is proven separately, by the pinned fixture in
///      `CeremonyAttestation.t.sol`; this exists so a test can vary one field of
///      a session and watch a verifier refuse it.
library AttestationBuilder {
    struct Range {
        uint32 start;
        uint32 end;
        bytes value;
    }

    struct Commitment {
        uint32 start;
        uint32 end;
        bytes32 value;
    }

    struct Direction {
        Range[] revealed;
        Commitment[] commitments;
        uint32 length;
    }

    function encode(
        bytes32 formatTag,
        bytes32 platformId,
        bytes32 operationTag,
        bytes32 authorityId,
        uint64 createdAt,
        Direction memory sent,
        Direction memory received
    ) internal pure returns (bytes memory out) {
        out = abi.encodePacked(
            formatTag, platformId, operationTag, authorityId, createdAt, sent.length, received.length
        );
        out = abi.encodePacked(out, _direction(sent), _direction(received));
    }

    function _direction(Direction memory d) private pure returns (bytes memory out) {
        out = abi.encodePacked(uint16(d.revealed.length));
        for (uint256 i = 0; i < d.revealed.length; ++i) {
            out = abi.encodePacked(out, d.revealed[i].start, d.revealed[i].end, d.revealed[i].value);
        }
        out = abi.encodePacked(out, uint16(d.commitments.length));
        for (uint256 i = 0; i < d.commitments.length; ++i) {
            out = abi.encodePacked(out, d.commitments[i].start, d.commitments[i].end, d.commitments[i].value);
        }
    }

    function one(Range memory r) internal pure returns (Range[] memory out) {
        out = new Range[](1);
        out[0] = r;
    }

    function two(Range memory a, Range memory b) internal pure returns (Range[] memory out) {
        out = new Range[](2);
        out[0] = a;
        out[1] = b;
    }

    function one(Commitment memory c) internal pure returns (Commitment[] memory out) {
        out = new Commitment[](1);
        out[0] = c;
    }

    function none() internal pure returns (Commitment[] memory out) {
        out = new Commitment[](0);
    }

    function two(Commitment memory a, Commitment memory b) internal pure returns (Commitment[] memory out) {
        out = new Commitment[](2);
        out[0] = a;
        out[1] = b;
    }
}
