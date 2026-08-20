// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";

/// @notice The identity-session request checks of REQ-COMMON-35, -39 and -40,
///         exercised against the attacks each one exists to stop.
/// @dev Mirrors `libid-rs/crates/libid-ceremony/src/attestation.rs`.
contract BearerHeaderRequestTest is Test {
    bytes constant BEARER = "AAAAbbbbCCCCdddd";

    function run(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        external
        pure
        returns (CeremonyAttestation.RangeCommitment memory)
    {
        return CeremonyAttestation.requireBearerHeaderRequest(block_, length);
    }

    /// A real `/2/users/me` request: the bearer committed, every other byte
    /// revealed, tiled exactly.
    function _request(string memory extraHeader, string memory bearerPrefix)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length)
    {
        bytes memory head = abi.encodePacked(
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n", extraHeader, bearerPrefix
        );
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(BEARER.length);
        length = end + uint32(tail.length);

        block_.revealed = new CeremonyAttestation.RevealedRange[](2);
        block_.revealed[0] = CeremonyAttestation.RevealedRange({start: 0, end: start, value: head});
        block_.revealed[1] = CeremonyAttestation.RevealedRange({start: end, end: length, value: tail});
        block_.commitments = new CeremonyAttestation.RangeCommitment[](1);
        block_.commitments[0] =
            CeremonyAttestation.RangeCommitment({start: start, end: end, commitment: bytes32(uint256(5))});
    }

    function _honest() private pure returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length) {
        return _request("", "\r\nauthorization: Bearer ");
    }

    function test_acceptsAnHonestIdentityRequest() public view {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        CeremonyAttestation.RangeCommitment memory c = this.run(b, len);
        assertEq(c.commitment, bytes32(uint256(5)));
    }

    function test_rejectsASecondAuthorizationHeader() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _request("authorization: Bearer stolen\r\n", "\r\nauthorization: Bearer ");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneAuthorizationHeader.selector, 2));
        this.run(b, len);
    }

    /// @dev Field names and the scheme token are case-insensitive and the colon
    ///      admits whitespace, so a literal search would miss this one.
    function test_rejectsACaseAndWhitespaceEvadedSecondHeader() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _request("AuThOrIzAtIoN:\tBeArEr stolen\r\n", "\r\nauthorization: Bearer ");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneAuthorizationHeader.selector, 2));
        this.run(b, len);
    }

    /// @dev The gap a security review found. `authorization:\r\n Bearer x`
    ///      normalizes to `authorization:\r\nbearer`, so the needle does not
    ///      match and the header is never counted.
    function test_rejectsAnObsoleteLineFold() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _request("authorization:\r\n Bearer stolen\r\n", "\r\nauthorization: Bearer ");
        vm.expectPartialRevert(CeremonyAttestation.ObsoleteLineFold.selector);
        this.run(b, len);
    }

    function test_rejectsARequestWithNoAuthorizationHeader() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _request("", "\r\nx-other: ");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneAuthorizationHeader.selector, 0));
        this.run(b, len);
    }

    /// @dev Why the three are one call: open a gap and the hidden bytes are
    ///      never scanned at all.
    function test_rejectsAGapTheScanWouldNeverRead() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        b.revealed[0].end -= 1;
        bytes memory v = b.revealed[0].value;
        assembly ("memory-safe") {
            mstore(v, sub(mload(v), 1))
        }
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run(b, len);
    }

    /// @dev Framing alone: the authorization header is whole and revealed, so
    ///      the needle counts once and coverage is exact, but the committed
    ///      range sits in the `host` header instead.
    function test_rejectsACommitmentThatIsNotTheHeaderValue() public {
        bytes memory head =
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nauthorization: Bearer TOKEN123\r\nhost: ";
        bytes memory committed = "api.";
        bytes memory tail = "x.com\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(committed.length);
        uint32 len = end + uint32(tail.length);

        CeremonyAttestation.DirectionBlock memory b;
        b.revealed = new CeremonyAttestation.RevealedRange[](2);
        b.revealed[0] = CeremonyAttestation.RevealedRange({start: 0, end: start, value: head});
        b.revealed[1] = CeremonyAttestation.RevealedRange({start: end, end: len, value: tail});
        b.commitments = new CeremonyAttestation.RangeCommitment[](1);
        b.commitments[0] =
            CeremonyAttestation.RangeCommitment({start: start, end: end, commitment: bytes32(uint256(5))});

        vm.expectRevert(CeremonyAttestation.BadBearerFraming.selector);
        this.run(b, len);
    }

    /// @dev Several commitments would leave the framed range and the range the
    ///      circuit opens unrelated.
    function test_rejectsMoreThanOneCommitment() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        CeremonyAttestation.RangeCommitment[] memory two = new CeremonyAttestation.RangeCommitment[](2);
        two[0] = CeremonyAttestation.RangeCommitment({start: 0, end: 1, commitment: bytes32(uint256(6))});
        two[1] = b.commitments[0];
        b.commitments = two;
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneCommitment.selector, 2));
        this.run(b, len);
    }
}
