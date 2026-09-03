// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {AttestationBuilder} from "./AttestationBuilder.sol";

/// @notice Pins the section 9.1 decoder against bytes produced by the Rust
///         encoder in `libid-rs/crates/libid-ceremony`.
/// @dev The notary writes these bytes and the chain reads them, in two
///      languages. If the two ever disagree the notary's signature derives a
///      key nobody trusts and every genuine attestation is rejected, so the
///      fixture below is the load-bearing test in this file: it is the Rust
///      encoder's output, not this decoder's.
contract CeremonyAttestationTest is Test {
    /// @dev Shaped like an X identity session: the request reveals every byte
    ///      but the bearer, which is committed between the revealed ranges.
    bytes constant FIXTURE = hex"4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d"
        hex"0000000069800e800000003c0000002800000000000000020000000000000000"
        hex"0000001461616161616161616161616161616161616161610000002800000000"
        hex"0000001462626262626262626262626262626262626262620000000000000001"
        hex"0000001400000028070707070707070707070707070707070707070707070707"
        hex"0707070707070707000000000000000100000000000000000000000a63636363"
        hex"63636363636300000000000000010000000a0000002809090909090909090909"
        hex"09090909090909090909090909090909090909090909";

    bytes32 constant FIXTURE_DIGEST = 0x48162f05bdb27b19b3544bf2aae608745861bf357bb31e07f536b6fb50e95936;

    function decode(bytes calldata data) external pure returns (CeremonyAttestation.AttestedData memory) {
        return CeremonyAttestation.decode(data);
    }

    function test_decodesTheRustEncoderOutput() public view {
        CeremonyAttestation.AttestedData memory a = this.decode(FIXTURE);

        assertEq(a.authorityId, keccak256(bytes("api.x.com")));
        assertEq(a.createdAt, 1_770_000_000);
        assertEq(a.sentTranscriptLength, 60);
        assertEq(a.recvTranscriptLength, 40);

        assertEq(a.sent.revealed.length, 2);
        assertEq(a.sent.revealed[0].start, 0);
        assertEq(a.sent.revealed[0].end, 20);
        assertEq(string(a.sent.revealed[0].value), "aaaaaaaaaaaaaaaaaaaa");
        assertEq(a.sent.revealed[1].start, 40);
        assertEq(a.sent.revealed[1].end, 60);
        assertEq(string(a.sent.revealed[1].value), "bbbbbbbbbbbbbbbbbbbb");

        assertEq(a.sent.commitments.length, 1);
        assertEq(a.sent.commitments[0].start, 20);
        assertEq(a.sent.commitments[0].end, 40);
        assertEq(
            a.sent.commitments[0].commitment,
            bytes32(uint256(0x0707070707070707070707070707070707070707070707070707070707070707))
        );

        assertEq(a.received.revealed.length, 1);
        assertEq(string(a.received.revealed[0].value), "cccccccccc");
        assertEq(a.received.commitments.length, 1);
        assertEq(a.received.commitments[0].start, 10);
        assertEq(a.received.commitments[0].end, 40);
    }

    /// @dev The digest is what the notary signed, so Rust and Solidity must
    ///      agree on it exactly or no signature ever verifies.
    function test_digestAgreesWithRust() public pure {
        assertEq(keccak256(FIXTURE), FIXTURE_DIGEST);
    }

    function test_headerIsFortyEightBytes() public pure {
        assertEq(CeremonyAttestation.HEADER_LEN, 48);
    }

    function test_rejectsTrailingBytes() public {
        bytes memory extended = bytes.concat(FIXTURE, hex"00");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.TrailingBytes.selector, 1));
        this.decode(extended);
    }

    /// @dev Never reverts with a panic, whatever a caller hands it.
    function test_rejectsEveryTruncation() public {
        for (uint256 cut = 0; cut < FIXTURE.length; ++cut) {
            bytes memory prefix = new bytes(cut);
            for (uint256 i = 0; i < cut; ++i) {
                prefix[i] = FIXTURE[i];
            }
            (bool ok,) = address(this).staticcall(abi.encodeWithSelector(this.decode.selector, prefix));
            assertFalse(ok, "accepted a truncated attestation");
        }
    }

    function test_rejectsACountThatOutrunsTheBuffer() public {
        // A declared count of 0xffff with nothing behind it must not read past
        // the end.
        bytes memory tampered = FIXTURE;
        tampered[CeremonyAttestation.HEADER_LEN] = 0xff;
        tampered[CeremonyAttestation.HEADER_LEN + 1] = 0xff;
        (bool ok,) = address(this).staticcall(abi.encodeWithSelector(this.decode.selector, tampered));
        assertFalse(ok, "accepted an impossible range count");
    }

    function test_rejectsARangePastTheSignedTranscriptLength() public {
        // The signed length is what makes bytes past the last revealed range
        // visible at all (REQ-COMMON-36). Shrink it and the layout must fail.
        bytes memory tampered = FIXTURE;
        tampered[43] = 0x32; // sentTranscriptLength 60 -> 50
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.PastTranscriptEnd.selector, 60, 50));
        this.decode(tampered);
    }

    function coverSent(bytes calldata data) external pure {
        CeremonyAttestation.AttestedData memory a = CeremonyAttestation.decode(data);
        CeremonyAttestation.requireExactCoverage(a.sent, a.sentTranscriptLength);
    }

    /// @dev The pinned fixture tiles the sent direction exactly: 0..20 revealed,
    ///      20..40 committed, 40..60 revealed.
    function test_coverageAcceptsAnExactTiling() public view {
        this.coverSent(FIXTURE);
    }

    /// @dev Moving the commitment one byte forward leaves sent byte 20 covered
    ///      by nothing. `decode` accepts that on purpose -- coverage is
    ///      conditional under REQ-COMMON-43 -- and the identity-session
    ///      verifier is what must refuse it. A gap is where a prover hides
    ///      bytes, so this is the check that keeps the committed range the only
    ///      region nobody can read.
    function test_coverageRejectsAGap() public {
        bytes memory tampered = FIXTURE;
        tampered[131] = bytes1(uint8(21)); // sent commitment start 20 -> 21

        // decode alone still accepts it, which is why the helper exists.
        this.decode(tampered);

        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.CoverageGap.selector, 20, 21));
        this.coverSent(tampered);
    }

    /// @dev A trailing gap is the other half: bytes past the last range are
    ///      invisible without the signed length to close them (REQ-COMMON-36).
    function test_coverageRejectsATrailingGap() public {
        bytes memory tampered = FIXTURE;
        tampered[43] = 0x50; // sentTranscriptLength 60 -> 80
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.CoverageGap.selector, 60, 80));
        this.coverSent(tampered);
    }

    function _sentOnly(AttestationBuilder.Range[] memory r, AttestationBuilder.Commitment[] memory c, uint32 len)
        private
        pure
        returns (bytes memory)
    {
        AttestationBuilder.Direction memory d = AttestationBuilder.Direction({revealed: r, commitments: c, length: len});
        AttestationBuilder.Direction memory e = AttestationBuilder.Direction({
            revealed: new AttestationBuilder.Range[](0), commitments: AttestationBuilder.none(), length: 0
        });
        return AttestationBuilder.encode(bytes32(uint256(1)), 1, d, e);
    }

    function test_rejectsAnEmptyRange() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.EmptyRange.selector, uint32(3)));
        this.decode(
            _sentOnly(
                AttestationBuilder.one(AttestationBuilder.Range({start: 3, value: ""})), AttestationBuilder.none(), 10
            )
        );
    }

    function test_rejectsRangesOutOfOrder() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.OutOfOrder.selector, uint32(0), uint32(10)));
        this.decode(
            _sentOnly(
                AttestationBuilder.two(
                    AttestationBuilder.Range({start: 5, value: "aaaaa"}),
                    AttestationBuilder.Range({start: 0, value: "bbbbb"})
                ),
                AttestationBuilder.none(),
                10
            )
        );
    }

    function test_rejectsACommitmentOverlappingARevealedRange() public {
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyAttestation.CommitmentOverlapsRevealed.selector, uint32(3), uint32(10))
        );
        this.decode(
            _sentOnly(
                AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: "aaaaa"})),
                AttestationBuilder.one(AttestationBuilder.Commitment({start: 3, end: 10, value: bytes32(uint256(1))})),
                10
            )
        );
    }
}
