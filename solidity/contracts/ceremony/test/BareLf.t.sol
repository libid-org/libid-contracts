// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";

/// Did the bare-LF guard actually close anything? Verified, not assumed.
contract BareLfTest is Test {
    function run(CeremonyAttestation.DirectionBlock memory b, uint32 len) external pure {
        CeremonyAttestation.requireBearerHeaderRequest(b, len);
    }

    function _req(string memory extra) private pure returns (CeremonyAttestation.DirectionBlock memory b, uint32 len) {
        bytes memory head =
            abi.encodePacked("GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n", extra, "\r\nauthorization: Bearer ");
        bytes memory bearer = "TOKENVALUE";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 s = uint32(head.length);
        uint32 e = s + uint32(bearer.length);
        len = e + uint32(tail.length);
        b.revealed = new CeremonyAttestation.RevealedRange[](2);
        b.revealed[0] = CeremonyAttestation.RevealedRange({start: 0, end: s, value: head});
        b.revealed[1] = CeremonyAttestation.RevealedRange({start: e, end: len, value: tail});
        b.commitments = new CeremonyAttestation.RangeCommitment[](1);
        b.commitments[0] = CeremonyAttestation.RangeCommitment({start: s, end: e, commitment: bytes32(uint256(1))});
    }

    /// A second authorization header on a BARE-LF line. The needle is
    /// CRLF-anchored, so before the guard this counted zero and passed.
    function test_aBareLfHeaderIsRefused() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _req("x-pad: a\nauthorization: Bearer STOLEN\r\n");
        vm.expectPartialRevert(CeremonyAttestation.BareLineFeed.selector);
        this.run(b, len);
    }

    function test_anHonestRequestStillVerifies() public view {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _req("accept: application/json\r\n");
        this.run(b, len);
    }
}
