// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";

/// @notice The shared handle vector table, run against the Solidity normalizer.
///
/// @dev Rust and TypeScript run the same table from the same JSON. That is the
///      whole guard: three hand-written normalizers, one set of cases, so a
///      language that disagrees fails here instead of writing a different key
///      on chain.
contract HandleNormalizerTest is Test {
    function _rules(string memory platform) internal pure returns (HandleNormalizer.Rules memory) {
        bytes32 key = keccak256(bytes(platform));
        if (key == keccak256("x")) {
            return HandleNormalizer.Rules({
                maxLength: uint16(HandleVectors.MAX_LENGTH_X),
                stripLeadingAt: true,
                isEmail: false,
                allowUnderscore: true,
                allowHyphen: false
            });
        }
        if (key == keccak256("github")) {
            return HandleNormalizer.Rules({
                maxLength: uint16(HandleVectors.MAX_LENGTH_GITHUB),
                stripLeadingAt: true,
                isEmail: false,
                allowUnderscore: false,
                allowHyphen: true
            });
        }
        if (key == keccak256("google")) {
            return HandleNormalizer.Rules({
                maxLength: uint16(HandleVectors.MAX_LENGTH_GOOGLE),
                stripLeadingAt: false,
                isEmail: true,
                allowUnderscore: false,
                allowHyphen: false
            });
        }
        revert("unknown platform in the vector table");
    }

    /// Exposed so `vm.expectRevert` has an external call to watch.
    function normalize(string memory raw, string memory platform) external pure returns (string memory) {
        return HandleNormalizer.normalize(raw, _rules(platform));
    }

    function test_everyVectorMatchesTheSharedTable() public {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            if (v.accepted) {
                assertEq(
                    this.normalize(v.input, v.platform),
                    v.output,
                    string.concat("vector ", vm.toString(i), " normalized to the wrong handle")
                );
            } else {
                vm.expectRevert(_selector(v.errorKind));
                this.normalize(v.input, v.platform);
            }
        }
    }

    /// The vector table names WHICH refusal, not merely that one happened. A
    /// bare `expectRevert` would pass when the normalizer refused for the wrong
    /// reason, and the reason is what the three languages must agree on.
    function _selector(uint8 kind) internal pure returns (bytes4) {
        if (kind == HandleVectors.ERROR_EMPTY) return HandleNormalizer.EmptyHandle.selector;
        if (kind == HandleVectors.ERROR_TOOLONG) return HandleNormalizer.HandleTooLong.selector;
        if (kind == HandleVectors.ERROR_BADCHARACTER) return HandleNormalizer.BadCharacter.selector;
        if (kind == HandleVectors.ERROR_BADSHAPE) return HandleNormalizer.BadShape.selector;
        revert("unknown error kind in the vector table");
    }

    /// The table must keep covering both outcomes. A regeneration that dropped
    /// every refusal would leave the test green and prove nothing.
    function test_theTableCoversBothOutcomes() public pure {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        uint256 accepted;
        uint256 refused;
        for (uint256 i = 0; i < vectors.length; i++) {
            if (vectors[i].accepted) accepted++;
            else refused++;
        }
        assertTrue(accepted > 0, "the table accepts nothing");
        assertTrue(refused > 0, "the table refuses nothing");
        assertEq(vectors.length, HandleVectors.COUNT, "the table lost cases");
    }

    /// Case folding is the only change to an accepted handle. Anything else
    /// could map two platform accounts onto one identity.
    function test_foldingIsTheOnlyChange() public view {
        assertEq(this.normalize("A.B+tag@Example.COM", "google"), "a.b+tag@example.com");
        assertEq(this.normalize("Alice_1", "x"), "alice_1");
        assertEq(this.normalize("Octo-Cat", "github"), "octo-cat");
    }
}
