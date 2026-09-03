// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibString} from "../bank/libraries/LibString.sol";

/// @dev Test-only harness exposing LibString.substringCalldata. LibTemplate only
///      ever calls it with in-bounds ranges, so its InvalidRange guard is
///      unreachable end-to-end — this isolates it.
contract LibStringHarness {
    function substr(bytes calldata data, uint256 start, uint256 end) external pure returns (string memory) {
        return LibString.substringCalldata(data, start, end);
    }
}

contract LibStringGuardsTest is Test {
    LibStringHarness h;

    function setUp() public {
        h = new LibStringHarness();
    }

    // 30. substringCalldata with end > data.length → InvalidRange (removing the
    //     guard yields an out-of-bounds slice panic instead).
    function test_InvalidRange_reverts() public {
        bytes memory data = bytes("hello");
        vm.expectRevert(LibString.InvalidRange.selector);
        h.substr(data, 0, data.length + 1);
    }
}
