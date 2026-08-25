// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";

/// @notice Stands in for a Platform Verifier.
///
/// @dev Everything a real one checks has its own suite. Here it only has to
///      charge, answer, and let the Consumer's own duties be exercised.
contract StubPlatformVerifier is IPlatformVerifier {
    bytes32 private immutable PLATFORM;
    uint256 public fee;
    string public userId = "2244994945";
    string public handle = "alice";
    uint64 public observedAt = 1_770_000_000;
    bytes32 public lastDigest;
    uint256 public lastValue;

    constructor(bytes32 platform, uint256 fee_) {
        PLATFORM = platform;
        fee = fee_;
    }

    function set(string memory u, string memory h) external {
        userId = u;
        handle = h;
    }

    function setObservedAt(uint64 t) external {
        observedAt = t;
    }

    function platformId() external view returns (bytes32) {
        return PLATFORM;
    }

    function quote() external view returns (uint256) {
        return fee;
    }

    function verify(bytes32 digest, Submission calldata) external payable returns (PlatformFields memory f) {
        lastDigest = digest;
        lastValue = msg.value;
        f.userId = userId;
        f.handle = handle;
        f.clientIdentifier = "client";
        f.metadataObservedAt = observedAt;
    }
}
