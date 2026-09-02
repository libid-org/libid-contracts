// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";

/// @notice Stands in for a Platform Verifier.
///
/// @dev Everything a real one checks has its own suite. Here it only has to
///      charge, decode, answer, and let the Consumer's and the Proof Verifier's
///      own duties be exercised.
///
///      It decodes a payload of its own shape and rebuilds the digest the way
///      a real verifier does -- from the decoded fields and the chain it runs
///      on -- so a test above it can watch the domain, the transaction data
///      and the digest travel, rather than have the stub invent them. Unlike a
///      real verifier it takes the ceremony version from the payload instead
///      of a constant, so one stub can stand in for several.
contract StubPlatformVerifier is IPlatformVerifier {
    /// @dev The stub's payload. Only what the digest needs.
    struct StubPayload {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
    }

    bytes32 private immutable PLATFORM;
    uint256 public fee;
    string public userId = "2244994945";
    string public handle = "alice";
    uint64 public observedAt = 1_770_000_000;
    bytes32 public lastDigest;
    uint256 public lastValue;
    bytes public lastPayload;

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

    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory c) {
        StubPayload memory p = abi.decode(payload, (StubPayload));
        lastPayload = payload;
        lastValue = msg.value;
        lastDigest = CeremonyAuthorization.digestFor(
            p.operationDomain, p.ceremonyVersion, p.authorizationNonce, p.transactionData
        );

        c.sessionId = lastDigest;
        c.operationDomain = p.operationDomain;
        c.transactionData = p.transactionData;
        c.ceremonyVersion = p.ceremonyVersion;
        c.clientIdentifier = "client";
        c.userId = userId;
        c.handle = handle;
        c.metadataObservedAt = observedAt;
    }
}
