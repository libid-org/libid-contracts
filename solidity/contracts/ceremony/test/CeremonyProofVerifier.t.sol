// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../CeremonyProofVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";

/// @notice The Proof Verifier as dispatch: it routes, forwards value, and
///         forwards what comes back. It reads nothing in between.
contract CeremonyProofVerifierTest is Test {
    CeremonyProofVerifier pv;
    StubPlatformVerifier platform;

    address constant OWNER = address(0xA11CE);
    bytes32 constant PLATFORM_ID = CeremonyProfile.PLATFORM_X;
    uint256 constant FEE = 0.002 ether;
    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant NONCE = bytes32(uint256(0x4444));

    function setUp() public {
        CeremonyProofVerifier impl = new CeremonyProofVerifier();
        pv = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );
        platform = new StubPlatformVerifier(PLATFORM_ID, FEE);
        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 1, IPlatformVerifier(address(platform)));
        vm.deal(address(this), 10 ether);
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The stub's payload, as the bytes a Consumer would hand this contract.
    function _payload(uint16 ceremonyVersion) private pure returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: ceremonyVersion,
                operationDomain: DOMAIN,
                authorizationNonce: NONCE,
                transactionData: _txData()
            })
        );
    }

    // ─── The payload is opaque here ─────────────────────────────────

    /// @dev The bytes reach the Platform Verifier exactly as submitted. This
    ///      contract does not decode them, so it cannot have changed them.
    function test_forwardsThePayloadUntouched() public {
        bytes memory payload = _payload(1);
        pv.verify{value: FEE}(PLATFORM_ID, 1, payload);
        assertEq(platform.lastPayload(), payload);
    }

    /// @dev The digest is the Platform Verifier's to build, from the payload it
    ///      decoded and the chain it runs on. Nothing at this hop computes one.
    function test_theVerifierBuildsTheDigestFromThisChain() public {
        pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));
        assertEq(platform.lastDigest(), CeremonyAuthorization.digestFor(DOMAIN, 1, NONCE, _txData()));
        assertEq(platform.lastDigest(), CeremonyAuthorization.digest(DOMAIN, 1, pv.chainId(), NONCE, _txData()));
    }

    /// @dev The payload carries no chain identifier, so there is nothing in it
    ///      for a caller to choose (REQ-COMMON-06C). Moving the chain must
    ///      therefore move the digest.
    function test_theDigestFollowsTheChainAndNotTheCaller() public {
        pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));
        bytes32 onThisChain = platform.lastDigest();

        vm.chainId(block.chainid + 1);
        pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));

        assertTrue(platform.lastDigest() != onThisChain);
    }

    /// @dev Two versions, and only one of them is in the digest. The VERIFIER
    ///      version is this chain's routing slot: two slots holding verifiers
    ///      of the same ceremony version share a digest space, which is what
    ///      lets a proof outlive a verifier upgrade. The CEREMONY version is
    ///      what the digest binds, so changing it separates the evidence.
    function test_theCeremonyVersionIsInTheDigestAndTheVerifierVersionIsNot() public {
        StubPlatformVerifier second = new StubPlatformVerifier(PLATFORM_ID, FEE);
        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 2, IPlatformVerifier(address(second)));

        pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));
        pv.verify{value: FEE}(PLATFORM_ID, 2, _payload(1));
        assertEq(platform.lastDigest(), second.lastDigest(), "same ceremony version, two slots, one digest");

        pv.verify{value: FEE}(PLATFORM_ID, 2, _payload(2));
        assertTrue(platform.lastDigest() != second.lastDigest(), "another ceremony version is another digest");
    }

    // ─── Dispatch ───────────────────────────────────────────────────

    function test_rejectsAPairOutsideTheSupportedVersionSet() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, PLATFORM_ID, uint16(9)));
        pv.verify{value: FEE}(PLATFORM_ID, 9, _payload(1));
    }

    function test_supportsTwoVersionsOfOnePlatformAtOnce() public {
        StubPlatformVerifier second = new StubPlatformVerifier(PLATFORM_ID, FEE);
        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 2, IPlatformVerifier(address(second)));

        pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));
        pv.verify{value: FEE}(PLATFORM_ID, 2, _payload(1));
        assertEq(platform.lastValue(), FEE);
        assertEq(second.lastValue(), FEE);
    }

    /// @dev A verifier registered under a platform it does not serve would take
    ///      payloads it cannot check and reject every one.
    function test_refusesAVerifierThatServesAnotherPlatform() public {
        StubPlatformVerifier other = new StubPlatformVerifier(CeremonyProfile.PLATFORM_GITHUB, FEE);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CeremonyProofVerifier.VerifierPlatformMismatch.selector, PLATFORM_ID, CeremonyProfile.PLATFORM_GITHUB
            )
        );
        pv.setVerifier(PLATFORM_ID, 5, IPlatformVerifier(address(other)));
    }

    /// @dev The set decides which proof statements this chain accepts, so it is
    ///      authority rather than configuration (REQ-COMMON-05C).
    function test_onlyGovernanceMovesTheSupportedVersionSet() public {
        vm.expectRevert();
        pv.setVerifier(PLATFORM_ID, 6, IPlatformVerifier(address(platform)));
    }

    // ─── The fee path ───────────────────────────────────────────────

    function test_quotesThePlatformVerifierForThatPair() public view {
        assertEq(pv.quote(PLATFORM_ID, 1), FEE);
    }

    /// @dev Exact value at every hop: no refund path, so no partial-failure
    ///      rule is needed and nothing can be captured in transit.
    function test_rejectsAValueOtherThanTheQuote() public {
        bytes memory payload = _payload(1);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.WrongValue.selector, FEE, FEE - 1));
        pv.verify{value: FEE - 1}(PLATFORM_ID, 1, payload);

        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.WrongValue.selector, FEE, FEE + 1));
        pv.verify{value: FEE + 1}(PLATFORM_ID, 1, payload);
    }

    function test_forwardsExactlyTheQuotedValue() public {
        pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));
        assertEq(platform.lastValue(), FEE);
        assertEq(address(pv).balance, 0);
    }

    // ─── What comes back ────────────────────────────────────────────

    /// @dev The claim goes through untouched. The transaction data is opaque
    ///      at this hop as at the one above: deciding what the bytes mean
    ///      belongs to the Consumer that fixed the domain (REQ-COMMON-06B).
    function test_returnsTheClaimWithTheDataUntouched() public {
        ICeremony.VerifiedClaim memory c = pv.verify{value: FEE}(PLATFORM_ID, 1, _payload(1));

        assertEq(c.operationDomain, DOMAIN);
        assertEq(c.transactionData, _txData());
        assertEq(c.ceremonyVersion, 1);
        assertEq(c.userId, "2244994945");
        assertEq(c.handle, "alice");
        assertEq(c.metadataObservedAt, 1_770_000_000);
        assertEq(c.sessionId, platform.lastDigest());
    }

    // ─── Telling "not wired" from "nobody holds it" ──────────────────

    function test_reportsWhetherAPlatformCanBeVerifiedAtAll() public {
        assertTrue(pv.verifiesPlatform(PLATFORM_ID));
        assertFalse(pv.verifiesPlatform(CeremonyProfile.PLATFORM_GOOGLE));

        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 1, IPlatformVerifier(address(0)));
        assertFalse(pv.verifiesPlatform(PLATFORM_ID));
    }

    function test_renouncingIsDisabled() public {
        vm.prank(OWNER);
        vm.expectRevert("renounce disabled");
        pv.renounceOwnership();
    }
}
