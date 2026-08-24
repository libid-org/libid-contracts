// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../CeremonyProofVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";

/// @dev Records what it was handed, so a test can see what the Proof Verifier
///      passed down rather than infer it from the answer.
contract RecordingVerifier is IPlatformVerifier {
    bytes32 private immutable PLATFORM;
    uint256 public fee;
    bytes32 public lastDigest;
    uint256 public lastValue;

    constructor(bytes32 platform, uint256 fee_) {
        PLATFORM = platform;
        fee = fee_;
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
        f.userId = "2244994945";
        f.handle = "alice";
        f.clientIdentifier = "client";
        f.metadataObservedAt = 1_770_000_000;
    }
}

contract CeremonyProofVerifierTest is Test {
    CeremonyProofVerifier pv;
    RecordingVerifier platform;

    address constant OWNER = address(0xA11CE);
    bytes32 constant PLATFORM_ID = CeremonyProfile.PLATFORM_X;
    uint256 constant FEE = 0.002 ether;
    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));

    function setUp() public {
        CeremonyProofVerifier impl = new CeremonyProofVerifier();
        pv = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );
        platform = new RecordingVerifier(PLATFORM_ID, FEE);
        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 1, IPlatformVerifier(address(platform)));
        vm.deal(address(this), 10 ether);
    }

    function _submission(uint16 version) private pure returns (ICeremony.Submission memory s) {
        s.platformId = PLATFORM_ID;
        s.version = version;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = bytes32(uint256(0x4444));
        s.transactionData = abi.encode(address(0xBEEF));
    }

    // ─── The digest ─────────────────────────────────────────────────

    /// @dev The whole reason this hop exists. The digest is built here, from
    ///      the chain this contract runs on, and handed down -- a Platform
    ///      Verifier rebuilding it would rebuild it from the submission, which
    ///      the caller wrote (REQ-COMMON-46).
    function test_handsDownTheDigestItRecomputed() public {
        ICeremony.Submission memory s = _submission(1);
        pv.verify{value: FEE}(s);

        assertEq(
            platform.lastDigest(),
            CeremonyAuthorization.digest(DOMAIN, 1, pv.chainId(), s.authorizationNonce, s.transactionData)
        );
    }

    /// @dev The submission carries no chain identifier, so there is nothing in
    ///      it for a caller to choose (REQ-COMMON-06C). Moving the chain must
    ///      therefore move the digest.
    function test_theDigestFollowsTheChainAndNotTheCaller() public {
        pv.verify{value: FEE}(_submission(1));
        bytes32 onThisChain = platform.lastDigest();

        vm.chainId(block.chainid + 1);
        pv.verify{value: FEE}(_submission(1));

        assertTrue(platform.lastDigest() != onThisChain);
    }

    /// @dev The version is in the digest, so two versions of one platform
    ///      cannot share evidence even when both are supported.
    function test_theVersionIsBoundIntoTheDigest() public {
        RecordingVerifier second = new RecordingVerifier(PLATFORM_ID, FEE);
        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 2, IPlatformVerifier(address(second)));

        pv.verify{value: FEE}(_submission(1));
        pv.verify{value: FEE}(_submission(2));
        assertTrue(platform.lastDigest() != second.lastDigest());
    }

    // ─── Dispatch ───────────────────────────────────────────────────

    function test_rejectsAPairOutsideTheSupportedVersionSet() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, PLATFORM_ID, uint16(9)));
        pv.verify{value: FEE}(_submission(9));
    }

    function test_supportsTwoVersionsOfOnePlatformAtOnce() public {
        RecordingVerifier second = new RecordingVerifier(PLATFORM_ID, FEE);
        vm.prank(OWNER);
        pv.setVerifier(PLATFORM_ID, 2, IPlatformVerifier(address(second)));

        pv.verify{value: FEE}(_submission(1));
        pv.verify{value: FEE}(_submission(2));
        assertEq(platform.lastValue(), FEE);
        assertEq(second.lastValue(), FEE);
    }

    /// @dev A verifier registered under a platform it does not serve would take
    ///      submissions it cannot check and reject every one.
    function test_refusesAVerifierThatServesAnotherPlatform() public {
        RecordingVerifier other = new RecordingVerifier(CeremonyProfile.PLATFORM_GITHUB, FEE);
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
        ICeremony.Submission memory s = _submission(1);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.WrongValue.selector, FEE, FEE - 1));
        pv.verify{value: FEE - 1}(s);

        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.WrongValue.selector, FEE, FEE + 1));
        pv.verify{value: FEE + 1}(s);
    }

    function test_forwardsExactlyTheQuotedValue() public {
        pv.verify{value: FEE}(_submission(1));
        assertEq(platform.lastValue(), FEE);
        assertEq(address(pv).balance, 0);
    }

    // ─── What comes back ────────────────────────────────────────────

    /// @dev The transaction data goes through untouched: deciding what these
    ///      bytes mean belongs to the Consumer that fixed the domain
    ///      (REQ-COMMON-06B).
    function test_returnsTheClaimWithTheDataUntouched() public {
        ICeremony.Submission memory s = _submission(1);
        ICeremony.VerifiedClaim memory c = pv.verify{value: FEE}(s);

        assertEq(c.operationDomain, DOMAIN);
        assertEq(c.transactionData, s.transactionData);
        assertEq(c.userId, "2244994945");
        assertEq(c.handle, "alice");
        assertEq(c.metadataObservedAt, 1_770_000_000);
        assertEq(c.authorizationDigest, platform.lastDigest());
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
