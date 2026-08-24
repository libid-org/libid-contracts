// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {ICeremony} from "../../ceremony/ICeremony.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";

/// @notice Stands in for a Platform Verifier. Everything it would check is
///         covered by its own suite; here it only has to charge, answer, and
///         let the Consumer's own duties be exercised.
contract StubVerifier is IPlatformVerifier {
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

/// @notice IdentityNames wearing the Proof Verifier and Consumer roles.
contract CeremonyClaimTest is Test {
    IdentityNames names;
    CeremonyProofVerifier proofVerifier;
    StubVerifier verifier;

    address constant OWNER = address(0xA11CE);
    address constant WALLET = address(0xBEEF);
    bytes32 constant PLATFORM = CeremonyProfile.PLATFORM_X;
    uint256 constant FEE = 0.002 ether;
    uint64 constant T0 = 1_770_000_000;

    function setUp() public {
        vm.warp(T0 + 100);
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (OWNER)))));
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );

        vm.startPrank(OWNER);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        names.setPlatform(
            PLATFORM,
            HandleNormalizer.Rules({
                maxLength: 15, stripLeadingAt: true, isEmail: false, allowUnderscore: true, allowHyphen: false
            })
        );
        verifier = new StubVerifier(PLATFORM, FEE);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(verifier)));
        vm.stopPrank();
        vm.deal(WALLET, 100 ether);
    }

    function _submission(address target, bytes32 nonce) private pure returns (ICeremony.Submission memory s) {
        s.platformId = PLATFORM;
        s.version = 1;
        s.operationDomain = keccak256(bytes("libid.claim-identity"));
        s.authorizationNonce = nonce;
        s.transactionData = abi.encode(target);
        s.publicInputs = new bytes32[](0);
        s.attestations = new ICeremony.Attestation[](0);
    }

    function _claim(ICeremony.Submission memory s, uint256 value) private {
        vm.prank(WALLET);
        names.claim{value: value}(s, false);
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_bindsAnIdentityFromACeremony() public {
        _claim(_submission(WALLET, bytes32(uint256(1))), FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(names.resolveId(PLATFORM, "2244994945"), WALLET);
    }

    /// @dev The digest the Consumer recomputed is what the Platform Verifier
    ///      was handed — not one the caller supplied (REQ-COMMON-46).
    function test_forwardsTheRecomputedDigest() public {
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(7)));
        _claim(s, FEE);
        bytes32 expected = CeremonyAuthorization.digest(
            s.operationDomain, s.version, names.chainId(), s.authorizationNonce, s.transactionData
        );
        assertEq(verifier.lastDigest(), expected);
    }

    function test_quotesAndForwardsTheWholePath() public {
        assertEq(names.quoteClaim(PLATFORM, 1), FEE);
        _claim(_submission(WALLET, bytes32(uint256(2))), FEE);
        assertEq(verifier.lastValue(), FEE);
    }

    function test_rejectsAnyValueOtherThanTheQuote() public {
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(3)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.WrongClaimValue.selector, FEE, FEE - 1));
        names.claim{value: FEE - 1}(s, false);
    }

    // ─── The digest is its own replay nullifier ─────────────────────

    /// @dev REQ-COMMON-03A. The circuit dropped its nullifier because this
    ///      exists; without it the drop would have opened a replay.
    function test_aDigestIsSpendableOnce() public {
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(9)));
        _claim(s, FEE);
        bytes32 digest = CeremonyAuthorization.digest(
            s.operationDomain, s.version, names.chainId(), s.authorizationNonce, s.transactionData
        );
        assertTrue(names.digestSpent(digest));

        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.DigestAlreadySpent.selector, digest));
        names.claim{value: FEE}(s, false);
    }

    /// @dev A fresh nonce is a fresh digest, so re-proving is always available.
    function test_aFreshNonceIsAFreshDigest() public {
        verifier.setObservedAt(T0);
        _claim(_submission(WALLET, bytes32(uint256(1))), FEE);
        verifier.setObservedAt(T0 + 1);
        _claim(_submission(WALLET, bytes32(uint256(2))), FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    // ─── The authorization predicate ────────────────────────────────

    /// @dev The Consumer binds to the AUTHENTICATED caller, not to an address
    ///      the submitter names. A Consumer doing otherwise would turn
    ///      consent-phishing into identity theft: anyone could spend a genuine
    ///      proof at an address of their choosing.
    function test_rejectsAProofSpentAtAnotherAddress() public {
        ICeremony.Submission memory s = _submission(address(0xDEAD), bytes32(uint256(4)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, address(0xDEAD), WALLET));
        names.claim{value: FEE}(s, false);
    }

    /// @dev REQ-COMMON-01F: one exact encoding, and trailing bytes refused.
    function test_rejectsMalformedTransactionData() public {
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(5)));
        s.transactionData = abi.encodePacked(abi.encode(WALLET), hex"00");
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.BadTransactionData.selector, 33));
        names.claim{value: FEE}(s, false);
    }

    // ─── The operation domain ───────────────────────────────────────

    /// @dev REQ-COMMON-06A. Checked before any fee moves, so a submission for
    ///      someone else's operation costs nothing.
    function test_rejectsAForeignOperationDomain() public {
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(6)));
        s.operationDomain = keccak256(bytes("someone.else.operation"));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.ForeignOperationDomain.selector, s.operationDomain));
        names.claim{value: FEE}(s, false);
    }

    // ─── The Supported Version Set ──────────────────────────────────

    function test_rejectsAnUnregisteredVersion() public {
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(8)));
        s.version = 2;
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, PLATFORM, uint16(2)));
        names.claim{value: FEE}(s, false);
    }

    /// @dev REQ-COMMON-05B: more than one version of one platform at a time, so
    ///      a deployment runs a new one beside the one it replaces.
    function test_supportsTwoVersionsAtOnce() public {
        StubVerifier second = new StubVerifier(PLATFORM, FEE);
        second.set("999", "bob");
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 2, IPlatformVerifier(address(second)));

        _claim(_submission(WALLET, bytes32(uint256(10))), FEE);
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(11)));
        s.version = 2;
        _claim(s, FEE);

        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(names.resolveHandle(PLATFORM, "bob"), WALLET);
    }

    /// @dev The set is authority, not configuration (REQ-COMMON-05C).
    function test_onlyTheOwnerChangesTheSupportedVersionSet() public {
        vm.expectRevert();
        proofVerifier.setVerifier(PLATFORM, 3, IPlatformVerifier(address(verifier)));
    }

    /// @dev A verifier for another platform in this platform's slot would
    ///      dispatch a submission to code that reads a different format.
    function test_refusesAVerifierForAnotherPlatform() public {
        StubVerifier other = new StubVerifier(CeremonyProfile.PLATFORM_GITHUB, FEE);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CeremonyProofVerifier.VerifierPlatformMismatch.selector, PLATFORM, CeremonyProfile.PLATFORM_GITHUB
            )
        );
        proofVerifier.setVerifier(PLATFORM, 4, IPlatformVerifier(address(other)));
    }

    // ─── The handle is normalized here, not by the verifier ─────────

    /// @dev REQ-PLAT-08B: the Consumer derives the key from the raw bytes on
    ///      its own write path, so a verifier returning a padded, at-prefixed,
    ///      mixed-case handle lands on the same node as the normalized one.
    function test_normalizesTheHandleItself() public {
        verifier.set("2244994945", " @Alice_1 ");
        _claim(_submission(WALLET, bytes32(uint256(12))), FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice_1"), WALLET);
        (address owner,,) = names.byHandle(IdentityNodes.handleNode(PLATFORM, "alice_1"));
        assertEq(owner, WALLET);
    }

    function test_rejectsAnEmptyUserId() public {
        verifier.set("", "alice");
        ICeremony.Submission memory s = _submission(WALLET, bytes32(uint256(13)));
        vm.prank(WALLET);
        vm.expectRevert(IdentityNames.NoUserId.selector);
        names.claim{value: FEE}(s, false);
    }
}
