// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @notice IdentityNames wearing the Consumer role, over a real Proof Verifier
///         and a stubbed Platform Verifier.
contract CeremonyClaimTest is Test {
    IdentityNames names;
    CeremonyProofVerifier proofVerifier;
    StubPlatformVerifier verifier;

    address constant OWNER = address(0xA11CE);
    address constant WALLET = address(0xBEEF);
    bytes32 constant PLATFORM = CeremonyProfile.PLATFORM_X;
    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    uint256 constant FEE = 0.002 ether;
    /// A hosted application, and what it charges for composing the ceremony.
    address constant HOST = address(0x405);
    uint256 constant SERVICE_FEE = 0.01 ether;
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
        verifier = new StubPlatformVerifier(PLATFORM, FEE);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(verifier)));
        vm.stopPrank();
        vm.deal(WALLET, 100 ether);
    }

    /// The Authorized Transaction Data of `libid.claim-identity`.
    function _txData(address target, uint256 feeAmount, address feeReceiver) private pure returns (bytes memory) {
        return abi.encode(target, feeAmount, feeReceiver);
    }

    /// The same, for a ceremony composed by hand: no application to pay.
    function _free(address target) private pure returns (bytes memory) {
        return _txData(target, 0, address(0));
    }

    /// The stub's payload for one authorization. The Consumer never sees
    /// inside it; only the stub does.
    function _payload(bytes32 domain, bytes memory txData, bytes32 nonce) private pure returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1, operationDomain: domain, authorizationNonce: nonce, transactionData: txData
            })
        );
    }

    function _payload(bytes32 domain, address target, bytes32 nonce) private pure returns (bytes memory) {
        return _payload(domain, _free(target), nonce);
    }

    function _payload(address target, bytes32 nonce) private pure returns (bytes memory) {
        return _payload(DOMAIN, _free(target), nonce);
    }

    function _claim(bytes memory payload, uint256 value) private {
        vm.prank(WALLET);
        names.claim{value: value}(PLATFORM, 1, payload, false);
    }

    function _digest(bytes memory txData, bytes32 nonce) private view returns (bytes32) {
        return CeremonyAuthorization.digestFor(DOMAIN, 1, nonce, txData);
    }

    function _digest(address target, bytes32 nonce) private view returns (bytes32) {
        return _digest(_free(target), nonce);
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_bindsAnIdentityFromACeremony() public {
        _claim(_payload(WALLET, bytes32(uint256(1))), FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(names.resolveId(PLATFORM, "2244994945"), WALLET);
    }

    /// @dev The Consumer hands the payload through as opaque bytes. What the
    ///      Platform Verifier decoded and digested is what it acted on.
    function test_recordsTheDigestTheVerifierBuilt() public {
        _claim(_payload(WALLET, bytes32(uint256(7))), FEE);
        assertEq(verifier.lastDigest(), _digest(WALLET, bytes32(uint256(7))));
        assertTrue(names.digestSpent(verifier.lastDigest()));
    }

    /// @dev Which OAuth client produced a binding is answerable only from the
    ///      call that wrote it -- nothing stores the value, and the contract
    ///      has no use for it. So a ceremony logs it, in the exact bytes the
    ///      platform authenticated, keyed by the digest that identifies the
    ///      ceremony.
    function test_logsTheAuthenticatedClientIdentifier() public {
        vm.recordLogs();
        _claim(_payload(WALLET, bytes32(uint256(11))), FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("CeremonyBound(bytes32,address,bytes32,bytes)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            assertEq(string(abi.decode(logs[i - 1].data, (bytes))), "client");
            return;
        }
        revert("no CeremonyBound in the logs");
    }

    /// @dev Logged, not stored. Nothing on chain reads which ceremony version
    ///      proved a binding; an operator asking which bindings a version
    ///      touched reads `IdentityBound`.
    function test_logsTheCeremonyVersionAndStoresNothingOfIt() public {
        vm.recordLogs();
        _claim(_payload(WALLET, bytes32(uint256(88))), FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("IdentityBound(address,bytes32,bytes32,bytes32,string,string,uint64,bool,uint16)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            (,,,,, uint16 version) = abi.decode(logs[i - 1].data, (bytes32, string, string, uint64, bool, uint16));
            assertEq(version, 1);
            return;
        }
        revert("no IdentityBound in the logs");
    }

    function test_quotesAndForwardsTheWholePath() public {
        assertEq(names.quoteClaim(PLATFORM, 1), FEE);
        _claim(_payload(WALLET, bytes32(uint256(2))), FEE);
        assertEq(verifier.lastValue(), FEE);
    }

    function test_rejectsAnyValueOtherThanTheQuote() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(3)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.WrongClaimValue.selector, FEE, FEE - 1));
        names.claim{value: FEE - 1}(PLATFORM, 1, p, false);
    }

    // ─── The digest is its own replay nullifier ─────────────────────

    /// @dev REQ-COMMON-03A. The circuit dropped its nullifier because this
    ///      exists; without it the drop would have opened a replay.
    function test_aDigestIsSpendableOnce() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(9)));
        _claim(p, FEE);
        bytes32 digest = _digest(WALLET, bytes32(uint256(9)));
        assertTrue(names.digestSpent(digest));

        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.DigestAlreadySpent.selector, digest));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    /// @dev A fresh nonce is a fresh digest, so re-proving is always available.
    function test_aFreshNonceIsAFreshDigest() public {
        verifier.setObservedAt(T0);
        _claim(_payload(WALLET, bytes32(uint256(1))), FEE);
        verifier.setObservedAt(T0 + 1);
        _claim(_payload(WALLET, bytes32(uint256(2))), FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    // ─── The authorization predicate ────────────────────────────────

    /// @dev The Consumer binds to the AUTHENTICATED caller, not to an address
    ///      the submitter names. A Consumer doing otherwise would turn
    ///      consent-phishing into identity theft: anyone could spend a genuine
    ///      proof at an address of their choosing.
    function test_rejectsAProofSpentAtAnotherAddress() public {
        bytes memory p = _payload(address(0xDEAD), bytes32(uint256(4)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, address(0xDEAD), WALLET));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    /// @dev REQ-COMMON-01F: one exact encoding, and trailing bytes refused.
    function test_rejectsMalformedTransactionData() public {
        bytes memory p = _payload(DOMAIN, abi.encodePacked(_free(WALLET), hex"00"), bytes32(uint256(5)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.BadTransactionData.selector, 97));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    // ─── The operation domain ───────────────────────────────────────

    /// @dev REQ-COMMON-06A. The domain is inside the payload, so the Consumer
    ///      learns it from the verifier's report and refuses one it does not
    ///      own before applying anything.
    function test_rejectsAForeignOperationDomain() public {
        bytes32 foreign = keccak256(bytes("someone.else.operation"));
        bytes memory p = _payload(foreign, WALLET, bytes32(uint256(6)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.ForeignOperationDomain.selector, foreign));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    // ─── The Supported Version Set ──────────────────────────────────

    function test_rejectsAnUnregisteredVerifierVersion() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(8)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, PLATFORM, uint16(2)));
        names.claim{value: FEE}(PLATFORM, 2, p, false);
    }

    /// @dev REQ-COMMON-05B: more than one verifier version of one platform at
    ///      a time, so a deployment runs a new one beside the one it replaces.
    function test_supportsTwoVerifierVersionsAtOnce() public {
        StubPlatformVerifier second = new StubPlatformVerifier(PLATFORM, FEE);
        second.set("999", "bob");
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 2, IPlatformVerifier(address(second)));

        _claim(_payload(WALLET, bytes32(uint256(10))), FEE);
        vm.prank(WALLET);
        names.claim{value: FEE}(PLATFORM, 2, _payload(WALLET, bytes32(uint256(11))), false);

        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(names.resolveHandle(PLATFORM, "bob"), WALLET);
    }

    /// @dev CeremonyProofVerifier's own doc says removing a version "strands no
    ///      name already bound under it". Routing resolution through the
    ///      Supported Version Set made that false: retiring the last version
    ///      stopped every bound name on the platform from resolving, for names
    ///      that were bound and still owned. A name does not belong to the
    ///      proof that established it.
    function test_aBoundNameOutlivesTheVersionThatEstablishedIt() public {
        _claim(_payload(WALLET, bytes32(uint256(77))), FEE);
        assertEq(names.resolveId(PLATFORM, "2244994945"), WALLET);

        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(0)));

        assertEq(names.resolveId(PLATFORM, "2244994945"), WALLET);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    /// @dev The set is authority, not configuration (REQ-COMMON-05C).
    function test_onlyTheOwnerChangesTheSupportedVersionSet() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        proofVerifier.setVerifier(PLATFORM, 3, IPlatformVerifier(address(verifier)));
    }

    /// @dev A verifier for another platform in this platform's slot would
    ///      dispatch a payload to code that reads a different format.
    function test_refusesAVerifierForAnotherPlatform() public {
        StubPlatformVerifier other = new StubPlatformVerifier(CeremonyProfile.PLATFORM_GITHUB, FEE);
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
        _claim(_payload(WALLET, bytes32(uint256(12))), FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice_1"), WALLET);
        (address owner,) = names.byHandle(IdentityNodes.handleNode(PLATFORM, "alice_1"));
        assertEq(owner, WALLET);
    }

    function test_rejectsAnEmptyUserId() public {
        verifier.set("", "alice");
        bytes memory p = _payload(WALLET, bytes32(uint256(13)));
        vm.prank(WALLET);
        vm.expectRevert(IdentityNames.NoUserId.selector);
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    function test_rejectsANoncanonicalAddressEncoding() public {
        // 96 bytes of the right length, whose first word is not an address.
        bytes memory bad = abi.encodePacked(bytes12(0xffffffffffffffffffffffff), WALLET, uint256(0), uint256(0));
        bytes memory p = _payload(DOMAIN, bad, bytes32(uint256(20)));
        vm.prank(WALLET);
        vm.expectRevert(); // abi.decode's own check
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    function test_rejectsShortTransactionData() public {
        bytes memory p = _payload(DOMAIN, abi.encodePacked(WALLET), bytes32(uint256(21)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.BadTransactionData.selector, 20));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    function test_rejectsEmptyTransactionData() public {
        bytes memory p = _payload(DOMAIN, hex"", bytes32(uint256(22)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.BadTransactionData.selector, 0));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    /// @dev A wei short of the verification path is caught before the payload
    ///      is verified: that much is knowable without decoding anything.
    function test_rejectsOneWeiLessThanTheQuote() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(23)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.WrongClaimValue.selector, FEE, FEE - 1));
        names.claim{value: FEE - 1}(PLATFORM, 1, p, false);
    }

    /// @dev A wei more is caught after: everything above the quote is the fee,
    ///      and this ceremony authorized none. There is no refund path, so
    ///      overpayment is refused rather than kept or forwarded.
    function test_rejectsOneWeiMoreThanTheClaimCosts() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(24)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.WrongFeeValue.selector, 0, 1));
        names.claim{value: FEE + 1}(PLATFORM, 1, p, false);
    }

    function test_setProofVerifierIsOwnerOnlyAndNonZero() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        vm.prank(OWNER);
        vm.expectRevert(IdentityNames.ZeroAddress.selector);
        names.setProofVerifier(IProofVerifier(address(0)));
    }

    function test_aRejectedClaimSpendsNoDigest() public {
        verifier.setObservedAt(0);
        bytes memory p = _payload(WALLET, bytes32(uint256(30)));
        vm.prank(WALLET);
        vm.expectRevert(IdentityNames.NoObservationTime.selector);
        names.claim{value: FEE}(PLATFORM, 1, p, false);
        assertFalse(names.digestSpent(_digest(WALLET, bytes32(uint256(30)))));
    }

    function test_theDomainIsJudgedBeforeTransactionDataIsDecoded() public {
        bytes memory p = _payload(keccak256("other"), hex"00", bytes32(uint256(40)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.ForeignOperationDomain.selector, keccak256("other")));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    function test_onePayloadIsSpentOnceAcrossTwoVerifierVersions() public {
        StubPlatformVerifier second = new StubPlatformVerifier(PLATFORM, FEE);
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 2, IPlatformVerifier(address(second)));
        bytes memory p = _payload(WALLET, bytes32(uint256(50)));
        _claim(p, FEE);
        vm.prank(WALLET);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.DigestAlreadySpent.selector, _digest(WALLET, bytes32(uint256(50))))
        );
        names.claim{value: FEE}(PLATFORM, 2, p, false);
    }

    function test_namesCannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        names.initialize(address(this));
    }

    // ─── The service fee ────────────────────────────────────────────

    /// @dev The whole point of carrying the fee in the Authorized Transaction
    ///      Data: the user approved this number at consent time, because it is
    ///      inside the digest the proof opens against. A hosted application
    ///      cannot raise it afterwards, and it is paid to the address the
    ///      ceremony named -- not to the caller, who is the target.
    function test_paysTheFeeTheCeremonyNamed() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(60)));
        uint256 hostBefore = HOST.balance;
        uint256 walletBefore = WALLET.balance;

        vm.expectEmit(true, true, false, true, address(names));
        emit IdentityNames.ClaimFeePaid(
            _digest(_txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(60))), HOST, SERVICE_FEE
        );
        _claim(p, FEE + SERVICE_FEE);

        assertEq(HOST.balance - hostBefore, SERVICE_FEE);
        assertEq(walletBefore - WALLET.balance, FEE + SERVICE_FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(address(names).balance, 0, "nothing was captured in transit");
    }

    /// @dev Anyone who composes their own ceremony names no fee and pays only
    ///      the verification path. Nothing on this chain knows who is hosted
    ///      and who is not; the difference is entirely in what the user signed.
    function test_aFreeClaimPaysOnlyTheVerificationPath() public {
        uint256 hostBefore = HOST.balance;
        vm.recordLogs();
        _claim(_payload(WALLET, bytes32(uint256(61))), FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != IdentityNames.ClaimFeePaid.selector, "a free claim paid something");
        }
        assertEq(HOST.balance, hostBefore);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    function test_rejectsAFeeTheCallerDidNotDeliver() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(62)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.WrongFeeValue.selector, SERVICE_FEE, 0));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    /// @dev Over is refused as firmly as under. Nobody consented to more, and
    ///      there is nowhere to send the difference back to.
    function test_rejectsMoreThanTheCeremonyAuthorized() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(63)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.WrongFeeValue.selector, SERVICE_FEE, SERVICE_FEE + 1));
        names.claim{value: FEE + SERVICE_FEE + 1}(PLATFORM, 1, p, false);
    }

    /// @dev REQ-COMMON-01F: one encoding per intent. A free claim is
    ///      `(0, address(0))`, so a receiver left beside a zero amount is a
    ///      second spelling of it and is refused rather than normalized.
    function test_rejectsAReceiverBesideAZeroFee() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, 0, HOST), bytes32(uint256(64)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NoncanonicalFee.selector, 0, HOST));
        names.claim{value: FEE}(PLATFORM, 1, p, false);
    }

    /// @dev The other half of the same rule. Paying a fee to nobody would burn
    ///      value the user did consent to part with, which is worse than
    ///      refusing.
    function test_rejectsAFeeBesideNoReceiver() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, address(0)), bytes32(uint256(65)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NoncanonicalFee.selector, SERVICE_FEE, address(0)));
        names.claim{value: FEE + SERVICE_FEE}(PLATFORM, 1, p, false);
    }

    /// @dev What makes the fee unforgeable: it is a digest input. Change the
    ///      amount or the receiver and the digest moves, so the proof the user
    ///      authorized no longer opens against it.
    function test_theFeeIsInsideTheDigest() public view {
        bytes32 n = bytes32(uint256(66));
        bytes32 asAgreed = _digest(_txData(WALLET, SERVICE_FEE, HOST), n);
        assertTrue(asAgreed != _digest(_txData(WALLET, SERVICE_FEE * 2, HOST), n), "the amount does not bind");
        assertTrue(asAgreed != _digest(_txData(WALLET, SERVICE_FEE, address(0xF00)), n), "the receiver does not bind");
        assertTrue(asAgreed != _digest(_free(WALLET), n), "a free claim is not a distinct digest");
    }

    /// @dev The receiver is an address the ceremony named, so it can be
    ///      hostile or simply broken. It cannot take the name without paying
    ///      for it: the claim is one transaction, and a fee that cannot be
    ///      delivered undoes the write with it.
    function test_aReceiverThatRefusesTheFeeUndoesTheWholeClaim() public {
        RejectingReceiver bad = new RejectingReceiver();
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, address(bad)), bytes32(uint256(67)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.FeeTransferFailed.selector, address(bad), SERVICE_FEE));
        names.claim{value: FEE + SERVICE_FEE}(PLATFORM, 1, p, false);

        assertEq(names.resolveHandle(PLATFORM, "alice"), address(0));
        assertFalse(names.digestSpent(_digest(_txData(WALLET, SERVICE_FEE, address(bad)), bytes32(uint256(67)))));
    }

    /// @dev The fee is the one call out of this contract, and it happens after
    ///      every write. A receiver that calls back in finds the guard closed;
    ///      it may still take the value, and the claim it re-entered stands.
    function test_aFeeReceiverCannotReenterTheClaim() public {
        ReenteringReceiver host = new ReenteringReceiver(names, PLATFORM, _payload(WALLET, bytes32(uint256(69))));
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, address(host)), bytes32(uint256(68)));
        _claim(p, FEE + SERVICE_FEE);

        assertTrue(host.reentryReverted(), "the guard let a fee receiver back in");
        assertEq(address(host).balance, SERVICE_FEE);
        assertEq(names.resolveHandle(PLATFORM, "alice"), WALLET);
        assertFalse(names.digestSpent(_digest(WALLET, bytes32(uint256(69)))));
    }

    // Reentrancy (the stronger, negative-paths shape: zero-fee verifier, re-enters via raw call, re-raises)

    function test_aReenteringVerifierIsRefused() public {
        ReenteringVerifier evil = new ReenteringVerifier(names, PLATFORM);
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(evil)));
        bytes memory p = _payload(WALLET, bytes32(uint256(1)));
        evil.setInner(_payload(address(evil), bytes32(uint256(2))));
        vm.prank(WALLET);
        vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
        names.claim(PLATFORM, 1, p, false);
        assertFalse(names.digestSpent(_digest(WALLET, bytes32(uint256(1)))));
        assertFalse(names.digestSpent(_digest(address(evil), bytes32(uint256(2)))));
    }
}

contract ReenteringVerifier is IPlatformVerifier {
    IdentityNames immutable names;
    bytes32 immutable platform;
    bytes innerPayload;
    bool armed;

    constructor(IdentityNames n, bytes32 p) {
        names = n;
        platform = p;
    }

    function setInner(bytes memory p) external {
        innerPayload = p;
        armed = true;
    }

    function platformId() external view returns (bytes32) {
        return platform;
    }

    function quote() external pure returns (uint256) {
        return 0;
    }

    function verify(bytes calldata) external payable returns (VerifiedClaim memory c) {
        if (armed) {
            armed = false;
            (bool ok, bytes memory ret) =
                address(names).call(abi.encodeCall(IdentityNames.claim, (platform, 1, innerPayload, false)));
            if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// @notice A fee receiver that will not take the value.
contract RejectingReceiver {
    receive() external payable {
        revert("no");
    }
}

/// @notice A fee receiver that tries to claim again while being paid.
contract ReenteringReceiver {
    IdentityNames immutable names;
    bytes32 immutable platform;
    bytes payload;
    bool public reentryReverted;

    constructor(IdentityNames n, bytes32 p, bytes memory inner) {
        names = n;
        platform = p;
        payload = inner;
    }

    receive() external payable {
        (bool ok,) = address(names).call(abi.encodeCall(IdentityNames.claim, (platform, 1, payload, false)));
        reentryReverted = !ok;
    }
}
