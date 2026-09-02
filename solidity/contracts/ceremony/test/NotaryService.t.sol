// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {NotaryService} from "../NotaryService.sol";

/// @notice The Notary Service of ceremony-common section 9.2.
/// @dev The signature below is real: produced with `cast wallet sign` over the
///      digest of the cross-language attestation fixture, by the public anvil
///      key. Nothing here mocks the thing under test.
contract NotaryServiceTest is Test {
    NotaryService service;

    address constant OWNER = address(0xA11CE);
    address constant NOTARY = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    uint256 constant FEE = 0.001 ether;

    /// The same bytes libid-rs encodes and CeremonyAttestation decodes.
    ///
    /// @dev Signed at test time rather than pinned as a literal. The old
    ///      pinned signature outlived two format changes unnoticed, because
    ///      this contract only hashed these bytes and never read them.
    bytes constant ATTESTED = hex"4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d"
        hex"0000000069800e800000003c0000002800000000000000020000000000000000"
        hex"0000001461616161616161616161616161616161616161610000002800000000"
        hex"0000001462626262626262626262626262626262626262620000000000000001"
        hex"0000001400000028070707070707070707070707070707070707070707070707"
        hex"0707070707070707000000000000000100000000000000000000000a63636363"
        hex"63636363636300000000000000010000000a0000002809090909090909090909"
        hex"09090909090909090909090909090909090909090909";

    /// @dev The anvil key whose address is `NOTARY`.
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    bytes SIG;

    function setUp() public {
        (uint8 v, bytes32 r, bytes32 sVal) =
            vm.sign(NOTARY_KEY, MessageHashUtils.toEthSignedMessageHash(keccak256(ATTESTED)));
        SIG = abi.encodePacked(r, sVal, v);

        NotaryService impl = new NotaryService();
        service = NotaryService(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(NotaryService.initialize, (OWNER, NOTARY, FEE))))
        );
    }

    // ─── The core property ──────────────────────────────────────────

    function test_acceptsARealNotarySignature() public {
        service.verify{value: FEE}(ATTESTED, SIG);
    }

    /// @dev REQ-COMMON-49, and the whole reason this contract replaced one that
    ///      took a digest. The signature is genuine and the key is trusted, but
    ///      the bytes differ by one bit -- so the digest derived HERE differs
    ///      and recovery lands on nobody. A verifier handed a caller-computed
    ///      digest would have accepted this.
    function test_rejectsASignatureOverDifferentBytes() public {
        bytes memory tampered = ATTESTED;
        tampered[200] = bytes1(uint8(tampered[200]) ^ 0x01);

        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        service.verify{value: FEE}(tampered, SIG);
    }

    function test_rejectsAnUntrustedKey() public {
        // A perfectly valid signature from a key the service does not hold.
        uint256 stranger = 0xB0B;
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(ATTESTED)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(stranger, ethHash);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(stranger)));
        service.verify{value: FEE}(ATTESTED, abi.encodePacked(r, s, v));
    }

    function test_rejectsAMalformedSignature() public {
        vm.expectRevert(NotaryService.MalformedSignature.selector);
        service.verify{value: FEE}(ATTESTED, hex"1234");
    }

    // ─── The fee ────────────────────────────────────────────────────

    function test_feeIsReadableBeforeBuildingASubmission() public view {
        assertEq(service.fee(), FEE);
    }

    /// @dev REQ-COMMON-34E: an exact match, both ways. Underpaying is obvious;
    ///      overpaying must fail too, so there is no overpayment to refund and
    ///      no silent overcharge of the Fee Payer.
    function test_rejectsAnyValueOtherThanTheFee() public {
        vm.expectRevert(abi.encodeWithSelector(NotaryService.WrongFee.selector, FEE, FEE - 1));
        service.verify{value: FEE - 1}(ATTESTED, SIG);

        vm.expectRevert(abi.encodeWithSelector(NotaryService.WrongFee.selector, FEE, FEE + 1));
        service.verify{value: FEE + 1}(ATTESTED, SIG);

        vm.expectRevert(abi.encodeWithSelector(NotaryService.WrongFee.selector, FEE, 0));
        service.verify(ATTESTED, SIG);
    }

    /// @dev REQ-COMMON-34C: a fee that varies by principal or content is
    ///      selective censorship of a permissionless service.
    function test_theFeeVariesWithNothing() public {
        uint256 quoted = service.fee();

        address[3] memory callers = [address(0x1), address(0x2), address(0x3)];
        for (uint256 i = 0; i < callers.length; ++i) {
            vm.deal(callers[i], 1 ether);
            vm.prank(callers[i], callers[i]); // distinct sender AND origin
            assertEq(service.fee(), quoted, "the fee moved with the caller");
            vm.prank(callers[i]);
            service.verify{value: quoted}(ATTESTED, SIG);
        }
    }

    function test_feesAccrueAndOnlyTheOwnerWithdraws() public {
        service.verify{value: FEE}(ATTESTED, SIG);
        service.verify{value: FEE}(ATTESTED, SIG);
        assertEq(address(service).balance, 2 * FEE);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        service.withdraw(address(this), FEE);

        address sink = address(0xBEEF);
        vm.prank(OWNER);
        service.withdraw(sink, 2 * FEE);
        assertEq(sink.balance, 2 * FEE);
        assertEq(address(service).balance, 0);
    }

    /// @dev A rejected verification must leave no fee behind (REQ-COMMON-42).
    ///      Reverting gives that by construction.
    function test_aRejectedVerificationDeliversNoFee() public {
        uint256 before = address(service).balance;
        vm.expectRevert(NotaryService.MalformedSignature.selector);
        service.verify{value: FEE}(ATTESTED, hex"1234");
        assertEq(address(service).balance, before, "a rejection kept the fee");
    }

    // ─── Governance ─────────────────────────────────────────────────

    /// @dev Rotation must not invalidate attestations already made under the
    ///      outgoing key, so both are trusted for a while.
    function test_twoKeysCanBeTrustedAtOnce() public {
        uint256 incoming = 0xC0FFEE;
        vm.prank(OWNER);
        service.setNotary(vm.addr(incoming), true);

        assertTrue(service.isTrustedNotary(NOTARY));
        assertTrue(service.isTrustedNotary(vm.addr(incoming)));
        // Not reverting IS the assertion: the outgoing key still verifies.
        service.verify{value: FEE}(ATTESTED, SIG);

        vm.prank(OWNER);
        service.setNotary(NOTARY, false);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, NOTARY));
        service.verify{value: FEE}(ATTESTED, SIG);
    }

    function test_onlyTheOwnerGoverns() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        service.setFee(1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        service.setNotary(address(0xD00D), true);
    }

    function test_theFeeCanChangeAndTakesEffectAtOnce() public {
        vm.prank(OWNER);
        service.setFee(5 wei);
        assertEq(service.fee(), 5 wei);
        service.verify{value: 5 wei}(ATTESTED, SIG);

        vm.expectRevert(abi.encodeWithSelector(NotaryService.WrongFee.selector, 5 wei, FEE));
        service.verify{value: FEE}(ATTESTED, SIG);
    }

    /// @dev A deployment may meter at no charge, and an exact match still
    ///      applies, so value attached to a free service is refused rather than
    ///      silently donated.
    function test_aZeroFeeStillRequiresAnExactMatch() public {
        vm.prank(OWNER);
        service.setFee(0);
        service.verify(ATTESTED, SIG);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.WrongFee.selector, 0, 1));
        service.verify{value: 1}(ATTESTED, SIG);
    }

    /// @dev The record comes back decoded, so a caller cannot hold the fields
    ///      without having paid for the check that vouches for them. With a
    ///      bare accept, nothing but two adjacent statements kept
    ///      "authenticate, then read" true.
    function test_handsBackTheDecodedRecord() public {
        CeremonyAttestation.AttestedData memory a = service.verify{value: FEE}(ATTESTED, SIG);

        assertEq(a.authorityId, keccak256(bytes("api.x.com")));
        assertEq(a.createdAt, 1_770_000_000);
        assertEq(a.sentTranscriptLength, 60);
        assertEq(a.recvTranscriptLength, 40);
        assertEq(a.sent.revealed.length, 2);
        assertEq(a.received.commitments.length, 1);
    }

    /// @dev A record the key vouched for but that this format cannot read is
    ///      refused here rather than one hop up. Decoding moved behind the
    ///      signature check, so this is where the shape is first seen.
    function test_refusesSignedBytesThatAreNotARecord() public {
        bytes memory junk = hex"deadbeef";
        (uint8 v, bytes32 r, bytes32 sVal) =
            vm.sign(NOTARY_KEY, MessageHashUtils.toEthSignedMessageHash(keccak256(junk)));
        vm.expectRevert();
        service.verify{value: FEE}(junk, abi.encodePacked(r, sVal, v));
    }

    function test_renouncingIsDisabled() public {
        vm.prank(OWNER);
        vm.expectRevert("renounce disabled");
        service.renounceOwnership();
    }
}
