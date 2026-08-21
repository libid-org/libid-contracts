// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

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
    bytes constant ATTESTED = hex"f1b67c286f7f90224eb4661a5922406b5092042b9515e4e9e448ec1d4f55b352"
        hex"7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83"
        hex"e7b961087ec316778e6885d11145cc06f1d75360430f461d0322fb7f105899dd"
        hex"4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d" hex"0000000069800e800000003c00000028"
        hex"000200000000000000146161616161616161616161616161616161616161"
        hex"000000280000003c6262626262626262626262626262626262626262" hex"00010000001400000028"
        hex"0707070707070707070707070707070707070707070707070707070707070707"
        hex"0001000000000000000a63636363636363636363" hex"00010000000a00000028"
        hex"0909090909090909090909090909090909090909090909090909090909090909";

    /// EIP-191 over keccak256(ATTESTED), signed by NOTARY.
    bytes constant SIG = hex"c789f9960c36dd89768bb3ba6858ede8cda4d5d785dca5e8b7edd23396cf17c8"
        hex"4f55c6fa3eaa4da2a6ccd04c89cf916ef87a08059a72b87c48d17413b5a5552d" hex"1b";

    function setUp() public {
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

    function test_renouncingIsDisabled() public {
        vm.prank(OWNER);
        vm.expectRevert("renounce disabled");
        service.renounceOwnership();
    }
}
