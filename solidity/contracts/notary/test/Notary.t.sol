// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Notary} from "../Notary.sol";

contract NotaryTest is Test {
    Notary internal notaryContract;

    uint256 internal constant SIGNER_PK = 0xA11CE;
    uint256 internal constant OTHER_PK = 0xB0B;

    address internal owner = makeAddr("owner");
    address internal stranger = makeAddr("stranger");
    address internal signer;

    event NotaryChanged(address indexed previousNotary, address indexed newNotary);

    function setUp() public {
        signer = vm.addr(SIGNER_PK);
        Notary impl = new Notary();
        notaryContract =
            Notary(address(new ERC1967Proxy(address(impl), abi.encodeCall(Notary.initialize, (owner, signer)))));
    }

    /// EIP-191 signature over `digest`, the way the notary signs.
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    // ─── initialize ─────────────────────────────────────────────────

    function test_initialize_setsOwnerAndNotary() public view {
        assertEq(notaryContract.owner(), owner);
        assertEq(notaryContract.notary(), signer);
    }

    function test_initialize_revertsOnZeroNotary() public {
        Notary impl = new Notary();
        vm.expectRevert(Notary.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(Notary.initialize, (owner, address(0))));
    }

    function test_initialize_revertsOnDoubleInit() public {
        vm.expectRevert();
        notaryContract.initialize(owner, signer);
    }

    // ─── verify ─────────────────────────────────────────────────────

    function test_verify_acceptsTheNotarySignature() public view {
        bytes32 digest = keccak256("some consumer digest");
        assertTrue(notaryContract.verify(digest, _sign(SIGNER_PK, digest)));
    }

    function test_verify_rejectsAnotherSigner() public view {
        bytes32 digest = keccak256("some consumer digest");
        assertFalse(notaryContract.verify(digest, _sign(OTHER_PK, digest)));
    }

    function test_verify_rejectsASignatureOverAnotherDigest() public view {
        bytes memory sig = _sign(SIGNER_PK, keccak256("digest A"));
        assertFalse(notaryContract.verify(keccak256("digest B"), sig));
    }

    /// A malformed proof answers false rather than reverting, so a consumer
    /// surfaces its own error.
    function test_verify_answersFalseOnMalformedProof() public view {
        bytes32 digest = keccak256("some consumer digest");
        assertFalse(notaryContract.verify(digest, ""));
        assertFalse(notaryContract.verify(digest, hex"deadbeef"));
        assertFalse(notaryContract.verify(digest, new bytes(65)));
    }

    /// A high-s (malleable) variant of a valid signature is refused.
    function test_verify_rejectsAMalleatedSignature() public view {
        bytes32 digest = keccak256("some consumer digest");
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, ethHash);
        // secp256k1 n
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory malleated = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        assertFalse(notaryContract.verify(digest, malleated));
    }

    // ─── setNotary ──────────────────────────────────────────────────

    function test_setNotary_rotatesAndEmits() public {
        address rotated = vm.addr(OTHER_PK);
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit NotaryChanged(signer, rotated);
        notaryContract.setNotary(rotated);
        assertEq(notaryContract.notary(), rotated);

        // The old key stops verifying; the new one starts.
        bytes32 digest = keccak256("some consumer digest");
        assertFalse(notaryContract.verify(digest, _sign(SIGNER_PK, digest)));
        assertTrue(notaryContract.verify(digest, _sign(OTHER_PK, digest)));
    }

    function test_setNotary_revertsIfNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert();
        notaryContract.setNotary(stranger);
    }

    function test_setNotary_revertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Notary.ZeroAddress.selector);
        notaryContract.setNotary(address(0));
    }

    // ─── Ownable2Step ───────────────────────────────────────────────

    function test_ownership_twoStepTransfer() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        notaryContract.transferOwnership(newOwner);
        assertEq(notaryContract.owner(), owner);
        assertEq(notaryContract.pendingOwner(), newOwner);

        vm.prank(newOwner);
        notaryContract.acceptOwnership();
        assertEq(notaryContract.owner(), newOwner);
    }

    function test_renounceOwnership_isDisabled() public {
        vm.prank(owner);
        vm.expectRevert("renounce disabled");
        notaryContract.renounceOwnership();
    }

    // ─── UUPS upgrade ───────────────────────────────────────────────

    function test_upgrade_revertsIfNotOwner() public {
        Notary newImpl = new Notary();
        vm.prank(stranger);
        vm.expectRevert();
        notaryContract.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgrade_byOwner_preservesState() public {
        Notary newImpl = new Notary();
        vm.prank(owner);
        notaryContract.upgradeToAndCall(address(newImpl), "");

        assertEq(notaryContract.owner(), owner);
        assertEq(notaryContract.notary(), signer);
        bytes32 digest = keccak256("some consumer digest");
        assertTrue(notaryContract.verify(digest, _sign(SIGNER_PK, digest)));
    }
}
