// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProofVerifier} from "../CeremonyProofVerifier.sol";

/// @notice TEST-EVM-01: the Chain ID this stack commits is the one the EVM
///         Chain Profile publishes, and the one a composition can read.
/// @dev The expected values are transcribed from `specs/chain-profiles.md`
///      §3.1, not produced by this library. A test that rebuilt them here
///      would agree with any preimage, including a wrong one -- and the
///      preimage is exactly what a Canonical Runtime has to guess without the
///      profile. `chainId` is the only digest input the two sides derive
///      independently, so it is the only one that can drift the way §7 did.
contract ChainProfileTest is Test {
    address constant OWNER = address(0xA11CE);

    uint256 constant ETHEREUM = 1;
    uint256 constant BASE = 8453;
    uint256 constant SEPOLIA = 11_155_111;

    bytes32 constant ETHEREUM_CHAIN_ID = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6;
    bytes32 constant BASE_CHAIN_ID = 0x3e30a4f0e31d8ec3b8e98957bc7fedf7f6fb560612e2775c74a396200aa3155b;
    bytes32 constant SEPOLIA_CHAIN_ID = 0x4679aa19497ce87eb9ffd768757c9397680da8c7963db8096790ee03622ae968;

    function chainId() external view returns (bytes32) {
        return CeremonyAuthorization.chainId();
    }

    /// @dev REQ-EVM-01. Reproducing three published vectors fixes the
    ///      preimage: the EIP-155 identifier's unsigned 256-bit big-endian
    ///      encoding, and nothing else of that width.
    function test_chainIdMatchesTheProfileVectors() public {
        vm.chainId(ETHEREUM);
        assertEq(this.chainId(), ETHEREUM_CHAIN_ID);
        vm.chainId(BASE);
        assertEq(this.chainId(), BASE_CHAIN_ID);
        vm.chainId(SEPOLIA);
        assertEq(this.chainId(), SEPOLIA_CHAIN_ID);
    }

    /// @dev REQ-EVM-01B. The composition supplies the Chain ID to the runtime
    ///      (REQ-COMMON-01C), and this is where it reads the exact 32 bytes
    ///      rather than deriving them a second time. What the Proof Verifier
    ///      hands out has to be the published value, or a composition that
    ///      trusts the reading commits something the destination will not
    ///      rebuild.
    function test_theProofVerifierExposesThePublishedChainId() public {
        vm.chainId(ETHEREUM);
        CeremonyProofVerifier impl = new CeremonyProofVerifier();
        CeremonyProofVerifier pv = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );
        assertEq(pv.chainId(), ETHEREUM_CHAIN_ID);
        assertEq(pv.chainId(), this.chainId());
    }

    /// @dev REQ-EVM-01 fixes the width at 256 bits, which is the ambiguity a
    ///      runtime author faces: the same identifier has a one-byte and an
    ///      eight-byte big-endian form, and each hashes somewhere else. The
    ///      vectors above already settle it; this says which readings they
    ///      rule out.
    function test_theWidthIsTwoHundredAndFiftySixBits() public {
        vm.chainId(ETHEREUM);
        assertTrue(this.chainId() != keccak256(abi.encodePacked(uint8(ETHEREUM))), "a minimal-length preimage");
        assertTrue(this.chainId() != keccak256(abi.encodePacked(uint64(ETHEREUM))), "an eight-byte preimage");
    }

    /// @dev REQ-EVM-01C in the small: two chains under this profile never
    ///      share a Chain ID, so a digest built for one opens against nothing
    ///      on the other.
    function test_everyChainGetsItsOwnChainId() public pure {
        assertTrue(ETHEREUM_CHAIN_ID != BASE_CHAIN_ID);
        assertTrue(BASE_CHAIN_ID != SEPOLIA_CHAIN_ID);
        assertTrue(ETHEREUM_CHAIN_ID != SEPOLIA_CHAIN_ID);
    }
}
