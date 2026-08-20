// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyProfile} from "../CeremonyProfile.sol";
import {GooglePlatformVerifier, IJwksRoots} from "../GooglePlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";

contract Honk is IHonkVerifier {
    bool public answer = true;

    function setAnswer(bool a) external {
        answer = a;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return answer;
    }
}

contract Roots is IJwksRoots {
    mapping(bytes32 => uint256) public expiry;

    function trust(bytes32 h, uint256 until) external {
        expiry[h] = until;
    }

    function trustedHashExpiresAt(bytes32 h) external view returns (uint256) {
        return expiry[h];
    }
}

/// @notice The `google/v1` profile: no notarized session, no Notary Service, no
///         fee, and the digest bound as a public proof input rather than
///         through PKCE.
contract GooglePlatformVerifierTest is Test {
    GooglePlatformVerifier verifier;
    Roots roots;
    Honk honk;

    address constant OWNER = address(0xA11CE);
    uint64 constant T0 = 1_770_000_000;
    uint64 constant EXP = T0 + 3600;

    bytes32 constant DIGEST = 0xb318fb559e16a179b853ed2853576cda16032d93b0839bb81a55135d334c0af5;
    bytes constant CLIENT_ID = "123456789-abcdef.apps.googleusercontent.com";
    string constant SUB = "123456789012345678901";
    string constant EMAIL = "a.b+tag@example.com";

    function setUp() public {
        vm.warp(T0);
        roots = new Roots();
        honk = new Honk();
        GooglePlatformVerifier impl = new GooglePlatformVerifier();
        verifier = GooglePlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        GooglePlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(0xDEAD)),
                            IHonkVerifier(address(honk)),
                            IJwksRoots(address(roots))
                        )
                    )
                )
            )
        );
        roots.trust(_modulusHash(), EXP + 86400);
        vm.deal(address(this), 1 ether);
    }

    // ─── Building the public inputs ─────────────────────────────────

    function _pack31(bytes memory s) private pure returns (bytes32 out) {
        require(s.length <= 31, "too long");
        uint256 v;
        for (uint256 i = 0; i < 31; ++i) {
            v = v << 8;
            if (i < s.length) v |= uint8(s[i]);
        }
        return bytes32(v);
    }

    function _packMulti(bytes memory s, uint256 count) private pure returns (bytes32[] memory out) {
        out = new bytes32[](count);
        for (uint256 f = 0; f < count; ++f) {
            bytes memory chunk = new bytes(31);
            for (uint256 i = 0; i < 31; ++i) {
                uint256 at = f * 31 + i;
                chunk[i] = at < s.length ? s[at] : bytes1(0);
            }
            out[f] = _pack31(chunk);
        }
    }

    function _modulusLimb(uint256 i) private pure returns (bytes32) {
        return bytes32(uint256(0x1000 + i));
    }

    function _modulusHash() private pure returns (bytes32) {
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; ++i) {
            bytes32 limb = _modulusLimb(i);
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), limb)
            }
        }
        return keccak256(packed);
    }

    function _inputs(bytes32 digest, bytes memory clientId, uint64 exp) private pure returns (bytes32[] memory pi) {
        pi = new bytes32[](56);
        for (uint256 i = 0; i < 32; ++i) {
            pi[i] = bytes32(uint256(uint8(digest[i])));
        }
        bytes32 aud = sha256(clientId);
        pi[32] = bytes32(uint256(aud) >> 128);
        pi[33] = bytes32(uint256(aud) & type(uint128).max);
        pi[34] = _pack31(bytes(SUB));
        bytes32[] memory email = _packMulti(bytes(EMAIL), 2);
        pi[35] = email[0];
        pi[36] = email[1];
        pi[37] = bytes32(uint256(exp));
        for (uint256 i = 0; i < 18; ++i) {
            pi[38 + i] = _modulusLimb(i);
        }
    }

    function _submission() private pure returns (ICeremony.Submission memory s) {
        s.platformId = CeremonyProfile.PLATFORM_GOOGLE;
        s.version = 1;
        s.proof = hex"00";
        s.publicInputs = _inputs(DIGEST, CLIENT_ID, EXP);
        s.attestations = new ICeremony.Attestation[](0);
        s.clientIdentifier = CLIENT_ID;
    }

    function run(ICeremony.Submission memory s) external payable returns (ICeremony.PlatformFields memory) {
        return verifier.verify{value: msg.value}(DIGEST, s);
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeGoogleCeremony() public {
        ICeremony.PlatformFields memory f = this.run(_submission());
        assertEq(f.userId, SUB);
        assertEq(f.handle, EMAIL);
        assertEq(string(f.clientIdentifier), string(CLIENT_ID));
        // Section 2.2: the signed `exp` supplies BOTH the watermark and the
        // validity ceiling.
        assertEq(f.metadataObservedAt, EXP);
    }

    /// @dev The handle is RAW: normalization is the Consumer's derivation on its
    ///      own write path, so the address keeps its dot and its plus tag
    ///      exactly as Google signed them.
    function test_returnsTheRawEmailUnnormalized() public {
        assertEq(this.run(_submission()).handle, "a.b+tag@example.com");
    }

    // ─── Zero attestations, zero fee ────────────────────────────────

    /// @dev A path with nothing to verify carries no value.
    function test_quotesNothing() public view {
        assertEq(verifier.quote(), 0);
    }

    /// @dev Not merely "no fee required" but "no value accepted": there is
    ///      nothing downstream to forward it to.
    function test_refusesAnyValue() public {
        ICeremony.Submission memory s = _submission();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, 0, 1));
        this.run{value: 1}(s);
    }

    /// @dev REQ-COMMON-05D: a profile requiring no attestation must not reach a
    ///      Notary Service. The one configured here is address(0xDEAD) with no
    ///      code — calling it would revert, so the happy path passing is the
    ///      proof it is never called.
    function test_neverCallsTheNotaryService() public {
        assertEq(verifier.notaryService(), address(0xDEAD));
        this.run(_submission());
    }

    function test_refusesAnyAttestation() public {
        ICeremony.Submission memory s = _submission();
        s.attestations = new ICeremony.Attestation[](1);
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongAttestationCount.selector, 0, 1));
        this.run(s);
    }

    // ─── The digest, bound the other way round ──────────────────────

    /// @dev REQ-COMMON-02A. X and GitHub recompute a PKCE verifier; Google
    ///      compares a public proof input carried by the signed `nonce`.
    function test_rejectsAProofForAnotherDigest() public {
        ICeremony.Submission memory s = _submission();
        s.publicInputs = _inputs(bytes32(uint256(DIGEST) ^ 1), CLIENT_ID, EXP);
        vm.expectPartialRevert(GooglePlatformVerifier.DigestMismatch.selector);
        this.run(s);
    }

    // ─── The audience ───────────────────────────────────────────────

    /// @dev REQ-PLAT-19A. The digest authenticates the bytes without the
    ///      circuit packing a variable-length string into public inputs.
    function test_rejectsAForgedClientIdentifier() public {
        ICeremony.Submission memory s = _submission();
        s.clientIdentifier = "attacker.apps.googleusercontent.com";
        vm.expectRevert(GooglePlatformVerifier.AudienceMismatch.selector);
        this.run(s);
    }

    function test_rejectsAMissingClientIdentifier() public {
        ICeremony.Submission memory s = _submission();
        s.clientIdentifier = "";
        vm.expectRevert(GooglePlatformVerifier.MissingClientIdentifier.selector);
        this.run(s);
    }

    // ─── The trusted modulus ────────────────────────────────────────

    /// @dev REQ-PLAT-23. The circuit exposes the modulus that verified the JWS
    ///      but decides no trust; that decision lives here alone.
    function test_rejectsAnUntrustedModulus() public {
        Roots empty = new Roots();
        vm.prank(OWNER);
        verifier.setJwksRoots(IJwksRoots(address(empty)));
        ICeremony.Submission memory s = _submission();
        vm.expectPartialRevert(GooglePlatformVerifier.UntrustedModulus.selector);
        this.run(s);
    }

    /// @dev Google rotates weekly, so a lapsed key must fail closed rather than
    ///      keep answering.
    function test_rejectsAModulusWhoseTrustHasLapsed() public {
        Roots lapsed = new Roots();
        lapsed.trust(_modulusHash(), T0);
        vm.prank(OWNER);
        verifier.setJwksRoots(IJwksRoots(address(lapsed)));
        ICeremony.Submission memory s = _submission();
        vm.expectPartialRevert(GooglePlatformVerifier.UntrustedModulus.selector);
        this.run(s);
    }

    // ─── Evidence time ──────────────────────────────────────────────

    function test_rejectsAnExpiredToken() public {
        vm.warp(EXP);
        ICeremony.Submission memory s = _submission();
        vm.expectPartialRevert(GooglePlatformVerifier.TokenExpired.selector);
        this.run(s);
    }

    function test_acceptsRightUpToExpiry() public {
        vm.warp(EXP - 1);
        this.run(_submission());
    }

    // ─── The proof ──────────────────────────────────────────────────

    function test_rejectsAProofThatDoesNotVerify() public {
        honk.setAnswer(false);
        ICeremony.Submission memory s = _submission();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run(s);
    }

    function test_rejectsTheWrongPublicInputCount() public {
        ICeremony.Submission memory s = _submission();
        s.publicInputs = new bytes32[](55);
        vm.expectRevert(abi.encodeWithSelector(GooglePlatformVerifier.WrongPublicInputCount.selector, 56, 55));
        this.run(s);
    }
}
