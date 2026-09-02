// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
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
    /// @dev Google id_tokens live an hour; two gives room without letting a
    ///      claim lock a name for longer than the token itself was valid.
    uint64 constant GOOGLE_ALLOWANCE = 7200;
    uint64 constant EXP = T0 + 3600;

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the public inputs carry as the signed `nonce`, derived in
    /// `setUp` from the payload below and this chain.
    bytes32 DIGEST;
    bytes constant CLIENT_ID = "123456789-abcdef.apps.googleusercontent.com";
    string constant SUB = "123456789012345678901";
    string constant EMAIL = "a.b+tag@example.com";

    function setUp() public {
        DIGEST = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());
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
                            INotaryService(address(0)),
                            IHonkVerifier(address(honk)),
                            address(honk).codehash,
                            GOOGLE_ALLOWANCE,
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

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `google/v1` payload the public inputs are made for. Nothing
    /// notarized in it: the evidence is the proof over a signed token, and the
    /// contract sees only its public inputs.
    function _payload() private view returns (GooglePlatformVerifier.GoogleProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.clientIdentifier = CLIENT_ID;
        s.publicInputs = _inputs(DIGEST, CLIENT_ID, EXP);
        s.proof = hex"00";
    }

    function run(GooglePlatformVerifier.GoogleProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    // ─── The happy path ─────────────────────────────────────────────

    /// @dev Nothing bounded `exp` from above before. `block.timestamp >= exp`
    ///      is a floor, so a token minted with a distant expiry wrote a
    ///      watermark that far ahead -- and `_requireNewer` then refused the
    ///      account owner's own re-proof for as long. Re-proving is the remedy
    ///      for a lost name, so an unbounded expiry buys a lock on one.
    function test_rejectsAnExpiryFurtherAheadThanTheAllowance() public {
        uint64 farOut = uint64(block.timestamp) + GOOGLE_ALLOWANCE + 1;
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = _inputs(DIGEST, CLIENT_ID, farOut);
        vm.expectPartialRevert(PlatformVerifierBase.ObservedInTheFuture.selector);
        this.run(s);
    }

    function test_verifiesAWholeGoogleCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run(_payload());
        assertEq(f.userId, SUB);
        assertEq(f.handle, EMAIL);
        assertEq(string(f.clientIdentifier), string(CLIENT_ID));
        // Section 2.2: the signed `exp` supplies BOTH the watermark and the
        // validity ceiling.
        // The signed expiry, brought onto the shared scale. Raw, it would
        // beat every X or GitHub claim made in the same hour.
        assertEq(f.metadataObservedAt, EXP - GOOGLE_ALLOWANCE);
    }

    /// @dev The handle is RAW: normalization is the Consumer's derivation on its
    ///      own write path, so the address keeps its dot and its plus tag
    ///      exactly as Google signed them.
    function test_returnsTheRawEmailUnnormalized() public {
        assertEq(this.run(_payload()).handle, "a.b+tag@example.com");
    }

    // ─── Zero attestations, zero fee ────────────────────────────────

    /// @dev A path with nothing to verify carries no value.
    /// @dev A profile that verifies no attestation holds no Notary Service.
    ///      Requiring a live address would make a deployer supply a dependency
    ///      purely to satisfy a check, and `notaryService()` would then report
    ///      a collaborator this contract is forbidden to call.
    function test_refusesANotaryItWouldNeverCall() public {
        GooglePlatformVerifier impl = new GooglePlatformVerifier();
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                GooglePlatformVerifier.initialize,
                (
                    OWNER,
                    INotaryService(address(0xDEAD)),
                    IHonkVerifier(address(honk)),
                    address(honk).codehash,
                    GOOGLE_ALLOWANCE,
                    IJwksRoots(address(roots))
                )
            )
        );
    }

    /// @dev REQ-COMMON-05D: a profile requiring no attestation must not reach a
    ///      Notary Service. It holds none at all, so there is nothing to reach
    ///      and nothing for `setTrustRoots` to rotate.
    function test_holdsNoNotary() public view {
        assertEq(verifier.notaryService(), address(0));
    }

    function test_quotesNothing() public view {
        assertEq(verifier.quote(), 0);
    }

    /// @dev Not merely "no fee required" but "no value accepted": there is
    ///      nothing downstream to forward it to.
    function test_refusesAnyValue() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, 0, 1));
        this.run{value: 1}(s);
    }

    // ─── The digest, bound the other way round ──────────────────────

    /// @dev REQ-COMMON-02A. X and GitHub recompute a PKCE verifier; Google
    ///      compares a public proof input carried by the signed `nonce`
    ///      against the digest it rebuilds from the payload. A token proved
    ///      for another digest does not match.
    function test_rejectsAProofForAnotherDigest() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = _inputs(bytes32(uint256(DIGEST) ^ 1), CLIENT_ID, EXP);
        vm.expectPartialRevert(GooglePlatformVerifier.DigestMismatch.selector);
        this.run(s);
    }

    /// @dev And the other way round: the same token, retargeted by changing a
    ///      digest input in the payload, opens against nothing.
    function test_rejectsAPayloadRetargetedToAnotherDigest() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectPartialRevert(GooglePlatformVerifier.DigestMismatch.selector);
        this.run(s);
    }

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run(s);
    }

    // ─── The audience ───────────────────────────────────────────────

    /// @dev REQ-PLAT-19A. The digest authenticates the bytes without the
    ///      circuit packing a variable-length string into public inputs.
    function test_rejectsAForgedClientIdentifier() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.clientIdentifier = "attacker.apps.googleusercontent.com";
        vm.expectRevert(GooglePlatformVerifier.AudienceMismatch.selector);
        this.run(s);
    }

    function test_rejectsAMissingClientIdentifier() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.clientIdentifier = "";
        vm.expectRevert(GooglePlatformVerifier.MissingClientIdentifier.selector);
        this.run(s);
    }

    /// @dev The audience hash arrives as two halves, and only the high one is
    ///      shifted. So an over-wide LOW half alone reproduces any 256-bit
    ///      value -- here the true hash of a client identifier the prover
    ///      never held -- and the audience check passes for free. The contract
    ///      cannot see the circuit's range constraints, so it states its own.
    function test_rejectsAnOverwideLowAudienceHalf() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        bytes32 aud = sha256(CLIENT_ID);
        s.publicInputs[32] = bytes32(0);
        s.publicInputs[33] = aud;
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    /// @dev The high half is shifted, so bits above its 128th fall off the top
    ///      and many values agree. Same rule, same reason.
    function test_rejectsAnOverwideHighAudienceHalf() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[32] = bytes32(uint256(s.publicInputs[32]) | (uint256(1) << 128));
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    // ─── The packed identity fields ─────────────────────────────────

    /// @dev `_unpack` reads 31 bytes of a field element and drops whatever
    ///      sits above them in silence. Dropped, the `sub` this returns is not
    ///      the one the circuit proved -- so a binding would be anchored on an
    ///      id nothing attested.
    function test_rejectsAnOverwideUserIdField() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[34] = bytes32(uint256(s.publicInputs[34]) | (uint256(1) << 248));
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    /// @dev The email is two such elements, and the same silence covers both.
    function test_rejectsAnOverwideEmailField() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[36] = bytes32(uint256(s.publicInputs[36]) | (uint256(1) << 248));
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    // ─── The trusted modulus ────────────────────────────────────────

    /// @dev REQ-PLAT-23. The circuit exposes the modulus that verified the JWS
    ///      but decides no trust; that decision lives here alone.
    function test_rejectsAnUntrustedModulus() public {
        Roots empty = new Roots();
        vm.prank(OWNER);
        verifier.setJwksRoots(IJwksRoots(address(empty)));
        GooglePlatformVerifier.GoogleProof memory s = _payload();
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
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectPartialRevert(GooglePlatformVerifier.UntrustedModulus.selector);
        this.run(s);
    }

    // ─── Evidence time ──────────────────────────────────────────────

    function test_rejectsAnExpiredToken() public {
        vm.warp(EXP);
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectPartialRevert(GooglePlatformVerifier.TokenExpired.selector);
        this.run(s);
    }

    function test_acceptsRightUpToExpiry() public {
        vm.warp(EXP - 1);
        this.run(_payload());
    }

    // ─── The proof ──────────────────────────────────────────────────

    function test_rejectsAProofThatDoesNotVerify() public {
        honk.setAnswer(false);
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run(s);
    }

    function test_rejectsTheWrongPublicInputCount() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = new bytes32[](55);
        vm.expectRevert(abi.encodeWithSelector(GooglePlatformVerifier.WrongPublicInputCount.selector, 56, 55));
        this.run(s);
    }
}
