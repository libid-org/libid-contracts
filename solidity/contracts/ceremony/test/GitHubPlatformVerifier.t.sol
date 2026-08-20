// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";

contract Honk is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice The `github/v1` path. The shared flow is covered by the X suite, so
///         this exercises what actually differs: two authorities, a bare-integer
///         id, the `login` field, a committed body credential, and the absence
///         of a `grant_type` to compare.
contract GitHubPlatformVerifierTest is Test {
    GitHubPlatformVerifier verifier;
    NotaryService notary;
    uint256 quote;

    address constant OWNER = address(0xA11CE);
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant LIFETIME = 3600;
    uint64 constant SKEW = 300;
    uint64 constant T0 = 1_770_000_000;

    bytes32 constant DIGEST = 0xb318fb559e16a179b853ed2853576cda16032d93b0839bb81a55135d334c0af5;
    bytes32 constant PKCE_NONCE = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));

    function setUp() public {
        vm.warp(T0 + 10);
        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        GitHubPlatformVerifier vImpl = new GitHubPlatformVerifier();
        verifier = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(notary)), IHonkVerifier(address(new Honk())), LIFETIME, SKEW)
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 100 ether);
    }

    function _sign(bytes memory a) private pure returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(a)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NOTARY_KEY, h);
        return abi.encodePacked(r, s, v);
    }

    /// The exchange: request line, then the revealed body PREFIX. The secret is
    /// ordered last and committed, so the prefix stops where it begins.
    function _exchange(bytes32 authority) private pure returns (ICeremony.Attestation memory) {
        bytes memory line = "POST /login/oauth/access_token HTTP/1.1\r\n";
        bytes memory prefix = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE)
        );
        uint32 lineEnd = uint32(line.length);
        uint32 prefixEnd = lineEnd + uint32(prefix.length);
        uint32 secretEnd = prefixEnd + 40; // `&client_secret=<hex>`, committed

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, end: lineEnd, value: line}),
                AttestationBuilder.Range({start: lineEnd, end: prefixEnd, value: prefix})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: prefixEnd, end: secretEnd, value: bytes32(uint256(0x5EC1E7))})
            ),
            length: secretEnd
        });

        bytes memory anchor = '"access_token":"';
        uint32 headEnd = 17;
        uint32 anchorEnd = headEnd + uint32(anchor.length);
        uint32 bearerEnd = anchorEnd + 40;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 20;

        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: headEnd, end: anchorEnd, value: anchor}),
                AttestationBuilder.Range({start: bearerEnd, end: quoteEnd, value: '"'})
            ),
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: anchorEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x99))})
            ),
            length: total
        });

        bytes memory attested = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_GITHUB,
            CeremonyProfile.TOKEN_SESSION_TAG,
            authority,
            T0,
            sent,
            received
        );
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    function _identity(string memory body, bytes32 authority) private pure returns (ICeremony.Attestation memory) {
        bytes memory head =
            "GET /user HTTP/1.1\r\naccept: application/vnd.github+json\r\nhost: api.github.com\r\n\r\nauthorization: Bearer ";
        bytes memory bearer = "gho_TOKENTOKENTOKEN";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(bearer.length);
        uint32 sentLen = end + uint32(tail.length);

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, end: start, value: head}),
                AttestationBuilder.Range({start: end, end: sentLen, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: sentLen
        });
        bytes memory b = bytes(body);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, end: uint32(b.length), value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_GITHUB,
            CeremonyProfile.IDENTITY_SESSION_TAG,
            authority,
            T0,
            sent,
            received
        );
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    function _publicInputs() private pure returns (bytes32[] memory pi) {
        pi = new bytes32[](64);
        for (uint256 i = 0; i < 32; ++i) {
            pi[i] = bytes32(uint256(uint8(TOKEN_COMMITMENT[i])));
            pi[32 + i] = bytes32(uint256(uint8(IDENTITY_COMMITMENT[i])));
        }
    }

    function _submission() private pure returns (ICeremony.Submission memory s) {
        s.platformId = CeremonyProfile.PLATFORM_GITHUB;
        s.version = 1;
        s.pkceNonce = PKCE_NONCE;
        s.proof = hex"00";
        s.publicInputs = _publicInputs();
        s.attestations = new ICeremony.Attestation[](2);
        s.attestations[0] = _exchange(CeremonyProfile.AUTHORITY_GITHUB);
        s.attestations[1] = _identity('{"login":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB_API);
    }

    function run(ICeremony.Submission memory s) external payable returns (ICeremony.PlatformFields memory) {
        return verifier.verify{value: msg.value}(DIGEST, s);
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeGitHubCeremony() public {
        ICeremony.PlatformFields memory f = this.run{value: quote}(_submission());
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.metadataObservedAt, T0);
    }

    /// @dev The `Iv1.` prefix is why the serializer-safe set includes the dot.
    function test_acceptsAGitHubStyleClientIdentifier() public {
        ICeremony.PlatformFields memory f = this.run{value: quote}(_submission());
        assertTrue(CeremonyFields.isSerializerSafe(f.clientIdentifier));
    }

    // ─── Two authorities, not one ───────────────────────────────────

    /// @dev `github.com` serves the exchange and `api.github.com` the identity
    ///      read. A profile pinning one authority would accept an identity
    ///      attestation from the exchange host, or the reverse.
    function test_rejectsTheExchangeFromTheApiHost() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[0] = _exchange(CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheIdentityReadFromTheExchangeHost() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identity('{"login":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    // ─── The bare-integer id (REQ-PLAT-51) ──────────────────────────

    function test_readsTheIdWithEitherTerminator() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identity('{"id":1,"login":"octocat"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        assertEq(this.run{value: quote}(s).userId, "1");
    }

    /// @dev The terminator proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one.
    function test_rejectsAnIdWithoutAStructuralTerminator() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identity('{"login":"octocat","id":583231 }', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.BadIntegerTerminator.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsANoncanonicalId() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identity('{"login":"octocat","id":007}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.NoncanonicalInteger.selector);
        this.run{value: quote}(s);
    }

    /// @dev A quoted id is not the integer GitHub returns, and REQ-PLAT-08
    ///      refuses it rather than coercing.
    function test_rejectsAQuotedId() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identity('{"login":"octocat","id":"583231"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.NoncanonicalInteger.selector);
        this.run{value: quote}(s);
    }

    // ─── The handle field is `login` ────────────────────────────────

    function test_rejectsAResponseWithNoLogin() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identity('{"username":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.FieldNotFound.selector);
        this.run{value: quote}(s);
    }

    // ─── Shared duties still hold ───────────────────────────────────

    function test_rejectsAnExchangeRetargetedToAnotherDigest() public {
        ICeremony.Submission memory s = _submission();
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        verifier.verify{value: quote}(bytes32(uint256(DIGEST) ^ 1), s);
    }

    function test_quotesTwoNotaryFees() public view {
        assertEq(verifier.quote(), 2 * FEE);
    }

    function test_rejectsASecondAuthorizationHeaderOnTheIdentityRead() public {
        ICeremony.Submission memory s = _submission();
        bytes memory attested = s.attestations[1].attestedData;
        // Corrupt the platform id so the session is refused before anything
        // else — a cheap check that the shared guards run for GitHub too.
        attested[32] = bytes1(uint8(attested[32]) ^ 0x01);
        s.attestations[1] = ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongPlatform.selector);
        this.run{value: quote}(s);
    }
}
