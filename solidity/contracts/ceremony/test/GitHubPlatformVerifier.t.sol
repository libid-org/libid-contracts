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

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the fixtures are made for, derived in `setUp` from the
    /// payload below and this chain.
    bytes32 DIGEST;
    bytes32 constant PKCE_NONCE = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));

    function setUp() public {
        DIGEST = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(T0 + 10);
        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        address honkAddr = address(new Honk());
        GitHubPlatformVerifier vImpl = new GitHubPlatformVerifier();
        verifier = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(notary)),
                            IHonkVerifier(honkAddr),
                            honkAddr.codehash,
                            LIFETIME,
                            SKEW,
                            SKEW
                        )
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
    function _exchange(bytes32 authority) private view returns (ICeremony.Attestation memory) {
        // One revealed run up to the secret, which is ordered last and
        // committed. The head boundary sits inside the revealed run, so the
        // body is located by the framing rather than by a range position.
        bytes memory whole = abi.encodePacked(
            "POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\n",
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE)
        );
        uint32 wholeEnd = uint32(whole.length);
        uint32 secretEnd = wholeEnd + 40; // `&client_secret=<hex>`, committed

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: wholeEnd, end: secretEnd, value: bytes32(uint256(0x5EC1E7))})
            ),
            length: secretEnd
        });

        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory anchor = '"access_token":"';
        uint32 statusEnd = uint32(status.length);
        uint32 headEnd = 17;
        uint32 anchorEnd = headEnd + uint32(anchor.length);
        uint32 bearerEnd = anchorEnd + 40;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 20;

        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: status}),
                AttestationBuilder.Range({start: headEnd, value: anchor}),
                AttestationBuilder.Range({start: bearerEnd, value: '"'})
            ),
            commitments: AttestationBuilder.three(
                AttestationBuilder.Commitment({start: statusEnd, end: headEnd, value: bytes32(uint256(0x88))}),
                AttestationBuilder.Commitment({start: anchorEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x99))})
            ),
            length: total
        });

        bytes memory attested = AttestationBuilder.encode(authority, T0, sent, received);
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
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: end, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: sentLen
        });
        // The status line rides at the front, revealed with the rest, so the
        // verifier reads the server's agreement at offset zero.
        bytes memory b = abi.encodePacked("HTTP/1.1 200 OK\r\n\r\n", body);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(authority, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `github/v1` payload the fixtures are made for.
    function _payload() private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.pkceNonce = PKCE_NONCE;
        s.proof = hex"00";
        s.tokenSession = _exchange(CeremonyProfile.AUTHORITY_GITHUB);
        s.identitySession = _identity('{"login":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB_API);
    }

    function run(TlsNotaryVerifierBase.TlsNotaryProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeGitHubCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, DIGEST);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        // On the shared scale, not raw. Profiles disagree about "now" -- this
        // one's evidence time is an attestation creation time, Google's is a
        // signed expiry an hour ahead -- so each verifier subtracts its own
        // allowance and a Consumer can compare the two.
        assertEq(f.metadataObservedAt, T0 - SKEW);
    }

    /// @dev The `Iv1.` prefix is why the serializer-safe set includes the dot.
    function test_acceptsAGitHubStyleClientIdentifier() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        assertTrue(CeremonyFields.isSerializerSafe(f.clientIdentifier));
    }

    // ─── Two authorities, not one ───────────────────────────────────

    /// @dev `github.com` serves the exchange and `api.github.com` the identity
    ///      read. A profile pinning one authority would accept an identity
    ///      attestation from the exchange host, or the reverse.
    function test_rejectsTheExchangeFromTheApiHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _exchange(CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheIdentityReadFromTheExchangeHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    // ─── The bare-integer id (REQ-PLAT-51) ──────────────────────────

    function test_readsTheIdWithEitherTerminator() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"id":1,"login":"octocat"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        assertEq(this.run{value: quote}(s).userId, "1");
    }

    /// @dev The terminator proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one.
    function test_rejectsAnIdWithoutAStructuralTerminator() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":583231 }', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.BadIntegerTerminator.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsANoncanonicalId() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":007}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.NoncanonicalInteger.selector);
        this.run{value: quote}(s);
    }

    /// @dev A quoted id is not the integer GitHub returns, and REQ-PLAT-08
    ///      refuses it rather than coercing.
    function test_rejectsAQuotedId() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":"583231"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.NoncanonicalInteger.selector);
        this.run{value: quote}(s);
    }

    // ─── The handle field is `login` ────────────────────────────────

    function test_rejectsAResponseWithNoLogin() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"username":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    // ─── Shared duties still hold ───────────────────────────────────

    function test_rejectsAnExchangeRetargetedToAnotherDigest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    function test_quotesTwoNotaryFees() public view {
        assertEq(verifier.quote(), 2 * FEE);
    }

    function test_rejectsASecondAuthorizationHeaderOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        // Corrupt the authority so the session is refused before anything else
        // — a cheap check that the shared guard runs for GitHub too. It is the
        // first 32 bytes now that the stamped tags are gone.
        attested[0] = bytes1(uint8(attested[0]) ^ 0x01);
        s.identitySession = ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }
}
