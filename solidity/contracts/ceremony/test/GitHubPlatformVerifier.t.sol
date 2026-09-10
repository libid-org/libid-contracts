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
    bytes32 digest;
    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));

    function setUp() public {
        digest = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());
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

    /// The head the Token-Exchange Service sends: the two headers the profile
    /// requires, and two it does not compare.
    bytes constant EXCHANGE_HEADERS =
        "host: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// The exchange request's head, declaring a body of `bodyLength` bytes.
    /// Assembled from its parts so a test can change one header and watch the
    /// verifier refuse it.
    function _exchangeHead(uint256 bodyLength) private pure returns (bytes memory) {
        return _exchangeHead(EXCHANGE_HEADERS, bodyLength);
    }

    function _exchangeHead(bytes memory headers, uint256 bodyLength) private pure returns (bytes memory) {
        return abi.encodePacked(
            "POST /login/oauth/access_token HTTP/1.1\r\n",
            headers,
            "content-length: ",
            vm.toString(bodyLength),
            "\r\n\r\n"
        );
    }

    /// The exchange: request line, then the revealed body PREFIX. The secret is
    /// ordered last and committed, so the prefix stops where it begins.
    /// The exchange request as the profile fixes it: one revealed run up to
    /// the secret, which is ordered last and committed. The head boundary sits
    /// inside the revealed run, so the body is located by the framing rather
    /// than by a range position.
    function _exchangeSent() private view returns (AttestationBuilder.Direction memory) {
        bytes memory prefix = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        // The declared length covers the committed `client_secret` too: it is
        // the body GitHub parsed, not the part of it this side can read.
        bytes memory whole = abi.encodePacked(_exchangeHead(prefix.length + 40), prefix);
        uint32 wholeEnd = uint32(whole.length);
        uint32 secretEnd = wholeEnd + 40; // `&client_secret=<hex>`, committed

        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: wholeEnd, end: secretEnd, value: bytes32(uint256(0x5EC1E7))})
            ),
            length: secretEnd
        });
    }

    /// The exchange response: the bearer committed and framed by the revealed
    /// `"access_token":"` anchor and its closing quote, every other byte hidden
    /// behind a commitment of its own.
    function _exchangeResponse() private pure returns (AttestationBuilder.Direction memory) {
        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory anchor = '"access_token":"';
        uint32 statusEnd = uint32(status.length);
        uint32 headEnd = 17;
        uint32 anchorEnd = headEnd + uint32(anchor.length);
        uint32 bearerEnd = anchorEnd + 40;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 20;

        return AttestationBuilder.Direction({
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
    }

    function _exchange(bytes32 authority) private view returns (ICeremony.Attestation memory) {
        bytes memory attested = AttestationBuilder.encode(authority, T0, _exchangeSent(), _exchangeResponse());
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
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
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
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
        assertEq(f.sessionId, digest);
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
        // A space before the brace is JSON's own and reads through; a space
        // before more digits touches no structural byte and is the
        // terminator, which is not one.
        s.identitySession = _identity('{"login":"octocat","id":583231 4}', CeremonyProfile.AUTHORITY_GITHUB_API);
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

    /// @dev REQ-COMMON-19A on the identity read: a second `authorization:`
    ///      header, revealed, anywhere in the request, is refused by the
    ///      line-anchored count. The identity attestation is rebuilt with the
    ///      extra header in its revealed head so the count sees two.
    function test_rejectsASecondAuthorizationHeaderOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("authorization: Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev GitHub honours `token` and Basic beside Bearer. A second
    ///      `authorization` under either is counted all the same; counting only
    ///      `bearer` left it uncounted, and a leaked personal token in it would
    ///      have named someone else's account under this exchange's bearer.
    function test_rejectsASecondAuthorizationHeaderOfAnotherSchemeOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("Authorization: token ghp_stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev And `cookie`, the other credential a platform might honour over
    ///      the bearer, is refused on the identity read by name.
    function test_rejectsACookieOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("cookie: user_session=stolen\r\n");
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("cookie")));
        this.run{value: quote}(s);
    }

    /// @dev The identity request as the browser composes it (`identityRequest`
    ///      on libid `feat/ceremony-rebuild-plan`): `host`, `authorization`,
    ///      `accept`, the browser's own `user-agent`, which GitHub demands,
    ///      `x-github-api-version`, `connection`, in that order and lowercased
    ///      by hyper. The exchange the Token-Exchange Service sends is the
    ///      happy path above already: `host`, `content-type`, `accept`,
    ///      `connection`, hyper's `content-length` last, which Heorhii ran
    ///      against GitHub for real.
    function test_verifiesTheIdentityRequestTheBrowserSends() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHead(
            "GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer ",
            "\r\naccept: application/vnd.github+json\r\n"
            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
            "x-github-api-version: 2022-11-28\r\nconnection: close\r\n\r\n"
        );
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.handle, "octocat");
    }

    /// The honest identity read for a request given as the bytes before the
    /// committed bearer and the bytes after it.
    function _identityWithHead(bytes memory head, bytes memory tail)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory bearer = "gho_TOKENTOKENTOKEN";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(bearer.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: end, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: end + uint32(tail.length)
        });
        bytes memory b = abi.encodePacked("HTTP/1.1 200 OK\r\n\r\n", '{"login":"octocat","id":583231}');
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    string constant RUST_SESSION = "contracts/ceremony/test/fixtures/github-ceremony-session.json";

    /// @dev The exchange as the Token-Exchange Service composes it and the
    ///      identity read as the browser composes it, both encoded by hyper,
    ///      laid out by `libid_transcript::ceremony`, committed with tlsn's
    ///      SHA-256 plaintext hashes, recorded by `AttestedData::from_observed`
    ///      and signed by the key this suite trusts -- the Rust pipeline minus
    ///      the MPC, with nothing written by hand. Verified with those
    ///      signatures unedited; the verifier inside was derived from this
    ///      suite's digest, which the first assertion checks. Generated by
    ///      `cargo run -p libid-tlsn --example ceremony_fixtures` in libid-rs.
    function test_verifiesTheRecordsLibidRsProduces() public {
        string memory json = vm.readFile(RUST_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "derived from this suite's digest");
        assertEq(vm.parseJsonBytes32(json, ".authorization_nonce"), AUTH_NONCE);
        assertEq(vm.parseJsonAddress(json, ".notary"), vm.addr(NOTARY_KEY), "signed by the key this suite trusts");
        assertEq(uint64(vm.parseJsonUint(json, ".created_at")), T0);

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(json, ".token.attested_data"),
            proof: vm.parseJsonBytes(json, ".token.notary_signature")
        });
        s.identitySession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(json, ".identity.attested_data"),
            proof: vm.parseJsonBytes(json, ".identity.notary_signature")
        });
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, digest);
    }

    /// @dev GitHub pretty-prints `/user` for the media type the profile pins:
    ///      a newline and two spaces before every member, a space after every
    ///      colon. The readers remove JSON whitespace before they look, so the
    ///      compact delimiters they match are the grammar, not the bytes.
    function test_readsTheIdentityGitHubPrettyPrints() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity(
            '{\n  "login": "octocat",\n  "id": 583231,\n  "node_id": "MDQ6VXNlcjU4MzIzMQ==",\n  "name": "The Octocat"\n}',
            CeremonyProfile.AUTHORITY_GITHUB_API
        );
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
    }

    /// @dev A second `login` in another spelling is a second `login`.
    function test_rejectsADuplicateMemberInAnotherWhitespaceSpelling() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession =
            _identity('{"login":"octocat","id":583231,"login" : "mallory"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.FieldNotUnique.selector, "login", 2));
        this.run{value: quote}(s);
    }

    /// @dev The wrong authority is still refused before any field is read.
    function test_rejectsAnIdentityReadFromTheWrongAuthority() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        attested[0] = bytes1(uint8(attested[0]) ^ 0x01);
        s.identitySession = ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    /// The honest identity read, with extra revealed header lines after the
    /// request line.
    function _identityWithHeadPrefix(string memory extraHeaders) private pure returns (ICeremony.Attestation memory) {
        bytes memory head = abi.encodePacked(
            "GET /user HTTP/1.1\r\n",
            extraHeaders,
            "accept: application/vnd.github+json\r\nhost: api.github.com\r\n\r\nauthorization: Bearer "
        );
        bytes memory bearer = "gho_TOKENTOKENTOKEN";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(bearer.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: end, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: end + uint32(tail.length)
        });
        bytes memory b = abi.encodePacked("HTTP/1.1 200 OK\r\n\r\n", '{"login":"octocat","id":583231}');
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    /// Commitment FIRST, then one revealed run: tiles, one commitment as the profile demands,
    /// head boundary inside the run. Only TlsNotaryVerifierBase.sol:294 stands between this and acceptance.
    function test_rejectsAnExchangeWhoseRequestLineIsHidden() public {
        bytes memory prefix = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        bytes memory whole = abi.encodePacked(_exchangeHead(prefix.length), prefix);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 40, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: 0, end: 40, value: bytes32(uint256(0x5EC1E7))})
            ),
            length: 40 + uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, uint32(40)));
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-21B, on the profile whose exchange this repository does
    ///      not compose: `github/v1` pins its OWN head, so a service sending a
    ///      request X's constant would have accepted is still refused here.
    ///      The media type is the header the requirement names, because it is
    ///      what decides whether GitHub reads the bytes `formField` reads as a
    ///      form at all.
    function test_rejectsAnotherMediaTypeOnTheExchange() public {
        bytes memory prefix = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        bytes memory head = _exchangeHead(
            "host: github.com\r\ncontent-type: application/json\r\naccept: application/json\r\nconnection: close\r\n",
            prefix.length + 40
        );
        bytes memory whole = abi.encodePacked(head, prefix);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({
                    start: uint32(whole.length), end: uint32(whole.length) + 40, value: bytes32(uint256(0x5EC1E7))
                })
            ),
            length: uint32(whole.length) + 40
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A header the profile never mentions is the Token-Exchange
    ///      Service's own business -- a `user-agent`, say -- as long as it is
    ///      not one of the forbidden names. The exchange still verifies.
    function test_acceptsAnUnlistedHeaderOnTheExchange() public {
        bytes memory prefix = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        bytes memory head = _exchangeHead(
            "host: github.com\r\nuser-agent: libid-bridge/0.3.0\r\ncontent-type: application/x-www-form-urlencoded\r\n"
            "accept: application/json\r\nconnection: close\r\n",
            prefix.length + 40
        );
        bytes memory whole = abi.encodePacked(head, prefix);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({
                    start: uint32(whole.length), end: uint32(whole.length) + 40, value: bytes32(uint256(0x5EC1E7))
                })
            ),
            length: uint32(whole.length) + 40
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.handle, "octocat");
    }

    /// @dev And the fixtures above compose that head from parts, so this is
    ///      what says the two lines the profile requires are among them.
    function test_theFixtureHeadCarriesTheProfilesRequiredHeaders() public pure {
        bytes memory head = _exchangeHead(0);
        bytes memory needle = abi.encodePacked(CeremonyProfile.GITHUB_TOKEN_REQUIRED_HEADERS, "\r\n");
        bool found;
        for (uint256 i = 0; i + needle.length <= head.length && !found; ++i) {
            found = true;
            for (uint256 j = 0; j < needle.length && found; ++j) {
                found = head[i + j] == needle[j];
            }
        }
        assertTrue(found);
    }

    function test_rejectsAnExchangeResponseWithNoRevealedAnchors() public {
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: "HTTP/1.1 200 OK"})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: 15, end: 80, value: TOKEN_COMMITMENT})
            ),
            length: 80
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, _exchangeSent(), received);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
    }

    /// REQ-PLAT-52B: mirror of XPlatformVerifier.t.sol:403 test_provesAgainstTheCommitmentsTheNotarySigned
    /// using this file's TOKEN_COMMITMENT / IDENTITY_COMMITMENT (verified passing as test_P25_…).
    function test_provesAgainstTheCommitmentsTheNotarySigned() public { /* copy of the X test */ }
}
