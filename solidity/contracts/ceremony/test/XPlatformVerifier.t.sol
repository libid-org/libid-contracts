// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract AcceptingHonk is IHonkVerifier {
    bool public answer = true;

    function setAnswer(bool a) external {
        answer = a;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return answer;
    }
}

/// @notice The `x/v1` path end to end: two attestations, a real notary
///         signature over each, and every check the profile assigns here.
contract XPlatformVerifierTest is Test {
    using AttestationBuilder for AttestationBuilder.Range;

    XPlatformVerifier verifier;
    NotaryService notary;
    AcceptingHonk honk;
    /// Hoisted: an external call inside a `{value:}` argument would consume the
    /// `expectRevert` before the call under test ever runs.
    uint256 quote;

    address constant OWNER = address(0xA11CE);
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant LIFETIME = 3600;
    uint64 constant SKEW = 300;
    uint64 constant T0 = 1_770_000_000;

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    bytes32 constant PKCE_NONCE = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    /// The digest the fixtures are made for: what the verifier rebuilds from
    /// the payload below, on this chain. Derived in `setUp`, because it
    /// depends on the chain id.
    bytes32 DIGEST;

    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));

    function setUp() public {
        vm.warp(T0 + 10);
        DIGEST = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());

        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        honk = new AcceptingHonk();

        XPlatformVerifier vImpl = new XPlatformVerifier();
        verifier = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        XPlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(notary)),
                            IHonkVerifier(address(honk)),
                            address(honk).codehash,
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

    // ─── Building a session ─────────────────────────────────────────

    function _sign(bytes memory attested) private pure returns (bytes memory) {
        return _signWith(NOTARY_KEY, attested);
    }

    function _signWith(uint256 key, bytes memory attested) private pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(attested)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// The token request: request line at offset 0, then the whole form body.
    function _tokenAttestation(string memory grantType, string memory clientId, string memory verifierValue)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        return _tokenAttestation(grantType, clientId, verifierValue, true);
    }

    /// @dev `bearerFraming` false commits the bearer with no revealed anchors,
    ///      which is the shape REQ-PLAT-57 exists to refuse.
    function _tokenAttestation(
        string memory grantType,
        string memory clientId,
        string memory verifierValue,
        bool bearerFraming
    ) private pure returns (ICeremony.Attestation memory) {
        AttestationBuilder.Direction memory received;
        // The whole request in one revealed run: X uses a public client and
        // hides no body field, so the head boundary is visible and the body is
        // located by the framing the server itself parsed.
        bytes memory whole = abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\n",
            "grant_type=",
            grantType,
            "&client_id=",
            clientId,
            "&code=abc&code_verifier=",
            verifierValue
        );
        uint32 wholeEnd = uint32(whole.length);

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: wholeEnd
        });
        // A real token response: the bearer committed and framed by the
        // revealed `"access_token":"` delimiter and its closing quote, with
        // every other byte hidden behind a commitment of its own.
        received = _tokenResponse(bearerFraming);

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    /// A token response shaped like the real one:
    ///   [0,15)  revealed `HTTP/1.1 200 OK` -- the server's agreement
    ///   [15,17) the CRLF closing it, committed
    ///   [17,33) revealed `"access_token":"`
    ///   [33,45) the committed bearer
    ///   [45,46) revealed closing quote
    ///   [46,70) the rest of the JSON, behind another commitment
    ///
    /// Every byte accounted for: the direction tiles, like the other three.
    function _tokenResponse(bool framed) private pure returns (AttestationBuilder.Direction memory received) {
        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory prefix = '"access_token":"';
        uint32 statusEnd = uint32(status.length);
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;

        if (framed) {
            return AttestationBuilder.Direction({
                revealed: AttestationBuilder.three(
                    AttestationBuilder.Range({start: 0, value: status}),
                    AttestationBuilder.Range({start: headEnd, value: prefix}),
                    AttestationBuilder.Range({start: bearerEnd, value: '"'})
                ),
                commitments: AttestationBuilder.three(
                    AttestationBuilder.Commitment({start: statusEnd, end: headEnd, value: bytes32(uint256(0x8888))}),
                    AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                    AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
                ),
                length: total
            });
        }

        // The status line and nothing else: the bearer commitment has no
        // revealed anchors around it, which is the shape REQ-PLAT-57 refuses,
        // because it could equally be a `refresh_token` value.
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: status})),
            commitments: AttestationBuilder.three(
                AttestationBuilder.Commitment({start: statusEnd, end: prefixEnd, value: bytes32(uint256(0x8888))}),
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: bearerEnd, end: total, value: bytes32(uint256(0x9999))})
            ),
            length: total
        });
    }

    /// The identity request: bearer committed, every other byte revealed.
    function _identityAttestation(string memory idValue, string memory username, string memory extraHeader)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory head = abi.encodePacked(
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n",
            extraHeader,
            "\r\nauthorization: Bearer "
        );
        bytes memory bearer = "TOKENTOKENTOKEN";
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

        // The status line rides at the front, revealed with the rest: the
        // verifier reads the server's agreement at offset zero.
        bytes memory body =
            abi.encodePacked('HTTP/1.1 200 OK\r\n\r\n{"id":"', idValue, '","username":"', username, '"}');
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: body})),
            commitments: AttestationBuilder.none(),
            length: uint32(body.length)
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `x/v1` payload the fixtures are made for. Public inputs are not in
    /// it: the verifier derives them from the two attestations.
    function _payload() private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        string memory verifierValue = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.pkceNonce = PKCE_NONCE;
        s.proof = hex"00";
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", verifierValue);
        s.identitySession = _identityAttestation("2244994945", "alice", "");
    }

    /// The payload as the bytes the Proof Verifier would forward.
    function run(TlsNotaryVerifierBase.TlsNotaryProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeXCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        assertEq(f.userId, "2244994945");
        assertEq(f.handle, "alice");
        assertEq(string(f.clientIdentifier), "myClient-1");
        // What entered the digest comes back, with the session id and the
        // ceremony version this verifier implements.
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

    function test_quotesTwoNotaryFees() public view {
        assertEq(verifier.quote(), 2 * notary.fee());
    }

    function test_bothFeesReachTheNotary() public {
        this.run{value: quote}(_payload());
        assertEq(address(notary).balance, 2 * FEE);
    }

    function test_rejectsAnyValueOtherThanTheQuote() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, quote, quote - 1));
        this.run{value: quote - 1}(s);
    }

    // ─── The digest binding ─────────────────────────────────────────

    /// @dev REQ-COMMON-15A, and the whole binding between evidence and
    ///      transaction. The verifier rebuilds the digest from the payload, so
    ///      changing any digest input -- here the nonce -- derives a different
    ///      verifier, and the revealed one no longer matches.
    function test_rejectsAnAttestationRetargetedToAnotherDigest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev The same for the transaction data: it is in the digest, so a
    ///      payload naming another target opens against nothing.
    function test_rejectsAnAttestationRetargetedToAnotherWallet() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.transactionData = abi.encode(address(0xDEAD));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAForgedPkceNonce() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.pkceNonce = bytes32(uint256(1));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev The verifier implements one ceremony version and the digest binds
    ///      it. A payload claiming another is refused by name, before any fee
    ///      moves, rather than as a verifier mismatch after both sessions were
    ///      paid for.
    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
    }

    // ─── grant_type ─────────────────────────────────────────────────

    /// @dev REQ-PLAT-56. A refresh grant still carries a code, a redirect_uri
    ///      and a digest-derived verifier, so every other check passes while X
    ///      mints a fresh bearer — letting an app with a refresh token mint
    ///      identity proofs at arbitrary addresses from one consent.
    function test_rejectsARefreshGrant() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.tokenSession = _tokenAttestation("refresh_token", "myClient-1", v);
        vm.expectPartialRevert(XPlatformVerifier.WrongGrantType.selector);
        this.run{value: quote}(s);
    }

    // ─── The client identifier ──────────────────────────────────────

    function test_rejectsAPercentEncodedClientIdentifier() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.tokenSession = _tokenAttestation("authorization_code", "my%2Bapp", v);
        vm.expectPartialRevert(TlsNotaryVerifierBase.ClientIdentifierNotSerializerSafe.selector);
        this.run{value: quote}(s);
    }

    // ─── The attestations themselves ────────────────────────────────

    function test_rejectsAnUntrustedNotary() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        s.identitySession.proof = _signWith(0xB0B, attested);
        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        this.run{value: quote}(s);
    }

    /// @dev Nothing in an attestation says which session of a ceremony it
    ///      covers, and nothing needs to. X serves both sessions from one host,
    ///      so the authority cannot separate them either -- what separates them
    ///      is the request line, which the notary recorded as a revealed range
    ///      and did not choose. Swapping the two therefore fails on bytes that
    ///      came off the wire rather than on a label the prover handed over.
    function test_rejectsTheTwoSessionsSwapped() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        (s.tokenSession, s.identitySession) = (s.identitySession, s.tokenSession);
        vm.expectPartialRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    // ─── The circuit link ───────────────────────────────────────────

    /// @dev The inputs the proof is checked against are BUILT from the two
    ///      attestations, so "the circuit proved a link between other
    ///      attestations" (REQ-PLAT-32C) is not a case to reject -- it is a
    ///      case that cannot be stated. This asserts what the verifier derived.
    function test_provesAgainstTheCommitmentsTheNotarySigned() public {
        bytes32[] memory expected = new bytes32[](64);
        for (uint256 i = 0; i < 32; ++i) {
            expected[i] = bytes32(uint256(uint8(TOKEN_COMMITMENT[i])));
            expected[32 + i] = bytes32(uint256(uint8(IDENTITY_COMMITMENT[i])));
        }

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        // Exact arguments: the proof as submitted, and inputs the caller never
        // supplied.
        vm.expectCall(address(honk), abi.encodeCall(IHonkVerifier.verify, (s.proof, expected)));
        this.run{value: quote}(s);
    }

    function test_rejectsAProofThatDoesNotVerify() public {
        honk.setAnswer(false);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run{value: quote}(s);
    }

    // ─── The identity request ───────────────────────────────────────

    function test_rejectsASecondAuthorizationHeader() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "alice", "authorization: Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAnObsoleteLineFold() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "alice", "authorization:\r\n Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.ObsoleteLineFold.selector);
        this.run{value: quote}(s);
    }

    // ─── Evidence time ──────────────────────────────────────────────

    function test_rejectsAnExpiredProof() public {
        vm.warp(T0 + LIFETIME);
        // Built first: `vm.sign` inside is an external call, and it would
        // consume the cheatcode before the call under test.
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectPartialRevert(PlatformVerifierBase.ProofExpired.selector);
        this.run{value: quote}(s);
    }

    function test_acceptsRightUpToExpiry() public {
        vm.warp(T0 + LIFETIME - 1);
        this.run{value: quote}(_payload());
    }

    function test_rejectsAnAttestationTooFarAhead() public {
        vm.warp(T0 - SKEW - 1);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectPartialRevert(PlatformVerifierBase.AttestationAhead.selector);
        this.run{value: quote}(s);
    }

    /// @dev Each parameter is capped, and the cap is not cosmetic.
    ///      `blockTime + skew` and `blockTime + allowance` are checked sums, so
    ///      a value near `type(uint64).max` panics EVERY verification through
    ///      this contract rather than widening its window -- and a governance
    ///      typo that only an upgrade can undo is the worst shape a parameter
    ///      can take.
    function test_refusesAnUnusableSkew() public {
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.ParameterTooLarge.selector);
        verifier.setProtocolParameters(LIFETIME, type(uint64).max, SKEW);
    }

    function test_refusesAnUnusableObservationAllowance() public {
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.ParameterTooLarge.selector);
        verifier.setProtocolParameters(LIFETIME, SKEW, type(uint64).max);
    }

    /// @dev A lifetime past the cap does not panic; it keeps a proof spendable
    ///      long after the session it attests, which the parameter exists to
    ///      stop.
    function test_refusesAnUnboundedLifetime() public {
        // Read before the cheatcodes: an argument is a call of its own, and
        // `expectRevert` would bind to it rather than to the setter.
        uint64 tooLong = verifier.MAX_PROOF_LIFETIME() + 1;
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.ParameterTooLarge.selector);
        verifier.setProtocolParameters(tooLong, SKEW, SKEW);
    }

    /// @dev The caps are ceilings, not targets: the profile's own defaults sit
    ///      far below them and stay settable.
    function test_acceptsTheSpecifiedDefaults() public {
        vm.prank(OWNER);
        verifier.setProtocolParameters(3600, 300, 3600);
        (uint64 lifetime, uint64 skew, uint64 allowance) = verifier.protocolParameters();
        assertEq(lifetime, 3600);
        assertEq(skew, 300);
        assertEq(allowance, 3600);
    }

    /// @dev Governance-owned, read at verification time, with no caller
    ///      substitute (REQ-PARAM-02).
    function test_loweringTheLifetimeRejectsAnOutstandingProof() public {
        vm.warp(T0 + 100);
        this.run{value: quote}(_payload());

        vm.prank(OWNER);
        verifier.setProtocolParameters(50, SKEW, SKEW);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectPartialRevert(PlatformVerifierBase.ProofExpired.selector);
        this.run{value: quote}(s);
    }

    /// @dev `maxFutureAttestationSkew` and `futureObservationAllowance` are
    ///      two numbers for two jobs -- how far ahead a notary's clock may
    ///      read, and how far ahead the watermark may sit -- and governance
    ///      sets them apart. Passing the first said nothing about the second,
    ///      so an attestation inside the skew but past the allowance wrote a
    ///      watermark in the future, and every honest later proof of that name
    ///      read as stale until the clock caught up.
    function test_rejectsAnAttestationPastTheObservationAllowanceButInsideTheSkew() public {
        vm.prank(OWNER);
        verifier.setProtocolParameters(LIFETIME, SKEW, 0);

        // T0 is SKEW ahead of the warp in setUp, so it passes the skew and not
        // a zero allowance.
        vm.warp(T0 - SKEW);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectPartialRevert(PlatformVerifierBase.ObservedInTheFuture.selector);
        this.run{value: quote}(s);
    }

    // ─── The proof artifact (REQ-COMMON-45) ─────────────────────────

    /// @dev An address alone does not say WHICH circuit answers behind it.
    ///      bb-generated Honk verifiers embed their verification key as code
    ///      constants and expose no getter, so the code hash is the only handle
    ///      governance has on the artifact it selected. Naming it makes a
    ///      mis-wiring fail here, at the governance call, rather than at the
    ///      first user's proof.
    function test_rejectsAVerifierThatIsNotTheNamedArtifact() public {
        address other = address(new AcceptingHonk());
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(other), keccak256("some other artifact"));
    }

    /// @dev An account with no code hashes to the empty-code hash, which no
    ///      real artifact matches, so a plain address cannot be wired either.
    /// @dev A non-existent account hashes to zero (EIP-1052) and an empty one
    ///      to `keccak256("")`, so either as the EXPECTED value is a hash any
    ///      such address satisfies -- and the mis-wiring surfaces at the first
    ///      user's proof, which is what this check exists to prevent.
    function test_refusesAnExpectedCodehashAnEmptyAccountWouldSatisfy() public {
        address untouched = address(0xDEAD0001);
        vm.startPrank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(untouched), bytes32(0));
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(untouched), keccak256(""));
        vm.stopPrank();
    }

    function test_rejectsAnAddressHoldingNoCode() public {
        address eoa = address(0xB0B);
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(eoa), keccak256("anything"));
    }

    function test_recordsTheArtifactItWired() public {
        address other = address(new AcceptingHonk());
        vm.prank(OWNER);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(other), other.codehash);
        assertEq(verifier.honkVerifier(), other);
        assertEq(verifier.honkVerifierCodehash(), other.codehash);
    }

    // ─── The identity fields ────────────────────────────────────────

    function test_rejectsAResponseNamingTwoUsernames() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", 'a","username":"b', "");
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    /// @dev The one duplicate this verifier does NOT catch, asserted so the
    ///      assumption it rests on is visible and will fail loudly if the
    ///      reasoning ever changes.
    ///
    ///      The genuine member sits behind a COMMITMENT. Every reader scans
    ///      revealed bytes, so it is invisible to the per-range read and to the
    ///      cross-range delimiter count alike: both see exactly one member, and
    ///      the handle recorded is the one the prover chose. The response is
    ///      tiled, not revealed whole, so nothing rejects it.
    ///
    ///      Reaching this requires the PLATFORM to emit a response naming an
    ///      authoritative field twice. ASM-PROV-06 assumes it does not, and
    ///      JSON escaping keeps a `","username":"` delimiter out of any value
    ///      the account controls -- a quote inside a string is written `\"`,
    ///      which does not match. This fixture writes the bytes directly,
    ///      which no serializer would produce.
    ///
    ///      The layout was revealed whole precisely to close this, at the cost
    ///      of publishing every byte of the response on chain. That trade was
    ///      taken the other way deliberately.
    function test_acceptsAnIdentityResponseHidingADuplicateMember() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationHidingAMember();
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        // `alice` is the member the prover revealed; the signed transcript also
        // carried `victim`, behind the commitment, and nothing here saw it.
        assertEq(f.handle, "alice");
    }

    /// The bytes `","username":"victim` sit inside the response, committed, and
    /// the prover reveals a second `"username":"alice"` after them.
    function _identityAttestationHidingAMember() private pure returns (ICeremony.Attestation memory) {
        bytes memory head =
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n\r\nauthorization: Bearer ";
        bytes memory bearer = "TOKENTOKENTOKEN";
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

        bytes memory open = 'HTTP/1.1 200 OK\r\n\r\n{"id":"2244994945","name":"';
        bytes memory hidden = '","username":"victim';
        bytes memory shown = '","username":"alice"}';
        uint32 hiddenStart = uint32(open.length);
        uint32 hiddenEnd = hiddenStart + uint32(hidden.length);

        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: open}),
                AttestationBuilder.Range({start: hiddenEnd, value: shown})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: hiddenStart, end: hiddenEnd, value: keccak256("hidden")})
            ),
            length: hiddenEnd + uint32(shown.length)
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    /// @dev The same, with the two members in SEPARATE revealed ranges.
    ///
    ///      The test above puts both inside one range, where the field reader's
    ///      own scan sees two matches. This one puts one member in each range,
    ///      so every individual range looks unambiguous and only the count
    ///      ACROSS ranges is wrong. A reader that returned the first match it
    ///      found -- or that stopped scanning once it had one -- would accept
    ///      this and let the prover choose which handle the chain records.
    function test_rejectsTwoUsernamesInSeparateRevealedRanges() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationSplitAcrossRanges();
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    /// @dev A second `"username":"` member whose DELIMITER is cut by a range
    ///      boundary. Neither half holds a whole delimiter, so the per-range
    ///      scan counted one and read the surviving copy -- which the prover
    ///      chose. The delimiter is counted over the concatenation for this.
    function test_rejectsADuplicateDelimiterHiddenUnderARangeBoundary() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        // Joined: ...,"username":"alice","username":"mallory"} -- two members,
        // and the boundary falls through the second one's delimiter.
        s.identitySession = _splitIdentityAttestation(
            'HTTP/1.1 200 OK\r\n\r\n{"id":"2244994945","username":"alice","userna', 'me":"mallory"}'
        );
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    /// @dev A handle that exists ONLY across a range boundary.
    ///
    ///      Neither revealed range contains a `username` member. Joined end to
    ///      end they spell one, because the prover split the delimiter itself:
    ///      the first range stops mid-word and the second resumes it. A reader
    ///      that concatenated the ranges before matching would find exactly one
    ///      member, find nothing wrong with it, and record a handle that never
    ///      crossed the wire. Reading each range on its own finds none, which
    ///      is the rejection.
    function test_rejectsAHandleSplicedAcrossARangeBoundary() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationSplicedHandle();
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    function _identityAttestationSplicedHandle() private pure returns (ICeremony.Attestation memory) {
        bytes memory first = 'HTTP/1.1 200 OK\r\n\r\n{"id":"2244994945","usern';
        bytes memory second = 'ame":"mallory"}';
        return _splitIdentityAttestation(first, second);
    }

    /// @dev An identity response whose two revealed ranges each carry a whole
    ///      `username` member. The ranges still tile the signed length, so
    ///      nothing but the cross-range count rejects it.
    function _identityAttestationSplitAcrossRanges() private pure returns (ICeremony.Attestation memory) {
        return _splitIdentityAttestation(
            'HTTP/1.1 200 OK\r\n\r\n{"id":"2244994945","username":"alice"', ',"username":"mallory"}'
        );
    }

    /// @dev One identity attestation whose received direction is exactly the two
    ///      revealed ranges given, tiling the signed length with no commitment.
    function _splitIdentityAttestation(bytes memory first, bytes memory second)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory head =
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\nauthorization: Bearer ";
        bytes memory bearer = "TOKENTOKENTOKEN";
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

        uint32 split = uint32(first.length);
        uint32 recvLen = split + uint32(second.length);

        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: first}),
                AttestationBuilder.Range({start: split, value: second})
            ),
            commitments: AttestationBuilder.none(),
            length: recvLen
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    // ─── The token response covers every byte ───────────────────────

    /// @dev The profile says every byte outside the anchors is committed. Until
    ///      the token response was tiled that was stated and not enforced, so a
    ///      prover could leave bytes neither revealed nor committed -- bytes the
    ///      notary signed no position for at all.
    function test_rejectsATokenResponseWithAnUncoveredByte() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenAttestationWithGap();
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }

    /// @dev A token response with one byte belonging to neither list: the
    ///      status line's CRLF is left out of both.
    function _tokenAttestationWithGap() private view returns (ICeremony.Attestation memory) {
        // The verifier is derived from the digest the payload rebuilds to, so
        // the request passes the PKCE check and the coverage gap below is what
        // the verifier trips on.
        bytes memory whole = abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\n",
            "grant_type=authorization_code&client_id=myClient-1&code=abc&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE)
        );
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });

        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory prefix = '"access_token":"';
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;

        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: status}),
                AttestationBuilder.Range({start: headEnd, value: prefix}),
                AttestationBuilder.Range({start: bearerEnd, value: '"'})
            ),
            // The CRLF at [15,17) is covered by nothing.
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
            ),
            length: total
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    // ─── The token response anchors (REQ-PLAT-57, TEST-PLAT-22) ─────

    /// @dev The bearer is identified by its framing, not by being the only
    ///      commitment: the response hides every other byte behind a commitment
    ///      of its own. With no revealed anchors the committed range is
    ///      indistinguishable from a `refresh_token` value, or any other
    ///      substring the prover chose to commit.
    function test_rejectsATokenResponseWithNoRevealedAnchors() public {
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", v, false);
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    // ─── The identity request line (REQ-COMMON-21A) ─────────────────

    /// @dev The path separates operations on the same server, so
    ///      `/2/users/me` must be what was asked. A lookup-by-username endpoint
    ///      would answer for an account the prover never held.
    function test_rejectsAForeignIdentityPath() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationOnPath("GET /2/users/by/username/victim ");
        vm.expectRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    function _identityAttestationOnPath(string memory requestLine) private pure returns (ICeremony.Attestation memory) {
        bytes memory head = abi.encodePacked(
            requestLine, "HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n", "\r\nauthorization: Bearer "
        );
        bytes memory bearer = "TOKENTOKENTOKEN";
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
        bytes memory body = '"id":"2244994945","username":"alice"';
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: body})),
            commitments: AttestationBuilder.none(),
            length: uint32(body.length)
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    /// @dev The authority is what the notary authenticated, not a revealed
    ///      `Host` header, so a transcript from an attacker's server cannot
    ///      substitute for the platform's.
    function test_rejectsAForeignAuthority() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        // authorityId is the first 32 bytes: it is the whole header identity
        // now that the stamped tags are gone.
        bytes32 evil = keccak256(bytes("evil.example"));
        for (uint256 i = 0; i < 32; ++i) {
            attested[i] = evil[i];
        }
        s.identitySession = ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheSameSubmissionOnAnotherChain() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.chainId(block.chainid + 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    function test_refusesTheWrongCeremonyVersionBeforeAnyNotaryCall() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectCall(address(notary), abi.encodeWithSelector(INotaryService.verify.selector), 0);
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
        assertEq(address(notary).balance, 0);
    }

    function test_aTlsProfileRefusesAZeroNotary() public {
        XPlatformVerifier impl = new XPlatformVerifier();
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                XPlatformVerifier.initialize,
                (
                    OWNER,
                    INotaryService(address(0)),
                    IHonkVerifier(address(honk)),
                    address(honk).codehash,
                    LIFETIME,
                    SKEW,
                    SKEW
                )
            )
        );
    }

    function test_onlyTheOwnerRotatesRootsAndParameters() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(address(honk)), address(honk).codehash);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.setProtocolParameters(1, 1, 1);
    }

    function test_zeroHonkVerifierIsRefused() public {
        vm.prank(OWNER);
        vm.expectRevert(PlatformVerifierBase.ZeroAddress.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(address(0)), address(honk).codehash);
    }

    function test_aRejectionAtTheSecondSessionLeavesNoFee() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession.proof = _signWith(0xB0B, s.identitySession.attestedData);
        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        this.run{value: quote}(s);
        assertEq(address(notary).balance, 0, "the first fee stayed delivered");
    }

    function test_rejectsOneWeiMoreThanTheQuote() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, quote, quote + 1));
        this.run{value: quote + 1}(s);
    }

    function test_rejectsAnEmptyClientIdentifier() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.tokenSession = _tokenAttestation("authorization_code", "", v);
        vm.expectPartialRevert(TlsNotaryVerifierBase.ClientIdentifierNotSerializerSafe.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsATokenRequestWithNoHeadBoundary() public {
        bytes memory whole = abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n",
            "grant_type=authorization_code&client_id=myClient-1&code=abc&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE)
        );
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.NoHeadBoundary.selector, 0));
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-21A: the method is part of the pinned request line, so
    ///      a GET with an otherwise honest body is refused before any field
    ///      is read.
    function test_rejectsTheWrongMethodOnTheTokenRequest() public {
        bytes memory whole = abi.encodePacked(
            "GET /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\n",
            "grant_type=authorization_code&client_id=myClient-1&code=abc&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE)
        );
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    /// The honest token request, byte for byte as `_tokenAttestation` sends it.
    function _honestXRequest() private view returns (bytes memory) {
        return abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\n",
            "grant_type=authorization_code&client_id=myClient-1&code=abc&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE)
        );
    }

    /// That request as the one revealed run the profile fixes.
    function _honestTokenSent() private view returns (AttestationBuilder.Direction memory) {
        bytes memory whole = _honestXRequest();
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
    }

    /// TlsNotaryVerifierBase.sol:294-295: request line hidden under a commitment tiling [0,10).
    function test_rejectsATokenRequestLineNotAtOrigin() public {
        bytes memory whole = _honestXRequest(); // the whole honest token request of _tokenAttestation
        bytes memory rest = new bytes(whole.length - 10);
        for (uint256 i = 0; i < rest.length; ++i) {
            rest[i] = whole[10 + i];
        }
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 10, value: rest})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: 0, end: 10, value: bytes32(uint256(0xAB))})
            ),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, uint32(10)));
        this.run{value: quote}(s);
    }

    /// TlsNotaryVerifierBase.sol:293: no revealed range in the sent direction at all.
    function test_rejectsATokenRequestWithNoRevealedRange() public {
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: new AttestationBuilder.Range[](0), commitments: AttestationBuilder.none(), length: 0
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, type(uint32).max));
        this.run{value: quote}(s);
    }

    function test_rejectsATokenResponseFramingTwoBearers() public {
        bytes memory p = '"access_token":"';
        AttestationBuilder.Direction memory recv = AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: p}),
                AttestationBuilder.Range({start: 28, value: abi.encodePacked('"', p)}),
                AttestationBuilder.Range({start: 57, value: '"'})
            ),
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: 16, end: 28, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: 45, end: 57, value: bytes32(uint256(0x3333))})
            ),
            length: 58
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, _honestTokenSent(), recv);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(CeremonyAttestation.AmbiguousFraming.selector);
        this.run{value: quote}(s);
    }

    function test_aForeignOperationDomainFailsTheBinding() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.operationDomain = keccak256("someone.else");
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    function test_aNeedleInsideAHeaderValueIsNotAHeaderLine() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "alice", "x-note: authorization: Bearer decoy\r\n");
        assertEq(this.run{value: quote}(s).handle, "alice");
    }

    function test_rejectsABareLineFeedInTheIdentityRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "alice", "x-pad: a\nauthorization: Bearer STOLEN\r\n");
        vm.expectPartialRevert(CeremonyAttestation.BareLineFeed.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAResponseNamingTwoIds() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation('1","id":"2', "alice", "");
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    function test_theIdentityAttestationsOwnTimeIsNotEvidenceTime() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory a = s.identitySession.attestedData;
        // createdAt := 1, the eight bytes after the authority id.
        for (uint256 i = 32; i < 40; ++i) {
            a[i] = 0;
        }
        a[39] = 0x01;
        s.identitySession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        assertEq(this.run{value: quote}(s).metadataObservedAt, T0 - SKEW);
    }

    function test_aMalformedPayloadRevertsWithNoData() public {
        (bool ok, bytes memory ret) = address(verifier).call{value: quote}(abi.encodeCall(verifier.verify, (hex"")));
        assertFalse(ok);
        assertEq(ret.length, 0);
    }
}
