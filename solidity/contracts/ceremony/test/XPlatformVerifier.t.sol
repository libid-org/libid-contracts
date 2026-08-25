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
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
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
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    /// Public inputs are the two commitments, one byte per field element.
    function _submission() private view returns (ICeremony.Submission memory s) {
        string memory verifierValue = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.platformId = CeremonyProfile.PLATFORM_X;
        s.version = 1;
        s.pkceNonce = PKCE_NONCE;
        s.proof = hex"00";
        s.attestations = new ICeremony.Attestation[](2);
        s.attestations[0] = _tokenAttestation("authorization_code", "myClient-1", verifierValue);
        s.attestations[1] = _identityAttestation("2244994945", "alice", "");
    }

    function run(ICeremony.Submission memory s) external payable returns (ICeremony.PlatformFields memory) {
        return verifier.verify{value: msg.value}(DIGEST, s);
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeXCeremony() public {
        ICeremony.PlatformFields memory f = this.run{value: quote}(_submission());
        assertEq(f.userId, "2244994945");
        assertEq(f.handle, "alice");
        assertEq(string(f.clientIdentifier), "myClient-1");
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
        this.run{value: quote}(_submission());
        assertEq(address(notary).balance, 2 * FEE);
    }

    function test_rejectsAnyValueOtherThanTheQuote() public {
        ICeremony.Submission memory s = _submission();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, quote, quote - 1));
        this.run{value: quote - 1}(s);
    }

    // ─── The digest binding ─────────────────────────────────────────

    /// @dev REQ-COMMON-15A, and the whole binding between evidence and
    ///      transaction. A different digest derives a different verifier, so
    ///      the revealed one no longer matches.
    function test_rejectsAnAttestationRetargetedToAnotherDigest() public {
        ICeremony.Submission memory s = _submission();
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        verifier.verify{value: quote}(bytes32(uint256(DIGEST) ^ 1), s);
    }

    function test_rejectsAForgedPkceNonce() public {
        ICeremony.Submission memory s = _submission();
        s.pkceNonce = bytes32(uint256(1));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    // ─── grant_type ─────────────────────────────────────────────────

    /// @dev REQ-PLAT-56. A refresh grant still carries a code, a redirect_uri
    ///      and a digest-derived verifier, so every other check passes while X
    ///      mints a fresh bearer — letting an app with a refresh token mint
    ///      identity proofs at arbitrary addresses from one consent.
    function test_rejectsARefreshGrant() public {
        ICeremony.Submission memory s = _submission();
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.attestations[0] = _tokenAttestation("refresh_token", "myClient-1", v);
        vm.expectPartialRevert(XPlatformVerifier.WrongGrantType.selector);
        this.run{value: quote}(s);
    }

    // ─── The client identifier ──────────────────────────────────────

    function test_rejectsAPercentEncodedClientIdentifier() public {
        ICeremony.Submission memory s = _submission();
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.attestations[0] = _tokenAttestation("authorization_code", "my%2Bapp", v);
        vm.expectPartialRevert(TlsNotaryVerifierBase.ClientIdentifierNotSerializerSafe.selector);
        this.run{value: quote}(s);
    }

    /// @dev X reads its client identifier from a revealed range, so a supplied
    ///      copy is a duplicate of a value the attested data already carries.
    function test_rejectsACallerSuppliedClientIdentifier() public {
        ICeremony.Submission memory s = _submission();
        s.clientIdentifier = "attacker";
        vm.expectRevert(TlsNotaryVerifierBase.UnexpectedClientIdentifier.selector);
        this.run{value: quote}(s);
    }

    // ─── The attestations themselves ────────────────────────────────

    function test_rejectsAnUntrustedNotary() public {
        ICeremony.Submission memory s = _submission();
        bytes memory attested = s.attestations[1].attestedData;
        s.attestations[1].signature = _signWith(0xB0B, attested);
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
        ICeremony.Submission memory s = _submission();
        (s.attestations[0], s.attestations[1]) = (s.attestations[1], s.attestations[0]);
        vm.expectPartialRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheWrongAttestationCount() public {
        ICeremony.Submission memory s = _submission();
        ICeremony.Attestation[] memory one = new ICeremony.Attestation[](1);
        one[0] = s.attestations[0];
        s.attestations = one;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongAttestationCount.selector, 2, 1));
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

        ICeremony.Submission memory s = _submission();
        // Exact arguments: the proof as submitted, and inputs the caller never
        // supplied.
        vm.expectCall(address(honk), abi.encodeCall(IHonkVerifier.verify, (s.proof, expected)));
        this.run{value: quote}(s);
    }

    /// @dev And the caller cannot state them. There is no field to disagree
    ///      with the attestations in.
    function test_refusesCallerSuppliedPublicInputs() public {
        ICeremony.Submission memory s = _submission();
        s.publicInputs = new bytes32[](64);
        vm.expectRevert(TlsNotaryVerifierBase.UnexpectedPublicInputs.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAProofThatDoesNotVerify() public {
        honk.setAnswer(false);
        ICeremony.Submission memory s = _submission();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run{value: quote}(s);
    }

    // ─── The identity request ───────────────────────────────────────

    function test_rejectsASecondAuthorizationHeader() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestation("2244994945", "alice", "authorization: Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAnObsoleteLineFold() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestation("2244994945", "alice", "authorization:\r\n Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.ObsoleteLineFold.selector);
        this.run{value: quote}(s);
    }

    // ─── Evidence time ──────────────────────────────────────────────

    function test_rejectsAnExpiredProof() public {
        vm.warp(T0 + LIFETIME);
        // Built first: `vm.sign` inside is an external call, and it would
        // consume the cheatcode before the call under test.
        ICeremony.Submission memory s = _submission();
        vm.expectPartialRevert(PlatformVerifierBase.ProofExpired.selector);
        this.run{value: quote}(s);
    }

    function test_acceptsRightUpToExpiry() public {
        vm.warp(T0 + LIFETIME - 1);
        this.run{value: quote}(_submission());
    }

    function test_rejectsAnAttestationTooFarAhead() public {
        vm.warp(T0 - SKEW - 1);
        ICeremony.Submission memory s = _submission();
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
        this.run{value: quote}(_submission());

        vm.prank(OWNER);
        verifier.setProtocolParameters(50, SKEW, SKEW);
        ICeremony.Submission memory s = _submission();
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
        ICeremony.Submission memory s = _submission();
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
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestation("2244994945", 'a","username":"b', "");
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    /// @dev And the same again, with the genuine member behind a COMMITMENT.
    ///
    ///      The scan reads revealed bytes, so a commitment is invisible to it.
    ///      A response that genuinely names the field twice -- one of them
    ///      echoed out of a user-controlled profile string -- lets the prover
    ///      commit the real member and reveal the one it chose. Both the
    ///      per-range read and the cross-range delimiter count then see exactly
    ///      one, and the handle written is the prover's.
    ///
    ///      The identity response carries no credential, so nothing in it may
    ///      be hidden at all.
    function test_rejectsAnIdentityResponseHidingBytes() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestationHidingAMember();
        vm.expectPartialRevert(CeremonyAttestation.UnexpectedCommitment.selector);
        this.run{value: quote}(s);
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
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
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
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestationSplitAcrossRanges();
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    /// @dev A second `"username":"` member whose DELIMITER is cut by a range
    ///      boundary. Neither half holds a whole delimiter, so the per-range
    ///      scan counted one and read the surviving copy -- which the prover
    ///      chose. The delimiter is counted over the concatenation for this.
    function test_rejectsADuplicateDelimiterHiddenUnderARangeBoundary() public {
        ICeremony.Submission memory s = _submission();
        // Joined: ...,"username":"alice","username":"mallory"} -- two members,
        // and the boundary falls through the second one's delimiter.
        s.attestations[1] = _splitIdentityAttestation(
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
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestationSplicedHandle();
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
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    // ─── The token response covers every byte ───────────────────────

    /// @dev The profile says every byte outside the anchors is committed. Until
    ///      the token response was tiled that was stated and not enforced, so a
    ///      prover could leave bytes neither revealed nor committed -- bytes the
    ///      notary signed no position for at all.
    function test_rejectsATokenResponseWithAnUncoveredByte() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[0] = _tokenAttestationWithGap();
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }

    /// @dev A token response with one byte belonging to neither list: the
    ///      status line's CRLF is left out of both.
    function _tokenAttestationWithGap() private pure returns (ICeremony.Attestation memory) {
        bytes memory whole =
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=myClient-1&code=abc&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";
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
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    // ─── The token response anchors (REQ-PLAT-57, TEST-PLAT-22) ─────

    /// @dev The bearer is identified by its framing, not by being the only
    ///      commitment: the response hides every other byte behind a commitment
    ///      of its own. With no revealed anchors the committed range is
    ///      indistinguishable from a `refresh_token` value, or any other
    ///      substring the prover chose to commit.
    function test_rejectsATokenResponseWithNoRevealedAnchors() public {
        string memory v = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        ICeremony.Submission memory s = _submission();
        s.attestations[0] = _tokenAttestation("authorization_code", "myClient-1", v, false);
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    // ─── The identity request line (REQ-COMMON-21A) ─────────────────

    /// @dev The path separates operations on the same server, so
    ///      `/2/users/me` must be what was asked. A lookup-by-username endpoint
    ///      would answer for an account the prover never held.
    function test_rejectsAForeignIdentityPath() public {
        ICeremony.Submission memory s = _submission();
        s.attestations[1] = _identityAttestationOnPath("GET /2/users/by/username/victim ");
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
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    /// @dev The authority is what the notary authenticated, not a revealed
    ///      `Host` header, so a transcript from an attacker's server cannot
    ///      substitute for the platform's.
    function test_rejectsAForeignAuthority() public {
        ICeremony.Submission memory s = _submission();
        bytes memory attested = s.attestations[1].attestedData;
        // authorityId is the first 32 bytes: it is the whole header identity
        // now that the stamped tags are gone.
        bytes32 evil = keccak256(bytes("evil.example"));
        for (uint256 i = 0; i < 32; ++i) {
            attested[i] = evil[i];
        }
        s.attestations[1] = ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }
}
