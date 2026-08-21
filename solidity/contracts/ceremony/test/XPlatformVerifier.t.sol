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
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, end: wholeEnd, value: whole})),
            commitments: AttestationBuilder.none(),
            length: wholeEnd
        });
        // A real token response: the bearer committed and framed by the
        // revealed `"access_token":"` delimiter and its closing quote, with
        // every other byte hidden behind a commitment of its own.
        received = _tokenResponse(bearerFraming);

        bytes memory attested = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_X,
            CeremonyProfile.TOKEN_SESSION_TAG,
            CeremonyProfile.AUTHORITY_X_API,
            T0,
            sent,
            received
        );
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    /// A token response shaped like the real one:
    ///   [0,17)  hidden status line and headers, behind their own commitment
    ///   [17,33) revealed `"access_token":"`
    ///   [33,45) the committed bearer
    ///   [45,46) revealed closing quote
    ///   [46,70) the rest of the JSON, behind another commitment
    function _tokenResponse(bool framed) private pure returns (AttestationBuilder.Direction memory received) {
        bytes memory prefix = '"access_token":"';
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;

        AttestationBuilder.Range[] memory revealed;
        if (framed) {
            revealed = AttestationBuilder.two(
                AttestationBuilder.Range({start: headEnd, end: prefixEnd, value: prefix}),
                AttestationBuilder.Range({start: bearerEnd, end: quoteEnd, value: '"'})
            );
        } else {
            // Nothing revealed at all — the shape REQ-PLAT-57 refuses, because
            // the committed range could equally be a `refresh_token` value.
            revealed = new AttestationBuilder.Range[](0);
        }

        received = AttestationBuilder.Direction({
            revealed: revealed,
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
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
                AttestationBuilder.Range({start: 0, end: start, value: head}),
                AttestationBuilder.Range({start: end, end: sentLen, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: sentLen
        });

        bytes memory body = abi.encodePacked('"id":"', idValue, '","username":"', username, '"');
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(
                AttestationBuilder.Range({start: 0, end: uint32(body.length), value: body})
            ),
            commitments: AttestationBuilder.none(),
            length: uint32(body.length)
        });

        bytes memory attested = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_X,
            CeremonyProfile.IDENTITY_SESSION_TAG,
            CeremonyProfile.AUTHORITY_X_API,
            T0,
            sent,
            received
        );
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    /// Public inputs are the two commitments, one byte per field element.
    function _publicInputs() private pure returns (bytes32[] memory pi) {
        pi = new bytes32[](64);
        for (uint256 i = 0; i < 32; ++i) {
            pi[i] = bytes32(uint256(uint8(TOKEN_COMMITMENT[i])));
            pi[32 + i] = bytes32(uint256(uint8(IDENTITY_COMMITMENT[i])));
        }
    }

    function _submission() private view returns (ICeremony.Submission memory s) {
        string memory verifierValue = string(CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE));
        s.platformId = CeremonyProfile.PLATFORM_X;
        s.version = 1;
        s.pkceNonce = PKCE_NONCE;
        s.proof = hex"00";
        s.publicInputs = _publicInputs();
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
        assertEq(f.metadataObservedAt, T0);
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

    /// @dev Two attestations of one ceremony differing only in which session
    ///      they came from would otherwise be interchangeable.
    function test_rejectsTheTwoSessionsSwapped() public {
        ICeremony.Submission memory s = _submission();
        (s.attestations[0], s.attestations[1]) = (s.attestations[1], s.attestations[0]);
        vm.expectPartialRevert(PlatformVerifierBase.WrongOperationTag.selector);
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

    /// @dev Without this the circuit could prove a link between two
    ///      attestations other than the ones submitted (REQ-PLAT-32C).
    function test_rejectsAProofLinkingOtherAttestations() public {
        ICeremony.Submission memory s = _submission();
        s.publicInputs[40] = bytes32(uint256(0xff));
        vm.expectPartialRevert(TlsNotaryVerifierBase.CommitmentMismatch.selector);
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

    /// @dev Governance-owned, read at verification time, with no caller
    ///      substitute (REQ-PARAM-02).
    function test_loweringTheLifetimeRejectsAnOutstandingProof() public {
        vm.warp(T0 + 100);
        this.run{value: quote}(_submission());

        vm.prank(OWNER);
        verifier.setProtocolParameters(50, SKEW);
        ICeremony.Submission memory s = _submission();
        vm.expectPartialRevert(PlatformVerifierBase.ProofExpired.selector);
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
        bytes memory first = '{"id":"2244994945","usern';
        bytes memory second = 'ame":"mallory"}';
        return _splitIdentityAttestation(first, second);
    }

    /// @dev An identity response whose two revealed ranges each carry a whole
    ///      `username` member. The ranges still tile the signed length, so
    ///      nothing but the cross-range count rejects it.
    function _identityAttestationSplitAcrossRanges() private pure returns (ICeremony.Attestation memory) {
        return _splitIdentityAttestation('{"id":"2244994945","username":"alice"', ',"username":"mallory"}');
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
                AttestationBuilder.Range({start: 0, end: start, value: head}),
                AttestationBuilder.Range({start: end, end: sentLen, value: tail})
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
                AttestationBuilder.Range({start: 0, end: split, value: first}),
                AttestationBuilder.Range({start: split, end: recvLen, value: second})
            ),
            commitments: AttestationBuilder.none(),
            length: recvLen
        });

        bytes memory attested = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_X,
            CeremonyProfile.IDENTITY_SESSION_TAG,
            CeremonyProfile.AUTHORITY_X_API,
            T0,
            sent,
            received
        );
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

    /// @dev And the framing must land on the range the circuit opened. Here the
    ///      anchors are present but the proof names the OTHER committed range —
    ///      which is what committing a `refresh_token` value and proving over
    ///      it would look like.
    function test_rejectsAProofOverTheWrongCommittedRange() public {
        ICeremony.Submission memory s = _submission();
        bytes32 other = bytes32(uint256(0x9999));
        for (uint256 i = 0; i < 32; ++i) {
            s.publicInputs[i] = bytes32(uint256(uint8(other[i])));
        }
        vm.expectPartialRevert(TlsNotaryVerifierBase.CommitmentMismatch.selector);
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
                AttestationBuilder.Range({start: 0, end: start, value: head}),
                AttestationBuilder.Range({start: end, end: sentLen, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: sentLen
        });
        bytes memory body = '"id":"2244994945","username":"alice"';
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(
                AttestationBuilder.Range({start: 0, end: uint32(body.length), value: body})
            ),
            commitments: AttestationBuilder.none(),
            length: uint32(body.length)
        });
        bytes memory attested = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_X,
            CeremonyProfile.IDENTITY_SESSION_TAG,
            CeremonyProfile.AUTHORITY_X_API,
            T0,
            sent,
            received
        );
        return ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
    }

    /// @dev The authority is what the notary authenticated, not a revealed
    ///      `Host` header, so a transcript from an attacker's server cannot
    ///      substitute for the platform's.
    function test_rejectsAForeignAuthority() public {
        ICeremony.Submission memory s = _submission();
        bytes memory attested = s.attestations[1].attestedData;
        // authorityId sits at bytes 96..128 of the header.
        bytes32 evil = keccak256(bytes("evil.example"));
        for (uint256 i = 0; i < 32; ++i) {
            attested[96 + i] = evil[i];
        }
        s.attestations[1] = ICeremony.Attestation({attestedData: attested, signature: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }
}
