// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";

contract Honk3 is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract LayoutForgeryTest is Test {
    XPlatformVerifier verifier;
    NotaryService notary;
    uint256 quote;

    address constant OWNER = address(0xA11CE);
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant T0 = 1_770_000_000;
    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the fixtures are made for, derived in `setUp` from the
    /// payload below and this chain.
    bytes32 DIGEST;
    bytes32 constant PKCE_NONCE = bytes32(uint256(0x4444));
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
        address honkAddr = address(new Honk3());
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
                            IHonkVerifier(honkAddr),
                            honkAddr.codehash,
                            3600,
                            300,
                            300
                        )
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 100 ether);
    }

    function _sign(bytes memory attested) private pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(attested)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NOTARY_KEY, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// Wholly honest token session. ONE revealed sent range, which is what
    /// `_tokenBody` requires -- two would revert `WrongTokenRequestLayout`
    /// before the identity session this file exists to exercise ever runs.
    function _honestToken() private view returns (ICeremony.Attestation memory) {
        bytes memory v = CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE);
        bytes memory request = abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\n",
            "grant_type=authorization_code&client_id=attackerapp&code=abc&code_verifier=",
            v
        );
        uint32 bodyEnd = uint32(request.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: request})),
            commitments: AttestationBuilder.none(),
            length: bodyEnd
        });

        bytes memory prefix = '"access_token":"';
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;
        // Tiled, like the shape XPlatformVerifier.t.sol proves: the status line
        // revealed at the origin, the CRLF closing it committed, then the
        // framed bearer.
        bytes memory status = "HTTP/1.1 200 OK";
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: status}),
                AttestationBuilder.Range({start: headEnd, value: prefix}),
                AttestationBuilder.Range({start: bearerEnd, value: '"'})
            ),
            commitments: AttestationBuilder.three(
                AttestationBuilder.Commitment({
                    start: uint32(status.length), end: headEnd, value: bytes32(uint256(0x8888))
                }),
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
            ),
            length: total
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    /// The identity session. The SENT side is wholly honest and exactly
    /// covered. The RECEIVED side is a genuine, notary-signed transcript of the
    /// attacker's OWN /2/users/me response -- account id 999, display name set
    /// to the victim's numeric id -- with three ascending, non-overlapping,
    /// in-range reveals chosen so the CONCATENATION reads as the victim.
    function _seamIdentity() private pure returns (AttestationBuilder.Direction memory received) {
        // {"data":{"id":"999","name":"44196397","username":"attacker"}}
        //  0            12            25          37                 61
        AttestationBuilder.Range[] memory rs = new AttestationBuilder.Range[](3);
        rs[0] = AttestationBuilder.Range({start: 0, value: '{"data":{"id'});
        rs[1] = AttestationBuilder.Range({start: 25, value: '":"44196397"'});
        rs[2] = AttestationBuilder.Range({start: 37, value: ',"username":"attacker"}}'});
        received = AttestationBuilder.Direction({revealed: rs, commitments: AttestationBuilder.none(), length: 61});
    }

    function _identity(AttestationBuilder.Direction memory received)
        private
        view
        returns (ICeremony.Attestation memory)
    {
        bytes memory head = abi.encodePacked(
            "GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n", "\r\nauthorization: Bearer "
        );
        bytes memory bearer = "TOKENTOKENTOKEN";
        bytes memory tail = "\r\n\r\n";
        uint32 bstart = uint32(head.length);
        uint32 bend = bstart + uint32(bearer.length);
        uint32 sentLen = bend + uint32(tail.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: bend, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: bstart, end: bend, value: IDENTITY_COMMITMENT})
            ),
            length: sentLen
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    function _submission() private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.pkceNonce = PKCE_NONCE;
        s.proof = hex"00";
    }

    function run(TlsNotaryVerifierBase.TlsNotaryProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    /// A response whose revealed ranges are spliced must not read as a document.
    ///
    /// @dev Was: returned userId 44196397, spliced out of the display name,
    ///      while the account's real id is 999. Reading fields from a
    ///      CONCATENATION of revealed ranges discarded every offset, so
    ///      disjoint fragments joined into a document that never existed on the
    ///      wire -- and the duplicate-delimiter check had nothing to fire on,
    ///      because the genuine member was not in the buffer at all.
    ///
    ///      COVERAGE is what closes it, and that is worth being exact about.
    ///      The fragments have to be disjoint for the splice to say anything
    ///      new, and disjoint means a gap -- which `requireExactCoverage`
    ///      refuses before any reader runs. The per-range read is the second
    ///      line, for a TILED response whose members sit in different ranges;
    ///      `XPlatformVerifier.t.sol` proves that one, because it cannot be
    ///      reached from here.
    function test_aSplicedResponseCannotForgeAnIdentity() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _submission();
        s.tokenSession = _honestToken();
        s.identitySession = _identity(_seamIdentity());
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }

    /// Finding 4(1): revealed range INDEX 0 need not start at transcript
    /// offset 0. The real request line is hidden; a header value the prover
    /// composed begins with `POST /2/oauth2/token ` and is the first revealed
    /// range, and a second planted header value is read as "the body".
    function _unanchoredToken() private view returns (ICeremony.Attestation memory) {
        bytes memory v = CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE);
        bytes memory fakeLine = "POST /2/oauth2/token HTTP/1.1";
        bytes memory fakeBody = abi.encodePacked("grant_type=authorization_code&client_id=victimapp&code_verifier=", v);
        uint32 s1 = 400; // deep inside the transcript, nowhere near offset 0
        uint32 e1 = s1 + uint32(fakeLine.length);
        uint32 s2 = e1 + 9;
        uint32 e2 = s2 + uint32(fakeBody.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: s1, value: fakeLine}),
                AttestationBuilder.Range({start: s2, value: fakeBody})
            ),
            commitments: AttestationBuilder.none(),
            length: e2 + 300
        });
        bytes memory prefix = '"access_token":"';
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: headEnd, value: prefix}),
                AttestationBuilder.Range({start: bearerEnd, value: '"'})
            ),
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
            ),
            length: total
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function _honestIdentityRecv() private pure returns (AttestationBuilder.Direction memory received) {
        bytes memory body = '{"data":{"id":"2244994945","username":"alice"}}';
        received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: body})),
            commitments: AttestationBuilder.none(),
            length: uint32(body.length)
        });
    }

    /// The request line must BEGIN the transcript, not merely be listed first.
    function test_aPlantedRequestLineIsRejected() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _submission();
        s.tokenSession = _unanchoredToken();
        s.identitySession = _identity(_honestIdentityRecv());
        // Was: returned clientIdentifier "victimapp", read out of a header value
        // the prover composed at offset 400. Range INDEX 0 is not range OFFSET
        // 0, and nothing tiled this direction, so both the request line and the
        // body were prover-typed text. Coverage fires first: the 400 bytes
        // before the first revealed range are covered by nothing at all.
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }
}
