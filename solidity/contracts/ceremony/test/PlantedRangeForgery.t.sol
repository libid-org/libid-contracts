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
import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";

contract Honk2 is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract PlantedRangeForgeryTest is Test {
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
        address honkAddr = address(new Honk2());
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

    function _tokenResponse() private pure returns (AttestationBuilder.Direction memory received) {
        bytes memory prefix = '"access_token":"';
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;
        received = AttestationBuilder.Direction({
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
    }

    /// A GENUINE refresh-token exchange to api.x.com. Offset 0 really is
    /// `POST /2/oauth2/token HTTP/1.1`, and the prover reveals it honestly.
    /// The prover added one header of its own choosing to the request it sent;
    /// X ignores it. That header's value is the only other revealed range.
    /// The real body -- grant_type=refresh_token -- is revealed to nobody.
    function _plantedHeaderToken() private view returns (ICeremony.Attestation memory) {
        bytes memory v = CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE);

        //  0: "POST /2/oauth2/token HTTP/1.1\r\n"          (31 bytes)
        // 31: "x-pad: " (7)                                -> planted value at 38
        bytes memory line = "POST /2/oauth2/token ";
        bytes memory planted = abi.encodePacked("grant_type=authorization_code&client_id=trustedApp&code_verifier=", v);
        uint32 plantedStart = 38;
        uint32 plantedEnd = plantedStart + uint32(planted.length);
        // headers + the REAL refresh-grant body follow, and stay hidden.
        uint32 total = plantedEnd + 200;

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: line}),
                AttestationBuilder.Range({start: plantedStart, value: planted})
            ),
            commitments: AttestationBuilder.none(),
            length: total
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse());
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function _honestIdentity() private view returns (ICeremony.Attestation memory) {
        bytes memory head =
            abi.encodePacked("GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n", "\r\nauthorization: Bearer ");
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
        bytes memory body = abi.encodePacked('HTTP/1.1 200 OK\r\n\r\n{"id":"2244994945","username":"alice"}');
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

    function _base() private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
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

    /// Finding 2, the realistic shape: honest request line at offset 0, real
    /// body never revealed, planted header value read as "the body".
    /// A refresh grant dressed up with a planted header must not verify.
    function test_aPlantedTokenRequestIsRejected() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _base();
        s.tokenSession = _plantedHeaderToken();
        s.identitySession = _honestIdentity();
        // Was: accepted a refresh grant. The compared `grant_type` came from a
        // planted header value, not from the body X actually answered.
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }

    /// Finding 4: a notary that reveals ONE FIELD PER RANGE, as the spec's
    /// section 5.2 table lists them, is rejected.
    function _perFieldToken() private view returns (ICeremony.Attestation memory) {
        bytes memory v = CeremonyAuthorization.codeVerifier(DIGEST, PKCE_NONCE);
        bytes memory line = "POST /2/oauth2/token ";
        bytes memory f1 = "grant_type=authorization_code";
        bytes memory f2 = "client_id=realapp";
        bytes memory f3 = abi.encodePacked("code_verifier=", v);
        uint32 s1 = 100;
        uint32 e1 = s1 + uint32(f1.length);
        uint32 s2 = e1 + 1; // the `&` between them is not a revealed range
        uint32 e2 = s2 + uint32(f2.length);
        uint32 s3 = e2 + 1;
        uint32 e3 = s3 + uint32(f3.length);

        AttestationBuilder.Range[] memory rs = new AttestationBuilder.Range[](4);
        rs[0] = AttestationBuilder.Range({start: 0, value: line});
        rs[1] = AttestationBuilder.Range({start: s1, value: f1});
        rs[2] = AttestationBuilder.Range({start: s2, value: f2});
        rs[3] = AttestationBuilder.Range({start: s3, value: f3});

        AttestationBuilder.Direction memory sent =
            AttestationBuilder.Direction({revealed: rs, commitments: AttestationBuilder.none(), length: e3});
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse());
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function test_skeptic2_perFieldLayoutIsRejected() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _base();
        s.tokenSession = _perFieldToken();
        s.identitySession = _honestIdentity();
        vm.expectRevert();
        this.run{value: quote}(s);
    }

    /// Finding 7: the empty handle never reaches a node -- normalize reverts.
    function test_skeptic2_emptyHandleReverts() public {
        HandleNormalizer.Rules memory google = HandleNormalizer.Rules({
            maxLength: 254, stripLeadingAt: false, isEmail: true, allowUnderscore: true, allowHyphen: true
        });
        vm.expectRevert(HandleNormalizer.EmptyHandle.selector);
        this.normalizeExternal("", google);
    }

    function normalizeExternal(string memory raw, HandleNormalizer.Rules memory rules)
        external
        pure
        returns (string memory)
    {
        return HandleNormalizer.normalize(raw, rules);
    }
}
