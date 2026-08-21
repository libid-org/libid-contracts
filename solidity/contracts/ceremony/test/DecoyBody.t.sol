// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";

contract OkHonk is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice The real body is COMMITTED and a decoy body is revealed after it.
///         Coverage tiles cleanly, so the direction looks honest.
contract DecoyBodyTest is Test {
    XPlatformVerifier verifier;
    NotaryService notary;
    uint256 quote;

    address constant OWNER = address(0xA11CE);
    uint256 constant KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant T0 = 1_770_000_000;
    bytes32 constant DIGEST = 0xb318fb559e16a179b853ed2853576cda16032d93b0839bb81a55135d334c0af5;
    bytes32 constant NONCE = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    bytes32 constant TOKEN_C = bytes32(uint256(0x1111));
    bytes32 constant ID_C = bytes32(uint256(0x2222));

    function setUp() public {
        vm.warp(T0 + 10);
        NotaryService ni = new NotaryService();
        notary = NotaryService(
            address(new ERC1967Proxy(address(ni), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(KEY), FEE))))
        );
        address honkAddr = address(new OkHonk());
        XPlatformVerifier vi = new XPlatformVerifier();
        verifier = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vi),
                    abi.encodeCall(
                        XPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(notary)), IHonkVerifier(honkAddr), honkAddr.codehash, 3600, 300)
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 10 ether);
    }

    function _sign(bytes memory a) private pure returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(a)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, h);
        return abi.encodePacked(r, s, v);
    }

    /// head revealed | REAL refresh-grant body COMMITTED | decoy body revealed
    function _decoyToken() private pure returns (ICeremony.Attestation memory) {
        bytes memory head = "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\ncontent-length: 90\r\n\r\n";
        bytes memory decoy = abi.encodePacked(
            "grant_type=authorization_code&client_id=trustedApp&code_verifier=",
            CeremonyAuthorization.codeVerifier(DIGEST, NONCE)
        );
        uint32 h = uint32(head.length);
        uint32 r = h + 90; // the real body x.com actually parsed
        uint32 l = r + uint32(decoy.length);

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, end: h, value: head}),
                AttestationBuilder.Range({start: r, end: l, value: decoy})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: h, end: r, value: bytes32(uint256(0xDEC0))})
            ),
            length: l
        });

        bytes memory anchor = '"access_token":"';
        uint32 a0 = 17;
        uint32 a1 = a0 + uint32(anchor.length);
        uint32 b1 = a1 + 20;
        uint32 q1 = b1 + 1;
        AttestationBuilder.Direction memory recv = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: a0, end: a1, value: anchor}),
                AttestationBuilder.Range({start: b1, end: q1, value: '"'})
            ),
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: a1, end: b1, value: TOKEN_C}),
                AttestationBuilder.Commitment({start: q1, end: q1 + 10, value: bytes32(uint256(9))})
            ),
            length: q1 + 10
        });

        bytes memory att = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_X,
            CeremonyProfile.TOKEN_SESSION_TAG,
            CeremonyProfile.AUTHORITY_X_API,
            T0,
            sent,
            recv
        );
        return ICeremony.Attestation({attestedData: att, signature: _sign(att)});
    }

    function _identity() private pure returns (ICeremony.Attestation memory) {
        bytes memory head = "GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n\r\nauthorization: Bearer ";
        bytes memory bearer = "VICTIMBEARERTOKEN";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 s0 = uint32(head.length);
        uint32 e0 = s0 + uint32(bearer.length);
        uint32 l = e0 + uint32(tail.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, end: s0, value: head}),
                AttestationBuilder.Range({start: e0, end: l, value: tail})
            ),
            commitments: AttestationBuilder.one(AttestationBuilder.Commitment({start: s0, end: e0, value: ID_C})),
            length: l
        });
        bytes memory body = '{"data":{"id":"2244994945","username":"victim"}}';
        AttestationBuilder.Direction memory recv = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(
                AttestationBuilder.Range({start: 0, end: uint32(body.length), value: body})
            ),
            commitments: AttestationBuilder.none(),
            length: uint32(body.length)
        });
        bytes memory att = AttestationBuilder.encode(
            CeremonyProfile.FORMAT_TAG,
            CeremonyProfile.PLATFORM_X,
            CeremonyProfile.IDENTITY_SESSION_TAG,
            CeremonyProfile.AUTHORITY_X_API,
            T0,
            sent,
            recv
        );
        return ICeremony.Attestation({attestedData: att, signature: _sign(att)});
    }

    function _submission() private pure returns (ICeremony.Submission memory s) {
        s.platformId = CeremonyProfile.PLATFORM_X;
        s.version = 1;
        s.pkceNonce = NONCE;
        s.proof = hex"00";
        s.publicInputs = new bytes32[](64);
        for (uint256 i = 0; i < 32; ++i) {
            s.publicInputs[i] = bytes32(uint256(uint8(TOKEN_C[i])));
            s.publicInputs[32 + i] = bytes32(uint256(uint8(ID_C[i])));
        }
        s.attestations = new ICeremony.Attestation[](2);
        s.attestations[0] = _decoyToken();
        s.attestations[1] = _identity();
    }

    function run(ICeremony.Submission memory s) external payable returns (ICeremony.PlatformFields memory) {
        return verifier.verify{value: msg.value}(DIGEST, s);
    }

    /// @dev The real body is committed and a decoy is revealed after it.
    ///      Coverage tiles, so the direction looks honest -- but `grant_type`
    ///      and `code_verifier` are read from bytes the platform never parsed.
    function test_aCommittedBodyWithARevealedDecoyIsRejected() public {
        ICeremony.Submission memory s = _submission();
        // Was: returned the victim's userId and handle with the attacker's
        // clientIdentifier, while x.com had executed a refresh grant that no
        // verifier ever read.
        vm.expectPartialRevert(TlsNotaryVerifierBase.WrongTokenRequestLayout.selector);
        this.run{value: quote}(s);
    }
}
