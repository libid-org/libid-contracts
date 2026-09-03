// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";

/// A reading of Google's JWKS that actually crossed the wire.
///
/// `GoogleJwtRoots.t.sol` builds its sessions: the request is a constant, the
/// response is framed by the test, and the notary is `vm.sign`. Every byte
/// there is one a test author chose. This file starts from the other end: the
/// fixture is a genuine MPC-TLS session with www.googleapis.com, captured on
/// 2026-09-03 by libid-org/notary's `examples/notarize_jwks.rs` through a notary signing
/// with anvil #0, and nothing in it was written by hand -- the request line is
/// what the keeper's prover put on the wire, the head is what Google's front
/// end answered, the framing is Google's, the key set is the one Google
/// published that minute, and the signature is the notary's own.
///
/// So the positive test here is the deployment's real path end to end, and
/// the negative ones are what a cheat has to do to a real record: change a
/// byte, borrow a signature, wait too long, or re-sign an edited request with
/// a key the service does trust.
contract GoogleJwtRootsRealSessionTest is Test {
    GoogleJwtRoots roots;
    NotaryService notary;

    address constant OWNER = address(0xA11CE);
    uint256 constant FEE = 0.001 ether;
    /// anvil #0: the key the notary that produced the fixture signed with.
    uint256 constant ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    /// A second key the service trusts, for the variants that re-sign the
    /// real bytes. Distinct from anvil #0 so a variant that passes is seen to
    /// pass on the strength of the service's trust, not the fixture's.
    uint256 constant TEST_KEY = 0x7E57;
    uint256 constant STRANGER_KEY = 0xB0B;

    string constant SESSION = "contracts/ceremony/test/fixtures/google-jwks-session.json";
    bytes constant REQUEST_LINE = "GET /oauth2/v3/certs HTTP/1.1\r\n";
    bytes constant HEAD_BOUNDARY = "\r\n\r\n";
    uint256 constant NONE = type(uint256).max;

    /// The record and its signature, exactly as the notary emitted them.
    bytes record;
    bytes signature;
    /// The record's `createdAt`, from the fixture's own field.
    uint64 createdAt;
    /// Who the fixture says signed.
    address signer;

    function setUp() public {
        string memory json = vm.readFile(SESSION);
        record = vm.parseJsonBytes(json, ".attested_data");
        signature = vm.parseJsonBytes(json, ".notary_signature");
        createdAt = uint64(vm.parseJsonUint(json, ".created_at"));
        signer = vm.parseJsonAddress(json, ".notary");

        // A minute after the notary's clock: inside the freshness window,
        // outside the clock-skew grace, the way a keeper's submission lands.
        vm.warp(createdAt + 60);

        NotaryService impl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(ANVIL_KEY), FEE))
                )
            )
        );
        vm.prank(OWNER);
        notary.setNotary(vm.addr(TEST_KEY), true);
        roots = _deployRoots();

        vm.deal(address(this), 1 ether);
    }

    function _deployRoots() private returns (GoogleJwtRoots) {
        GoogleJwtRoots impl = new GoogleJwtRoots();
        return GoogleJwtRoots(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(GoogleJwtRoots.initialize, (OWNER, INotaryService(address(notary))))
                )
            )
        );
    }

    /// The four kids Google served in the fixture. Asserted against the body
    /// below, so this list cannot drift from the record it describes.
    function _kids() private pure returns (string[] memory kids) {
        kids = new string[](4);
        kids[0] = "d6a0e659c3392d9e592a4b0ad88e7b2b88076909";
        kids[1] = "a8f80b512469959cdc1eeba44b066c2f79944779";
        kids[2] = "943a3a5d7d919625a454e489b75c29adab57acba";
        kids[3] = "f10f87405a979c1df36df26606734f33cd85c271";
    }

    // ─── What the fixture is ────────────────────────────────────────

    /// The record is the JWKS session layout, signed by the key the fixture
    /// names, and its bytes sit where the section 9.1 layout fixes them: the
    /// sent direction's first revealed range begins at 48 + 8 + 4 + 8 = 68,
    /// the received one at 68 + 136 + 8 + 8 + 4 + 8 = 232.
    function test_theRecordIsTheSessionTheFixtureDescribes() public view {
        assertEq(signer, vm.addr(ANVIL_KEY), "the fixture was signed by anvil #0");
        assertEq(record.length, 2811);
        assertEq(signature.length, 65);

        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(keccak256(record));
        assertEq(ECDSA.recover(ethHash, signature), signer, "the signature is over these exact bytes");

        CeremonyAttestation.AttestedData memory data = this.decode(record);
        assertEq(data.authorityId, roots.AUTHORITY(), "the notary authenticated www.googleapis.com");
        assertEq(data.createdAt, createdAt, "bytes 32..40 are the fixture's created_at");
        assertEq(data.sentTranscriptLength, 136);
        assertEq(data.recvTranscriptLength, 2571);

        // The JWKS layout: everything revealed, nothing committed, in both
        // directions -- what lets the contract read each join as the wire.
        assertEq(data.sent.revealed.length, 1);
        assertEq(data.sent.revealed[0].start, 0);
        assertEq(data.sent.revealed[0].end, 136);
        assertEq(data.sent.commitments.length, 0);
        assertEq(data.received.revealed.length, 1);
        assertEq(data.received.revealed[0].start, 0);
        assertEq(data.received.revealed[0].end, 2571);
        assertEq(data.received.commitments.length, 0);

        assertEq(_slice(record, 68, 68 + REQUEST_LINE.length), REQUEST_LINE, "the request begins at byte 68");
        assertEq(_slice(record, 232, 232 + 17), bytes("HTTP/1.1 200 OK\r\n"), "the response begins at byte 232");
    }

    /// The libid-rs origin-form fix, proven on the wire: hyper writes the
    /// request-target as the URI displays, and the prover was handed an
    /// absolute one, so without the rewrite this line would read
    /// `GET https://www.googleapis.com/oauth2/v3/certs HTTP/1.1` and every
    /// verifier would refuse it.
    function test_theRealRequestLineIsOriginForm() public view {
        bytes memory sent = this.decode(record).sent.revealed[0].value;
        assertTrue(_startsWith(sent, REQUEST_LINE), "origin-form request line");
        assertEq(_indexOf(sent, "://", 0), NONE, "an absolute-form target would carry a scheme");

        bytes memory rest = _slice(sent, REQUEST_LINE.length, sent.length);
        assertTrue(_startsWith(rest, "host: www.googleapis.com\r\n"), "the Host the contract pins, right after it");
        assertEq(_count(sent, "\r\nhost:"), 1, "one Host header");
        assertTrue(_endsWith(sent, HEAD_BOUNDARY), "a head and no body");
    }

    /// Google framed the body chunked, with capitalised field names -- the
    /// builder-made sessions write them lowercase, so this is the one place
    /// the head normalisation is tested against a head a server wrote. One
    /// chunk of 0x7ff bytes, then the terminator, no trailers.
    function test_googleFramedTheBodyChunked() public view {
        bytes memory received = this.decode(record).received.revealed[0].value;
        bytes memory head = _head(received);
        bytes memory body = _afterHead(received);

        assertTrue(_startsWith(head, "HTTP/1.1 200 OK\r\n"));
        assertTrue(_contains(head, "\r\nTransfer-Encoding: chunked\r\n"), "chunked, capitalised as Google writes it");
        assertTrue(_contains(head, "\r\nContent-Type: application/json; charset=UTF-8\r\n"));
        assertTrue(_contains(head, "\r\nConnection: close\r\n"));

        bytes memory normalized = CeremonyAttestation.normalizeHeaderBytes(head);
        assertEq(_count(normalized, "\r\ntransfer-encoding:chunked\r\n"), 1, "the needle the contract counts");
        assertEq(_count(normalized, "\r\ncontent-length:"), 0, "no length alongside the coding");

        assertTrue(_startsWith(body, "7ff\r\n"), "one chunk of 2047 bytes");
        assertTrue(_endsWith(body, "\r\n0\r\n\r\n"), "the terminator, no trailers");
        bytes memory json = _dechunk(body);
        assertEq(json.length, 0x7ff);
        assertTrue(_startsWith(json, "{\n  \"keys\": ["), "Google's pretty-printed key set");
    }

    /// The builder used to forge variants below reproduces the real record
    /// byte for byte, so a variant differs from the wire in exactly the edit
    /// it makes and nothing else.
    function test_theBuilderReproducesTheRealRecordByteForByte() public view {
        CeremonyAttestation.AttestedData memory data = this.decode(record);
        bytes memory rebuilt = AttestationBuilder.encode(
            data.authorityId,
            data.createdAt,
            _whole(data.sent.revealed[0].value),
            _whole(data.received.revealed[0].value)
        );
        assertEq(rebuilt, record);
    }

    // ─── The real rotation ──────────────────────────────────────────

    /// The real bytes, the real signature, a real Notary Service trusting the
    /// key that signed: every kid Google published that minute is installed
    /// as the current generation, trusted for the lifetime from the notary's
    /// clock, and the fee lands where every other attestation's does.
    function test_theRealReadingInstallsEveryKidGoogleServed() public {
        vm.recordLogs();
        roots.rotate{value: FEE}(record, signature);

        bytes memory json = _realBody();
        string[] memory kids = _kids();
        assertEq(_count(json, "\"kid\""), kids.length, "the list above names every kid in the body");
        for (uint256 i = 0; i < kids.length; ++i) {
            assertTrue(_contains(json, abi.encodePacked("\"kid\": \"", kids[i], "\"")), "kid is in the body");
        }

        // The rotation announces the reading's keys in the order Google
        // listed them, so the event is what ties each kid to its modulus.
        (uint64 observedAt, string[] memory announced, bytes32[] memory moduli) = _rotation();
        assertEq(observedAt, createdAt, "stamped with the notary's clock");
        assertEq(announced, kids, "every kid, in the fixture's order");
        assertEq(moduli.length, kids.length);
        uint256 stamp = createdAt + roots.READING_LIFETIME();
        for (uint256 i = 0; i < moduli.length; ++i) {
            assertTrue(moduli[i] != bytes32(0), "kid installed");
            assertEq(roots.trustedHashExpiresAt(moduli[i]), stamp, "trusted for the lifetime, from the reading's clock");
            for (uint256 j = 0; j < i; ++j) {
                assertTrue(moduli[i] != moduli[j], "four distinct keys");
            }
        }

        (GoogleJwtRoots.Generation memory current, GoogleJwtRoots.Generation memory previous) = roots.currentKeys();
        assertEq(current.observedAt, createdAt);
        assertEq(current.moduli, moduli, "four moduli, in the fixture's order");
        assertEq(previous.moduli.length, 0, "nothing precedes the first reading");
        assertFalse(roots.needsRotation());
        assertEq(roots.freshestObservedAt(), createdAt);
        assertEq(address(notary).balance, FEE, "the fee reached the Notary Service");
        assertEq(address(roots).balance, 0);
    }

    /// The same body, re-read under `Content-Length` by a different trusted
    /// notary, installs identical modulus hashes on a fresh list: the framing
    /// and the signer are transparent to what gets written, which is the
    /// keeper's own limb hash of the bytes Google sent.
    function test_theSameBodyUnderContentLengthYieldsTheSameKeys() public {
        roots.rotate{value: FEE}(record, signature);

        CeremonyAttestation.AttestedData memory data = this.decode(record);
        bytes memory json = _realBody();
        bytes memory response = abi.encodePacked(
            "HTTP/1.1 200 OK\r\n",
            "content-type: application/json; charset=UTF-8\r\n",
            "content-length: ",
            vm.toString(json.length),
            "\r\n\r\n",
            json
        );
        bytes memory reread = AttestationBuilder.encode(
            data.authorityId, data.createdAt, _whole(data.sent.revealed[0].value), _whole(response)
        );

        GoogleJwtRoots again = _deployRoots();
        again.rotate{value: FEE}(reread, _signWith(TEST_KEY, reread));

        (GoogleJwtRoots.Generation memory viaChunked,) = roots.currentKeys();
        (GoogleJwtRoots.Generation memory viaLength,) = again.currentKeys();
        assertEq(viaLength.moduli.length, _kids().length);
        assertEq(viaLength.moduli, viaChunked.moduli, "framing changed the key");
    }

    // ─── The ways to cheat with it ──────────────────────────────────
    //
    // Two kinds of surgery. Where the point is that no byte may change, the
    // edit is made on the raw record at the offset the layout fixes, so the
    // signature is checked against exactly what the notary signed minus one
    // bit. Where the point is that the CONTENT is refused even under a good
    // signature, the record is decoded with `CeremonyAttestation`, the
    // request bytes are edited, and the result is re-encoded with
    // `AttestationBuilder` and re-signed -- legitimate because the builder
    // reproduces the real record byte for byte (see above), so the forged
    // record differs from the wire in the edit alone.

    /// One bit inside the first modulus. The signature is the notary's and the
    /// key is trusted, but the digest the service derives is of these bytes,
    /// so recovery lands on a key nobody trusts -- and the test names which.
    function test_aFlippedByteIsRefusedThoughTheSignatureIsGenuine() public {
        bytes memory tampered = record;
        uint256 at = _indexOf(tampered, "\"n\": \"", 0) + 10;
        tampered[at] = bytes1(uint8(tampered[at]) ^ 0x01);

        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(keccak256(tampered));
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethHash, signature);
        assertEq(uint8(err), uint8(ECDSA.RecoverError.NoError), "a well-formed signature still recovers to someone");
        assertTrue(recovered != signer, "just not to the notary");

        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, recovered));
        roots.rotate{value: FEE}(tampered, signature);
    }

    /// The real bytes, signed by someone the service never trusted.
    function test_aStrangersSignatureOverTheRealBytesIsRefused() public {
        bytes memory sig = _signWith(STRANGER_KEY, record);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(STRANGER_KEY)));
        roots.rotate{value: FEE}(record, sig);
    }

    /// Genuine, and too old: past the window the reading says nothing about
    /// what Google publishes now. The boundary itself is still inside.
    function test_theRealReadingIsRefusedPastItsWindow() public {
        uint256 window = roots.FRESHNESS_WINDOW();

        vm.warp(createdAt + window + 1);
        vm.expectRevert(GoogleJwtRoots.StaleProof.selector);
        roots.rotate{value: FEE}(record, signature);

        vm.warp(createdAt + window);
        roots.rotate{value: FEE}(record, signature);
        (GoogleJwtRoots.Generation memory current,) = roots.currentKeys();
        assertEq(current.moduli.length, 4);
    }

    /// The real request with a second `Host` smuggled in behind a bare LF --
    /// the line Google's front end honours and a CRLF-anchored count cannot
    /// see -- re-signed by a key the service DOES trust. The signature is
    /// good; the request is refused before any header is counted, at the
    /// offset of the LF: 31 bytes of request line, then `x-a: b`.
    function test_aSmuggledHostReSignedByATrustedKeyIsRefused() public {
        assertTrue(notary.isTrustedNotary(vm.addr(TEST_KEY)), "the forger holds a trusted key");

        CeremonyAttestation.AttestedData memory data = this.decode(record);
        bytes memory sent = data.sent.revealed[0].value;
        bytes memory smuggled = abi.encodePacked(
            _slice(sent, 0, REQUEST_LINE.length),
            "x-a: b\nhost: storage.googleapis.com\r\n",
            _slice(sent, REQUEST_LINE.length, sent.length)
        );
        bytes memory forged = AttestationBuilder.encode(
            data.authorityId, data.createdAt, _whole(smuggled), _whole(data.received.revealed[0].value)
        );
        bytes memory sig = _signWith(TEST_KEY, forged);

        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.BareLineFeed.selector, REQUEST_LINE.length + 6));
        roots.rotate{value: FEE}(forged, sig);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// `CeremonyAttestation.decode` reads calldata, so the record goes out
    /// through an external call to come back decoded.
    function decode(bytes calldata data) external pure returns (CeremonyAttestation.AttestedData memory) {
        return CeremonyAttestation.decode(data);
    }

    /// Google's key set as the contract reads it: the received direction past
    /// the head, de-chunked.
    function _realBody() private view returns (bytes memory) {
        return _dechunk(_afterHead(this.decode(record).received.revealed[0].value));
    }

    /// The one `KeysRotated` among the recorded logs, decoded.
    function _rotation() private returns (uint64 observedAt, string[] memory kids, bytes32[] memory moduli) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("KeysRotated(uint64,string[],bytes32[])");
        uint256 seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(roots) || logs[i].topics[0] != topic) continue;
            ++seen;
            (observedAt, kids, moduli) = abi.decode(logs[i].data, (uint64, string[], bytes32[]));
        }
        assertEq(seen, 1, "one KeysRotated per rotation");
    }

    function _signWith(uint256 key, bytes memory attested) private pure returns (bytes memory) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(keccak256(attested));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// The JWKS layout: one revealed range covering the whole direction,
    /// nothing committed.
    function _whole(bytes memory transcript) private pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: transcript})),
            commitments: AttestationBuilder.none(),
            length: uint32(transcript.length)
        });
    }

    function _head(bytes memory message) private pure returns (bytes memory) {
        uint256 boundary = _indexOf(message, HEAD_BOUNDARY, 0);
        assertTrue(boundary != NONE, "no head boundary");
        return _slice(message, 0, boundary + 2);
    }

    function _afterHead(bytes memory message) private pure returns (bytes memory) {
        uint256 boundary = _indexOf(message, HEAD_BOUNDARY, 0);
        assertTrue(boundary != NONE, "no head boundary");
        return _slice(message, boundary + 4, message.length);
    }

    /// A strict test-side de-chunker: hex size, CRLF, data, CRLF; a zero
    /// size followed by CRLF and nothing more ends it.
    function _dechunk(bytes memory chunked) private pure returns (bytes memory out) {
        uint256 at;
        while (true) {
            uint256 size;
            uint256 lineEnd = _indexOf(chunked, "\r\n", at);
            assertTrue(lineEnd != NONE && lineEnd > at, "chunk size line");
            for (; at < lineEnd; ++at) {
                uint8 c = uint8(chunked[at]);
                uint256 nibble = c <= 0x39 ? c - 0x30 : (c | 0x20) - 0x61 + 10;
                size = (size << 4) | nibble;
            }
            at += 2;
            if (size == 0) {
                assertEq(chunked.length - at, 2, "no trailers");
                return out;
            }
            out = abi.encodePacked(out, _slice(chunked, at, at + size));
            at += size;
            assertEq(_slice(chunked, at, at + 2), bytes("\r\n"), "CRLF after chunk data");
            at += 2;
        }
    }

    function _count(bytes memory haystack, bytes memory needle) private pure returns (uint256 count) {
        for (uint256 at = _indexOf(haystack, needle, 0); at != NONE; at = _indexOf(haystack, needle, at + 1)) {
            ++count;
        }
    }

    function _contains(bytes memory haystack, bytes memory needle) private pure returns (bool) {
        return _indexOf(haystack, needle, 0) != NONE;
    }

    function _indexOf(bytes memory haystack, bytes memory needle, uint256 from) private pure returns (uint256) {
        for (uint256 i = from; i + needle.length <= haystack.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) return i;
        }
        return NONE;
    }

    function _startsWith(bytes memory data, bytes memory prefix) private pure returns (bool) {
        return data.length >= prefix.length && keccak256(_slice(data, 0, prefix.length)) == keccak256(prefix);
    }

    function _endsWith(bytes memory data, bytes memory suffix) private pure returns (bool) {
        return data.length >= suffix.length
            && keccak256(_slice(data, data.length - suffix.length, data.length)) == keccak256(suffix);
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }
}
