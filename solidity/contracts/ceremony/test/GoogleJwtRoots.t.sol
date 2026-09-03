// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";

/// `_splitLimbs` is internal so the hash a reading will write can be computed
/// test-side, independent of the list's state: a key's hash is asserted from
/// its bytes, never read back from the contract that wrote it.
contract LimbHasher is GoogleJwtRoots {
    function hashOf(bytes memory modulus) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_splitLimbs(modulus)));
    }

    function hashOfB64url(string memory modulus) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_splitLimbs(_b64urlDecode(bytes(modulus)))));
    }
}

/// The `google/v1` profile's trust list, fed by a notarized reading of
/// Google's JWKS endpoint.
///
/// The reading is an ordinary section 9.1 session: built with the same
/// builder every Platform Verifier test uses, signed at test time by the anvil
/// key, and authenticated by a real NotaryService behind a proxy charging a
/// real fee. Nothing here mocks the thing under test. Google's real body rides
/// along as a fixture, so the parser is tested against the document it will
/// read rather than a shape a test author remembered.
contract GoogleJwtRootsTest is Test {
    GoogleJwtRoots roots;
    NotaryService notary;
    LimbHasher hasher;

    address constant OWNER = address(0xA11CE);
    address keeper = makeAddr("keeper");
    /// The anvil key.
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant T0 = 1_770_000_000;
    bytes32 constant AUTHORITY = keccak256("www.googleapis.com");

    /// Google's real body, fetched 2026-09-03: pretty-printed, two keys.
    string constant GOOGLE_JWKS = "contracts/ceremony/test/fixtures/google-jwks.json";
    string constant GOOGLE_KID_1 = "943a3a5d7d919625a454e489b75c29adab57acba";
    string constant GOOGLE_KID_2 = "f10f87405a979c1df36df26606734f33cd85c271";

    /// The keeper's limb-hash vector. `decision::modulus_hash` in the keeper
    /// and `_splitLimbs` here must agree on this one, or a key the keeper
    /// reports as trusted is one the verifier refuses.
    string constant KEEPER_MODULUS =
        "BAsSGSAnLjU8Q0pRWF9mbXR7gomQl56lrLO6wcjP1t3k6_L5BQwTGiEoLzY9REtSWWBnbnV8g4qRmJ-mrbS7wsnQ197l7PP6Bg0UGyIpMDc-RUxTWmFob3Z9hIuSmaCnrrW8w8rR2N_m7fT7Bw4VHCMqMTg_Rk1UW2JpcHd-hYyTmqGor7a9xMvS2eDn7vUBCA8WHSQrMjlAR05VXGNqcXh_ho2Um6KpsLe-xczT2uHo7_YCCRAXHiUsMzpBSE9WXWRrcnmAh46VnKOqsbi_xs3U2-Lp8PcDChEYHyYtNDtCSVBXXmVsc3qBiI-WnaSrsrnAx87V3OPq8fgECxIZIA";
    bytes32 constant KEEPER_MODULUS_HASH = 0xc5c1457ba4adf8bb84324e8595bf883639aa7ebd7aa7e7626a0b51f90e6838bc;

    /// The request the keeper's prover sends. The User-Agent value is not
    /// read on chain, so the version it carries is immaterial.
    bytes constant REQUEST = "GET /oauth2/v3/certs HTTP/1.1\r\n" "host: www.googleapis.com\r\n" "connection: close\r\n"
        "accept: application/json\r\n" "user-agent: libid-keeper/0.1.0\r\n" "\r\n";
    bytes constant STATUS_OK = "HTTP/1.1 200 OK\r\n";
    bytes constant CONTENT_TYPE = "content-type: application/json; charset=UTF-8\r\n";

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
        roots = _deployRoots(INotaryService(address(notary)));
        hasher = new LimbHasher();

        vm.deal(address(this), 100 ether);
        vm.deal(keeper, 1 ether);
    }

    function _deployRoots(INotaryService service) private returns (GoogleJwtRoots) {
        GoogleJwtRoots impl = new GoogleJwtRoots();
        return GoogleJwtRoots(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(GoogleJwtRoots.initialize, (OWNER, service))))
        );
    }

    // ─── Building a reading ─────────────────────────────────────────

    function _signWith(uint256 key, bytes memory attested) private pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(attested)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _sign(bytes memory attested) private pure returns (bytes memory) {
        return _signWith(NOTARY_KEY, attested);
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

    function _empty() private pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: new AttestationBuilder.Range[](0), commitments: AttestationBuilder.none(), length: 0
        });
    }

    function _attest(bytes memory sent, bytes memory received, uint64 createdAt) private pure returns (bytes memory) {
        return AttestationBuilder.encode(AUTHORITY, createdAt, _whole(sent), _whole(received));
    }

    /// A reading of `body`, framed by `Content-Length`, observed now.
    function _reading(bytes memory body) private view returns (bytes memory) {
        return _readingAt(body, _now());
    }

    function _readingAt(bytes memory body, uint64 createdAt) private pure returns (bytes memory) {
        return _attest(REQUEST, _contentLength(body), createdAt);
    }

    function _rotate(bytes memory attested) private {
        roots.rotate{value: FEE}(attested, _sign(attested));
    }

    /// Signed BEFORE the expectation: `vm.sign` is an external call, and one
    /// inside the call under test would consume the `expectRevert`.
    function _refuses(bytes memory attested, bytes memory err) private {
        bytes memory sig = _sign(attested);
        vm.expectRevert(err);
        roots.rotate{value: FEE}(attested, sig);
    }

    function _refuses(bytes memory attested, bytes4 selector) private {
        _refuses(attested, abi.encodeWithSelector(selector));
    }

    // ─── Framing the response ───────────────────────────────────────

    function _contentLength(bytes memory body) private pure returns (bytes memory) {
        return
            abi.encodePacked(
                STATUS_OK, CONTENT_TYPE, "content-length: ", vm.toString(body.length), "\r\n", "\r\n", body
            );
    }

    /// Chunked transfer coding, `size` bytes per chunk, as Google serves it.
    function _chunked(bytes memory body, uint256 size) private pure returns (bytes memory) {
        return abi.encodePacked(STATUS_OK, CONTENT_TYPE, "transfer-encoding: chunked\r\n", "\r\n", _chunks(body, size));
    }

    function _chunks(bytes memory body, uint256 size) private pure returns (bytes memory out) {
        for (uint256 at = 0; at < body.length; at += size) {
            uint256 take = body.length - at < size ? body.length - at : size;
            bytes memory chunk = new bytes(take);
            for (uint256 i = 0; i < take; ++i) {
                chunk[i] = body[at + i];
            }
            out = abi.encodePacked(out, _hex(take), "\r\n", chunk, "\r\n");
        }
        out = abi.encodePacked(out, "0\r\n\r\n");
    }

    function _hex(uint256 v) private pure returns (bytes memory out) {
        if (v == 0) return "0";
        bytes memory digits = "0123456789abcdef";
        while (v != 0) {
            out = abi.encodePacked(digits[v & 0xf], out);
            v >>= 4;
        }
    }

    // ─── Building a key set ─────────────────────────────────────────

    /// One JWK the way Google writes them, compact.
    function _jwk(string memory kid, string memory n) private pure returns (bytes memory) {
        return abi.encodePacked('{"kty":"RSA","use":"sig","kid":"', kid, '","n":"', n, '","e":"AQAB","alg":"RS256"}');
    }

    function _body(bytes memory jwks) private pure returns (bytes memory) {
        return abi.encodePacked('{"keys":[', jwks, "]}");
    }

    function _oneKey(string memory kid, string memory seed) private pure returns (bytes memory) {
        return _body(_jwk(kid, _modulus(seed)));
    }

    function _twoKeys(string memory kidA, string memory seedA, string memory kidB, string memory seedB)
        private
        pure
        returns (bytes memory)
    {
        return _body(abi.encodePacked(_jwk(kidA, _modulus(seedA)), ",", _jwk(kidB, _modulus(seedB))));
    }

    /// A 2048-bit modulus derived from `seed`, base64url without padding: 256
    /// bytes encode to exactly 342 characters. Different seeds give different
    /// keys, which is the only property the caller needs.
    function _modulus(string memory seed) private pure returns (string memory) {
        return string(_b64url(_bytes(seed, 256)));
    }

    /// The limb hash the list writes for the key `seed` derives, computed
    /// from the bytes rather than read back.
    function _hash(string memory seed) private view returns (bytes32) {
        return hasher.hashOf(_bytes(seed, 256));
    }

    function _bytes(string memory seed, uint256 count) private pure returns (bytes memory out) {
        out = new bytes(count);
        for (uint256 i = 0; i < count; ++i) {
            if (i % 32 == 0) {
                bytes32 word = keccak256(abi.encodePacked(seed, i / 32));
                for (uint256 j = 0; j < 32 && i + j < count; ++j) {
                    out[i + j] = word[j];
                }
            }
        }
    }

    function _b64url(bytes memory data) private pure returns (bytes memory out) {
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        uint256 full = data.length / 3;
        uint256 tail = data.length % 3;
        out = new bytes(full * 4 + (tail == 0 ? 0 : tail + 1));
        uint256 o;
        for (uint256 i = 0; i < full; ++i) {
            uint256 v = (uint256(uint8(data[3 * i])) << 16) | (uint256(uint8(data[3 * i + 1])) << 8)
                | uint256(uint8(data[3 * i + 2]));
            out[o++] = alphabet[(v >> 18) & 63];
            out[o++] = alphabet[(v >> 12) & 63];
            out[o++] = alphabet[(v >> 6) & 63];
            out[o++] = alphabet[v & 63];
        }
        if (tail == 1) {
            uint256 v = uint256(uint8(data[3 * full])) << 16;
            out[o++] = alphabet[(v >> 18) & 63];
            out[o++] = alphabet[(v >> 12) & 63];
        } else if (tail == 2) {
            uint256 v = (uint256(uint8(data[3 * full])) << 16) | (uint256(uint8(data[3 * full + 1])) << 8);
            out[o++] = alphabet[(v >> 18) & 63];
            out[o++] = alphabet[(v >> 12) & 63];
            out[o++] = alphabet[(v >> 6) & 63];
        }
    }

    /// `count` keys, `kid-0` .. `kid-<count-1>`, each with its own modulus
    /// (seeded by its kid).
    function _manyKeys(uint256 count) private pure returns (bytes memory list) {
        for (uint256 i = 0; i < count; ++i) {
            string memory kid = string.concat("kid-", vm.toString(i));
            list = abi.encodePacked(list, i == 0 ? "" : ",", _jwk(kid, _modulus(kid)));
        }
        return _body(list);
    }

    /// Install one key `kid` derived from `seed`, observed now, and return the
    /// hash it wrote.
    function _install(string memory kid, string memory seed) private returns (bytes32) {
        _rotate(_reading(_oneKey(kid, seed)));
        return _hash(seed);
    }

    // ─── Reading the list back ──────────────────────────────────────

    function _current() private view returns (GoogleJwtRoots.Generation memory current) {
        (current,) = roots.currentKeys();
    }

    function _previous() private view returns (GoogleJwtRoots.Generation memory previous) {
        (, previous) = roots.currentKeys();
    }

    function _one(bytes32 a) private pure returns (bytes32[] memory out) {
        out = new bytes32[](1);
        out[0] = a;
    }

    function _two(bytes32 a, bytes32 b) private pure returns (bytes32[] memory out) {
        out = new bytes32[](2);
        out[0] = a;
        out[1] = b;
    }

    function _names(string memory a, string memory b) private pure returns (string[] memory out) {
        out = new string[](2);
        out[0] = a;
        out[1] = b;
    }

    function _assertGeneration(
        GoogleJwtRoots.Generation memory g,
        uint64 observedAt,
        bytes32[] memory moduli,
        string memory label
    ) private pure {
        assertEq(g.observedAt, observedAt, string.concat(label, ": observedAt"));
        assertEq(g.moduli, moduli, string.concat(label, ": moduli"));
    }

    function _assertEmpty(GoogleJwtRoots.Generation memory g, string memory label) private pure {
        _assertGeneration(g, 0, new bytes32[](0), label);
    }

    /// The one `KeysRotated` among the recorded logs, decoded.
    function _lastRotation() private returns (uint64 observedAt, string[] memory kids, bytes32[] memory moduli) {
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

    // ─── What it accepts ────────────────────────────────────────────

    function test_aContentLengthFramedReadingInstallsTheKeys() public {
        uint64 at = _now();
        _rotate(_reading(_twoKeys("kid-1", "one", "kid-2", "two")));

        bytes32 first = _hash("one");
        bytes32 second = _hash("two");
        assertTrue(first != second, "distinct keys");
        _assertGeneration(_current(), at, _two(first, second), "current");
        _assertEmpty(_previous(), "nothing precedes the first reading");
        assertEq(roots.trustedHashExpiresAt(first), at + roots.READING_LIFETIME());
        assertEq(roots.trustedHashExpiresAt(second), at + roots.READING_LIFETIME());
    }

    /// Google serves the key set chunked. The chunk size here cuts the first
    /// modulus value three times, so the de-chunker is what reassembles it;
    /// the same body under `Content-Length` yields the same hash, which is the
    /// framing being transparent -- the second reading refreshes the set
    /// rather than rotating it.
    function test_aChunkedReadingInstallsTheKeys() public {
        bytes memory body = _oneKey("kid-1", "one");
        _rotate(_attest(REQUEST, _chunked(body, 100), _now()));
        assertEq(_current().moduli, _one(_hash("one")), "installed through chunked framing");

        vm.warp(block.timestamp + 1);
        _rotate(_reading(body));
        assertEq(_current().moduli, _one(_hash("one")), "framing changed the key");
        _assertEmpty(_previous(), "framing changed the key");
    }

    /// The document this contract exists to read: Google's body, verbatim,
    /// pretty-printed with a space after every colon, in the framing Google
    /// uses.
    function test_googlesRealBodyIsAccepted() public {
        bytes memory body = bytes(vm.readFile(GOOGLE_JWKS));
        assertEq(string(_slice(body, 0, 13)), "{\n  \"keys\": [", "the fixture is Google's pretty-printed body");

        vm.recordLogs();
        _rotate(_attest(REQUEST, _chunked(body, 512), _now()));

        (, string[] memory kids, bytes32[] memory moduli) = _lastRotation();
        assertEq(kids, _names(GOOGLE_KID_1, GOOGLE_KID_2), "both Google kids, in Google's order");
        assertTrue(moduli[0] != moduli[1], "two distinct keys");
        assertEq(_current().moduli, moduli);
        assertFalse(roots.needsRotation());
    }

    /// Cross-language pin: the keeper's `decision::modulus_hash` and the
    /// Google circuit produce this value for this modulus. The test-side
    /// hasher is pinned to the same vector, so every `_hash` below is too.
    function test_theLimbHashMatchesTheKeeper() public {
        assertEq(hasher.hashOfB64url(KEEPER_MODULUS), KEEPER_MODULUS_HASH);
        _rotate(_reading(_body(_jwk("keeper", KEEPER_MODULUS))));
        assertEq(_current().moduli, _one(KEEPER_MODULUS_HASH));
        assertGt(roots.trustedHashExpiresAt(KEEPER_MODULUS_HASH), 0);
    }

    /// Anyone may submit one. The reading carries its own authority -- the
    /// notary signed it -- so gating the caller would only add a keeper to
    /// trust.
    function test_anybodyMaySubmitARotation() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = _sign(attested);
        vm.prank(keeper);
        roots.rotate{value: FEE}(attested, sig);
        assertEq(_current().moduli, _one(_hash("one")));
    }

    /// The Notary Fee is the one thing a rotation costs beyond gas, and it
    /// accrues where every other attestation's does.
    function test_theRotationPaysTheNotaryFee() public {
        assertEq(roots.quoteRotation(), FEE);
        _install("kid-1", "one");
        assertEq(address(notary).balance, FEE, "the fee reached the Notary Service");
        assertEq(address(roots).balance, 0, "nothing stays with the list");
    }

    // ─── Which readings count ───────────────────────────────────────

    /// Re-applying the reading in force is refused: `NotNewer`, with the
    /// reading's own clock on both sides. Nothing is written -- in particular
    /// the lifetime does NOT restart, so spamming one reading for its whole
    /// freshness window cannot stretch trust by a second -- and the revert
    /// hands the fee back, where a silent return charged it for nothing done.
    function test_replayingTheReadingInForceIsRefused() public {
        uint64 at = _now();
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        _rotate(attested);

        vm.warp(block.timestamp + 30 minutes); // still inside the window
        _refuses(attested, abi.encodeWithSelector(GoogleJwtRoots.NotNewer.selector, at, at));

        assertEq(address(notary).balance, FEE, "the refused replay paid a fee");
        _assertGeneration(_current(), at, _one(_hash("one")), "current");
        _assertEmpty(_previous(), "a replay shifted the list");
        assertEq(
            roots.trustedHashExpiresAt(_hash("one")), at + roots.READING_LIFETIME(), "replay restarted the lifetime"
        );
    }

    /// Two readings dated the same second cannot disagree: the second is
    /// refused whatever it carries, so equal evidence never swaps the set
    /// and drops the keys Google still signs with.
    function test_aReadingDatedTheSameSecondIsRefused() public {
        uint64 at = _now();
        _rotate(_readingAt(_oneKey("kid-1", "one"), at));

        _refuses(
            _readingAt(_oneKey("kid-1", "two"), at), abi.encodeWithSelector(GoogleJwtRoots.NotNewer.selector, at, at)
        );

        _assertGeneration(_current(), at, _one(_hash("one")), "current");
        _assertEmpty(_previous(), "the same second shifted the list");
        assertEq(roots.trustedHashExpiresAt(_hash("two")), 0, "the same second installed a key");
    }

    /// The rollback that matters: a GENUINELY signed older reading, replayed
    /// inside its freshness window after a newer one has landed. The signature
    /// verifies; the reading's own clock is what refuses the regression, and
    /// the error carries both clocks, so a keeper reading it knows which
    /// reading it lost to.
    function test_aGenuinelySignedOlderReadingIsRefused() public {
        uint64 dated = _now() - 30 minutes;
        bytes memory older = _readingAt(_oneKey("kid-1", "retired"), dated);
        uint64 at = _now();
        bytes32 live = _install("kid-1", "live");

        _refuses(older, abi.encodeWithSelector(GoogleJwtRoots.NotNewer.selector, dated, at));

        _assertGeneration(_current(), at, _one(live), "older reading rolled the set back");
        _assertEmpty(_previous(), "older reading shifted the list");
        assertEq(roots.trustedHashExpiresAt(_hash("retired")), 0, "older reading installed a retired key");
        assertEq(roots.trustedHashExpiresAt(live), at + roots.READING_LIFETIME(), "live key lost trust");
    }

    /// The front-run shape the silent return once existed for: a stranger
    /// lands the keeper's own reading first. The keeper's transaction is
    /// refused, its fee comes back with the revert -- gas is all it lost --
    /// and its next reading lands as usual. Nothing was consumed: with no
    /// nullifier there is nothing a front-runner can spend on the keeper's
    /// behalf, which is why "never revert, or the keeper is bricked" no
    /// longer applies.
    function test_aFrontRunKeeperLosesGasOnly() public {
        uint64 at = _now();
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = _sign(attested);
        address stranger = makeAddr("stranger");
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        roots.rotate{value: FEE}(attested, sig);

        uint256 funds = keeper.balance;
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(GoogleJwtRoots.NotNewer.selector, at, at));
        roots.rotate{value: FEE}(attested, sig);
        assertEq(keeper.balance, funds, "the refused reading kept the keeper's fee");
        assertEq(address(notary).balance, FEE, "one fee reached the service: the stranger's");

        vm.warp(at + 1 minutes);
        bytes memory next = _reading(_oneKey("kid-1", "one"));
        sig = _sign(next);
        vm.prank(keeper);
        roots.rotate{value: FEE}(next, sig);
        assertEq(roots.freshestObservedAt(), at + 1 minutes, "the keeper's next reading landed");
        assertEq(address(notary).balance, 2 * FEE);
    }

    /// A newer reading of the set already current is Google saying the set
    /// still stands: its lifetime restarts from the new reading, nothing
    /// shifts, and the order Google listed the keys in is immaterial.
    function test_aNewerReadingOfTheSameSetRefreshesWithoutShifting() public {
        uint64 first = _now();
        _rotate(_readingAt(_twoKeys("kid-1", "one", "kid-2", "two"), first));
        bytes32[] memory set = _two(_hash("one"), _hash("two"));

        vm.warp(first + 20 minutes);
        uint64 second = first + 10 minutes;
        vm.expectEmit(false, false, false, true);
        emit GoogleJwtRoots.ReadingRefreshed(second);
        _rotate(_readingAt(_twoKeys("kid-2", "two", "kid-1", "one"), second)); // the same set, reversed

        _assertGeneration(_current(), second, set, "refreshed in place, original order kept");
        _assertEmpty(_previous(), "a refresh shifted the list");
        assertEq(roots.trustedHashExpiresAt(_hash("one")), second + roots.READING_LIFETIME(), "lifetime restarted");
        assertEq(roots.trustedHashExpiresAt(_hash("two")), second + roots.READING_LIFETIME(), "lifetime restarted");
        assertEq(roots.freshestObservedAt(), second);
    }

    /// A newer reading of a different set is a rotation: what was current is
    /// kept one generation back, the reading becomes current, and the event
    /// carries the reading's keys in the order Google listed them.
    function test_aNewerReadingOfADifferentSetRotates() public {
        uint64 first = _now();
        bytes32 old = _install("kid-a", "a");

        vm.warp(first + 20 minutes);
        uint64 second = first + 10 minutes;
        bytes32[] memory incoming = _two(_hash("b"), _hash("c"));
        vm.expectEmit(false, false, false, true);
        emit GoogleJwtRoots.KeysRotated(second, _names("kid-b", "kid-c"), incoming);
        _rotate(_readingAt(_twoKeys("kid-b", "b", "kid-c", "c"), second));

        _assertGeneration(_current(), second, incoming, "current");
        _assertGeneration(_previous(), first, _one(old), "previous");
        assertEq(roots.trustedHashExpiresAt(old), first + roots.READING_LIFETIME(), "the old set keeps its own stamp");
        assertEq(roots.trustedHashExpiresAt(_hash("b")), second + roots.READING_LIFETIME());
        assertEq(roots.trustedHashExpiresAt(_hash("c")), second + roots.READING_LIFETIME());
        assertEq(roots.freshestObservedAt(), second);
    }

    /// Two generations and no history: a third distinct set drops the oldest
    /// outright, and a key only that set listed stops being trusted -- with
    /// no prune, no untrust, no transaction but the rotation itself.
    function test_aThirdSetDropsTheOldest() public {
        uint64 first = _now();
        bytes32 a = _install("kid-a", "a");
        vm.warp(first + 1 minutes);
        uint64 second = _now();
        bytes32 b = _install("kid-b", "b");
        vm.warp(second + 1 minutes);
        uint64 third = _now();
        bytes32 c = _install("kid-c", "c");

        _assertGeneration(_current(), third, _one(c), "current");
        _assertGeneration(_previous(), second, _one(b), "previous");
        assertEq(roots.trustedHashExpiresAt(a), 0, "the oldest set is still trusted");
        assertEq(roots.trustedHashExpiresAt(b), second + roots.READING_LIFETIME());
        assertEq(roots.trustedHashExpiresAt(c), third + roots.READING_LIFETIME());
    }

    /// Google's sets overlap -- a key is usually in the reading before and
    /// the reading after -- and a key in both generations carries the current
    /// one's stamp: the later reading is the later word that it is listed.
    function test_aKeyInBothGenerationsCarriesTheCurrentStamp() public {
        uint64 first = _now();
        _rotate(_readingAt(_twoKeys("kid-1", "one", "kid-2", "two"), first));
        vm.warp(first + 1 minutes);
        uint64 second = _now();
        _rotate(_readingAt(_twoKeys("kid-2", "two", "kid-3", "three"), second));

        assertEq(roots.trustedHashExpiresAt(_hash("two")), second + roots.READING_LIFETIME(), "in both: current stamp");
        assertEq(roots.trustedHashExpiresAt(_hash("one")), first + roots.READING_LIFETIME(), "previous only");
        assertEq(roots.trustedHashExpiresAt(_hash("three")), second + roots.READING_LIFETIME(), "current only");
    }

    /// Trust lapses by the reading's own clock, with no transaction from
    /// anyone: the stamp is `createdAt + READING_LIFETIME` -- the notary's
    /// time, not the block the rotation landed in -- and past it the
    /// verifier-facing read is already in the past.
    function test_trustLapsesByTheReadingsOwnClockWithNoCall() public {
        uint64 observedAt = _now() - 30 minutes;
        _rotate(_readingAt(_oneKey("kid-1", "one"), observedAt));
        uint256 stamp = observedAt + roots.READING_LIFETIME();
        assertEq(roots.trustedHashExpiresAt(_hash("one")), stamp, "anchored to the reading, not the block");
        assertTrue(stamp < block.timestamp + roots.READING_LIFETIME(), "block time did not stretch it");

        vm.warp(stamp);
        assertEq(roots.trustedHashExpiresAt(_hash("one")), stamp, "nothing rewrote the stamp");
        assertTrue(roots.trustedHashExpiresAt(_hash("one")) <= block.timestamp, "expired by time alone");
        assertTrue(roots.needsRotation());
        _assertGeneration(_current(), observedAt, _one(_hash("one")), "the generation is still what was read");
    }

    /// The freshest-reading mark is the current generation's clock: it only
    /// ever moves forward, whether the newer reading refreshes or rotates,
    /// and an older reading is refused against it.
    function test_freshestObservedAtIsTheReadingInForce() public {
        assertEq(roots.freshestObservedAt(), 0);
        uint64 first = _now();
        _rotate(_readingAt(_oneKey("kid-1", "one"), first));
        assertEq(roots.freshestObservedAt(), first);

        _refuses(
            _readingAt(_oneKey("kid-1", "one"), first - 10 minutes),
            abi.encodeWithSelector(GoogleJwtRoots.NotNewer.selector, first - 10 minutes, first)
        );
        assertEq(roots.freshestObservedAt(), first, "an older reading moved the mark");

        vm.warp(first + 20 minutes);
        _rotate(_readingAt(_oneKey("kid-1", "one"), first + 10 minutes)); // same set: refresh
        assertEq(roots.freshestObservedAt(), first + 10 minutes, "a refresh must move the mark");
        _rotate(_readingAt(_oneKey("kid-2", "two"), first + 15 minutes)); // different set: rotation
        assertEq(roots.freshestObservedAt(), first + 15 minutes, "a rotation must move the mark");
    }

    // ─── What a keeper reads ────────────────────────────────────────

    /// Before any reading: two empty generations, a zero mark, and a list
    /// that wants a rotation.
    function test_currentKeysStartsEmpty() public view {
        _assertEmpty(_current(), "current");
        _assertEmpty(_previous(), "previous");
        assertEq(roots.freshestObservedAt(), 0);
        assertTrue(roots.needsRotation());
    }

    /// The single bit a keeper polls: true until the first rotation, false
    /// while the current generation has RENEWAL_MARGIN of trusted runway,
    /// true again as the runway shortens -- and long before it expires.
    function test_needsRotationTracksTheTrustedRunway() public {
        assertTrue(roots.needsRotation(), "an empty list needs a rotation");
        // Whatever the clock says: a fresh deployment on a chain younger than
        // the lifetime must still ask for its first reading.
        vm.warp(1);
        assertTrue(roots.needsRotation(), "an empty list needs a rotation at any block time");
        vm.warp(T0 + 10);

        uint64 at = _now();
        _install("kid-1", "one");
        assertFalse(roots.needsRotation(), "a fresh rotation buys quiet");

        uint256 stamp = at + roots.READING_LIFETIME();
        vm.warp(stamp - roots.RENEWAL_MARGIN() - 1);
        assertFalse(roots.needsRotation(), "still a second of margin to spare");
        vm.warp(stamp - roots.RENEWAL_MARGIN());
        assertTrue(roots.needsRotation(), "the margin should trip before expiry does");
    }

    /// The rotation announces the reading's keys -- kids and limb hashes in
    /// the order Google listed them -- with the reading's own timestamp, the
    /// notary's clock, so a bot can follow the list from logs alone.
    function test_aRotationAnnouncesTheKeysInReadingOrder() public {
        uint64 provenAt = _now() - 10 minutes;

        vm.recordLogs();
        _rotate(_readingAt(_manyKeys(3), provenAt));

        (uint64 observedAt, string[] memory kids, bytes32[] memory moduli) = _lastRotation();
        assertEq(observedAt, provenAt, "observedAt is the notary's clock");
        assertEq(kids.length, 3);
        assertEq(moduli.length, 3);
        for (uint256 i = 0; i < 3; ++i) {
            string memory kid = string.concat("kid-", vm.toString(i));
            assertEq(kids[i], kid, "kid in reading order");
            assertEq(moduli[i], _hash(kid), "modulus in reading order");
        }
        assertEq(_current().moduli, moduli, "the event is what was stored");
    }

    // ─── Administration ─────────────────────────────────────────────

    /// The Notary Service is the trust root. Pointing at another one moves
    /// the whole list under that service's keys and fee.
    function test_theOwnerCanPointAtAnotherNotaryService() public {
        uint256 otherKey = 0xC0FFEE;
        NotaryService otherImpl = new NotaryService();
        NotaryService other = NotaryService(
            address(
                new ERC1967Proxy(
                    address(otherImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(otherKey), 2 * FEE))
                )
            )
        );

        vm.prank(OWNER);
        vm.expectEmit(false, false, false, true);
        emit GoogleJwtRoots.NotaryServiceChanged(address(other));
        roots.setNotaryService(INotaryService(address(other)));

        assertEq(roots.notaryService(), address(other));
        assertEq(roots.quoteRotation(), 2 * FEE);

        // The old service's key no longer vouches for anything here...
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory oldSig = _sign(attested);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(NOTARY_KEY)));
        roots.rotate{value: 2 * FEE}(attested, oldSig);

        // ...and the new one's does, at the new fee.
        roots.rotate{value: 2 * FEE}(attested, _signWith(otherKey, attested));
        assertEq(_current().moduli, _one(_hash("one")));
        assertEq(address(other).balance, 2 * FEE);
    }

    function test_onlyTheOwnerSetsTheNotaryService() public {
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, keeper));
        roots.setNotaryService(INotaryService(address(0xD00D)));
    }

    function test_aZeroNotaryServiceIsRefused() public {
        vm.prank(OWNER);
        vm.expectRevert(GoogleJwtRoots.ZeroAddress.selector);
        roots.setNotaryService(INotaryService(address(0)));

        GoogleJwtRoots impl = new GoogleJwtRoots();
        vm.expectRevert(GoogleJwtRoots.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(GoogleJwtRoots.initialize, (OWNER, INotaryService(address(0)))));
    }

    /// Renouncing would freeze the list while Google's keys keep expiring, so
    /// the Google verifier would stop accepting proofs with no way back.
    function test_renouncingIsDisabled() public {
        vm.prank(OWNER);
        vm.expectRevert(bytes("renounce disabled"));
        roots.renounceOwnership();
    }

    // ─── What it refuses: the fee and the notary ────────────────────

    /// An exact match, both ways. Underpaying is obvious; overpaying must fail
    /// too, so there is no overpayment to refund and no silent overcharge.
    function test_refusesAnyValueOtherThanTheFee() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = _sign(attested);

        vm.expectRevert(abi.encodeWithSelector(GoogleJwtRoots.WrongValue.selector, FEE, FEE - 1));
        roots.rotate{value: FEE - 1}(attested, sig);

        vm.expectRevert(abi.encodeWithSelector(GoogleJwtRoots.WrongValue.selector, FEE, FEE + 1));
        roots.rotate{value: FEE + 1}(attested, sig);

        vm.expectRevert(abi.encodeWithSelector(GoogleJwtRoots.WrongValue.selector, FEE, 0));
        roots.rotate(attested, sig);
    }

    /// The signature is the whole authority, so a reading the trusted notary
    /// did not sign is worth nothing. Trust lives on the Notary Service, and
    /// this list follows it.
    function test_refusesAnUntrustedNotaryKey() public {
        uint256 stranger = 0xB0B;
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = _signWith(stranger, attested);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(stranger)));
        roots.rotate{value: FEE}(attested, sig);
    }

    /// The signature is genuine and the key is trusted, but one byte of the
    /// record differs -- so the digest the service derives differs and
    /// recovery lands on nobody. Nothing in the record can be edited after
    /// signing: not the host, not the clock, not a modulus.
    function test_refusesATamperedAttestedByte() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = _sign(attested);
        attested[attested.length - 40] = bytes1(uint8(attested[attested.length - 40]) ^ 0x01);
        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        roots.rotate{value: FEE}(attested, sig);
    }

    function test_refusesAMalformedSignature() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        vm.expectRevert(NotaryService.MalformedSignature.selector);
        roots.rotate{value: FEE}(attested, hex"1234");
    }

    /// A rejected rotation leaves no fee behind.
    function test_aRejectedRotationDeliversNoFee() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        vm.expectRevert(NotaryService.MalformedSignature.selector);
        roots.rotate{value: FEE}(attested, hex"1234");
        assertEq(address(notary).balance, 0, "a rejection kept the fee");
        assertEq(address(roots).balance, 0);
    }

    // ─── What it refuses: the session ───────────────────────────────

    /// A reading genuinely signed for another host is refused on its merits.
    /// The authority is the one field the notary observed rather than was
    /// told, and it is checked before any byte of the transcript is read.
    function test_refusesAnotherAuthority() public {
        bytes32 other = keccak256("storage.googleapis.com");
        bytes memory attested =
            AttestationBuilder.encode(other, _now(), _whole(REQUEST), _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, abi.encodeWithSelector(GoogleJwtRoots.WrongAuthority.selector, AUTHORITY, other));
    }

    function test_refusesAReadingFromTheFuture() public {
        uint64 ahead = _now() + uint64(roots.CLOCK_SKEW_GRACE()) + 1;
        _refuses(_readingAt(_oneKey("kid-1", "one"), ahead), GoogleJwtRoots.FutureProof.selector);
        // And accepts one exactly at the grace, which is the boundary.
        _rotate(_readingAt(_oneKey("kid-1", "one"), ahead - 1));
    }

    /// Past the window the reading says nothing about what Google publishes
    /// now, which is the only question this list answers.
    function test_refusesAStaleReading() public {
        uint64 provenAt = _now();
        bytes memory attested = _readingAt(_oneKey("kid-1", "one"), provenAt);
        vm.warp(provenAt + roots.FRESHNESS_WINDOW() + 1);
        _refuses(attested, GoogleJwtRoots.StaleProof.selector);
    }

    /// Both directions must tile the signed length. A gap is where a prover
    /// hides bytes, and this contract reads the join as the document.
    function test_refusesACoverageGapInTheRequest() public {
        uint32 len = uint32(REQUEST.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: _slice(REQUEST, 0, len - 1)})),
            commitments: AttestationBuilder.none(),
            length: len
        });
        bytes memory attested =
            AttestationBuilder.encode(AUTHORITY, _now(), sent, _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, abi.encodeWithSelector(CeremonyAttestation.CoverageGap.selector, len - 1, len));
    }

    function test_refusesACoverageGapInTheResponse() public {
        bytes memory response = _contentLength(_oneKey("kid-1", "one"));
        uint32 len = uint32(response.length);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 1, value: _slice(response, 1, len)})),
            commitments: AttestationBuilder.none(),
            length: len
        });
        bytes memory attested = AttestationBuilder.encode(AUTHORITY, _now(), _whole(REQUEST), received);
        _refuses(attested, abi.encodeWithSelector(CeremonyAttestation.CoverageGap.selector, 0, 1));
    }

    /// A commitment tiles like a revealed range, so coverage passes -- and the
    /// bytes behind it are exactly what this contract must not read around.
    function test_refusesAHiddenByteInTheRequest() public {
        uint32 len = uint32(REQUEST.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: REQUEST})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: len, end: len + 4, value: bytes32(uint256(0x7777))})
            ),
            length: len + 4
        });
        bytes memory attested =
            AttestationBuilder.encode(AUTHORITY, _now(), sent, _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, GoogleJwtRoots.HiddenBytes.selector);
    }

    function test_refusesAHiddenByteInTheResponse() public {
        bytes memory response = _contentLength(_oneKey("kid-1", "one"));
        uint32 len = uint32(response.length);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: response})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: len, end: len + 4, value: bytes32(uint256(0x7777))})
            ),
            length: len + 4
        });
        bytes memory attested = AttestationBuilder.encode(AUTHORITY, _now(), _whole(REQUEST), received);
        _refuses(attested, GoogleJwtRoots.HiddenBytes.selector);
    }

    /// An empty direction passes coverage against a zero signed length; it is
    /// named rather than left to an out-of-bounds panic.
    function test_refusesAnEmptyRequest() public {
        bytes memory attested =
            AttestationBuilder.encode(AUTHORITY, _now(), _empty(), _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, abi.encodeWithSelector(GoogleJwtRoots.RequestLineNotAtOrigin.selector, type(uint32).max));
    }

    function test_refusesAnEmptyResponse() public {
        bytes memory attested = AttestationBuilder.encode(AUTHORITY, _now(), _whole(REQUEST), _empty());
        _refuses(attested, abi.encodeWithSelector(GoogleJwtRoots.RequestLineNotAtOrigin.selector, type(uint32).max));
    }

    // ─── What it refuses: the request ───────────────────────────────

    function _withRequest(bytes memory request) private view returns (bytes memory) {
        return _attest(request, _contentLength(_oneKey("kid-1", "one")), _now());
    }

    function test_refusesAPostRequestLine() public {
        bytes memory request =
            abi.encodePacked("POST /oauth2/v3/certs HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length));
        _refuses(_withRequest(request), GoogleJwtRoots.WrongRequestLine.selector);
    }

    /// The path separates the key set from everything else the host serves.
    function test_refusesAnotherPath() public {
        bytes memory request =
            abi.encodePacked("GET /oauth2/v3/certs2 HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length));
        _refuses(_withRequest(request), GoogleJwtRoots.WrongRequestLine.selector);
    }

    /// The same path with a query is another document. Google really serves
    /// `/oauth2/v3/certs?callback=<name>` as a 200 `text/javascript` JSONP
    /// body -- `<name>({...})` -- that begins with bytes the requester chose,
    /// so the whole request line through its CRLF is pinned, and a query is
    /// refused before any byte of the response is read.
    function test_refusesAQueryInTheRequestTarget() public {
        bytes memory request =
            abi.encodePacked("GET /oauth2/v3/certs?callback=foo HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length));
        _refuses(_withRequest(request), GoogleJwtRoots.WrongRequestLine.selector);
    }

    /// Only the origin-form line, like every other verifier.
    function test_refusesAnAbsoluteFormRequestTarget() public {
        bytes memory request = abi.encodePacked(
            "GET https://www.googleapis.com/oauth2/v3/certs HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length)
        );
        _refuses(_withRequest(request), GoogleJwtRoots.WrongRequestLine.selector);
    }

    /// googleapis.com answers for many hosts under one certificate. With two
    /// `Host` headers, which backend answered is the backend's business.
    function test_refusesASecondHostHeader() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "host: www.googleapis.com\r\n",
            "host: storage.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(GoogleJwtRoots.NotOneHostHeader.selector, 2));
    }

    /// Field names are case-insensitive and the colon admits whitespace, so
    /// the count runs over normalized bytes.
    function test_refusesASecondHostHeaderEvadingCaseAndWhitespace() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "host: www.googleapis.com\r\n",
            "HOST\t : storage.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(GoogleJwtRoots.NotOneHostHeader.selector, 2));
    }

    /// The notary vouches for the bytes, not their HTTP shape. Google's front
    /// end honours a second `Host` that a bare LF separates from the line
    /// before it -- confirmed live: this request is answered by the storage
    /// backend -- while a CRLF-anchored count sees one `Host`, the right one.
    /// The bare LF is refused before anything is counted, at its offset.
    function test_refusesASecondHostHeaderBehindABareLineFeed() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "x-a: b\nhost: storage.googleapis.com\r\n",
            "host: www.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(CeremonyAttestation.BareLineFeed.selector, 37));
    }

    /// An obsolete line fold normalizes to `\r\nhost:` -- the fold's space is
    /// stripped, its CRLF kept -- so a folded continuation would be counted as
    /// the one legitimate `Host` and pair with a bare-LF second one. The fold
    /// is refused first, at the CRLF that starts it.
    function test_refusesAnObsoleteLineFoldInTheRequest() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n", "x-a: b\r\n host: www.googleapis.com\r\n", "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(CeremonyAttestation.ObsoleteLineFold.selector, 37));

        // The pairing the fold enables: a folded right host over a bare-LF
        // wrong one. The fold scan runs first and names the fold.
        request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "x-a: b\r\n host: www.googleapis.com\r\n",
            "x-b: c\nhost: storage.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(CeremonyAttestation.ObsoleteLineFold.selector, 37));
    }

    /// The server reads hosts from the head. A `Host` after the blank line
    /// is body bytes, and does not satisfy the count.
    function test_aHostInTheRequestBodyDoesNotCount() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n", "connection: close\r\n\r\n", "host: www.googleapis.com\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(GoogleJwtRoots.NotOneHostHeader.selector, 0));
    }

    /// A head that never ends has no head to count in.
    function test_refusesARequestWhoseHeadNeverEnds() public {
        bytes memory request = "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com\r\n";
        _refuses(_withRequest(request), GoogleJwtRoots.NoHeadBoundary.selector);
    }

    function test_refusesARequestWithoutAHostHeader() public {
        bytes memory request = "GET /oauth2/v3/certs HTTP/1.1\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), abi.encodeWithSelector(GoogleJwtRoots.NotOneHostHeader.selector, 0));
    }

    /// The TLS authority is the certificate's name; the `Host` header is
    /// which of Google's backends answered. Both must be Google's JWKS host.
    function test_refusesAnotherGoogleHost() public {
        bytes memory request =
            "GET /oauth2/v3/certs HTTP/1.1\r\nhost: storage.googleapis.com\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), GoogleJwtRoots.WrongHost.selector);
    }

    /// A host that is a prefix of the right one, or the right one followed by
    /// more, is another host.
    function test_refusesAHostThatMerelyContainsTheRightOne() public {
        bytes memory request =
            "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com.evil\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), GoogleJwtRoots.WrongHost.selector);
        request = "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.co\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), GoogleJwtRoots.WrongHost.selector);
    }

    // ─── What it refuses: the response ──────────────────────────────

    function _withResponse(bytes memory response) private view returns (bytes memory) {
        return _attest(REQUEST, response, _now());
    }

    /// Only the server's agreement counts. A redirect carries a body too, and
    /// it is not the key set.
    function test_refusesARedirect() public {
        bytes memory response =
            abi.encodePacked("HTTP/1.1 302 Found\r\nlocation: /elsewhere\r\ncontent-length: 0\r\n\r\n");
        _refuses(_withResponse(response), GoogleJwtRoots.WrongStatusLine.selector);
    }

    function test_refusesAResponseWithoutAHeadBoundary() public {
        bytes memory response = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "content-length: 2\r\n", "{}");
        _refuses(_withResponse(response), GoogleJwtRoots.NoHeadBoundary.selector);
    }

    /// The prover negotiates no compression, so a `Content-Encoding` is a
    /// body this contract cannot read. Refused by name, before the framing
    /// is even looked at, rather than as some byte deep in the JSON walk.
    function test_refusesAnEncodedBody() public {
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory response = abi.encodePacked(
            STATUS_OK,
            CONTENT_TYPE,
            "content-encoding: gzip\r\n",
            "content-length: ",
            vm.toString(body.length),
            "\r\n\r\n",
            body
        );
        _refuses(_withResponse(response), GoogleJwtRoots.EncodedBody.selector);
    }

    /// Every deviation from strict chunked framing is one error: a size that
    /// is not hex, a chunk extension, a missing terminator, trailers, an
    /// over-long size, and chunk data not followed by CRLF.
    function test_refusesBadChunkFraming() public {
        bytes memory head = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "transfer-encoding: chunked\r\n\r\n");
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory sizeLine = abi.encodePacked(_hex(body.length), "\r\n");

        // A size that is not hex.
        _refuses(
            _withResponse(abi.encodePacked(head, "zz\r\n", body, "\r\n0\r\n\r\n")),
            GoogleJwtRoots.BadChunkFraming.selector
        );
        // A chunk extension.
        _refuses(
            _withResponse(abi.encodePacked(head, _hex(body.length), ";ext=1\r\n", body, "\r\n0\r\n\r\n")),
            GoogleJwtRoots.BadChunkFraming.selector
        );
        // No terminating zero chunk.
        _refuses(_withResponse(abi.encodePacked(head, sizeLine, body, "\r\n")), GoogleJwtRoots.BadChunkFraming.selector);
        // Trailers after the zero chunk.
        _refuses(
            _withResponse(abi.encodePacked(head, sizeLine, body, "\r\n0\r\nx-trailer: 1\r\n\r\n")),
            GoogleJwtRoots.BadChunkFraming.selector
        );
        // Nine hex digits.
        _refuses(
            _withResponse(abi.encodePacked(head, "000000001\r\n", body, "\r\n0\r\n\r\n")),
            GoogleJwtRoots.BadChunkFraming.selector
        );
        // Chunk data not followed by CRLF.
        _refuses(
            _withResponse(abi.encodePacked(head, sizeLine, body, "0\r\n\r\n")), GoogleJwtRoots.BadChunkFraming.selector
        );
        // A size past the end of the body.
        _refuses(
            _withResponse(abi.encodePacked(head, "ffff\r\n", body, "\r\n0\r\n\r\n")),
            GoogleJwtRoots.BadChunkFraming.selector
        );
        // Bytes after the final CRLF.
        _refuses(
            _withResponse(abi.encodePacked(head, sizeLine, body, "\r\n0\r\n\r\n\r\n")),
            GoogleJwtRoots.BadChunkFraming.selector
        );
        // And the strict form of the same body is accepted.
        _rotate(_withResponse(abi.encodePacked(head, sizeLine, body, "\r\n0\r\n\r\n")));
    }

    function test_refusesAContentLengthThatIsNotTheBody() public {
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory response = abi.encodePacked(
            STATUS_OK, CONTENT_TYPE, "content-length: ", vm.toString(body.length + 1), "\r\n\r\n", body
        );
        _refuses(
            _withResponse(response),
            abi.encodeWithSelector(GoogleJwtRoots.ContentLengthMismatch.selector, body.length + 1, body.length)
        );

        // A value that is not a decimal declares no length any body matches.
        response = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "content-length: 4x\r\n\r\n", body);
        _refuses(
            _withResponse(response),
            abi.encodeWithSelector(GoogleJwtRoots.ContentLengthMismatch.selector, 4, body.length)
        );
    }

    /// With neither framing header, `connection: close` delimits and the body
    /// is what follows the head.
    function test_acceptsABodyDelimitedByConnectionClose() public {
        bytes memory response = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "\r\n", _oneKey("kid-1", "one"));
        _rotate(_withResponse(response));
        assertEq(_current().moduli, _one(_hash("one")));
    }

    // ─── What it refuses: the key set ───────────────────────────────

    function _withBody(bytes memory body) private view returns (bytes memory) {
        return _reading(body);
    }

    function test_refusesABodyWithoutKeys() public {
        _refuses(
            _withBody(abi.encodePacked('{"kyes":[', _jwk("kid-1", _modulus("one")), "]}")),
            abi.encodeWithSelector(GoogleJwtRoots.MissingMember.selector, "keys")
        );
        // Present, but not an array.
        _refuses(
            _withBody(abi.encodePacked('{"keys":', _jwk("kid-1", _modulus("one")), "}")),
            abi.encodeWithSelector(GoogleJwtRoots.MissingMember.selector, "keys")
        );
    }

    /// A decoy: two `keys` members, and nothing to say which one Google's
    /// parser -- or a verifier's -- would honour.
    function test_refusesADecoyKeysMember() public {
        bytes memory body = abi.encodePacked(
            '{"keys":[', _jwk("kid-1", _modulus("one")), '],"keys":[', _jwk("kid-2", _modulus("two")), "]}"
        );
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.AmbiguousMember.selector, "keys"));
    }

    function test_refusesAKeyWithoutAModulus() public {
        bytes memory body = _body('{"kty":"RSA","kid":"kid-1","e":"AQAB"}');
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.MissingMember.selector, "n"));
    }

    function test_refusesAKeyWithoutAKid() public {
        bytes memory body = _body(abi.encodePacked('{"kty":"RSA","n":"', _modulus("one"), '","e":"AQAB"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.MissingMember.selector, "kid"));
    }

    /// The circuit verifies RS256 under 65537 and nothing else, and the
    /// verifier trusts a key by its modulus alone -- so a key published with
    /// any other exponent must never be listed, and one that names no
    /// exponent is not a key this list can vouch for.
    function test_refusesAnotherExponent() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid-1","n":"', _modulus("one"), '","e":"AQAC"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.WrongExponent.selector, bytes("AQAC")));
        // 65537 in a padded or longer encoding is still not the token pinned.
        body = _body(abi.encodePacked('{"kid":"kid-1","n":"', _modulus("one"), '","e":"AQAB="}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.WrongExponent.selector, bytes("AQAB=")));
    }

    function test_refusesAKeyWithoutAnExponent() public {
        bytes memory body = _body(abi.encodePacked('{"kty":"RSA","kid":"kid-1","n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.MissingMember.selector, "e"));
    }

    /// Two `kid` members in one object: a duplicate leaves the value
    /// undefined, and different parsers pick different ones.
    function test_refusesADuplicateKidMember() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid-1","kid":"kid-2","n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.AmbiguousMember.selector, "kid"));
    }

    function test_refusesAnUnterminatedKid() public {
        bytes memory body = _body(abi.encodePacked('{"n":"', _modulus("one"), '","kid":"kid-1}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.UnterminatedMember.selector, "kid"));
    }

    function test_refusesAnUnterminatedKeysArray() public {
        _refuses(
            _withBody(abi.encodePacked('{"keys":[', _jwk("kid-1", _modulus("one")))),
            abi.encodeWithSelector(GoogleJwtRoots.UnterminatedMember.selector, "keys")
        );
        // An element that is not an object.
        _refuses(
            _withBody(abi.encodePacked('{"keys":[', _jwk("kid-1", _modulus("one")), ',"x"]}')),
            abi.encodeWithSelector(GoogleJwtRoots.UnterminatedMember.selector, "keys")
        );
        // An object with no closing brace.
        _refuses(
            _withBody(abi.encodePacked('{"keys":[{"kid":"kid-1","n":"', _modulus("one"), '"')),
            abi.encodeWithSelector(GoogleJwtRoots.UnterminatedMember.selector, "keys")
        );
    }

    /// A backslash is refused rather than unescaped: a kid and a base64url
    /// modulus need none, and unescaping is a parser this contract does not
    /// carry.
    function test_refusesAnEscapedValue() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid\\"1","n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.EscapedValue.selector, "kid"));
    }

    function test_refusesANestedObject() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid-1","x5c":["MIIC"],"n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), GoogleJwtRoots.UnexpectedNesting.selector);
        body = _body(abi.encodePacked('{"kid":"kid-1","inner":{},"n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), GoogleJwtRoots.UnexpectedNesting.selector);
    }

    /// One reading carries at most MAX_KEYS keys, and the refusal names how
    /// many it carried. The cap itself is accepted.
    function test_refusesNineKeys() public {
        uint256 max = roots.MAX_KEYS();
        assertEq(max, 8);
        _refuses(_withBody(_manyKeys(max + 1)), abi.encodeWithSelector(GoogleJwtRoots.TooManyKeys.selector, max + 1));
        _rotate(_withBody(_manyKeys(max)));
        assertEq(_current().moduli.length, max, "the cap itself is a valid reading");
    }

    /// A set, not a list: the same modulus twice is not the document Google
    /// publishes, and a set with a repeat would compare as a set it is not.
    function test_refusesADuplicateModulus() public {
        bytes memory body = _twoKeys("kid-1", "one", "kid-2", "one");
        _refuses(_withBody(body), abi.encodeWithSelector(GoogleJwtRoots.DuplicateKey.selector, _hash("one")));
    }

    function test_refusesTrailingBytes() public {
        bytes memory body = _oneKey("kid-1", "one");
        _refuses(_withBody(abi.encodePacked(body, "x")), GoogleJwtRoots.TrailingBytes.selector);
        _refuses(_withBody(abi.encodePacked(body, "{}")), GoogleJwtRoots.TrailingBytes.selector);
        // No closing brace at all.
        _refuses(_withBody(_slice(body, 0, body.length - 1)), GoogleJwtRoots.TrailingBytes.selector);
        // But whitespace after it is what Google sends.
        _rotate(_withBody(abi.encodePacked(body, "\n")));
    }

    /// The circuit takes a 2048-bit modulus and nothing else.
    function test_refusesAShortModulus() public {
        bytes memory body = _body(_jwk("kid-1", string(_b64url(_bytes("short", 255)))));
        _refuses(_withBody(body), GoogleJwtRoots.InvalidModulusLength.selector);
    }

    function test_refusesANonBase64urlCharacter() public {
        bytes memory body = _body(_jwk("kid-1", "AAA+"));
        _refuses(_withBody(body), GoogleJwtRoots.InvalidB64Char.selector);
    }

    function test_refusesAnImpossibleBase64Length() public {
        bytes memory body = _body(_jwk("kid-1", "AAAAA"));
        _refuses(_withBody(body), GoogleJwtRoots.InvalidB64Length.selector);
    }

    /// A reading with no keys says nothing about what Google publishes. It
    /// would pay the fee and shift the live set into `previous` on the
    /// strength of a document that names no key.
    function test_refusesAnEmptyKeySet() public {
        _refuses(_withBody('{"keys":[]}'), GoogleJwtRoots.EmptyKeySet.selector);
        _refuses(_withBody('{"keys": [ ]}'), GoogleJwtRoots.EmptyKeySet.selector);
    }

    /// The header the body is located by gets the rule every other read
    /// gets: a delimiter that matches twice is refused, not chosen from.
    function test_refusesDuplicateOrConflictingFramingHeaders() public {
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory length = abi.encodePacked("content-length: ", vm.toString(body.length), "\r\n");
        _refuses(
            _withResponse(abi.encodePacked(STATUS_OK, CONTENT_TYPE, length, length, "\r\n", body)),
            abi.encodeWithSelector(GoogleJwtRoots.DuplicateFramingHeader.selector, "content-length", 2)
        );
        bytes memory chunked = "transfer-encoding: chunked\r\n";
        _refuses(
            _withResponse(
                abi.encodePacked(
                    STATUS_OK, CONTENT_TYPE, chunked, "Transfer-Encoding: identity\r\n", "\r\n", _chunks(body, 64)
                )
            ),
            abi.encodeWithSelector(GoogleJwtRoots.DuplicateFramingHeader.selector, "transfer-encoding", 2)
        );
        _refuses(
            _withResponse(abi.encodePacked(STATUS_OK, CONTENT_TYPE, chunked, length, "\r\n", _chunks(body, 64))),
            GoogleJwtRoots.ConflictingFraming.selector
        );
        // A coding other than chunked frames a body this contract cannot locate.
        _refuses(
            _withResponse(abi.encodePacked(STATUS_OK, CONTENT_TYPE, "transfer-encoding: gzip\r\n", "\r\n", body)),
            GoogleJwtRoots.BadChunkFraming.selector
        );
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// Read through the cheatcode rather than `block.timestamp`: under via-IR
    /// the optimizer treats TIMESTAMP as movable and may re-read it after a
    /// `vm.warp`, so a value captured before the warp is not one.
    function _now() private view returns (uint64) {
        return uint64(vm.getBlockTimestamp());
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }
}
