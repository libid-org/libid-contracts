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

    address constant OWNER = address(0xA11CE);
    address keeper = makeAddr("keeper");
    /// The anvil key.
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant T0 = 1_770_000_000;
    bytes32 constant AUTHORITY = keccak256("www.googleapis.com");

    /// Google's real body, fetched 2026-09-03: pretty-printed, two keys.
    string constant GOOGLE_JWKS = "contracts/ceremony/test/fixtures/google-jwks.json";
    bytes32 constant GOOGLE_KID_1 = keccak256("943a3a5d7d919625a454e489b75c29adab57acba");
    bytes32 constant GOOGLE_KID_2 = keccak256("f10f87405a979c1df36df26606734f33cd85c271");

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

    /// A 2048-bit modulus derived from `seed`, base64url without padding: 256
    /// bytes encode to exactly 342 characters. Different seeds give different
    /// keys, which is the only property the caller needs.
    function _modulus(string memory seed) private pure returns (string memory) {
        return string(_b64url(_bytes(seed, 256)));
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

    /// `count` keys, `kid-0` .. `kid-<count-1>`, each with its own modulus.
    function _manyKeys(uint256 count) private pure returns (bytes memory list) {
        for (uint256 i = 0; i < count; ++i) {
            string memory kid = string.concat("kid-", vm.toString(i));
            list = abi.encodePacked(list, i == 0 ? "" : ",", _jwk(kid, _modulus(kid)));
        }
        return _body(list);
    }

    /// Install `kid` carrying a key derived from `seed`, observed now, and
    /// return the modulus hash it wrote.
    function _installKid(string memory kid, string memory seed) private returns (bytes32) {
        _rotate(_reading(_oneKey(kid, seed)));
        return roots.modulusOfKid(keccak256(bytes(kid)));
    }

    // ─── What it accepts ────────────────────────────────────────────

    function test_aContentLengthFramedReadingInstallsTheKeys() public {
        bytes memory body = _body(abi.encodePacked(_jwk("kid-1", _modulus("one")), ",", _jwk("kid-2", _modulus("two"))));
        _rotate(_reading(body));

        bytes32 first = roots.modulusOfKid(keccak256("kid-1"));
        bytes32 second = roots.modulusOfKid(keccak256("kid-2"));
        assertTrue(first != bytes32(0), "kid-1 installed");
        assertTrue(second != bytes32(0), "kid-2 installed");
        assertTrue(first != second, "distinct keys");
        assertEq(roots.trustedHashExpiresAt(first), block.timestamp + roots.DEFAULT_MODULUS_TTL());
        assertEq(roots.trustedHashExpiresAt(second), block.timestamp + roots.DEFAULT_MODULUS_TTL());
        assertEq(roots.expiresAtKid(keccak256("kid-1")), block.timestamp + roots.DEFAULT_MODULUS_TTL());
    }

    /// Google serves the key set chunked. The chunk size here cuts the first
    /// modulus value three times, so the de-chunker is what reassembles it;
    /// the same body under `Content-Length` yields the same hash, which is the
    /// framing being transparent.
    function test_aChunkedReadingInstallsTheKeys() public {
        bytes memory body = _oneKey("kid-1", "one");
        _rotate(_attest(REQUEST, _chunked(body, 100), _now()));
        bytes32 viaChunked = roots.modulusOfKid(keccak256("kid-1"));
        assertTrue(viaChunked != bytes32(0), "installed through chunked framing");

        vm.warp(block.timestamp + 1);
        _rotate(_reading(body));
        assertEq(roots.modulusOfKid(keccak256("kid-1")), viaChunked, "framing changed the key");
    }

    /// The document this contract exists to read: Google's body, verbatim,
    /// pretty-printed with a space after every colon, in the framing Google
    /// uses.
    function test_googlesRealBodyIsAccepted() public {
        bytes memory body = bytes(vm.readFile(GOOGLE_JWKS));
        assertEq(string(_slice(body, 0, 13)), "{\n  \"keys\": [", "the fixture is Google's pretty-printed body");

        _rotate(_attest(REQUEST, _chunked(body, 512), _now()));

        assertTrue(roots.modulusOfKid(GOOGLE_KID_1) != bytes32(0), "first Google key installed");
        assertTrue(roots.modulusOfKid(GOOGLE_KID_2) != bytes32(0), "second Google key installed");
        assertEq(roots.currentRoots().length, 2);
        assertFalse(roots.needsRotation());
    }

    /// Cross-language pin: the keeper's `decision::modulus_hash` and the
    /// Google circuit produce this value for this modulus.
    function test_theLimbHashMatchesTheKeeper() public {
        _rotate(_reading(_body(_jwk("keeper", KEEPER_MODULUS))));
        assertEq(roots.modulusOfKid(keccak256("keeper")), KEEPER_MODULUS_HASH);
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
        assertTrue(roots.modulusOfKid(keccak256("kid-1")) != bytes32(0));
    }

    /// The Notary Fee is the one thing a rotation costs beyond gas, and it
    /// accrues where every other attestation's does.
    function test_theRotationPaysTheNotaryFee() public {
        assertEq(roots.quoteRotation(), FEE);
        _installKid("kid-1", "one");
        assertEq(address(notary).balance, FEE, "the fee reached the Notary Service");
        assertEq(address(roots).balance, 0, "nothing stays with the list");
    }

    /// Re-applying the same reading writes the same values. It must not
    /// revert: with an open caller set, a revert would let a front-runner land
    /// the reading first and brick the honest keeper.
    function test_replayingAReadingIsIdempotent() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        _rotate(attested);
        bytes32 first = roots.modulusOfKid(keccak256("kid-1"));

        _rotate(attested);
        assertEq(roots.modulusOfKid(keccak256("kid-1")), first);
    }

    /// Resubmitting the exact reading already applied writes nothing -- in
    /// particular it does NOT re-stamp the TTL, so spamming one reading for
    /// its whole freshness window cannot stretch trust by even a second.
    function test_anIdenticalResubmissionDoesNotRestampTheTtl() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        _rotate(attested);
        uint256 expiry = roots.expiresAtKid(keccak256("kid-1"));

        vm.warp(block.timestamp + 30 minutes); // still inside the window
        vm.recordLogs();
        _rotate(attested);

        assertEq(roots.expiresAtKid(keccak256("kid-1")), expiry, "replay re-stamped the TTL");
        assertEq(vm.getRecordedLogs().length, 0, "a no-op emitted something");
    }

    /// The rollback that matters: a GENUINELY signed older reading, replayed
    /// inside its freshness window after a newer one has landed. The signature
    /// verifies; the per-kid monotonic stamp is what refuses the regression --
    /// silently, so a keeper batch is never bricked.
    function test_aGenuinelySignedOlderReadingCannotRegressState() public {
        bytes memory older = _readingAt(_oneKey("kid-1", "retired-modulus"), _now() - 30 minutes);
        bytes32 newModulus = _installKid("kid-1", "current-modulus");

        bytes32 kidHash = keccak256("kid-1");
        uint256 stamp = roots.rotatedAtKid(kidHash);
        uint256 expiry = roots.expiresAtKid(kidHash);

        _rotate(older); // must not revert, must not apply

        assertEq(roots.modulusOfKid(kidHash), newModulus, "older reading rolled the kid back");
        assertEq(roots.rotatedAtKid(kidHash), stamp, "older reading overwrote the stamp");
        assertEq(roots.expiresAtKid(kidHash), expiry, "older reading re-stamped the TTL");
        assertEq(roots.trustedHashExpiresAt(newModulus), expiry, "current key lost trust");
    }

    /// The freshest-reading mark only moves forward, whoever submits.
    function test_freshestObservedAtIsMonotonic() public {
        assertEq(roots.freshestObservedAt(), 0);
        uint64 first = _now();
        _rotate(_readingAt(_oneKey("kid-1", "one"), first));
        assertEq(roots.freshestObservedAt(), first);

        _rotate(_readingAt(_oneKey("kid-1", "one"), first - 10 minutes));
        assertEq(roots.freshestObservedAt(), first, "an older reading moved the mark");

        vm.warp(first + 20 minutes);
        _rotate(_readingAt(_oneKey("kid-1", "one"), first + 10 minutes));
        assertEq(roots.freshestObservedAt(), first + 10 minutes, "a newer reading must move the mark");
    }

    // ─── Losing trust ───────────────────────────────────────────────

    /// The verifier resolves by modulus, not by kid, so a key that a rotation
    /// replaced has to stop being trusted at that moment. Leaving it keeps a
    /// retired key usable for the rest of its thirty-day stamp -- which is the
    /// exact window a compromised key would be used in.
    function test_rotatingAKidRetiresTheKeyItCarried() public {
        bytes32 first = _installKid("kid-1", "modulus-one");
        assertGt(roots.trustedHashExpiresAt(first), 0, "first key trusted");

        vm.warp(block.timestamp + 1 minutes);
        vm.expectEmit(true, false, false, true);
        emit GoogleJwtRoots.ModulusUntrusted(first);
        bytes32 second = _installKid("kid-1", "modulus-two");

        assertGt(roots.trustedHashExpiresAt(second), 0, "second key trusted");
        assertEq(roots.trustedHashExpiresAt(first), 0, "the replaced key is no longer trusted");
    }

    /// The case that cannot wait for a rotation: a key Google has not retired,
    /// or has retired in a way this list has not seen yet.
    function test_theOwnerCanUntrustAKeyOutright() public {
        bytes32 modulusHash = _installKid("kid-1", "one");
        assertGt(roots.trustedHashExpiresAt(modulusHash), 0);

        vm.prank(OWNER);
        vm.expectEmit(true, false, false, true);
        emit GoogleJwtRoots.ModulusUntrusted(modulusHash);
        roots.untrustModulus(modulusHash);

        assertEq(roots.trustedHashExpiresAt(modulusHash), 0, "no longer trusted");
    }

    function test_onlyTheOwnerUntrusts() public {
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, keeper));
        roots.untrustModulus(bytes32(uint256(1)));
    }

    // ─── Expiry and pruning ─────────────────────────────────────────

    /// Time alone retires a key: past its stamp the verifier-facing read says
    /// expired, with no transaction from anyone. `prune()` -- callable by
    /// anyone -- then reclaims the bookkeeping.
    function test_anExpiredKeyIsPrunableByAnyone() public {
        uint64 provenAt = _now();
        bytes32 modulusHash = _installKid("kid-1", "one");
        bytes32 kidHash = keccak256("kid-1");
        uint256 expiry = roots.expiresAtKid(kidHash);

        vm.warp(expiry); // the stamp is spent; use-site checks already refuse it

        vm.expectEmit(true, false, false, true);
        emit GoogleJwtRoots.RootPruned(kidHash, modulusHash);
        vm.prank(keeper);
        roots.prune();

        assertEq(roots.modulusOfKid(kidHash), bytes32(0), "kid still tracked");
        assertEq(roots.expiresAtKid(kidHash), 0);
        assertEq(roots.trustedHashExpiresAt(modulusHash), 0, "spent stamp not cleared");
        assertEq(roots.currentRoots().length, 0, "enumeration not reclaimed");
        // The monotonic floor survives the prune: an old reading still cannot
        // resurrect what time retired.
        assertEq(roots.rotatedAtKid(kidHash), provenAt, "provenance floor lost");
    }

    /// Pruning is a no-op while the keys are alive.
    function test_pruneLeavesLiveKeysAlone() public {
        bytes32 modulusHash = _installKid("kid-1", "one");

        vm.prank(keeper);
        roots.prune();

        assertEq(roots.currentRoots().length, 1, "a live key was pruned");
        assertGt(roots.trustedHashExpiresAt(modulusHash), 0);
    }

    /// The tracked set is capped, and the cap defends itself: a full set first
    /// sheds its expired entries, and only a set full of LIVE keys refuses.
    /// Since every kid must arrive inside a notarized reading of Google's own
    /// JWKS, an adversary cannot even choose the kids -- this is the ceiling
    /// on Google's, not the submitter's, behavior.
    function test_theTrackedSetIsBoundedAndSelfPrunes() public {
        uint256 max = roots.MAX_TRACKED_KIDS();
        _rotate(_reading(_manyKeys(max)));
        assertEq(roots.currentRoots().length, max, "set should sit at the cap");

        // A brand-new kid while every slot holds a live key: refused.
        _refuses(_reading(_oneKey("kid-overflow", "overflow")), GoogleJwtRoots.TooManyKids.selector);

        // Once the old stamps are spent, the same insert prunes its own room.
        vm.warp(block.timestamp + roots.DEFAULT_MODULUS_TTL() + 1);
        _rotate(_reading(_oneKey("kid-overflow", "overflow")));
        assertEq(roots.currentRoots().length, 1, "expired entries should have been shed");
        assertEq(roots.currentRoots()[0].kidHash, keccak256("kid-overflow"));
    }

    // ─── What a keeper reads ────────────────────────────────────────

    /// One call, the whole state: every tracked key with its provenance and
    /// expiry.
    function test_currentRootsDescribesTheWholeList() public {
        uint64 provenAt = _now() - 5 minutes;
        _rotate(_readingAt(_manyKeys(3), provenAt));

        GoogleJwtRoots.RootInfo[] memory infos = roots.currentRoots();
        assertEq(infos.length, 3, "every key should be listed");
        for (uint256 i = 0; i < infos.length; ++i) {
            assertEq(infos[i].kidHash, keccak256(bytes(string.concat("kid-", vm.toString(i)))));
            assertEq(infos[i].modulusHash, roots.modulusOfKid(infos[i].kidHash));
            assertEq(infos[i].observedAt, provenAt, "provenance is the reading's timestamp");
            assertEq(infos[i].expiresAt, roots.trustedHashExpiresAt(infos[i].modulusHash));
        }
    }

    /// The single bit a keeper polls: true until the first rotation, false
    /// while a key has RENEWAL_MARGIN of trusted runway, true again as the
    /// runway shortens -- and long before anything actually expires.
    function test_needsRotationTracksTheTrustedRunway() public {
        assertTrue(roots.needsRotation(), "an empty list needs a rotation");

        _installKid("kid-1", "one");
        assertFalse(roots.needsRotation(), "a fresh rotation buys quiet");

        uint256 expiry = roots.expiresAtKid(keccak256("kid-1"));
        vm.warp(expiry - roots.RENEWAL_MARGIN());
        assertTrue(roots.needsRotation(), "the margin should trip before expiry does");
    }

    /// Each applied key announces itself with the reading's own timestamp --
    /// the notary's clock, not the block's -- so a bot can follow the list
    /// from logs alone.
    function test_rotationEmitsRootAppliedWithProvenance() public {
        uint64 provenAt = _now() - 10 minutes;
        bytes32 kidHash = keccak256("kid-1");

        vm.recordLogs();
        _rotate(_readingAt(_oneKey("kid-1", "one"), provenAt));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("RootApplied(bytes32,bytes32,uint256,uint256)");
        uint256 seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(roots) || logs[i].topics[0] != topic) continue;
            ++seen;
            assertEq(logs[i].topics[1], kidHash);
            assertEq(logs[i].topics[2], roots.modulusOfKid(kidHash));
            (uint256 observedAt, uint256 expiresAt) = abi.decode(logs[i].data, (uint256, uint256));
            assertEq(observedAt, provenAt, "observedAt is the notary's clock");
            assertEq(expiresAt, block.timestamp + roots.DEFAULT_MODULUS_TTL());
        }
        assertEq(seen, 1, "one RootApplied per key");
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
        assertTrue(roots.modulusOfKid(keccak256("kid-1")) != bytes32(0));
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
        assertTrue(roots.modulusOfKid(keccak256("kid-1")) != bytes32(0));
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

    /// The cap on tracked kids is also the cap on keys in one reading.
    function test_refusesSeventeenKeys() public {
        _refuses(_withBody(_manyKeys(17)), GoogleJwtRoots.TooManyKids.selector);
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
    /// would pay the fee, move `freshestObservedAt` and emit nothing.
    function test_refusesAnEmptyKeySet() public {
        _refuses(_withBody('{"keys":[]}'), GoogleJwtRoots.EmptyKeySet.selector);
        _refuses(_withBody('{"keys": [ ]}'), GoogleJwtRoots.EmptyKeySet.selector);
    }

    /// Two readings dated the same second cannot disagree about a kid: the
    /// second is ignored whatever it carries, so equal evidence never swaps a
    /// key and retires the one Google still signs with.
    function test_aReadingDatedTheSameSecondCannotSwapAKey() public {
        uint64 at = _now();
        _rotate(_readingAt(_oneKey("kid-1", "one"), at));
        bytes32 kidHash = keccak256("kid-1");
        bytes32 installed = roots.modulusOfKid(kidHash);
        uint256 expiry = roots.expiresAtKid(kidHash);

        vm.recordLogs();
        _rotate(_readingAt(_oneKey("kid-1", "two"), at)); // must not revert, must not apply

        assertEq(roots.modulusOfKid(kidHash), installed, "the same second swapped the key");
        assertEq(roots.trustedHashExpiresAt(installed), expiry, "the installed key lost trust");
        assertEq(roots.rotatedAtKid(kidHash), at, "the stamp moved");
        assertEq(vm.getRecordedLogs().length, 0, "a no-op emitted something");
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
