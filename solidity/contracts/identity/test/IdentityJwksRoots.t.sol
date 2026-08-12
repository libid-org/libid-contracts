// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IdentityJwksRoots} from "../IdentityJwksRoots.sol";
import {Notary} from "../../notary/Notary.sol";
import {deployNotary} from "../../notary/test/DeployNotary.sol";

/// The naming system's Google trust list, fed by a notarized reading of
/// Google's JWKS endpoint.
///
/// The fixture is a real notarized rotation, signed by the deterministic test
/// notary. It is this tree's own copy on purpose: the proof binds no contract,
/// so the same reading is valid wherever that notary is trusted — but reading
/// it out of another tree would be the coupling this system exists without.
contract IdentityJwksRootsTest is Test {
    IdentityJwksRoots internal roots;
    Notary internal notaryContract;

    address internal constant NOTARY = 0x6f4c950442e1Af093BcfF730381E63Ae9171b87a;
    /// A notary this test can sign as, for the cases the fixture cannot reach.
    uint256 internal constant TEST_NOTARY_PK = 0xA11CE;
    bytes32 internal constant EXPECTED_DOMAIN_HASH = keccak256(bytes("www.googleapis.com"));

    address internal owner = makeAddr("owner");
    address internal keeper = makeAddr("keeper");

    IdentityJwksRoots.NotarizedJwksProof internal proof;
    IdentityJwksRoots.JwkClaim[] internal claims;
    uint256 internal provenAt;

    function setUp() public {
        notaryContract = deployNotary(owner, NOTARY);
        IdentityJwksRoots impl = new IdentityJwksRoots();
        roots = IdentityJwksRoots(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(IdentityJwksRoots.initialize, (owner, address(notaryContract)))
                )
            )
        );

        _loadFixture();
        vm.warp(provenAt + 60);
    }

    function _loadFixture() internal {
        string memory j = vm.readFile("contracts/identity/test/fixtures/oidc/jwks-proof.json");
        proof.notarySignature = vm.parseJsonBytes(j, ".notary_signature");
        proof.domainHash = vm.parseJsonBytes32(j, ".domain_hash");
        proof.clientRandom = vm.parseJsonBytes32(j, ".client_random");
        proof.serverRandom = vm.parseJsonBytes32(j, ".server_random");
        proof.serverEphemeralKey = vm.parseJsonBytes(j, ".server_ephemeral_key");
        proof.transcriptRoot = vm.parseJsonBytes32(j, ".transcript_root");
        provenAt = vm.parseJsonUint(j, ".timestamp");
        proof.timestamp = provenAt;
        proof.domainPath = vm.parseJsonBytes32Array(j, ".domain_path");
        proof.endpointPath = vm.parseJsonBytes32Array(j, ".endpoint_path");

        for (uint256 i = 0; i < 16; i++) {
            string memory base = string.concat(".claims[", vm.toString(i), "]");
            try this.probeKid(j, base) returns (string memory kid) {
                IdentityJwksRoots.JwkClaim memory c;
                c.kid = bytes(kid);
                c.nB64url = bytes(vm.parseJsonString(j, string.concat(base, ".n_b64url")));
                c.jwkBytes = vm.parseJsonBytes(j, string.concat(base, ".jwk_bytes"));
                c.jwkPath = vm.parseJsonBytes32Array(j, string.concat(base, ".jwk_path"));
                claims.push(c);
            } catch {
                break;
            }
        }
        require(claims.length > 0, "fixture carries no claims");
    }

    function probeKid(string memory j, string memory base) external view returns (string memory) {
        return vm.parseJsonString(j, string.concat(base, ".kid"));
    }

    function _noClaims() internal pure returns (IdentityJwksRoots.JwkClaim[] memory) {
        return new IdentityJwksRoots.JwkClaim[](0);
    }

    /// A reading signed by `TEST_NOTARY_PK`, naming whatever host is asked for.
    /// The digest is over the TLS session alone — no contract appears in it,
    /// which is why one reading is valid wherever the notary is trusted.
    function _signedProof(bytes32 domainHash) internal view returns (IdentityJwksRoots.NotarizedJwksProof memory p) {
        p.domainHash = domainHash;
        p.clientRandom = keccak256("client");
        p.serverRandom = keccak256("server");
        p.serverEphemeralKey = bytes("ephemeral-key");
        p.transcriptRoot = keccak256("root");
        p.timestamp = block.timestamp;
        p.domainPath = new bytes32[](0);
        p.endpointPath = new bytes32[](0);
        _sign(p);
    }

    /// Sign whatever the proof currently says. Callers that edit the transcript
    /// re-sign, since the root is inside the digest.
    function _sign(IdentityJwksRoots.NotarizedJwksProof memory p) internal pure {
        bytes32 digest = keccak256(
            abi.encode(
                p.domainHash,
                p.clientRandom,
                p.serverRandom,
                keccak256(p.serverEphemeralKey),
                p.transcriptRoot,
                p.timestamp
            )
        );
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TEST_NOTARY_PK, ethHash);
        p.notarySignature = abi.encodePacked(r, s, v);
    }

    // ─── What it accepts ────────────────────────────────────────────

    function test_aNotarizedReadingInstallsTheKeys() public {
        roots.rotate(proof, claims);

        for (uint256 i = 0; i < claims.length; i++) {
            bytes32 kidHash = keccak256(claims[i].kid);
            bytes32 modulusHash = roots.modulusOfKid(kidHash);
            assertTrue(modulusHash != bytes32(0), "kid installed");
            assertEq(roots.trustedHashExpiresAt(modulusHash), block.timestamp + roots.DEFAULT_MODULUS_TTL());
        }
    }

    /// Anyone may submit one. The proof carries its own authority — the notary
    /// signed it — so gating the caller would only add a keeper to trust.
    function test_anybodyMaySubmitARotation() public {
        vm.prank(keeper);
        roots.rotate(proof, claims);

        assertTrue(roots.modulusOfKid(keccak256(claims[0].kid)) != bytes32(0));
    }

    /// Re-applying the same reading writes the same values. It must not revert:
    /// with an open caller set, a revert would let a front-runner land one
    /// claim and brick the honest keeper's batch.
    function test_replayingAReadingIsIdempotent() public {
        roots.rotate(proof, claims);
        bytes32 first = roots.modulusOfKid(keccak256(claims[0].kid));

        roots.rotate(proof, claims);
        assertEq(roots.modulusOfKid(keccak256(claims[0].kid)), first);
    }

    // ─── What it refuses ────────────────────────────────────────────

    /// The signature is the whole authority, so a reading the current notary
    /// did not sign is worth nothing. Rotation happens on the shared Notary
    /// contract, and this list follows it.
    function test_aReadingFromAnUnknownNotaryIsRefused() public {
        vm.prank(owner);
        notaryContract.setNotary(makeAddr("somebody else"));

        vm.expectRevert(IdentityJwksRoots.UnknownNotary.selector);
        roots.rotate(proof, claims);
    }

    /// The host is inside the signed digest, so it cannot be edited after the
    /// fact: changing it makes the signature recover to somebody else. That is
    /// what stops a notarized reading of one host being presented as another's.
    function test_theHostCannotBeChangedAfterSigning() public {
        IdentityJwksRoots.NotarizedJwksProof memory p = proof;
        p.domainHash = keccak256("accounts.example.com");

        vm.expectRevert(IdentityJwksRoots.UnknownNotary.selector);
        roots.rotate(p, claims);
    }

    /// And a reading genuinely signed for another host is refused on its
    /// merits. Signed here with a key this test holds, since the fixture's
    /// notary key is not in the repository.
    ///
    /// No claims are needed: the host is checked before any key is read, which
    /// is the order that matters — the expensive parsing never runs for a
    /// reading that was never about Google.
    function test_aReadingGenuinelySignedForAnotherHostIsRefused() public {
        vm.prank(owner);
        notaryContract.setNotary(vm.addr(TEST_NOTARY_PK));

        IdentityJwksRoots.NotarizedJwksProof memory p = _signedProof(keccak256("accounts.example.com"));

        vm.expectRevert(IdentityJwksRoots.WrongDomain.selector);
        roots.rotate(p, _noClaims());
    }

    /// The right host, but a transcript that does not carry it as a leaf. The
    /// signature covers the root, not what is under it.
    function test_aReadingWithoutTheHostLeafIsRefused() public {
        vm.prank(owner);
        notaryContract.setNotary(vm.addr(TEST_NOTARY_PK));

        IdentityJwksRoots.NotarizedJwksProof memory p = _signedProof(keccak256(bytes("www.googleapis.com")));

        vm.expectRevert(IdentityJwksRoots.MerkleMismatch.selector);
        roots.rotate(p, _noClaims());
    }

    /// Past the window the reading says nothing about what Google publishes
    /// now, which is the only question this list answers.
    function test_aStaleReadingIsRefused() public {
        vm.warp(provenAt + roots.FRESHNESS_WINDOW() + 1);

        vm.expectRevert(IdentityJwksRoots.StaleProof.selector);
        roots.rotate(proof, claims);
    }

    /// Rotation is open, so an older reading replayed inside the window would
    /// otherwise roll a kid back to a modulus Google has retired — and re-stamp
    /// it for another full TTL.
    function test_anOlderReadingCannotRollAKidBack() public {
        roots.rotate(proof, claims);

        bytes32 kidHash = keccak256(claims[0].kid);
        bytes32 current = roots.modulusOfKid(kidHash);
        uint256 currentExpiry = roots.expiresAtKid(kidHash);

        // The same claims, presented as if proved a minute earlier. The
        // timestamp is inside the signed digest, so editing it makes the
        // signature recover to somebody else — which is the guard working, one
        // step earlier than the monotonic check behind it.
        IdentityJwksRoots.NotarizedJwksProof memory older = proof;
        older.timestamp = provenAt - 60;

        vm.expectRevert(IdentityJwksRoots.UnknownNotary.selector);
        roots.rotate(older, claims);

        assertEq(roots.modulusOfKid(kidHash), current, "kid unchanged");
        assertEq(roots.expiresAtKid(kidHash), currentExpiry, "expiry not re-stamped");
    }

    // ─── Losing trust ───────────────────────────────────────────────

    /// The verifier resolves by modulus, not by kid, so a key that a rotation
    /// replaced has to stop being trusted at that moment. Leaving it keeps a
    /// retired key usable for the rest of its thirty-day stamp — which is the
    /// exact window a compromised key would be used in.
    function test_rotatingAKidRetiresTheKeyItCarried() public {
        vm.prank(owner);
        notaryContract.setNotary(vm.addr(TEST_NOTARY_PK));

        // Install a first key for this kid, then a second one for the same kid.
        bytes32 first = _installKid("kid-1", "modulus-one");
        assertGt(roots.trustedHashExpiresAt(first), 0, "first key trusted");

        bytes32 second = _installKid("kid-1", "modulus-two");
        assertGt(roots.trustedHashExpiresAt(second), 0, "second key trusted");
        assertEq(roots.trustedHashExpiresAt(first), 0, "the replaced key is no longer trusted");
    }

    /// The case that cannot wait for a rotation: a key Google has not retired,
    /// or has retired in a way this list has not seen yet.
    function test_theOwnerCanUntrustAKeyOutright() public {
        roots.rotate(proof, claims);

        bytes32 kidHash = keccak256(claims[0].kid);
        bytes32 modulusHash = roots.modulusOfKid(kidHash);
        assertGt(roots.trustedHashExpiresAt(modulusHash), 0);

        vm.prank(owner);
        roots.untrustModulus(modulusHash);

        assertEq(roots.trustedHashExpiresAt(modulusHash), 0, "no longer trusted");
    }

    function test_onlyTheOwnerUntrusts() public {
        vm.prank(keeper);
        vm.expectRevert();
        roots.untrustModulus(bytes32(uint256(1)));
    }

    /// Install `kid` carrying a key derived from `seed`, and return the modulus
    /// hash it wrote.
    ///
    /// The fixture holds one reading of Google's real keys, and a rotation only
    /// retires something when a kid comes back carrying a DIFFERENT key — which
    /// no single reading contains. So this builds a second reading: a JWKS leaf
    /// of its own, a transcript that carries it beside the domain and endpoint
    /// leaves, and the notary key this test holds.
    function _installKid(string memory kid, string memory seed) internal returns (bytes32) {
        bytes memory nB64 = _syntheticModulus(seed);
        bytes memory jwk = abi.encodePacked('{"kid":"', kid, '","n":"', nB64, '"}');

        // Three leaves under one root: domain and endpoint, which every reading
        // must carry, and this key. Siblings are hashed in sorted order, so a
        // path is just the list of them from the leaf upward.
        bytes32 domainLeaf = _leaf("domain:", bytes("www.googleapis.com"));
        bytes32 endpointLeaf = _leaf("endpoint:", bytes("/oauth2/v3/certs"));
        bytes32 jwkLeaf = _leaf("recv:", jwk);
        bytes32 pair = _hashPair(domainLeaf, endpointLeaf);
        bytes32 root = _hashPair(pair, jwkLeaf);

        IdentityJwksRoots.NotarizedJwksProof memory p = _signedProof(EXPECTED_DOMAIN_HASH);
        p.transcriptRoot = root;
        p.domainPath = _path(endpointLeaf, jwkLeaf);
        p.endpointPath = _path(domainLeaf, jwkLeaf);
        _sign(p);

        IdentityJwksRoots.JwkClaim[] memory one = new IdentityJwksRoots.JwkClaim[](1);
        one[0].jwkBytes = jwk;
        one[0].jwkPath = _path(pair);
        one[0].kid = bytes(kid);
        one[0].nB64url = nB64;

        roots.rotate(p, one);
        return roots.modulusOfKid(keccak256(bytes(kid)));
    }

    /// A 2048-bit modulus, written straight in base64url so the test needs no
    /// encoder: 342 characters decode to exactly the 256 bytes the contract
    /// requires. Different seeds give different keys, which is the only property
    /// the caller needs.
    function _syntheticModulus(string memory seed) internal pure returns (bytes memory out) {
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        bytes32 filler = keccak256(bytes(seed));
        out = new bytes(342);
        for (uint256 i = 0; i < 342; i++) {
            out[i] = alphabet[uint8(filler[i % 32]) & 0x3f];
        }
    }

    function _leaf(string memory prefix, bytes memory value) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _path(bytes32 a) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = a;
    }

    function _path(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](2);
        p[0] = a;
        p[1] = b;
    }

    // ─── Administration ─────────────────────────────────────────────

    function test_onlyTheOwnerRotatesTheNotary() public {
        vm.prank(keeper);
        vm.expectRevert();
        notaryContract.setNotary(keeper);
    }

    /// The list reads the notary through the shared Notary contract.
    function test_theNotaryIsReadThroughTheNotaryContract() public view {
        assertEq(address(roots.notaryContract()), address(notaryContract));
        assertEq(roots.notary(), NOTARY);
    }

    /// Renouncing would freeze the list while Google's keys keep expiring, so
    /// the naming system would stop accepting Google proofs with no way back.
    function test_renouncingIsDisabled() public {
        vm.prank(owner);
        vm.expectRevert(bytes("renounce disabled"));
        roots.renounceOwnership();
    }
}
