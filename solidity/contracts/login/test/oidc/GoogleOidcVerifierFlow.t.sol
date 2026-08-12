// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HonkVerifier} from "../../oidc/Verifier.sol";
import {GoogleOidcVerifier} from "../../oidc/GoogleOidcVerifier.sol";
import {deployNotary} from "../../../notary/test/DeployNotary.sol";

/// End-to-end: TLSN-notarized JWKS rotation, then a Honk-proof JWT
/// validation through the GoogleOidcVerifier.
///
/// Reads two on-disk fixtures:
///   * `contracts/login/test/fixtures/oidc/jwks-proof.json` - rotation proof
///     (notary-signed with the deterministic test key, address
///     `0x6f4c…b87a`).
///   * `circuits/jwt_email/target/{proof,public_inputs,proof_meta.json}`
///     - a Honk proof of a real Google JWT. These are produced by the
///     OIDC CLI on demand and *not* committed (the proof's `exp`
///     ages out within an hour, so refreshing is part of the test's
///     bootstrap).
///
/// When the per-run circuit artifacts are absent, the test logs a
/// clear "skipped" message and returns - so the suite stays green in
/// CI environments that don't run the CLI.
contract GoogleOidcVerifierFlowTest is Test {
    GoogleOidcVerifier verifier;
    HonkVerifier honk;

    address constant NOTARY = 0x6f4c950442e1Af093BcfF730381E63Ae9171b87a;
    address constant OWNER = address(0xA11CE);
    /// Client id the verifier is initialized with. The per-run proof fixture is
    /// generated for its own (env) client id, so the fixture-backed tests
    /// override the expected hash from the proof's own public inputs via
    /// `_configureAudienceFromFixture` rather than relying on this value.
    string constant CLIENT_ID = "test-client-id.apps.googleusercontent.com";

    GoogleOidcVerifier.NotarizedJwksProof rotProof;
    GoogleOidcVerifier.JwkClaim[] rotClaims;
    uint256 rotTimestamp;

    bytes honkProof;
    bytes32[] honkPub;
    string jwtEmail;
    string jwtSub;
    address sessionAddress;
    uint256 jwtExp;
    bool fixturesPresent;

    function setUp() public {
        honk = new HonkVerifier();
        // Deploy behind a UUPS proxy (same shape as production).
        GoogleOidcVerifier impl = new GoogleOidcVerifier();
        // rotate()/rotateRoots() are permissionless — no rotator wiring needed.
        verifier = GoogleOidcVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        GoogleOidcVerifier.initialize, (honk, OWNER, address(deployNotary(OWNER, NOTARY)), CLIENT_ID)
                    )
                )
            )
        );

        _loadRotation();
        fixturesPresent = _tryLoadUserProof();

        // Always warp inside the rotation freshness window so the
        // rotation-only test runs without the per-run circuit
        // artifacts. When the JWT fixtures ARE present, narrow to a
        // moment that's inside both freshness windows.
        uint256 t = rotTimestamp + 60;
        if (fixturesPresent) {
            uint256 jwtAnchor = jwtExp - 60;
            if (jwtAnchor > t) t = jwtAnchor;
        }
        vm.warp(t);
    }

    // ─── Fixture loaders ──────────────────────────────────────────────

    function _loadRotation() internal {
        string memory j = vm.readFile("contracts/login/test/fixtures/oidc/jwks-proof.json");
        rotProof.notarySignature = vm.parseJsonBytes(j, ".notary_signature");
        rotProof.domainHash = vm.parseJsonBytes32(j, ".domain_hash");
        rotProof.clientRandom = vm.parseJsonBytes32(j, ".client_random");
        rotProof.serverRandom = vm.parseJsonBytes32(j, ".server_random");
        rotProof.serverEphemeralKey = vm.parseJsonBytes(j, ".server_ephemeral_key");
        rotProof.transcriptRoot = vm.parseJsonBytes32(j, ".transcript_root");
        rotTimestamp = vm.parseJsonUint(j, ".timestamp");
        rotProof.timestamp = rotTimestamp;
        rotProof.domainPath = vm.parseJsonBytes32Array(j, ".domain_path");
        rotProof.endpointPath = vm.parseJsonBytes32Array(j, ".endpoint_path");

        for (uint256 i = 0; i < 16; i++) {
            string memory base = string.concat(".claims[", vm.toString(i), "]");
            try this._probeKid(j, base) returns (string memory kidStr) {
                GoogleOidcVerifier.JwkClaim memory c;
                c.kid = bytes(kidStr);
                c.nB64url = bytes(vm.parseJsonString(j, string.concat(base, ".n_b64url")));
                c.jwkBytes = vm.parseJsonBytes(j, string.concat(base, ".jwk_bytes"));
                c.jwkPath = vm.parseJsonBytes32Array(j, string.concat(base, ".jwk_path"));
                rotClaims.push(c);
            } catch {
                break;
            }
        }
        require(rotClaims.length > 0, "no rotation claims");
    }

    function _probeKid(string memory j, string memory base) external view returns (string memory) {
        return vm.parseJsonString(j, string.concat(base, ".kid"));
    }

    function _tryLoadUserProof() internal returns (bool) {
        try this._readBinary("circuits/jwt_email/target/proof") returns (bytes memory proof) {
            honkProof = proof;
        } catch {
            return false;
        }
        bytes memory raw;
        try this._readBinary("circuits/jwt_email/target/public_inputs") returns (bytes memory pub) {
            raw = pub;
        } catch {
            return false;
        }
        // 28 public inputs: modulus[18] + email[2] + nonce[2] + sub[1]
        // + exp[1] + audience_hash[2] + chain_id[1] + registry_addr[1].
        if (raw.length != 28 * 32) return false;
        for (uint256 i = 0; i < 28; i++) {
            bytes32 v;
            assembly {
                v := mload(add(add(raw, 32), mul(i, 32)))
            }
            honkPub.push(v);
        }
        string memory meta;
        try this._readText("circuits/jwt_email/target/proof_meta.json") returns (string memory m) {
            meta = m;
        } catch {
            return false;
        }
        jwtEmail = vm.parseJsonString(meta, ".email");
        jwtSub = vm.parseJsonString(meta, ".sub");
        sessionAddress = vm.parseAddress(vm.parseJsonString(meta, ".session_address"));
        jwtExp = vm.parseJsonUint(meta, ".exp");
        return true;
    }

    function _readBinary(string calldata path) external view returns (bytes memory) {
        return vm.readFileBinary(path);
    }

    function _readText(string calldata path) external view returns (string memory) {
        return vm.readFile(path);
    }

    function _userProofBytes() internal view returns (bytes memory) {
        GoogleOidcVerifier.UserProof memory u = GoogleOidcVerifier.UserProof({
            honkProof: honkProof, publicInputs: honkPub, email: jwtEmail, sessionKey: sessionAddress, sub: jwtSub
        });
        return abi.encode(u);
    }

    // ─── Tests ────────────────────────────────────────────────────────

    /// Rotation succeeds and at least one kid lands in storage. Doesn't
    /// require the per-run circuit artifacts.
    function test_rotation_installs_kids() public {
        vm.prank(OWNER);
        verifier.rotate(rotProof, rotClaims);
        bytes32 kid0Hash = keccak256(rotClaims[0].kid);
        assertGt(verifier.expiresAtKid(kid0Hash), block.timestamp, "rotation didn't store kid");
    }

    /// Rotation is PERMISSIONLESS: any caller may submit. This is the point of
    /// removing the rotator role — a third-party keeper must be able to keep
    /// JWKS fresh without being allowlisted by us.
    function test_rotation_permissionless_anyCaller() public {
        vm.prank(address(0xBADBAD));
        verifier.rotate(rotProof, rotClaims);
        assertGt(
            verifier.expiresAtKid(keccak256(rotClaims[0].kid)),
            block.timestamp,
            "unauthorized caller should have been able to rotate"
        );
    }

    /// Re-submitting the same proof is IDEMPOTENT, not a revert. With an open
    /// caller set a one-shot nullifier would itself be the attack: a front-runner
    /// could consume the digest and brick the honest keeper.
    function test_rotation_replay_isIdempotent() public {
        verifier.rotate(rotProof, rotClaims);
        bytes32 kid0 = keccak256(rotClaims[0].kid);
        bytes32 mod0 = verifier.modulusOfKid(kid0);

        vm.prank(address(0xBADBAD));
        verifier.rotate(rotProof, rotClaims); // must NOT revert

        assertEq(verifier.modulusOfKid(kid0), mod0, "replay changed the modulus");
        assertGt(verifier.expiresAtKid(kid0), block.timestamp);
    }

    /// A partial submission must not block a later fuller one — the griefing
    /// vector the digest nullifier would have created once anyone can call.
    function test_rotation_subsetDoesNotBlockFullRotation() public {
        GoogleOidcVerifier.JwkClaim[] memory empty = new GoogleOidcVerifier.JwkClaim[](0);
        vm.prank(address(0xBADBAD));
        verifier.rotate(rotProof, empty); // front-runner submits nothing useful

        verifier.rotate(rotProof, rotClaims); // honest keeper still lands
        assertGt(
            verifier.expiresAtKid(keccak256(rotClaims[0].kid)),
            block.timestamp,
            "subset submission blocked the real rotation"
        );
    }

    /// What actually prevents an old proof regressing a newer modulus is the
    /// freshness window, NOT the caller gate — so it must still bite.
    function test_rotation_staleProof_stillRejected() public {
        vm.warp(block.timestamp + verifier.FRESHNESS_WINDOW() + 1);
        vm.expectRevert(GoogleOidcVerifier.StaleProof.selector);
        verifier.rotate(rotProof, rotClaims);
    }

    /// Replaying an OLDER proof inside the freshness window must not roll a kid
    /// back to a modulus Google has already retired, nor re-extend its TTL. The
    /// caller gate used to make this unreachable; with rotation permissionless
    /// anyone can replay a still-fresh proof, so the per-kid `rotatedAtKid`
    /// guard is what holds the invariant.
    ///
    /// Uses a verifier whose notary key the test controls, so it can re-sign the
    /// fixture's transcript at a later timestamp (the claims still merkle-verify
    /// against the same root).
    function test_rotation_olderProofDoesNotRollBackNewer() public {
        uint256 notaryPk = 0xB0B;
        GoogleOidcVerifier v = _deployWithNotary(vm.addr(notaryPk));

        GoogleOidcVerifier.NotarizedJwksProof memory older = rotProof;
        older.notarySignature = _sign(notaryPk, _digest(older));

        GoogleOidcVerifier.NotarizedJwksProof memory newer = rotProof;
        newer.timestamp = rotProof.timestamp + 10 minutes;
        newer.notarySignature = _sign(notaryPk, _digest(newer));

        // Newer rotation lands first.
        vm.warp(newer.timestamp + 1);
        v.rotate(newer, rotClaims);

        bytes32 kid0 = keccak256(rotClaims[0].kid);
        uint256 provenAfterNewer = v.rotatedAtKid(kid0);
        bytes32 modulusAfterNewer = v.modulusOfKid(kid0);
        uint256 expiryAfterNewer = v.expiresAtKid(kid0);
        assertEq(provenAfterNewer, newer.timestamp, "newer rotation did not record its timestamp");

        // Anyone replays the OLDER, still-fresh proof later.
        vm.warp(older.timestamp + 50 minutes);
        vm.prank(address(0xBADBAD));
        v.rotate(older, rotClaims);

        assertEq(v.rotatedAtKid(kid0), provenAfterNewer, "older proof overwrote the provenance stamp");
        assertEq(v.modulusOfKid(kid0), modulusAfterNewer, "older proof rolled the modulus back");
        assertEq(v.expiresAtKid(kid0), expiryAfterNewer, "older proof re-extended the TTL");
    }

    function _deployWithNotary(address notary_) internal returns (GoogleOidcVerifier) {
        GoogleOidcVerifier impl = new GoogleOidcVerifier();
        return GoogleOidcVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        GoogleOidcVerifier.initialize, (honk, OWNER, address(deployNotary(OWNER, notary_)), CLIENT_ID)
                    )
                )
            )
        );
    }

    /// Mirrors GoogleOidcVerifier._notaryDigest — deliberately an independent
    /// reimplementation so a change to the digest breaks this test loudly.
    function _digest(GoogleOidcVerifier.NotarizedJwksProof memory p) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                p.domainHash,
                p.clientRandom,
                p.serverRandom,
                keccak256(p.serverEphemeralKey),
                p.transcriptRoot,
                p.timestamp
            )
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// Renouncing ownership is disabled — it would brick the UUPS upgrade path.
    function test_renounceOwnership_disabled() public {
        vm.prank(OWNER);
        vm.expectRevert(bytes("renounce disabled"));
        verifier.renounceOwnership();
    }

    // ─── UUPS upgrade ───────────────────────────────────────────────

    function test_upgrade_revertsIfNotOwner() public {
        GoogleOidcVerifier newImpl = new GoogleOidcVerifier();
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        verifier.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgrade_byOwner_preservesState() public {
        // Seed state, then upgrade and confirm it survives.
        verifier.rotate(rotProof, rotClaims);
        bytes32 kid0Hash = keccak256(rotClaims[0].kid);
        uint256 expiryBefore = verifier.expiresAtKid(kid0Hash);
        assertGt(expiryBefore, 0, "precondition: kid installed");

        GoogleOidcVerifier newImpl = new GoogleOidcVerifier();
        vm.prank(OWNER);
        verifier.upgradeToAndCall(address(newImpl), "");

        assertEq(verifier.owner(), OWNER, "owner preserved");
        assertEq(verifier.expiresAtKid(kid0Hash), expiryBefore, "rotated kid preserved");
        // Rotation is permissionless and idempotent across the upgrade.
        verifier.rotate(rotProof, rotClaims);
        assertEq(verifier.expiresAtKid(kid0Hash), expiryBefore, "replay changed state after upgrade");
    }

    /// User-side verification fails when no rotation has happened (the
    /// modulus is not yet trusted).
    function test_verify_fails_before_rotation() public {
        if (!fixturesPresent) {
            emit log("SKIPPED: circuits/jwt_email/target/proof artifacts absent - run oidc-noir-cli to refresh");
            return;
        }
        vm.expectRevert(GoogleOidcVerifier.UntrustedModulus.selector);
        verifier.verifyAndExtract(_userProofBytes());
    }

    /// Full pipeline: rotate, then verify. The verifier returns the
    /// validated email plaintext (matches the dyaka Registry's `(platform,
    /// handle)` storage shape - see Registry.register_session_oidc).
    function test_full_pipeline_rotate_then_verify() public {
        if (!fixturesPresent) {
            emit log("SKIPPED: circuits/jwt_email/target/proof artifacts absent - run oidc-noir-cli to refresh");
            return;
        }
        // Configure the verifier with the plaintext client id the proof fixture
        // was generated for (GMAIL_CLIENT_ID, the same value dev-start feeds the
        // prover and the deploy). This drives the real setExpectedAudience path
        // (on-chain SHA-256), so a passing proof proves the contract's audience
        // check — hashing AND the 16-byte half split — matches the circuit, not
        // a value echoed back from the proof itself.
        string memory clientId = vm.envOr("GMAIL_CLIENT_ID", string(""));
        if (bytes(clientId).length == 0) {
            emit log("SKIPPED: set GMAIL_CLIENT_ID (the client id the proof fixture was generated for) to run this test");
            return;
        }
        vm.prank(OWNER);
        verifier.rotate(rotProof, rotClaims);
        vm.prank(OWNER);
        verifier.setExpectedAudience(clientId);
        (string memory handle, address sessionKey, uint256 expiresAt, string memory userId) = verifier.verifyDirect(
            GoogleOidcVerifier.UserProof({
                honkProof: honkProof, publicInputs: honkPub, email: jwtEmail, sessionKey: sessionAddress, sub: jwtSub
            })
        );
        assertEq(handle, jwtEmail, "verifier should hand back the validated email plaintext");
        assertEq(sessionKey, sessionAddress, "session key passes through");
        assertEq(expiresAt, jwtExp, "exp comes from the JWT public input");
        assertEq(userId, jwtSub, "sub comes from the JWT public input");
    }

    /// Confused-deputy guard: a valid proof whose `aud` is some OTHER Google
    /// OAuth app is rejected. Same fixture, but the verifier is configured for a
    /// different client id, so its audience-hash public inputs don't match.
    function test_verify_rejects_wrong_audience() public {
        if (!fixturesPresent) {
            emit log("SKIPPED: circuits/jwt_email/target/proof artifacts absent - run oidc-noir-cli to refresh");
            return;
        }
        vm.prank(OWNER);
        verifier.rotate(rotProof, rotClaims);
        // Configure a different app than the one the proof was minted for.
        vm.prank(OWNER);
        verifier.setExpectedAudience("some-other-app.apps.googleusercontent.com");
        vm.expectRevert(GoogleOidcVerifier.WrongAudience.selector);
        verifier.verifyDirect(
            GoogleOidcVerifier.UserProof({
                honkProof: honkProof, publicInputs: honkPub, email: jwtEmail, sessionKey: sessionAddress, sub: jwtSub
            })
        );
    }

    // ─── Audience configuration ─────────────────────────────────────

    /// initialize pins the accepted client id: the stored hash is SHA-256 of it.
    function test_initialize_configuresAudience() public view {
        assertEq(verifier.expectedAudienceHash(), sha256(bytes(CLIENT_ID)), "init should hash the client id");
    }

    /// The owner can rotate which app may register; the hash tracks the id.
    function test_setExpectedAudience_hashesClientId() public {
        string memory newId = "another-app.apps.googleusercontent.com";
        vm.prank(OWNER);
        verifier.setExpectedAudience(newId);
        assertEq(verifier.expectedAudienceHash(), sha256(bytes(newId)), "hash should follow the new client id");
    }

    /// Audience config is owner-gated (both the string and raw-hash setters).
    function test_setExpectedAudience_onlyOwner() public {
        vm.prank(address(0xBADBAD));
        vm.expectRevert();
        verifier.setExpectedAudience("x.apps.googleusercontent.com");

        vm.prank(address(0xBADBAD));
        vm.expectRevert();
        verifier.setExpectedAudienceHash(bytes32(uint256(1)));
    }

    /// An empty client id / zero hash is rejected — never leaves the verifier
    /// silently accepting nothing (or, via the zero-guard, everything).
    function test_setExpectedAudience_rejectsEmpty() public {
        vm.prank(OWNER);
        vm.expectRevert(GoogleOidcVerifier.EmptyAudience.selector);
        verifier.setExpectedAudience("");

        vm.prank(OWNER);
        vm.expectRevert(GoogleOidcVerifier.EmptyAudience.selector);
        verifier.setExpectedAudienceHash(bytes32(0));
    }

    /// A client id longer than the circuit's AUDIENCE_MAX (128) is rejected at
    /// config time — otherwise it would silently make every proof revert.
    function test_setExpectedAudience_rejectsTooLong() public {
        string memory tooLong = new string(uint256(verifier.MAX_AUDIENCE_BYTES()) + 1);
        vm.prank(OWNER);
        vm.expectRevert(GoogleOidcVerifier.AudienceTooLong.selector);
        verifier.setExpectedAudience(tooLong);

        // Exactly MAX_AUDIENCE_BYTES is still accepted (boundary).
        string memory atLimit = new string(uint256(verifier.MAX_AUDIENCE_BYTES()));
        vm.prank(OWNER);
        verifier.setExpectedAudience(atLimit);
        assertEq(verifier.expectedAudienceHash(), sha256(bytes(atLimit)), "boundary length should be accepted");
    }
}
