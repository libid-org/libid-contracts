// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {IOidcVerifier} from "./IOidcVerifier.sol";
import {IVerifier} from "./Verifier.sol";

/// IOidcVerifier implementation for Google OIDC.
///
/// Owns three things:
///
///   1. A set of trusted notary addresses (PoA). Used to verify TLS-notary
///      attestations over `googleapis.com/oauth2/v3/certs` that rotate the
///      RSA JWKS.
///   2. The kid → modulusHash mapping populated by `rotateRoots`. Each entry
///      has an expiry; old keys age out automatically.
///   3. A reference to the UltraHonk Verifier deployed for the `jwt_email`
///      Noir circuit. `verifyAndExtract` checks the user's ZK proof and
///      ensures its `modulus` public input lines up with a currently-trusted
///      kid.
///   4. The accepted Google OAuth client id (`expectedAudienceHash`). The
///      `jwt_email` circuit is application-agnostic — it binds whatever `aud`
///      the token carries and exposes its SHA-256 — so this contract is what
///      pins registrations to one app. Configurable at deploy and by the owner.
contract GoogleOidcVerifier is IOidcVerifier, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    // ─── Constants ────────────────────────────────────────────────
    bytes32 private constant EXPECTED_DOMAIN_HASH = keccak256(bytes("www.googleapis.com"));
    bytes private constant EXPECTED_DOMAIN = bytes("www.googleapis.com");
    bytes private constant EXPECTED_ENDPOINT = bytes("/oauth2/v3/certs");
    uint256 public constant FRESHNESS_WINDOW = 1 hours;
    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 public constant DEFAULT_MODULUS_TTL = 30 days;
    uint256 public constant TOTAL_PUBLIC_INPUTS = 28;
    /// Max `aud` (client id) length the jwt_email circuit hashes — must match its
    /// `AUDIENCE_MAX`. A configured client id longer than this can never match.
    uint256 public constant MAX_AUDIENCE_BYTES = 128;
    bytes32 private constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // ─── Storage ──────────────────────────────────────────────────
    // Owner lives in Ownable2StepUpgradeable's namespaced storage (owner()).
    address public registry;
    /// UltraHonk verifier for the jwt_email circuit. Set in `initialize`
    /// (not immutable — this contract sits behind a UUPS proxy).
    IVerifier public verifier;

    mapping(address => bool) public isNotary;
    /// kid keccak → modulusHash (the value stored is the limb-keccak the
    /// circuit produces).
    mapping(bytes32 => bytes32) public modulusOfKid;
    mapping(bytes32 => uint256) public expiresAtKid;
    /// modulusHash → expiry. Lets `verifyAndExtract` check trust without
    /// needing kid (the JWT Noir circuit doesn't expose kid).
    mapping(bytes32 => uint256) public trustedHashExpiresAt;

    /// SHA-256 of the Google OAuth client id (the JWT `aud`) this verifier
    /// accepts. Configurable per deployment: set at `initialize` and mutable by
    /// the owner (`setExpectedAudience`). The circuit binds `aud` to the token
    /// and exposes SHA-256(aud) as public inputs [24..26); `_verifyAndExtract`
    /// checks those halves against this value so a token minted for a DIFFERENT
    /// Google OAuth app (confused deputy) cannot register here.
    bytes32 public expectedAudienceHash;

    /// Timestamp of the rotation proof that last wrote each kid. Rotation is
    /// permissionless, so ANY caller may replay a still-fresh proof; without
    /// this, replaying an older proof inside FRESHNESS_WINDOW silently rolls a
    /// kid back to a modulus Google has already retired and re-stamps it for
    /// another DEFAULT_MODULUS_TTL. Monotonic rather than a one-shot nullifier:
    /// a nullifier would let a front-runner consume the digest and brick the
    /// honest keeper, which is exactly what the open caller set makes cheap.
    mapping(bytes32 => uint256) public rotatedAtKid;

    /// Reserved storage slots for future upgrades (UUPS). New state must be
    /// appended before this gap and the gap shrunk to preserve layout.
    uint256[50] private __gap;

    // ─── Events / errors ──────────────────────────────────────────
    event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
    event NotaryAdded(address indexed notary);
    event NotaryRemoved(address indexed notary);
    /// Emitted whenever the accepted Google client id changes. `clientId` is the
    /// plaintext id when configured via the string setter, or "" when set by raw
    /// hash; `audienceHash` is authoritative.
    event AudienceConfigured(bytes32 indexed audienceHash, string clientId);

    error ZeroAddress();
    error UnknownNotary();
    error WrongDomain();
    error FutureProof();
    error StaleProof();
    error MerkleMismatch();
    error PathTooLong();
    error WrongChain();
    error WrongRegistry();
    error MissingKidInLeaf();
    error MissingNInLeaf();
    error InvalidModulusLength();
    error InvalidB64Char();
    error InvalidB64Length();
    error MalleableSignature();
    error InvalidSignatureV();

    error WrongPublicInputCount();
    error BadHonkProof();
    error WrongEmail();
    error WrongAddress();
    error WrongSub();
    error EmptySub();
    error UntrustedModulus();
    error JwtExpired();
    /// Proof's `aud` (SHA-256) doesn't match the configured client id, or no
    /// client id has been configured yet.
    error WrongAudience();
    /// A client id / audience hash of zero was supplied.
    error EmptyAudience();
    /// A client id longer than `MAX_AUDIENCE_BYTES` was supplied — the circuit
    /// couldn't produce a matching hash, so it's rejected at config time.
    error AudienceTooLong();

    // ─── Types ────────────────────────────────────────────────────
    struct NotarizedJwksProof {
        bytes notarySignature;
        bytes32 domainHash;
        bytes32 clientRandom;
        bytes32 serverRandom;
        bytes serverEphemeralKey;
        bytes32 transcriptRoot;
        uint256 timestamp;
        bytes32[] domainPath;
        bytes32[] endpointPath;
    }

    struct JwkClaim {
        bytes jwkBytes;
        bytes32[] jwkPath;
        bytes kid;
        bytes nB64url;
    }

    /// User-side: bundles everything needed to verify a JWT Honk proof.
    struct UserProof {
        bytes honkProof;
        bytes32[] publicInputs;
        string email;
        address sessionKey;
        /// Immutable Google account id (JWT `sub`). Validated against the
        /// proof's packed `sub` public input; identity binds on this.
        string sub;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// Initialize the proxy. Mirrors XZkVerifier's UUPS pattern: the Honk
    /// `verifier`, owner, and an initial notary are set here (not in the
    /// constructor) because this contract sits behind an ERC1967 proxy.
    /// @param clientId The Google OAuth client id whose id_tokens this verifier
    ///        accepts (the JWT `aud`). Bound into the proof by the circuit and
    ///        enforced on chain — see `expectedAudienceHash`. Changeable later
    ///        by the owner via `setExpectedAudience`.
    function initialize(IVerifier _verifier, address _owner, address initialNotary, string calldata clientId)
        external
        initializer
    {
        if (address(_verifier) == address(0) || _owner == address(0) || initialNotary == address(0)) {
            revert ZeroAddress();
        }
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        verifier = _verifier;
        _setExpectedAudience(clientId);
        isNotary[initialNotary] = true;
        emit NotaryAdded(initialNotary);
    }

    /// Only the owner may upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing ownership is disabled: a zero owner would permanently
    ///      brick the UUPS upgrade path and every admin function.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }

    // ─── Admin ────────────────────────────────────────────────────

    /// Set the Registry that's allowed to call `rotateRoots`. The owner can
    /// always also rotate (useful for ops scripts / emergency).
    function setRegistry(address r) external onlyOwner {
        registry = r;
    }

    /// Reconfigure the accepted Google OAuth client id (the JWT `aud`). Use this
    /// on upgrade or when rotating which app may register through this verifier.
    /// The circuit is application-agnostic, so no redeploy of the Honk verifier
    /// is needed — only this on-chain expectation changes.
    function setExpectedAudience(string calldata clientId) external onlyOwner {
        _setExpectedAudience(clientId);
    }

    /// Lower-level variant: set the expected `aud` hash directly (SHA-256 of the
    /// client id). Handy when the hash is known but the plaintext id isn't, and
    /// used by tests. Prefer `setExpectedAudience` for the readable audit trail.
    function setExpectedAudienceHash(bytes32 audienceHash) external onlyOwner {
        if (audienceHash == bytes32(0)) revert EmptyAudience();
        expectedAudienceHash = audienceHash;
        emit AudienceConfigured(audienceHash, "");
    }

    function _setExpectedAudience(string memory clientId) internal {
        uint256 len = bytes(clientId).length;
        if (len == 0) revert EmptyAudience();
        // The circuit hashes at most AUDIENCE_MAX (128) bytes of `aud`. A client
        // id longer than that could never produce a matching `audience_hash`, so
        // configuring it would silently make every registration revert
        // WrongAudience. Reject it here (real Google client ids are ~72 bytes).
        if (len > MAX_AUDIENCE_BYTES) revert AudienceTooLong();
        bytes32 audienceHash = sha256(bytes(clientId));
        expectedAudienceHash = audienceHash;
        emit AudienceConfigured(audienceHash, clientId);
    }

    function addNotary(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddress();
        isNotary[n] = true;
        emit NotaryAdded(n);
    }

    function removeNotary(address n) external onlyOwner {
        delete isNotary[n];
        emit NotaryRemoved(n);
    }

    // ─── IPlatformProver ──────────────────────────────────────────
    function platformName() external pure override returns (string memory) {
        return "google";
    }

    function rotateRoots(bytes calldata rotationProof) external override {
        (NotarizedJwksProof memory p, JwkClaim[] memory claims) =
            abi.decode(rotationProof, (NotarizedJwksProof, JwkClaim[]));
        _rotate(p, claims);
    }

    function verifyAndExtract(bytes calldata proof)
        external
        view
        override
        returns (string memory handle, address sessionKey, uint256 expiresAt, string memory userId)
    {
        UserProof memory u = abi.decode(proof, (UserProof));
        return _verifyAndExtract(u);
    }

    // ─── Direct entry points (typed; useful for tests / scripts) ──
    function rotate(NotarizedJwksProof calldata proof, JwkClaim[] calldata claims) external {
        _rotate(proof, claims);
    }

    function verifyDirect(UserProof calldata u)
        external
        view
        returns (string memory handle, address sessionKey, uint256 expiresAt, string memory userId)
    {
        return _verifyAndExtract(u);
    }

    // ─── Internal: rotation ───────────────────────────────────────
    function _rotate(NotarizedJwksProof memory p, JwkClaim[] memory claims) internal {
        bytes32 digest = _notaryDigest(p);
        address signer = _ecrecoverEth191(digest, p.notarySignature);
        if (!isNotary[signer]) revert UnknownNotary();

        if (p.timestamp > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > p.timestamp + FRESHNESS_WINDOW) revert StaleProof();

        // PERMISSIONLESS: anyone may submit a rotation. There is deliberately no
        // one-shot nullifier here — with an open caller set it would BE the
        // attack: a front-runner could consume a proof's digest (optionally with
        // a claims subset) and brick the honest keeper's rotation. Freshness is
        // enforced by the notary signature plus the FRESHNESS_WINDOW /
        // CLOCK_SKEW_GRACE bounds above; re-applying the same rotation is
        // idempotent.

        if (p.domainHash != EXPECTED_DOMAIN_HASH) revert WrongDomain();
        _verifyLeaf(p.domainPath, p.transcriptRoot, "domain:", EXPECTED_DOMAIN);
        _verifyLeaf(p.endpointPath, p.transcriptRoot, "endpoint:", EXPECTED_ENDPOINT);

        uint256 expiry = block.timestamp + DEFAULT_MODULUS_TTL;
        for (uint256 i = 0; i < claims.length; i++) {
            _processClaim(claims[i], p.transcriptRoot, expiry, p.timestamp);
        }
    }

    function _notaryDigest(NotarizedJwksProof memory p) internal pure returns (bytes32) {
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

    function _processClaim(JwkClaim memory c, bytes32 transcriptRoot, uint256 expiry, uint256 provenAt) internal {
        if (c.jwkPath.length > 32) revert PathTooLong();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked("recv:", c.jwkBytes))));
        if (!_merkleVerifyMem(c.jwkPath, transcriptRoot, leaf)) revert MerkleMismatch();

        if (!_containsKeyValue(c.jwkBytes, "kid", c.kid)) revert MissingKidInLeaf();
        if (!_containsKeyValue(c.jwkBytes, "n", c.nB64url)) revert MissingNInLeaf();

        bytes memory rawN = _b64urlDecode(c.nB64url);
        if (rawN.length != 256) revert InvalidModulusLength();
        bytes32[18] memory limbs = _splitLimbs(rawN);

        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; i++) {
            bytes32 v = limbs[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        bytes32 modulusHash = keccak256(packed);

        bytes32 kidHash = keccak256(c.kid);
        // Ignore a claim proved no later than the one already applied. Equal
        // timestamps re-apply identical values, so replay stays idempotent
        // rather than reverting — a revert would let a front-runner grief the
        // keeper's batch by landing one claim from it first.
        if (provenAt < rotatedAtKid[kidHash]) return;
        rotatedAtKid[kidHash] = provenAt;

        modulusOfKid[kidHash] = modulusHash;
        expiresAtKid[kidHash] = expiry;
        trustedHashExpiresAt[modulusHash] = expiry;
        emit ModulusRotated(kidHash, string(c.kid), modulusHash, expiry);
    }

    // ─── Internal: user verification ──────────────────────────────
    function _verifyAndExtract(UserProof memory u)
        internal
        view
        returns (string memory handle, address sessionKey, uint256 expiresAt, string memory userId)
    {
        if (u.publicInputs.length != TOTAL_PUBLIC_INPUTS) revert WrongPublicInputCount();

        // 1. Honk proof
        if (!verifier.verify(u.honkProof, u.publicInputs)) revert BadHonkProof();

        // Public-input layout (mirrors the circuit):
        //   [0..18)  modulus limbs
        //   [18..20) email packed (62 bytes)
        //   [20..22) nonce packed (62 bytes)
        //   [22]     sub packed (31 bytes, JWT `sub`)
        //   [23]     exp
        //   [24..26) SHA-256(aud), two big-endian 16-byte halves
        //   [26]     chain_id        (== block.chainid)
        //   [27]     registry_addr   (== msg.sender, the calling Registry)
        bytes memory packed;
        {
            packed = new bytes(18 * 32);
            for (uint256 i = 0; i < 18; i++) {
                bytes32 v = u.publicInputs[i];
                assembly {
                    mstore(add(add(packed, 32), mul(i, 32)), v)
                }
            }
        }
        bytes32 modulusHash = keccak256(packed);
        uint256 modExpiry = trustedHashExpiresAt[modulusHash];
        if (modExpiry == 0 || block.timestamp >= modExpiry) revert UntrustedModulus();

        // 3. exp
        uint256 jwtExp = uint256(u.publicInputs[23]);
        if (jwtExp + CLOCK_SKEW_GRACE <= block.timestamp) revert JwtExpired();

        // 4. email matches packed
        {
            (bytes32 e0, bytes32 e1) = _pack62(_padTo62(bytes(u.email)));
            if (u.publicInputs[18] != e0 || u.publicInputs[19] != e1) revert WrongEmail();
        }

        // 5. session address matches packed nonce
        {
            (bytes32 n0, bytes32 n1) = _pack62(_padTo62(_addressToAscii(u.sessionKey)));
            if (u.publicInputs[20] != n0 || u.publicInputs[21] != n1) revert WrongAddress();
        }

        // 5b. sub (immutable account id) matches packed public input.
        //     Reject an empty sub up front (defense-in-depth: identity binds on it,
        //     and Registry would otherwise revert with an opaque UserIdRequired).
        {
            if (bytes(u.sub).length == 0) revert EmptySub();
            bytes32 s0 = _pack31(_padTo31(bytes(u.sub)));
            if (u.publicInputs[22] != s0) revert WrongSub();
        }

        // 6. Deployment binding: the proof commits chain_id + Registry address,
        // so a proof minted for one (chain, Registry) cannot be replayed against
        // another deployment that shares this verification key. `msg.sender` is
        // the Registry that dispatched `verifyAndExtract`.
        if (uint256(u.publicInputs[26]) != block.chainid) revert WrongChain();
        if (uint256(u.publicInputs[27]) != uint256(uint160(msg.sender))) revert WrongRegistry();

        // 7. Audience: the circuit binds the JWT `aud` to the token and exposes
        // SHA-256(aud) as publicInputs[24..26) (two big-endian 16-byte halves).
        // Enforce it equals the client id this verifier was configured for, so a
        // Google-signed id_token minted for a DIFFERENT OAuth app can't be
        // replayed here (confused deputy). Layout mirrors the circuit's split:
        // high 16 bytes in [24], low 16 bytes in [25].
        bytes32 aud = expectedAudienceHash;
        if (aud == bytes32(0)) revert WrongAudience(); // not configured
        if (
            uint256(u.publicInputs[24]) != uint256(aud) >> 128
                || uint256(u.publicInputs[25]) != uint256(aud) & type(uint128).max
        ) {
            revert WrongAudience();
        }

        // `u.email` was already validated against the proof's packed public
        // inputs above (lines marked "email matches packed") — return it
        // verbatim so the Registry can use it as the display handle. `u.sub`
        // is the immutable id identity binds on.
        handle = u.email;
        sessionKey = u.sessionKey;
        expiresAt = jwtExp;
        userId = u.sub;
    }

    // ─── Internal: shared crypto / decode primitives ──────────────
    function _verifyLeaf(bytes32[] memory path, bytes32 root, string memory prefix, bytes memory value) internal pure {
        if (path.length > 32) revert PathTooLong();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
        if (!_merkleVerifyMem(path, root, leaf)) revert MerkleMismatch();
    }

    function _merkleVerifyMem(bytes32[] memory path, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 cur = leaf;
        for (uint256 i = 0; i < path.length; i++) {
            cur = _hashPair(cur, path[i]);
        }
        return cur == root;
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _ecrecoverEth191(bytes32 digest, bytes memory sig) internal pure returns (address) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        require(sig.length == 65, "sig: bad length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignatureV();
        if (uint256(s) > uint256(SECP256K1_HALF_N)) revert MalleableSignature();
        return ecrecover(ethHash, v, r, s);
    }

    function _containsKeyValue(bytes memory haystack, bytes memory key, bytes memory value)
        internal
        pure
        returns (bool)
    {
        return _contains(haystack, abi.encodePacked('"', key, '":"', value, '"'))
            || _contains(haystack, abi.encodePacked('"', key, '": "', value, '"'));
    }

    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        uint256 hLen = haystack.length;
        uint256 nLen = needle.length;
        if (nLen == 0) return true;
        if (nLen > hLen) return false;
        for (uint256 i = 0; i + nLen <= hLen; i++) {
            bool m = true;
            for (uint256 j = 0; j < nLen; j++) {
                if (haystack[i + j] != needle[j]) {
                    m = false;
                    break;
                }
            }
            if (m) return true;
        }
        return false;
    }

    function _b64urlDecode(bytes memory input) internal pure returns (bytes memory) {
        uint256 len = input.length;
        while (len > 0 && uint8(input[len - 1]) == 0x3d) len--;
        uint256 fullChunks = len / 4;
        uint256 tail = len % 4;
        if (tail == 1) revert InvalidB64Length();
        uint256 outLen = fullChunks * 3 + (tail == 0 ? 0 : tail - 1);
        bytes memory out = new bytes(outLen);
        uint256 outIdx = 0;
        uint256 inIdx = 0;
        for (uint256 i = 0; i < fullChunks; i++) {
            uint256 b0 = _b64char(input[inIdx]);
            uint256 b1 = _b64char(input[inIdx + 1]);
            uint256 b2 = _b64char(input[inIdx + 2]);
            uint256 b3 = _b64char(input[inIdx + 3]);
            inIdx += 4;
            out[outIdx] = bytes1(uint8((b0 << 2) | (b1 >> 4)));
            out[outIdx + 1] = bytes1(uint8(((b1 & 0xf) << 4) | (b2 >> 2)));
            out[outIdx + 2] = bytes1(uint8(((b2 & 0x3) << 6) | b3));
            outIdx += 3;
        }
        if (tail == 2) {
            uint256 b0 = _b64char(input[inIdx]);
            uint256 b1 = _b64char(input[inIdx + 1]);
            out[outIdx] = bytes1(uint8((b0 << 2) | (b1 >> 4)));
        } else if (tail == 3) {
            uint256 b0 = _b64char(input[inIdx]);
            uint256 b1 = _b64char(input[inIdx + 1]);
            uint256 b2 = _b64char(input[inIdx + 2]);
            out[outIdx] = bytes1(uint8((b0 << 2) | (b1 >> 4)));
            out[outIdx + 1] = bytes1(uint8(((b1 & 0xf) << 4) | (b2 >> 2)));
        }
        return out;
    }

    function _b64char(bytes1 c) internal pure returns (uint256) {
        uint8 v = uint8(c);
        if (v >= 65 && v <= 90) return v - 65;
        if (v >= 97 && v <= 122) return v - 71;
        if (v >= 48 && v <= 57) return uint256(v) + 4;
        if (v == 45) return 62;
        if (v == 95) return 63;
        revert InvalidB64Char();
    }

    function _splitLimbs(bytes memory be) internal pure returns (bytes32[18] memory limbs) {
        uint256[8] memory words;
        assembly {
            let beOffset := add(be, 32)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(words, mul(i, 32)), mload(add(beOffset, mul(i, 32))))
            }
        }
        for (uint256 k = 0; k < 18; k++) {
            uint256 startBit = k * 120;
            uint256 endBit = startBit + 120;
            if (endBit > 2048) endBit = 2048;
            uint256 width = endBit - startBit;
            uint256 startWord = startBit / 256;
            uint256 endWord = (endBit - 1) / 256;
            uint256 lv;
            if (startWord == endWord) {
                uint256 w = words[7 - startWord];
                lv = (w >> (startBit % 256)) & ((uint256(1) << width) - 1);
            } else {
                uint256 lowWord = words[7 - startWord];
                uint256 highWord = words[7 - endWord];
                uint256 lowShift = startBit % 256;
                uint256 lowBits = 256 - lowShift;
                uint256 highBits = width - lowBits;
                uint256 lowVal = lowWord >> lowShift;
                uint256 highMask = (uint256(1) << highBits) - 1;
                uint256 highVal = (highWord & highMask) << lowBits;
                lv = lowVal | highVal;
            }
            limbs[k] = bytes32(lv);
        }
    }

    function _padTo62(bytes memory s) internal pure returns (bytes memory out) {
        require(s.length <= 62, "input >62 bytes");
        out = new bytes(62);
        for (uint256 i = 0; i < s.length; i++) {
            out[i] = s[i];
        }
    }

    function _pack62(bytes memory p) internal pure returns (bytes32 hi, bytes32 lo) {
        require(p.length == 62, "not 62");
        uint256 h;
        uint256 l;
        for (uint256 i = 0; i < 31; i++) {
            h = h * 256 + uint8(p[i]);
            l = l * 256 + uint8(p[i + 31]);
        }
        hi = bytes32(h);
        lo = bytes32(l);
    }

    function _padTo31(bytes memory s) internal pure returns (bytes memory out) {
        require(s.length <= 31, "input >31 bytes");
        out = new bytes(31);
        for (uint256 i = 0; i < s.length; i++) {
            out[i] = s[i];
        }
    }

    function _pack31(bytes memory p) internal pure returns (bytes32 packed) {
        require(p.length == 31, "not 31");
        uint256 v;
        for (uint256 i = 0; i < 31; i++) {
            v = v * 256 + uint8(p[i]);
        }
        packed = bytes32(v);
    }

    function _addressToAscii(address a) internal pure returns (bytes memory) {
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        bytes16 hexc = "0123456789abcdef";
        uint160 v = uint160(a);
        for (uint256 i = 0; i < 20; i++) {
            uint8 b = uint8(v >> ((19 - i) * 8));
            out[2 + i * 2] = hexc[b >> 4];
            out[2 + i * 2 + 1] = hexc[b & 0x0f];
        }
        return out;
    }
}
