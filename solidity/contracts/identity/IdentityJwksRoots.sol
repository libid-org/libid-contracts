// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {INotary} from "../notary/INotary.sol";

/// @title IdentityJwksRoots - which Google signing keys the naming system
///        trusts, and until when.
///
/// @notice Google rotates the keys it signs id_tokens with. This contract is
///         where the naming system learns the current ones, from a notarized
///         reading of Google's published JWKS.
///
/// @dev **Rotation is permissionless, and deliberately has no nullifier.** With
///      an open caller set a one-shot nullifier would BE the attack: a
///      front-runner could consume a proof's digest and brick the honest
///      keeper. Freshness comes from the notary signature plus the window
///      below, and re-applying the same rotation is idempotent.
///
///      **The rotation proof names no contract.** Its digest is over the TLS
///      session alone — domain, randoms, transcript root, timestamp — so the
///      same notarized reading of Google's JWKS is valid anywhere the notary is
///      trusted. That cross-deployment replay is a feature, and the digest
///      shape must not grow a chain id or a verifying-contract binding. Which
///      key is trusted lives in the shared Notary contract; the digest itself
///      stays this contract's own.
///
///      **Why a contract of its own.** A verifier should verify. Rotation is a
///      separate concern with a separate caller set and a separate key list,
///      and a second OIDC provider would want the same list.
///
///      **The trust model, in one line: the notary attests the reading, time
///      does the expiry, and nobody owns rotation.** Every entry carries a
///      stamp, verifiers check the stamp at use-site, and an expired key stops
///      being trusted with no transaction from anyone. The owner's only lever
///      over the key list is `untrustModulus`, which can only REMOVE trust.
contract IdentityJwksRoots is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    bytes32 private constant EXPECTED_DOMAIN_HASH = keccak256(bytes("www.googleapis.com"));
    bytes private constant EXPECTED_DOMAIN = bytes("www.googleapis.com");
    bytes private constant EXPECTED_ENDPOINT = bytes("/oauth2/v3/certs");
    uint256 public constant FRESHNESS_WINDOW = 1 hours;
    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 public constant DEFAULT_MODULUS_TTL = 30 days;
    /// The most distinct kids the list will track at once. Google publishes a
    /// handful of overlapping keys; a notarized reading cannot invent kids, so
    /// this cap is headroom, not a working limit. It exists so the enumeration
    /// below stays a bounded loop no submitter — honest or not — can bloat.
    uint256 public constant MAX_TRACKED_KIDS = 16;
    /// How much trusted runway `needsRotation()` insists on. Rotation re-stamps
    /// every key for DEFAULT_MODULUS_TTL, so a keeper acting on this signal
    /// rotates roughly weekly rather than racing the expiry.
    uint256 public constant RENEWAL_MARGIN = 7 days;

    /// @notice The Notary contract a rotation's attestation is checked with.
    INotary public notaryContract;

    /// @notice kid keccak -> the limb-keccak the circuit produces.
    mapping(bytes32 => bytes32) public modulusOfKid;
    mapping(bytes32 => uint256) public expiresAtKid;

    /// @notice modulusHash -> expiry. This is what a verifier reads: the JWT
    ///         circuit does not expose `kid`, so trust has to be checkable from
    ///         the modulus alone.
    mapping(bytes32 => uint256) public trustedHashExpiresAt;

    /// @notice When each kid was last written, by the rotation proof's own
    ///         timestamp. Rotation is open, so without this a replayed older
    ///         proof inside the freshness window would roll a kid back to a
    ///         modulus Google has retired and re-stamp it for another TTL.
    mapping(bytes32 => uint256) public rotatedAtKid;

    /// Every kid currently tracked, so keepers can enumerate the list without
    /// an indexer. Bounded by MAX_TRACKED_KIDS; expired entries leave via
    /// `prune()`, which anyone may call.
    bytes32[] private _trackedKids;
    /// kid keccak -> index+1 in `_trackedKids` (0 = not tracked).
    mapping(bytes32 => uint256) private _trackedKidIndex;
    /// The timestamp of the freshest reading ever applied — the notary's
    /// observation time, not the block it landed in. A keeper compares this to
    /// wall-clock to decide whether its reading would be news.
    uint256 public freshestObservedAt;

    /// Reserved for future upgrades (UUPS). New state is appended before this
    /// gap and the gap shrunk, so the layout survives.
    uint256[47] private __gap;

    event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
    event ModulusUntrusted(bytes32 indexed modulusHash);
    /// One key written by a rotation, with the reading's own timestamp. What a
    /// keeper watches: `observedAt` orders readings, `expiresAt` says when this
    /// entry stops being trusted if no rotation lands before then.
    event RootApplied(bytes32 indexed kidHash, bytes32 indexed modulusHash, uint256 observedAt, uint256 expiresAt);
    /// An expired key left the tracked set. Permissionless — time retired the
    /// key, `prune()` merely reclaimed the slot.
    event RootPruned(bytes32 indexed kidHash, bytes32 modulusHash);

    error ZeroAddress();
    error TooManyKids();
    error UnknownNotary();
    error WrongDomain();
    error FutureProof();
    error StaleProof();
    error MerkleMismatch();
    error PathTooLong();
    error MissingKidInLeaf();
    error MissingNInLeaf();
    error InvalidModulusLength();
    error InvalidB64Char();
    error InvalidB64Length();

    /// One notarized reading of Google's JWKS endpoint.
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

    /// One key from that reading.
    struct JwkClaim {
        bytes jwkBytes;
        bytes32[] jwkPath;
        bytes kid;
        bytes nB64url;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param notaryContract_ The shared Notary contract (INotary). Notary key
    ///        rotation happens THERE; this contract holds only the pointer.
    function initialize(address owner_, address notaryContract_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        if (notaryContract_ == address(0)) revert ZeroAddress();
        notaryContract = INotary(notaryContract_);
    }

    /// @notice The current notary signer, read through the Notary contract.
    function notary() external view returns (address) {
        return notaryContract.notary();
    }

    /// @notice Stop trusting a key before anything replaces it.
    ///
    /// @dev Rotation already retires the key a kid used to carry, which covers
    ///      the ordinary case. This covers the one that cannot wait: a key
    ///      Google has not rotated yet, or has rotated in a way this list has
    ///      not seen. Without it the only remedy for a compromised modulus is
    ///      an upgrade, and a thirty-day stamp is a long time to hold a key
    ///      nobody should be signing with.
    ///
    ///      Owner-only, and it can only ever REMOVE trust: the worst an owner
    ///      does with it is refuse bindings, which the rotation any keeper can
    ///      submit undoes.
    function untrustModulus(bytes32 modulusHash) external onlyOwner {
        delete trustedHashExpiresAt[modulusHash];
        emit ModulusUntrusted(modulusHash);
    }

    /// @notice Apply a notarized reading of Google's JWKS. Anyone may call it.
    ///         The proof is the whole authorization: a keeper needs gas and
    ///         nothing else — no role, no allowlist, no owner anywhere in the
    ///         path.
    function rotate(NotarizedJwksProof calldata proof, JwkClaim[] calldata claims) external {
        _rotate(proof, claims);
    }

    /// @notice Drop every expired kid from the tracked set. Anyone may call it.
    ///
    /// @dev Expiry itself needs no transaction — verifiers check the stamp at
    ///      use-site, so an expired key is already untrusted the second its TTL
    ///      passes. Pruning only reclaims enumeration slots (and the storage
    ///      refund). Rotation calls this by itself when the set is full, so
    ///      even the prune is optional housekeeping.
    function prune() external {
        _pruneExpired();
    }

    // ─── Keeper views ─────────────────────────────────────────────

    /// One tracked key, as a keeper sees it.
    struct RootInfo {
        bytes32 kidHash;
        bytes32 modulusHash;
        /// The notarized reading that last wrote this kid (proof timestamp).
        uint256 observedAt;
        /// When this entry stops being trusted, absent a fresher rotation.
        uint256 expiresAt;
    }

    /// @notice Every tracked key with its provenance and expiry, expired ones
    ///         included until someone prunes. One call tells a keeper the whole
    ///         state of the list.
    function currentRoots() external view returns (RootInfo[] memory infos) {
        uint256 n = _trackedKids.length;
        infos = new RootInfo[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 kidHash = _trackedKids[i];
            infos[i] = RootInfo({
                kidHash: kidHash,
                modulusHash: modulusOfKid[kidHash],
                observedAt: rotatedAtKid[kidHash],
                expiresAt: expiresAtKid[kidHash]
            });
        }
    }

    /// @notice True when no key is guaranteed trusted RENEWAL_MARGIN from now —
    ///         the single bit a keeper polls to decide whether to fetch a fresh
    ///         reading. True from deployment until the first rotation lands.
    function needsRotation() external view returns (bool) {
        uint256 horizon = block.timestamp + RENEWAL_MARGIN;
        uint256 n = _trackedKids.length;
        for (uint256 i = 0; i < n; i++) {
            bytes32 modulusHash = modulusOfKid[_trackedKids[i]];
            if (trustedHashExpiresAt[modulusHash] > horizon) return false;
        }
        return true;
    }

    function _rotate(NotarizedJwksProof memory p, JwkClaim[] memory claims) internal {
        // The digest deliberately names no chain and no contract (see the
        // contract comment); the Notary contract checks the attestation over
        // it — EIP-191 + recover + signer compare today.
        bytes32 digest = _notaryDigest(p);
        if (!notaryContract.verify(digest, p.notarySignature)) revert UnknownNotary();

        if (p.timestamp > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > p.timestamp + FRESHNESS_WINDOW) revert StaleProof();

        if (p.domainHash != EXPECTED_DOMAIN_HASH) revert WrongDomain();
        _verifyLeaf(p.domainPath, p.transcriptRoot, "domain:", EXPECTED_DOMAIN);
        _verifyLeaf(p.endpointPath, p.transcriptRoot, "endpoint:", EXPECTED_ENDPOINT);

        // Monotonic high-water mark of reading timestamps. Replaying an older
        // proof leaves it alone, so it only ever moves forward.
        if (p.timestamp > freshestObservedAt) freshestObservedAt = p.timestamp;

        uint256 expiry = block.timestamp + DEFAULT_MODULUS_TTL;
        for (uint256 i = 0; i < claims.length; i++) {
            _processClaim(claims[i], p.transcriptRoot, expiry, p.timestamp);
        }
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
        // Ignore a claim proved no later than the one already applied — the
        // monotonic rule that makes replay harmless. Rotation is open and a
        // proof binds no contract, so anyone can replay any still-fresh
        // reading anywhere, forever; ignoring (never reverting) keeps a
        // front-runner from bricking the honest keeper's batch by landing one
        // claim from it first, and skipping (never applying) keeps an older
        // reading from rolling a kid back or re-stamping its TTL.
        if (provenAt < rotatedAtKid[kidHash]) return;
        bytes32 previous = modulusOfKid[kidHash];
        // A byte-identical resubmission of the applied reading is a no-op:
        // nothing is written, nothing is emitted, and in particular the TTL is
        // NOT re-stamped — so spamming the same proof neither grows state nor
        // stretches trust.
        if (provenAt == rotatedAtKid[kidHash] && previous == modulusHash) return;
        rotatedAtKid[kidHash] = provenAt;

        // The key this kid used to carry stops being trusted NOW, rather than
        // when its thirty-day stamp runs out.
        //
        // The verifier resolves by modulus, not by kid, so leaving the old
        // entry keeps a retired key usable for the rest of its TTL — which is
        // exactly the window a compromised key would be used in. Google
        // publishes overlapping keys and tokens live about an hour, so the cost
        // is that a token signed by the key Google just retired stops verifying
        // a little early; the user signs in again.
        if (previous != bytes32(0) && previous != modulusHash) {
            delete trustedHashExpiresAt[previous];
            emit ModulusUntrusted(previous);
        } else if (previous == bytes32(0)) {
            _trackKid(kidHash);
        }

        modulusOfKid[kidHash] = modulusHash;
        expiresAtKid[kidHash] = expiry;
        trustedHashExpiresAt[modulusHash] = expiry;
        emit ModulusRotated(kidHash, string(c.kid), modulusHash, expiry);
        emit RootApplied(kidHash, modulusHash, provenAt, expiry);
    }

    /// Add a kid to the enumeration. Growth is doubly bounded: a kid can only
    /// enter through a notarized reading of Google's own JWKS (a submitter
    /// cannot invent one), and the set is capped — when full, expired entries
    /// are pruned to make room, and only a set full of LIVE keys refuses.
    function _trackKid(bytes32 kidHash) internal {
        if (_trackedKidIndex[kidHash] != 0) return;
        if (_trackedKids.length >= MAX_TRACKED_KIDS) {
            _pruneExpired();
            if (_trackedKids.length >= MAX_TRACKED_KIDS) revert TooManyKids();
        }
        _trackedKids.push(kidHash);
        _trackedKidIndex[kidHash] = _trackedKids.length;
    }

    /// Swap-remove every expired kid. `rotatedAtKid` survives on purpose: it is
    /// the monotonic floor that keeps a replayed old reading from resurrecting
    /// the entry the prune just removed.
    function _pruneExpired() internal {
        uint256 i = _trackedKids.length;
        while (i > 0) {
            i--;
            bytes32 kidHash = _trackedKids[i];
            if (expiresAtKid[kidHash] > block.timestamp) continue;

            bytes32 modulusHash = modulusOfKid[kidHash];
            delete modulusOfKid[kidHash];
            delete expiresAtKid[kidHash];
            // Only clear the verifier-facing stamp if it is genuinely spent —
            // it can sit above the kid's own expiry only if some fresher
            // rotation re-trusted the same modulus under another kid.
            if (trustedHashExpiresAt[modulusHash] <= block.timestamp) {
                delete trustedHashExpiresAt[modulusHash];
            }

            uint256 last = _trackedKids.length - 1;
            if (i != last) {
                bytes32 moved = _trackedKids[last];
                _trackedKids[i] = moved;
                _trackedKidIndex[moved] = i + 1;
            }
            _trackedKids.pop();
            delete _trackedKidIndex[kidHash];
            emit RootPruned(kidHash, modulusHash);
        }
    }

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
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would freeze the notary allowlist, and Google's keys
    ///      would expire with no way to replace them.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
