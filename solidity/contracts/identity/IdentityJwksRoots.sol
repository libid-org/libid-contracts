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
contract IdentityJwksRoots is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    bytes32 private constant EXPECTED_DOMAIN_HASH = keccak256(bytes("www.googleapis.com"));
    bytes private constant EXPECTED_DOMAIN = bytes("www.googleapis.com");
    bytes private constant EXPECTED_ENDPOINT = bytes("/oauth2/v3/certs");
    uint256 public constant FRESHNESS_WINDOW = 1 hours;
    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 public constant DEFAULT_MODULUS_TTL = 30 days;

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

    /// Reserved for future upgrades (UUPS). New state is appended before this
    /// gap and the gap shrunk, so the layout survives.
    uint256[50] private __gap;

    event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
    event ModulusUntrusted(bytes32 indexed modulusHash);

    error ZeroAddress();
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
    function rotate(NotarizedJwksProof calldata proof, JwkClaim[] calldata claims) external {
        _rotate(proof, claims);
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
        // Ignore a claim proved no later than the one already applied. Equal
        // timestamps re-apply identical values, so replay stays idempotent
        // rather than reverting — a revert would let a front-runner grief the
        // keeper's batch by landing one claim from it first.
        if (provenAt < rotatedAtKid[kidHash]) return;
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
        bytes32 previous = modulusOfKid[kidHash];
        if (previous != bytes32(0) && previous != modulusHash) {
            delete trustedHashExpiresAt[previous];
            emit ModulusUntrusted(previous);
        }

        modulusOfKid[kidHash] = modulusHash;
        expiresAtKid[kidHash] = expiry;
        trustedHashExpiresAt[modulusHash] = expiry;
        emit ModulusRotated(kidHash, string(c.kid), modulusHash, expiry);
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
