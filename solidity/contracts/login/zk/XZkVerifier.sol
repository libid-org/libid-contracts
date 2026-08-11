// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {IZkSessionVerifier} from "./IZkSessionVerifier.sol";

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// X ZK identity verifier — small token-only proof + two TLSN attestations.
/// Public-input layout is documented inline above the offset constants.
/// Registry (not this contract) enforces walletAddress semantics.
contract XZkVerifier is IZkSessionVerifier, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    struct TokenAttestation {
        bytes32 bearerHash;
        uint32 bearerRangeStart;
        uint32 bearerRangeEnd;
        bytes sentRevealed;
        uint64 timestamp;
        bytes notarySignature;
    }

    /// /me sentRevealed = concat of two TLSN-revealed ranges:
    ///   [0, bearerRangeStart)        — request line + headers up to and
    ///                                  including `authorization: Bearer `.
    ///                                  Ends at `sentPrefixEnd == bearerRangeStart`.
    ///   [bearerRangeEnd, bearerRangeEnd + 2) — exactly the 2 bytes after
    ///                                  the bearer, which MUST be CRLF.
    ///                                  Ends at `sentSuffixEnd == bearerRangeEnd + 2`.
    /// Anchoring the end of the bearer range canonicalizes `bearer_len`, so
    /// one real OAuth bearer hashes to exactly one nullifier (H1).
    struct MeAttestation {
        bytes32 bearerHash;
        uint32 bearerRangeStart;
        uint32 bearerRangeEnd;
        bytes sentRevealed;
        uint32 sentPrefixEnd;
        uint32 sentSuffixEnd;
        bytes recvRevealed;
        string handle;
        /// Immutable platform user-id from the same /me response (X `"id":"…"`).
        /// "" when the prover did not reveal it (handle-key fallback).
        string userId;
        address sessionAddr;
        uint64 timestamp;
        bytes notarySignature;
    }

    struct XProof {
        bytes proof;
        bytes32[] publicInputs;
        TokenAttestation tokenAttest;
        MeAttestation meAttest;
    }

    // PI layout: one byte per slot, low-byte of each bytes32.
    //   [  0..32) bearer_hash_token  SHA256(bearer || blinder_token)
    //   [ 32..64) bearer_hash_me     SHA256(bearer || blinder_me)
    //   [ 64..96) nullifier          keccak256(bearer_padded || len.be32)
    //   [ 96..116) wallet_address
    //   [116..136) session_addr
    uint256 private constant OFF_BEARER_HASH_TOKEN = 0;
    uint256 private constant OFF_BEARER_HASH_ME = 32;
    uint256 private constant OFF_NULLIFIER = 64;
    uint256 private constant OFF_WALLET_ADDR = 96;
    uint256 private constant OFF_SESSION_ADDR = 116;
    uint256 private constant TOTAL_PUBLIC_INPUTS = 136;

    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 private constant ZK_PROOF_TTL = 10 minutes;
    uint256 private constant MAX_CLIENT_ID_LEN = 64;
    /// Allowlist size cap. Verification scans the revealed request once per
    /// entry, so this bounds worst-case gas for `_anyClientIdMatches`.
    uint256 private constant MAX_CLIENT_IDS = 16;
    uint256 private constant MAX_REVEALED_LEN = 4096;
    uint256 private constant MAX_HANDLE_LEN = 32;

    /// Domain-sep tags for the single notary key.
    bytes32 internal constant OP_TOKEN_ATTEST = keccak256("XZkVerifier.token.v1");
    bytes32 internal constant OP_ME_ATTEST = keccak256("XZkVerifier.me.v1");

    address public notary;
    IHonkVerifier public honkVerifier;
    string public endpoint;
    string public handlePrefix;
    string public override platformName;

    /// Allowed OAuth `client_id`s. A /token proof passes when the revealed
    /// request carries ANY of them (see `_anyClientIdMatches`). Kept as an array
    /// because matching is a substring search over the revealed request, not a
    /// lookup by a caller-supplied id.
    bytes[] private _clientIds;
    /// keccak256(client_id) => allowed. Mirrors `_clientIds` for O(1) membership
    /// and dedupe.
    mapping(bytes32 => bool) public isClientIdAllowed;
    /// When true, ANY client_id is accepted.
    ///
    /// Deliberately a separate flag: an EMPTY allowlist means DENY ALL, never
    /// "allow everyone". Conflating "not configured yet" with "intentionally
    /// permissive" would let an unseeded deploy, a botched migration, or removal
    /// of the last entry silently drop the app binding (fail-open). Enabling this
    /// removes the proof that the notarized /token came from a known OAuth app —
    /// any app's token can then register a session. That is the permissionless
    /// model, so it must be an explicit, evented choice.
    bool public openClientIds;

    /// X `/me` numeric id is JSON `"id":"<digits>"`. Fixed for this platform,
    /// so it's a constant rather than an init param (no deploy-signature change).
    string private constant ID_PREFIX = "\"id\":\"";
    string private constant ID_SUFFIX = "\"";

    error InvalidPublicInputsLength();
    error ZkVerificationFailed();
    error NotaryVerificationFailed();
    error FutureProof();
    error StaleProof();
    error BearerHashMismatch();
    error ClientIdMismatch();
    error MeRequestPrefixMismatch();
    error MeBearerAdjacencyMismatch();
    error MeBearerEndAdjacencyMismatch();
    error MeBearerEndNotCrlf();
    error MeBadSentLayout();
    error HandleNotFound();
    error IdNotFound();
    error EmptyHandle();
    error HandleTooLong();
    error RevealedTooLong();
    error SessionAddrMismatch();
    error ClientIdAlreadyAllowed();
    error ClientIdNotAllowed();
    error TooManyClientIds();
    error BadClientIdLength();

    event ClientIdAdded(bytes clientId);
    event ClientIdRemoved(bytes clientId);
    /// Emitted on every permissive-mode toggle so the trust change is auditable.
    event OpenClientIdsSet(bool open);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _notary,
        IHonkVerifier _honkVerifier,
        bytes calldata _xClientId,
        string calldata _endpoint,
        string calldata _handlePrefix,
        string calldata _platformName
    ) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        require(_notary != address(0), "zero notary");
        require(address(_honkVerifier) != address(0), "zero verifier");
        require(bytes(_endpoint).length > 0, "empty endpoint");
        require(bytes(_handlePrefix).length > 0, "empty prefix");
        require(bytes(_platformName).length > 0, "empty platform");
        notary = _notary;
        honkVerifier = _honkVerifier;
        // Seed the allowlist with the deploying app so existing deployments and
        // the unchanged deploy signature keep working.
        _addClientId(_xClientId);
        endpoint = _endpoint;
        handlePrefix = _handlePrefix;
        platformName = _platformName;
    }

    function setNotary(address _v) external onlyOwner {
        require(_v != address(0), "zero notary");
        notary = _v;
    }

    function setHonkVerifier(IHonkVerifier _v) external onlyOwner {
        require(address(_v) != address(0), "zero verifier");
        honkVerifier = _v;
    }

    /// Allow one more OAuth app's `client_id` to register sessions here.
    function addClientId(bytes calldata _id) external onlyOwner {
        _addClientId(_id);
    }

    /// Revoke a `client_id`. Removing the last entry leaves the allowlist EMPTY,
    /// which denies everything (unless `openClientIds` is explicitly on) — that
    /// fail-closed outcome is intentional.
    function removeClientId(bytes calldata _id) external onlyOwner {
        bytes32 key = keccak256(_id);
        if (!isClientIdAllowed[key]) revert ClientIdNotAllowed();
        delete isClientIdAllowed[key];

        uint256 n = _clientIds.length;
        for (uint256 i = 0; i < n; i++) {
            if (keccak256(_clientIds[i]) == key) {
                _clientIds[i] = _clientIds[n - 1];
                _clientIds.pop();
                break;
            }
        }
        emit ClientIdRemoved(_id);
    }

    /// Accept ANY client_id. See `openClientIds` — this drops the app binding
    /// and is a trust-model change, not a config knob.
    function setOpenClientIds(bool _open) external onlyOwner {
        openClientIds = _open;
        emit OpenClientIdsSet(_open);
    }

    function clientIdCount() external view returns (uint256) {
        return _clientIds.length;
    }

    function clientIdAt(uint256 _i) external view returns (bytes memory) {
        return _clientIds[_i];
    }

    function _addClientId(bytes memory _id) internal {
        if (_id.length == 0 || _id.length > MAX_CLIENT_ID_LEN) revert BadClientIdLength();
        if (_clientIds.length >= MAX_CLIENT_IDS) revert TooManyClientIds();
        bytes32 key = keccak256(_id);
        if (isClientIdAllowed[key]) revert ClientIdAlreadyAllowed();
        isClientIdAllowed[key] = true;
        _clientIds.push(_id);
        emit ClientIdAdded(_id);
    }

    function setEndpoint(string calldata _endpoint) external onlyOwner {
        require(bytes(_endpoint).length > 0, "empty endpoint");
        endpoint = _endpoint;
    }

    function setHandlePrefix(string calldata _prefix) external onlyOwner {
        require(bytes(_prefix).length > 0, "empty prefix");
        handlePrefix = _prefix;
    }

    function setPlatformName(string calldata _name) external onlyOwner {
        require(bytes(_name).length > 0, "empty platform");
        platformName = _name;
    }

    function verifyAndExtract(bytes calldata payload)
        external
        view
        override
        returns (
            string memory handle,
            address sessionKey,
            address walletAddress,
            uint256 expiresAt,
            bytes32 nullifier,
            string memory userId
        )
    {
        XProof calldata p = _decode(payload);

        if (p.publicInputs.length != TOTAL_PUBLIC_INPUTS) revert InvalidPublicInputsLength();
        if (p.tokenAttest.sentRevealed.length > MAX_REVEALED_LEN) revert RevealedTooLong();
        if (p.meAttest.sentRevealed.length > MAX_REVEALED_LEN) revert RevealedTooLong();
        if (p.meAttest.recvRevealed.length > MAX_REVEALED_LEN) revert RevealedTooLong();
        if (bytes(p.meAttest.handle).length == 0) revert EmptyHandle();
        if (bytes(p.meAttest.handle).length > MAX_HANDLE_LEN) revert HandleTooLong();

        _checkTimestamp(p.tokenAttest.timestamp);
        _checkTimestamp(p.meAttest.timestamp);

        // Dual-blinder cross-bind: same bearer hashes to BOTH commits via the
        // circuit, but with different blinders (one per TLSN session).
        if (_extractBytes32(p.publicInputs, OFF_BEARER_HASH_TOKEN) != p.tokenAttest.bearerHash) {
            revert BearerHashMismatch();
        }
        if (_extractBytes32(p.publicInputs, OFF_BEARER_HASH_ME) != p.meAttest.bearerHash) {
            revert BearerHashMismatch();
        }

        // sessionAddr from PI must equal notary-signed value in meAttest.
        address piSession = _extractAddress(p.publicInputs, OFF_SESSION_ADDR);
        if (piSession != p.meAttest.sessionAddr) revert SessionAddrMismatch();

        // /token: client_id bound + notary sig.
        if (!_anyClientIdMatches(p.tokenAttest.sentRevealed)) revert ClientIdMismatch();
        _verifyTokenSig(p.tokenAttest);

        // /me: request structure + handle present in RECV + notary sig.
        _verifyMeRequestStructure(p.meAttest);
        _verifyHandleInRecv(p.meAttest);
        _verifyIdInRecv(p.meAttest);
        _verifyMeSig(p.meAttest);

        // ZK proof (token-only).
        if (!honkVerifier.verify(p.proof, p.publicInputs)) revert ZkVerificationFailed();

        handle = p.meAttest.handle;
        userId = p.meAttest.userId;
        sessionKey = piSession;
        walletAddress = _extractAddress(p.publicInputs, OFF_WALLET_ADDR);
        bytes32 rawNullifier = _extractBytes32(p.publicInputs, OFF_NULLIFIER);
        nullifier = keccak256(abi.encode(keccak256(bytes(platformName)), rawNullifier));
        // TTL anchored to the OLDER of the two attestations -- the proof is
        // only as fresh as its stalest input.
        uint256 anchorTs = uint256(p.tokenAttest.timestamp) < uint256(p.meAttest.timestamp)
            ? uint256(p.tokenAttest.timestamp)
            : uint256(p.meAttest.timestamp);
        expiresAt = anchorTs + ZK_PROOF_TTL;
    }

    function _extractBytes32(bytes32[] calldata pi, uint256 offset) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let r := 0
            let src := add(pi.offset, mul(offset, 0x20))
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                r := or(r, shl(mul(sub(31, i), 8), and(calldataload(add(src, mul(i, 0x20))), 0xff)))
            }
            result := r
        }
    }

    function _extractAddress(bytes32[] calldata pi, uint256 offset) internal pure returns (address result) {
        assembly ("memory-safe") {
            let r := 0
            let src := add(pi.offset, mul(offset, 0x20))
            for { let i := 0 } lt(i, 20) { i := add(i, 1) } {
                r := or(r, shl(mul(sub(19, i), 8), and(calldataload(add(src, mul(i, 0x20))), 0xff)))
            }
            result := r
        }
    }

    function _decode(bytes calldata payload) internal pure returns (XProof calldata p) {
        assembly ("memory-safe") {
            p := add(payload.offset, calldataload(payload.offset))
        }
    }

    function _checkTimestamp(uint64 ts) internal view {
        if (ts > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > uint256(ts) + ZK_PROOF_TTL) revert StaleProof();
    }

    function _verifyMeRequestStructure(MeAttestation calldata att) internal view {
        bytes memory prefix = abi.encodePacked("GET ", endpoint, " HTTP/1.1\r\n");
        bytes memory authSuffix = bytes("authorization: Bearer ");

        bytes memory sent = att.sentRevealed;

        // H1: sentRevealed is concat of [prefix part] ++ [2-byte CRLF post-bearer].
        // Length must be exactly `prefixLen + 2`. `prefixLen` = sentPrefixEnd
        // because the prefix range starts at offset 0.
        uint256 prefixLen = uint256(att.sentPrefixEnd);
        if (sent.length != prefixLen + 2) revert MeBadSentLayout();
        if (prefixLen < prefix.length + authSuffix.length) revert MeRequestPrefixMismatch();

        // Prefix part [0..prefixLen) must start with `GET ... HTTP/1.1\r\n` and
        // end with `authorization: Bearer `.
        for (uint256 i = 0; i < prefix.length; i++) {
            if (sent[i] != prefix[i]) revert MeRequestPrefixMismatch();
        }
        uint256 suffixStart = prefixLen - authSuffix.length;
        for (uint256 i = 0; i < authSuffix.length; i++) {
            if (sent[suffixStart + i] != authSuffix[i]) revert MeRequestPrefixMismatch();
        }

        // Start adjacency: bearer starts immediately after the revealed prefix.
        if (att.sentPrefixEnd != att.bearerRangeStart) revert MeBearerAdjacencyMismatch();

        // End adjacency (H1): the second revealed range covers exactly the 2
        // bytes immediately after the bearer.
        if (att.sentSuffixEnd != att.bearerRangeEnd + 2) revert MeBearerEndAdjacencyMismatch();

        // The trailing 2 bytes of sentRevealed are the post-bearer bytes. They
        // MUST be CRLF. Bearer is base64url; `\r\n` cannot appear inside it,
        // so truncating the bearer range and re-anchoring on a fake CRLF
        // elsewhere in the request is impossible without rewriting the wire.
        if (sent[prefixLen] != 0x0d) revert MeBearerEndNotCrlf();
        if (sent[prefixLen + 1] != 0x0a) revert MeBearerEndNotCrlf();
    }

    function _verifyHandleInRecv(MeAttestation calldata att) internal view {
        bytes memory needle = abi.encodePacked(handlePrefix, att.handle, '"');
        bytes memory prefix = bytes(handlePrefix);
        bytes memory haystack = att.recvRevealed;
        if (prefix.length == 0 || haystack.length < needle.length) revert HandleNotFound();

        // Single pass: count `handlePrefix` occurrences and verify the full
        // needle matches at the unique prefix hit. Rejecting >1 prefix hit
        // defends against an unescaped upstream field containing a synthetic
        // `"username":"<attacker>"`.
        uint256 needleStart = type(uint256).max;
        uint256 hits = 0;
        uint256 limit = haystack.length - prefix.length + 1;
        for (uint256 i = 0; i < limit; i++) {
            bool m = true;
            for (uint256 j = 0; j < prefix.length; j++) {
                if (haystack[i + j] != prefix[j]) {
                    m = false;
                    break;
                }
            }
            if (m) {
                hits++;
                if (hits > 1) revert HandleNotFound();
                needleStart = i;
            }
        }
        if (hits == 0) revert HandleNotFound();
        if (needleStart + needle.length > haystack.length) revert HandleNotFound();
        for (uint256 j = 0; j < needle.length; j++) {
            if (haystack[needleStart + j] != needle[j]) revert HandleNotFound();
        }
    }

    /// Verify the immutable user-id is present in the notary-attested /me recv
    /// bytes as `"id":"<userId>"`. Empty userId → skip (handle-key fallback).
    /// Same unique-prefix-hit guard as the handle check.
    function _verifyIdInRecv(MeAttestation calldata att) internal pure {
        // Id is required — identity binds on the immutable platform id, not the
        // mutable handle. An attestation without a revealed id is rejected.
        if (bytes(att.userId).length == 0) revert IdNotFound();
        bytes memory needle = abi.encodePacked(ID_PREFIX, att.userId, ID_SUFFIX);
        bytes memory prefix = bytes(ID_PREFIX);
        bytes memory haystack = att.recvRevealed;
        if (haystack.length < needle.length) revert IdNotFound();

        uint256 needleStart = type(uint256).max;
        uint256 hits = 0;
        uint256 limit = haystack.length - prefix.length + 1;
        for (uint256 i = 0; i < limit; i++) {
            bool m = true;
            for (uint256 j = 0; j < prefix.length; j++) {
                if (haystack[i + j] != prefix[j]) {
                    m = false;
                    break;
                }
            }
            if (m) {
                hits++;
                if (hits > 1) revert IdNotFound();
                needleStart = i;
            }
        }
        if (hits == 0) revert IdNotFound();
        if (needleStart + needle.length > haystack.length) revert IdNotFound();
        for (uint256 j = 0; j < needle.length; j++) {
            if (haystack[needleStart + j] != needle[j]) revert IdNotFound();
        }
    }

    function _verifyTokenSig(TokenAttestation calldata att) internal view {
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                keccak256(bytes(platformName)),
                OP_TOKEN_ATTEST,
                att.bearerHash,
                uint256(att.bearerRangeStart),
                uint256(att.bearerRangeEnd),
                keccak256(att.sentRevealed),
                uint256(att.timestamp)
            )
        );
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        if (ECDSA.recover(ethHash, att.notarySignature) != notary) revert NotaryVerificationFailed();
    }

    function _verifyMeSig(MeAttestation calldata att) internal view {
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                keccak256(bytes(platformName)),
                OP_ME_ATTEST,
                att.bearerHash,
                uint256(att.bearerRangeStart),
                uint256(att.bearerRangeEnd),
                keccak256(att.sentRevealed),
                uint256(att.sentPrefixEnd),
                uint256(att.sentSuffixEnd),
                keccak256(att.recvRevealed),
                keccak256(bytes(att.handle)),
                keccak256(bytes(att.userId)),
                att.sessionAddr,
                uint256(att.timestamp)
            )
        );
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        if (ECDSA.recover(ethHash, att.notarySignature) != notary) revert NotaryVerificationFailed();
    }

    /// True when the revealed /token request carries an accepted `client_id`.
    /// An empty allowlist matches nothing: "unconfigured" denies rather than
    /// allows.
    ///
    /// Scans the revealed request ONCE, extracts the `client_id=` value, and
    /// answers from the `isClientIdAllowed` mirror. The previous shape re-ran
    /// the full O(revealedLen) scan per allowlist entry, so a proof from the
    /// last-listed app paid MAX_CLIENT_IDS times the dominant cost of
    /// `verifyAndExtract` — enough to push `register_session_zk` toward the
    /// block gas limit for exactly the multi-app case the allowlist exists to
    /// serve. Cost is now independent of how many ids are configured.
    function _anyClientIdMatches(bytes memory revealed) internal view returns (bool) {
        if (openClientIds) return true;
        if (_clientIds.length == 0) return false;

        bytes10 needle = "client_id=";
        uint256 revealedLen = revealed.length;
        if (revealedLen < 11) return false;

        uint256 limit = revealedLen - 10;
        for (uint256 i = 0; i < limit; i++) {
            bool m = true;
            for (uint256 j = 0; j < 10; j++) {
                if (revealed[i + j] != needle[j]) {
                    m = false;
                    break;
                }
            }
            if (!m) continue;

            // Value runs to `&`, CR, or end-of-buffer. Bounded by
            // MAX_CLIENT_ID_LEN so a pathological revealed buffer cannot make
            // this scan unbounded; an over-long value simply fails to match.
            uint256 start = i + 10;
            uint256 end = start;
            while (end < revealedLen) {
                bytes1 b = revealed[end];
                if (b == 0x26 || b == 0x0d) break;
                unchecked {
                    ++end;
                }
                if (end - start > MAX_CLIENT_ID_LEN) break;
            }
            uint256 valueLen = end - start;
            if (valueLen == 0 || valueLen > MAX_CLIENT_ID_LEN) continue;

            bytes memory value = new bytes(valueLen);
            for (uint256 j = 0; j < valueLen; j++) {
                value[j] = revealed[start + j];
            }
            if (isClientIdAllowed[keccak256(value)]) return true;
        }
        return false;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing ownership is disabled: a zero owner would permanently
    ///      brick the UUPS upgrade path and every admin function.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
