// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {CeremonyAttestation} from "../ceremony/CeremonyAttestation.sol";
import {INotaryService} from "../ceremony/INotaryService.sol";

/// @title IdentityJwksRoots - which Google signing keys the naming system
///        trusts, and until when.
///
/// @notice Google rotates the keys it signs id_tokens with. This contract is
///         where the naming system learns the current ones, from a notarized
///         reading of Google's published JWKS.
///
/// @dev The reading is an ordinary notarized session -- the section 9.1
///      record every Platform Verifier consumes, authenticated by the same
///      Notary Service and charged the same Notary Fee. What differs is the
///      layout the keeper's prover produces: everything in both directions is
///      revealed and nothing is committed. A public key set has nothing to
///      hide, and zero commitments is what lets this contract read the
///      transcript by concatenation safely -- with exact coverage and no
///      commitment, a cut between ranges cannot hide bytes.
///
///      **Rotation is permissionless, and deliberately has no nullifier.** With
///      an open caller set a one-shot nullifier would BE the attack: a
///      front-runner could consume a reading's digest and brick the honest
///      keeper. Freshness comes from the notary's signed `createdAt` plus the
///      window below, and re-applying the same reading is idempotent. A
///      rotation pays the Notary Fee, which is the one thing a submitter
///      needs beyond gas.
///
///      **The reading names no contract.** The attested record is the TLS
///      session alone -- authority, notary clock, transcript -- so the same
///      notarized reading of Google's JWKS is valid anywhere the notary key is
///      trusted. That cross-deployment replay is a feature, and the record
///      must not grow a chain id or a verifying-contract binding. Which key is
///      trusted lives in the shared Notary Service; the transcript checks stay
///      this contract's own.
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
    // ─── State ──────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:libid.storage.IdentityJwksRoots
    struct IdentityJwksRootsStorage {
        /// Authenticates a reading and charges for it.
        INotaryService notary;
        /// kid keccak -> the limb-keccak the circuit produces.
        mapping(bytes32 => bytes32) modulusOfKid;
        mapping(bytes32 => uint256) expiresAtKid;
        /// modulusHash -> expiry. This is what a verifier reads: the JWT
        /// circuit does not expose `kid`, so trust has to be checkable from
        /// the modulus alone.
        mapping(bytes32 => uint256) trustedHashExpiresAt;
        /// When each kid was last written, by the reading's own `createdAt`.
        /// Rotation is open, so without this a replayed older reading inside
        /// the freshness window would roll a kid back to a modulus Google has
        /// retired and re-stamp it for another TTL.
        mapping(bytes32 => uint256) rotatedAtKid;
        /// Every kid currently tracked, so keepers can enumerate the list
        /// without an indexer. Bounded by MAX_TRACKED_KIDS; expired entries
        /// leave via `prune()`, which anyone may call.
        bytes32[] trackedKids;
        /// kid keccak -> index+1 in `trackedKids` (0 = not tracked).
        mapping(bytes32 => uint256) trackedKidIndex;
        /// The timestamp of the freshest reading ever applied -- the notary's
        /// observation time, not the block it landed in. A keeper compares
        /// this to wall-clock to decide whether its reading would be news.
        uint256 freshestObservedAt;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.IdentityJwksRoots")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITY_JWKS_ROOTS_STORAGE =
        0x1aceb787a5cb65251c62e0afbe6fbce480e0d1c9636ff7b90cdca2969527ef00;

    function _s() private pure returns (IdentityJwksRootsStorage storage $) {
        assembly {
            $.slot := IDENTITY_JWKS_ROOTS_STORAGE
        }
    }

    // ─── Constants ──────────────────────────────────────────────────

    /// @notice The TLS server name the notary must have authenticated.
    bytes32 public constant AUTHORITY = keccak256("www.googleapis.com");
    uint256 public constant FRESHNESS_WINDOW = 1 hours;
    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 public constant DEFAULT_MODULUS_TTL = 30 days;
    /// The most distinct kids the list will track at once. Google publishes a
    /// handful of overlapping keys; a notarized reading cannot invent kids, so
    /// this cap is headroom, not a working limit. It exists so the enumeration
    /// below stays a bounded loop no submitter -- honest or not -- can bloat.
    uint256 public constant MAX_TRACKED_KIDS = 16;
    /// How much trusted runway `needsRotation()` insists on. Rotation re-stamps
    /// every key for DEFAULT_MODULUS_TTL, so a keeper acting on this signal
    /// rotates roughly weekly rather than racing the expiry.
    uint256 public constant RENEWAL_MARGIN = 7 days;

    /// @dev The request line the keeper's prover puts on the wire, in
    ///      origin-form like every other verifier pins it. The path is what
    ///      separates the key set from everything else googleapis.com serves.
    bytes private constant REQUEST_LINE = "GET /oauth2/v3/certs HTTP/1.1\r\n";
    /// @dev googleapis.com serves many virtual hosts under one certificate, so
    ///      the TLS authority alone does not pin which backend answered. The
    ///      `Host` header does, and the notary signed it.
    bytes private constant HOST_NEEDLE = "\r\nhost:";
    bytes private constant EXPECTED_HOST = "www.googleapis.com";
    bytes private constant STATUS_LINE = "HTTP/1.1 200 ";
    bytes private constant HEAD_BOUNDARY = "\r\n\r\n";
    bytes private constant CHUNKED_NEEDLE = "\r\ntransfer-encoding:chunked\r\n";
    bytes private constant CONTENT_LENGTH_NEEDLE = "\r\ncontent-length:";
    bytes private constant KEYS_TOKEN = '"keys"';

    uint256 private constant MODULUS_BYTES = 256;
    uint256 private constant MODULUS_LIMBS = 18;

    // ─── Events ─────────────────────────────────────────────────────

    event NotaryServiceChanged(address notary);
    event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
    event ModulusUntrusted(bytes32 indexed modulusHash);
    /// One key written by a rotation, with the reading's own timestamp. What a
    /// keeper watches: `observedAt` orders readings, `expiresAt` says when this
    /// entry stops being trusted if no rotation lands before then.
    event RootApplied(bytes32 indexed kidHash, bytes32 indexed modulusHash, uint256 observedAt, uint256 expiresAt);
    /// An expired key left the tracked set. Permissionless -- time retired the
    /// key, `prune()` merely reclaimed the slot.
    event RootPruned(bytes32 indexed kidHash, bytes32 modulusHash);

    // ─── Errors ─────────────────────────────────────────────────────

    error ZeroAddress();
    error TooManyKids();
    /// @dev Exact value, both ways: the Notary Fee is forwarded whole, so there
    ///      is no overpayment to refund and nothing captured in transit.
    error WrongValue(uint256 required, uint256 provided);
    error WrongAuthority(bytes32 expected, bytes32 found);
    error FutureProof();
    error StaleProof();
    /// @dev A direction carries a commitment. The reading must hide nothing:
    ///      a hidden byte is a byte this contract reads around, and the join
    ///      below is only safe when there is nothing to read around.
    error HiddenBytes();
    /// @dev The first revealed range of a direction does not begin the
    ///      transcript, so nothing says the bytes read as the request line (or
    ///      the status line) are it. Raised for either direction; a direction
    ///      revealing nothing reports `type(uint32).max`.
    error RequestLineNotAtOrigin(uint32 start);
    /// @dev Not `GET /oauth2/v3/certs HTTP/1.1\r\n`.
    error WrongRequestLine();
    error NotOneHostHeader(uint256 count);
    error WrongHost();
    /// @dev Not `HTTP/1.1 200 `.
    error WrongStatusLine();
    /// @dev A direction with no blank line ending its head. Raised for the
    ///      request too: its `Host` count runs over the head alone, and a
    ///      request whose head never ends has no head to count in.
    error NoHeadBoundary();
    error BadChunkFraming();
    /// @dev The declared `Content-Length` is not the body the transcript
    ///      carries. A value that is not a decimal declares no length any
    ///      body can match.
    error ContentLengthMismatch(uint256 declared, uint256 found);
    /// @dev The member is absent, or present but not in the shape read here:
    ///      `keys` must be an array, `kid` and `n` must be strings.
    error MissingMember(string name);
    error AmbiguousMember(string name);
    /// @dev A string value with no closing quote, or the `keys` array with no
    ///      closing bracket (or an element that is not an object).
    error UnterminatedMember(string name);
    /// @dev A backslash inside a value this contract reads. Neither a kid nor
    ///      a base64url modulus needs one, and unescaping is a parser this
    ///      contract does not carry.
    error EscapedValue(string name);
    /// @dev `{` or `[` inside a JWK object.
    error UnexpectedNesting();
    /// @dev Bytes other than SP/HTAB/CR/LF after the closing `}`.
    error TrailingBytes();
    error InvalidModulusLength();
    error InvalidB64Char();
    error InvalidB64Length();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param notary_ The shared Notary Service. Notary key rotation happens
    ///        THERE; this contract holds only the pointer.
    function initialize(address owner_, INotaryService notary_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setNotaryService(notary_);
    }

    // ─── The Notary Service ─────────────────────────────────────────

    function notaryService() external view returns (address) {
        return address(_s().notary);
    }

    /// @notice Point the list at another Notary Service.
    /// @dev The service is the trust root for every reading, so this is the
    ///      owner's one lever over what a rotation can install -- the same
    ///      lever every Platform Verifier's owner holds over its trust roots.
    function setNotaryService(INotaryService notary_) external onlyOwner {
        _setNotaryService(notary_);
    }

    function _setNotaryService(INotaryService notary_) private {
        if (address(notary_) == address(0)) revert ZeroAddress();
        _s().notary = notary_;
        emit NotaryServiceChanged(address(notary_));
    }

    /// @notice What one rotation costs: the Notary Fee, forwarded whole.
    function quoteRotation() external view returns (uint256) {
        return _s().notary.fee();
    }

    // ─── Rotation ───────────────────────────────────────────────────

    /// @notice Apply a notarized reading of Google's JWKS. Anyone may call it.
    ///         The reading is the whole authorization: a keeper needs gas and
    ///         the Notary Fee, and nothing else -- no role, no allowlist, no
    ///         owner anywhere in the path.
    ///
    /// @param attestedData The exact bytes of ceremony-common section 9.1.
    /// @param proof        The notary's authentication of them, opaque here.
    function rotate(bytes calldata attestedData, bytes calldata proof) external payable {
        IdentityJwksRootsStorage storage $ = _s();

        // Exact value, so there is no refund path to get wrong and no value
        // can be captured in transit.
        uint256 fee = $.notary.fee();
        if (msg.value != fee) revert WrongValue(fee, msg.value);

        // Authenticated and decoded in one call. The Notary Service owns the
        // format its key vouches for; everything read below is a field it
        // handed back, never a byte this contract decoded on its own.
        CeremonyAttestation.AttestedData memory data = $.notary.verify{value: fee}(attestedData, proof);

        // The one thing in the record the notary observed rather than was
        // told: the TLS server name it authenticated in the handshake.
        if (data.authorityId != AUTHORITY) revert WrongAuthority(AUTHORITY, data.authorityId);

        uint256 createdAt = data.createdAt;
        if (createdAt > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > createdAt + FRESHNESS_WINDOW) revert StaleProof();

        _requireJwksRequest(data.sent, data.sentTranscriptLength);
        bytes memory body = _jwksBody(data.received, data.recvTranscriptLength);

        // Monotonic high-water mark of reading timestamps. Replaying an older
        // reading leaves it alone, so it only ever moves forward.
        if (createdAt > $.freshestObservedAt) $.freshestObservedAt = createdAt;

        uint256 expiry = block.timestamp + DEFAULT_MODULUS_TTL;
        _applyKeys(body, expiry, createdAt);
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
        delete _s().trustedHashExpiresAt[modulusHash];
        emit ModulusUntrusted(modulusHash);
    }

    /// @notice Drop every expired kid from the tracked set. Anyone may call it.
    ///
    /// @dev Expiry itself needs no transaction -- verifiers check the stamp at
    ///      use-site, so an expired key is already untrusted the second its TTL
    ///      passes. Pruning only reclaims enumeration slots (and the storage
    ///      refund). Rotation calls this by itself when the set is full, so
    ///      even the prune is optional housekeeping.
    function prune() external {
        _pruneExpired();
    }

    // ─── Keeper views ───────────────────────────────────────────────

    /// One tracked key, as a keeper sees it.
    struct RootInfo {
        bytes32 kidHash;
        bytes32 modulusHash;
        /// The notarized reading that last wrote this kid (its `createdAt`).
        uint256 observedAt;
        /// When this entry stops being trusted, absent a fresher rotation.
        uint256 expiresAt;
    }

    function modulusOfKid(bytes32 kidHash) external view returns (bytes32) {
        return _s().modulusOfKid[kidHash];
    }

    function expiresAtKid(bytes32 kidHash) external view returns (uint256) {
        return _s().expiresAtKid[kidHash];
    }

    /// @notice modulusHash -> expiry. What `GooglePlatformVerifier` reads.
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256) {
        return _s().trustedHashExpiresAt[modulusHash];
    }

    function rotatedAtKid(bytes32 kidHash) external view returns (uint256) {
        return _s().rotatedAtKid[kidHash];
    }

    function freshestObservedAt() external view returns (uint256) {
        return _s().freshestObservedAt;
    }

    /// @notice Every tracked key with its provenance and expiry, expired ones
    ///         included until someone prunes. One call tells a keeper the whole
    ///         state of the list.
    function currentRoots() external view returns (RootInfo[] memory infos) {
        IdentityJwksRootsStorage storage $ = _s();
        uint256 n = $.trackedKids.length;
        infos = new RootInfo[](n);
        for (uint256 i = 0; i < n; ++i) {
            bytes32 kidHash = $.trackedKids[i];
            infos[i] = RootInfo({
                kidHash: kidHash,
                modulusHash: $.modulusOfKid[kidHash],
                observedAt: $.rotatedAtKid[kidHash],
                expiresAt: $.expiresAtKid[kidHash]
            });
        }
    }

    /// @notice True when no key is guaranteed trusted RENEWAL_MARGIN from now --
    ///         the single bit a keeper polls to decide whether to fetch a fresh
    ///         reading. True from deployment until the first rotation lands.
    function needsRotation() external view returns (bool) {
        IdentityJwksRootsStorage storage $ = _s();
        uint256 horizon = block.timestamp + RENEWAL_MARGIN;
        uint256 n = $.trackedKids.length;
        for (uint256 i = 0; i < n; ++i) {
            bytes32 modulusHash = $.modulusOfKid[$.trackedKids[i]];
            if ($.trustedHashExpiresAt[modulusHash] > horizon) return false;
        }
        return true;
    }

    // ─── The transcript ─────────────────────────────────────────────

    /// @dev The whole of one direction, joined. Three checks make the join
    ///      safe: the direction tiles the signed length, it hides nothing, and
    ///      its first range begins at the origin. Together they say every
    ///      transcript byte is in the result exactly once, at the offset the
    ///      notary signed it at -- so unlike a Platform Verifier reading around
    ///      a commitment, this contract may read the concatenation as the
    ///      document that crossed the wire.
    function _wholeDirection(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        private
        pure
        returns (bytes memory)
    {
        CeremonyAttestation.requireExactCoverage(block_, length);
        if (block_.commitments.length != 0) revert HiddenBytes();
        // Unreachable once the two checks above pass with a nonempty
        // transcript, and named for the empty one: no ranges pass coverage
        // against a zero signed length, and an out-of-bounds panic would tell
        // an operator nothing.
        if (block_.revealed.length == 0) revert RequestLineNotAtOrigin(type(uint32).max);
        if (block_.revealed[0].start != 0) revert RequestLineNotAtOrigin(block_.revealed[0].start);
        return CeremonyAttestation.concatRevealed(block_);
    }

    /// @dev The request must be the keeper's, to Google's JWKS endpoint, on
    ///      Google's own host.
    ///
    ///      The `Host` count is the whole of the virtual-host pin, so it gets
    ///      every guard the bearer-header count gets, in the same order. The
    ///      notary vouches that these bytes crossed a TLS session to
    ///      www.googleapis.com and nothing about their HTTP shape; the prover
    ///      chose them. Google's front end honours a `Host` line that only a
    ///      bare LF separates from the one before it, and routes to that
    ///      backend -- so a count that anchors on CRLF must first insist the
    ///      request has no other kind of line ending.
    function _requireJwksRequest(CeremonyAttestation.DirectionBlock memory block_, uint32 length) private pure {
        bytes memory sent = _wholeDirection(block_, length);
        if (!_startsWith(sent, REQUEST_LINE)) revert WrongRequestLine();
        CeremonyAttestation.requireCrlfLineEndings(sent);

        // Only the head names a host. A `Host` after the blank line is body
        // bytes to the server, whatever the count would make of it, so the
        // count stops where the server stops reading headers. The head keeps
        // the CRLF that closes its last line, so a line-anchored needle
        // matches that line too.
        uint256 boundary = _indexOf(sent, HEAD_BOUNDARY, 0);
        if (boundary == type(uint256).max) revert NoHeadBoundary();
        bytes memory head = _slice(sent, 0, boundary + 2);

        // Counted over normalized bytes, so a second `Host` cannot hide
        // behind case or whitespace (REQ-COMMON-39's rule, applied to a
        // different header). Exactly one: with two, which the backend
        // honoured is the backend's business, not something this contract
        // can know.
        bytes memory normalized = CeremonyAttestation.normalizeHeaderBytes(head);
        (uint256 count, uint256 at) = _find(normalized, HOST_NEEDLE);
        if (count != 1) revert NotOneHostHeader(count);

        uint256 from = at + HOST_NEEDLE.length;
        uint256 to = _indexOf(normalized, "\r\n", from);
        if (to == type(uint256).max || to - from != EXPECTED_HOST.length) revert WrongHost();
        for (uint256 i = 0; i < EXPECTED_HOST.length; ++i) {
            if (normalized[from + i] != EXPECTED_HOST[i]) revert WrongHost();
        }
    }

    /// @dev The response body, located by the framing the server itself
    ///      wrote: the head boundary first, then whichever of chunked or
    ///      `Content-Length` the head declares.
    ///
    ///      The FIRST head boundary, not the only one. A chunked body ends in
    ///      `0\r\n\r\n`, so uniqueness -- which the token request demands --
    ///      would refuse every real Google response.
    function _jwksBody(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        private
        pure
        returns (bytes memory body)
    {
        bytes memory received = _wholeDirection(block_, length);
        if (!_startsWith(received, STATUS_LINE)) revert WrongStatusLine();

        uint256 boundary = _indexOf(received, HEAD_BOUNDARY, 0);
        if (boundary == type(uint256).max) revert NoHeadBoundary();
        // The head keeps the CRLF that closes its last line, so a line-anchored
        // needle matches that line too.
        bytes memory head = _slice(received, 0, boundary + 2);
        body = _slice(received, boundary + 4, received.length);

        bytes memory normalized = CeremonyAttestation.normalizeHeaderBytes(head);
        (uint256 chunked,) = _find(normalized, CHUNKED_NEEDLE);
        if (chunked != 0) return _dechunk(body);

        (uint256 declaredLength, uint256 at) = _find(normalized, CONTENT_LENGTH_NEEDLE);
        if (declaredLength != 0) {
            uint256 declared = _decimal(normalized, at + CONTENT_LENGTH_NEEDLE.length, body.length);
            if (declared != body.length) revert ContentLengthMismatch(declared, body.length);
        }
        // Neither: `connection: close` delimits, and the body is what follows
        // the head.
    }

    /// @dev A decimal run ending at CRLF. Anything else is a length no body
    ///      can match, and is reported as such rather than parsed leniently.
    function _decimal(bytes memory data, uint256 at, uint256 found) private pure returns (uint256 value) {
        uint256 digits;
        for (; at < data.length; ++at) {
            bytes1 c = data[at];
            if (c == 0x0d) break;
            if (c < 0x30 || c > 0x39) revert ContentLengthMismatch(value, found);
            // A transcript length is a u32; ten digits already exceed it.
            if (++digits > 10) revert ContentLengthMismatch(value, found);
            value = value * 10 + (uint8(c) - 0x30);
        }
    }

    /// @dev Strict chunked transfer coding: a hex size of one to eight digits,
    ///      CRLF, that many bytes, CRLF; a zero size ends it and must be
    ///      followed by CRLF and nothing more. No extensions, no trailers.
    ///      Every iteration consumes at least five bytes, so the loop is
    ///      bounded by the body.
    function _dechunk(bytes memory chunked) private pure returns (bytes memory out) {
        out = new bytes(chunked.length);
        uint256 n;
        uint256 at;
        while (true) {
            uint256 size;
            uint256 digits;
            while (at < chunked.length) {
                uint256 nibble = _hexNibble(chunked[at]);
                if (nibble == type(uint256).max) break;
                if (++digits > 8) revert BadChunkFraming();
                size = (size << 4) | nibble;
                ++at;
            }
            // Covers a missing size, a chunk extension (`;`) and any other
            // byte where CRLF belongs.
            if (digits == 0 || !_crlfAt(chunked, at)) revert BadChunkFraming();
            at += 2;

            if (size == 0) {
                if (chunked.length - at != 2 || !_crlfAt(chunked, at)) revert BadChunkFraming();
                break;
            }
            if (at + size + 2 > chunked.length) revert BadChunkFraming();
            for (uint256 i = 0; i < size; ++i) {
                out[n++] = chunked[at + i];
            }
            at += size;
            if (!_crlfAt(chunked, at)) revert BadChunkFraming();
            at += 2;
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    // ─── The key set ────────────────────────────────────────────────

    /// @dev Read every JWK out of the body and apply it. The body is Google's
    ///      pretty-printed JSON; this reads exactly the shape Google publishes
    ///      and refuses anything it does not recognise, so it is a checker
    ///      for one document rather than a JSON parser.
    ///
    ///      `keys` is located by counting: the token appears once in the
    ///      whole body, or the document is not the one this reads. Objects are
    ///      flat -- a `{` or `[` inside one is refused -- so each ends at its
    ///      first `}` and the walk is one forward pass bounded by the body,
    ///      with the object count capped at MAX_TRACKED_KIDS.
    function _applyKeys(bytes memory body, uint256 expiry, uint256 provenAt) private {
        (uint256 count, uint256 at) = _find(body, KEYS_TOKEN);
        if (count == 0) revert MissingMember("keys");
        if (count > 1) revert AmbiguousMember("keys");

        at = _ws(body, at + KEYS_TOKEN.length);
        if (at >= body.length || body[at] != ":") revert MissingMember("keys");
        at = _ws(body, at + 1);
        if (at >= body.length || body[at] != "[") revert MissingMember("keys");
        ++at;

        uint256 keys;
        while (true) {
            at = _ws(body, at);
            if (at >= body.length) revert UnterminatedMember("keys");
            if (body[at] == "]") {
                ++at;
                break;
            }
            if (keys != 0) {
                if (body[at] != ",") revert UnterminatedMember("keys");
                at = _ws(body, at + 1);
                if (at >= body.length) revert UnterminatedMember("keys");
            }
            if (body[at] != "{") revert UnterminatedMember("keys");
            if (keys == MAX_TRACKED_KIDS) revert TooManyKids();

            uint256 close = _objectEnd(body, at);
            _applyKey(_slice(body, at, close + 1), expiry, provenAt);
            ++keys;
            at = close + 1;
        }

        at = _ws(body, at);
        if (at >= body.length || body[at] != "}") revert TrailingBytes();
        if (_ws(body, at + 1) != body.length) revert TrailingBytes();
    }

    /// @dev The index of the `}` closing the object opened at `open`.
    function _objectEnd(bytes memory body, uint256 open) private pure returns (uint256 at) {
        for (at = open + 1; at < body.length; ++at) {
            bytes1 c = body[at];
            if (c == "}") return at;
            if (c == "{" || c == "[") revert UnexpectedNesting();
        }
        revert UnterminatedMember("keys");
    }

    function _applyKey(bytes memory jwk, uint256 expiry, uint256 provenAt) private {
        bytes memory kid = _member(jwk, "kid");
        bytes memory nB64url = _member(jwk, "n");

        bytes memory rawN = _b64urlDecode(nB64url);
        if (rawN.length != MODULUS_BYTES) revert InvalidModulusLength();
        _processClaim(kid, _modulusHash(rawN), expiry, provenAt);
    }

    /// @dev One string member of a flat object. The token `"name"` appears
    ///      exactly once, then `:` and an opening quote with whitespace either
    ///      side (Google writes a space after the colon), and the value runs
    ///      to the next quote. A backslash is refused rather than unescaped.
    function _member(bytes memory jwk, string memory name) private pure returns (bytes memory) {
        bytes memory token = abi.encodePacked('"', name, '"');
        (uint256 count, uint256 at) = _find(jwk, token);
        if (count == 0) revert MissingMember(name);
        if (count > 1) revert AmbiguousMember(name);

        at = _ws(jwk, at + token.length);
        if (at >= jwk.length || jwk[at] != ":") revert MissingMember(name);
        at = _ws(jwk, at + 1);
        if (at >= jwk.length || jwk[at] != '"') revert MissingMember(name);
        ++at;

        uint256 start = at;
        for (; at < jwk.length; ++at) {
            bytes1 c = jwk[at];
            if (c == '"') return _slice(jwk, start, at);
            if (c == "\\") revert EscapedValue(name);
        }
        revert UnterminatedMember(name);
    }

    /// @dev The hash the Google circuit exposes: keccak over the eighteen
    ///      120-bit limbs as 32-byte words. The keeper's `decision::modulus_hash`
    ///      computes the same value, and a test pins one vector across both.
    function _modulusHash(bytes memory rawN) private pure returns (bytes32) {
        bytes32[18] memory limbs = _splitLimbs(rawN);
        bytes memory packed = new bytes(MODULUS_LIMBS * 32);
        for (uint256 i = 0; i < MODULUS_LIMBS; ++i) {
            bytes32 v = limbs[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        return keccak256(packed);
    }

    function _processClaim(bytes memory kid, bytes32 modulusHash, uint256 expiry, uint256 provenAt) private {
        IdentityJwksRootsStorage storage $ = _s();
        bytes32 kidHash = keccak256(kid);
        // Ignore a claim proved no later than the one already applied -- the
        // monotonic rule that makes replay harmless. Rotation is open and a
        // reading binds no contract, so anyone can replay any still-fresh
        // reading anywhere, forever; ignoring (never reverting) keeps a
        // front-runner from bricking the honest keeper's batch by landing one
        // claim from it first, and skipping (never applying) keeps an older
        // reading from rolling a kid back or re-stamping its TTL.
        if (provenAt < $.rotatedAtKid[kidHash]) return;
        bytes32 previous = $.modulusOfKid[kidHash];
        // A byte-identical resubmission of the applied reading is a no-op:
        // nothing is written, nothing is emitted, and in particular the TTL is
        // NOT re-stamped -- so spamming the same reading neither grows state
        // nor stretches trust.
        if (provenAt == $.rotatedAtKid[kidHash] && previous == modulusHash) return;
        $.rotatedAtKid[kidHash] = provenAt;

        // The key this kid used to carry stops being trusted NOW, rather than
        // when its thirty-day stamp runs out.
        //
        // The verifier resolves by modulus, not by kid, so leaving the old
        // entry keeps a retired key usable for the rest of its TTL -- which is
        // exactly the window a compromised key would be used in. Google
        // publishes overlapping keys and tokens live about an hour, so the cost
        // is that a token signed by the key Google just retired stops verifying
        // a little early; the user signs in again.
        if (previous != bytes32(0) && previous != modulusHash) {
            delete $.trustedHashExpiresAt[previous];
            emit ModulusUntrusted(previous);
        } else if (previous == bytes32(0)) {
            _trackKid(kidHash);
        }

        $.modulusOfKid[kidHash] = modulusHash;
        $.expiresAtKid[kidHash] = expiry;
        $.trustedHashExpiresAt[modulusHash] = expiry;
        emit ModulusRotated(kidHash, string(kid), modulusHash, expiry);
        emit RootApplied(kidHash, modulusHash, provenAt, expiry);
    }

    /// Add a kid to the enumeration. Growth is doubly bounded: a kid can only
    /// enter through a notarized reading of Google's own JWKS (a submitter
    /// cannot invent one), and the set is capped -- when full, expired entries
    /// are pruned to make room, and only a set full of LIVE keys refuses.
    function _trackKid(bytes32 kidHash) private {
        IdentityJwksRootsStorage storage $ = _s();
        if ($.trackedKidIndex[kidHash] != 0) return;
        if ($.trackedKids.length >= MAX_TRACKED_KIDS) {
            _pruneExpired();
            if ($.trackedKids.length >= MAX_TRACKED_KIDS) revert TooManyKids();
        }
        $.trackedKids.push(kidHash);
        $.trackedKidIndex[kidHash] = $.trackedKids.length;
    }

    /// Swap-remove every expired kid. `rotatedAtKid` survives on purpose: it is
    /// the monotonic floor that keeps a replayed old reading from resurrecting
    /// the entry the prune just removed.
    function _pruneExpired() private {
        IdentityJwksRootsStorage storage $ = _s();
        uint256 i = $.trackedKids.length;
        while (i > 0) {
            i--;
            bytes32 kidHash = $.trackedKids[i];
            if ($.expiresAtKid[kidHash] > block.timestamp) continue;

            bytes32 modulusHash = $.modulusOfKid[kidHash];
            delete $.modulusOfKid[kidHash];
            delete $.expiresAtKid[kidHash];
            // Only clear the verifier-facing stamp if it is genuinely spent --
            // it can sit above the kid's own expiry only if some fresher
            // rotation re-trusted the same modulus under another kid.
            if ($.trustedHashExpiresAt[modulusHash] <= block.timestamp) {
                delete $.trustedHashExpiresAt[modulusHash];
            }

            uint256 last = $.trackedKids.length - 1;
            if (i != last) {
                bytes32 moved = $.trackedKids[last];
                $.trackedKids[i] = moved;
                $.trackedKidIndex[moved] = i + 1;
            }
            $.trackedKids.pop();
            delete $.trackedKidIndex[kidHash];
            emit RootPruned(kidHash, modulusHash);
        }
    }

    // ─── Bytes ──────────────────────────────────────────────────────

    /// @dev How many times `needle` occurs in `haystack`, and where the first
    ///      occurrence begins. Overlapping occurrences count, which can only
    ///      over-count -- the direction that fails closed.
    function _find(bytes memory haystack, bytes memory needle) private pure returns (uint256 count, uint256 first) {
        first = type(uint256).max;
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) {
                if (count == 0) first = i;
                ++count;
            }
        }
    }

    /// @dev The first occurrence of `needle` at or after `from`, or
    ///      `type(uint256).max`.
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
        return type(uint256).max;
    }

    function _startsWith(bytes memory data, bytes memory prefix) private pure returns (bool) {
        if (data.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }

    /// @dev Skip JSON whitespace: SP, HTAB, CR, LF.
    function _ws(bytes memory data, uint256 at) private pure returns (uint256) {
        while (at < data.length) {
            bytes1 c = data[at];
            if (c != 0x20 && c != 0x09 && c != 0x0d && c != 0x0a) break;
            ++at;
        }
        return at;
    }

    function _crlfAt(bytes memory data, uint256 at) private pure returns (bool) {
        return at + 2 <= data.length && data[at] == 0x0d && data[at + 1] == 0x0a;
    }

    /// @dev The value of a hex digit, or `type(uint256).max` for anything else.
    function _hexNibble(bytes1 c) private pure returns (uint256) {
        uint8 v = uint8(c);
        if (v >= 0x30 && v <= 0x39) return v - 0x30;
        if (v >= 0x41 && v <= 0x46) return v - 0x41 + 10;
        if (v >= 0x61 && v <= 0x66) return v - 0x61 + 10;
        return type(uint256).max;
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

    /// @dev Eighteen little-endian 120-bit limbs of a 2048-bit big-endian
    ///      modulus, the way the Google circuit takes its public inputs. Kept
    ///      verbatim: the keeper and the circuit compute the same split.
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

    /// @dev Required by UUPS -- only the owner can upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would freeze the Notary Service pointer, and Google's
    ///      keys would expire with no way to replace them.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
