// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {INotaryService} from "./INotaryService.sol";

/// @title GoogleJwtRoots - the signing keys the `google/v1` profile trusts,
///        and until when.
///
/// @notice Google rotates the keys it signs id_tokens with. This contract is
///         where the Google Platform Verifier learns the current ones, from a
///         notarized reading of Google's published JWKS: a JWT verifies only
///         while the modulus that signed it is listed here and unexpired.
///
/// @dev The list is two generations of Google's key set, and nothing else.
///      Google's JWKS is an unordered set of a few keys with no "next"
///      marker, so a reading is stored as the set it is: `current` is the
///      latest reading applied, `previous` the reading before it. A newer
///      reading of the same set only restarts `current`'s lifetime; a newer
///      reading of a different set replaces -- `current` becomes `previous`,
///      the reading becomes `current`, and what `previous` held is gone.
///      There is no history and no maintenance: nothing to prune, nothing to
///      untrust, no owner lever over which of Google's keys are trusted.
///
///      A generation is trusted until READING_LIFETIME after its reading's
///      own `createdAt` -- the notary's clock, not the block the rotation
///      landed in -- so trust lapses by time alone, with no transaction from
///      anyone, and a later reading of the same set extends it. `previous`
///      is kept because Google's rotation and the keeper's reading are not
///      simultaneous: a token minted under the key Google just rotated out
///      is still being presented for the rest of its hour, and a keeper's
///      reading can land in between. One generation back covers that;
///      further back is history.
///
///      The reading is an ordinary notarized session -- the section 9.1
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
///      window below, and a reading dated no later than the one in force is
///      ignored rather than refused. A rotation pays the Notary Fee, which is
///      the one thing a submitter needs beyond gas.
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
///      does the expiry, and nobody owns rotation.** Verifiers check the stamp
///      at use-site, and an expired generation stops being trusted with no
///      transaction from anyone. The owner's one lever is the Notary Service
///      pointer: which notary a reading must carry, never which Google key
///      is trusted.
contract GoogleJwtRoots is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    // ─── State ──────────────────────────────────────────────────────

    /// One reading of Google's key set: when the notary read it, and the
    /// limb hash of every modulus it listed, in the order Google listed them.
    struct Generation {
        uint64 observedAt;
        bytes32[] moduli;
    }

    /// @custom:storage-location erc7201:libid.storage.GoogleJwtRoots
    struct GoogleJwtRootsStorage {
        /// Authenticates a reading and charges for it.
        INotaryService notary;
        /// The latest reading applied. Google's set already lists the key it
        /// will sign with next, so this is Google's current AND next keys.
        Generation current;
        /// The reading before it, kept for the tokens still in flight under a
        /// key Google has since dropped.
        Generation previous;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.GoogleJwtRoots")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GOOGLE_JWT_ROOTS_STORAGE =
        0x7f78ff13201a03086d4b08e3085224c34a9fc247d0f67d11acd0db52976eb300;

    function _s() private pure returns (GoogleJwtRootsStorage storage $) {
        assembly {
            $.slot := GOOGLE_JWT_ROOTS_STORAGE
        }
    }

    // ─── Constants ──────────────────────────────────────────────────

    /// @notice The TLS server name the notary must have authenticated.
    bytes32 public constant AUTHORITY = keccak256("www.googleapis.com");
    uint256 public constant FRESHNESS_WINDOW = 1 hours;
    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    /// How long a generation is trusted after the reading that wrote it, by
    /// the reading's own clock. Google's keys overlap for days and a keeper
    /// reads weekly, so this is runway for a keeper outage, not a key's life.
    uint256 public constant READING_LIFETIME = 30 days;
    /// The most keys one reading may carry. Google served four on 2026-09-03,
    /// and a notarized reading cannot invent any, so this is headroom: it
    /// bounds the set comparison below, not what Google publishes.
    uint256 public constant MAX_KEYS = 8;
    /// How much trusted runway `needsRotation()` insists on. A reading stamps
    /// its set for READING_LIFETIME, so a keeper acting on this signal
    /// rotates roughly weekly rather than racing the expiry.
    uint256 public constant RENEWAL_MARGIN = 7 days;

    /// @dev The request line the keeper's prover puts on the wire, in
    ///      origin-form like every other verifier pins it. The path is what
    ///      separates the key set from everything else googleapis.com serves,
    ///      and the whole line -- through the CRLF -- is what keeps a query
    ///      out: `?callback=` turns the same path into JSONP, a 200 whose
    ///      body begins with bytes the requester chose.
    bytes private constant REQUEST_LINE = "GET /oauth2/v3/certs HTTP/1.1\r\n";
    /// @dev googleapis.com serves many virtual hosts under one certificate, so
    ///      the TLS authority alone does not pin which backend answered. The
    ///      `Host` header does, and the notary signed it.
    bytes private constant HOST_NEEDLE = "\r\nhost:";
    bytes private constant EXPECTED_HOST = "www.googleapis.com";
    bytes private constant STATUS_LINE = "HTTP/1.1 200 ";
    bytes private constant HEAD_BOUNDARY = "\r\n\r\n";
    bytes private constant TRANSFER_ENCODING_NEEDLE = "\r\ntransfer-encoding:";
    bytes private constant CHUNKED_NEEDLE = "\r\ntransfer-encoding:chunked\r\n";
    bytes private constant CONTENT_LENGTH_NEEDLE = "\r\ncontent-length:";
    bytes private constant CONTENT_ENCODING_NEEDLE = "\r\ncontent-encoding:";
    bytes private constant KEYS_TOKEN = '"keys"';
    /// @dev 65537, the one public exponent the `google/v1` circuit verifies
    ///      RS256 under.
    bytes private constant EXPECTED_EXPONENT = "AQAB";

    uint256 private constant MODULUS_BYTES = 256;
    uint256 private constant MODULUS_LIMBS = 18;

    // ─── Events ─────────────────────────────────────────────────────

    event NotaryServiceChanged(address notary);
    /// A different set than `current` landed: `current` became `previous`,
    /// this reading became `current`. `kids` and `moduli` are the reading's
    /// keys in the order Google listed them, `observedAt` the notary's clock
    /// -- enough for a keeper to follow the list from logs alone.
    event KeysRotated(uint64 observedAt, string[] kids, bytes32[] moduli);
    /// A newer reading of the set already current: nothing shifted, and the
    /// set's lifetime restarted from this reading's clock.
    event ReadingRefreshed(uint64 observedAt);

    // ─── Errors ─────────────────────────────────────────────────────

    error ZeroAddress();
    /// @dev A reading whose key set is empty says nothing about what Google
    ///      publishes; applying it would shift the live set into `previous`
    ///      on the strength of a document that names no key. Refused rather
    ///      than charged.
    error EmptyKeySet();
    /// @dev More keys in one reading than MAX_KEYS.
    error TooManyKeys(uint256 count);
    /// @dev The same modulus twice in one reading. Google lists each key
    ///      once; a document that repeats one is not the document this
    ///      reads, and a set with a repeat would compare as a set it is not.
    error DuplicateKey(bytes32 modulusHash);
    /// @dev A JWK whose public exponent is not 65537. The verifier trusts a
    ///      key by its modulus alone, so a key that would verify under a
    ///      different exponent must never be listed.
    error WrongExponent(bytes found);
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
    /// @dev A framing header appears more than once. The header the body is
    ///      located by gets the rule every other read gets (REQ-COMMON-19A):
    ///      a delimiter matching twice is refused, not chosen from.
    error DuplicateFramingHeader(string name, uint256 count);
    /// @dev Both `Transfer-Encoding` and `Content-Length` are present, so two
    ///      parsers could frame two bodies.
    error ConflictingFraming();
    /// @dev The response declares a `Content-Encoding`. The prover must not
    ///      negotiate compression: gzip bytes would only fail later, somewhere
    ///      in the JSON walk, and an explicit refusal names the cause.
    error EncodedBody();
    /// @dev The member is absent, or present but not in the shape read here:
    ///      `keys` must be an array, `kid`, `n` and `e` must be strings.
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
        GoogleJwtRootsStorage storage $ = _s();

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

        uint64 createdAt = data.createdAt;
        if (createdAt > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > createdAt + FRESHNESS_WINDOW) revert StaleProof();

        _requireJwksRequest(data.sent, data.sentTranscriptLength);
        bytes memory body = _jwksBody(data.received, data.recvTranscriptLength);

        // The whole set is read before any of it is written: a reading is
        // applied entire or refused entire, never half.
        (string[] memory kids, bytes32[] memory moduli) = _readKeys(body);
        _apply(createdAt, kids, moduli);
    }

    // ─── What a verifier, and a keeper, read ────────────────────────

    /// @notice modulusHash -> when it stops being trusted, or zero. What
    ///         `GooglePlatformVerifier` reads: the JWT circuit does not expose
    ///         `kid`, so trust has to be checkable from the modulus alone.
    /// @dev A key in both generations reports the current one's stamp: the
    ///      later reading is the later word that Google still lists it.
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256) {
        GoogleJwtRootsStorage storage $ = _s();
        if (_lists($.current.moduli, modulusHash)) return uint256($.current.observedAt) + READING_LIFETIME;
        if (_lists($.previous.moduli, modulusHash)) return uint256($.previous.observedAt) + READING_LIFETIME;
        return 0;
    }

    /// @notice Both generations, as stored. One call tells a keeper the whole
    ///         state of the list; an empty `current` is a list nothing has
    ///         been read into yet.
    function currentKeys() external view returns (Generation memory current, Generation memory previous) {
        GoogleJwtRootsStorage storage $ = _s();
        return ($.current, $.previous);
    }

    /// @notice The `createdAt` of the reading in force -- the notary's clock,
    ///         not the block it landed in. A keeper compares this to
    ///         wall-clock to decide whether its reading would be news.
    function freshestObservedAt() external view returns (uint256) {
        return _s().current.observedAt;
    }

    /// @notice True when the current generation is not guaranteed trusted
    ///         RENEWAL_MARGIN from now -- the single bit a keeper polls to
    ///         decide whether to fetch a fresh reading. True from deployment
    ///         until the first rotation lands.
    function needsRotation() external view returns (bool) {
        return block.timestamp + RENEWAL_MARGIN >= uint256(_s().current.observedAt) + READING_LIFETIME;
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
        // The body must be the document, not a compressed form of it. The
        // prover sends no `Accept-Encoding`; a server that compresses anyway
        // is refused by name rather than somewhere in the JSON walk.
        (uint256 encodings,) = _find(normalized, CONTENT_ENCODING_NEEDLE);
        if (encodings != 0) revert EncodedBody();

        (uint256 codings,) = _find(normalized, TRANSFER_ENCODING_NEEDLE);
        (uint256 lengths, uint256 at) = _find(normalized, CONTENT_LENGTH_NEEDLE);
        // Exactly one framing header, of one kind. Two of either, or one of
        // each, is a message two parsers could frame two ways -- the
        // request-smuggling shape -- and a field read from revealed bytes is
        // refused when its delimiter matches twice, not read from whichever
        // copy the server happened to honour.
        if (codings > 1) revert DuplicateFramingHeader("transfer-encoding", codings);
        if (lengths > 1) revert DuplicateFramingHeader("content-length", lengths);
        if (codings != 0 && lengths != 0) revert ConflictingFraming();

        if (codings != 0) {
            // The one coding this reads. Any other frames a body this
            // contract cannot locate.
            (uint256 chunked,) = _find(normalized, CHUNKED_NEEDLE);
            if (chunked != 1) revert BadChunkFraming();
            return _dechunk(body);
        }
        if (lengths != 0) {
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

    /// @dev Read every JWK out of the body, writing nothing. The body is
    ///      Google's pretty-printed JSON; this reads exactly the shape Google
    ///      publishes and refuses anything it does not recognise, so it is a
    ///      checker for one document rather than a JSON parser.
    ///
    ///      `keys` is located by counting: the token appears once in the
    ///      whole body, or the document is not the one this reads. Objects are
    ///      flat -- a `{` or `[` inside one is refused -- so each ends at its
    ///      first `}` and the walk is one forward pass bounded by the body.
    ///      Past MAX_KEYS the walk only counts, so the refusal names how many
    ///      keys the reading carries rather than the first one too many.
    function _readKeys(bytes memory body) private pure returns (string[] memory kids, bytes32[] memory moduli) {
        (uint256 count, uint256 at) = _find(body, KEYS_TOKEN);
        if (count == 0) revert MissingMember("keys");
        if (count > 1) revert AmbiguousMember("keys");

        at = _ws(body, at + KEYS_TOKEN.length);
        if (at >= body.length || body[at] != ":") revert MissingMember("keys");
        at = _ws(body, at + 1);
        if (at >= body.length || body[at] != "[") revert MissingMember("keys");
        ++at;

        kids = new string[](MAX_KEYS);
        moduli = new bytes32[](MAX_KEYS);
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

            uint256 close = _objectEnd(body, at);
            if (keys < MAX_KEYS) (kids[keys], moduli[keys]) = _readKey(_slice(body, at, close + 1));
            ++keys;
            at = close + 1;
        }

        if (keys == 0) revert EmptyKeySet();
        if (keys > MAX_KEYS) revert TooManyKeys(keys);

        at = _ws(body, at);
        if (at >= body.length || body[at] != "}") revert TrailingBytes();
        if (_ws(body, at + 1) != body.length) revert TrailingBytes();

        assembly ("memory-safe") {
            mstore(kids, keys)
            mstore(moduli, keys)
        }

        // A set, so a repeat is refused rather than counted twice. Bounded by
        // MAX_KEYS squared.
        for (uint256 i = 1; i < keys; ++i) {
            for (uint256 j = 0; j < i; ++j) {
                if (moduli[i] == moduli[j]) revert DuplicateKey(moduli[i]);
            }
        }
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

    /// @dev One JWK: its kid, and the limb hash of its modulus.
    ///
    ///      The exponent is read and pinned, not stored. The `google/v1`
    ///      circuit verifies RS256 with the public exponent fixed at 65537,
    ///      and the verifier trusts a key by its modulus alone -- so a key
    ///      Google published under another exponent would be trusted for a
    ///      signature the circuit does not check. Google has only ever
    ///      published `AQAB` here; anything else is refused by name.
    function _readKey(bytes memory jwk) private pure returns (string memory kid, bytes32 modulusHash) {
        kid = string(_member(jwk, "kid"));
        bytes memory nB64url = _member(jwk, "n");
        bytes memory exponent = _member(jwk, "e");
        if (keccak256(exponent) != keccak256(EXPECTED_EXPONENT)) revert WrongExponent(exponent);

        bytes memory rawN = _b64urlDecode(nB64url);
        if (rawN.length != MODULUS_BYTES) revert InvalidModulusLength();
        modulusHash = _modulusHash(rawN);
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

    /// @dev Apply a set the notary read at `observedAt`. Three outcomes, and
    ///      the notary's clock alone decides the first.
    ///
    ///      A reading dated no later than the one in force is ignored -- never
    ///      refused. Rotation is open and a reading binds no contract, so
    ///      anyone can replay any still-fresh reading anywhere, forever;
    ///      ignoring keeps a front-runner from bricking the honest keeper by
    ///      landing its reading first, and skipping keeps an older reading from
    ///      rolling the set back or re-stamping its lifetime. No later includes
    ///      equal: a second reading dated the same second cannot swap the set
    ///      -- the rule for equal evidence everywhere in the protocol
    ///      (REQ-COMMON-25A).
    ///
    ///      A newer reading of the same set is Google saying the set still
    ///      stands: its lifetime restarts from this reading, nothing shifts,
    ///      `previous` stays as it was. A newer reading of a different set is
    ///      a rotation: what was current is kept one generation for the tokens
    ///      still in flight under it, and what was previous is gone.
    function _apply(uint64 observedAt, string[] memory kids, bytes32[] memory moduli) private {
        GoogleJwtRootsStorage storage $ = _s();
        if (observedAt <= $.current.observedAt) return;

        if (_sameSet($.current.moduli, moduli)) {
            $.current.observedAt = observedAt;
            emit ReadingRefreshed(observedAt);
            return;
        }

        $.previous.observedAt = $.current.observedAt;
        $.previous.moduli = $.current.moduli;
        $.current.observedAt = observedAt;
        $.current.moduli = moduli;
        emit KeysRotated(observedAt, kids, moduli);
    }

    /// @dev Whether `stored` and `read` list the same moduli, in any order.
    ///      Both are sets -- a reading with a repeat is refused before it gets
    ///      here, and every stored generation was once a reading -- so equal
    ///      length plus every read modulus present is equality. Bounded by
    ///      MAX_KEYS squared.
    function _sameSet(bytes32[] storage stored, bytes32[] memory read) private view returns (bool) {
        if (stored.length != read.length) return false;
        for (uint256 i = 0; i < read.length; ++i) {
            if (!_lists(stored, read[i])) return false;
        }
        return true;
    }

    function _lists(bytes32[] storage moduli, bytes32 modulusHash) private view returns (bool) {
        uint256 n = moduli.length;
        for (uint256 i = 0; i < n; ++i) {
            if (moduli[i] == modulusHash) return true;
        }
        return false;
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
