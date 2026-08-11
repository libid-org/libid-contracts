// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {IdentityClaim, IIdentityVerifier} from "./IIdentityVerifier.sol";

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @title XIdentityVerifier - the naming system's own X proof.
///
/// @notice Verifies a notarized, zero-knowledge proof of an X `/me` response
///         and returns the account it names.
///
/// @dev **This contract is the one the notary attests to.** Both attestation
///      digests bind `address(this)`, so a signature made out to any other
///      contract does not recover here — and the naming system's notary is its
///      own deployment, configured with this address. It reads nothing from the
///      wallet product and shares no contract with it.
///
///      That is a duplicate of the wallet product's proof pipeline, on purpose.
///      The two speak the same protocol to the same API today and will drift
///      apart; a duplicate costs a second attestation, a shared one costs the
///      independence the naming system is for.
///
///      **The attestation tags are byte-identical, and that is not a
///      reference.** `XZkVerifier.token.v1` and `.me.v1` are the format's
///      version strings, computed by the notary. Duplicating the pipeline means
///      duplicating the format, and what separates the two deployments is the
///      contract address inside the digest, not the tag.
///
///      **What it does not check, and what that costs.** The OAuth client id.
///      A bearer from any X application drives a binding here.
///
///      The naming argument for it: the `/me` response is notarized either way,
///      so the account is proved whoever the bearer belongs to. A product built
///      on these names does not have to be ours, and does not have to ask us to
///      be listed.
///
///      The price, stated plainly. Mallory registers her own X application and
///      gets a victim to authorize it — an ordinary "connect with X" prompt.
///      She takes the resulting bearer, drives the naming system's notary
///      through `/2/users/me` with it, and binds the victim's handle and id to
///      her own wallet. `XZkVerifier` refuses that same bearer with
///      `ClientIdMismatch`; this contract accepts it.
///
///      The remedy is the real owner proving again, which needs them to notice
///      and does not recover what was already routed. It rests on `observedAt`
///      being the notary's wall clock rather than anything a prover states, so
///      a later honest proof always outranks an earlier hostile one, and on
///      `IdentityNames` refusing an observation dated further ahead than the
///      platform allows. Read an X name as "somebody proved this account", not
///      "the account holder chose this address".
///
///      **One notarized session, not two.** The wallet product also notarizes
///      the `/token` exchange, because the client id lives in that request
///      while the account lives in `/me`, and the two have to be tied to one
///      bearer — otherwise an attacker pairs their own `/token` with somebody
///      else's `/me`. Dropping the client id leaves nothing to tie, so the
///      second session and its blinder are not asked for here. The `/me`
///      attestation carries the whole claim: the handle, the id, the response
///      bytes, the request layout around the withheld bearer, and the bearer's
///      commitment.
///
///      **What it checks.** The notary signature, the bearer cross-bind that
///      ties the ZK proof to that signed session, the request shape around the
///      withheld bearer, handle and id present exactly once in the notarized
///      response, and the ZK proof itself.
contract XIdentityVerifier is IIdentityVerifier, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
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
        MeAttestation meAttest;
    }

    // PI layout: one byte per slot, low-byte of each bytes32.
    //   [  0..32) bearer_hash_token  SHA256(bearer || blinder_token)
    //                                Unread. It commits the bearer against a
    //                                second blinder so a `/token` session can
    //                                be tied to the `/me` one — see the
    //                                contract comment on why a name binding
    //                                has no second session to tie.
    //   [ 32..64) bearer_hash_me     SHA256(bearer || blinder_me)
    //   [ 64..96) nullifier          keccak256(bearer_padded || len.be32)
    //                                Present in the circuit, unread here: a
    //                                nullifier stops a proof being spent twice,
    //                                and a binding is idempotent. The layout
    //                                still lists it, because the offsets after
    //                                it are only correct if it is there.
    //   [ 96..116) wallet_address
    //   [116..136) session_addr
    uint256 private constant OFF_BEARER_HASH_ME = 32;
    uint256 private constant OFF_WALLET_ADDR = 96;
    uint256 private constant OFF_SESSION_ADDR = 116;
    uint256 private constant TOTAL_PUBLIC_INPUTS = 136;

    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 private constant ZK_PROOF_TTL = 10 minutes;
    uint256 private constant MAX_REVEALED_LEN = 4096;
    uint256 private constant MAX_HANDLE_LEN = 32;

    /// Domain-sep tag for the notary key. The attestation format's version
    /// string, computed by the notary and therefore identical wherever the
    /// format is spoken.
    bytes32 internal constant OP_ME_ATTEST = keccak256("XZkVerifier.me.v1");

    /// @notice The notary key whose attestations this accepts.
    address public notary;

    /// @notice The circuit's on-chain verifier.
    IHonkVerifier public honkVerifier;

    /// @notice How the notarized `/me` exchange reads.
    ///
    /// @dev `platformName` is the SNI the notary hashes into both digests;
    ///      `endpoint` is the path the revealed request line must carry;
    ///      `handlePrefix` is where the handle begins in the response; and
    ///      `idPrefix`/`idSuffix` bracket the account id in it — X writes
    ///      `"id":"<digits>"` today. All of it is settable, because a response
    ///      that changes shape must not be able to take X naming off the air
    ///      until an upgrade ships. Leaving the id delimiters out would have
    ///      covered half of what `verify` matches.
    struct ResponseShape {
        string platformName;
        string endpoint;
        string handlePrefix;
        string idPrefix;
        string idSuffix;
    }

    /// @notice This contract's own view of the exchange, stored rather than
    ///         read from anywhere. A name has to resolve whether or not
    ///         anything else is running.
    ResponseShape private _shape;

    error InvalidPublicInputsLength();
    error ZkVerificationFailed();
    error NotaryVerificationFailed();
    error FutureProof();
    error StaleProof();
    error BearerHashMismatch();
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
    error ZeroSigner();
    error EmptyResponseShape();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address notary_, address honkVerifier_, ResponseShape calldata shape_)
        external
        initializer
    {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setTrust(notary_, honkVerifier_);
        _setResponseShape(shape_);
    }

    /// @notice Rotate the notary key or replace the circuit verifier.
    function setTrust(address notary_, address honkVerifier_) external onlyOwner {
        _setTrust(notary_, honkVerifier_);
    }

    /// @notice Follow a change in X's response.
    function setResponseShape(ResponseShape calldata shape_) external onlyOwner {
        _setResponseShape(shape_);
    }

    function _setTrust(address notary_, address honkVerifier_) private {
        if (notary_ == address(0) || honkVerifier_ == address(0)) revert ZeroSigner();
        notary = notary_;
        honkVerifier = IHonkVerifier(honkVerifier_);
    }

    function _setResponseShape(ResponseShape calldata shape_) private {
        // An empty prefix matches at every position, and an empty platform
        // name or endpoint would leave the digest and the request line
        // unpinned. `idSuffix` may be empty: a value that runs to the end of
        // the revealed bytes has nothing after it to name.
        if (
            bytes(shape_.platformName).length == 0 || bytes(shape_.endpoint).length == 0
                || bytes(shape_.handlePrefix).length == 0 || bytes(shape_.idPrefix).length == 0
        ) {
            revert EmptyResponseShape();
        }
        _shape = shape_;
    }

    /// @inheritdoc IIdentityVerifier
    function platformName() public view override returns (string memory) {
        return _shape.platformName;
    }

    /// @notice The path the revealed request line must carry.
    function endpoint() public view returns (string memory) {
        return _shape.endpoint;
    }

    /// @notice Where the handle begins in the notarized response.
    function handlePrefix() public view returns (string memory) {
        return _shape.handlePrefix;
    }

    /// @notice What brackets the account id in the notarized response.
    function idPrefix() public view returns (string memory) {
        return _shape.idPrefix;
    }

    function idSuffix() public view returns (string memory) {
        return _shape.idSuffix;
    }

    // ─── Verification ───────────────────────────────────────────────

    /// @inheritdoc IIdentityVerifier
    function verify(bytes calldata proof) external view override returns (IdentityClaim memory claim) {
        XProof calldata p = _decode(proof);

        if (p.publicInputs.length != TOTAL_PUBLIC_INPUTS) revert InvalidPublicInputsLength();
        if (p.meAttest.sentRevealed.length > MAX_REVEALED_LEN) revert RevealedTooLong();
        if (p.meAttest.recvRevealed.length > MAX_REVEALED_LEN) revert RevealedTooLong();
        if (bytes(p.meAttest.handle).length == 0) revert EmptyHandle();
        if (bytes(p.meAttest.handle).length > MAX_HANDLE_LEN) revert HandleTooLong();

        _checkTimestamp(p.meAttest.timestamp);

        // The load-bearing cross-bind: the bearer the circuit committed to is
        // the bearer of the notarized session. Without it any proof would pair
        // with any attestation.
        if (_extractBytes32(p.publicInputs, OFF_BEARER_HASH_ME) != p.meAttest.bearerHash) {
            revert BearerHashMismatch();
        }

        // Kept although a name binding installs no session: the public input is
        // what the circuit committed to, and letting it disagree with the
        // notary-signed value would leave one field of the proof unchecked.
        if (_extractAddress(p.publicInputs, OFF_SESSION_ADDR) != p.meAttest.sessionAddr) {
            revert SessionAddrMismatch();
        }

        _verifyMeRequestStructure(p.meAttest);
        _verifyHandleInRecv(p.meAttest);
        _verifyIdInRecv(p.meAttest);
        _verifyMeSig(p.meAttest);

        if (!honkVerifier.verify(p.proof, p.publicInputs)) revert ZkVerificationFailed();

        // The wallet the proof was made out to. `IdentityNames` requires it to
        // be the caller, which is the whole of the authorization.
        address target = _extractAddress(p.publicInputs, OFF_WALLET_ADDR);

        uint64 observedAt = p.meAttest.timestamp;

        return
            IdentityClaim({
                userId: p.meAttest.userId, handle: p.meAttest.handle, target: target, observedAt: observedAt
            });
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
        bytes memory prefix = abi.encodePacked("GET ", endpoint(), " HTTP/1.1\r\n");
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
        //
        // Widened before the sum. Both fields are the caller's to set, so a
        // `bearerRangeEnd` near the top of uint32 would overflow the checked
        // addition and revert with an arithmetic panic — no custom error, and
        // an operator debugging a corrupt notary sees a panic in a contract
        // that does no user-facing arithmetic.
        if (uint256(att.sentSuffixEnd) != uint256(att.bearerRangeEnd) + 2) {
            revert MeBearerEndAdjacencyMismatch();
        }

        // The trailing 2 bytes of sentRevealed are the post-bearer bytes. They
        // MUST be CRLF. Bearer is base64url; `\r\n` cannot appear inside it,
        // so truncating the bearer range and re-anchoring on a fake CRLF
        // elsewhere in the request is impossible without rewriting the wire.
        if (sent[prefixLen] != 0x0d) revert MeBearerEndNotCrlf();
        if (sent[prefixLen + 1] != 0x0a) revert MeBearerEndNotCrlf();
    }

    function _verifyHandleInRecv(MeAttestation calldata att) internal view {
        bytes memory needle = abi.encodePacked(handlePrefix(), att.handle, '"');
        bytes memory prefix = bytes(handlePrefix());
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
    /// bytes, bracketed by the configured delimiters — `"id":"<userId>"` as X
    /// writes it today. An empty id is refused: a name binds on the immutable
    /// id, so there is nothing to fall back to.
    /// Same unique-prefix-hit guard as the handle check.
    function _verifyIdInRecv(MeAttestation calldata att) internal view {
        // Id is required — identity binds on the immutable platform id, not the
        // mutable handle. An attestation without a revealed id is rejected.
        if (bytes(att.userId).length == 0) revert IdNotFound();
        bytes memory needle = abi.encodePacked(idPrefix(), att.userId, idSuffix());
        bytes memory prefix = bytes(idPrefix());
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

    function _verifyMeSig(MeAttestation calldata att) internal view {
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                keccak256(bytes(platformName())),
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

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to rotate a key or follow a change
    ///      in the exchange.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
