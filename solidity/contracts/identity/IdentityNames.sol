// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "./HandleNormalizer.sol";
import {IdentityNodes} from "./IdentityNodes.sol";

/// @title IdentityNames - proof-derived names for any wallet.
///
/// @notice Binds two things to a wallet address: a platform's immutable account
///         id, and that account's mutable handle. Anyone may resolve either.
///
/// @dev The contract never calls the address it binds, so a target may be an
///      EOA, a Safe, an ERC-4337 account or a managed wallet. It knows nothing
///      about any of them, which is what makes it usable by a product that is
///      not ours.
///
///      Authorization is one rule: a proof states the address it was made out
///      to, and that address has to be the caller. Nothing else grants a
///      binding: there is no owner function that writes, moves or deletes an
///      entry in either mapping. An account's own fresh proof retires the
///      handle that account used to hold, and nobody else's — see `bind`.
///
///      **What the owner can still do, stated plainly.** It configures which
///      verifiers a platform uses, and a verifier is trusted to report what a
///      proof says — so an owner that installs a dishonest verifier can mint
///      any claim. It can also change a platform's normalization rules, which
///      re-keys every handle already written: the old entries survive but no
///      longer answer the public resolvers. And the contract is UUPS, so the
///      owner can replace all of this. Read the guarantee above as "under
///      honest configuration"; the trust boundary is the owner key, and it is
///      the same one every upgradeable contract here has.
///
///      **A platform has verifier versions, and a keyspace it keeps across all
///      of them.** A platform's proof can change shape without the account
///      behind it changing — X gaining OIDC, say — so verifiers are keyed by
///      version and several are live at once while users migrate. What does
///      NOT vary by version is `rules`: it decides the key a handle hashes to,
///      and two versions normalizing differently would put one handle on two
///      nodes and make `resolveHandle` answer differently depending on which
///      version last wrote.
///
///      Retiring a version stops new bindings in that format and touches no
///      name already bound — a name belongs to the account that proved it, not
///      to the format the proof was written in. Which ceremony version proved a
///      binding is logged, not stored: the proof has happened and the effect
///      has been applied by the time anybody asks, so the answer is for an
///      operator reading `IdentityBound`, and nothing on chain reads it.
///
///      **This contract does not know what a proof looks like.** `claim` takes
///      a platform, a verifier version and opaque bytes, and hands all three to
///      the Proof Verifier, which routes them to the one contract that does
///      know. What comes back is trusted the way that contract is trusted: it
///      extracted every field from evidence it authenticated, and the owner
///      installed it.
///
///      **The two mappings are separate on purpose.** One proof writes both, so
///      a consumer that holds an id and a handle can compare them later and
///      learn whether its copy is stale. Merging them into one map would remove
///      the only freshness signal the chain can give.
///
///      **There is no nullifier.** A binding is idempotent, so replaying a
///      proof would rewrite the same value; the danger is an older proof
///      undoing a newer one, and the `observedAt` watermark refuses that. A
///      replay carries the same timestamp, so the same rule refuses it too.
///
///      **There is no pause.** A pause is a lever over other people's names,
///      and nothing here needs one: no funds are held, and no address is
///      predicted ahead of its deployment.
contract IdentityNames is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
    /// @notice A binding, and the moment the platform stated it.
    ///
    /// @dev `observedAt` is a provider timestamp, never a chain timestamp. Two
    ///      proofs of one handle are ordered by when the platform said it, not
    ///      by when somebody got around to submitting.
    ///
    ///      It is that moment on the scale every platform shares: the Platform
    ///      Verifier subtracts its own profile's future allowance before it
    ///      returns, because profiles disagree about what "now" is. Raw values
    ///      would compare two clocks and the looser one would always win.
    struct Binding {
        address owner;
        uint64 observedAt;
    }

    /// @notice A platform this contract accepts proofs for: its keyspace.
    ///
    /// @dev What lives here is what every version of a platform's proof must
    ///      agree on. `rules` decides the key a handle hashes to, so it CANNOT
    ///      vary by version — two versions normalizing differently would put
    ///      one handle on two nodes, and `resolveHandle` would answer
    ///      differently depending on which version last wrote. That is a split
    ///      namespace wearing the costume of a config option.
    ///
    ///      **The account id follows from what a version is.** A version is
    ///      another way to prove the SAME account — a notarized session, an
    ///      OIDC token — not another account space. The account did not change,
    ///      so its id did not change, and `bind` keys every version on the same
    ///      `idNode(platformId, attested.userId)`.
    ///
    ///      Read that as a test, not as a rule to remember: a proof format that
    ///      reports a different id is not proving the same account, so it is
    ///      not a version of this platform. It is a second platform, and it
    ///      wants its own `platformId` and its own keyspace.
    ///
    ///      **The id reaches the key verbatim.** A handle passes through
    ///      `rules` on the way in; an account id does not, and must not — any
    ///      normalization risks folding two accounts into one, which is worse
    ///      than the drift it would fix. So a verifier has to report the id
    ///      exactly as the provider issues it, down to the byte: a stray quote,
    ///      a prefix or a space writes a different node.
    ///
    ///      The trap is not exotic. A provider often has two immutable ids for
    ///      one account — GitHub's REST `id` (`20213174`) and its GraphQL
    ///      `node_id` (`MDQ6VXNlcjIwMjEzMTc0`) — and a verifier built on the
    ///      other API picks up the other one without anybody making a mistake.
    ///
    ///      The usual cost is not a stolen name; those two never collide. It is
    ///      that one person now owns two id nodes: neither binding supersedes
    ///      the other, a rename through one leaves the handle held under the
    ///      other resolving, and `resolveId` answers differently depending on
    ///      which id the caller happens to hold.
    ///
    ///      A string carries no provenance, so nothing on chain can catch this.
    ///      It is settled where a verifier is reviewed, next to "does it lie
    ///      about the account" — not in configuration, which sees an address
    ///      and nothing else.
    ///
    /// @param rules      How this platform's handles normalize.
    /// @param configured Whether the platform exists at all. A platform whose
    ///                   every version has been retired still owns its
    ///                   keyspace, so "is it wired" cannot be read off the
    ///                   Supported Version Set.
    struct Platform {
        HandleNormalizer.Rules rules;
        bool configured;
    }

    // ─── State ──────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:libid.storage.IdentityNames
    struct IdentityNamesStorage {
        /// idNode -> the wallet that proved that account id.
        mapping(bytes32 => Binding) byId;
        /// handleNode -> the wallet that last proved that handle.
        mapping(bytes32 => Binding) byHandle;
        /// wallet -> platformId -> the handle it published, if it chose to.
        ///
        /// A node cannot be turned back into a string, so the reverse direction
        /// needs the string itself. Publishing is optional: the event carries
        /// the plaintext either way, so an indexer never needs this, and only a
        /// contract that must display a name does.
        mapping(address => mapping(bytes32 => string)) published;
        /// platformId -> its keyspace: handle rules and current version.
        mapping(bytes32 => Platform) platforms;
        /// idNode -> the handle node that account last proved, and back.
        ///
        /// An account holds one handle at a time. When it proves a new one the
        /// old one has to stop resolving, or a payment meant for whoever holds
        /// that handle now would keep going to the wallet that renamed away
        /// from it. The reverse map answers "is this node still the one this
        /// account wrote", so a second account that took the handle in the
        /// meantime keeps it.
        mapping(bytes32 => bytes32) handleOfId;
        mapping(bytes32 => bytes32) idOfHandle;
        // ── The ceremony path. `proofVerifier` takes the index the retired
        //    `verifiers` mapping held, which is safe only because a mapping's
        //    base slot is never written; `everBound` and `spentDigests` are
        //    appended after everything above.
        /// The one component this Consumer calls to verify a proof.
        ///
        /// One address, not a version set. The Supported Version Set lives at
        /// the Proof Verifier, because a Consumer holding its own copy would
        /// be a second version-governance surface free to drift from it.
        IProofVerifier proofVerifier;
        /// platformId -> has any name ever been bound on it.
        ///
        /// Set once and never cleared: it answers "was this platform ever able
        /// to verify", which a retirement cannot make false in retrospect.
        mapping(bytes32 => bool) everBound;
        /// Every Authorization Digest this Consumer has accepted.
        ///
        /// The digest is its own replay nullifier, and recording belongs to the
        /// party the operation authorizes (REQ-COMMON-03A). Recording it at the
        /// Proof Verifier instead would let anyone observing a submission call
        /// first, consume the digest, and leave this contract nothing to apply
        /// -- a denial of service costing the attacker only a fee.
        mapping(bytes32 => bool) spentDigests;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.IdentityNames")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITY_NAMES_STORAGE =
        0x064503501234cc9c6e116cf4a84c07475158dabb6a3dcee437a89227e23bf200;

    /// @dev All state of this contract sits under one namespaced root, like
    ///      every upgradeable contract in this repo. Three things follow.
    ///
    ///      It cannot collide with the ERC-7201 namespaces of the OpenZeppelin
    ///      upgradeable bases, so this contract owns its slots outright and
    ///      needs no reserved gap.
    ///
    ///      A field may be APPENDED on upgrade without slot arithmetic. Do not
    ///      reorder or remove one: both would make an upgraded proxy read every
    ///      stored value out of the wrong bytes, and a struct read from the
    ///      wrong bytes does not revert — it answers.
    ///
    ///      And moving here from sequential slots abandons the old ones, so a
    ///      proxy upgraded onto this without re-running `setPlatform` reads a
    ///      root that has never been written: every platform comes back
    ///      unconfigured and every resolver reverts `UnknownPlatform`. Loud and
    ///      uniform, rather than one platform silently answering with rules
    ///      parsed out of an address.
    function _s() private pure returns (IdentityNamesStorage storage $) {
        assembly {
            $.slot := IDENTITY_NAMES_STORAGE
        }
    }

    // ─── Storage reads (the ABI the public variables gave) ─────────

    /// @notice The wallet that proved this account id, and when it proved it.
    function byId(bytes32 idNode) external view returns (address owner, uint64 observedAt) {
        Binding storage b = _s().byId[idNode];
        return (b.owner, b.observedAt);
    }

    /// @notice The same for a handle node.
    function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt) {
        Binding storage b = _s().byHandle[handleNode];
        return (b.owner, b.observedAt);
    }

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice A wallet proved an identity.
    ///
    /// @dev The plaintext rides along so an indexer or a browser can build
    ///      reverse resolution without the on-chain string.
    ///
    ///      `published` says whether the handle is the wallet's displayed name
    ///      after this bind. Without it the log cannot reconstruct `_published`
    ///      at all: only `unpublish` would be observable, so an indexer would
    ///      have to guess which bindings a wallet chose to show.
    ///      `ceremonyVersion` names the protocol revision that proved the
    ///      binding, as the verifier reported it. It lives in the log and not
    ///      in storage: nothing on chain acts on it, and what an operator needs
    ///      it for -- which bindings a ceremony version later found unsound
    ///      touched, whether anybody still depends on one before retiring it --
    ///      is answered by reading the log.
    event IdentityBound(
        address indexed owner,
        bytes32 indexed idNode,
        bytes32 indexed handleNode,
        bytes32 platformId,
        string userId,
        string handle,
        uint64 observedAt,
        bool published,
        uint16 ceremonyVersion
    );

    /// @notice What a ceremony carried that a binding does not keep.
    ///
    /// @dev Beside `IdentityBound`, not inside it. The two paths share that
    ///      event, and only a ceremony authenticates an OAuth client -- a field
    ///      the legacy path could never fill is a field an indexer must always
    ///      test for emptiness.
    ///
    ///      `clientIdentifier` is the exact bytes the platform authenticated.
    ///      The contract has no use for them: the digest already binds the
    ///      transaction. But an operator answering "which application produced
    ///      these bindings", after a client is found compromised, has no other
    ///      source -- the value exists only inside the call that writes the
    ///      binding. The digest keys it, because the digest is what identifies
    ///      one ceremony.
    event CeremonyBound(
        bytes32 indexed authorizationDigest, address indexed owner, bytes32 indexed platformId, bytes clientIdentifier
    );

    /// @notice A handle stopped resolving because the account that held it
    ///         proved a different one.
    /// @dev Nobody else's entry can be retired this way. See `bind`.
    event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed owner);

    /// @notice A platform's keyspace was configured or reconfigured.
    /// @dev Reconfiguring `rules` re-keys every handle already written.
    event PlatformConfigured(bytes32 indexed platformId);

    /// @notice This Consumer was pointed at a Proof Verifier.
    event ProofVerifierConfigured(address verifier);

    /// @notice A wallet withdrew its published handle.
    /// @dev An indexer that mirrors `reverseOf` needs this to stop showing it.
    event NameUnpublished(address indexed owner, bytes32 indexed platformId);

    // ─── Errors ─────────────────────────────────────────────────────

    /// This platform has no keyspace configured.
    error UnknownPlatform(bytes32 platformId);
    /// @notice The one operation this Consumer owns.
    ///
    /// @dev A new operation, or a change to what its transaction data means,
    ///      takes a NEW domain string rather than another digest field
    ///      (REQ-COMMON-01A). Note the consequence the specification is candid
    ///      about: a digest is spendable once at EACH Consumer accepting this
    ///      domain, so two deployments choosing the same string share a digest
    ///      space.
    bytes32 public constant CLAIM_IDENTITY_DOMAIN = keccak256(bytes("libid.claim-identity"));

    error ZeroAddress();
    /// @dev The submission names an operation this Consumer does not own
    ///      (REQ-COMMON-06A).
    error ForeignOperationDomain(bytes32 operationDomain);
    /// @dev A digest is spendable once here (REQ-COMMON-03A).
    error DigestAlreadySpent(bytes32 digest);
    /// @dev The Authorized Transaction Data of this operation is exactly one
    ///      address; trailing bytes and other shapes are refused
    ///      (REQ-COMMON-01F).
    error BadTransactionData(uint256 length);
    error WrongClaimValue(uint256 required, uint256 provided);
    /// The proof names a different address than the caller.
    error NotProofTarget(address proved, address caller);
    /// The proof carries no observation time, so it cannot be ordered.
    error NoObservationTime();
    /// The proof names no account id. A binding is anchored on the id.
    error NoUserId();
    /// A newer proof already wrote one of these nodes.
    error StaleProof(uint64 observedAt, uint64 known);

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
    }

    /// @notice Add a platform or change how its handles normalize.
    ///
    /// @dev Owner-managed, and this is the keyspace half: it says what a handle
    ///      on this platform means, not how a proof of one is read. See the
    ///      contract comment for the whole of what the owner's power is — in
    ///      particular, changing `rules` re-keys handles already written.
    ///
    ///      A platform is never removed. The names would stay in storage while
    ///      every resolver began reverting `UnknownPlatform`, which is worse
    ///      than a platform whose versions have all been retired: that one
    ///      still resolves what it holds and merely accepts nothing new.
    function setPlatform(bytes32 platformId, HandleNormalizer.Rules calldata rules) external onlyOwner {
        Platform storage platform = _s().platforms[platformId];
        platform.rules = rules;
        platform.configured = true;
        emit PlatformConfigured(platformId);
    }

    // ─── Binding ────────────────────────────────────────────────────

    /// @notice Bind an identity from a ceremony.
    ///
    /// @dev The CONSUMER of ceremony-common section 5.1, and only that. It
    ///      owns the operation domain, records the digest, enforces the
    ///      authorization predicate and applies the effect. Dispatch and the
    ///      fee path belong to the Proof Verifier, which is a contract of its
    ///      own so a second Consumer does not become a second
    ///      version-governance surface; decoding and verifying the payload
    ///      belong to the Platform Verifier the route ends at.
    ///
    ///      This function does not know what `payload` is. It names the
    ///      platform and the verifier version -- this chain's slot for that
    ///      platform, not the ceremony version inside the proof -- and passes
    ///      the bytes through.
    ///
    ///      The value attached must equal `quoteClaim` for the same pair. Exact
    ///      value at every hop needs no refund path, so no partial-failure rule
    ///      is required and nothing can be captured in transit.
    function claim(bytes32 platformId, uint16 verifierVersion, bytes calldata payload, bool publishName)
        external
        payable
        nonReentrant
    {
        Platform memory platform = _requireConfigured(platformId);

        IProofVerifier pv = _s().proofVerifier;
        uint256 required = pv.quote(platformId, verifierVersion);
        if (msg.value != required) revert WrongClaimValue(required, msg.value);

        ICeremony.VerifiedClaim memory claimed = pv.verify{value: required}(platformId, verifierVersion, payload);

        // ── Is this operation ours at all? (REQ-COMMON-06A) ───────────
        //
        // What AUTHENTICATES the domain is the Platform Verifier: it rebuilt
        // the Authorization Digest from this value and the proof opened
        // against that digest -- through the revealed `code_verifier` for X
        // and GitHub, through a public input for Google. Name another domain
        // and the digest changes, so no proof opens against it. This
        // comparison is the Consumer's own duty on top of that: a verifier
        // reports what it read, and this contract applies an effect only for
        // the operation it owns.
        if (claimed.operationDomain != CLAIM_IDENTITY_DOMAIN) {
            revert ForeignOperationDomain(claimed.operationDomain);
        }

        // ── Spend the digest before any effect ────────────────────────
        //
        // Recording belongs here rather than one hop up: at the Proof Verifier
        // anyone watching a submission could call first, consume the digest,
        // and leave this contract nothing to apply -- denial of service for the
        // price of a fee (REQ-COMMON-03A).
        //
        // "Before any effect" is true of the WRITE below, but the digest only
        // becomes known from the call above it, so the nullifier cannot be set
        // before that call returns. `nonReentrant` is what closes the window
        // rather than callee goodwill: without it a Platform Verifier could
        // reenter here, find the digest unspent, and be relying on the outer
        // frame reverting.
        if (_s().spentDigests[claimed.sessionId]) {
            revert DigestAlreadySpent(claimed.sessionId);
        }
        _s().spentDigests[claimed.sessionId] = true;

        // ── The authorization predicate ───────────────────────────────
        //
        // The Authorized Transaction Data of this operation is one address: the
        // wallet the identity binds to. Requiring it to be the authenticated
        // caller is what keeps consent-phishing out of identity theft -- binding
        // to a submitter-supplied address instead would let anyone spend a
        // genuine proof at an address of their choosing.
        if (claimed.transactionData.length != 32) {
            revert BadTransactionData(claimed.transactionData.length);
        }
        address target = abi.decode(claimed.transactionData, (address));
        if (target != msg.sender) revert NotProofTarget(target, msg.sender);

        if (bytes(claimed.userId).length == 0) revert NoUserId();
        if (claimed.metadataObservedAt == 0) revert NoObservationTime();

        _write(
            platformId,
            claimed.userId,
            claimed.handle,
            // Already on the shared scale, and already below the profile's own
            // ceiling: the Platform Verifier owns both, because only it knows
            // what "now" means for the evidence it read.
            claimed.metadataObservedAt,
            publishName,
            platform,
            claimed.ceremonyVersion
        );

        emit CeremonyBound(claimed.sessionId, msg.sender, platformId, claimed.clientIdentifier);
    }

    /// @notice What `claim` requires to be delivered for this pair.
    ///
    /// @dev Asked of the Proof Verifier rather than worked out here: quoting
    ///      covers the whole path -- two Notary Fees on X and GitHub, zero on
    ///      Google -- and a Consumer that computed it would need to know the
    ///      path's topology (REQ-COMMON-06E).
    function quoteClaim(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return _s().proofVerifier.quote(platformId, verifierVersion);
    }

    /// @notice Whether this digest has already been spent here.
    function digestSpent(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    /// @notice The Proof Verifier this Consumer calls.
    function proofVerifier() external view returns (IProofVerifier) {
        return _s().proofVerifier;
    }

    /// @notice Point this Consumer at a Proof Verifier.
    ///
    /// @dev The Supported Version Set is not this contract's to hold. Which
    ///      proof statements the chain accepts is governance's decision over
    ///      there, and a Consumer keeping its own copy would be a second such
    ///      decision, free to drift.
    function setProofVerifier(IProofVerifier verifier) external onlyOwner {
        if (address(verifier) == address(0)) revert ZeroAddress();
        _s().proofVerifier = verifier;
        emit ProofVerifierConfigured(address(verifier));
    }

    /// @dev Everything after authentication, shared by both entry points.
    ///
    ///      Which proof established a name is the authentication half's
    ///      business; the keyspace, the ordering and the display are the same
    ///      whichever half ran.
    function _write(
        bytes32 platformId,
        string memory userId,
        string memory rawHandle,
        uint64 observedAt,
        bool publishName,
        Platform memory platform,
        uint16 ceremonyVersion
    ) private {
        // This platform has now verified something, and no later retirement of
        // its versions makes that untrue. The resolvers read it so a name
        // outlives the format that established it.
        _s().everBound[platformId] = true;

        // `observedAt` arrives already on the shared scale. Profiles disagree
        // about what "now" is -- a notary states wall-clock time, an OIDC claim
        // carries the token's `exp` and runs about an hour ahead -- and the
        // nodes are shared, so raw values would compare two clocks and the
        // looser one would win every time. The Platform Verifier subtracts its
        // own allowance before returning, because only it knows the evidence it
        // read. Subtracting again here would push one platform below every
        // other.

        // Normalize here rather than trusting the verifier or the caller. The
        // key has to come from the same transform every reader uses.
        string memory handle = HandleNormalizer.normalize(rawHandle, platform.rules);

        bytes32 idKey = IdentityNodes.idNode(platformId, userId);
        bytes32 handleKey = IdentityNodes.handleNode(platformId, handle);

        // Strictly newer than BOTH, which is what stops a proof held back from
        // undoing a newer one. It also stops a plain replay, because equal is
        // not newer.
        //
        // Checking the handle node too is the load-bearing half: after somebody
        // else proves this handle, an older proof of it must not take it back.
        _requireNewer(observedAt, _s().byId[idKey].observedAt);
        _requireNewer(observedAt, _s().byHandle[handleKey].observedAt);

        _s().byId[idKey] = Binding({owner: msg.sender, observedAt: observedAt});
        _s().byHandle[handleKey] = Binding({owner: msg.sender, observedAt: observedAt});

        _retirePreviousHandle(platformId, idKey, handleKey);
        _s().handleOfId[idKey] = handleKey;
        _s().idOfHandle[handleKey] = idKey;

        // Publishing follows the wallet's own name, rather than the flag's
        // default. A caller that re-proves after a rename must not keep
        // displaying the handle it no longer holds, and `publishName: false`
        // must not silently withdraw the display either — so an existing
        // publication is refreshed, and only `unpublish` removes one.
        bool published = publishName || bytes(_s().published[msg.sender][platformId]).length != 0;
        if (published) {
            _s().published[msg.sender][platformId] = handle;
        }

        emit IdentityBound(
            msg.sender, idKey, handleKey, platformId, userId, handle, observedAt, published, ceremonyVersion
        );
    }

    /// @dev Stop resolving the handle this account used to hold.
    ///
    ///      A rename is invisible to the chain until somebody proves the new
    ///      state, and this bind is that proof: the account states it holds a
    ///      different handle now, so the old one must stop routing to this
    ///      wallet. Leaving it would send a payment meant for whoever holds
    ///      that handle today to the wallet that renamed away from it.
    ///
    ///      Only the entry this account itself wrote is retired. If somebody
    ///      else has since proved that handle, `_idOfHandle` names their
    ///      account and the entry is left alone — which also covers one wallet
    ///      holding two accounts on a platform, where the second may have taken
    ///      the handle the first released.
    ///
    ///      The owner is cleared, the watermark is kept. Deleting the whole
    ///      record would drop the node back to `observedAt == 0` and let a
    ///      proof older than the one just retired take it — the exact ordering
    ///      `_requireNewer` exists to enforce.
    function _retirePreviousHandle(bytes32 platformId, bytes32 idKey, bytes32 handleKey) private {
        bytes32 previous = _s().handleOfId[idKey];
        if (previous == bytes32(0) || previous == handleKey) return;
        if (_s().idOfHandle[previous] != idKey) return;

        _s().byHandle[previous].owner = address(0);
        emit HandleRetired(platformId, previous, msg.sender);
    }

    /// @notice Withdraw a published handle. Affects the caller's record only.
    ///
    /// @dev Publishing is the one thing here a user can undo, and it needs its
    ///      own door. Passing `publishName: false` to `bind` does NOT clear an
    ///      earlier publish — a caller that binds again after a rename should
    ///      not silently withdraw a name because a flag defaulted; it refreshes
    ///      the published string to the handle just proved. Withdrawing what
    ///      you chose to display must not depend on being able to log in again.
    ///
    ///      The binding itself stays. This clears the on-chain string, not the
    ///      proof of who owns the account, and the `IdentityBound` event that
    ///      carried the plaintext is already public and always will be. Read
    ///      this as "stop displaying it here", not as erasure.
    function unpublish(bytes32 platformId) external {
        delete _s().published[msg.sender][platformId];
        emit NameUnpublished(msg.sender, platformId);
    }

    /// @dev The write path's gate: the keyspace exists, and nothing more. What
    ///      may be claimed against it is the Proof Verifier's question, and it
    ///      is asked there.
    function _requireConfigured(bytes32 platformId) private view returns (Platform memory platform) {
        platform = _s().platforms[platformId];
        if (!platform.configured) revert UnknownPlatform(platformId);
    }

    /// @dev A resolver answers once the platform has both halves: a keyspace,
    ///      and a way to verify. `configured` alone is not enough — between
    ///      `setPlatform` and the first registered version a platform owns a
    ///      keyspace and can verify nothing, and answering `address(0)` there
    ///      would tell a caller "nobody holds this name" about a platform that
    ///      is not wired yet.
    function _requireUsable(bytes32 platformId) private view returns (Platform memory platform) {
        platform = _requireConfigured(platformId);
        // `everBound` first: it is a storage read the resolvers already make,
        // and it settles every name already bound. "Can verify" moves, and
        // governance retiring the last version of a platform must not stop
        // those names resolving -- a name does not belong to the proof that
        // established it.
        //
        // The Proof Verifier holds the Supported Version Set, so it is asked
        // rather than mirrored. It is an external call, so it is asked only
        // when the local answer says nothing.
        if (_s().everBound[platformId]) return platform;

        IProofVerifier pv = _s().proofVerifier;
        if (address(pv) == address(0) || !pv.verifiesPlatform(platformId)) {
            revert UnknownPlatform(platformId);
        }
    }

    function _requireNewer(uint64 observedAt, uint64 known) private pure {
        if (observedAt <= known) revert StaleProof(observedAt, known);
    }

    // ─── Reading ────────────────────────────────────────────────────

    /// @notice The wallet that proved this account id, or the zero address.
    ///
    /// @dev Reverts for a platform with no verifier, like the other two
    ///      resolvers. Returning the zero address there would answer "nobody
    ///      owns this" to a question that was never asked — the platform is not
    ///      wired — and a caller cannot tell the two apart from a zero.
    function resolveId(bytes32 platformId, string calldata userId) external view returns (address) {
        _requireUsable(platformId);
        return _s().byId[IdentityNodes.idNode(platformId, userId)].owner;
    }

    /// @notice The wallet that last proved this handle, or the zero address.
    ///
    /// @dev Takes the handle as written. Normalization happens here, so a
    ///      caller cannot reach a key by hashing the handle its own way.
    ///
    ///      Total in the handle: text this platform could never hold answers
    ///      the zero address, not a revert. A contract resolving whatever a
    ///      user typed into a recipient field would otherwise fail the whole
    ///      transaction on a stray space, with a library error it cannot tell
    ///      apart from `UnknownPlatform`. An unwired platform still reverts,
    ///      because that question was never asked.
    function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address) {
        Platform memory platform = _requireUsable(platformId);
        (bool ok, bytes32 handleKey) = _handleKey(platformId, handle, platform.rules);
        return ok ? _s().byHandle[handleKey].owner : address(0);
    }

    /// @dev The node a handle keys to under the platform's current rules, or
    ///      `ok == false` when the text does not normalize under them.
    function _handleKey(bytes32 platformId, string memory handle, HandleNormalizer.Rules memory rules)
        private
        pure
        returns (bool ok, bytes32 handleKey)
    {
        (HandleNormalizer.Problem problem, string memory normalized) = HandleNormalizer.tryNormalize(handle, rules);
        if (problem != HandleNormalizer.Problem.None) return (false, bytes32(0));
        return (true, IdentityNodes.handleNode(platformId, normalized));
    }

    /// @notice The handle a wallet published, exactly as stored.
    /// @dev May name a handle that now belongs to somebody else. Use
    ///      `primaryOf` unless you are doing the forward check yourself.
    function reverseOf(address wallet, bytes32 platformId) external view returns (string memory) {
        return _s().published[wallet][platformId];
    }

    /// @notice The handle a wallet published, but only while it still resolves
    ///         back to that wallet. Empty otherwise.
    ///
    /// @dev This is the forward check ENS requires of its integrators, done
    ///      here so an integrator cannot skip it. Their reverse records can lie,
    ///      because anyone may set their own; ours cannot, because a proof
    ///      wrote it. Ours can still go stale, which needs the same check: after
    ///      a rename, a wallet's published handle may belong to somebody else.
    ///      The stored string is re-normalized rather than hashed as it stands.
    ///      It was normalized when it was written, but under the rules of that
    ///      moment: after the owner narrows a platform's rules, hashing it
    ///      as-is would reach a node the forward resolver can no longer name,
    ///      and this would keep handing out a name `resolveHandle` refuses.
    function primaryOf(address wallet, bytes32 platformId) external view returns (string memory) {
        string memory published = _s().published[wallet][platformId];
        if (bytes(published).length == 0) return "";
        (bool ok, bytes32 handleKey) = _handleKey(platformId, published, _s().platforms[platformId].rules);
        if (!ok) return "";
        if (_s().byHandle[handleKey].owner != wallet) return "";
        return published;
    }

    /// @notice Resolve a handle, and say whether the caller's account id agrees.
    ///
    /// @dev The whole point of the two mappings. A consumer holds a
    ///      `(handle, userId)` pair it learned at some moment; this reports
    ///      whether the chain still puts them together.
    ///
    ///      Disagreement is not corruption. It means somebody proved the handle
    ///      after the caller learned who owned it. It is also NOT a reason to
    ///      refuse a transfer: a name that will not route is not a name. The
    ///      caller reads this before it signs and decides what to tell a user.
    ///
    /// @return wallet    The current owner of the handle, or the zero address.
    /// @return idAgrees  True only when the id resolves to that same wallet.
    function resolvePair(bytes32 platformId, string calldata handle, string calldata userId)
        external
        view
        returns (address wallet, bool idAgrees)
    {
        Platform memory platform = _requireUsable(platformId);

        (bool ok, bytes32 handleKey) = _handleKey(platformId, handle, platform.rules);
        wallet = ok ? _s().byHandle[handleKey].owner : address(0);

        address idOwner = _s().byId[IdentityNodes.idNode(platformId, userId)].owner;
        // An unknown id does not agree either. A caller holding an id the chain
        // has never seen is exactly as uninformed as one holding a stale id.
        idAgrees = wallet != address(0) && idOwner == wallet;
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would freeze platform configuration forever, which
    ///      leaves no way to replace a verifier whose provider changed.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
