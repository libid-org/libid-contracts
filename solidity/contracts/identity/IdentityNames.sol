// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {HandleNormalizer} from "./HandleNormalizer.sol";
import {IdentityNodes} from "./IdentityNodes.sol";
import {IdentityClaim, IIdentityVerifier} from "./IIdentityVerifier.sol";

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
///      **A platform has versions, and a keyspace it keeps across all of
///      them.** A platform's proof can change shape without the account behind
///      it changing — X gaining OIDC, say — so verifiers are keyed by version
///      and several are live at once while users migrate. What does NOT vary
///      by version is `rules`: it decides the key a handle hashes to, and two
///      versions normalizing differently would put one handle on two nodes and
///      make `resolveHandle` answer differently depending on which version
///      last wrote.
///
///      Retiring a version stops new bindings in that format and touches no
///      name already bound — a name belongs to the account that proved it, not
///      to the format the proof was written in. Every binding records the
///      version that established it, so "is anybody still on the old format"
///      is a question the chain answers rather than one an operator guesses.
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
contract IdentityNames is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @notice A binding, the moment the platform stated it, and the proof
    ///         version that established it.
    ///
    /// @dev `observedAt` is a provider timestamp, never a chain timestamp. Two
    ///      proofs of one handle are ordered by when the platform said it, not
    ///      by when somebody got around to submitting.
    ///
    ///      `version` is what makes retiring an old proof format possible. The
    ///      owner may only stop accepting a version once nobody depends on it,
    ///      and this is the on-chain record of who still does. It rides in the
    ///      same slot: 20 + 8 + 4 bytes is exactly one word, so keeping it
    ///      costs no extra storage.
    struct Binding {
        address owner;
        uint64 observedAt;
        uint32 version;
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
    /// @param rules         How this platform's handles normalize.
    /// @param latestVersion The version plain `bind` uses. Zero means the
    ///                      platform has no verifier yet.
    /// @param configured    Whether the platform exists at all. A platform with
    ///                      every version retired still owns its keyspace, so
    ///                      "is it wired" cannot be read off a verifier address.
    struct Platform {
        HandleNormalizer.Rules rules;
        uint32 latestVersion;
        bool configured;
    }

    /// @notice One proof format for one platform.
    ///
    /// @dev Versions exist because a platform's proof can change shape without
    ///      the account behind it changing — X gaining OIDC, say. Both formats
    ///      have to be accepted while users migrate, so the verifier is keyed
    ///      by version rather than replaced.
    ///
    /// @param verifier             Reads this version of the platform's proof.
    /// @param maxFutureObservation How far ahead of the chain this version's
    ///                             observations may claim to be. Per version,
    ///                             not per platform: a notary states wall-clock
    ///                             time and is never ahead, while an OIDC claim
    ///                             carries the token's `exp` and reads about an
    ///                             hour ahead. See `_requireNotAhead`.
    struct VerifierSlot {
        IIdentityVerifier verifier;
        uint64 maxFutureObservation;
    }

    // ─── State ──────────────────────────────────────────────────────

    /// @notice idNode -> the wallet that proved that account id.
    mapping(bytes32 => Binding) public byId;

    /// @notice handleNode -> the wallet that last proved that handle.
    mapping(bytes32 => Binding) public byHandle;

    /// @notice wallet -> platformId -> the handle it published, if it chose to.
    ///
    /// @dev A node cannot be turned back into a string, so the reverse
    ///      direction needs the string itself. Publishing is optional: the
    ///      event carries the plaintext either way, so an indexer never needs
    ///      this, and only a contract that must display a name does.
    mapping(address => mapping(bytes32 => string)) private _published;

    /// @notice platformId -> its keyspace: handle rules and current version.
    mapping(bytes32 => Platform) private _platforms;

    /// @notice platformId -> version -> the verifier that reads that format.
    ///
    /// @dev Retiring a version is `delete` on one entry here. The keyspace and
    ///      every name already bound under it are untouched: a name does not
    ///      belong to the proof that established it.
    mapping(bytes32 => mapping(uint32 => VerifierSlot)) private _verifiers;

    /// @notice idNode -> the handle node that account last proved, and back.
    ///
    /// @dev An account holds one handle at a time. When it proves a new one the
    ///      old one has to stop resolving, or a payment meant for whoever holds
    ///      that handle now would keep going to the wallet that renamed away
    ///      from it. The reverse map answers "is this node still the one this
    ///      account wrote", so a second account that took the handle in the
    ///      meantime keeps it.
    mapping(bytes32 => bytes32) private _handleOfId;
    mapping(bytes32 => bytes32) private _idOfHandle;

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
    ///      `version` names the proof format that established the binding. It
    ///      is what tells an operator whether a version is still in use, and
    ///      therefore whether retiring it would strand anybody.
    event IdentityBound(
        address indexed owner,
        bytes32 indexed idNode,
        bytes32 indexed handleNode,
        bytes32 platformId,
        string userId,
        string handle,
        uint64 observedAt,
        bool published,
        uint32 version
    );

    /// @notice A handle stopped resolving because the account that held it
    ///         proved a different one.
    /// @dev Nobody else's entry can be retired this way. See `bind`.
    event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed owner);

    /// @notice A platform's keyspace was configured or reconfigured.
    /// @dev Reconfiguring `rules` re-keys every handle already written.
    event PlatformConfigured(bytes32 indexed platformId);

    /// @notice A proof version gained or replaced its verifier.
    event VerifierConfigured(
        bytes32 indexed platformId, uint32 indexed version, address verifier, uint64 maxFutureObservation
    );

    /// @notice A proof version stopped being accepted.
    /// @dev The names bound under it stay exactly where they are.
    event VerifierRetired(bytes32 indexed platformId, uint32 indexed version);

    /// @notice The version plain `bind` now uses.
    event LatestVersionChanged(bytes32 indexed platformId, uint32 indexed version);

    /// @notice A wallet withdrew its published handle.
    /// @dev An indexer that mirrors `reverseOf` needs this to stop showing it.
    event NameUnpublished(address indexed owner, bytes32 indexed platformId);

    // ─── Errors ─────────────────────────────────────────────────────

    /// This platform has no keyspace configured.
    error UnknownPlatform(bytes32 platformId);
    /// This platform has no verifier for that proof version, or it was retired.
    error UnknownVersion(bytes32 platformId, uint32 version);
    /// Version zero is the "no version" sentinel and cannot name a verifier.
    error ZeroVersion();
    /// Retiring the version `bind` defaults to would leave the platform unusable.
    error VersionInUseAsLatest(bytes32 platformId, uint32 version);
    /// The proof names a different address than the caller.
    error NotProofTarget(address proved, address caller);
    /// The proof names nobody. Such a claim is one anybody could redirect.
    error NoTarget();
    /// The proof carries no observation time, so it cannot be ordered.
    error NoObservationTime();
    /// The proof names no account id. A binding is anchored on the id.
    error NoUserId();
    /// A platform needs a verifier. The zero address would remove one.
    error NoVerifier();
    /// The allowance for future observations is larger than any platform needs.
    error AllowanceTooLarge(uint64 allowance, uint64 max);
    /// A newer proof already wrote one of these nodes.
    error StaleProof(uint64 observedAt, uint64 known);
    /// The proof claims an observation further ahead than the platform allows.
    error ObservedInTheFuture(uint64 observedAt, uint64 limit);

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
    }

    /// @notice The largest allowance a platform may carry.
    ///
    /// @dev Two jobs. It keeps the allowance meaningful — the platforms that
    ///      need one report an expiry about an hour ahead, so a day is already
    ///      generous and anything past it is a typo. And it keeps
    ///      `_requireNotAhead` from reverting on its own arithmetic: that sum
    ///      is checked, so an allowance near `type(uint64).max` would panic
    ///      every `bind` for the platform instead of widening its window.
    uint64 public constant MAX_FUTURE_OBSERVATION = 1 days;

    /// @notice The version a platform's first verifier is registered under.
    ///
    /// @dev Numbering starts at one because zero is the "no verifier" sentinel:
    ///      an unconfigured platform reads `latestVersion == 0`, and a retired
    ///      version reads back as the zero address. A version zero would be
    ///      indistinguishable from both.
    uint32 public constant INITIAL_VERSION = 1;

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
        Platform storage platform = _platforms[platformId];
        platform.rules = rules;
        platform.configured = true;
        emit PlatformConfigured(platformId);
    }

    /// @notice Install the verifier for one proof version of a platform.
    ///
    /// @dev This is how a new proof format arrives. Registering it does NOT
    ///      redirect anybody: `bind` keeps using `latestVersion` until the
    ///      owner moves it, so a version can be deployed, exercised against the
    ///      real chain, and only then made the default. The exception is the
    ///      first version a platform gets, where there is nothing to protect
    ///      and requiring two calls would only invite a half-configured
    ///      platform.
    ///
    ///      Re-registering an existing version replaces its verifier, which is
    ///      the repair path for a verifier found to be wrong.
    function setVerifier(bytes32 platformId, uint32 version, IIdentityVerifier verifier, uint64 maxFutureObservation)
        external
        onlyOwner
    {
        if (version == 0) revert ZeroVersion();
        if (address(verifier) == address(0)) revert NoVerifier();
        if (maxFutureObservation > MAX_FUTURE_OBSERVATION) {
            revert AllowanceTooLarge(maxFutureObservation, MAX_FUTURE_OBSERVATION);
        }
        Platform storage platform = _platforms[platformId];
        if (!platform.configured) revert UnknownPlatform(platformId);

        _verifiers[platformId][version] = VerifierSlot({verifier: verifier, maxFutureObservation: maxFutureObservation});
        emit VerifierConfigured(platformId, version, address(verifier), maxFutureObservation);

        if (platform.latestVersion == 0) {
            platform.latestVersion = version;
            emit LatestVersionChanged(platformId, version);
        }
    }

    /// @notice Point plain `bind` at a different version.
    ///
    /// @dev The migration switch. Both versions keep working either side of it
    ///      — this only decides which one a caller that names no version gets.
    function setLatestVersion(bytes32 platformId, uint32 version) external onlyOwner {
        if (version == 0) revert ZeroVersion();
        if (!_platforms[platformId].configured) revert UnknownPlatform(platformId);
        if (address(_verifiers[platformId][version].verifier) == address(0)) {
            revert UnknownVersion(platformId, version);
        }
        _platforms[platformId].latestVersion = version;
        emit LatestVersionChanged(platformId, version);
    }

    /// @notice Stop accepting a proof version.
    ///
    /// @dev The end of a migration. Names bound under this version are NOT
    ///      touched: a name belongs to the account that proved it, not to the
    ///      format the proof was written in. What stops is minting new ones.
    ///
    ///      The version `bind` defaults to cannot be retired, because that
    ///      would leave the platform accepting nothing while still answering
    ///      `bind` — move `latestVersion` first, then retire.
    ///
    ///      Whether anybody still depends on a version is answerable before
    ///      calling this: every `IdentityBound` carries the version, and
    ///      `byId`/`byHandle` record it per binding.
    function retireVerifier(bytes32 platformId, uint32 version) external onlyOwner {
        if (address(_verifiers[platformId][version].verifier) == address(0)) {
            revert UnknownVersion(platformId, version);
        }
        if (_platforms[platformId].latestVersion == version) {
            revert VersionInUseAsLatest(platformId, version);
        }
        delete _verifiers[platformId][version];
        emit VerifierRetired(platformId, version);
    }

    /// @notice The verifier for one version of a platform, or the zero address.
    function verifierOf(bytes32 platformId, uint32 version) external view returns (IIdentityVerifier) {
        return _verifiers[platformId][version].verifier;
    }

    /// @notice The version plain `bind` uses, or zero if the platform has none.
    function latestVersionOf(bytes32 platformId) external view returns (uint32) {
        return _platforms[platformId].latestVersion;
    }

    // ─── Binding ────────────────────────────────────────────────────

    /// @notice Prove an identity and bind it to the caller.
    ///
    /// @param platformId  Which platform the proof is for.
    /// @param proof       The platform's proof, opaque to this contract.
    /// @param publishName Also store the handle as a string, so a contract can
    ///                    read the reverse direction on chain. The event
    ///                    carries the plaintext either way.
    function bind(bytes32 platformId, bytes calldata proof, bool publishName) external {
        _bind(platformId, _platforms[platformId].latestVersion, proof, publishName);
    }

    /// @notice Prove an identity with a named proof version.
    ///
    /// @dev The caller states the version rather than the contract inferring
    ///      it. Inferring would mean either a version header every verifier has
    ///      to agree on — which couples the formats together, the thing
    ///      versioning exists to avoid — or trying each verifier in turn, which
    ///      costs gas per retired version and risks a proof for one format
    ///      accidentally satisfying another.
    ///
    ///      A client that does not care passes none: `bind` uses the platform's
    ///      latest. A client mid-migration names the version it built its proof
    ///      for, and keeps working the day the default moves.
    ///
    /// @param version Which proof format `proof` is written in.
    function bindAtVersion(bytes32 platformId, uint32 version, bytes calldata proof, bool publishName) external {
        _bind(platformId, version, proof, publishName);
    }

    function _bind(bytes32 platformId, uint32 version, bytes calldata proof, bool publishName) private {
        Platform memory platform = _platforms[platformId];
        if (!platform.configured) revert UnknownPlatform(platformId);

        VerifierSlot memory slot = _verifiers[platformId][version];
        if (address(slot.verifier) == address(0)) revert UnknownVersion(platformId, version);

        IdentityClaim memory claim = slot.verifier.verify(proof);

        if (claim.target == address(0)) revert NoTarget();
        // The one authorization rule. A proof read from the mempool is useless
        // to a reader, because spending it requires being the address it names.
        if (claim.target != msg.sender) revert NotProofTarget(claim.target, msg.sender);
        if (claim.observedAt == 0) revert NoObservationTime();
        // Every shipped verifier rejects an empty id before returning, so this
        // is the check that keeps that true for the next one. Without it every
        // account a lax verifier reported would land on the single node
        // `idNode(platformId, "")` and take turns owning it.
        if (bytes(claim.userId).length == 0) revert NoUserId();
        _requireNotAhead(claim.observedAt, slot.maxFutureObservation);

        // Normalize here rather than trusting the verifier or the caller. The
        // key has to come from the same transform every reader uses.
        string memory handle = HandleNormalizer.normalize(claim.handle, platform.rules);

        bytes32 idKey = IdentityNodes.idNode(platformId, claim.userId);
        bytes32 handleKey = IdentityNodes.handleNode(platformId, handle);

        // Strictly newer than BOTH, which is what stops a proof held back from
        // undoing a newer one. It also stops a plain replay, because equal is
        // not newer.
        //
        // Checking the handle node too is the load-bearing half: after somebody
        // else proves this handle, an older proof of it must not take it back.
        _requireNewer(claim.observedAt, byId[idKey].observedAt);
        _requireNewer(claim.observedAt, byHandle[handleKey].observedAt);

        byId[idKey] = Binding({owner: msg.sender, observedAt: claim.observedAt, version: version});
        byHandle[handleKey] = Binding({owner: msg.sender, observedAt: claim.observedAt, version: version});

        _retirePreviousHandle(platformId, idKey, handleKey);
        _handleOfId[idKey] = handleKey;
        _idOfHandle[handleKey] = idKey;

        // Publishing follows the wallet's own name, rather than the flag's
        // default. A caller that re-proves after a rename must not keep
        // displaying the handle it no longer holds, and `publishName: false`
        // must not silently withdraw the display either — so an existing
        // publication is refreshed, and only `unpublish` removes one.
        bool published = publishName || bytes(_published[msg.sender][platformId]).length != 0;
        if (published) {
            _published[msg.sender][platformId] = handle;
        }

        emit IdentityBound(
            msg.sender, idKey, handleKey, platformId, claim.userId, handle, claim.observedAt, published, version
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
        bytes32 previous = _handleOfId[idKey];
        if (previous == bytes32(0) || previous == handleKey) return;
        if (_idOfHandle[previous] != idKey) return;

        byHandle[previous].owner = address(0);
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
        delete _published[msg.sender][platformId];
        emit NameUnpublished(msg.sender, platformId);
    }

    function _requireNewer(uint64 observedAt, uint64 known) private pure {
        if (observedAt <= known) revert StaleProof(observedAt, known);
    }

    /// @dev Refuse an observation dated further ahead than the platform allows.
    ///
    ///      This is what keeps a name recoverable. A binding is superseded only
    ///      by a strictly newer `observedAt`, so a proof dated far enough ahead
    ///      would make every honest later proof look stale and hold the name
    ///      until the clock caught up. Proving again is the whole remedy for a
    ///      name bound by somebody else, so it must not be possible to take
    ///      that remedy away.
    ///
    ///      The allowance is per platform because the platforms report on
    ///      different scales. A notary states wall-clock time, so its proofs
    ///      are never ahead. Google's circuit exposes no `iat`, so an OIDC
    ///      claim carries the token's `exp` — roughly an hour ahead of
    ///      issuance. One number for both would either reject every Google
    ///      binding or hand X a griefing window it never needed.
    function _requireNotAhead(uint64 observedAt, uint64 allowance) private view {
        uint64 limit = uint64(block.timestamp) + allowance;
        if (observedAt > limit) revert ObservedInTheFuture(observedAt, limit);
    }

    // ─── Reading ────────────────────────────────────────────────────

    /// @notice The wallet that proved this account id, or the zero address.
    ///
    /// @dev Reverts for a platform with no verifier, like the other two
    ///      resolvers. Returning the zero address there would answer "nobody
    ///      owns this" to a question that was never asked — the platform is not
    ///      wired — and a caller cannot tell the two apart from a zero.
    function resolveId(bytes32 platformId, string calldata userId) external view returns (address) {
        if (!_platforms[platformId].configured) revert UnknownPlatform(platformId);
        return byId[IdentityNodes.idNode(platformId, userId)].owner;
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
        Platform memory platform = _platforms[platformId];
        if (!platform.configured) revert UnknownPlatform(platformId);
        (bool ok, bytes32 handleKey) = _handleKey(platformId, handle, platform.rules);
        return ok ? byHandle[handleKey].owner : address(0);
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
        return _published[wallet][platformId];
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
        string memory published = _published[wallet][platformId];
        if (bytes(published).length == 0) return "";
        (bool ok, bytes32 handleKey) = _handleKey(platformId, published, _platforms[platformId].rules);
        if (!ok) return "";
        if (byHandle[handleKey].owner != wallet) return "";
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
        Platform memory platform = _platforms[platformId];
        if (!platform.configured) revert UnknownPlatform(platformId);

        (bool ok, bytes32 handleKey) = _handleKey(platformId, handle, platform.rules);
        wallet = ok ? byHandle[handleKey].owner : address(0);

        address idOwner = byId[IdentityNodes.idNode(platformId, userId)].owner;
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
