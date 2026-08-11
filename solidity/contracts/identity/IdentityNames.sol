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
///      verifier a platform uses, and a verifier is trusted to report what a
///      proof says — so an owner that installs a dishonest verifier can mint
///      any claim. It can also change a platform's normalization rules, which
///      re-keys every handle already written: the old entries survive but no
///      longer answer the public resolvers. And the contract is UUPS, so the
///      owner can replace all of this. Read the guarantee above as "under
///      honest configuration"; the trust boundary is the owner key, and it is
///      the same one every upgradeable contract here has.
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
    /// @notice A binding and the moment the platform stated it.
    /// @dev `observedAt` is a provider timestamp, never a chain timestamp. Two
    ///      proofs of one handle are ordered by when the platform said it, not
    ///      by when somebody got around to submitting.
    struct Binding {
        address owner;
        uint64 observedAt;
    }

    /// @notice A platform this contract accepts proofs for.
    ///
    /// @param verifier             Reads the platform's proof.
    /// @param maxFutureObservation How far ahead of the chain this platform's
    ///                             observations may claim to be. See
    ///                             `_requireNotAhead` for why it exists and why
    ///                             it belongs to the platform rather than being
    ///                             one number for all of them.
    /// @param rules                How this platform's handles normalize.
    struct Platform {
        IIdentityVerifier verifier;
        uint64 maxFutureObservation;
        HandleNormalizer.Rules rules;
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

    /// @notice platformId -> its verifier and handle rules.
    mapping(bytes32 => Platform) private _platforms;

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
    event IdentityBound(
        address indexed owner,
        bytes32 indexed idNode,
        bytes32 indexed handleNode,
        bytes32 platformId,
        string userId,
        string handle,
        uint64 observedAt,
        bool published
    );

    /// @notice A handle stopped resolving because the account that held it
    ///         proved a different one.
    /// @dev Nobody else's entry can be retired this way. See `bind`.
    event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed owner);

    /// @notice A platform was configured or reconfigured.
    event PlatformConfigured(bytes32 indexed platformId, address verifier);

    /// @notice A wallet withdrew its published handle.
    /// @dev An indexer that mirrors `reverseOf` needs this to stop showing it.
    event NameUnpublished(address indexed owner, bytes32 indexed platformId);

    // ─── Errors ─────────────────────────────────────────────────────

    /// No verifier is configured for this platform.
    error UnknownPlatform(bytes32 platformId);
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

    /// @notice Add a platform or replace its verifier and rules.
    ///
    /// @dev Owner-managed. See the contract comment for the whole of what this
    ///      power is — in particular, changing `rules` re-keys handles that are
    ///      already written.
    ///
    ///      A zero verifier is refused. It would read as "remove this
    ///      platform", and removal is not a power this contract offers: the
    ///      names would stay in storage while `bind`, `resolveHandle` and
    ///      `resolvePair` all began reverting `UnknownPlatform`.
    function setPlatform(
        bytes32 platformId,
        IIdentityVerifier verifier,
        uint64 maxFutureObservation,
        HandleNormalizer.Rules calldata rules
    ) external onlyOwner {
        if (address(verifier) == address(0)) revert NoVerifier();
        if (maxFutureObservation > MAX_FUTURE_OBSERVATION) {
            revert AllowanceTooLarge(maxFutureObservation, MAX_FUTURE_OBSERVATION);
        }
        _platforms[platformId] =
            Platform({verifier: verifier, maxFutureObservation: maxFutureObservation, rules: rules});
        emit PlatformConfigured(platformId, address(verifier));
    }

    /// @notice The verifier configured for a platform, or the zero address.
    function verifierOf(bytes32 platformId) external view returns (IIdentityVerifier) {
        return _platforms[platformId].verifier;
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
        Platform memory platform = _platforms[platformId];
        if (address(platform.verifier) == address(0)) revert UnknownPlatform(platformId);

        IdentityClaim memory claim = platform.verifier.verify(proof);

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
        _requireNotAhead(claim.observedAt, platform.maxFutureObservation);

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

        byId[idKey] = Binding({owner: msg.sender, observedAt: claim.observedAt});
        byHandle[handleKey] = Binding({owner: msg.sender, observedAt: claim.observedAt});

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

        emit IdentityBound(msg.sender, idKey, handleKey, platformId, claim.userId, handle, claim.observedAt, published);
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
        if (address(_platforms[platformId].verifier) == address(0)) revert UnknownPlatform(platformId);
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
        if (address(platform.verifier) == address(0)) revert UnknownPlatform(platformId);
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
        if (address(platform.verifier) == address(0)) revert UnknownPlatform(platformId);

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
