// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {
    ReentrancyGuardTransientUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";

import {HandleNormalizer} from "../identity/HandleNormalizer.sol";
import {IIdentityNames} from "./IIdentityNames.sol";

/// @title HandleEscrow - send to a platform handle before anybody claims it.
///
/// @notice Holds tokens against a platform handle. Whoever proves that handle
///         to the naming system takes what is held for it.
///
/// @dev The point is a sender who knows `@alice` and nothing else. The Bank's
///      escrow is keyed by an account's immutable id, which such a sender does
///      not have, so this keys by the handle itself.
///
///      **The handle is the whole key. There is no deadline and no refund.**
///      That was decided deliberately, and the consequence is stated here
///      rather than left to be discovered: A PLATFORM THAT RECYCLES A HANDLE
///      HANDS THE NEW HOLDER WHATEVER ACCUMULATED FOR THE PREVIOUS ONE. So does
///      a rename — the account that renames away stops being able to claim, and
///      whoever proves the freed handle next receives it. A depositor cannot
///      take a deposit back, and neither can the owner. Send to a handle the
///      way you send to an address: because you mean that name to have it.
///
///      **The escrow is for the window before a handle is claimed, and only
///      that.** A deposit for a handle that already resolves is paid straight to
///      its holder; once an account has claimed its identity, holding the value
///      would add a claim transaction and reach the same wallet. So an escrow
///      slot exists only while nobody holds the handle, and stops being written
///      the moment somebody does.
///
///      **What the escrow keys on is NOT what it validates against.** The slot
///      comes from a rules-independent form of the text — see `_canonical` — so
///      the owner reconfiguring a platform's normalization cannot move money
///      that is already held. The text is separately checked against the
///      platform's CURRENT rules on the way in, so nobody funds a slot that
///      could never be claimed. A later rules change therefore decides what is
///      accepted next, and never where what is already here belongs.
///
///      What it can still do is STRAND. A claim is authorized by
///      `resolveHandle`, which normalizes under the rules of the moment, so an
///      owner who narrows a platform — dropping the underscore, say — makes
///      handles carrying one resolve to nobody, and the value keyed to them
///      waits, at the same key, until compatible rules return. Immunity from
///      re-keying is not immunity from that.
///
///      **The transform is pinned here, the rules are read live.** This
///      contract carries its own compiled copy of `HandleNormalizer` and reads
///      only `Rules` from the naming system. That is what makes the key
///      independent of configuration — but it also means the naming system
///      cannot change the TRANSFORM alone: it is separately upgradeable, and a
///      normalizer that folded differently there would break the agreement
///      silently, in the direction of one identity holding two slots. Such an
///      upgrade has to carry an upgrade here. The same goes for a `Rules`
///      field appended on that side: this contract's decoder would drop it.
///
///      **The naming contract is set once and never moved.** Repointing it
///      would redirect every entitlement held, so changing it is an upgrade,
///      which leaves a record.
///
///      **There is no pause.** A pause on `claim` freezes other people's money
///      behind an owner key, and the emergency lever is the upgrade, which is
///      already visible.
///
///      **The naming system's owner is part of this contract's trust base, and
///      that is not a pause substitute — it is larger.** Authorization here is
///      `resolveHandle` and nothing else, so whoever can decide what that
///      answers can take what is held. The naming owner can: `setVerifier`
///      installs a verifier it controls, a `bind` through it makes it the
///      holder of any handle, and `claim` then pays it. Two ordinary
///      transactions, no upgrade and no proxy event. Read every guarantee here
///      as "under an honest naming owner"; it is the same key that already
///      decides which proofs mint names at all, so this adds no new party —
///      only a new thing that key can reach.
contract HandleEscrow is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardTransientUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice The native token of the chain, as a token address.
    address public constant NATIVE = address(0);

    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct HandleEscrowStorage {
        /// slot -> token -> amount held.
        mapping(bytes32 => mapping(address => uint256)) held;
        /// The naming system this escrow resolves through. Set in `initialize`.
        IIdentityNames names;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.HandleEscrow")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant HANDLE_ESCROW_STORAGE = 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400;

    /// @dev One namespaced root, as `IdentityNames` and `Registry` have. Fields
    ///      may be APPENDED on upgrade; reordering or removing one would make
    ///      every stored balance read out of the wrong bytes, and a balance read
    ///      from the wrong bytes does not revert — it answers.
    function _s() private pure returns (HandleEscrowStorage storage $) {
        assembly {
            $.slot := HANDLE_ESCROW_STORAGE
        }
    }

    /// @dev The domain separator of the slot key. Version it rather than
    ///      changing the derivation in place: a new scheme must land on new
    ///      slots, not silently re-point the funded ones.
    bytes32 private constant HANDLE_SLOT_V1 = keccak256(bytes("libid.escrow.handle-slot.v1"));

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice Value was placed against a handle.
    /// @dev `handle` rides along as text so an indexer can show who it is for
    ///      without turning a slot back into a string, which cannot be done.
    event Deposited(
        bytes32 indexed slot,
        address indexed token,
        address indexed depositor,
        bytes32 platformId,
        string handle,
        uint256 amount
    );

    /// @notice A deposit for a handle somebody already held was paid straight to
    ///         that holder, and never entered the books.
    /// @dev Distinct from `Deposited` on purpose: an indexer must be able to tell
    ///      "this is waiting" from "this was delivered", and no balance changed
    ///      here for it to read.
    event Forwarded(
        bytes32 indexed slot,
        address indexed token,
        address indexed depositor,
        address holder,
        bytes32 platformId,
        string handle,
        uint256 amount
    );

    /// @notice The holder of a handle took what was held for it.
    event Claimed(
        bytes32 indexed slot, address indexed token, address indexed claimer, address recipient, uint256 amount
    );

    // ─── Errors ─────────────────────────────────────────────────────

    /// A deposit of nothing writes nothing.
    error ZeroAmount();
    /// Native value must equal the amount, and a token deposit carries none.
    error ValueMismatch(uint256 expected, uint256 provided);
    /// Nothing is held for this handle in this token.
    error NothingHeld(bytes32 slot, address token);
    /// The caller does not hold this handle.
    error NotTheHolder(address holder, address caller);
    /// A payout to the zero address burns it; one to this contract strands it.
    error BadRecipient(address recipient);
    /// Text this platform could never accept as a handle.
    error UnusableHandle(HandleNormalizer.Problem problem);
    /// The recipient refused the transfer.
    error NativeTransferFailed(address recipient, uint256 amount);
    /// The escrow needs a naming system to resolve through.
    error NoNames();

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, IIdentityNames names_) external initializer {
        if (address(names_) == address(0)) revert NoNames();
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuardTransient_init();
        _s().names = names_;
    }

    /// @notice The naming system this escrow resolves through.
    function names() external view returns (IIdentityNames) {
        return _s().names;
    }

    // ─── Depositing ─────────────────────────────────────────────────

    /// @notice Put `amount` of `token` against a handle.
    ///
    /// @dev Escrows whether or not somebody holds the handle today. The
    ///      depositor gives up the value: there is no way to take it back.
    ///
    ///      The text is validated against the platform's current rules, so a
    ///      typo — a space, a character the platform forbids, a handle past its
    ///      length — is refused here rather than accepted into a slot no proof
    ///      could ever claim.
    ///
    ///      **A handle somebody already holds is paid straight through.** The
    ///      escrow exists for the window before a handle is claimed. Once it is
    ///      claimed the escrow has no purpose: holding the value would only add
    ///      a claim transaction to reach the same wallet. So a deposit for a
    ///      resolving handle is a payment, and only an unclaimed handle escrows.
    ///
    ///      This is what makes a deposit depend on the recipient: a holder that
    ///      cannot receive value fails the whole call. That is the honest
    ///      outcome — the sender learns instead of the value waiting in a slot
    ///      only that same wallet could ever claim.
    ///
    ///      **The race is accepted.** One calldata has two outcomes depending on
    ///      whether it lands before or after a `bind` in the same block: it pays
    ///      through, or it escrows and waits for a claim. Both deliver to the
    ///      holder of the handle, so the difference is one transaction, not one
    ///      of destination.
    ///
    ///      When it does escrow, what is credited is the balance the contract
    ///      actually gained, not the amount asked for, so a token that takes a
    ///      fee on transfer cannot make the books promise more than the contract
    ///      holds. A payment through is not measured, because nothing is booked:
    ///      such a token simply delivers less, exactly as it would on a direct
    ///      transfer.
    ///
    /// @param platformId Which platform the handle belongs to.
    /// @param handle     The handle, as written. Case and surrounding spaces do
    ///                   not matter; a leading at-sign is refused, because it
    ///                   is the same handle spelled another way.
    /// @param token      The ERC-20, or `NATIVE` for the chain's own token.
    /// @param amount     How much. For `NATIVE` it must equal `msg.value`.
    function deposit(bytes32 platformId, string calldata handle, address token, uint256 amount)
        external
        payable
        nonReentrant
    {
        if (amount == 0) revert ZeroAmount();
        bytes32 slot = _requireUsableSlot(platformId, handle);

        if (token == NATIVE) {
            if (msg.value != amount) revert ValueMismatch(amount, msg.value);
        } else if (msg.value != 0) {
            // Ether riding on a token deposit has nowhere to land.
            revert ValueMismatch(0, msg.value);
        }

        address holder = _s().names.resolveHandle(platformId, handle);
        if (holder != address(0)) {
            uint256 delivered = amount;
            if (token == NATIVE) {
                _sendNative(holder, amount);
            } else {
                // What the holder GAINED, not what was asked for. A token that
                // takes a fee on transfer delivers less, and an event carrying
                // the requested figure would be the only record of a payment
                // that never happened at that size — the escrowed path at
                // least has a stored balance to correct against.
                uint256 before = IERC20(token).balanceOf(holder);
                IERC20(token).safeTransferFrom(msg.sender, holder, amount);
                delivered = IERC20(token).balanceOf(holder) - before;
            }
            emit Forwarded(slot, token, msg.sender, holder, platformId, handle, delivered);
            return;
        }

        uint256 credited;
        if (token == NATIVE) {
            credited = amount;
        } else {
            uint256 before = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            credited = IERC20(token).balanceOf(address(this)) - before;
            if (credited == 0) revert ZeroAmount();
        }

        _s().held[slot][token] += credited;
        emit Deposited(slot, token, msg.sender, platformId, handle, credited);
    }

    // ─── Claiming ───────────────────────────────────────────────────

    /// @notice Take everything held for a handle in one token.
    ///
    /// @dev Authorized by the naming system and nothing else: the caller has to
    ///      be the wallet that handle currently resolves to. Copying this
    ///      calldata out of the mempool gains nothing, because the check is
    ///      against the caller.
    ///
    ///      A retired handle — one whose account renamed away — resolves to
    ///      nobody, so its slot waits until somebody proves that handle again.
    ///      That may be a different account, and then the balance is theirs.
    ///      See the contract comment.
    ///
    ///      **The destination is checked, not only the caller.** The zero
    ///      address accepts a native transfer without reverting, so an unset
    ///      recipient would burn the slot and log a success; this contract's
    ///      own address would empty the books while the value stayed put as
    ///      surplus nothing points at. Neither is recoverable — there is no
    ///      refund and no owner lever — so both are refused here.
    ///
    ///      The platform's rules are NOT re-checked on the way out. Text that
    ///      no longer normalizes resolves to nobody, so the holder check
    ///      already refuses it, and re-checking would only replace an honest
    ///      `NotTheHolder` with a misleading `UnusableHandle`.
    ///
    /// @param recipient Where the value goes. The claimer's choice, so a wallet
    ///                  that holds the name can pay out somewhere else.
    function claim(bytes32 platformId, string calldata handle, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        bytes32 slot = slotOf(platformId, handle);

        address holder = _s().names.resolveHandle(platformId, handle);
        if (holder != msg.sender) revert NotTheHolder(holder, msg.sender);

        uint256 amount = _s().held[slot][token];
        if (amount == 0) revert NothingHeld(slot, token);
        _s().held[slot][token] = 0;

        if (token == NATIVE) {
            _sendNative(recipient, amount);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
        emit Claimed(slot, token, msg.sender, recipient, amount);
    }

    // ─── Reading ────────────────────────────────────────────────────

    /// @notice How much is held for a handle in one token.
    function escrowed(bytes32 platformId, string calldata handle, address token) external view returns (uint256) {
        return _s().held[slotOf(platformId, handle)][token];
    }

    /// @notice The same, for a slot already computed.
    ///
    /// @dev Takes the slot as given and checks nothing about it, which is what
    ///      an indexer reading raw slots off the logs needs. A slot that was
    ///      never funded and a slot that could never exist both answer zero,
    ///      and this cannot tell them apart. Where the handle is known, use
    ///      `escrowed` — but note it applies only the refusals that KEYING
    ///      needs, not the platform's rules; text a deposit would refuse can
    ///      still be read for.
    function escrowedAt(bytes32 slot, address token) external view returns (uint256) {
        return _s().held[slot][token];
    }

    /// @notice The slot a handle keys to.
    ///
    /// @dev Public so an indexer, a Rust deployer and a browser can all reach
    ///      the same key, and so a caller can check two spellings land together
    ///      before it sends anything.
    function slotOf(bytes32 platformId, string memory handle) public pure returns (bytes32) {
        return keccak256(abi.encode(HANDLE_SLOT_V1, platformId, keccak256(bytes(_canonical(handle)))));
    }

    /// @notice The form of a handle this contract keys on.
    /// @dev Exposed so the transform can be checked against the naming system's
    ///      own by anybody, in any language.
    function canonicalHandle(string memory handle) public pure returns (string memory) {
        return _canonical(handle);
    }

    function _sendNative(address to, uint256 amount) private {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeTransferFailed(to, amount);
    }

    // ─── The key ────────────────────────────────────────────────────

    /// @dev The form a handle keys on, WITHOUT reading a platform's rules.
    ///
    ///      Rules-independent on purpose. Deriving the slot from
    ///      `HandleNormalizer.normalize` would tie every held balance to the
    ///      configuration of the moment, and the owner narrowing a platform's
    ///      rules would move money already deposited onto keys nobody asks
    ///      about. What varies by platform belongs in the check on the way in,
    ///      not in the key.
    ///
    ///      It is a PREFIX of the naming system's transform: trim ASCII spaces,
    ///      fold A-Z. Both steps are also the first steps of `tryNormalize`,
    ///      neither touches a byte the other cares about, and both are
    ///      idempotent — so for text the platform accepts, this returns exactly
    ///      what `normalize` returns, whatever the rules are.
    ///
    ///      The one place the two could disagree is `stripLeadingAt`, which
    ///      folds an at-prefixed spelling and a bare one together in the naming
    ///      system. So this drops one leading at-sign too, and the two spellings
    ///      reach one slot instead of splitting one identity's money across two
    ///      keys with half of it unreachable.
    function _canonical(string memory handle) private pure returns (string memory) {
        bytes memory input = bytes(handle);

        uint256 start = 0;
        uint256 end = input.length;
        while (start < end && input[start] == 0x20) {
            start++;
        }
        while (end > start && input[end - 1] == 0x20) {
            end--;
        }

        // Drop ONE leading at-sign, exactly as `stripLeadingAt` does. Doing it
        // unconditionally is safe because no expressible `Rules` accepts a
        // handle whose text starts with one: a non-email platform refuses
        // `0x40` outright, and an email needs a name part before its `@`. So
        // for a platform that strips, both spellings reach one slot and agree
        // with the resolver; for one that does not, the spelling with the
        // at-sign is refused by the rules check and never funds anything.
        //
        // The invariant to keep: a platform must never accept a handle
        // beginning with an at-sign. If one ever could, `@x` and `x` would be
        // two identities sharing a slot.
        if (start < end && input[start] == 0x40) {
            start++;
        }

        uint256 length = end - start;
        if (length == 0) revert UnusableHandle(HandleNormalizer.Problem.Empty);

        bytes memory out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            bytes1 c = input[start + i];
            if (c >= 0x41 && c <= 0x5A) {
                c = bytes1(uint8(c) + 0x20);
            }
            out[i] = c;
        }
        return string(out);
    }

    /// @dev The slot for text the platform can actually accept.
    ///
    ///      Both halves matter. `rulesOf` reverts for a platform that is not
    ///      wired, which catches a mistyped `platformId` before it takes
    ///      anybody's money. `tryNormalize` then decides whether this text
    ///      could ever be a handle there, which is the question `resolveHandle`
    ///      cannot answer: it returns the zero address for a handle nobody
    ///      holds and for text nobody could hold, and those two must not be
    ///      confused when money is about to move.
    function _requireUsableSlot(bytes32 platformId, string calldata handle) private view returns (bytes32) {
        HandleNormalizer.Rules memory rules = _s().names.rulesOf(platformId);
        (HandleNormalizer.Problem problem,) = HandleNormalizer.tryNormalize(handle, rules);
        if (problem != HandleNormalizer.Problem.None) revert UnusableHandle(problem);
        return slotOf(platformId, handle);
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to repair a broken deployment, and
    ///      the upgrade is the only lever there is.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
