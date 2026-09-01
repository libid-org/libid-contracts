// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {
    ReentrancyGuardTransientUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";

import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityNames} from "../../identity/IdentityNames.sol";
import {IIdentityVerifier} from "../../identity/IIdentityVerifier.sol";
import {MockIdentityVerifier} from "../../identity/test/MockIdentityVerifier.sol";
import {MockERC20} from "../../transfer/MockERC20.sol";
import {HandleEscrow} from "../HandleEscrow.sol";
import {IIdentityNames} from "../IIdentityNames.sol";

/// @notice Takes a cut of every transfer, the way a fee-on-transfer token does.
contract FeeToken is MockERC20 {
    uint256 public constant FEE_BPS = 100; // 1%

    constructor() MockERC20("Fee", "FEE") {}

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        _transfer(from, address(0xdead), fee);
        _transfer(from, to, amount - fee);
        _spendAllowance(from, msg.sender, amount);
        return true;
    }
}

/// @notice A second version that APPENDS to the namespaced root, which is the
///         only change the storage rule allows.
///
/// @dev Upgrading to a byte-identical implementation proves nothing about the
///      layout. This adds a field after the existing ones and reads the old
///      ones back, so a reordered or removed field shows up as a wrong balance
///      rather than as a passing test.
contract HandleEscrowV2 is HandleEscrow {
    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct V2Storage {
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityNames names;
        uint256 appended;
    }

    function _v2() private pure returns (V2Storage storage $) {
        assembly {
            $.slot := 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400
        }
    }

    function setAppended(uint256 v) external {
        _v2().appended = v;
    }

    function appended() external view returns (uint256) {
        return _v2().appended;
    }

    /// Read the pre-existing fields through the V2 layout.
    function heldThroughV2(bytes32 slot, address token) external view returns (uint256) {
        return _v2().held[slot][token];
    }

    function namesThroughV2() external view returns (address) {
        return address(_v2().names);
    }
}

/// @notice Refuses every native transfer.
contract RejectEther {
    // No receive, no fallback.
}

/// @notice Calls `deposit` again from inside its own transfer, the way a token
///         with a receiver hook does.
///
/// @dev This is what the guard on `deposit` is for. The credit is the balance
///      the contract GAINED, measured across the transfer — so a transfer that
///      re-enters and deposits again folds the inner deposit's tokens into the
///      outer one's measurement, and the books end up promising more than the
///      contract holds.
contract ReenteringToken is MockERC20 {
    HandleEscrow public escrow;
    bytes32 public platformId;
    bool private entered;

    constructor() MockERC20("Hook", "HOOK") {}

    function arm(HandleEscrow escrow_, bytes32 platformId_) external {
        escrow = escrow_;
        platformId = platformId_;
        _approve(address(this), address(escrow_), type(uint256).max);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        bool ok = super.transferFrom(from, to, amount);
        if (!entered && address(escrow) != address(0)) {
            entered = true;
            escrow.deposit(platformId, "bob", address(this), 1 ether);
        }
        return ok;
    }
}

/// @notice Calls `claim` again from inside the native payout.
contract ReenteringClaimer {
    HandleEscrow private immutable escrow;
    bytes32 private immutable platformId;
    string private handle;
    bool private entered;

    constructor(HandleEscrow escrow_, bytes32 platformId_, string memory handle_) {
        escrow = escrow_;
        platformId = platformId_;
        handle = handle_;
    }

    function take() external {
        escrow.claim(platformId, handle, address(0), address(this));
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        escrow.claim(platformId, handle, address(0), address(this));
    }
}

/// @notice The handle-keyed escrow, against the real naming system.
///
/// @dev Wired to a real `IdentityNames` behind its proxy rather than a mock, so
///      a rename and a recycled handle are stageable exactly as they happen.
contract HandleEscrowTest is Test {
    IdentityNames internal names;
    MockIdentityVerifier internal verifier;
    HandleEscrow internal escrow;
    MockERC20 internal token;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;
    bytes32 internal constant UNWIRED = keccak256("no such platform");

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal sender = makeAddr("sender");
    address internal owner = makeAddr("owner");

    uint32 internal constant V1 = 1;
    uint64 internal constant NO_FUTURE_ALLOWANCE = 0;
    address internal constant NATIVE = address(0);

    function setUp() public {
        IdentityNames namesImpl = new IdentityNames();
        names = IdentityNames(
            address(new ERC1967Proxy(address(namesImpl), abi.encodeCall(IdentityNames.initialize, (owner))))
        );
        verifier = new MockIdentityVerifier("mock");

        vm.startPrank(owner);
        names.setPlatform(X, HandleVectors.rulesFor(X));
        names.setVerifier(X, V1, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
        names.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB));
        names.setVerifier(GITHUB, V1, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
        vm.stopPrank();

        HandleEscrow escrowImpl = new HandleEscrow();
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(escrowImpl),
                    abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(address(names))))
                )
            )
        );

        token = new MockERC20("Token", "TKN");
        token.mint(sender, 1_000 ether);
        vm.prank(sender);
        token.approve(address(escrow), type(uint256).max);

        vm.deal(sender, 100 ether);
        vm.warp(1_000_000);
    }

    /// Prove `handle` for `who`, the way a login does.
    function _bind(address who, string memory userId, string memory handle, uint64 at) internal {
        verifier.stage(userId, handle, who, at);
        vm.prank(who);
        names.bind(X, hex"", false);
    }

    function _depositNative(string memory handle, uint256 amount) internal {
        vm.prank(sender);
        escrow.deposit{value: amount}(X, handle, NATIVE, amount);
    }

    // ─── The key ────────────────────────────────────────────────────

    /// The lemma the whole design rests on: for every handle the naming system
    /// accepts, the escrow's key of the raw text and of the normalized text are
    /// the SAME slot. If they ever differed, one identity's money would be
    /// split across two keys and half of it would be unreachable.
    function test_everyAcceptedVectorKeysWithItsNormalizedForm() public view {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            if (!v.accepted) continue;

            bytes32 platformId = _platformIdFor(v.platform);
            assertEq(
                escrow.slotOf(platformId, v.input),
                escrow.slotOf(platformId, v.output),
                string.concat("vector ", vm.toString(i), " keys differently from its normalized form")
            );
        }
    }

    /// A literal, so Rust and TypeScript cannot compute a different key and
    /// still pass their own tests.
    ///
    /// Derived from the formula rather than copied out of this contract:
    ///   keccak256(keccak256("libid.escrow.handle-slot.v1")
    ///             ‖ keccak256("dyaka.identity.platform.x")
    ///             ‖ keccak256("alice_1"))
    function test_theSlotDerivationIsPinned() public view {
        assertEq(escrow.slotOf(X, " Alice_1 "), escrow.slotOf(X, "alice_1"));
        assertEq(escrow.slotOf(X, "alice_1"), 0x48d2123d2510af6875a95858dec72232eba05885e8773f13d56b792d6cccc7e2);
    }

    function test_theCanonicalFormTrimsAndFolds() public view {
        assertEq(escrow.canonicalHandle("  ALICE  "), "alice");
        assertEq(escrow.canonicalHandle("Alice_1"), "alice_1");
        // Nothing else is touched: two texts that differ in more than case and
        // padding stay two handles.
        assertEq(escrow.canonicalHandle("ali-ce"), "ali-ce");
    }

    /// The naming system folds an at-prefixed spelling into the bare handle,
    /// so this must too — otherwise one identity's money splits across two
    /// keys and half of it is unreachable.
    function test_aLeadingAtSignFoldsIntoTheBareHandle() public {
        assertEq(escrow.slotOf(X, "@alice"), escrow.slotOf(X, "alice"));
        assertEq(escrow.slotOf(X, "  @Alice  "), escrow.slotOf(X, "alice"));
        assertEq(escrow.canonicalHandle("@alice"), "alice");
        // One at-sign, the same as `stripLeadingAt`. A second is a character
        // the platform refuses, so the deposit below never lands.
        assertEq(escrow.canonicalHandle("@@alice"), "@alice");

        // Both spellings pay into the same slot, and reading either sees both.
        vm.startPrank(sender);
        escrow.deposit{value: 1 ether}(X, "@alice", NATIVE, 1 ether);
        escrow.deposit{value: 2 ether}(X, "alice", NATIVE, 2 ether);
        vm.stopPrank();
        assertEq(escrow.escrowed(X, "@alice", NATIVE), 3 ether);
        assertEq(escrow.escrowed(X, "alice", NATIVE), 3 ether);
    }

    /// The read pairs with `resolveHandle` on whatever text a user typed: the
    /// naming system answers for an at-prefixed spelling, so this must not
    /// revert on it.
    function test_readingPairsWithTheResolverOnEitherSpelling() public {
        // Escrowed first, while nobody holds it — a deposit after the bind
        // would pay through and leave nothing to read.
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        assertEq(names.resolveHandle(X, "@alice"), alice);
        assertEq(escrow.escrowed(X, "@alice", NATIVE), 1 ether);
    }

    /// Text with nothing left after trimming and the at-sign has no slot.
    function test_aBareAtSignHasNoSlot() public {
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.Empty));
        escrow.slotOf(X, " @ ");
    }

    function test_textWithNothingInItHasNoSlot() public {
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.Empty));
        escrow.slotOf(X, "   ");
    }

    /// Different platforms are different keyspaces, so the same text on two of
    /// them is two slots.
    function test_theSlotIsPerPlatform() public view {
        assertTrue(escrow.slotOf(X, "alice") != escrow.slotOf(GITHUB, "alice"));
    }

    /// The platform id is load-bearing in the key, not decoration: the same
    /// text on two platforms is two different people, and their money must not
    /// meet. Proving it on one platform reaches only that one's slot.
    function test_theSameTextOnTwoPlatformsIsTwoEscrows() public {
        vm.startPrank(sender);
        escrow.deposit{value: 1 ether}(X, "alice", NATIVE, 1 ether);
        escrow.deposit{value: 2 ether}(GITHUB, "alice", NATIVE, 2 ether);
        vm.stopPrank();

        _bind(alice, "1", "alice", 100); // on X only

        vm.prank(alice);
        escrow.claim(X, "alice", NATIVE, alice);
        assertEq(alice.balance, 1 ether);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(GITHUB, "alice", NATIVE, alice);

        assertEq(escrow.escrowed(GITHUB, "alice", NATIVE), 2 ether, "the other platform's escrow moved");
    }

    /// Why the at-sign is refused rather than handled: the naming system reads
    /// both spellings as ONE handle. Keying them apart would split one
    /// identity's money across two slots, and only one of them would ever be
    /// claimable.
    function test_theNamingSystemReadsBothSpellingsAsOneHandle() public {
        _bind(alice, "1", "@alice", 100);

        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(names.resolveHandle(X, "@alice"), alice);
    }

    // ─── Depositing ─────────────────────────────────────────────────

    function test_depositHoldsNativeAgainstTheHandle() public {
        _depositNative("alice", 1 ether);

        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether);
        assertEq(address(escrow).balance, 1 ether);
    }

    function test_depositHoldsTokensAgainstTheHandle() public {
        vm.prank(sender);
        escrow.deposit(X, "alice", address(token), 10 ether);

        assertEq(escrow.escrowed(X, "alice", address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// Two spellings of one handle land in one slot and add up.
    function test_spellingsOfOneHandleAccumulate() public {
        _depositNative("alice", 1 ether);
        _depositNative(" ALICE ", 2 ether);

        assertEq(escrow.escrowed(X, "alice", NATIVE), 3 ether);
    }

    /// The books must never promise more than the contract holds.
    function test_aFeeOnTransferTokenCreditsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        escrow.deposit(X, "alice", address(fee), 100 ether);
        vm.stopPrank();

        assertEq(escrow.escrowed(X, "alice", address(fee)), 99 ether, "credited more than arrived");
        assertEq(fee.balanceOf(address(escrow)), 99 ether);
    }

    /// A handle nobody holds yet is the whole point.
    function test_depositingForAnUnclaimedHandleIsFine() public {
        assertEq(names.resolveHandle(X, "nobody"), address(0));
        _depositNative("nobody", 1 ether);
        assertEq(escrow.escrowed(X, "nobody", NATIVE), 1 ether);
    }

    /// The escrow exists for the window before a handle is claimed. Once it
    /// resolves, holding the value would only add a claim transaction to reach
    /// the same wallet, so the deposit is a payment.
    function test_depositForAHeldHandleIsPaidStraightThrough() public {
        _bind(alice, "1", "alice", 100);

        uint256 before = alice.balance;
        _depositNative("alice", 1 ether);

        assertEq(alice.balance, before + 1 ether, "the holder was not paid");
        assertEq(escrow.escrowed(X, "alice", NATIVE), 0, "the value was escrowed instead");
        assertEq(address(escrow).balance, 0, "the escrow kept it");
    }

    function test_aForwardedDepositIsAnnouncedAsSuch() public {
        _bind(alice, "1", "alice", 100);
        bytes32 slot = escrow.slotOf(X, "alice");

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(slot, NATIVE, sender, alice, X, "alice", 1 ether);
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, "alice", NATIVE, 1 ether);
    }

    function test_tokensForAHeldHandleGoStraightToTheHolder() public {
        _bind(alice, "1", "alice", 100);

        vm.prank(sender);
        escrow.deposit(X, "alice", address(token), 10 ether);

        assertEq(token.balanceOf(alice), 10 ether, "the holder was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(X, "alice", address(token)), 0);
    }

    /// The price of paying through: the call depends on the recipient. Failing
    /// is the honest outcome — the sender learns, instead of the value waiting
    /// in a slot only that same wallet could ever claim.
    function test_aHolderThatCannotReceiveFailsTheDeposit() public {
        address rejector = address(new RejectEther());
        _bind(rejector, "1", "alice", 100);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.deposit{value: 1 ether}(X, "alice", NATIVE, 1 ether);
    }

    /// The window the escrow is for: deposit while unclaimed, and the same
    /// handle pays through once it is claimed.
    function test_theSameHandleEscrowsThenPaysThrough() public {
        _depositNative("alice", 1 ether);
        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether);

        _bind(alice, "1", "alice", 100);

        uint256 before = alice.balance;
        _depositNative("alice", 2 ether);
        assertEq(alice.balance, before + 2 ether, "the second deposit did not pay through");
        // The first one still waits for its claim.
        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether, "the waiting balance moved");
    }

    function test_aDepositOfNothingIsRefused() public {
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, "alice", NATIVE, 0);
    }

    function test_nativeValueMustEqualTheAmount() public {
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.deposit{value: 1 ether}(X, "alice", NATIVE, 2 ether);
    }

    /// Ether sent alongside a token deposit has no slot to land in.
    function test_aTokenDepositCarriesNoValue() public {
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.deposit{value: 1 ether}(X, "alice", address(token), 10 ether);
    }

    /// A mistyped platform id takes nobody's money.
    function test_anUnwiredPlatformIsRefused() public {
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, UNWIRED));
        escrow.deposit{value: 1 ether}(UNWIRED, "alice", NATIVE, 1 ether);
    }

    /// The reason `rulesOf` exists. Text this platform could never accept would
    /// otherwise fund a slot no proof can ever claim, and there is no refund.
    function test_aHandleThePlatformCouldNeverAcceptIsRefused() public {
        vm.startPrank(sender);

        // A space inside is not a handle on X.
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.BadChar));
        escrow.deposit{value: 1 ether}(X, "ali ce", NATIVE, 1 ether);

        // A hyphen is GitHub's, not X's.
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.BadChar));
        escrow.deposit{value: 1 ether}(X, "ali-ce", NATIVE, 1 ether);

        // Past X's length.
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.TooLong));
        escrow.deposit{value: 1 ether}(X, "a123456789012345", NATIVE, 1 ether);

        vm.stopPrank();
    }

    // ─── Claiming ───────────────────────────────────────────────────

    function test_theHolderTakesWhatIsHeld() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(X, "alice", NATIVE, alice);

        assertEq(alice.balance, 1 ether);
        assertEq(escrow.escrowed(X, "alice", NATIVE), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// The claimer names where it goes, so a wallet that holds the name can pay
    /// out somewhere else.
    function test_theClaimerChoosesTheRecipient() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(X, "alice", NATIVE, bob);

        assertEq(bob.balance, 1 ether);
        assertEq(alice.balance, 0);
    }

    function test_aClaimTakesOnlyTheTokenItNames() public {
        _depositNative("alice", 1 ether);
        vm.prank(sender);
        escrow.deposit(X, "alice", address(token), 10 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(X, "alice", NATIVE, alice);

        assertEq(escrow.escrowed(X, "alice", NATIVE), 0);
        assertEq(escrow.escrowed(X, "alice", address(token)), 10 ether, "the token balance moved too");
    }

    /// Any spelling of the handle reaches the same slot.
    function test_aClaimCanUseAnySpelling() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(X, " ALICE ", NATIVE, alice);

        assertEq(alice.balance, 1 ether);
    }

    function test_somebodyElseCannotClaim() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, alice, bob));
        escrow.claim(X, "alice", NATIVE, bob);
    }

    /// Nobody holds it yet, so nobody can take it. The value waits.
    function test_anUnclaimedHandleCannotBeDrained() public {
        _depositNative("alice", 1 ether);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), bob));
        escrow.claim(X, "alice", NATIVE, bob);

        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether);
    }

    function test_claimingAnEmptySlotIsRefused() public {
        _bind(alice, "1", "alice", 100);
        // Read the slot BEFORE the prank: an external call inside the revert
        // argument is itself the next call and would consume it.
        bytes32 slot = escrow.slotOf(X, "alice");

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, slot, NATIVE));
        escrow.claim(X, "alice", NATIVE, alice);
    }

    function test_aRecipientThatRefusesNativeValueFailsTheClaim() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        address rejector = address(new RejectEther());

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.claim(X, "alice", NATIVE, rejector);
    }

    /// A token that calls back inside its own transfer would otherwise have the
    /// outer deposit credit the inner deposit's tokens as well — two slots
    /// funded by one transfer, and more promised than held.
    function test_aTokenThatReentersDepositIsRefused() public {
        ReenteringToken hook = new ReenteringToken();
        hook.mint(sender, 100 ether);
        hook.mint(address(hook), 10 ether);
        hook.arm(escrow, X);

        vm.startPrank(sender);
        hook.approve(address(escrow), type(uint256).max);
        // The guard specifically, not any revert: a mis-staged token or a
        // missing approval would also revert and would also look green.
        vm.expectRevert(
            abi.encodeWithSelector(ReentrancyGuardTransientUpgradeable.ReentrancyGuardReentrantCall.selector)
        );
        escrow.deposit(X, "alice", address(hook), 100 ether);
        vm.stopPrank();

        assertEq(escrow.escrowed(X, "alice", address(hook)), 0);
        assertEq(escrow.escrowed(X, "bob", address(hook)), 0);
        assertEq(hook.balanceOf(address(escrow)), 0, "the escrow kept tokens it never credited");
    }

    /// The payout is an external call to an address the claimer chose.
    ///
    /// Somebody else's escrow is funded alongside, and that is the point: a
    /// second drain is only observable when the contract holds more than the
    /// claimed slot. Without it, the second transfer runs out of balance and
    /// fails for a reason that has nothing to do with reentrancy.
    function test_aReenteringClaimerCannotDrainTwice() public {
        ReenteringClaimer claimer = new ReenteringClaimer(escrow, X, "alice");
        _depositNative("alice", 1 ether);
        _depositNative("bob", 1 ether); // not the claimer's
        _bind(address(claimer), "1", "alice", 100);

        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, address(claimer), 1 ether));
        claimer.take();

        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether, "the slot was drained");
        assertEq(escrow.escrowed(X, "bob", NATIVE), 1 ether, "somebody else's escrow moved");
        assertEq(address(escrow).balance, 2 ether);
        assertEq(address(claimer).balance, 0, "the claimer took anything at all");
    }

    /// A payout to nobody is not a payout. The zero address ACCEPTS a native
    /// transfer, so without this the slot would be emptied, the value burned
    /// and `Claimed` would report success.
    function test_aClaimToNobodyIsRefused() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(0)));
        escrow.claim(X, "alice", NATIVE, address(0));

        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether, "the slot was emptied");
        assertEq(address(0).balance, 0, "value was burned");
    }

    /// A payout to this contract would zero the books and leave the value here
    /// as surplus no slot points at — unreachable, with no refund and no owner
    /// lever.
    function test_aClaimBackIntoTheEscrowIsRefused() public {
        vm.prank(sender);
        escrow.deposit(X, "alice", address(token), 10 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(escrow)));
        escrow.claim(X, "alice", address(token), address(escrow));

        assertEq(escrow.escrowed(X, "alice", address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// The ERC-20 payout branch, which no other test reaches: every other
    /// claim in this suite takes the native token.
    function test_aTokenClaimPaysTheRecipient() public {
        vm.prank(sender);
        escrow.deposit(X, "alice", address(token), 10 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(X, "alice", address(token), bob);

        assertEq(token.balanceOf(bob), 10 ether, "the recipient was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(X, "alice", address(token)), 0);
    }

    /// `Deposited` is the only on-chain record tying a slot back to a handle —
    /// a slot cannot be turned back into a string — so its payload is worth an
    /// assertion of its own.
    function test_depositAndClaimAnnounceTheirPayloads() public {
        bytes32 slot = escrow.slotOf(X, "alice");

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Deposited(slot, NATIVE, sender, X, "alice", 1 ether);
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, "alice", NATIVE, 1 ether);

        _bind(alice, "1", "alice", 100);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Claimed(slot, NATIVE, alice, bob, 1 ether);
        vm.prank(alice);
        escrow.claim(X, "alice", NATIVE, bob);
    }

    /// A fee-on-transfer token delivers less than was asked for, and the event
    /// is the only record of a payment that never entered the books.
    function test_aForwardedPaymentReportsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        _bind(alice, "1", "alice", 100);

        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(escrow.slotOf(X, "alice"), address(fee), sender, alice, X, "alice", 99 ether);
        escrow.deposit(X, "alice", address(fee), 100 ether);
        vm.stopPrank();

        assertEq(fee.balanceOf(alice), 99 ether, "the holder received something else");
    }

    // ─── Consequences accepted on purpose ───────────────────────────

    /// NOT a vulnerability. The escrow is keyed by the handle and nothing else,
    /// so a platform that frees a handle and gives it to somebody new hands the
    /// new holder whatever accumulated for the old one. This is the decision,
    /// and this test exists so changing it fails here.
    function test_ACCEPTED_aRecycledHandlePaysTheNewHolder() public {
        // Escrowed while nobody held it, and never claimed.
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        // The platform frees the handle: alice renames away, bob's account
        // takes it.
        _bind(alice, "1", "alice2", 200);
        _bind(bob, "2", "alice", 300);

        vm.prank(bob);
        escrow.claim(X, "alice", NATIVE, bob);

        assertEq(bob.balance, 1 ether, "the new holder did not receive it");
    }

    /// NOT a vulnerability. Between a rename and the next proof of the freed
    /// handle, the handle resolves to nobody and the slot waits — including
    /// against the account that just renamed away from it.
    function test_ACCEPTED_aRenamedAwayHandleIsClaimableByNobody() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        _bind(alice, "1", "alice2", 200);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(X, "alice", NATIVE, alice);

        // And it did not follow the account to its new name.
        assertEq(escrow.escrowed(X, "alice2", NATIVE), 0, "the balance followed the account");
        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether);
    }

    /// NOT a vulnerability. A deposit is a gift to a name, so the sender has no
    /// way back. There is no deadline and no refund by decision.
    function test_ACCEPTED_theDepositorCannotTakeItBack() public {
        _depositNative("alice", 1 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), sender));
        escrow.claim(X, "alice", NATIVE, sender);

        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether);
    }

    /// The owner is not a way in either: there is no owner function that moves
    /// a balance, and being the owner does not make it the holder.
    function test_theOwnerCannotTakeADeposit() public {
        _depositNative("alice", 1 ether);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), owner));
        escrow.claim(X, "alice", NATIVE, owner);
    }

    // ─── Wiring ─────────────────────────────────────────────────────

    /// Repointing it would redirect every entitlement held, so there is no
    /// setter. Moving it is an upgrade, which leaves a record.
    function test_theNamingContractIsReadableAndHasNoSetter() public view {
        assertEq(address(escrow.names()), address(names));
    }

    function test_initializeRefusesAZeroNamingContract() public {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(HandleEscrow.NoNames.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(address(0)))));
    }

    function test_ownershipCannotBeRenounced() public {
        vm.prank(owner);
        vm.expectRevert("renounce disabled");
        escrow.renounceOwnership();
    }

    function test_onlyTheOwnerMayUpgrade() public {
        HandleEscrow next = new HandleEscrow();

        vm.prank(bob);
        vm.expectRevert();
        escrow.upgradeToAndCall(address(next), "");

        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");
    }

    /// The balances have to survive it, or the upgrade is the theft the pause
    /// was refused to avoid.
    function test_balancesSurviveAnUpgrade() public {
        _depositNative("alice", 1 ether);
        bytes32 slot = escrow.slotOf(X, "alice");
        // A version that APPENDS a field, not a copy of the same bytecode: a
        // byte-identical upgrade cannot detect a reordered or removed one,
        // which is the only mistake this test exists to catch.
        HandleEscrowV2 next = new HandleEscrowV2();

        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");

        HandleEscrowV2 upgraded = HandleEscrowV2(payable(address(escrow)));
        assertEq(upgraded.heldThroughV2(slot, NATIVE), 1 ether, "the balance moved under the new layout");
        assertEq(upgraded.namesThroughV2(), address(names), "the naming pointer moved");
        assertEq(upgraded.appended(), 0, "the appended field read somebody else's bytes");

        // The old surface still answers, and the new field is its own slot.
        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether);
        upgraded.setAppended(7);
        assertEq(upgraded.appended(), 7);
        assertEq(escrow.escrowed(X, "alice", NATIVE), 1 ether, "writing the new field disturbed a balance");
    }

    /// The load-bearing claim of the whole design: a rules change cannot MOVE
    /// money already held. Nothing else in this suite calls `setPlatform`
    /// twice.
    function test_ACCEPTED_aRulesChangeCannotMoveHeldValueButCanStrandIt() public {
        _depositNative("alice_9", 1 ether);
        bytes32 slot = escrow.slotOf(X, "alice_9");
        _bind(alice, "1", "alice_9", 100);

        // The owner narrows X: no underscore any more.
        vm.prank(owner);
        names.setPlatform(
            X,
            HandleNormalizer.Rules({
                maxLength: 15, stripLeadingAt: true, isEmail: false, allowUnderscore: false, allowHyphen: false
            })
        );

        // The key did not move — that is what the rules-independent form buys.
        assertEq(escrow.slotOf(X, "alice_9"), slot, "the slot re-keyed");
        assertEq(escrow.escrowedAt(slot, NATIVE), 1 ether, "the value moved");

        // And what it does NOT buy: the handle no longer resolves, so the
        // holder cannot claim until compatible rules return.
        assertEq(names.resolveHandle(X, "alice_9"), address(0));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(X, "alice_9", NATIVE, alice);

        // Restoring the rules restores the claim, at the same key.
        vm.prank(owner);
        names.setPlatform(X, HandleVectors.rulesFor(X));
        vm.prank(alice);
        escrow.claim(X, "alice_9", NATIVE, alice);
        assertEq(alice.balance, 1 ether);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _platformIdFor(string memory platform) internal pure returns (bytes32) {
        bytes32 key = keccak256(bytes(platform));
        if (key == keccak256("x")) return HandleVectors.PLATFORM_X;
        if (key == keccak256("github")) return HandleVectors.PLATFORM_GITHUB;
        if (key == keccak256("google")) return HandleVectors.PLATFORM_GOOGLE;
        revert("unknown platform in the vector table");
    }
}
