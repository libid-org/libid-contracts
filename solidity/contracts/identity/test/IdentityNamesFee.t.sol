// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";
import {IIdentityVerifier} from "../IIdentityVerifier.sol";
import {INativePriceSource} from "../price/INativePriceSource.sol";
import {OwnerPushedNativePriceSource} from "../price/OwnerPushedNativePriceSource.sol";
import {MockIdentityVerifier} from "./MockIdentityVerifier.sol";

/// @notice Refuses every native transfer, the way a contract with no
///         `receive()` does.
contract RejectEther {
    // No receive, no fallback.
}

/// @notice Binds a name for ITSELF from inside the fee transfer.
///
/// @dev The reentrant call has to be one that would otherwise SUCCEED, or the
///      test cannot tell a working guard from a broken setup: any inner revert
///      fails the fee transfer and reverts the outer bind either way. So this
///      stages its own claim first, and pays the inner fee out of the fee it
///      was just handed.
contract ReenteringRecipient {
    IdentityNames private immutable names;
    MockIdentityVerifier private immutable verifier;
    bytes32 private immutable platformId;
    bool private entered;

    constructor(IdentityNames names_, MockIdentityVerifier verifier_, bytes32 platformId_) {
        names = names_;
        verifier = verifier_;
        platformId = platformId_;
    }

    receive() external payable {
        // The inner bind pays this contract too. One level is the attack.
        if (entered) return;
        entered = true;

        verifier.stage("999", "attacker", address(this), 100);
        names.bind{value: msg.value}(platformId, hex"", false, msg.value);
    }
}

/// @notice The first-bind fee: who pays it, who does not, and what happens
///         when the price source stops answering.
contract IdentityNamesFeeTest is Test {
    IdentityNames internal names;
    MockIdentityVerifier internal verifier;
    OwnerPushedNativePriceSource internal price;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal owner = makeAddr("owner");
    address internal treasury = makeAddr("treasury");

    uint32 internal constant V1 = 1;
    uint64 internal constant NO_FUTURE_ALLOWANCE = 0;

    /// A literal rather than a `block.timestamp` local: under `via_ir` the
    /// optimizer may re-read `TIMESTAMP` after a `vm.warp`, so such a local
    /// follows the clock instead of recording a moment.
    uint256 internal constant T0 = 1_000_000;
    uint256 internal constant STALE_AFTER = 1 hours;

    /// $1.00, on the eight-decimal scale `FEE_USD_DECIMALS` names.
    uint256 internal constant ONE_DOLLAR = 1e8;
    /// $2500.00 for one native token.
    uint256 internal constant NATIVE_AT_2500 = 2500e8;
    /// $1.00 at $2500 per token.
    uint256 internal constant ONE_DOLLAR_IN_WEI = 4e14;

    function setUp() public {
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (owner)))));
        verifier = new MockIdentityVerifier("mock");
        price = new OwnerPushedNativePriceSource(owner, STALE_AFTER);

        vm.startPrank(owner);
        names.setPlatform(X, HandleVectors.rulesFor(X));
        names.setVerifier(X, V1, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
        names.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB));
        names.setVerifier(GITHUB, V1, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
        vm.stopPrank();

        vm.warp(T0);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    /// Charge $1.00, priced by the owner-pushed source, paid to the treasury.
    function _chargeADollar() internal {
        vm.startPrank(owner);
        price.setPrice(NATIVE_AT_2500);
        names.setBindFee(INativePriceSource(address(price)), ONE_DOLLAR, treasury);
        vm.stopPrank();
    }

    function _bind(address who, string memory userId, string memory handle, uint64 at, uint256 value) internal {
        verifier.stage(userId, handle, who, at);
        vm.prank(who);
        names.bind{value: value}(X, hex"", false, value);
    }

    // ─── Off by default ─────────────────────────────────────────────

    /// A deployment that never calls `setBindFee` charges nothing, and never
    /// asks a price source anything.
    function test_bindIsFreeUntilAFeeIsConfigured() public {
        assertEq(names.bindFeeWei(), 0, "an unconfigured contract quotes a fee");

        _bind(alice, "123", "alice", 100, 0);
        assertEq(names.resolveId(X, "123"), alice);
        assertEq(treasury.balance, 0);
    }

    // ─── The charge ─────────────────────────────────────────────────

    function test_theFirstBindOfAnIdPaysTheFee() public {
        _chargeADollar();
        assertEq(names.bindFeeWei(), ONE_DOLLAR_IN_WEI, "the quote is not $1 at $2500");

        uint256 before = alice.balance;
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);

        assertEq(treasury.balance, ONE_DOLLAR_IN_WEI, "the treasury was not paid");
        assertEq(alice.balance, before - ONE_DOLLAR_IN_WEI, "the payer was charged the wrong amount");
        assertEq(address(names).balance, 0, "the contract kept funds");
    }

    function test_theFeeIsAnnouncedWithThePriceItUsed() public {
        _chargeADollar();
        bytes32 idKey = IdentityNodes.idNode(X, "123");

        verifier.stage("123", "alice", alice, 100);
        vm.expectEmit(true, true, true, true, address(names));
        emit IdentityNames.BindFeePaid(alice, idKey, treasury, ONE_DOLLAR_IN_WEI, ONE_DOLLAR);
        vm.prank(alice);
        names.bind{value: ONE_DOLLAR_IN_WEI}(X, hex"", false, ONE_DOLLAR_IN_WEI);
    }

    /// The recipient the owner set at THIS moment, not the one an indexer would
    /// reconstruct from the last configuration event.
    function test_theEventNamesTheRecipientThatWasPaid() public {
        _chargeADollar();

        address second = makeAddr("second-treasury");
        vm.prank(owner);
        names.setBindFee(INativePriceSource(address(price)), ONE_DOLLAR, second);

        verifier.stage("123", "alice", alice, 100);
        vm.expectEmit(true, true, true, true, address(names));
        emit IdentityNames.BindFeePaid(alice, IdentityNodes.idNode(X, "123"), second, ONE_DOLLAR_IN_WEI, ONE_DOLLAR);
        vm.prank(alice);
        names.bind{value: ONE_DOLLAR_IN_WEI}(X, hex"", false, ONE_DOLLAR_IN_WEI);

        assertEq(second.balance, ONE_DOLLAR_IN_WEI, "the new recipient was not paid");
        assertEq(treasury.balance, 0, "the old recipient was paid");
    }

    /// A rename is a later bind of the SAME account id.
    function test_arenameIsFree() public {
        _chargeADollar();
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);

        uint256 before = alice.balance;
        _bind(alice, "123", "alice2", 200, 0);

        assertEq(names.resolveHandle(X, "alice2"), alice, "the rename did not land");
        assertEq(alice.balance, before, "the rename was charged");
        assertEq(treasury.balance, ONE_DOLLAR_IN_WEI, "the treasury was paid twice");
    }

    /// Proving again from another wallet is the whole remedy for a name held
    /// by the wrong one. It must not have a price.
    function test_movingAnAccountToAnotherWalletIsFree() public {
        _chargeADollar();
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);

        uint256 before = bob.balance;
        _bind(bob, "123", "alice", 200, 0);

        assertEq(names.resolveId(X, "123"), bob, "the account did not move");
        assertEq(bob.balance, before, "the move was charged");
    }

    /// The fee is per account id, so a second account pays its own.
    function test_aSecondAccountOnTheSamePlatformPaysAgain() public {
        _chargeADollar();
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);
        _bind(alice, "456", "second", 100, ONE_DOLLAR_IN_WEI);

        assertEq(treasury.balance, 2 * ONE_DOLLAR_IN_WEI, "the second account did not pay");
    }

    /// A new proof format is another way to prove the same account, not a new
    /// account, so it is not a new charge.
    function test_bindingTheSameIdThroughANewVersionIsFree() public {
        _chargeADollar();
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);

        MockIdentityVerifier v2 = new MockIdentityVerifier("mock2");
        vm.prank(owner);
        names.setVerifier(X, 2, IIdentityVerifier(address(v2)), NO_FUTURE_ALLOWANCE);

        v2.stage("123", "alice", alice, 300);
        uint256 before = alice.balance;
        vm.prank(alice);
        names.bindAtVersion(X, 2, hex"", false, 0);

        assertEq(alice.balance, before, "the version migration was charged");
    }

    // ─── Paying ─────────────────────────────────────────────────────

    /// Underpaying while WILLING to pay the fee: the ceiling is high enough,
    /// the value is not.
    function test_underpaymentIsRefused() public {
        _chargeADollar();

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.InsufficientFee.selector, ONE_DOLLAR_IN_WEI, ONE_DOLLAR_IN_WEI - 1)
        );
        names.bind{value: ONE_DOLLAR_IN_WEI - 1}(X, hex"", false, ONE_DOLLAR_IN_WEI);
    }

    /// The ceiling is the whole point: a caller may send a buffer and still not
    /// be charged more than it authorized, whatever the price does before the
    /// block lands.
    function test_aFeeAboveTheCeilingIsRefused() public {
        _chargeADollar();
        uint256 quote = names.bindFeeWeiFor(X, "123");

        // The token halves after the quote was read, so the fee doubles.
        vm.prank(owner);
        price.setPrice(NATIVE_AT_2500 / 2);

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.FeeAboveMax.selector, quote * 2, quote));
        names.bind{value: 1 ether}(X, hex"", false, quote);

        assertEq(treasury.balance, 0, "the treasury was paid past the ceiling");
        assertEq(names.resolveId(X, "123"), address(0), "the bind landed anyway");
    }

    /// A ceiling of zero is what every free bind passes, and it refuses a first
    /// bind on a chain that charges rather than quietly taking the value sent.
    function test_aZeroCeilingRefusesAChargedBind() public {
        _chargeADollar();

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.FeeAboveMax.selector, ONE_DOLLAR_IN_WEI, 0));
        names.bind{value: ONE_DOLLAR_IN_WEI}(X, hex"", false, 0);
    }

    /// `bindAtVersion` carries the same fee, ceiling and guard. Nothing else in
    /// the suite sends value through it.
    function test_bindAtVersionChargesTheFeeToo() public {
        _chargeADollar();

        MockIdentityVerifier v2 = new MockIdentityVerifier("mock2");
        vm.prank(owner);
        names.setVerifier(X, 2, IIdentityVerifier(address(v2)), NO_FUTURE_ALLOWANCE);

        v2.stage("777", "seven", alice, 100);
        uint256 before = alice.balance;
        vm.prank(alice);
        names.bindAtVersion{value: ONE_DOLLAR_IN_WEI}(X, 2, hex"", false, ONE_DOLLAR_IN_WEI);

        assertEq(treasury.balance, ONE_DOLLAR_IN_WEI, "bindAtVersion did not charge");
        assertEq(alice.balance, before - ONE_DOLLAR_IN_WEI);
        assertEq(names.resolveId(X, "777"), alice);
    }

    /// A source may answer zero without reverting. Dividing would panic, which
    /// reads as a bug here rather than as a source that cannot be used.
    function test_aZeroPriceIsNamedRatherThanPanicking() public {
        FixedPrice18 zero = new FixedPrice18(0);
        vm.prank(owner);
        names.setBindFee(INativePriceSource(address(zero)), ONE_DOLLAR, treasury);

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnusablePrice.selector, address(zero)));
        names.bindFeeWei();
    }

    /// A refused payment writes nothing, so the caller does not pay gas for
    /// state the transaction then throws away.
    function test_aRefusedPaymentWritesNothing() public {
        _chargeADollar();

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert();
        names.bind{value: 0}(X, hex"", false, ONE_DOLLAR_IN_WEI);

        assertEq(names.resolveId(X, "123"), address(0));
        assertEq(names.resolveHandle(X, "alice"), address(0));
    }

    /// A USD price moves between the quote and the block, so a caller sends a
    /// little more than the quote and gets the difference back.
    function test_theExcessComesBack() public {
        _chargeADollar();

        uint256 before = alice.balance;
        _bind(alice, "123", "alice", 100, 1 ether);

        assertEq(alice.balance, before - ONE_DOLLAR_IN_WEI, "the excess was kept");
        assertEq(treasury.balance, ONE_DOLLAR_IN_WEI, "the treasury got the excess");
    }

    /// Value sent on a free bind is not a donation.
    function test_valueSentOnAFreeBindIsReturnedWhole() public {
        uint256 before = alice.balance;
        _bind(alice, "123", "alice", 100, 1 ether);

        assertEq(alice.balance, before, "value sent on a free bind was kept");
    }

    function test_aRecipientThatRefusesTheFeeFailsTheBind() public {
        address rejector = address(new RejectEther());
        vm.startPrank(owner);
        price.setPrice(NATIVE_AT_2500);
        names.setBindFee(INativePriceSource(address(price)), ONE_DOLLAR, rejector);
        vm.stopPrank();

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.NativeTransferFailed.selector, rejector, ONE_DOLLAR_IN_WEI)
        );
        names.bind{value: ONE_DOLLAR_IN_WEI}(X, hex"", false, ONE_DOLLAR_IN_WEI);
    }

    /// The fee transfer is an external call into an owner-configured address,
    /// which is the reentrancy the guard is there for.
    ///
    /// Without the guard the inner bind lands and the outer one succeeds, so
    /// the specific revert below — and the name that was never written — are
    /// what separates a working guard from a broken test.
    function test_aReenteringRecipientIsBlocked() public {
        ReenteringRecipient recipient = new ReenteringRecipient(names, verifier, X);
        vm.startPrank(owner);
        price.setPrice(NATIVE_AT_2500);
        names.setBindFee(INativePriceSource(address(price)), ONE_DOLLAR, address(recipient));
        vm.stopPrank();

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        // The guard reverts the inner bind, which fails the fee transfer and
        // takes the outer call with it.
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.NativeTransferFailed.selector, address(recipient), ONE_DOLLAR_IN_WEI)
        );
        names.bind{value: ONE_DOLLAR_IN_WEI}(X, hex"", false, ONE_DOLLAR_IN_WEI);

        assertEq(names.resolveId(X, "999"), address(0), "the reentrant bind landed");
        assertEq(names.resolveId(X, "123"), address(0), "the outer bind was not rolled back");
    }

    // ─── A price source that stops answering ────────────────────────

    /// The load-bearing case. A dead price source must stop a FIRST bind and
    /// nothing else: the remedy for a name held by the wrong wallet cannot
    /// depend on an oracle being alive.
    function test_aDeadPriceSourceStopsAFirstBindButNotARebind() public {
        _chargeADollar();
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);

        vm.warp(T0 + STALE_AFTER + 1);

        // A first bind cannot be priced, so it is refused.
        verifier.stage("999", "newcomer", bob, 200);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OwnerPushedNativePriceSource.StalePrice.selector, T0, T0 + STALE_AFTER));
        names.bind{value: 1 ether}(X, hex"", false, 1 ether);

        // The remedy still works: bob takes the already-bound account.
        _bind(bob, "123", "alice", 200, 0);
        assertEq(names.resolveId(X, "123"), bob, "the remedy was blocked by a dead oracle");

        // And so does a rename.
        _bind(bob, "123", "renamed", 300, 0);
        assertEq(names.resolveHandle(X, "renamed"), bob);
    }

    /// The escape hatch an operator has when it cannot push a price.
    function test_turningTheFeeOffRestoresFirstBinds() public {
        _chargeADollar();
        vm.warp(T0 + STALE_AFTER + 1);

        vm.prank(owner);
        names.setBindFee(INativePriceSource(address(0)), 0, address(0));

        assertEq(names.bindFeeWei(), 0);
        _bind(alice, "123", "alice", 200, 0);
        assertEq(names.resolveId(X, "123"), alice);
    }

    // ─── The quote ──────────────────────────────────────────────────

    /// The strongest form of "the quote is honest": pay EXACTLY what it says.
    /// A quote below the real fee reverts `InsufficientFee`; one above it leaves
    /// change. Asserting the balances after an exact payment pins both sides.
    function _bindPayingExactly(address who, string memory userId, string memory handle, uint64 at) internal {
        uint256 quote = names.bindFeeWeiFor(X, userId);
        uint256 payerBefore = who.balance;
        uint256 treasuryBefore = treasury.balance;

        verifier.stage(userId, handle, who, at);
        vm.prank(who);
        names.bind{value: quote}(X, hex"", false, quote);

        assertEq(treasury.balance - treasuryBefore, quote, "the treasury received something else");
        assertEq(payerBefore - who.balance, quote, "the payer was charged something else");
    }

    function test_theQuoteIsWhatIsCharged() public {
        _chargeADollar();

        // A first bind: quoted and charged.
        _bindPayingExactly(alice, "123", "alice", 100);
        assertEq(treasury.balance, ONE_DOLLAR_IN_WEI);

        // A rename of the same account: quoted zero, charged zero.
        assertEq(names.bindFeeWeiFor(X, "123"), 0, "a rename was quoted a fee");
        _bindPayingExactly(alice, "123", "alice2", 200);

        // A wallet move: still the same account, still zero.
        _bindPayingExactly(bob, "123", "alice2", 300);

        // A different account pays its own.
        assertEq(names.bindFeeWeiFor(X, "456"), ONE_DOLLAR_IN_WEI, "a new account was quoted free");
        _bindPayingExactly(alice, "456", "second", 100);
        assertEq(treasury.balance, 2 * ONE_DOLLAR_IN_WEI);
    }

    /// Across any price and any fee the owner can set, the quote and the charge
    /// agree — including where the division truncates to zero.
    function testFuzz_theQuoteIsWhatIsCharged(uint256 priceRaw, uint256 feeUsdRaw) public {
        uint256 nativePrice = bound(priceRaw, 1, 1_000_000e8); // $0.00000001 … $1M
        uint256 feeUsd = bound(feeUsdRaw, 1, 10_000e8); // $0.00000001 … $10k

        vm.startPrank(owner);
        price.setPrice(nativePrice);
        names.setBindFee(INativePriceSource(address(price)), feeUsd, treasury);
        vm.stopPrank();

        uint256 quote = names.bindFeeWeiFor(X, "123");
        vm.deal(alice, quote + 1 ether);

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bind{value: quote}(X, hex"", false, quote);

        assertEq(treasury.balance, quote, "the charge and the quote disagree");
        assertEq(names.bindFeeWeiFor(X, "123"), 0, "the account is still quoted a fee after binding");
    }

    /// The short circuit, seen from the quote: an already-bound account is
    /// quoted zero WITHOUT the price source being consulted, so a rename stays
    /// quotable on a chain whose source has died.
    function test_theQuoteSurvivesADeadPriceSourceForABoundAccount() public {
        _chargeADollar();
        _bind(alice, "123", "alice", 100, ONE_DOLLAR_IN_WEI);

        vm.warp(T0 + STALE_AFTER + 1);

        assertEq(names.bindFeeWeiFor(X, "123"), 0, "a bound account could not be quoted");

        // And an unbound one cannot be quoted at all, which is the same refusal
        // `bind` gives.
        vm.expectRevert(abi.encodeWithSelector(OwnerPushedNativePriceSource.StalePrice.selector, T0, T0 + STALE_AFTER));
        names.bindFeeWeiFor(X, "999");
    }

    /// A quote about a platform that is not wired answers a question nobody
    /// asked, so it refuses like the resolvers do.
    function test_theQuoteRefusesAnUnwiredPlatform() public {
        bytes32 unwired = keccak256("dyaka.identity.platform.nowhere");

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unwired));
        names.bindFeeWeiFor(unwired, "123");
    }

    /// With no fee configured every account is quoted zero, and no price source
    /// is reachable to be asked.
    function test_theQuoteIsZeroWhenBindsAreFree() public view {
        assertEq(names.bindFeeWeiFor(X, "123"), 0);
    }

    // ─── Configuration ──────────────────────────────────────────────

    function test_onlyTheOwnerMaySetTheFee() public {
        vm.prank(alice);
        vm.expectRevert();
        names.setBindFee(INativePriceSource(address(price)), ONE_DOLLAR, treasury);
    }

    function test_aFeeNeedsBothAPriceSourceAndARecipient() public {
        vm.startPrank(owner);

        vm.expectRevert(IdentityNames.IncompleteFeeConfig.selector);
        names.setBindFee(INativePriceSource(address(0)), ONE_DOLLAR, treasury);

        vm.expectRevert(IdentityNames.IncompleteFeeConfig.selector);
        names.setBindFee(INativePriceSource(address(price)), ONE_DOLLAR, address(0));

        vm.stopPrank();
    }

    /// A zero fee clears the rest, so nothing is left pointing at a source
    /// that is no longer consulted.
    function test_aZeroFeeClearsTheWholeConfiguration() public {
        _chargeADollar();

        vm.prank(owner);
        names.setBindFee(INativePriceSource(address(price)), 0, treasury);

        (INativePriceSource source, uint256 feeUsd, address recipient) = names.bindFee();
        assertEq(address(source), address(0));
        assertEq(feeUsd, 0);
        assertEq(recipient, address(0));
    }

    function test_theConfigurationReadsBack() public {
        _chargeADollar();

        (INativePriceSource source, uint256 feeUsd, address recipient) = names.bindFee();
        assertEq(address(source), address(price));
        assertEq(feeUsd, ONE_DOLLAR);
        assertEq(recipient, treasury);
    }

    /// The quote follows the price, which is the point of denominating in USD.
    function test_theQuoteFollowsThePrice() public {
        _chargeADollar();
        assertEq(names.bindFeeWei(), ONE_DOLLAR_IN_WEI);

        vm.prank(owner);
        price.setPrice(1250e8); // the token halved

        assertEq(names.bindFeeWei(), 2 * ONE_DOLLAR_IN_WEI, "the fee did not follow the price");
    }

    /// A source on another scale is normalized rather than taken as eight
    /// decimals.
    function test_theQuoteNormalizesTheSourcesScale() public {
        FixedPrice18 source = new FixedPrice18(2500e18);
        vm.prank(owner);
        names.setBindFee(INativePriceSource(address(source)), ONE_DOLLAR, treasury);

        assertEq(names.bindFeeWei(), ONE_DOLLAR_IN_WEI, "an 18-decimal source was misread");
    }
}

/// @notice A price source on an eighteen-decimal scale.
contract FixedPrice18 is INativePriceSource {
    uint256 private immutable _price;

    constructor(uint256 price_) {
        _price = price_;
    }

    function nativeUsdPrice() external view returns (uint256, uint8) {
        return (_price, 18);
    }
}
