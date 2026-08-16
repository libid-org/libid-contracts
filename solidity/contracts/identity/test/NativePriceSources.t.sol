// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ChainlinkNativePriceSource, IAggregatorV3} from "../price/ChainlinkNativePriceSource.sol";
import {OwnerPushedNativePriceSource} from "../price/OwnerPushedNativePriceSource.sol";
import {MockAggregatorV3} from "./MockAggregatorV3.sol";

/// @notice The two price sources, against the rules they promise.
contract NativePriceSourcesTest is Test {
    address internal owner = makeAddr("owner");
    address internal mallory = makeAddr("mallory");

    uint256 internal constant HOUR = 1 hours;

    /// @dev A literal, not a `block.timestamp` read held in a local. Under
    ///      `via_ir` the optimizer treats `TIMESTAMP` as movable and may
    ///      re-read it after a `vm.warp`, so such a local silently follows the
    ///      clock and the "when was this answered" value moves with it.
    uint256 internal constant T0 = 1_000_000;

    function setUp() public {
        // Past every staleness window, so a timestamp can be staged behind the
        // chain without underflowing.
        vm.warp(T0);
    }

    // ─── Chainlink ──────────────────────────────────────────────────

    function _feed(int256 answer, uint8 decimals) internal returns (MockAggregatorV3) {
        return new MockAggregatorV3(answer, block.timestamp, decimals);
    }

    function test_chainlinkReportsTheFeedsAnswerAndScale() public {
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(_feed(2500e8, 8), HOUR);

        (uint256 price, uint8 decimals) = source.nativeUsdPrice();
        assertEq(price, 2500e8, "the price is not the feed's answer");
        assertEq(decimals, 8, "the scale is not the feed's");
    }

    /// The feed decides the scale, so a feed on another one is passed through
    /// rather than folded to eight decimals here.
    function test_chainlinkPassesThroughANonEightDecimalFeed() public {
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(_feed(2500e18, 18), HOUR);

        (uint256 price, uint8 decimals) = source.nativeUsdPrice();
        assertEq(price, 2500e18);
        assertEq(decimals, 18);
    }

    function test_chainlinkRefusesANonPositiveAnswer() public {
        MockAggregatorV3 feed = _feed(2500e8, 8);
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(feed, HOUR);

        feed.stage(0, block.timestamp);
        vm.expectRevert(abi.encodeWithSelector(ChainlinkNativePriceSource.InvalidPrice.selector, int256(0)));
        source.nativeUsdPrice();

        feed.stage(-1, block.timestamp);
        vm.expectRevert(abi.encodeWithSelector(ChainlinkNativePriceSource.InvalidPrice.selector, int256(-1)));
        source.nativeUsdPrice();
    }

    function test_chainlinkRefusesAnAnswerOlderThanTheStalenessBound() public {
        MockAggregatorV3 feed = _feed(2500e8, 8);
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(feed, HOUR);

        vm.warp(T0 + HOUR);
        source.nativeUsdPrice(); // exactly at the deadline still answers

        vm.warp(T0 + HOUR + 1);
        vm.expectRevert(abi.encodeWithSelector(ChainlinkNativePriceSource.StalePrice.selector, T0, T0 + HOUR));
        source.nativeUsdPrice();
    }

    /// The subtraction this check does NOT use would underflow here.
    function test_chainlinkWorksOnAChainYoungerThanItsStalenessBound() public {
        vm.warp(5);
        MockAggregatorV3 feed = _feed(2500e8, 8);
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(feed, 30 days);

        (uint256 price,) = source.nativeUsdPrice();
        assertEq(price, 2500e8);
    }

    /// A bound near the top of the range would panic on the addition every
    /// read makes, and the value is immutable — so it is refused at
    /// construction instead.
    function test_aStalenessBoundBeyondTheCapIsRefused() public {
        MockAggregatorV3 feed = _feed(2500e8, 8);

        vm.expectRevert(ChainlinkNativePriceSource.InvalidConfig.selector);
        new ChainlinkNativePriceSource(feed, type(uint256).max);

        vm.expectRevert(ChainlinkNativePriceSource.InvalidConfig.selector);
        new ChainlinkNativePriceSource(feed, 366 days);

        vm.expectRevert(OwnerPushedNativePriceSource.InvalidConfig.selector);
        new OwnerPushedNativePriceSource(owner, type(uint256).max);

        // The cap itself is allowed.
        new ChainlinkNativePriceSource(feed, 365 days);
        new OwnerPushedNativePriceSource(owner, 365 days);
    }

    /// An aggregator mid-round carries the previous answer with no timestamp.
    /// Dating that to the epoch would pass the staleness bound on any chain
    /// whose clock is younger than the bound.
    function test_chainlinkRefusesAnIncompleteRound() public {
        MockAggregatorV3 feed = _feed(2500e8, 8);
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(feed, HOUR);

        feed.stage(2500e8, 0);
        vm.expectRevert(ChainlinkNativePriceSource.IncompleteRound.selector);
        source.nativeUsdPrice();
    }

    function test_chainlinkRefusesAZeroFeedOrZeroStaleness() public {
        // Deployed FIRST: a `new` after `expectRevert` is itself the next call,
        // and it succeeds, which consumes the expectation.
        MockAggregatorV3 feed = _feed(2500e8, 8);

        vm.expectRevert(ChainlinkNativePriceSource.InvalidConfig.selector);
        new ChainlinkNativePriceSource(IAggregatorV3(address(0)), HOUR);

        vm.expectRevert(ChainlinkNativePriceSource.InvalidConfig.selector);
        new ChainlinkNativePriceSource(feed, 0);
    }

    // ─── Owner-pushed ───────────────────────────────────────────────

    function _pushed() internal returns (OwnerPushedNativePriceSource) {
        return new OwnerPushedNativePriceSource(owner, HOUR);
    }

    function test_pushedReportsWhatTheOwnerSet() public {
        OwnerPushedNativePriceSource source = _pushed();

        vm.prank(owner);
        source.setPrice(4e8); // $4.00 per TIA

        (uint256 price, uint8 decimals) = source.nativeUsdPrice();
        assertEq(price, 4e8);
        assertEq(decimals, 8, "the pushed scale is not Chainlink's");
        assertEq(source.updatedAt(), block.timestamp);
    }

    /// Before the first push there is nothing to report, and answering zero
    /// would divide by zero in the consumer.
    function test_pushedRefusesToAnswerBeforeTheFirstPush() public {
        OwnerPushedNativePriceSource source = _pushed();

        vm.expectRevert(OwnerPushedNativePriceSource.NoPrice.selector);
        source.nativeUsdPrice();
    }

    function test_pushedRefusesAZeroPrice() public {
        OwnerPushedNativePriceSource source = _pushed();

        vm.prank(owner);
        vm.expectRevert(OwnerPushedNativePriceSource.InvalidPrice.selector);
        source.setPrice(0);
    }

    function test_onlyTheOwnerMayPush() public {
        OwnerPushedNativePriceSource source = _pushed();

        vm.prank(mallory);
        vm.expectRevert();
        source.setPrice(4e8);
    }

    /// A forgotten deployment refuses to price a fee rather than charging a
    /// rate nobody has confirmed.
    function test_pushedGoesStale() public {
        OwnerPushedNativePriceSource source = _pushed();

        vm.prank(owner);
        source.setPrice(4e8);

        vm.warp(T0 + HOUR);
        source.nativeUsdPrice(); // exactly at the deadline still answers

        vm.warp(T0 + HOUR + 1);
        vm.expectRevert(abi.encodeWithSelector(OwnerPushedNativePriceSource.StalePrice.selector, T0, T0 + HOUR));
        source.nativeUsdPrice();

        // And a fresh push revives it.
        vm.prank(owner);
        source.setPrice(4e8);
        source.nativeUsdPrice();
    }

    function test_pushedRefusesZeroStaleness() public {
        vm.expectRevert(OwnerPushedNativePriceSource.InvalidConfig.selector);
        new OwnerPushedNativePriceSource(owner, 0);
    }

    /// Renouncing would freeze the price and then let it go stale forever.
    function test_pushedOwnershipCannotBeRenounced() public {
        OwnerPushedNativePriceSource source = _pushed();

        vm.prank(owner);
        vm.expectRevert("renounce disabled");
        source.renounceOwnership();
    }
}
