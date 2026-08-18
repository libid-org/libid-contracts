// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {INativePriceSource} from "./INativePriceSource.sol";

/// @dev The part of Chainlink's `AggregatorV3Interface` this contract reads.
///      Declared here rather than vendored, the way `IIdentityVerifier` and
///      `INotary` are: two functions do not justify a dependency.
interface IAggregatorV3 {
    function decimals() external view returns (uint8);
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// @title ChainlinkNativePriceSource - a Chainlink feed, read as a price source.
///
/// @notice Reports the native token price from a Chainlink USD feed, and
///         refuses an answer that is stale or not positive.
///
/// @dev Immutable, and deliberately not upgradeable or ownable: it holds no
///      value, decides nothing, and points at one feed for its whole life.
///      Moving to another feed is a new deployment plus one `setBindFee` call,
///      which leaves a record. An owner key here would add a way to redirect
///      the price and buy nothing.
///
///      `maxStaleness` belongs to the FEED, because the heartbeat does. An
///      ETH/USD feed updates far more often than a long-tail one, so a single
///      number for every chain would either reject live prices or accept dead
///      ones.
contract ChainlinkNativePriceSource is INativePriceSource {
    /// @notice The feed this contract reads.
    IAggregatorV3 public immutable feed;

    /// @notice How old an answer may be before it is refused, in seconds.
    /// @dev Set it above the feed's heartbeat, or every read reverts.
    uint256 public immutable maxStaleness;

    /// The feed reports zero or a negative price, which cannot be a price.
    error InvalidPrice(int256 answer);
    /// The last answer is older than `maxStaleness`.
    error StalePrice(uint256 updatedAt, uint256 deadline);
    /// The feed reports an incomplete round.
    error IncompleteRound();
    /// A feed address of zero, or a staleness bound of zero or past
    /// `MAX_STALENESS`, configures nothing.
    error InvalidConfig();

    /// @notice The largest staleness bound a deployment may carry.
    ///
    /// @dev Bounded for two reasons. `updatedAt + maxStaleness` is checked
    ///      arithmetic, so a bound near `type(uint256).max` would panic on
    ///      every read instead of meaning "never stale" — and the value is
    ///      immutable, so that mistake is only recoverable by redeploying. And
    ///      a year already exceeds every feed's heartbeat by orders of
    ///      magnitude, so nothing legitimate is refused.
    uint256 public constant MAX_STALENESS = 365 days;

    constructor(IAggregatorV3 feed_, uint256 maxStaleness_) {
        if (address(feed_) == address(0) || maxStaleness_ == 0 || maxStaleness_ > MAX_STALENESS) {
            revert InvalidConfig();
        }
        feed = feed_;
        maxStaleness = maxStaleness_;
    }

    /// @inheritdoc INativePriceSource
    function nativeUsdPrice() external view returns (uint256 price, uint8 decimals) {
        (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
        if (answer <= 0) revert InvalidPrice(answer);
        // An aggregator mid-round reports `updatedAt == 0` while still
        // carrying the previous answer. Treating that as a timestamp would
        // date the price to the epoch, which passes the bound below on any
        // chain whose clock is younger than it.
        if (updatedAt == 0) revert IncompleteRound();

        // Added to `updatedAt`, not subtracted from `block.timestamp`: the
        // subtraction underflows on a chain younger than `maxStaleness`, which
        // is every fresh test chain.
        uint256 deadline = updatedAt + maxStaleness;
        if (block.timestamp > deadline) revert StalePrice(updatedAt, deadline);

        return (uint256(answer), feed.decimals());
    }
}
