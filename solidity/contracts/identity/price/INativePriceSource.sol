// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title INativePriceSource - what one native token is worth in USD.
///
/// @dev A fee denominated in USD but paid in the chain's own token needs a
///      price, and the way to get one differs per chain. Chainlink has a feed
///      for ETH and for the usual L2 tokens; Celestia Eden has none for TIA. So
///      the source is an address `IdentityNames` points at, not a dependency it
///      hard-codes.
///
///      **The source owns the staleness rule, and REVERTS instead of answering
///      with a price it does not stand behind.** Only the source knows its own
///      cadence: a Chainlink feed has a heartbeat, an owner-pushed price has an
///      operations schedule. A second staleness bound in the consumer would be
///      one more place to configure the same policy wrong.
interface INativePriceSource {
    /// @notice USD for one whole native token.
    ///
    /// @dev Reverts when the price is stale or not usable.
    ///
    /// @return price    The value, with `decimals` decimal places.
    /// @return decimals How many decimal places `price` carries.
    function nativeUsdPrice() external view returns (uint256 price, uint8 decimals);
}
