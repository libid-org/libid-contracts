// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {INativePriceSource} from "./INativePriceSource.sol";

/// @title OwnerPushedNativePriceSource - a price an owner key states.
///
/// @notice The native token price for a chain with no feed. The owner writes
///         the number; the contract only says how old it is.
///
/// @dev **This is a trust addition, and it is not a formality.** Everything
///      else in the naming system is proof-derived, and this is not: the owner
///      chooses what one token is worth, so it chooses what a bind costs. A
///      wrong number here overcharges or undercharges every first bind on the
///      chain until it is corrected. Use it where no feed exists — Celestia
///      Eden and TIA — and prefer `ChainlinkNativePriceSource` everywhere one does.
///
///      What the owner CANNOT do is take the money: this contract never holds
///      value, and the fee goes to the recipient `IdentityNames` records.
///
///      **A price that stops being pushed stops working, on purpose.** After
///      `maxStaleness` the reads revert, so a forgotten deployment refuses to
///      price a fee rather than charging last quarter's rate. That blocks a
///      FIRST bind, and only a first bind: `IdentityNames` reads no price on
///      any other path, so a rename or a wallet move still works. The escape
///      hatch for an operator that cannot push is `setBindFee` with a zero fee,
///      which stops charging.
contract OwnerPushedNativePriceSource is INativePriceSource, Ownable2Step {
    /// @notice How many decimal places `price` carries.
    /// @dev Eight, the same as Chainlink's USD feeds, so both sources report on
    ///      one scale and a deployment can swap them without re-scaling a fee.
    uint8 public constant DECIMALS = 8;

    /// @notice How old the pushed price may be before reads refuse it.
    uint256 public immutable maxStaleness;

    /// @notice USD for one whole native token, with `DECIMALS` decimals.
    uint256 public price;

    /// @notice When the owner last pushed. Zero until the first push.
    uint256 public updatedAt;

    /// @notice The owner pushed a price.
    event PricePushed(uint256 price, uint256 updatedAt);

    /// Zero is not a price, and it would divide by zero downstream.
    error InvalidPrice();
    /// A staleness bound of zero, or past `MAX_STALENESS`, configures nothing.
    error InvalidConfig();
    /// No price has been pushed yet.
    error NoPrice();
    /// The pushed price is older than `maxStaleness`.
    error StalePrice(uint256 updatedAt, uint256 deadline);

    /// @notice The largest staleness bound a deployment may carry.
    /// @dev `updatedAt + maxStaleness` is checked arithmetic, so a bound near
    ///      `type(uint256).max` would panic on every read rather than mean
    ///      "never stale", and the value is immutable.
    uint256 public constant MAX_STALENESS = 365 days;

    constructor(address owner_, uint256 maxStaleness_) Ownable(owner_) {
        if (maxStaleness_ == 0 || maxStaleness_ > MAX_STALENESS) revert InvalidConfig();
        maxStaleness = maxStaleness_;
    }

    /// @notice State what one native token is worth in USD.
    function setPrice(uint256 price_) external onlyOwner {
        if (price_ == 0) revert InvalidPrice();
        price = price_;
        updatedAt = block.timestamp;
        emit PricePushed(price_, block.timestamp);
    }

    /// @inheritdoc INativePriceSource
    function nativeUsdPrice() external view returns (uint256, uint8) {
        if (updatedAt == 0) revert NoPrice();
        uint256 deadline = updatedAt + maxStaleness;
        if (block.timestamp > deadline) revert StalePrice(updatedAt, deadline);
        return (price, DECIMALS);
    }

    /// @dev Renouncing would freeze the price at whatever it says now, and the
    ///      reads would start reverting one `maxStaleness` later.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
