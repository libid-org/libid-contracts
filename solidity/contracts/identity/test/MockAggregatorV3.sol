// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAggregatorV3} from "../price/ChainlinkNativePriceSource.sol";

/// @notice A Chainlink feed that answers whatever a test stages.
contract MockAggregatorV3 is IAggregatorV3 {
    int256 private _answer;
    uint256 private _updatedAt;
    uint8 private _decimals;
    bool private _shouldRevert;

    constructor(int256 answer_, uint256 updatedAt_, uint8 decimals_) {
        _answer = answer_;
        _updatedAt = updatedAt_;
        _decimals = decimals_;
    }

    function stage(int256 answer_, uint256 updatedAt_) external {
        _answer = answer_;
        _updatedAt = updatedAt_;
    }

    function setRevert(bool value) external {
        _shouldRevert = value;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        require(!_shouldRevert, "feed is down");
        return (1, _answer, _updatedAt, _updatedAt, 1);
    }
}
