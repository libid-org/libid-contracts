// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IIdentityVerifier} from "../IIdentityVerifier.sol";
import {ChainlinkNativePriceSource, IAggregatorV3} from "../price/ChainlinkNativePriceSource.sol";
import {INativePriceSource} from "../price/INativePriceSource.sol";
import {MockIdentityVerifier} from "./MockIdentityVerifier.sol";

/// @notice The fee against a REAL Chainlink feed, on a fork of mainnet.
///
/// @dev Everything else about the price sources is proved against a mock, which
///      says nothing about whether we read a live aggregator correctly. The
///      cases that only production data can settle are the shape of
///      `latestRoundData`, the scale the feed reports, and whether a real
///      answer is fresh enough to be usable at all.
///
///      A misread of `decimals` is the failure this exists to catch: it does not
///      revert, it prices the fee wrong by orders of magnitude, and every mock
///      agrees with whatever the mock was told.
///
///      **Self-skipping.** Without `MAINNET_RPC_URL` these tests skip rather
///      than fail, the way the OIDC flow tests skip without their proof
///      artifacts. CI stays offline; a developer opts in by exporting the URL.
///
///      Nothing is asserted about the price itself. The feed moves, so the
///      assertions are relationships — the quote equals what the feed says, the
///      charge equals the quote — plus one order-of-magnitude band that a
///      decimals mistake cannot survive.
contract ChainlinkNativePriceSourceForkTest is Test {
    /// Chainlink ETH/USD on Ethereum mainnet.
    address internal constant ETH_USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    /// Generous on purpose: what is under test is the decode, not the feed's
    /// heartbeat. `test_aTightStalenessBoundRefusesRealData` covers the refusal.
    uint256 internal constant STALENESS = 1 days;

    /// $1.00 on the eight-decimal scale `FEE_USD_DECIMALS` names.
    uint256 internal constant ONE_DOLLAR = 1e8;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;

    address internal alice = makeAddr("alice");
    address internal owner = makeAddr("owner");
    address internal treasury = makeAddr("treasury");

    /// Select the fork, or skip. Returns false when the test must not run.
    function _fork() internal returns (bool) {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true, "set MAINNET_RPC_URL to run the Chainlink fork tests");
            return false;
        }
        vm.createSelectFork(rpc);

        // On a fork an address is not empty just because a test invented it.
        // `treasury` here is a deployed forwarder on mainnet: it accepts the
        // fee and passes it straight on, so its balance never moves and the
        // payment looks lost. Clear the code and they are ordinary accounts
        // again.
        vm.etch(alice, "");
        vm.etch(treasury, "");
        return true;
    }

    /// The wrapper reports exactly what the aggregator reports.
    function test_theWrapperReportsTheLiveFeed() public {
        if (!_fork()) return;

        (, int256 answer,,,) = IAggregatorV3(ETH_USD).latestRoundData();
        uint8 feedDecimals = IAggregatorV3(ETH_USD).decimals();

        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(IAggregatorV3(ETH_USD), STALENESS);
        (uint256 price, uint8 decimals) = source.nativeUsdPrice();

        assertGt(answer, 0, "the live feed reports no price");
        assertEq(price, uint256(answer), "the wrapper does not report the feed's answer");
        assertEq(decimals, feedDecimals, "the wrapper does not report the feed's scale");
    }

    /// The whole path on live data: quote, pay exactly the quote, and the
    /// treasury receives it.
    function test_aFirstBindIsPricedAndChargedFromTheLiveFeed() public {
        if (!_fork()) return;

        IdentityNames names = IdentityNames(
            address(new ERC1967Proxy(address(new IdentityNames()), abi.encodeCall(IdentityNames.initialize, (owner))))
        );
        MockIdentityVerifier verifier = new MockIdentityVerifier("mock");
        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(IAggregatorV3(ETH_USD), STALENESS);

        vm.startPrank(owner);
        names.setPlatform(X, HandleVectors.rulesFor(X));
        names.setVerifier(X, 1, IIdentityVerifier(address(verifier)), 0);
        names.setBindFee(INativePriceSource(address(source)), ONE_DOLLAR, treasury);
        vm.stopPrank();

        // What the feed says a dollar is worth, computed here rather than read
        // back from the contract under test.
        (, int256 answer,,,) = IAggregatorV3(ETH_USD).latestRoundData();
        uint8 feedDecimals = IAggregatorV3(ETH_USD).decimals();
        uint256 expected = (ONE_DOLLAR * (10 ** feedDecimals) * 1 ether) / (uint256(answer) * (10 ** 8));

        uint256 quote = names.bindFeeWeiFor(X, "123");
        assertEq(quote, expected, "the quote disagrees with the live feed");

        // A dollar of ether, at any price this feed will ever report. Reaching
        // either edge means `decimals` was misread, which is the mistake a mock
        // cannot catch.
        assertGt(quote, 1e12, "a dollar priced under 0.000001 ETH");
        assertLt(quote, 1 ether, "a dollar priced over 1 ETH");

        vm.deal(alice, quote);
        verifier.stage("123", "alice", alice, uint64(block.timestamp));
        vm.prank(alice);
        names.bind{value: quote}(X, hex"", false, quote);

        assertEq(treasury.balance, quote, "the treasury received something else");
        assertEq(alice.balance, 0, "the payer was charged something else");
        assertEq(names.resolveHandle(X, "alice"), alice, "the bind did not land");
        assertEq(names.bindFeeWeiFor(X, "123"), 0, "the account is still quoted a fee");
    }

    /// The staleness path fires against real data, without the test depending
    /// on how often the feed happens to update.
    function test_aTightStalenessBoundRefusesRealData() public {
        if (!_fork()) return;

        ChainlinkNativePriceSource source = new ChainlinkNativePriceSource(IAggregatorV3(ETH_USD), 1);
        (,,, uint256 updatedAt,) = IAggregatorV3(ETH_USD).latestRoundData();

        // A one-second bound cannot hold unless the feed updated this block.
        vm.warp(updatedAt + 2);
        vm.expectRevert(
            abi.encodeWithSelector(ChainlinkNativePriceSource.StalePrice.selector, updatedAt, updatedAt + 1)
        );
        source.nativeUsdPrice();
    }
}
