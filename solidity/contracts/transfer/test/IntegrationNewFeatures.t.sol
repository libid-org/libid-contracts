// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IntegrationTest} from "./Integration.t.sol";
import {IBank} from "../bank/IBank.sol";
import {WebWallet} from "../../login/WebWallet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title Integration tests for transfer_within, balanceOf, balanceOfTotal
/// @dev Extends the existing IntegrationTest with new story chapters.
contract IntegrationNewFeaturesTest is IntegrationTest {
    // ═══════════════════════════════════════════════════════════════
    //  Helper: transfer_within via execute()
    // ═══════════════════════════════════════════════════════════════

    function _transferWithin(
        WebWallet sender,
        uint256 senderPk,
        string memory receiverPlatform,
        string memory receiverHandle,
        uint256 amount
    ) internal {
        bytes memory data = abi.encodeCall(
            IBank.transfer_within,
            (_domain(receiverPlatform), receiverHandle, _idFor(receiverHandle), address(token), amount)
        );
        _execute(sender, address(bank), data, senderPk);
    }

    function _approveBank(WebWallet wallet, uint256 amount, uint256 pk) internal {
        bytes memory data = abi.encodeCall(IERC20.approve, (address(bank), amount));
        _execute(wallet, address(token), data, pk);
    }

    // ═══════════════════════════════════════════════════════════════
    //  CHAPTER: transfer_within flow
    // ═══════════════════════════════════════════════════════════════

    /// @notice Full transfer_within story: registered→registered, registered→unregistered, then late registration
    function test_story_transferWithinFlow() public {
        // 1. Alice registers via OAuth, deposits 500 USDC into Bank
        WebWallet alice = _alice();
        _fund("x", "alice", 500e18);
        _assertBankBalance(alice, 500e18);

        // 2. Bob registers via OAuth
        WebWallet bob = _bob();

        // 3. Alice calls transfer_within("x", "bob", usdc, 200) via execute()
        _transferWithin(alice, ALICE_PK, "x", "bob", 200e18);

        // 4. Assert Alice's balanceOf = 300, Bob's balanceOf = 200
        _assertBankBalance("x", "alice", 300e18);
        _assertBankBalance("x", "bob", 200e18);
        _assertBankBalance(alice, 300e18);
        _assertBankBalance(bob, 200e18);

        // 5. Alice calls transfer_within to an unregistered handle "charlie"
        _transferWithin(alice, ALICE_PK, "x", "charlie", 100e18);

        // 6. Assert balanceOf("x", "charlie", usdc) = 100 in unregistered slot
        _assertBankBalance("x", "charlie", 100e18);
        _assertUnregisteredBalance("x", "charlie", 100e18);
        _assertBankBalance(alice, 200e18);

        // 7. Charlie later registers — balanceOf reflects the migrated balance
        WebWallet charlie = _charlie();
        _assertBankBalance(charlie, 100e18);
        _assertBankBalance("x", "charlie", 100e18);
    }

    // ═══════════════════════════════════════════════════════════════
    //  CHAPTER: balanceOf / balanceOfTotal
    // ═══════════════════════════════════════════════════════════════

    /// @notice Full balance view story: zero → deposit → wallet ERC20 → cross-check variants
    function test_story_balanceViews() public {
        // 1. Fresh Alice wallet with 0 balance
        WebWallet alice = _alice();
        assertEq(bank.balanceOf(address(alice), address(token)), 0);
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 0);

        // 2. Alice deposits 300 USDC into Bank
        _fund("x", "alice", 300e18);
        assertEq(bank.balanceOf(address(alice), address(token)), 300e18);
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 300e18);

        // 3. Alice also holds 100 USDC directly in her WebWallet (ERC20 transfer)
        _fundWallet(alice, 100e18);
        assertEq(bank.balanceOf(address(alice), address(token)), 300e18); // Bank-only unchanged
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 400e18); // Bank + wallet ERC20

        // 4. Test both address and (platform, handle) variants return same values
        assertEq(
            bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token)),
            bank.balanceOf(address(alice), address(token))
        );
        assertEq(
            bank.balanceOfTotal("api.x.com", "alice", _idFor("alice"), address(token)),
            bank.balanceOfTotal(address(alice), address(token))
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  CHAPTER: transfer_within auto-top-up
    // ═══════════════════════════════════════════════════════════════

    /// @notice Auto-top-up story: 0 Bank balance, 500 in wallet, transfer pulls from wallet
    function test_story_transferWithinAutoTopUp() public {
        // Setup: Alice and Bob registered
        WebWallet alice = _alice();
        WebWallet bob = _bob();

        // 1. Alice has 0 Bank balance but 500 USDC in WebWallet
        _fundWallet(alice, 500e18);
        _assertBankBalance(alice, 0);
        _assertTokenBalance(alice, 500e18);

        // Alice approves Bank to pull from her wallet
        _approveBank(alice, type(uint256).max, ALICE_PK);

        // 2. Alice calls transfer_within for 200 USDC
        _transferWithin(alice, ALICE_PK, "x", "bob", 200e18);

        // 3. Assert Bank pulled 200 from WebWallet, credited Bob
        _assertBankBalance(alice, 0); // All pulled, all sent
        _assertTokenBalance(alice, 300e18); // 500 - 200 shortfall pulled
        _assertBankBalance(bob, 200e18); // Bob received 200
    }
}
