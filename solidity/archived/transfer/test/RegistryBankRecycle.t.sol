// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {RegistryTest} from "../../login/test/Registry.t.sol";

/// Registry × Bank integration. Lives here, not in Registry.t.sol, so the
/// login-side Registry tests carry no Bank dependency. Inherits RegistryTest
/// for its fixtures and `_registerXAliceId` helper.
contract RegistryBankRecycleTest is RegistryTest, BankDiamondDeployer {
    // T12: Bank balance under A's id survives a handle recycle to B (I2/I3).
    function test_T12_bankBalanceSurvivesRecycle() public {
        // A Bank diamond wired to this registry.
        IBank bank = IBank(deployBankDiamond(owner, notaryAddr, backendAddr, address(registry)));
        bank.registerToken("ETH", address(0));

        // A registers x.com/alice under id 100 and is funded.
        address walletA = _registerXAliceId("100", userSessionAddr, block.timestamp);
        bank.deposit{value: 1 ether}("x.com", "alice", "100", address(0), 1 ether);
        assertEq(bank.balanceOf(walletA, address(0)), 1 ether);

        // B recycles the handle "alice" under a fresh id 200.
        uint256 bPk = 0xB003;
        address bAddr = vm.addr(bPk);
        address walletB = _registerXAliceId("200", bAddr, block.timestamp);

        // Resolve now points to B, but A's funds are intact and reachable by id.
        assertEq(registry.resolve("x.com", "alice"), walletB);
        assertEq(registry.resolveById("x.com", "100"), walletA);
        assertEq(bank.balanceOf(walletA, address(0)), 1 ether);
        assertEq(bank.balanceOf(walletB, address(0)), 0);
    }
}
