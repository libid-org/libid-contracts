// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IntegrationTest} from "./Integration.t.sol";
import {WebWallet} from "../../login/WebWallet.sol";

contract BalanceViewsTest is IntegrationTest {
    // ── balanceOf(address, token) — Dyaka only ─────────────────────

    function test_balanceOf_byAddress_registered() public {
        WebWallet alice = _alice();
        _fund("x", "alice", 100e18);

        assertEq(bank.balanceOf(address(alice), address(token)), 100e18);
    }

    function test_balanceOf_byAddress_withUnmigrated() public {
        // Fund before registration → goes to unregisteredBalances
        _fund("x", "alice", 50e18);
        // Now register
        WebWallet alice = _alice();
        // Fund again after registration → goes to registeredBalances
        _fund("x", "alice", 30e18);

        // balanceOf should see both: 30 registered + 50 unmigrated
        assertEq(bank.balanceOf(address(alice), address(token)), 80e18);
    }

    function test_balanceOf_byAddress_unregisteredWallet() public {
        // Unknown wallet address → 0
        assertEq(bank.balanceOf(address(0xdead), address(token)), 0);
    }

    // ── balanceOf(platform, handle, token) — Dyaka only ────────────

    function test_balanceOf_byHandle_registered() public {
        _alice();
        _fund("x", "alice", 200e18);
        assertEq(bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token)), 200e18);
    }

    function test_balanceOf_byHandle_unregistered() public {
        _fund("x", "nobody", 75e18);
        assertEq(bank.balanceOf("api.x.com", "nobody", _idFor("nobody"), address(token)), 75e18);
    }

    function test_balanceOf_byHandle_noBalance() public {
        assertEq(bank.balanceOf("api.x.com", "ghost", _idFor("ghost"), address(token)), 0);
    }

    // ── balanceOfTotal(address, token) — Dyaka + wallet ERC20 ──────

    function test_balanceOfTotal_byAddress() public {
        WebWallet alice = _alice();
        _fund("x", "alice", 100e18);
        _fundWallet(alice, 500e18);
        // Total = 100 (Dyaka) + 500 (wallet ERC20)
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 600e18);
    }

    function test_balanceOfTotal_byAddress_onlyDyaka() public {
        WebWallet alice = _alice();
        _fund("x", "alice", 100e18);
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 100e18);
    }

    function test_balanceOfTotal_byAddress_onlyWallet() public {
        WebWallet alice = _alice();
        _fundWallet(alice, 500e18);
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 500e18);
    }

    function test_balanceOfTotal_byAddress_zero() public {
        WebWallet alice = _alice();
        assertEq(bank.balanceOfTotal(address(alice), address(token)), 0);
    }

    // ── balanceOfTotal(platform, handle, token) — Dyaka + wallet ───

    function test_balanceOfTotal_byHandle_registered() public {
        WebWallet alice = _alice();
        _fund("x", "alice", 100e18);
        _fundWallet(alice, 250e18);
        // Total = 100 (Dyaka) + 250 (wallet ERC20)
        assertEq(bank.balanceOfTotal("api.x.com", "alice", _idFor("alice"), address(token)), 350e18);
    }

    function test_balanceOfTotal_byHandle_unregistered() public {
        // Unregistered: only Dyaka balance, no wallet
        _fund("x", "nobody", 75e18);
        assertEq(bank.balanceOfTotal("api.x.com", "nobody", _idFor("nobody"), address(token)), 75e18);
    }

    function test_balanceOfTotal_byHandle_noBalance() public {
        assertEq(bank.balanceOfTotal("api.x.com", "ghost", _idFor("ghost"), address(token)), 0);
    }
}
