// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IntegrationTest} from "./Integration.t.sol";
import {Registry} from "../../login/Registry.sol";
import {UserIdRequired} from "../bank/BankErrors.sol";
import {WebWallet} from "../../login/WebWallet.sol";

/// @notice Regression suite for the id-as-truth escrow invariant.
///
/// Core invariant: unregistered escrow is keyed by the IMMUTABLE platform
/// user-id, domain-separated by the "id:v1" tag. The legacy handle-sweep
/// keyspace (keccak256(abi.encode(platform, handle))) must never collide with
/// it, so a wallet whose handle equals a victim's numeric id string cannot
/// sweep the victim's id-escrow.
contract EscrowByIdTest is IntegrationTest {
    string constant XHOST = "api.x.com";

    /// id-escrow slot key, mirroring Bank._escrowKey
    /// (keccak256(abi.encode(ID_ESCROW_TAG, platform, userId))).
    function _idKey(string memory platform, string memory userId) internal pure returns (bytes32) {
        return keccak256(abi.encode("id:v1", platform, userId));
    }

    /// Legacy handle-keyed slot (pre-id deposits / handle sweep target).
    function _handleKey(string memory platform, string memory handle) internal pure returns (bytes32) {
        return keccak256(abi.encode(platform, handle));
    }

    /// Deposit `amount` into the id-escrow for (XHOST, userId). Handle is only
    /// used for the (unregistered) resolve and never enters the escrow key.
    function _fundId(string memory handle, string memory userId, uint256 amount) internal {
        token.mint(address(this), amount);
        token.approve(address(bank), amount);
        bank.deposit(XHOST, handle, userId, address(token), amount);
    }

    /// Register a fresh wallet for (handle, userId) with a distinct session key.
    function _registerWallet(string memory handle, string memory userId, uint256 pk) internal returns (WebWallet) {
        address sessionAddr = vm.addr(pk);
        Registry.FullTlsProof memory proof = _buildRegistryProofWithId(
            XHOST, handle, userId, "api.test.com/endpoint", '"username":"', sessionAddr, address(0), block.timestamp
        );
        registry.register_session(proof, XHOST, handle, userId, "api.test.com/endpoint");
        return WebWallet(payable(registry.resolve(XHOST, handle)));
    }

    /// Trigger lazy migration on `wallet` by depositing a tiny amount to its
    /// (registered) identity. Returns nothing; side-effect is the sweep.
    function _triggerMigrate(string memory handle, string memory userId) internal {
        _fundId(handle, userId, 1);
    }

    // ── Core invariant: escrow follows the id, not the handle ──────────

    /// Funds deposited to an unregistered id are swept to the wallet that later
    /// registers that SAME id, even if the wallet's current handle differs.
    function test_idEscrow_migratesByIdAcrossRename() public {
        // Deposit to unregistered id "777" (handle at deposit time: "oldname").
        _fundId("oldname", "777", 100e18);
        assertEq(bank.unregisteredBalances(_idKey(XHOST, "777"), address(token)), 100e18);

        // The same id "777" later registers under a DIFFERENT handle "newname".
        WebWallet w = _registerWallet("newname", "777", 0xE001);

        // Migrate: id-escrow for "777" sweeps into the registered wallet.
        _triggerMigrate("newname", "777");

        assertEq(bank.unregisteredBalances(_idKey(XHOST, "777"), address(token)), 0, "id-escrow not swept");
        // 100e18 deposit + 1 wei migrate trigger.
        assertEq(bank.registeredBalances(address(w), address(token)), 100e18 + 1, "registered balance wrong");
    }

    // ── C1 regression: id keyspace must not collide with handle sweep ──

    /// Fund id-escrow for (x, userId="12345"). Then register a DIFFERENT wallet
    /// whose HANDLE is literally "12345" (with a different userId). Migrating it
    /// must NOT sweep the victim's id-escrow.
    function test_idEscrow_notStolenByHandleEqualToVictimId() public {
        // Victim: 1000 tokens escrowed under the immutable id "12345".
        _fundId("victim_handle", "12345", 1000e18);
        bytes32 victimKey = _idKey(XHOST, "12345");
        assertEq(bank.unregisteredBalances(victimKey, address(token)), 1000e18);

        // Attacker registers a wallet whose HANDLE is the numeric string "12345"
        // but whose immutable id is something else entirely.
        WebWallet attacker = _registerWallet("12345", "id_attacker", 0xA77ACC);

        // Sanity: the attacker's handle-sweep key and the victim's id-key differ.
        assertTrue(_handleKey(XHOST, "12345") != victimKey, "domain separation broken");

        // Trigger migration on the attacker's wallet (handle == "12345").
        _triggerMigrate("12345", "id_attacker");

        // The victim's id-escrow is UNTOUCHED — the attacker only swept its own
        // (empty) handle slot and its own id slot.
        assertEq(bank.unregisteredBalances(victimKey, address(token)), 1000e18, "victim id-escrow was swept (C1)");
        // Attacker only received its own 1-wei migrate trigger, nothing of the victim's.
        assertEq(bank.registeredBalances(address(attacker), address(token)), 1, "attacker stole funds");
    }

    /// The victim can still claim their escrow by registering the real id.
    function test_victimCanClaimAfterCollisionAttempt() public {
        _fundId("victim_handle", "12345", 1000e18);

        // Attacker tries the handle-collision sweep first (no-op for the victim).
        _registerWallet("12345", "id_attacker", 0xA77ACC);
        _triggerMigrate("12345", "id_attacker");
        assertEq(bank.unregisteredBalances(_idKey(XHOST, "12345"), address(token)), 1000e18);

        // The legitimate owner of id "12345" registers (handle "real_owner").
        WebWallet victim = _registerWallet("real_owner", "12345", 0xC1A12);
        _triggerMigrate("real_owner", "12345");

        assertEq(bank.unregisteredBalances(_idKey(XHOST, "12345"), address(token)), 0, "victim could not claim");
        assertEq(bank.registeredBalances(address(victim), address(token)), 1000e18 + 1);
    }

    // ── Deposit/read consistency through the id key ────────────────────

    /// balanceOf(platform, handle, userId) reads the same id-escrow slot a
    /// deposit with that userId writes — regardless of the handle string.
    function test_balanceOf_readsIdEscrowConsistently() public {
        _fundId("some_handle", "999", 42e18);
        // Same id, different handle still reads the same slot.
        assertEq(bank.balanceOf(XHOST, "some_handle", "999", address(token)), 42e18);
        assertEq(bank.balanceOf(XHOST, "another_handle", "999", address(token)), 42e18);
        // Different id reads an empty slot.
        assertEq(bank.balanceOf(XHOST, "some_handle", "111", address(token)), 0);
    }

    /// Empty userId is a write-only revert; reads of an unknown id return 0,
    /// not a revert (no escrow slot to key).
    function test_balanceOf_emptyId_returnsZero() public view {
        assertEq(bank.balanceOf(XHOST, "ghost", "", address(token)), 0);
        assertEq(bank.balanceOfTotal(XHOST, "ghost", "", address(token)), 0);
    }

    /// Empty userId for an unregistered receiver reverts UserIdRequired.
    function test_deposit_emptyIdForUnregistered_reverts() public {
        token.mint(address(this), 1e18);
        token.approve(address(bank), 1e18);
        vm.expectRevert(UserIdRequired.selector);
        bank.deposit(XHOST, "ghost", "", address(token), 1e18);
    }
}
