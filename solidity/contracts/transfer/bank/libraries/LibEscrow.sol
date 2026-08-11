// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {LibEscrowStorage} from "../storage/LibEscrowStorage.sol";
import {LibCoreStorage} from "../storage/LibCoreStorage.sol";
import {IRegistry} from "../../../login/IRegistry.sol";
import {UserIdRequired, InsufficientBalance, InsufficientAllowance} from "../BankErrors.sol";

/// @title LibEscrow — the shared money layer (ledgers + id-escrow) for the Bank
///        vault and transfer facets.
/// @dev Escrow is keyed by the immutable platform userId (recycle-proof),
///      domain-separated with ID_ESCROW_TAG. On a FRESH deploy there is no legacy
///      handle-keyed escrow, so sweeps + totals read the id keyspace only.
library LibEscrow {
    using SafeERC20 for IERC20;

    /// @dev Domain-separation tag for the id-keyed escrow keyspace.
    string internal constant ID_ESCROW_TAG = "id:v1";

    /// @dev Escrow slot key, keyed by the immutable platform userId.
    function escrowKey(string memory platform, string memory userId) internal pure returns (bytes32) {
        if (bytes(userId).length == 0) revert UserIdRequired();
        return keccak256(abi.encode(ID_ESCROW_TAG, platform, userId));
    }

    /// @dev Identity hash for a (domain, username) pair.
    function identityHash(string calldata domain, string calldata username) internal pure returns (bytes32) {
        return keccak256(abi.encode(domain, username));
    }

    /// @dev Resolve a wallet by its immutable platform userId. Fresh deploy has no
    ///      pre-id (handle-keyed) users, so there is no handle fallback — a miss is
    ///      "unregistered" and the caller escrows under the id.
    function resolveById(string memory platform, string memory id) internal view returns (address) {
        return IRegistry(LibCoreStorage.store().registry).resolveById(platform, id);
    }

    /// @dev Token decimals (native defaults to 18). A genuine 0-decimal ERC-20 is
    ///      honored as 0 — a token whose `decimals()` reverts fails the whole tx.
    function tokenDecimals(address token) internal view returns (uint8) {
        if (token == address(0)) return 18;
        return IERC20Metadata(token).decimals();
    }

    /// @dev Sweep one id-escrow slot into the wallet's registered balance.
    function sweepKey(address wallet, address token, bytes32 key) internal {
        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        uint256 pending = es.unregisteredBalances[key][token];
        if (pending > 0) {
            delete es.unregisteredBalances[key][token];
            es.registeredBalances[wallet][token] += pending;
        }
    }

    /// @dev Sweep the wallet's id-escrow slots into its registered balance (the
    ///      ids are proven via the Registry, so recycle-proof).
    function migrate(address wallet, address token) internal {
        (string[] memory platforms, string[] memory userIds) =
            IRegistry(LibCoreStorage.store().registry).getUserIds(wallet);
        for (uint256 i = 0; i < platforms.length; i++) {
            if (bytes(userIds[i]).length == 0) continue;
            sweepKey(wallet, token, keccak256(abi.encode(ID_ESCROW_TAG, platforms[i], userIds[i])));
        }
    }

    /// @dev View total: registered + all (id-keyed) unregistered escrow for wallet.
    function totalBalance(address wallet, address token) internal view returns (uint256 total) {
        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        total = es.registeredBalances[wallet][token];
        (string[] memory platforms, string[] memory userIds) =
            IRegistry(LibCoreStorage.store().registry).getUserIds(wallet);
        for (uint256 i = 0; i < platforms.length; i++) {
            if (bytes(userIds[i]).length == 0) continue;
            total += es.unregisteredBalances[keccak256(abi.encode(ID_ESCROW_TAG, platforms[i], userIds[i]))][token];
        }
    }

    /// @dev Ensure `wallet` has `amount` registered, pulling any shortfall via its
    ///      ERC-20 allowance (native tokens can't be pulled → revert on shortfall).
    function autoTopUp(address wallet, address token, uint256 amount) internal {
        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        uint256 bal = es.registeredBalances[wallet][token];
        if (bal < amount) {
            if (token == address(0)) revert InsufficientBalance();
            uint256 shortfall = amount - bal;
            uint256 allowed = IERC20(token).allowance(wallet, address(this));
            if (allowed < shortfall) revert InsufficientAllowance(token, wallet, address(this), shortfall, allowed);
            IERC20(token).safeTransferFrom(wallet, address(this), shortfall);
            es.registeredBalances[wallet][token] += shortfall;
        }
    }
}
