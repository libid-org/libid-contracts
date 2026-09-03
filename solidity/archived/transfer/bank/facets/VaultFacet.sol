// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {BankModifiers} from "../BankModifiers.sol";
import {LibEscrow} from "../libraries/LibEscrow.sol";
import {LibEscrowStorage} from "../storage/LibEscrowStorage.sol";
import {LibTokenStorage} from "../storage/LibTokenStorage.sol";
import {
    ZeroAmount,
    TokenNotRegistered,
    NativeAmountMismatch,
    NativeSentWithErc20,
    InsufficientAllowance,
    InsufficientBalance,
    NativeTransferFailed
} from "../BankErrors.sol";

/// @title VaultFacet — deposits, withdrawals, and balance views.
/// @dev The user-facing money surface. Funds live in the diamond; the ledgers +
///      id-escrow live in LibEscrowStorage, read/written through LibEscrow.
contract VaultFacet is BankModifiers {
    using SafeERC20 for IERC20;

    event Deposited(address indexed wallet, bytes32 indexed handleKey, address indexed token, uint256 amount);
    event Withdrawn(address indexed wallet, address indexed recipient, address indexed token, uint256 amount);

    /// @notice Top up a user's balance. Credits the resolved wallet, or id-escrow
    ///         when the recipient hasn't registered yet.
    function deposit(
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address token,
        uint256 amount
    ) external payable nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (bytes(LibTokenStorage.store().tokenName[token]).length == 0) revert TokenNotRegistered();

        if (token == address(0)) {
            if (msg.value != amount) revert NativeAmountMismatch();
        } else {
            if (msg.value != 0) revert NativeSentWithErc20();
            uint256 allowed = IERC20(token).allowance(msg.sender, address(this));
            if (allowed < amount) revert InsufficientAllowance(token, msg.sender, address(this), amount, allowed);
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }

        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        address wallet = LibEscrow.resolveById(platform, userId);
        if (wallet != address(0)) {
            LibEscrow.migrate(wallet, token);
            es.registeredBalances[wallet][token] += amount;
            emit Deposited(wallet, bytes32(0), token, amount);
        } else {
            bytes32 key = LibEscrow.escrowKey(platform, userId);
            es.unregisteredBalances[key][token] += amount;
            emit Deposited(address(0), key, token, amount);
        }
    }

    /// @notice Withdraw from the caller's registered balance to `recipient`.
    function withdraw(address recipient, address token, uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();

        LibEscrow.migrate(msg.sender, token);
        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        if (es.registeredBalances[msg.sender][token] < amount) revert InsufficientBalance();
        es.registeredBalances[msg.sender][token] -= amount;

        if (token == address(0)) {
            (bool ok,) = recipient.call{value: amount}("");
            if (!ok) revert NativeTransferFailed();
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
        emit Withdrawn(msg.sender, recipient, token, amount);
    }

    /// @notice Registered + id-escrow balance (Bank-held) for a wallet.
    function balanceOf(address wallet, address token) external view returns (uint256) {
        return LibEscrow.totalBalance(wallet, token);
    }

    /// @notice Bank-held balance plus the wallet's own on-chain token balance.
    function balanceOfTotal(address wallet, address token) external view returns (uint256) {
        uint256 walletBal = token == address(0) ? wallet.balance : IERC20(token).balanceOf(wallet);
        return LibEscrow.totalBalance(wallet, token) + walletBal;
    }

    /// @notice Bank-held balance for a (platform, id) identity. Registered → the
    ///         full aggregated total; else the id-escrow slot. Handle is display-only.
    function balanceOf(string calldata platform, string calldata handle, string calldata userId, address token)
        external
        view
        returns (uint256)
    {
        address wallet = LibEscrow.resolveById(platform, userId);
        if (wallet != address(0)) return LibEscrow.totalBalance(wallet, token);
        if (bytes(userId).length == 0) return 0;
        return LibEscrowStorage.store().unregisteredBalances[LibEscrow.escrowKey(platform, userId)][token];
    }

    /// @notice As the (platform,...) `balanceOf`, plus the resolved wallet's own
    ///         on-chain token balance.
    function balanceOfTotal(string calldata platform, string calldata handle, string calldata userId, address token)
        external
        view
        returns (uint256)
    {
        address wallet = LibEscrow.resolveById(platform, userId);
        if (wallet == address(0)) {
            if (bytes(userId).length == 0) return 0;
            return LibEscrowStorage.store().unregisteredBalances[LibEscrow.escrowKey(platform, userId)][token];
        }
        uint256 walletBal = token == address(0) ? wallet.balance : IERC20(token).balanceOf(wallet);
        return LibEscrow.totalBalance(wallet, token) + walletBal;
    }

    /// @notice Compute the identity hash for a (domain, username) pair.
    function identityHash(string calldata domain, string calldata username) external pure returns (bytes32) {
        return LibEscrow.identityHash(domain, username);
    }

    /// @notice Raw registered-ledger balance for a wallet (matches the old Bank
    ///         public mapping getter). Aggregation is `balanceOf`.
    function registeredBalances(address wallet, address token) external view returns (uint256) {
        return LibEscrowStorage.store().registeredBalances[wallet][token];
    }

    /// @notice Raw id-escrow slot balance (matches the old Bank public mapping getter).
    function unregisteredBalances(bytes32 key, address token) external view returns (uint256) {
        return LibEscrowStorage.store().unregisteredBalances[key][token];
    }
}
