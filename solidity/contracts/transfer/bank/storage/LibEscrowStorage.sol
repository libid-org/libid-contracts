// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibEscrowStorage — the Bank's token ledgers.
/// @dev The money: registered-wallet balances and id-escrow (unregistered)
///      balances, in their own namespaced slot — isolated from config/templates
///      so only the transfer/vault path touches funds.
library LibEscrowStorage {
    bytes32 internal constant STORAGE_POSITION = keccak256("dyaka.bank.escrow.v1");

    struct EscrowStorage {
        // Registered users: wallet → token → amount.
        mapping(address => mapping(address => uint256)) registeredBalances;
        // Unregistered users (id-escrow): escrowKey → token → amount, where
        // escrowKey = keccak256(abi.encode(ID_ESCROW_TAG, platform, userId)).
        mapping(bytes32 => mapping(address => uint256)) unregisteredBalances;
    }

    function store() internal pure returns (EscrowStorage storage es) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            es.slot := position
        }
    }
}
