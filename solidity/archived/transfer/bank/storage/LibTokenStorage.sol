// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibTokenStorage — the ERC-20 token registry.
/// @dev name↔address mapping (both directions) + the registered-token list,
///      in its own namespaced slot — isolated from templates and escrow.
library LibTokenStorage {
    bytes32 internal constant STORAGE_POSITION = keccak256("dyaka.bank.token.v1");

    struct TokenStorage {
        mapping(bytes32 => address) tokenByName; // keccak(name) → ERC20 (case-sensitive)
        mapping(address => string) tokenName; // ERC20 → canonical display name
        address[] registeredTokens;
    }

    function store() internal pure returns (TokenStorage storage ts) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            ts.slot := position
        }
    }
}
