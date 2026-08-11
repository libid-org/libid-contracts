// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibCoreStorage — cross-cutting Bank config + lifecycle flags.
/// @dev Trusted-party pointers, replay set, and the pause / reentrancy flags
///      (replacing the OZ Pausable / ReentrancyGuard base contracts a diamond
///      cannot inherit). Ownership lives in `LibDiamond` (ERC-173). Its own
///      namespaced slot, isolated from the other Bank storage concerns.
library LibCoreStorage {
    bytes32 internal constant STORAGE_POSITION = keccak256("dyaka.bank.core.v1");

    struct CoreStorage {
        address notary; // NotaryRegistry proxy
        address backend; // backend signer
        address registry; // Registry (resolves WebWallet by id)
        mapping(bytes32 => bool) usedTransfers; // replay protection by uid
        bool paused;
        bool initialized; // one-shot guard: BankInit.init sets it; a re-delegatecall reverts
        uint256 reentrancyStatus; // 0/1 = not entered, 2 = entered
    }

    function store() internal pure returns (CoreStorage storage cs) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            cs.slot := position
        }
    }
}
