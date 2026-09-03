// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibDiamond} from "../diamond/libraries/LibDiamond.sol";
import {LibCoreStorage} from "./storage/LibCoreStorage.sol";
import {EnforcedPause, ReentrantCall} from "./BankErrors.sol";

/// @title BankModifiers — shared access / lifecycle modifiers for Bank facets.
/// @dev One definition inherited by every facet (a diamond can't inherit OZ's
///      Ownable/Pausable/ReentrancyGuard per-facet). Owner is the diamond owner
///      (ERC-173); pause + reentrancy flags live in LibCoreStorage.
abstract contract BankModifiers {
    modifier onlyOwner() {
        LibDiamond.enforceIsContractOwner();
        _;
    }

    modifier whenNotPaused() {
        if (LibCoreStorage.store().paused) revert EnforcedPause();
        _;
    }

    modifier nonReentrant() {
        LibCoreStorage.CoreStorage storage cs = LibCoreStorage.store();
        if (cs.reentrancyStatus == 2) revert ReentrantCall();
        cs.reentrancyStatus = 2;
        _;
        cs.reentrancyStatus = 1;
    }
}
