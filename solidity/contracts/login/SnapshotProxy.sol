// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SnapshotProxy — minimal delegating proxy with snapshotted implementation.
/// @notice Stores the implementation address in the ERC1967 slot at deploy time.
///         NOT automatically upgraded when a beacon changes — each wallet keeps
///         the implementation it was deployed with. The implementation contract
///         can update the slot via UUPS-style self-upgrade (upgrade_to_latest).
contract SnapshotProxy {
    /// @dev ERC1967 implementation storage slot.
    ///      bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    bytes32 private constant _IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address implementation) {
        assembly {
            sstore(_IMPL_SLOT, implementation)
        }
    }

    fallback() external payable {
        assembly {
            let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
