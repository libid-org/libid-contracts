// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ERC-173 — contract ownership standard (used by the diamond).
interface IERC173 {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice The address of the owner.
    function owner() external view returns (address owner_);

    /// @notice Transfer ownership. Set to `address(0)` to renounce.
    function transferOwnership(address _newOwner) external;
}
