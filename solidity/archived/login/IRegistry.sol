// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IRegistry — maps (platform, handle) → wallet address.
interface IRegistry {
    /// @notice Resolve a platform handle to its wallet contract address.
    /// @return The wallet address, or address(0) if not registered.
    function resolve(string calldata platform, string calldata handle) external view returns (address);

    /// @notice Resolve a platform id to its wallet — authoritative, no handle indirection.
    /// @return The wallet address, or address(0) if not registered.
    function resolveById(string calldata platform, string calldata id) external view returns (address);

    /// @notice The immutable id a handle currently points to ("" if unbound).
    function handleHint(string calldata platform, string calldata handle) external view returns (string memory);

    /// @notice Get all (platform, handle) pairs linked to a wallet.
    function getHandles(address wallet) external view returns (string[] memory platforms, string[] memory handles);

    /// @notice Get all (platform, userId) pairs linked to a wallet — the
    ///         immutable identity key (handle is a mutable label). "" for
    ///         identities registered before the id refactor.
    function getUserIds(address wallet) external view returns (string[] memory platforms, string[] memory userIds);

    /// @notice Emitted when a handle is registered or updated.
    event HandleRegistered(string platform, string handle, address indexed owner);
}
