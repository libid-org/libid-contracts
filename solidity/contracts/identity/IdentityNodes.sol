// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Turns a platform identity into the fixed-width key it is stored
///         under.
///
/// @dev The shape follows ENS: hash the parts, combine them into one `bytes32`
///      node, and key storage by the node rather than by a string. Fixed width
///      keeps a mapping cheap and a key unambiguous.
///
///      It differs from ENS in one way that matters. `abi.encode` is used
///      rather than concatenation, and a version tag leads every preimage, so
///      two node kinds can never produce the same key.
///
///      A node cannot be turned back into a string. That is a property of the
///      hash, not a shortcoming to route around: ENS answers the reverse
///      direction by storing the string, and so does this system.
library IdentityNodes {
    /// Separates an id node from a handle node.
    ///
    /// Without it, a handle that reads as a number and an account id that is
    /// that number produce the same key. Numeric handles are legal on X, and an
    /// old account's id is short, so the collision is reachable rather than
    /// theoretical.
    bytes32 internal constant ID_NODE_V1 = keccak256(bytes("dyaka.identity.id-node.v1"));
    bytes32 internal constant HANDLE_NODE_V1 = keccak256(bytes("dyaka.identity.handle-node.v1"));

    /// @notice The key an account id is stored under.
    /// @param platformId Which platform, as `keccak256` of its domain string.
    /// @param userId     The platform's immutable account id.
    function idNode(bytes32 platformId, string memory userId) internal pure returns (bytes32) {
        return keccak256(abi.encode(ID_NODE_V1, platformId, keccak256(bytes(userId))));
    }

    /// @notice The key a handle is stored under.
    /// @param platformId       Which platform, as `keccak256` of its domain string.
    /// @param normalizedHandle The handle AFTER normalization. Passing a raw
    ///                         handle here writes a key no reader will find.
    function handleNode(bytes32 platformId, string memory normalizedHandle) internal pure returns (bytes32) {
        return keccak256(abi.encode(HANDLE_NODE_V1, platformId, keccak256(bytes(normalizedHandle))));
    }
}
