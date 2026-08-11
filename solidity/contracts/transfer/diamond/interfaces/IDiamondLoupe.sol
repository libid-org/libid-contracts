// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EIP-2535 Diamond — loupe (introspection) interface.
/// @dev Lets tools enumerate the facets and their selectors on a diamond.
interface IDiamondLoupe {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    /// @notice All facet addresses and their function selectors.
    function facets() external view returns (Facet[] memory facets_);

    /// @notice Function selectors provided by a facet.
    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory);

    /// @notice All facet addresses used by the diamond.
    function facetAddresses() external view returns (address[] memory);

    /// @notice The facet that implements the given selector (or `address(0)`).
    function facetAddress(bytes4 _functionSelector) external view returns (address);
}
