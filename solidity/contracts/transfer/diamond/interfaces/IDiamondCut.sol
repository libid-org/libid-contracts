// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EIP-2535 Diamond — cut interface.
/// @dev Add/replace/remove facet functions on a diamond. Reference: EIP-2535.
interface IDiamondCut {
    enum FacetCutAction {
        Add,
        Replace,
        Remove
    }

    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    /// @notice Add/replace/remove any number of functions and optionally run a
    ///         delegatecall `_init` with `_calldata` in one transaction.
    /// @param _diamondCut Facets and their function selectors to cut in.
    /// @param _init Address of the contract to delegatecall (or `address(0)`).
    /// @param _calldata Calldata for the `_init` delegatecall.
    function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external;

    event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
}
