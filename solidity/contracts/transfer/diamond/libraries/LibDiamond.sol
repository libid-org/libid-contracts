// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IDiamondCut} from "../interfaces/IDiamondCut.sol";

/// @title LibDiamond — EIP-2535 diamond storage, cut, and ownership.
/// @dev Reference implementation (diamond-3, Nick Mudge), adapted. Holds the
///      diamond's OWN state (facet routing table + owner) in a fixed namespaced
///      slot, separate from any facet's application storage.
library LibDiamond {
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 functionSelectorPosition; // position in facetFunctionSelectors.functionSelectors
    }

    struct FacetFunctionSelectors {
        bytes4[] functionSelectors;
        uint256 facetAddressPosition; // position of facetAddress in facetAddresses
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;
        mapping(address => FacetFunctionSelectors) facetFunctionSelectors;
        address[] facetAddresses;
        mapping(bytes4 => bool) supportedInterfaces;
        address contractOwner;
    }

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event DiamondCut(IDiamondCut.FacetCut[] _diamondCut, address _init, bytes _calldata);

    error NotContractOwner(address caller, address owner);
    error NoSelectorsInFacet();
    error FacetAddressZeroWithSelectors();
    error FunctionAlreadyExists(bytes4 selector);
    error FacetHasNoCode(address facet);
    error CannotReplaceWithSameFunction(bytes4 selector);
    error RemoveFacetMustBeZeroAddress(address facet);
    error CannotRemoveNonexistentFunction(bytes4 selector);
    error CannotRemoveImmutableFunction(bytes4 selector);
    error IncorrectFacetCutAction();
    error InitAddressZeroWithCalldata();
    error InitCalldataEmptyWithAddress();
    error InitReverted(address init, bytes returndata);

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    function setContractOwner(address _newOwner) internal {
        DiamondStorage storage ds = diamondStorage();
        address previousOwner = ds.contractOwner;
        ds.contractOwner = _newOwner;
        emit OwnershipTransferred(previousOwner, _newOwner);
    }

    function contractOwner() internal view returns (address) {
        return diamondStorage().contractOwner;
    }

    function enforceIsContractOwner() internal view {
        address owner_ = diamondStorage().contractOwner;
        if (msg.sender != owner_) revert NotContractOwner(msg.sender, owner_);
    }

    // ─── Diamond cut ────────────────────────────────────────────────────

    function diamondCut(IDiamondCut.FacetCut[] memory _diamondCut, address _init, bytes memory _calldata) internal {
        for (uint256 i; i < _diamondCut.length; i++) {
            bytes4[] memory selectors = _diamondCut[i].functionSelectors;
            address facet = _diamondCut[i].facetAddress;
            if (selectors.length == 0) revert NoSelectorsInFacet();
            IDiamondCut.FacetCutAction action = _diamondCut[i].action;
            if (action == IDiamondCut.FacetCutAction.Add) {
                addFunctions(facet, selectors);
            } else if (action == IDiamondCut.FacetCutAction.Replace) {
                replaceFunctions(facet, selectors);
            } else if (action == IDiamondCut.FacetCutAction.Remove) {
                removeFunctions(facet, selectors);
            } else {
                revert IncorrectFacetCutAction();
            }
        }
        emit DiamondCut(_diamondCut, _init, _calldata);
        initializeDiamondCut(_init, _calldata);
    }

    function addFunctions(address _facet, bytes4[] memory _selectors) internal {
        if (_facet == address(0)) revert FacetAddressZeroWithSelectors();
        DiamondStorage storage ds = diamondStorage();
        uint96 selectorPosition = uint96(ds.facetFunctionSelectors[_facet].functionSelectors.length);
        if (selectorPosition == 0) addFacet(ds, _facet);
        for (uint256 i; i < _selectors.length; i++) {
            bytes4 selector = _selectors[i];
            if (ds.selectorToFacetAndPosition[selector].facetAddress != address(0)) {
                revert FunctionAlreadyExists(selector);
            }
            addFunction(ds, selector, selectorPosition, _facet);
            selectorPosition++;
        }
    }

    function replaceFunctions(address _facet, bytes4[] memory _selectors) internal {
        if (_facet == address(0)) revert FacetAddressZeroWithSelectors();
        DiamondStorage storage ds = diamondStorage();
        uint96 selectorPosition = uint96(ds.facetFunctionSelectors[_facet].functionSelectors.length);
        if (selectorPosition == 0) addFacet(ds, _facet);
        for (uint256 i; i < _selectors.length; i++) {
            bytes4 selector = _selectors[i];
            address old = ds.selectorToFacetAndPosition[selector].facetAddress;
            if (old == _facet) revert CannotReplaceWithSameFunction(selector);
            removeFunction(ds, old, selector);
            addFunction(ds, selector, selectorPosition, _facet);
            selectorPosition++;
        }
    }

    function removeFunctions(address _facet, bytes4[] memory _selectors) internal {
        DiamondStorage storage ds = diamondStorage();
        // Remove facet address must be address(0).
        if (_facet != address(0)) revert RemoveFacetMustBeZeroAddress(_facet);
        for (uint256 i; i < _selectors.length; i++) {
            bytes4 selector = _selectors[i];
            address old = ds.selectorToFacetAndPosition[selector].facetAddress;
            removeFunction(ds, old, selector);
        }
    }

    function addFacet(DiamondStorage storage ds, address _facet) internal {
        enforceHasContractCode(_facet);
        ds.facetFunctionSelectors[_facet].facetAddressPosition = ds.facetAddresses.length;
        ds.facetAddresses.push(_facet);
    }

    function addFunction(DiamondStorage storage ds, bytes4 _selector, uint96 _position, address _facet) internal {
        ds.selectorToFacetAndPosition[_selector].functionSelectorPosition = _position;
        ds.facetFunctionSelectors[_facet].functionSelectors.push(_selector);
        ds.selectorToFacetAndPosition[_selector].facetAddress = _facet;
    }

    function removeFunction(DiamondStorage storage ds, address _facet, bytes4 _selector) internal {
        if (_facet == address(0)) revert CannotRemoveNonexistentFunction(_selector);
        // An immutable function is defined directly in the diamond (facet == diamond).
        if (_facet == address(this)) revert CannotRemoveImmutableFunction(_selector);

        uint256 selectorPosition = ds.selectorToFacetAndPosition[_selector].functionSelectorPosition;
        uint256 lastSelectorPosition = ds.facetFunctionSelectors[_facet].functionSelectors.length - 1;
        if (selectorPosition != lastSelectorPosition) {
            bytes4 lastSelector = ds.facetFunctionSelectors[_facet].functionSelectors[lastSelectorPosition];
            ds.facetFunctionSelectors[_facet].functionSelectors[selectorPosition] = lastSelector;
            ds.selectorToFacetAndPosition[lastSelector].functionSelectorPosition = uint96(selectorPosition);
        }
        ds.facetFunctionSelectors[_facet].functionSelectors.pop();
        delete ds.selectorToFacetAndPosition[_selector];

        if (lastSelectorPosition == 0) {
            // Remove the facet address from facetAddresses.
            uint256 lastFacetPosition = ds.facetAddresses.length - 1;
            uint256 facetPosition = ds.facetFunctionSelectors[_facet].facetAddressPosition;
            if (facetPosition != lastFacetPosition) {
                address lastFacet = ds.facetAddresses[lastFacetPosition];
                ds.facetAddresses[facetPosition] = lastFacet;
                ds.facetFunctionSelectors[lastFacet].facetAddressPosition = facetPosition;
            }
            ds.facetAddresses.pop();
            delete ds.facetFunctionSelectors[_facet].facetAddressPosition;
        }
    }

    function initializeDiamondCut(address _init, bytes memory _calldata) internal {
        if (_init == address(0)) {
            if (_calldata.length != 0) revert InitAddressZeroWithCalldata();
            return;
        }
        if (_calldata.length == 0) revert InitCalldataEmptyWithAddress();
        enforceHasContractCode(_init);
        (bool success, bytes memory returndata) = _init.delegatecall(_calldata);
        if (!success) {
            if (returndata.length > 0) {
                assembly {
                    revert(add(32, returndata), mload(returndata))
                }
            }
            revert InitReverted(_init, returndata);
        }
    }

    function enforceHasContractCode(address _contract) internal view {
        if (_contract.code.length == 0) revert FacetHasNoCode(_contract);
    }
}
