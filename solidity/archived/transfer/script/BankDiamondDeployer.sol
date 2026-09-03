// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {CommonBase} from "forge-std/Base.sol";

import {Diamond} from "../diamond/Diamond.sol";
import {DiamondCutFacet} from "../diamond/facets/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "../diamond/facets/DiamondLoupeFacet.sol";
import {OwnershipFacet} from "../diamond/facets/OwnershipFacet.sol";
import {IDiamondCut} from "../diamond/interfaces/IDiamondCut.sol";

import {AdminFacet} from "../bank/facets/AdminFacet.sol";
import {VaultFacet} from "../bank/facets/VaultFacet.sol";
import {TransferFacet} from "../bank/facets/TransferFacet.sol";
import {BankInit} from "../bank/BankInit.sol";

/// @title BankDiamondDeployer — assemble a fresh Bank diamond (facets + cut + init).
/// @dev Shared by the deploy script and the test suite so both wire the SAME facet
///      set. Facet selectors are read from the compiled `methodIdentifiers` (keys
///      are canonical signatures → `bytes4(keccak256(sig))`), so adding a function
///      to a facet needs no manual selector list here.
abstract contract BankDiamondDeployer is CommonBase {
    /// @notice Deploy every facet, cut them into a new diamond, and run `BankInit`.
    /// @param owner    Diamond owner (ERC-173).
    /// @param notary   The shared Notary contract (verifies notary attestations).
    /// @param backend  Backend signer address.
    /// @param registry Registry contract (identity resolution).
    function deployBankDiamond(address owner, address notary, address backend, address registry)
        internal
        returns (address diamond)
    {
        DiamondCutFacet cutFacet = new DiamondCutFacet();
        diamond = address(new Diamond(owner, address(cutFacet)));

        DiamondLoupeFacet loupe = new DiamondLoupeFacet();
        OwnershipFacet ownership = new OwnershipFacet();
        AdminFacet admin = new AdminFacet();
        VaultFacet vault = new VaultFacet();
        TransferFacet transferFacet = new TransferFacet();
        BankInit initializer = new BankInit();

        IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](5);
        cut[0] = _facetCut(address(loupe), "DiamondLoupeFacet");
        cut[1] = _facetCut(address(ownership), "OwnershipFacet");
        cut[2] = _facetCut(address(admin), "AdminFacet");
        cut[3] = _facetCut(address(vault), "VaultFacet");
        cut[4] = _facetCut(address(transferFacet), "TransferFacet");

        IDiamondCut(diamond)
            .diamondCut(cut, address(initializer), abi.encodeCall(BankInit.init, (notary, backend, registry)));
    }

    function _facetCut(address facet, string memory name) private view returns (IDiamondCut.FacetCut memory) {
        return IDiamondCut.FacetCut({
            facetAddress: facet, action: IDiamondCut.FacetCutAction.Add, functionSelectors: _selectors(name)
        });
    }

    /// @dev All external selectors of a facet, from its artifact's methodIdentifiers.
    function _selectors(string memory name) private view returns (bytes4[] memory sels) {
        string memory json = vm.readFile(string.concat("out/", name, ".sol/", name, ".json"));
        string[] memory sigs = vm.parseJsonKeys(json, ".methodIdentifiers");
        sels = new bytes4[](sigs.length);
        for (uint256 i = 0; i < sigs.length; i++) {
            sels[i] = bytes4(keccak256(bytes(sigs[i])));
        }
    }
}
