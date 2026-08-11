// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {IDiamondCut} from "../diamond/interfaces/IDiamondCut.sol";
import {IDiamondLoupe} from "../diamond/interfaces/IDiamondLoupe.sol";
import {IERC173} from "../diamond/interfaces/IERC173.sol";
import {AdminFacet} from "../bank/facets/AdminFacet.sol";
import {BankInit} from "../bank/BankInit.sol";
import {NotRegistered, AlreadyRegistered, AlreadyInitialized} from "../bank/BankErrors.sol";

/// @title BankDiamondTest — structural smoke test for the assembled Bank diamond.
/// @dev Verifies the deployer wires facets + runs BankInit, and that every facet
///      stays under the EIP-170 24576-byte limit.
contract BankDiamondTest is Test, BankDiamondDeployer {
    uint256 constant EIP170_LIMIT = 24576;

    address diamond;

    function setUp() public {
        // init only stores the pointers (no calls) → dummy non-zero addrs suffice.
        diamond = deployBankDiamond(address(this), address(1), address(2), address(3));
    }

    /// One-shot: the deploy ran BankInit.init once; a second init via diamondCut
    /// (re-delegatecall) must revert — else a later owner cut would silently
    /// overwrite the trusted-party pointers and duplicate the honor templates.
    function test_bankInit_reinit_reverts() public {
        BankInit reinit = new BankInit();
        IDiamondCut.FacetCut[] memory noCut = new IDiamondCut.FacetCut[](0);
        vm.expectRevert(AlreadyInitialized.selector);
        IDiamondCut(diamond)
            .diamondCut(noCut, address(reinit), abi.encodeCall(BankInit.init, (address(1), address(2), address(3))));
    }

    function test_ownerIsDeployer() public view {
        assertEq(IERC173(diamond).owner(), address(this));
    }

    function test_loupeListsAllFacets() public view {
        // 5 cut facets (loupe, ownership, admin, vault, transfer) + DiamondCutFacet.
        assertEq(IDiamondLoupe(diamond).facetAddresses().length, 6);
    }

    function test_supportsCoreInterfaces() public view {
        assertTrue(IERC165(diamond).supportsInterface(type(IERC165).interfaceId));
        assertTrue(IERC165(diamond).supportsInterface(type(IDiamondCut).interfaceId));
        assertTrue(IERC165(diamond).supportsInterface(type(IDiamondLoupe).interfaceId));
        assertTrue(IERC165(diamond).supportsInterface(type(IERC173).interfaceId));
    }

    function test_initSeededTemplates() public view {
        assertEq(AdminFacet(diamond).platformTemplateCount("api.x.com"), 4);
        assertEq(AdminFacet(diamond).platformTemplateCount("api.github.com"), 2);
    }

    function test_adminRoutingRegisterToken() public {
        AdminFacet(diamond).registerToken("$DEV", address(0xBEEF));
        assertEq(AdminFacet(diamond).resolveToken("$DEV"), address(0xBEEF));
    }

    // ── Token-registry guards (review fixes) ──────────────────────────────

    /// A typo / never-registered name must revert — NOT silently wipe the native
    /// (address(0)) registration.
    function test_unregisterToken_typoDoesNotWipeNative() public {
        AdminFacet(diamond).registerToken("TIA", address(0)); // native
        AdminFacet(diamond).registerToken("USDC", address(0xBEEF));
        vm.expectRevert(NotRegistered.selector);
        AdminFacet(diamond).unregisterToken("USDCC"); // typo
        assertEq(AdminFacet(diamond).tokenName(address(0)), "TIA", "native was wiped");
    }

    /// The native asset is still unregisterable by its own name.
    function test_unregisterNative_byName_ok() public {
        AdminFacet(diamond).registerToken("TIA", address(0));
        AdminFacet(diamond).unregisterToken("TIA");
        assertEq(AdminFacet(diamond).tokenName(address(0)), "");
    }

    /// unregisterToken prunes the address from getRegisteredTokens (no stale entry).
    function test_unregisterToken_prunesRegisteredList() public {
        AdminFacet(diamond).registerToken("USDC", address(0xBEEF));
        AdminFacet(diamond).registerToken("DAI", address(0xCAFE));
        AdminFacet(diamond).unregisterToken("USDC");
        address[] memory toks = AdminFacet(diamond).getRegisteredTokens();
        for (uint256 i = 0; i < toks.length; i++) {
            assertTrue(toks[i] != address(0xBEEF), "unregistered token still listed");
        }
    }

    /// Registering the same address under a second name must revert (no dup entry).
    function test_registerToken_duplicateAddressReverts() public {
        AdminFacet(diamond).registerToken("USDC", address(0xBEEF));
        vm.expectRevert(AlreadyRegistered.selector);
        AdminFacet(diamond).registerToken("USDC2", address(0xBEEF));
    }

    /// A name held by the NATIVE asset can't be hijacked for an ERC-20 (native
    /// keeps address(0) in tokenByName, so the plain name check can't see it).
    function test_registerToken_nativeNameHijack_reverts() public {
        AdminFacet(diamond).registerToken("TIA", address(0)); // native under "TIA"
        vm.expectRevert(AlreadyRegistered.selector);
        AdminFacet(diamond).registerToken("TIA", address(0xBEEF)); // hijack attempt
        // Native still owns the name; the registry stays consistent.
        assertEq(AdminFacet(diamond).tokenName(address(0)), "TIA");
        assertEq(AdminFacet(diamond).resolveToken("TIA"), address(0));
    }

    /// Case-insensitive: webTransferV2 resolves the native asset case-insensitively,
    /// so a case variant of the native name ("TIA" → "tia") can't be hijacked for an
    /// ERC-20 either — else the registry desyncs and a by-name honor settles wrong.
    function test_registerToken_nativeNameHijack_caseVariant_reverts() public {
        AdminFacet(diamond).registerToken("TIA", address(0)); // native under "TIA"
        vm.expectRevert(AlreadyRegistered.selector);
        AdminFacet(diamond).registerToken("tia", address(0xBEEF)); // case-variant hijack
        assertEq(AdminFacet(diamond).tokenName(address(0)), "TIA");
    }

    /// @notice Every deployed facet must fit the EIP-170 contract-size limit.
    function test_facetsUnderEip170() public view {
        address[] memory facets = IDiamondLoupe(diamond).facetAddresses();
        for (uint256 i = 0; i < facets.length; i++) {
            assertLe(facets[i].code.length, EIP170_LIMIT, "facet exceeds EIP-170 24KB");
        }
    }
}
