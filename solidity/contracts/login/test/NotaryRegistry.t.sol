// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NotaryRegistry} from "../NotaryRegistry.sol";

contract NotaryRegistryTest is Test {
    NotaryRegistry registry;

    address owner = makeAddr("owner");
    address notary1 = makeAddr("notary1");
    address notary2 = makeAddr("notary2");
    address stranger = makeAddr("stranger");

    event NotaryAdded(address indexed notary);
    event NotaryRemoved(address indexed notary);

    function setUp() public {
        NotaryRegistry impl = new NotaryRegistry();
        registry = NotaryRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(NotaryRegistry.initialize, (owner, notary1))))
        );
    }

    // ─── initialize ─────────────────────────────────────────────────

    function test_init_ownerSet() public view {
        assertEq(registry.owner(), owner);
    }

    function test_init_initialNotaryRegistered() public view {
        assertTrue(registry.isNotary(notary1));
    }

    function test_init_strangerNotRegistered() public view {
        assertFalse(registry.isNotary(notary2));
    }

    // ─── addNotary ──────────────────────────────────────────────────

    function test_addNotary_registersAndEmits() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit NotaryAdded(notary2);
        registry.addNotary(notary2);
        assertTrue(registry.isNotary(notary2));
    }

    function test_addNotary_revertsIfNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert();
        registry.addNotary(notary2);
    }

    function test_addNotary_revertsIfZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(NotaryRegistry.ZeroAddress.selector);
        registry.addNotary(address(0));
    }

    function test_addNotary_revertsIfAlreadyRegistered() public {
        vm.prank(owner);
        vm.expectRevert(NotaryRegistry.NotaryAlreadyRegistered.selector);
        registry.addNotary(notary1);
    }

    function test_addNotary_multipleNotaries() public {
        vm.startPrank(owner);
        registry.addNotary(notary2);
        address notary3 = makeAddr("notary3");
        registry.addNotary(notary3);
        vm.stopPrank();
        assertTrue(registry.isNotary(notary1));
        assertTrue(registry.isNotary(notary2));
        assertTrue(registry.isNotary(notary3));
    }

    // ─── removeNotary ───────────────────────────────────────────────

    function test_removeNotary_deregistersAndEmits() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit NotaryRemoved(notary1);
        registry.removeNotary(notary1);
        assertFalse(registry.isNotary(notary1));
    }

    function test_removeNotary_revertsIfNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert();
        registry.removeNotary(notary1);
    }

    function test_removeNotary_revertsIfNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert(NotaryRegistry.NotaryNotRegistered.selector);
        registry.removeNotary(notary2);
    }

    function test_removeNotary_canReAddAfterRemoval() public {
        vm.startPrank(owner);
        registry.removeNotary(notary1);
        assertFalse(registry.isNotary(notary1));
        registry.addNotary(notary1);
        assertTrue(registry.isNotary(notary1));
        vm.stopPrank();
    }

    // ─── Ownable2Step ───────────────────────────────────────────────

    function test_ownership_twoStepTransfer() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        registry.transferOwnership(newOwner);
        // Not yet transferred
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), newOwner);

        vm.prank(newOwner);
        registry.acceptOwnership();
        assertEq(registry.owner(), newOwner);
    }

    function test_ownership_pendingCannotActAsOwner() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        registry.transferOwnership(newOwner);

        vm.prank(newOwner);
        vm.expectRevert();
        registry.addNotary(notary2);
    }

    // ─── UUPS upgrade ───────────────────────────────────────────────

    function test_upgrade_revertsIfNotOwner() public {
        NotaryRegistry newImpl = new NotaryRegistry();
        vm.prank(stranger);
        vm.expectRevert();
        registry.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgrade_byOwner_preservesState() public {
        NotaryRegistry newImpl = new NotaryRegistry();
        vm.prank(owner);
        registry.upgradeToAndCall(address(newImpl), "");
        // State should survive upgrade
        assertTrue(registry.isNotary(notary1));
        assertEq(registry.owner(), owner);
    }
}
