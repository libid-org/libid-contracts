// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {WalletFactory} from "../WalletFactory.sol";
import {WebWallet} from "../WebWallet.sol";

contract WalletFactoryTest is Test {
    WalletFactory factory;
    WebWallet walletImpl;

    address owner = makeAddr("owner");
    address registry = makeAddr("registry");
    address stranger = makeAddr("stranger");

    bytes32 constant IDENTITY_ALICE = keccak256(abi.encode("tiktok", "alice"));

    function setUp() public {
        walletImpl = new WebWallet();
        WalletFactory fImpl = new WalletFactory();
        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl), abi.encodeCall(WalletFactory.initialize, (owner, address(walletImpl), registry))
                )
            )
        );
    }

    function test_initialize_setsBeacon() public view {
        assertTrue(address(factory.beacon()) != address(0));
    }

    function test_initialize_setsRegistry() public view {
        assertEq(factory.registry(), registry);
    }

    function test_deployWebWallet_onlyRegistry() public {
        vm.expectRevert(WalletFactory.OnlyRegistry.selector);
        factory.deploy_web_wallet("tiktok", "alice", "alice_id");
    }

    function test_deployWebWallet_success() public {
        vm.prank(registry);
        address wallet = factory.deploy_web_wallet("tiktok", "alice", "alice_id");

        assertTrue(wallet != address(0));
        assertTrue(factory.isRegisteredWallet(wallet));

        WebWallet w = WebWallet(payable(wallet));
        assertEq(w.registry(), registry);
        assertEq(w.identityCount(), 0); // identity tracked only after session registration
        assertEq(w.threshold(), 1);
    }

    function test_deployWebWallet_multipleWalletsPerIdentity() public {
        vm.startPrank(registry);
        address w1 = factory.deploy_web_wallet("tiktok", "alice", "alice_id");
        address w2 = factory.deploy_web_wallet("tiktok", "alice", "alice_id");
        vm.stopPrank();

        assertTrue(w1 != w2);
        assertTrue(factory.isRegisteredWallet(w1));
        assertTrue(factory.isRegisteredWallet(w2));
    }

    function test_upgradeWalletImplementation_onlyOwner() public {
        WebWallet newImpl = new WebWallet();
        vm.expectRevert();
        factory.upgradeWalletImplementation(address(newImpl));
    }

    function test_upgradeWalletImplementation_success() public {
        WebWallet newImpl = new WebWallet();
        vm.prank(owner);
        factory.upgradeWalletImplementation(address(newImpl));
        assertEq(factory.beacon().implementation(), address(newImpl));
    }

    function test_setRegistry_onlyOwner() public {
        vm.expectRevert();
        factory.setRegistry(makeAddr("newRegistry"));
    }

    function test_setRegistry_success() public {
        address newRegistry = makeAddr("newRegistry");
        vm.prank(owner);
        factory.setRegistry(newRegistry);
        assertEq(factory.registry(), newRegistry);
    }
}
