// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Registry} from "../../login/Registry.sol";
import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {ResourceInfo, SenderInfo, BackendSig, NotaryTlsProof} from "../bank/BankTypes.sol";
import {EnforcedPause, InsufficientBalance} from "../bank/BankErrors.sol";

/// @notice Pausable emergency-stop / migration-cutover gate on Registry + Bank.
///         Proves: pause/unpause are owner-only; a gated entrypoint reverts
///         `EnforcedPause` while paused and resumes its normal behaviour after
///         unpause; admin/owner functions stay callable while paused.
contract PausableFlowTest is Test, BankDiamondDeployer {
    Registry registry;
    IBank bank;
    address owner = address(this);
    address notOwner = address(0xBEEF);

    function setUp() public {
        Registry rImpl = new Registry();
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    // notary, backend, walletFactory, owner — all must be non-zero.
                    abi.encodeCall(Registry.initialize, (address(0x11), address(0x12), address(0x13), owner))
                )
            )
        );
        // real registry so withdraw's lazy _migrate (getUserIds) is a no-op, not a call to a codeless addr.
        bank = IBank(deployBankDiamond(owner, address(0x21), address(0x22), address(registry)));
    }

    // ── access control ─────────────────────────────────────────────

    function test_pause_onlyOwner() public {
        vm.prank(notOwner);
        vm.expectRevert();
        registry.pause();

        vm.prank(notOwner);
        vm.expectRevert();
        bank.pause();
    }

    function test_unpause_onlyOwner() public {
        registry.pause();
        bank.pause();
        vm.prank(notOwner);
        vm.expectRevert();
        registry.unpause();
        vm.prank(notOwner);
        vm.expectRevert();
        bank.unpause();
    }

    // ── Registry: gated when paused, normal after unpause ──────────

    function test_registry_pausedBlocksRegistration() public {
        registry.pause();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        registry.register_session_zk("api.x.com", "");

        // Gate lifted → reaches the real path (no verifier configured).
        registry.unpause();
        vm.expectRevert(Registry.ZkVerifierNotSet.selector);
        registry.register_session_zk("api.x.com", "");
    }

    // ── Bank: gated when paused, normal after unpause ──────────────

    function test_bank_pausedBlocksWithdraw() public {
        bank.pause();
        vm.expectRevert(EnforcedPause.selector);
        bank.withdraw(owner, address(0), 1);

        // Gate lifted → reaches the real path (no balance to withdraw).
        bank.unpause();
        vm.expectRevert(InsufficientBalance.selector);
        bank.withdraw(owner, address(0), 1);
    }

    /// Both webTransferV2 overloads move user funds, so a pause must block them
    /// before any proof work. whenNotPaused runs ahead of proof validation, so a
    /// paused call reverts EnforcedPause even with empty proof structs.
    function test_bank_pausedBlocksWebTransfer() public {
        ResourceInfo memory resource = ResourceInfo("api.x.com", "", "", "");
        NotaryTlsProof memory tls = NotaryTlsProof(
            "",
            bytes32(0),
            bytes32(0),
            bytes32(0),
            "",
            bytes32(0),
            0,
            new bytes32[](0),
            new bytes32[](0),
            new bytes32[](0),
            new bytes32[](0),
            new bytes32[](0),
            new bytes32[](0),
            "",
            new bytes32[](0),
            "",
            new bytes32[](0),
            ""
        );
        BackendSig memory sig = BackendSig("", 0);

        bank.pause();

        // token-by-name overload
        vm.expectRevert(EnforcedPause.selector);
        bank.webTransferV2(
            resource, SenderInfo("author", "", ""), "", tls, sig, "bob", "id_bob", "$X", "1", 1, "https://x.com/p/1"
        );

        // token-by-address overload
        vm.expectRevert(EnforcedPause.selector);
        bank.webTransferV2(
            resource,
            SenderInfo("author", "", ""),
            "",
            tls,
            sig,
            "bob",
            "id_bob",
            address(0xCAFE),
            "1",
            1,
            "https://x.com/p/1"
        );
    }

    // ── admin/owner fns stay callable while paused ────────────────

    function test_adminWorksWhilePaused() public {
        registry.pause();
        bank.pause();

        // Neither carries whenNotPaused — must still work (so migrate/rotate
        // can run during a cutover pause).
        registry.setNotary(address(0x99));
        bank.registerToken("$X", address(0xCAFE));

        assertEq(registry.notary(), address(0x99), "admin setNotary blocked by pause");
        assertTrue(registry.paused(), "registry should be paused");
        assertTrue(bank.paused(), "bank should still be paused");
        // A whenNotPaused entrypoint (withdraw) still reverts EnforcedPause.
        vm.expectRevert(EnforcedPause.selector);
        bank.withdraw(owner, address(0), 1);
    }
}
