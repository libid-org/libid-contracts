// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Edge-case and boundary tests for the refactored contracts.

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {WebWallet} from "../../login/WebWallet.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {
    ZeroAmount,
    InsufficientBalance,
    TokenNotRegistered,
    ZeroAddress,
    AlreadyRegistered,
    EmptyName,
    NotRegistered,
    NativeSentWithErc20,
    InsufficientAllowance
} from "../bank/BankErrors.sol";
import {Notary} from "../../notary/Notary.sol";
import {deployNotary} from "../../notary/test/DeployNotary.sol";

// ─── helpers ────────────────────────────────────────────────────────────────

contract MockToken is ERC20 {
    constructor(string memory sym) ERC20(sym, sym) {}

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

/// @dev Mock Registry for edge-case tests. Supports resolve and getHandles.
contract MockRegistryForEdge {
    struct HandleEntry {
        string platform;
        string handle;
    }

    mapping(string => mapping(string => address)) private _resolve;
    mapping(string => mapping(string => string)) private _hint;
    mapping(address => HandleEntry[]) private _handles;

    function setResolve(string calldata platform, string calldata handle, address wallet) external {
        _resolve[platform][handle] = wallet;
        _handles[wallet].push(HandleEntry(platform, handle));
    }

    function setHint(string calldata platform, string calldata handle, string calldata id) external {
        _hint[platform][handle] = id;
    }

    function resolve(string calldata platform, string calldata handle) external view returns (address) {
        return _resolve[platform][handle];
    }

    // This mock keys identity by userId == handle, so resolveById mirrors resolve.
    function resolveById(string calldata platform, string calldata id) external view returns (address) {
        return _resolve[platform][id];
    }

    // Unbound by default; setHint simulates a handle pointing to a specific id.
    function handleHint(string calldata platform, string calldata handle) external view returns (string memory) {
        return _hint[platform][handle];
    }

    function getHandles(address wallet) external view returns (string[] memory platforms, string[] memory handles) {
        HandleEntry[] storage entries = _handles[wallet];
        uint256 len = entries.length;
        platforms = new string[](len);
        handles = new string[](len);
        for (uint256 i = 0; i < len; i++) {
            platforms[i] = entries[i].platform;
            handles[i] = entries[i].handle;
        }
    }

    // This mock keys deposits/transfers by userId == handle, so report the
    // handle as the immutable userId — lets _migrate sweep the id-escrow slot.
    function getUserIds(address wallet) external view returns (string[] memory platforms, string[] memory userIds) {
        HandleEntry[] storage entries = _handles[wallet];
        uint256 len = entries.length;
        platforms = new string[](len);
        userIds = new string[](len);
        for (uint256 i = 0; i < len; i++) {
            platforms[i] = entries[i].platform;
            userIds[i] = entries[i].handle;
        }
    }

    // This mock keys identity by userId == handle, so pass the handle as userId.
    function registerSession(WebWallet wallet, string calldata platform, string calldata handle, address sessionAddr)
        external
    {
        wallet.register_session(platform, handle, handle, sessionAddr);
    }

    fallback() external payable {}
    receive() external payable {}
}

// ─── base setup ─────────────────────────────────────────────────────────────

abstract contract EdgeBase is Test, BankDiamondDeployer {
    address govOwner = makeAddr("govOwner");
    address depositor = makeAddr("depositor");
    MockRegistryForEdge mockRegistryContract;
    address mockRegistry;

    uint256 notaryPk = 0xBE01;
    uint256 backendPk = 0xBE02;
    address notaryAddr;
    address backendAddr;

    uint256 alicePk = 0xBE10;
    address aliceSessionAddr;

    uint256 bobPk = 0xBE20;
    address bobSessionAddr;

    function setUp() public virtual {
        notaryAddr = vm.addr(notaryPk);
        backendAddr = vm.addr(backendPk);

        aliceSessionAddr = vm.addr(alicePk);
        bobSessionAddr = vm.addr(bobPk);

        mockRegistryContract = new MockRegistryForEdge();
        mockRegistry = address(mockRegistryContract);

        vm.warp(1_000_000);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Deploy a WebWallet with a session registered via mock registry.
    function _deployWalletWithSession(string memory platform, string memory handle, uint256 sessionPk_)
        internal
        returns (WebWallet wallet)
    {
        address sAddr = vm.addr(sessionPk_);
        wallet = new WebWallet();
        wallet.initialize(mockRegistry, address(0), platform, handle);
        mockRegistryContract.registerSession(wallet, platform, handle, sAddr);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. WebWallet edge cases
// ═══════════════════════════════════════════════════════════════════════════

contract WebWalletEdgeCases is EdgeBase {
    WebWallet wallet;

    function setUp() public override {
        super.setUp();
        wallet = _deployWalletWithSession("tiktok", "alice", alicePk);
    }

    function test_registerSession_revertsIfNotRegistry() public {
        vm.expectRevert(WebWallet.OnlyRegistry.selector);
        wallet.register_session("tiktok", "alice", "alice", aliceSessionAddr);
    }

    function test_execute_incrementsNonce() public {
        assertEq(wallet.nonce(), 0);

        bytes memory data = hex"";
        bytes32 digest = keccak256(
            abi.encode(mockRegistry, uint256(0), keccak256(data), uint256(0), block.chainid, address(wallet))
        );

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(alicePk, digest);

        wallet.execute(mockRegistry, 0, data, sigs);
        assertEq(wallet.nonce(), 1);
    }

    function test_execute_samePairCountsOnce() public {
        mockRegistryContract.registerSession(wallet, "tiktok", "alice", bobSessionAddr);

        bytes memory data = hex"";
        bytes32 digest = keccak256(
            abi.encode(mockRegistry, uint256(0), keccak256(data), uint256(0), block.chainid, address(wallet))
        );

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(alicePk, digest);
        sigs[1] = _sign(bobPk, digest);

        wallet.execute(mockRegistry, 0, data, sigs);
        assertEq(wallet.nonce(), 1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Bank edge cases
// ═══════════════════════════════════════════════════════════════════════════

contract BankEdgeCases is EdgeBase {
    // Mirrors AdminFacet's RegistrySet — for expectEmit (no registry() getter on the diamond).
    event RegistrySet(address indexed oldRegistry, address indexed newRegistry);

    IBank bank;
    MockToken usdc;
    MockToken dai;
    WebWallet aliceWallet;

    function setUp() public override {
        super.setUp();

        usdc = new MockToken("USDC");
        dai = new MockToken("DAI");

        aliceWallet = _deployWalletWithSession("tiktok", "alice", alicePk);
        mockRegistryContract.setResolve("tiktok", "alice", address(aliceWallet));

        {
            Notary notaryReg = deployNotary(address(this), notaryAddr);
            bank = IBank(deployBankDiamond(address(this), address(notaryReg), backendAddr, mockRegistry));
        }
        bank.registerToken("USDC", address(usdc));
        bank.registerToken("DAI", address(dai));

        usdc.mint(depositor, 1_000e18);
        dai.mint(depositor, 1_000e18);
        vm.startPrank(depositor);
        usdc.approve(address(bank), type(uint256).max);
        dai.approve(address(bank), type(uint256).max);
        vm.stopPrank();
    }

    function _deposit(address tkn, uint256 amt) internal {
        vm.prank(depositor);
        bank.deposit("tiktok", "alice", "alice", tkn, amt);
    }

    function _executeWithdraw(address tkn, uint256 amt) internal {
        bytes memory withdrawData = abi.encodeCall(IBank.withdraw, (address(aliceWallet), tkn, amt));

        uint256 currentNonce = aliceWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(bank), uint256(0), keccak256(withdrawData), currentNonce, block.chainid, address(aliceWallet)
            )
        );

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(alicePk, digest);

        aliceWallet.execute(address(bank), 0, withdrawData, sigs);
    }

    // ── Deposit routing ────────────────────────────────────────────

    function test_deposit_registeredGoesToRegisteredBalances() public {
        _deposit(address(usdc), 100e18);
        // Alice is registered, so should be in registeredBalances
        assertEq(bank.registeredBalances(address(aliceWallet), address(usdc)), 100e18);
    }

    function test_deposit_unregisteredGoesToUnregisteredBalances() public {
        vm.prank(depositor);
        bank.deposit("tiktok", "bob", "bob", address(usdc), 100e18);
        // Bob is not registered — id-escrow is domain-separated by "id:v1"
        bytes32 key = keccak256(abi.encode("id:v1", "tiktok", "bob"));
        assertEq(bank.unregisteredBalances(key, address(usdc)), 100e18);
    }

    // Recycled handle (hint id != provided id): escrow under the id, don't credit prior owner.
    function test_deposit_recycledHandle_escrowsUnderIdNotPriorOwner() public {
        mockRegistryContract.setHint("tiktok", "alice", "111");
        vm.prank(depositor);
        bank.deposit("tiktok", "alice", "999", address(usdc), 100e18);

        assertEq(bank.registeredBalances(address(aliceWallet), address(usdc)), 0);
        bytes32 key = keccak256(abi.encode("id:v1", "tiktok", "999"));
        assertEq(bank.unregisteredBalances(key, address(usdc)), 100e18);
    }

    // Matching hint (same id) still resolves the registered wallet.
    function test_deposit_matchingHint_creditsRegisteredWallet() public {
        mockRegistryContract.setHint("tiktok", "alice", "alice");
        vm.prank(depositor);
        bank.deposit("tiktok", "alice", "alice", address(usdc), 100e18);
        assertEq(bank.registeredBalances(address(aliceWallet), address(usdc)), 100e18);
    }

    function test_deposit_revertsOnZeroAmount() public {
        vm.prank(depositor);
        vm.expectRevert(ZeroAmount.selector);
        bank.deposit("tiktok", "alice", "alice", address(usdc), 0);
    }

    // ── Withdraw ────────────────────────────────────────────────────

    function test_withdraw_success() public {
        _deposit(address(usdc), 100e18);
        _executeWithdraw(address(usdc), 50e18);
        assertEq(bank.registeredBalances(address(aliceWallet), address(usdc)), 50e18);
        assertEq(usdc.balanceOf(address(aliceWallet)), 50e18);
    }

    function test_withdraw_revertsIfNotRegisteredWallet() public {
        _deposit(address(usdc), 100e18);
        address anyone = makeAddr("anyone");
        vm.prank(anyone);
        vm.expectRevert(InsufficientBalance.selector);
        bank.withdraw(anyone, address(usdc), 100e18);
    }

    function test_withdraw_revertsOnOverdraft() public {
        _deposit(address(usdc), 50e18);

        bytes memory withdrawData = abi.encodeCall(IBank.withdraw, (address(aliceWallet), address(usdc), 100e18));
        uint256 currentNonce = aliceWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(bank), uint256(0), keccak256(withdrawData), currentNonce, block.chainid, address(aliceWallet)
            )
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(alicePk, digest);

        vm.expectRevert(); // InsufficientBalance wrapped in ExecutionFailed
        aliceWallet.execute(address(bank), 0, withdrawData, sigs);
    }

    // ── Lazy migration ──────────────────────────────────────────────

    function test_withdraw_migratesUnregisteredFirst() public {
        // Deposit as unregistered first (before alice is "known" for this key)
        // We'll simulate: put tokens in unregisteredBalances for alice's handle
        // by depositing for "tiktok"/"alice" when she's NOT resolved yet

        // Create a new bank where alice is not yet resolved
        MockRegistryForEdge freshRegistry = new MockRegistryForEdge();
        IBank freshBank;
        {
            Notary notaryReg2 = deployNotary(address(this), notaryAddr);
            freshBank =
                IBank(deployBankDiamond(address(this), address(notaryReg2), backendAddr, address(freshRegistry)));
        }
        freshBank.registerToken("USDC", address(usdc));

        // Deposit while alice is unregistered
        vm.prank(depositor);
        usdc.approve(address(freshBank), type(uint256).max);
        vm.prank(depositor);
        freshBank.deposit("tiktok", "alice", "alice", address(usdc), 100e18);

        bytes32 key = keccak256(abi.encode("id:v1", "tiktok", "alice"));
        assertEq(freshBank.unregisteredBalances(key, address(usdc)), 100e18);

        // Now register alice
        freshRegistry.setResolve("tiktok", "alice", address(aliceWallet));

        // Withdraw should migrate first
        bytes memory withdrawData = abi.encodeCall(IBank.withdraw, (address(aliceWallet), address(usdc), 60e18));
        uint256 currentNonce = aliceWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(freshBank),
                uint256(0),
                keccak256(withdrawData),
                currentNonce,
                block.chainid,
                address(aliceWallet)
            )
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(alicePk, digest);
        aliceWallet.execute(address(freshBank), 0, withdrawData, sigs);

        // Unregistered should be zero, registered should have remainder
        assertEq(freshBank.unregisteredBalances(key, address(usdc)), 0);
        assertEq(freshBank.registeredBalances(address(aliceWallet), address(usdc)), 40e18);
    }

    // ── balanceOf ───────────────────────────────────────────────────

    function test_balanceOf_handleVersion_registered() public {
        _deposit(address(usdc), 100e18);
        assertEq(bank.balanceOf("tiktok", "alice", "alice", address(usdc)), 100e18);
    }

    function test_balanceOf_handleVersion_unregistered() public {
        vm.prank(depositor);
        bank.deposit("tiktok", "bob", "bob", address(usdc), 100e18);
        assertEq(bank.balanceOf("tiktok", "bob", "bob", address(usdc)), 100e18);
    }

    function test_balanceOf_walletVersion() public {
        _deposit(address(usdc), 100e18);
        assertEq(bank.balanceOf(address(aliceWallet), address(usdc)), 100e18);
    }

    function test_balanceOf_returnsZeroForUnknownIdentity() public view {
        assertEq(bank.balanceOf("discord", "nobody", "nobody", address(usdc)), 0);
    }

    // ── Multiple tokens ─────────────────────────────────────────────

    // ── deposit with unregistered token ────────────────────────────

    function test_deposit_revertsWithUnregisteredToken() public {
        MockToken rando = new MockToken("RANDO");
        rando.mint(depositor, 100e18);
        vm.prank(depositor);
        rando.approve(address(bank), 100e18);
        vm.prank(depositor);
        vm.expectRevert(TokenNotRegistered.selector);
        bank.deposit("tiktok", "alice", "alice", address(rando), 100e18);
    }

    // ── withdraw zero amount ────────────────────────────────────────

    function test_withdraw_revertsOnZeroAmount() public {
        _deposit(address(usdc), 100e18);
        bytes memory withdrawData = abi.encodeCall(IBank.withdraw, (address(aliceWallet), address(usdc), 0));
        uint256 currentNonce = aliceWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(bank), uint256(0), keccak256(withdrawData), currentNonce, block.chainid, address(aliceWallet)
            )
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(alicePk, digest);
        vm.expectRevert(); // ZeroAmount wrapped in ExecutionFailed
        aliceWallet.execute(address(bank), 0, withdrawData, sigs);
    }

    // ── setRegistry ─────────────────────────────────────────────────

    function test_setRegistry_onlyOwner() public {
        address newRegistry = makeAddr("newReg");
        // Non-owner fails
        vm.prank(depositor);
        vm.expectRevert();
        bank.setRegistry(newRegistry);
    }

    function test_setRegistry_updatesRegistry() public {
        address newRegistry = makeAddr("newReg");
        vm.expectEmit(true, true, false, true, address(bank));
        emit RegistrySet(mockRegistry, newRegistry);
        bank.setRegistry(newRegistry);
        assertEq(bank.registry(), newRegistry);
    }

    function test_setRegistry_revertsZeroAddress() public {
        vm.expectRevert(ZeroAddress.selector);
        bank.setRegistry(address(0));
    }

    // ── registerToken / unregisterToken ──────────────────────────────

    function test_registerToken_revertsIfNotOwner() public {
        vm.prank(depositor);
        vm.expectRevert();
        bank.registerToken("X", address(1));
    }

    function test_registerToken_revertsIfAlreadyRegistered() public {
        vm.expectRevert(AlreadyRegistered.selector);
        bank.registerToken("USDC", address(usdc));
    }

    function test_registerToken_nativeAssetAllowed() public {
        // address(0) is now allowed as native asset.
        bank.registerToken("ETH", address(0));
        assertEq(bank.tokenName(address(0)), "ETH");
    }

    function test_registerToken_revertsEmptyName() public {
        vm.expectRevert(EmptyName.selector);
        bank.registerToken("", address(1));
    }

    function test_unregisterToken_success() public {
        bank.unregisterToken("USDC");
        assertEq(bank.resolveToken("USDC"), address(0));
        assertEq(bank.tokenName(address(usdc)), "");
    }

    function test_unregisterToken_revertsIfNotRegistered() public {
        vm.expectRevert(NotRegistered.selector);
        bank.unregisterToken("NONEXISTENT");
    }

    function test_unregisterToken_revertsIfNotOwner() public {
        vm.prank(depositor);
        vm.expectRevert();
        bank.unregisterToken("USDC");
    }

    function test_deposit_revertsAfterUnregister() public {
        bank.unregisterToken("USDC");
        vm.prank(depositor);
        vm.expectRevert(TokenNotRegistered.selector);
        bank.deposit("tiktok", "alice", "alice", address(usdc), 100e18);
    }

    // ── resolveToken ────────────────────────────────────────────────

    function test_resolveToken_returnsCorrectAddress() public view {
        assertEq(bank.resolveToken("USDC"), address(usdc));
    }

    function test_resolveToken_returnsZeroForUnknown() public view {
        assertEq(bank.resolveToken("NOPE"), address(0));
    }

    // ── balanceOf with multiple linked handles ──────────────────────

    function test_balanceOf_aggregatesAcrossHandles() public {
        // Setup bob wallet with second handle
        WebWallet bobWallet = _deployWalletWithSession("tiktok", "bob", bobPk);
        mockRegistryContract.setResolve("tiktok", "bob", address(bobWallet));

        // Add a second handle for bob
        mockRegistryContract.setResolve("github", "bob_gh", address(bobWallet));
        mockRegistryContract.registerSession(bobWallet, "github", "bob_gh", makeAddr("bobGhSession"));

        // Deposit to both handles
        vm.prank(depositor);
        bank.deposit("tiktok", "bob", "bob", address(usdc), 100e18);

        // Deposit to unregistered second handle directly
        // Since mockRegistry already maps github/bob_gh -> bobWallet, deposit goes to registered
        vm.prank(depositor);
        bank.deposit("github", "bob_gh", "bob_gh", address(usdc), 200e18);

        // Total should aggregate
        assertEq(bank.balanceOf(address(bobWallet), address(usdc)), 300e18);
    }

    // ── Multiple tokens ─────────────────────────────────────────────

    function test_multipleTokens_independentBalances() public {
        vm.prank(depositor);
        bank.deposit("tiktok", "alice", "alice", address(usdc), 300e18);
        vm.prank(depositor);
        bank.deposit("tiktok", "alice", "alice", address(dai), 500e18);

        assertEq(bank.registeredBalances(address(aliceWallet), address(usdc)), 300e18);
        assertEq(bank.registeredBalances(address(aliceWallet), address(dai)), 500e18);

        _executeWithdraw(address(usdc), 100e18);

        assertEq(bank.registeredBalances(address(aliceWallet), address(usdc)), 200e18);
        assertEq(bank.registeredBalances(address(aliceWallet), address(dai)), 500e18);
    }

    // ═══════════════════════════════════════════════════════════════
    //  MUTATION-GUARD NEGATIVE TESTS
    // ═══════════════════════════════════════════════════════════════

    // 14. Depositing an ERC20 while also sending native (msg.value > 0) →
    //     NativeSentWithErc20. depositor is approved, so removing the guard would
    //     succeed (pull the ERC20 anyway), killing the mutant.
    function test_NativeSentWithErc20_reverts() public {
        vm.deal(depositor, 1 ether);
        vm.prank(depositor);
        vm.expectRevert(NativeSentWithErc20.selector);
        bank.deposit{value: 1}("tiktok", "alice", "alice", address(usdc), 100e18);
    }

    // 15. Depositing an ERC20 without approving the diamond → the allowance guard
    //     fires with the custom InsufficientAllowance (removing it yields the OZ
    //     ERC20 transfer error).
    function test_InsufficientAllowance_deposit_reverts() public {
        address poor = makeAddr("poor");
        usdc.mint(poor, 100e18); // holds tokens but grants no allowance
        // Parametrized error → match on the selector prefix (removing the guard
        // yields the OZ ERC20 allowance error, a different selector).
        vm.prank(poor);
        vm.expectPartialRevert(InsufficientAllowance.selector);
        bank.deposit("tiktok", "alice", "alice", address(usdc), 100e18);
    }
}
