// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../../login/Registry.sol";
import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {SenderNotRegistered, ZeroAmount, InsufficientBalance, InsufficientAllowance} from "../bank/BankErrors.sol";
import {Notary} from "../../notary/Notary.sol";
import {deployNotary} from "../../notary/test/DeployNotary.sol";
import {WalletFactory} from "../../login/WalletFactory.sol";
import {WebWallet} from "../../login/WebWallet.sol";
import {MockERC20} from "../MockERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TransferWithinTest is Test, BankDiamondDeployer {
    uint256 constant NOTARY_KEY = uint256(keccak256("notary"));
    uint256 constant BACKEND_KEY = uint256(keccak256("backend"));

    address NOTARY;
    address BACKEND;

    Registry registry;
    IBank bank;
    WalletFactory factory;
    MockERC20 token;

    uint256 constant ALICE_PK = 0xA001;
    uint256 constant BOB_PK = 0xB001;
    uint256 constant CHARLIE_PK = 0xC001;

    function setUp() public {
        NOTARY = vm.addr(NOTARY_KEY);
        BACKEND = vm.addr(BACKEND_KEY);

        WebWallet walletImpl = new WebWallet();
        Registry rImpl = new Registry();
        WalletFactory fImpl = new WalletFactory();

        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl),
                    abi.encodeCall(WalletFactory.initialize, (address(this), address(walletImpl), address(1)))
                )
            )
        );

        Notary notaryReg = deployNotary(address(this), NOTARY);
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(Registry.initialize, (address(notaryReg), BACKEND, address(factory), address(this)))
                )
            )
        );

        factory.setRegistry(address(registry));
        bank = IBank(deployBankDiamond(address(this), address(notaryReg), BACKEND, address(registry)));
        token = new MockERC20("Test", "TST");
        bank.registerToken("TST", address(token));

        // Register platforms used in tests (X-style quoted id binding).
        registry.setPlatform("api.x.com", "api.test.com/endpoint", '"username":"', '"id":"', '"');
        registry.setPlatform("api.github.com", "api.test.com/endpoint", '"username":"', '"id":"', '"');

        vm.warp(1_000_000);
    }

    /// Deterministic immutable id for a handle (escrow keyed by id).
    function _idFor(string memory handle) internal pure returns (string memory) {
        return string(abi.encodePacked("id_", handle));
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// Map platform shortname to API domain for Registry registration.
    function _domain(string memory platform) internal pure returns (string memory) {
        if (keccak256(bytes(platform)) == keccak256("x")) return "api.x.com";
        if (keccak256(bytes(platform)) == keccak256("github")) return "api.github.com";
        return platform;
    }

    function _walletFor(string memory platform, string memory handle, uint256 pk) internal returns (WebWallet) {
        string memory domain = _domain(platform);
        string memory userId = _idFor(handle);
        address sessionAddr = vm.addr(pk);
        Registry.FullTlsProof memory proof = _buildRegistryProof(
            domain, handle, userId, "api.test.com/endpoint", '"username":"', sessionAddr, block.timestamp
        );
        registry.register_session(proof, domain, handle, userId, "api.test.com/endpoint");
        return WebWallet(payable(registry.resolve(domain, handle)));
    }

    function _fund(string memory platform, string memory handle, uint256 amount) internal {
        token.mint(address(this), amount);
        token.approve(address(bank), amount);
        bank.deposit(_domain(platform), handle, _idFor(handle), address(token), amount);
    }

    function _fundWallet(WebWallet wallet, uint256 amount) internal {
        token.mint(address(wallet), amount);
    }

    function _execute(WebWallet wallet, address target, bytes memory data, uint256 pk) internal {
        uint256 currentNonce = wallet.nonce();
        bytes32 digest =
            keccak256(abi.encode(target, uint256(0), keccak256(data), currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(pk, digest);
        wallet.execute(target, 0, data, sigs);
    }

    function _executeBatch(
        WebWallet wallet,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory datas,
        uint256 pk
    ) internal {
        uint256 currentNonce = wallet.nonce();
        bytes32 dataHashes = keccak256(abi.encode(datas));
        bytes32 digest =
            keccak256(abi.encode(targets, values, dataHashes, currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(pk, digest);
        wallet.executeBatch(targets, values, datas, sigs);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _leaf(string memory prefix, bytes memory value) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
    }

    function _h(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    // 4-leaf tree (D, U, E, Id) — id bound via the quoted "id":"<id>" recv leaf.
    function _buildRegistryProof(
        string memory domain,
        string memory username,
        string memory userId,
        string memory endpoint,
        string memory handlePrefix,
        address userAddress,
        uint256 ts
    ) internal view returns (Registry.FullTlsProof memory proof) {
        bytes32 clientRandom = bytes32(uint256(111));
        bytes32 serverRandom = bytes32(uint256(222));
        bytes memory serverEphKey = hex"deadbeef";
        bytes32 domainHash = keccak256(bytes(domain));

        bytes32 leafD = _leaf("domain:", bytes(domain));
        bytes32 leafU = _leaf("recv:", abi.encodePacked(handlePrefix, username, '"'));
        bytes32 leafE = _leaf("endpoint:", bytes(endpoint));
        bytes32 leafId = _leaf("recv:", abi.encodePacked('"id":"', userId, '"'));

        bytes32 hDU = _h(leafD, leafU);
        bytes32 hEId = _h(leafE, leafId);
        bytes32 transcriptRoot = _h(hDU, hEId);

        bytes32[] memory dp = new bytes32[](2);
        dp[0] = leafU;
        dp[1] = hEId;
        bytes32[] memory up = new bytes32[](2);
        up[0] = leafD;
        up[1] = hEId;
        bytes32[] memory ep = new bytes32[](2);
        ep[0] = leafId;
        ep[1] = hDU;
        bytes32[] memory idp = new bytes32[](2);
        idp[0] = leafE;
        idp[1] = hDU;

        bytes32 notaryDigest = keccak256(
            abi.encode(
                block.chainid,
                address(registry),
                domainHash,
                clientRandom,
                serverRandom,
                keccak256(serverEphKey),
                transcriptRoot,
                ts
            )
        );
        bytes32 backendDigest = keccak256(abi.encode(userAddress, address(0), transcriptRoot, ts));

        proof = Registry.FullTlsProof({
            notarySignature: _sign(NOTARY_KEY, notaryDigest),
            backendSignature: _sign(BACKEND_KEY, backendDigest),
            userAddress: userAddress,
            walletAddress: address(0),
            domainHash: domainHash,
            clientRandom: clientRandom,
            serverRandom: serverRandom,
            serverEphemeralKey: serverEphKey,
            transcriptRoot: transcriptRoot,
            timestamp: ts,
            domainPath: dp,
            usernamePath: up,
            endpointPath: ep,
            idPath: idp
        });
    }

    // ─── transfer_within via execute helper ─────────────────────────

    function _transferWithin(
        WebWallet sender,
        uint256 senderPk,
        string memory receiverPlatform,
        string memory receiverHandle,
        uint256 amount
    ) internal {
        bytes memory data = abi.encodeCall(
            IBank.transfer_within,
            (_domain(receiverPlatform), receiverHandle, _idFor(receiverHandle), address(token), amount)
        );
        _execute(sender, address(bank), data, senderPk);
    }

    // ─── Tests ──────────────────────────────────────────────────────

    /// @notice Happy path: registered sender → registered receiver
    function test_transferWithin_registeredToRegistered() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);
        WebWallet bob = _walletFor("x", "bob", BOB_PK);

        _fund("x", "alice", 1000e18);

        _transferWithin(alice, ALICE_PK, "x", "bob", 400e18);

        assertEq(bank.registeredBalances(address(alice), address(token)), 600e18);
        assertEq(bank.registeredBalances(address(bob), address(token)), 400e18);
    }

    /// @notice Transfer to unregistered receiver goes to unregisteredBalances
    function test_transferWithin_toUnregistered() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);

        _fund("x", "alice", 500e18);

        _transferWithin(alice, ALICE_PK, "x", "charlie", 200e18);

        assertEq(bank.registeredBalances(address(alice), address(token)), 300e18);
        bytes32 key = keccak256(abi.encode("id:v1", "api.x.com", _idFor("charlie")));
        assertEq(bank.unregisteredBalances(key, address(token)), 200e18);
    }

    /// @notice Auto-top-up: Bank balance insufficient, pulls from WebWallet ERC20
    function test_transferWithin_autoTopUp() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);
        WebWallet bob = _walletFor("x", "bob", BOB_PK);

        // Give alice 200 in bank, 300 as ERC20 on wallet
        _fund("x", "alice", 200e18);
        _fundWallet(alice, 300e18);

        // Approve bank to pull from wallet
        bytes memory approveData = abi.encodeCall(IERC20.approve, (address(bank), type(uint256).max));
        _execute(alice, address(token), approveData, ALICE_PK);

        // Transfer 400 — needs 200 shortfall from ERC20
        _transferWithin(alice, ALICE_PK, "x", "bob", 400e18);

        assertEq(bank.registeredBalances(address(alice), address(token)), 0);
        assertEq(bank.registeredBalances(address(bob), address(token)), 400e18);
        assertEq(token.balanceOf(address(alice)), 100e18); // 300 - 200 shortfall
    }

    /// @notice Fails if sender is not registered
    function test_transferWithin_senderNotRegistered_reverts() public {
        _walletFor("x", "bob", BOB_PK);

        // Call from an unregistered address
        vm.prank(address(0xdead));
        vm.expectRevert(SenderNotRegistered.selector);
        bank.transfer_within("x", "bob", "", address(token), 100e18);
    }

    /// @notice Fails if insufficient balance and no ERC20 approved
    function test_transferWithin_insufficientAndNoApproval_reverts() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);

        _fund("x", "alice", 100e18);

        // Try to transfer 200 — shortfall 100, but no approval → revert
        bytes memory data = abi.encodeCall(IBank.transfer_within, ("x", "bob", "", address(token), 200e18));
        uint256 currentNonce = alice.nonce();
        bytes32 digest = keccak256(
            abi.encode(address(bank), uint256(0), keccak256(data), currentNonce, block.chainid, address(alice))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(ALICE_PK, digest);

        vm.expectRevert(); // safeTransferFrom will revert (no approval/balance)
        alice.execute(address(bank), 0, data, sigs);
    }

    /// @notice Zero amount reverts
    function test_transferWithin_zeroAmount_reverts() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);

        vm.prank(address(alice));
        vm.expectRevert(ZeroAmount.selector);
        bank.transfer_within("x", "bob", "", address(token), 0);
    }

    // ═══════════════════════════════════════════════════════════════
    //  MUTATION-GUARD NEGATIVE TESTS
    // ═══════════════════════════════════════════════════════════════

    // 10. transfer_within from a caller that is NOT a registered wallet (empty
    //     getHandles) → SenderNotRegistered. The caller holds tokens + approval so
    //     removing the guard would SUCCEED (auto-top-up pulls), killing the mutant.
    function test_SenderNotRegistered_transferWithin_reverts() public {
        _walletFor("x", "bob", BOB_PK); // registered receiver

        address stranger = address(0xBEEF);
        token.mint(stranger, 100e18);
        vm.prank(stranger);
        token.approve(address(bank), 100e18);

        vm.prank(stranger);
        vm.expectRevert(SenderNotRegistered.selector);
        bank.transfer_within("api.x.com", "bob", _idFor("bob"), address(token), 100e18);
    }

    // 18. transfer_within NATIVE (address(0)) with bank balance < amount: native
    //     can't be pulled → LibEscrow.autoTopUp reverts InsufficientBalance.
    function test_InsufficientBalance_reverts() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);

        vm.prank(address(alice));
        vm.expectRevert(InsufficientBalance.selector);
        bank.transfer_within("api.x.com", "bob", _idFor("bob"), address(0), 1 ether);
    }

    // 19. transfer_within ERC20 with bank balance < amount AND no allowance → the
    //     shortfall pull can't be authorized → LibEscrow.autoTopUp reverts the
    //     custom InsufficientAllowance (removing the guard yields the OZ ERC20 error).
    function test_InsufficientAllowance_reverts() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 100e18); // bank balance 100; transfer 200 → shortfall 100

        // Parametrized error → match on the selector prefix (removing the guard
        // yields the OZ ERC20 allowance error, a different selector).
        vm.prank(address(alice));
        vm.expectPartialRevert(InsufficientAllowance.selector);
        bank.transfer_within("api.x.com", "bob", _idFor("bob"), address(token), 200e18);
    }
}
