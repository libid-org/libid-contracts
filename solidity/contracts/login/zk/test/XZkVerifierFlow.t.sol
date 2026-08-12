// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../../Registry.sol";
import {WalletFactory} from "../../WalletFactory.sol";
import {WebWallet} from "../../WebWallet.sol";
import {IZkSessionVerifier} from "../IZkSessionVerifier.sol";
import {deployNotary} from "../../../notary/test/DeployNotary.sol";

/// Stand-in verifier that returns whatever the test author set up. Lets us
/// exercise the Registry dispatcher path without dragging in real
/// circuits / notary signatures (which live in `XZkVerifierBindings.t.sol`,
/// the X-specific cases).
contract StubZkVerifier is IZkSessionVerifier {
    string public override platformName = "stub.example";
    string public handle = "alice";
    address public sessionKey = address(0xC0FFEE);
    address public walletAddr = address(0);
    uint256 public expiresAt = type(uint256).max;
    bytes32 public nullifier = bytes32(uint256(0xBEEF));
    string public userId = "id_alice";
    bool public shouldRevert;
    bytes public revertMessage;

    function setIdentity(string memory h, address k) external {
        handle = h;
        sessionKey = k;
        // Escrow is keyed by the immutable id; derive a unique id per handle so
        // distinct identities map to distinct wallets.
        userId = string(abi.encodePacked("id_", h));
    }

    function setUserId(string memory u) external {
        userId = u;
    }

    function setWalletAddr(address w) external {
        walletAddr = w;
    }

    function setExpiresAt(uint256 e) external {
        expiresAt = e;
    }

    function setNullifier(bytes32 n) external {
        nullifier = n;
    }

    function setRevert(bool b, bytes memory m) external {
        shouldRevert = b;
        revertMessage = m;
    }

    function verifyAndExtract(bytes calldata)
        external
        view
        override
        returns (
            string memory _handle,
            address _sessionKey,
            address _walletAddr,
            uint256 _expiresAt,
            bytes32 _nullifier,
            string memory _userId
        )
    {
        if (shouldRevert) {
            bytes memory m = revertMessage;
            assembly { revert(add(m, 0x20), mload(m)) }
        }
        return (handle, sessionKey, walletAddr, expiresAt, nullifier, userId);
    }
}

/// Dispatcher-level tests for `Registry.register_session_zk(platform, bytes)`.
///
/// The Registry stays small and platform-agnostic; per-platform proof
/// semantics (circuit, notary signature, attestation shape) live inside
/// each `IZkSessionVerifier` implementation. These tests cover the
/// Registry-side invariants — dispatch, expiry, session-key replay,
/// nullifier replay, and wallet-deploy idempotency — against a stub
/// verifier so the assertions don't depend on circuit specifics.
contract RegistryZkDispatcherTest is Test {
    Registry registry;
    WalletFactory factory;
    StubZkVerifier verifier;

    address constant OWNER = address(0xA11CE);
    address constant NOTARY = address(0xB0B);
    address constant BACKEND = address(0xBE);
    string constant PLATFORM = "api.x.com";

    function setUp() public {
        WebWallet walletImpl = new WebWallet();
        WalletFactory fImpl = new WalletFactory();
        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl), abi.encodeCall(WalletFactory.initialize, (OWNER, address(walletImpl), address(1)))
                )
            )
        );

        Registry rImpl = new Registry();
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(
                        Registry.initialize, (address(deployNotary(OWNER, NOTARY)), BACKEND, address(factory), OWNER)
                    )
                )
            )
        );

        vm.prank(OWNER);
        factory.setRegistry(address(registry));

        verifier = new StubZkVerifier();
        vm.prank(OWNER);
        registry.setZkVerifier(PLATFORM, IZkSessionVerifier(address(verifier)));
    }

    function test_happyPath_dispatchesAndRegistersHandle() public {
        registry.register_session_zk(PLATFORM, hex"");
        address wallet = registry.resolve(PLATFORM, "alice");
        assertTrue(wallet != address(0));
        // Session is keyed by the immutable (platform, userId), not the handle.
        assertEq(
            WebWallet(payable(wallet)).sessionAt(keccak256(abi.encode(PLATFORM, "id_alice")), 0), address(0xC0FFEE)
        );
    }

    function test_unsetPlatform_reverts() public {
        vm.expectRevert(Registry.ZkVerifierNotSet.selector);
        registry.register_session_zk("not.configured", hex"");
    }

    function test_expiredProof_reverts() public {
        vm.warp(1_000_000);
        verifier.setExpiresAt(1_000_000); // boundary: expiresAt == now → ProofExpired
        vm.expectRevert(Registry.ProofExpired.selector);
        registry.register_session_zk(PLATFORM, hex"");
    }

    function test_zeroSessionKey_reverts() public {
        verifier.setIdentity("alice", address(0));
        vm.expectRevert(bytes("zero session"));
        registry.register_session_zk(PLATFORM, hex"");
    }

    function test_sessionKeyReplay_reverts() public {
        registry.register_session_zk(PLATFORM, hex"");
        // second call with same session key (same handle, even) reverts on
        // the global `usedSessionKeys` guard, NOT on handle-already-claimed.
        verifier.setNullifier(bytes32(uint256(0xDEAD))); // unique nullifier
        vm.expectRevert(Registry.SessionKeyAlreadyUsed.selector);
        registry.register_session_zk(PLATFORM, hex"");
    }

    function test_nullifierReplay_reverts() public {
        registry.register_session_zk(PLATFORM, hex"");
        // second call with a different session key but same nullifier
        // reverts on the bearer-nullifier replay guard.
        verifier.setIdentity("alice", address(0xC0FFEE2));
        vm.expectRevert(Registry.BearerNullifierUsed.selector);
        registry.register_session_zk(PLATFORM, hex"");
    }

    function test_verifierRevert_propagates() public {
        verifier.setRevert(true, bytes("custom verifier rejection"));
        vm.expectRevert(bytes("custom verifier rejection"));
        registry.register_session_zk(PLATFORM, hex"");
    }

    function test_secondHandleDeploysSecondWallet() public {
        registry.register_session_zk(PLATFORM, hex"");
        address w1 = registry.resolve(PLATFORM, "alice");

        // Different session key + nullifier + handle → still the same
        // platform; expected to deploy a NEW wallet (not link).
        verifier.setIdentity("bob", address(0xB0B11E));
        verifier.setNullifier(bytes32(uint256(0xBAD2)));
        registry.register_session_zk(PLATFORM, hex"");
        address w2 = registry.resolve(PLATFORM, "bob");
        assertTrue(w2 != address(0));
        assertTrue(w2 != w1);
    }

    function test_link_zk_happy_attachesHandleToCallingWallet() public {
        registry.register_session_zk(PLATFORM, hex"");
        address wallet = registry.resolve(PLATFORM, "alice");

        verifier.setIdentity("alice2", address(0xA11CE2));
        verifier.setWalletAddr(wallet); // PI walletAddress == msg.sender for link
        verifier.setNullifier(bytes32(uint256(0x1111)));
        vm.prank(wallet);
        registry.link_identity_zk(PLATFORM, hex"");

        assertEq(registry.resolve(PLATFORM, "alice2"), wallet);
    }

    function test_link_zk_unregisteredCaller_reverts() public {
        address stranger = address(0x5727A6);
        verifier.setIdentity("bob", address(0xB0B5E5));
        verifier.setWalletAddr(stranger); // matches msg.sender, so we hit NotRegisteredWallet
        verifier.setNullifier(bytes32(uint256(0x3333)));
        vm.prank(stranger);
        vm.expectRevert(Registry.NotRegisteredWallet.selector);
        registry.link_identity_zk(PLATFORM, hex"");
    }

    /// Register path must reject any non-zero walletAddress in the proof's PI.
    /// The factory deploys a fresh wallet, so binding is not allowed.
    function test_register_zk_nonZeroWalletAddr_reverts() public {
        verifier.setWalletAddr(address(0xDEADBEEF));
        vm.expectRevert(Registry.WrongWalletAddr.selector);
        registry.register_session_zk(PLATFORM, hex"");
    }

    /// Link path: PI walletAddress must equal msg.sender. Substituting a
    /// different wallet (the classic mempool front-run vector) reverts.
    function test_link_zk_walletAddr_mismatch_reverts() public {
        // Bootstrap alice's wallet.
        registry.register_session_zk(PLATFORM, hex"");
        address aliceWallet = registry.resolve(PLATFORM, "alice");

        // Try to link a second handle from a DIFFERENT wallet's pov.
        address otherWallet = address(0xB0B0B0B0);
        verifier.setIdentity("alice2", address(0xA11CE2));
        verifier.setWalletAddr(aliceWallet); // proof's PI binds to aliceWallet
        verifier.setNullifier(bytes32(uint256(0x4242)));

        vm.prank(otherWallet);
        vm.expectRevert(Registry.WrongWalletAddr.selector);
        registry.link_identity_zk(PLATFORM, hex"");
    }

    /// Link path: PI walletAddress == 0 (register-path shape) must NOT be
    /// accepted as a link, even from a registered wallet.
    function test_link_zk_zeroWalletAddr_reverts() public {
        registry.register_session_zk(PLATFORM, hex"");
        address aliceWallet = registry.resolve(PLATFORM, "alice");

        verifier.setIdentity("alice2", address(0xA11CE2));
        verifier.setWalletAddr(address(0)); // register-shape PI
        verifier.setNullifier(bytes32(uint256(0x5757)));

        vm.prank(aliceWallet);
        vm.expectRevert(Registry.WrongWalletAddr.selector);
        registry.link_identity_zk(PLATFORM, hex"");
    }
}
