// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {WalletFactory} from "../WalletFactory.sol";
import {WebWallet} from "../WebWallet.sol";

/// @dev Mock registry that accepts register_session calls.
contract MockRegistryForWalletTest {
    function registerSession(
        WebWallet wallet,
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address sessionAddr
    ) external {
        wallet.register_session(platform, handle, userId, sessionAddr);
    }

    function reregisterById(
        WebWallet wallet,
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address sessionAddr
    ) external {
        wallet.reregisterSessionById(platform, handle, userId, sessionAddr);
    }

    fallback() external payable {}
    receive() external payable {}
}

contract WebWalletTest is Test {
    WebWallet wallet;
    MockRegistryForWalletTest mockRegistryContract;
    address mockRegistry;

    // Sessions are keyed by the immutable (platform, userId), NOT the handle.
    string constant ALICE_ID = "alice_id";
    bytes32 constant IDENTITY_ALICE_TT = keccak256(abi.encode("tiktok", ALICE_ID));
    bytes32 constant IDENTITY_ALICE_KEY = keccak256(abi.encode("tiktok", ALICE_ID));

    uint256 sessionPk = 0xDEAD;
    address sessionAddr;

    function setUp() public {
        sessionAddr = vm.addr(sessionPk);

        mockRegistryContract = new MockRegistryForWalletTest();
        mockRegistry = address(mockRegistryContract);

        wallet = new WebWallet();
        wallet.initialize(mockRegistry, address(0), "tiktok", "alice");

        // Register session via mock registry
        mockRegistryContract.registerSession(wallet, "tiktok", "alice", ALICE_ID, sessionAddr);

        vm.warp(1_000_000);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _execute(address target, uint256 value, bytes memory data, uint256[] memory pks) internal {
        uint256 currentNonce = wallet.nonce();
        bytes32 digest =
            keccak256(abi.encode(target, value, keccak256(data), currentNonce, block.chainid, address(wallet)));

        bytes[] memory sigs = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            sigs[i] = _sign(pks[i], digest);
        }

        wallet.execute(target, value, data, sigs);
    }

    // ── register_session ────────────────────────────────────────────

    function test_registerSession_storesSession() public view {
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 1);
        assertEq(wallet.sessionAt(IDENTITY_ALICE_KEY, 0), sessionAddr);
    }

    function test_registerSession_setsSession() public view {
        assertTrue(wallet.isSession(sessionAddr));
    }

    function test_registerSession_storesIdentity() public view {
        assertEq(wallet.sessionIdentity(sessionAddr), IDENTITY_ALICE_KEY);
    }

    function test_registerSession_revertsIfNotRegistry() public {
        vm.expectRevert(WebWallet.OnlyRegistry.selector);
        wallet.register_session("tiktok", "alice", ALICE_ID, sessionAddr);
    }

    function test_registerSession_revertsIfZeroAddress() public {
        vm.prank(mockRegistry);
        vm.expectRevert("zero session");
        wallet.register_session("tiktok", "alice", ALICE_ID, address(0));
    }

    function test_registerSession_newPairAddsIdentity() public {
        assertEq(wallet.identityCount(), 1);
        // Register session for a new (platform, handle) pair
        uint256 pk2 = 0xBEEF;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(wallet, "github.com", "alice", "alice_gh_id", addr2);
        assertEq(wallet.identityCount(), 2);
        bytes32 ghKey = keccak256(abi.encode("github.com", "alice_gh_id"));
        assertTrue(wallet.isIdentity(ghKey));
    }

    function test_registerSession_existingPairJustAddsKey() public {
        assertEq(wallet.identityCount(), 1);
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 1);
        // Register another session for same pair
        uint256 pk2 = 0xBEEF;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(wallet, "tiktok", "alice", ALICE_ID, addr2);
        assertEq(wallet.identityCount(), 1); // still 1 identity
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 2); // 2 sessions
    }

    // ── initialize ──────────────────────────────────────────────────

    function test_initialize_setsRegistry() public view {
        assertEq(wallet.registry(), mockRegistry);
    }

    function test_initialize_setsThresholdToOne() public view {
        assertEq(wallet.threshold(), 1);
    }

    function test_initialize_addsFirstIdentity() public view {
        assertTrue(wallet.isIdentity(IDENTITY_ALICE_TT));
        assertEq(wallet.identityCount(), 1);
    }

    function test_initialize_storesIdentityFromPlatformHandle() public {
        WebWallet w2 = new WebWallet();
        w2.initialize(mockRegistry, address(0), "discord", "bob");
        bytes32 key = keccak256(abi.encode("discord", "bob_id"));
        // Identity is only tracked after a session is registered
        assertEq(w2.identityCount(), 0);
        // Register a session — identity should now appear
        uint256 pk2 = 0xCAFE;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(w2, "discord", "bob", "bob_id", addr2);
        assertEq(w2.identityCount(), 1);
        assertEq(w2.identityAt(0), key);
    }

    // ── execute ─────────────────────────────────────────────────────

    function test_execute_incrementsNonce() public {
        assertEq(wallet.nonce(), 0);

        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(mockRegistry, 0, hex"", pks);
        assertEq(wallet.nonce(), 1);
    }

    function test_execute_duplicatePairCountsOnce() public {
        // Register a second session for the same (tiktok, alice) pair
        uint256 pk2 = 0xBEEF;
        mockRegistryContract.registerSession(wallet, "tiktok", "alice", ALICE_ID, vm.addr(pk2));

        uint256[] memory pks = new uint256[](2);
        pks[0] = sessionPk;
        pks[1] = pk2;

        // threshold=1, 1 distinct pair → should succeed
        _execute(mockRegistry, 0, hex"", pks);
        assertEq(wallet.nonce(), 1);
    }

    function test_execute_differentPairsCountSeparately() public {
        // Register a session for a different identity
        uint256 pk2 = 0xBEEF;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(wallet, "github.com", "alice", "alice_gh_id", addr2);

        // Set threshold to 2
        uint256[] memory pks1 = new uint256[](1);
        pks1[0] = sessionPk;
        _execute(address(wallet), 0, abi.encodeCall(WebWallet.setThreshold, (2)), pks1);

        // Now need 2 distinct pairs
        uint256[] memory pks2 = new uint256[](2);
        pks2[0] = sessionPk;
        pks2[1] = pk2;
        _execute(mockRegistry, 0, hex"", pks2);
        assertEq(wallet.nonce(), 2);
    }

    function test_execute_revokedSessionDoesNotCount() public {
        // Register a second identity so we can revoke alice and test
        uint256 pk2 = 0xBEEF;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(wallet, "github.com", "alice", "alice_gh_id", addr2);

        // Revoke the original tiktok/alice session
        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(
            address(wallet), 0, abi.encodeCall(WebWallet.revokeSession, ("tiktok", "alice", ALICE_ID, sessionAddr)), pks
        );

        // Now try to use revoked session — should fail (threshold=1, 0 valid sigs)
        bytes memory data = hex"";
        uint256 currentNonce = wallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(mockRegistry, uint256(0), keccak256(data), currentNonce, block.chainid, address(wallet))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);

        vm.expectRevert(WebWallet.ThresholdNotMet.selector);
        wallet.execute(mockRegistry, 0, data, sigs);
    }

    // ── revokeSession ───────────────────────────────────────────────

    function test_revokeSession_removesLastSession_identityDisappears() public {
        // Revoke via execute (self-call)
        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(
            address(wallet), 0, abi.encodeCall(WebWallet.revokeSession, ("tiktok", "alice", ALICE_ID, sessionAddr)), pks
        );

        assertFalse(wallet.isSession(sessionAddr));
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 0);
        assertFalse(wallet.isIdentity(IDENTITY_ALICE_TT));
        assertEq(wallet.identityCount(), 0); // identity removed from array
    }

    function test_revokeSession_removesNonLastSession_identityPersists() public {
        // Register a second session for the same pair
        uint256 pk2 = 0xBEEF;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(wallet, "tiktok", "alice", ALICE_ID, addr2);
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 2);

        // Revoke the first session
        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(
            address(wallet), 0, abi.encodeCall(WebWallet.revokeSession, ("tiktok", "alice", ALICE_ID, sessionAddr)), pks
        );

        assertFalse(wallet.isSession(sessionAddr));
        assertTrue(wallet.isSession(addr2));
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 1);
        assertTrue(wallet.isIdentity(IDENTITY_ALICE_TT)); // still active
        assertEq(wallet.identityCount(), 1); // identity still in array
    }

    function test_revokeSession_revertsIfNotSelf() public {
        vm.expectRevert(WebWallet.OnlySelf.selector);
        wallet.revokeSession("tiktok", "alice", ALICE_ID, sessionAddr);
    }

    function test_revokeSession_revertsIfNotFound() public {
        address fake = makeAddr("fake");
        bytes memory revokeData = abi.encodeCall(WebWallet.revokeSession, ("tiktok", "alice", ALICE_ID, fake));

        uint256 currentNonce = wallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(address(wallet), uint256(0), keccak256(revokeData), currentNonce, block.chainid, address(wallet))
        );

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);

        vm.expectRevert(); // SessionNotFound wrapped in ExecutionFailed
        wallet.execute(address(wallet), 0, revokeData, sigs);
    }

    // ── upgradeToLatest ─────────────────────────────────────────────

    function test_upgradeToLatest_revertsIfNotSelf() public {
        vm.expectRevert("only via execute()");
        wallet.upgradeToLatest();
    }

    /// @notice Happy path: upgradeToLatest via execute() updates implementation slot.
    function test_upgradeToLatest_success() public {
        WebWallet implV1 = new WebWallet();
        WebWallet implV2 = new WebWallet();

        // Deploy factory pointing to implV1
        WalletFactory fImpl = new WalletFactory();
        WalletFactory wFactory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl),
                    abi.encodeCall(WalletFactory.initialize, (address(this), address(implV1), mockRegistry))
                )
            )
        );

        // Deploy wallet proxy via factory (snapshot implV1)
        vm.prank(mockRegistry);
        WebWallet proxiedWallet = WebWallet(payable(wFactory.deploy_web_wallet("tiktok", "carol", "carol_id")));
        mockRegistryContract.registerSession(proxiedWallet, "tiktok", "carol", "carol_id", sessionAddr);

        // Upgrade beacon to implV2
        wFactory.upgradeWalletImplementation(address(implV2));
        assertEq(wFactory.latestImplementation(), address(implV2));

        // ERC1967 impl slot
        bytes32 implSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        address beforeImpl = address(uint160(uint256(vm.load(address(proxiedWallet), implSlot))));
        assertEq(beforeImpl, address(implV1));

        // Call upgradeToLatest via execute (self-call)
        bytes memory data = abi.encodeCall(WebWallet.upgradeToLatest, ());
        uint256 nonce = proxiedWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(proxiedWallet), uint256(0), keccak256(data), nonce, block.chainid, address(proxiedWallet)
            )
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        proxiedWallet.execute(address(proxiedWallet), 0, data, sigs);

        address afterImpl = address(uint160(uint256(vm.load(address(proxiedWallet), implSlot))));
        assertEq(afterImpl, address(implV2));
    }

    /// @notice State (sessions, threshold) is preserved after upgradeToLatest.
    function test_upgradeToLatest_statePreserved() public {
        WebWallet implV1 = new WebWallet();
        WebWallet implV2 = new WebWallet();

        WalletFactory fImpl = new WalletFactory();
        WalletFactory wFactory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl),
                    abi.encodeCall(WalletFactory.initialize, (address(this), address(implV1), mockRegistry))
                )
            )
        );

        vm.prank(mockRegistry);
        WebWallet proxiedWallet = WebWallet(payable(wFactory.deploy_web_wallet("tiktok", "carol", "carol_id")));
        mockRegistryContract.registerSession(proxiedWallet, "tiktok", "carol", "carol_id", sessionAddr);

        bytes32 identityKey = keccak256(abi.encode("tiktok", "carol_id"));
        assertEq(proxiedWallet.sessionCount(identityKey), 1);
        assertEq(proxiedWallet.threshold(), 1);

        // Upgrade beacon and call upgradeToLatest
        wFactory.upgradeWalletImplementation(address(implV2));
        bytes memory data = abi.encodeCall(WebWallet.upgradeToLatest, ());
        uint256 nonce = proxiedWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(proxiedWallet), uint256(0), keccak256(data), nonce, block.chainid, address(proxiedWallet)
            )
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        proxiedWallet.execute(address(proxiedWallet), 0, data, sigs);

        // State unchanged after upgrade
        assertEq(proxiedWallet.sessionCount(identityKey), 1);
        assertEq(proxiedWallet.sessionAt(identityKey, 0), sessionAddr);
        assertEq(proxiedWallet.threshold(), 1);
        assertTrue(proxiedWallet.isSession(sessionAddr));
    }

    /// @notice upgradeToLatest is a no-op (same impl) when factory still points to current impl.
    function test_upgradeToLatest_noOpIfAlreadyLatest() public {
        WebWallet implV1 = new WebWallet();

        WalletFactory fImpl = new WalletFactory();
        WalletFactory wFactory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl),
                    abi.encodeCall(WalletFactory.initialize, (address(this), address(implV1), mockRegistry))
                )
            )
        );

        vm.prank(mockRegistry);
        WebWallet proxiedWallet = WebWallet(payable(wFactory.deploy_web_wallet("tiktok", "carol", "carol_id")));
        mockRegistryContract.registerSession(proxiedWallet, "tiktok", "carol", "carol_id", sessionAddr);

        bytes32 implSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        address beforeImpl = address(uint160(uint256(vm.load(address(proxiedWallet), implSlot))));

        // Don't upgrade beacon — factory still returns implV1
        bytes memory data = abi.encodeCall(WebWallet.upgradeToLatest, ());
        uint256 nonce = proxiedWallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(
                address(proxiedWallet), uint256(0), keccak256(data), nonce, block.chainid, address(proxiedWallet)
            )
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        proxiedWallet.execute(address(proxiedWallet), 0, data, sigs);

        address afterImpl = address(uint160(uint256(vm.load(address(proxiedWallet), implSlot))));
        assertEq(afterImpl, beforeImpl);
    }

    // ── setThreshold ────────────────────────────────────────────────

    function test_setThreshold_revertsIfNotSelf() public {
        vm.expectRevert(WebWallet.OnlySelf.selector);
        wallet.setThreshold(1);
    }

    function test_setThreshold_revertsIfZero() public {
        bytes memory data = abi.encodeCall(WebWallet.setThreshold, (0));
        uint256 currentNonce = wallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(address(wallet), uint256(0), keccak256(data), currentNonce, block.chainid, address(wallet))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        vm.expectRevert(); // "zero threshold" wrapped in ExecutionFailed
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_setThreshold_revertsIfExceedsIdentityCount() public {
        // wallet has 1 identity, try to set threshold to 2
        bytes memory data = abi.encodeCall(WebWallet.setThreshold, (2));
        uint256 currentNonce = wallet.nonce();
        bytes32 digest = keccak256(
            abi.encode(address(wallet), uint256(0), keccak256(data), currentNonce, block.chainid, address(wallet))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        vm.expectRevert(); // ThresholdExceedsIdentityCount wrapped in ExecutionFailed
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_setThreshold_successAtIdentityCount() public {
        // Add a second identity
        uint256 pk2 = 0xBEEF;
        mockRegistryContract.registerSession(wallet, "github.com", "alice", "alice_gh_id", vm.addr(pk2));
        assertEq(wallet.identityCount(), 2);

        // Set threshold to 2 — should succeed
        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(address(wallet), 0, abi.encodeCall(WebWallet.setThreshold, (2)), pks);
        assertEq(wallet.threshold(), 2);
    }

    // ── register_session duplicate ──────────────────────────────────

    function test_registerSession_revertsDuplicate() public {
        // sessionAddr is already registered, try to register again
        vm.prank(mockRegistry);
        vm.expectRevert(WebWallet.SessionAlreadyRegistered.selector);
        wallet.register_session("tiktok", "alice", ALICE_ID, sessionAddr);
    }

    function test_registerSession_revertsDuplicateAcrossIdentities() public {
        // sessionAddr registered for tiktok/alice, try for github/alice
        vm.prank(mockRegistry);
        vm.expectRevert(WebWallet.SessionAlreadyRegistered.selector);
        wallet.register_session("github.com", "alice", "alice_gh_id", sessionAddr);
    }

    // ── execute edge cases ──────────────────────────────────────────

    function test_execute_revertsIfNonceWrong() public {
        // Use nonce=999 instead of current (0)
        bytes memory data = hex"";
        bytes32 digest = keccak256(
            abi.encode(mockRegistry, uint256(0), keccak256(data), uint256(999), block.chainid, address(wallet))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        vm.expectRevert(WebWallet.ThresholdNotMet.selector);
        wallet.execute(mockRegistry, 0, data, sigs);
    }

    function test_execute_revertsIfChainIdWrong() public {
        bytes memory data = hex"";
        // Sign with wrong chainId
        bytes32 digest = keccak256(
            abi.encode(mockRegistry, uint256(0), keccak256(data), uint256(0), uint256(9999), address(wallet))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);
        vm.expectRevert(WebWallet.ThresholdNotMet.selector);
        wallet.execute(mockRegistry, 0, data, sigs);
    }

    // ── executeBatch ────────────────────────────────────────────────

    function test_executeBatch_revertsIfLengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1); // mismatch
        bytes[] memory datas = new bytes[](2);
        bytes[] memory sigs = new bytes[](0);

        vm.expectRevert("length mismatch");
        wallet.executeBatch(targets, values, datas, sigs);
    }

    function test_executeBatch_emptyBatchSucceeds() public {
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory datas = new bytes[](0);

        uint256 currentNonce = wallet.nonce();
        bytes32 dataHashes = keccak256(abi.encode(datas));
        bytes32 digest =
            keccak256(abi.encode(targets, values, dataHashes, currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);

        wallet.executeBatch(targets, values, datas, sigs);
        assertEq(wallet.nonce(), 1);
    }

    function test_executeBatch_revertsIfAnyCallFails() public {
        // First call succeeds (noop to mock registry), second reverts
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = mockRegistry;
        targets[1] = address(wallet);
        values[0] = 0;
        values[1] = 0;
        datas[0] = hex"";
        datas[1] = abi.encodeCall(WebWallet.setThreshold, (0)); // will revert

        uint256 currentNonce = wallet.nonce();
        bytes32 dataHashes = keccak256(abi.encode(datas));
        bytes32 digest =
            keccak256(abi.encode(targets, values, dataHashes, currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);

        vm.expectRevert(); // ExecutionFailed
        wallet.executeBatch(targets, values, datas, sigs);
        // Nonce should NOT have incremented
        assertEq(wallet.nonce(), 0);
    }

    function test_executeBatch_incrementsNonceCorrectly() public {
        // Two noop calls
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = mockRegistry;
        targets[1] = mockRegistry;
        values[0] = 0;
        values[1] = 0;
        datas[0] = hex"";
        datas[1] = hex"";

        uint256 currentNonce = wallet.nonce();
        bytes32 dataHashes = keccak256(abi.encode(datas));
        bytes32 digest =
            keccak256(abi.encode(targets, values, dataHashes, currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(sessionPk, digest);

        wallet.executeBatch(targets, values, datas, sigs);
        assertEq(wallet.nonce(), 1); // only +1 per batch, not per call
    }

    // ── revokeSession cleans up identityKeys ────────────────────────

    function test_revokeSession_lastSessionCleansUpIdentityKeys() public {
        // Already tested above but let's verify identityAt is cleaned
        assertEq(wallet.identityCount(), 1);
        assertEq(wallet.identityAt(0), IDENTITY_ALICE_KEY);

        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(
            address(wallet), 0, abi.encodeCall(WebWallet.revokeSession, ("tiktok", "alice", ALICE_ID, sessionAddr)), pks
        );

        assertEq(wallet.identityCount(), 0);
    }

    // ── initialize double-init ──────────────────────────────────────

    function test_initialize_revertsOnDoubleInit() public {
        vm.expectRevert();
        wallet.initialize(mockRegistry, address(0), "tiktok", "alice");
    }

    // ── id-keying: rename stability ─────────────────────────────────
    //
    // A handle rename must NOT move a session. Sessions are keyed by the
    // immutable (platform, userId); the handle is display-only.

    function test_rename_sameIdKeepsSessionsUnderOneIdentity() public {
        // setUp registered tiktok/alice under ALICE_ID with display handle "alice".
        // Simulate a rename: register another session under the SAME (tiktok, ALICE_ID)
        // but with a NEW display handle.
        uint256 pk2 = 0xBEEF;
        address addr2 = vm.addr(pk2);
        mockRegistryContract.registerSession(wallet, "tiktok", "alice_renamed", ALICE_ID, addr2);

        // Both sessions live under the SAME identity key — the rename did not
        // create a new identity.
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 2);
        assertEq(wallet.identityCount(), 1);
        assertEq(wallet.sessionIdentity(addr2), IDENTITY_ALICE_KEY);

        // Revoking by the NEW display handle + same userId works, proving the key
        // is the id, not the handle.
        uint256[] memory pks = new uint256[](1);
        pks[0] = sessionPk;
        _execute(
            address(wallet),
            0,
            abi.encodeCall(WebWallet.revokeSession, ("tiktok", "alice_renamed", ALICE_ID, addr2)),
            pks
        );
        assertFalse(wallet.isSession(addr2));
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 1);
        assertEq(wallet.identityCount(), 1);
    }

    // ── id-keying: threshold counts distinct ids ────────────────────

    function test_threshold_countsDistinctIdsNotSessions() public {
        // Second session under the SAME id (tiktok, ALICE_ID) — different display handle.
        uint256 pkSameId = 0xBEEF;
        address addrSameId = vm.addr(pkSameId);
        mockRegistryContract.registerSession(wallet, "tiktok", "alice_alt", ALICE_ID, addrSameId);

        // A genuinely distinct identity (github, alice_gh_id).
        uint256 pkOtherId = 0xF00D;
        address addrOtherId = vm.addr(pkOtherId);
        mockRegistryContract.registerSession(wallet, "github.com", "alice", "alice_gh_id", addrOtherId);
        assertEq(wallet.identityCount(), 2);

        // Raise threshold to 2 (2 distinct identities exist).
        uint256[] memory one = new uint256[](1);
        one[0] = sessionPk;
        _execute(address(wallet), 0, abi.encodeCall(WebWallet.setThreshold, (2)), one);
        assertEq(wallet.threshold(), 2);

        bytes memory noop = hex"";
        uint256 n = wallet.nonce();
        bytes32 digest =
            keccak256(abi.encode(mockRegistry, uint256(0), keccak256(noop), n, block.chainid, address(wallet)));

        // Two sessions under the SAME id → 1 distinct identity → below threshold=2.
        bytes[] memory sameIdSigs = new bytes[](2);
        sameIdSigs[0] = _sign(sessionPk, digest);
        sameIdSigs[1] = _sign(pkSameId, digest);
        vm.expectRevert(WebWallet.ThresholdNotMet.selector);
        wallet.execute(mockRegistry, 0, noop, sameIdSigs);

        // Two sessions under DISTINCT ids → 2 distinct identities → meets threshold=2.
        bytes[] memory distinctSigs = new bytes[](2);
        distinctSigs[0] = _sign(sessionPk, digest);
        distinctSigs[1] = _sign(pkOtherId, digest);
        wallet.execute(mockRegistry, 0, noop, distinctSigs);
        assertEq(wallet.nonce(), 2); // setThreshold(+1) then this exec(+1)
    }

    // ── id-keying: reregisterSessionById migration ──────────────────

    function test_reregisterSessionById_noOpWhenAlreadyIdKeyed() public {
        // sessionAddr is already under the id key (tiktok, ALICE_ID); reregister is a no-op.
        mockRegistryContract.reregisterById(wallet, "tiktok", "alice", ALICE_ID, sessionAddr);
        assertTrue(wallet.isSession(sessionAddr));
        assertEq(wallet.sessionCount(IDENTITY_ALICE_KEY), 1);
        assertEq(wallet.sessionIdentity(sessionAddr), IDENTITY_ALICE_KEY);
    }

    function test_reregisterSessionById_migratesLegacyHandleKeyToIdKey() public {
        // Seed a "legacy" session by registering with userId == handle, which yields
        // the pre-upgrade key keccak256(platform, handle).
        uint256 legacyPk = 0xABCD;
        address legacyAddr = vm.addr(legacyPk);
        mockRegistryContract.registerSession(wallet, "discord", "carol", "carol", legacyAddr);
        bytes32 legacyKey = keccak256(abi.encode("discord", "carol"));
        bytes32 idKey = keccak256(abi.encode("discord", "carol_real_id"));
        assertEq(wallet.sessionCount(legacyKey), 1);
        assertEq(wallet.sessionCount(idKey), 0);

        // Migrate it to the immutable id key.
        mockRegistryContract.reregisterById(wallet, "discord", "carol", "carol_real_id", legacyAddr);

        assertEq(wallet.sessionCount(legacyKey), 0);
        assertEq(wallet.sessionCount(idKey), 1);
        assertEq(wallet.sessionAt(idKey, 0), legacyAddr);
        assertEq(wallet.sessionIdentity(legacyAddr), idKey);
        assertTrue(wallet.isSession(legacyAddr));
    }

    function test_reregisterSessionById_revertsIfNotRegistry() public {
        vm.expectRevert(WebWallet.OnlyRegistry.selector);
        wallet.reregisterSessionById("tiktok", "alice", ALICE_ID, sessionAddr);
    }

    function test_reregisterSessionById_revertsOnEmptyUserId() public {
        vm.prank(mockRegistry);
        vm.expectRevert("empty userId");
        wallet.reregisterSessionById("tiktok", "alice", "", sessionAddr);
    }
}
