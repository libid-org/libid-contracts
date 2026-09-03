// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../Registry.sol";
import {Notary} from "../../notary/Notary.sol";
import {deployNotary} from "../../notary/test/DeployNotary.sol";
import {WalletFactory} from "../WalletFactory.sol";
import {WebWallet} from "../WebWallet.sol";

contract RegistryTest is Test {
    Registry registry;
    WalletFactory factory;
    Notary notaryContract;
    WebWallet walletImplV1;

    address owner = address(this);

    uint256 notaryPk = 0xA001;
    uint256 backendPk = 0xA002;
    uint256 userPk = 0xA003;
    uint256 linkSessionPk = 0xA009;

    address notaryAddr;
    address backendAddr;

    address userSessionAddr;
    address linkSessionAddr;

    // ─── setUp ──────────────────────────────────────────────────────

    function setUp() public {
        notaryAddr = vm.addr(notaryPk);
        backendAddr = vm.addr(backendPk);
        userSessionAddr = vm.addr(userPk);
        linkSessionAddr = vm.addr(linkSessionPk);

        walletImplV1 = new WebWallet();

        Registry rImpl = new Registry();
        WalletFactory fImpl = new WalletFactory();

        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl), abi.encodeCall(WalletFactory.initialize, (owner, address(walletImplV1), address(1)))
                )
            )
        );

        notaryContract = deployNotary(owner, notaryAddr);
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(Registry.initialize, (address(notaryContract), backendAddr, address(factory), owner))
                )
            )
        );

        factory.setRegistry(address(registry));

        // Register platforms used in tests
        registry.setPlatform("x.com", "api.x.com/2/users/me", '"username":"', '"id":"', '"');
        registry.setPlatform("github.com", "api.github.com/user", '"login":"', '"id":', ",");

        vm.warp(1_000_000);
    }

    // ─── proof helpers ──────────────────────────────────────────────

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _leaf(string memory prefix, bytes memory value) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
    }

    function _buildPaths(bytes memory domainBytes, bytes memory usernameBytes, bytes memory endpointBytes)
        internal
        pure
        returns (
            bytes32 transcriptRoot,
            bytes32[] memory domainPath,
            bytes32[] memory usernamePath,
            bytes32[] memory endpointPath
        )
    {
        bytes32 leafD = _leaf("domain:", domainBytes);
        bytes32 leafU = _leaf("recv:", usernameBytes);
        bytes32 leafE = _leaf("endpoint:", endpointBytes);

        bytes32 hDu =
            leafD < leafU ? keccak256(abi.encodePacked(leafD, leafU)) : keccak256(abi.encodePacked(leafU, leafD));

        transcriptRoot = hDu < leafE ? keccak256(abi.encodePacked(hDu, leafE)) : keccak256(abi.encodePacked(leafE, hDu));

        domainPath = new bytes32[](2);
        domainPath[0] = leafU;
        domainPath[1] = leafE;

        usernamePath = new bytes32[](2);
        usernamePath[0] = leafD;
        usernamePath[1] = leafE;

        endpointPath = new bytes32[](1);
        endpointPath[0] = hDu;
    }

    struct ProofBundle {
        Registry.FullTlsProof proof;
    }

    function _buildProof(
        string memory domain,
        string memory username,
        string memory endpoint,
        string memory handlePrefix,
        address _userAddress,
        uint256 ts
    ) internal view returns (ProofBundle memory b) {
        return _buildProofForWallet(domain, username, endpoint, handlePrefix, _userAddress, address(0), ts);
    }

    function _buildProofForWallet(
        string memory domain,
        string memory username,
        string memory endpoint,
        string memory handlePrefix,
        address _userAddress,
        address _walletAddress,
        uint256 ts
    ) internal view returns (ProofBundle memory b) {
        bytes32 clientRandom = bytes32(uint256(111));
        bytes32 serverRandom = bytes32(uint256(222));
        bytes memory serverEphKey = hex"deadbeef";
        bytes32 domainHash = keccak256(bytes(domain));

        bytes memory usernameSnippet = abi.encodePacked(handlePrefix, username, '"');
        (bytes32 transcriptRoot, bytes32[] memory dp, bytes32[] memory up, bytes32[] memory ep) =
            _buildPaths(bytes(domain), usernameSnippet, bytes(endpoint));

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
        bytes32 backendDigest = keccak256(abi.encode(_userAddress, _walletAddress, transcriptRoot, ts));

        b.proof = Registry.FullTlsProof({
            notarySignature: _sign(0xA001, notaryDigest),
            backendSignature: _sign(0xA002, backendDigest),
            userAddress: _userAddress,
            walletAddress: _walletAddress,
            domainHash: domainHash,
            clientRandom: clientRandom,
            serverRandom: serverRandom,
            serverEphemeralKey: serverEphKey,
            transcriptRoot: transcriptRoot,
            timestamp: ts,
            domainPath: dp,
            usernamePath: up,
            endpointPath: ep,
            idPath: new bytes32[](0)
        });
    }

    function _buildXProof(uint256 ts) internal view returns (ProofBundle memory) {
        return _buildProofWithId(
            "x.com", "alice", "12345", "api.x.com/2/users/me", '"username":"', '"id":"', '"', userSessionAddr, ts
        );
    }

    function _registerXAlice() internal returns (address wallet) {
        ProofBundle memory b = _buildXProof(block.timestamp);
        registry.register_session(b.proof, "x.com", "alice", "12345", "api.x.com/2/users/me");
        wallet = registry.resolve("x.com", "alice");
    }

    // 4-leaf tree: D, U, E, Id. hDU = h(D,U), hEId = h(E,Id), root = h(hDU, hEId).
    function _buildProofWithId(
        string memory domain,
        string memory username,
        string memory userId,
        string memory endpoint,
        string memory handlePrefix,
        string memory idPrefix,
        string memory idSuffix,
        address _userAddress,
        uint256 ts
    ) internal view returns (ProofBundle memory b) {
        bytes32 clientRandom = bytes32(uint256(111));
        bytes32 serverRandom = bytes32(uint256(222));
        bytes memory serverEphKey = hex"deadbeef";
        bytes32 domainHash = keccak256(bytes(domain));

        bytes32 leafD = _leaf("domain:", bytes(domain));
        bytes32 leafU = _leaf("recv:", abi.encodePacked(handlePrefix, username, '"'));
        bytes32 leafE = _leaf("endpoint:", bytes(endpoint));
        bytes32 leafId = _leaf("recv:", abi.encodePacked(idPrefix, userId, idSuffix));

        bytes32 hDU = _hash(leafD, leafU);
        bytes32 hEId = _hash(leafE, leafId);
        bytes32 root = _hash(hDU, hEId);

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
                root,
                ts
            )
        );
        bytes32 backendDigest = keccak256(abi.encode(_userAddress, address(0), root, ts));

        b.proof = Registry.FullTlsProof({
            notarySignature: _sign(0xA001, notaryDigest),
            backendSignature: _sign(0xA002, backendDigest),
            userAddress: _userAddress,
            walletAddress: address(0),
            domainHash: domainHash,
            clientRandom: clientRandom,
            serverRandom: serverRandom,
            serverEphemeralKey: serverEphKey,
            transcriptRoot: root,
            timestamp: ts,
            domainPath: dp,
            usernamePath: up,
            endpointPath: ep,
            idPath: idp
        });
    }

    /// Like `_buildProofWithId` but bound to a linking wallet: `linkIdentity`
    /// requires `proof.walletAddress == msg.sender`, so re-bind walletAddress
    /// and re-sign the backend digest (notary digest is wallet-independent).
    function _linkProofWithId(
        string memory domain,
        string memory username,
        string memory userId,
        string memory endpoint,
        string memory handlePrefix,
        string memory idPrefix,
        string memory idSuffix,
        address _userAddress,
        address _walletAddress,
        uint256 ts
    ) internal view returns (ProofBundle memory b) {
        b = _buildProofWithId(domain, username, userId, endpoint, handlePrefix, idPrefix, idSuffix, _userAddress, ts);
        b.proof.walletAddress = _walletAddress;
        b.proof.backendSignature =
            _sign(0xA002, keccak256(abi.encode(_userAddress, _walletAddress, b.proof.transcriptRoot, ts)));
    }

    function _hash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    // Execute `linkData` on `wallet` via the multisig executor, signed by userPk.
    function _execLink(address wallet, bytes memory linkData) internal {
        uint256 currentNonce = WebWallet(payable(wallet)).nonce();
        bytes32 execDigest = keccak256(
            abi.encode(address(registry), uint256(0), keccak256(linkData), currentNonce, block.chainid, wallet)
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(userPk, execDigest);
        WebWallet(payable(wallet)).execute(address(registry), 0, linkData, sigs);
    }

    // ─── happy path: new user ───────────────────────────────────────

    function test_registerSession_newUser_deploysWalletAndRegistersSession() public {
        address wallet = _registerXAlice();

        assertTrue(wallet != address(0));
        assertTrue(factory.isRegisteredWallet(wallet));
        assertEq(registry.resolve("x.com", "alice"), wallet);

        WebWallet w = WebWallet(payable(wallet));
        bytes32 key = keccak256(abi.encode("x.com", "12345"));
        assertEq(w.sessionCount(key), 1);
        assertEq(w.sessionAt(key, 0), userSessionAddr);

        assertTrue(w.isIdentity(key));
    }

    // ─── happy path: existing user ──────────────────────────────────

    function test_registerSession_existingUser_registersNewSession() public {
        address wallet = _registerXAlice();

        uint256 user2Pk = 0xA004;
        address user2Addr = vm.addr(user2Pk);

        ProofBundle memory b = _buildProofWithId(
            "x.com", "alice", "12345", "api.x.com/2/users/me", '"username":"', '"id":"', '"', user2Addr, block.timestamp
        );

        registry.register_session(b.proof, "x.com", "alice", "12345", "api.x.com/2/users/me");

        assertEq(registry.resolve("x.com", "alice"), wallet);

        WebWallet w = WebWallet(payable(wallet));
        bytes32 key = keccak256(abi.encode("x.com", "12345"));
        assertEq(w.sessionCount(key), 2);
        assertEq(w.sessionAt(key, 1), user2Addr);
    }

    // ─── invalid proof rejected ─────────────────────────────────────

    function test_registerSession_invalidNotarySignature_reverts() public {
        ProofBundle memory b = _buildXProof(block.timestamp);

        // Re-sign notary digest with wrong key
        bytes32 notaryDigest = keccak256(
            abi.encode(
                b.proof.domainHash,
                b.proof.clientRandom,
                b.proof.serverRandom,
                keccak256(b.proof.serverEphemeralKey),
                b.proof.transcriptRoot,
                b.proof.timestamp
            )
        );
        b.proof.notarySignature = _sign(0xDEAD, notaryDigest);

        vm.expectRevert();
        registry.register_session(b.proof, "x.com", "alice", "", "api.x.com/2/users/me");
    }

    function test_registerSession_invalidBackendSignature_reverts() public {
        ProofBundle memory b = _buildXProof(block.timestamp);

        bytes32 backendDigest = keccak256(abi.encode(b.proof.userAddress, b.proof.transcriptRoot, b.proof.timestamp));
        b.proof.backendSignature = _sign(notaryPk, backendDigest);

        vm.expectRevert(Registry.InvalidBackendSignature.selector);
        registry.register_session(b.proof, "x.com", "alice", "", "api.x.com/2/users/me");
    }

    // ─── session address reuse rejected (flat — same addr any platform) ──

    function test_registerSession_sessionKeyReuse_reverts() public {
        _registerXAlice();

        ProofBundle memory b2 = _buildProofWithId(
            "x.com",
            "bob",
            "67890",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            userSessionAddr,
            block.timestamp
        );

        vm.expectRevert(Registry.SessionKeyAlreadyUsed.selector);
        registry.register_session(b2.proof, "x.com", "bob", "67890", "api.x.com/2/users/me");
    }

    // ─── stale timestamp rejected ───────────────────────────────────

    function test_registerSession_staleTimestamp_reverts() public {
        ProofBundle memory b = _buildProof(
            "x.com", "alice", "api.x.com/2/users/me", '"username":"', userSessionAddr, block.timestamp - 2 hours
        );

        vm.expectRevert(Registry.StaleProof.selector);
        registry.register_session(b.proof, "x.com", "alice", "", "api.x.com/2/users/me");
    }

    function test_registerSession_futureTimestamp_reverts() public {
        ProofBundle memory b = _buildProof(
            "x.com", "alice", "api.x.com/2/users/me", '"username":"', userSessionAddr, block.timestamp + 5 minutes + 1
        );

        vm.expectRevert(Registry.FutureProof.selector);
        registry.register_session(b.proof, "x.com", "alice", "", "api.x.com/2/users/me");
    }

    // ─── WebWallet.register_session reverts if caller is not Registry ─

    function test_webWalletRegisterSession_revertsIfNotRegistry() public {
        address wallet = _registerXAlice();
        vm.expectRevert(WebWallet.OnlyRegistry.selector);
        WebWallet(payable(wallet)).register_session("x.com", "alice", "12345", userSessionAddr);
    }

    // ─── resolve returns address(0) for unknown handle ──────────────

    function test_resolve_returnsZeroForUnknownHandle() public view {
        assertEq(registry.resolve("x.com", "nobody"), address(0));
    }

    // ─── getHandles ─────────────────────────────────────────────────

    function test_getHandles_returnsCorrectEntries() public {
        _registerXAlice();
        (string[] memory platforms, string[] memory handles) = registry.getHandles(registry.resolve("x.com", "alice"));
        assertEq(platforms.length, 1);
        assertEq(platforms[0], "x.com");
        assertEq(handles[0], "alice");
    }

    // ─── linkIdentity tests ─────────────────────────────────────────

    function test_linkIdentity_happyPath() public {
        address wallet = _registerXAlice();

        ProofBundle memory ghProof = _linkProofWithId(
            "github.com",
            "alice",
            "777",
            "api.github.com/user",
            '"login":"',
            '"id":',
            ",",
            linkSessionAddr,
            wallet,
            block.timestamp
        );

        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("github.com", "alice", "777", ghProof.proof, "api.github.com/user"));

        uint256 currentNonce = WebWallet(payable(wallet)).nonce();
        bytes32 execDigest = keccak256(
            abi.encode(address(registry), uint256(0), keccak256(linkData), currentNonce, block.chainid, wallet)
        );

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(userPk, execDigest);

        WebWallet(payable(wallet)).execute(address(registry), 0, linkData, sigs);

        assertEq(registry.resolve("github.com", "alice"), wallet);

        (string[] memory platforms,) = registry.getHandles(wallet);
        assertEq(platforms.length, 2);
    }

    // Re-pointing a handle to a new owner is allowed; only an id mapped to a
    // different wallet is a real conflict (see test_linkIdentity_idAlreadyLinked_reverts).
    function test_linkIdentity_rePointHandle_allowed() public {
        address aliceWallet = _registerXAlice();

        // bob registers github handle "shared" under id 100.
        uint256 bobPk = 0xA007;
        address bobAddr = vm.addr(bobPk);
        ProofBundle memory bobProof = _buildProofWithId(
            "x.com", "shared", "100", "api.x.com/2/users/me", '"username":"', '"id":"', '"', bobAddr, block.timestamp
        );
        registry.register_session(bobProof.proof, "x.com", "shared", "100", "api.x.com/2/users/me");

        // alice links the same handle "shared" under a different id 200 — allowed.
        ProofBundle memory ghProof = _linkProofWithId(
            "x.com",
            "shared",
            "200",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            linkSessionAddr,
            aliceWallet,
            block.timestamp
        );
        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("x.com", "shared", "200", ghProof.proof, "api.x.com/2/users/me"));
        _execLink(aliceWallet, linkData);

        // handleHint re-points to alice's id; resolve follows.
        assertEq(registry.resolveById("x.com", "200"), aliceWallet);
        assertEq(registry.resolve("x.com", "shared"), aliceWallet);
    }

    /// M2 regression: re-linking the SAME (platform, userId) to the SAME wallet
    /// must not append a duplicate HandleEntry (which would double-count
    /// that id downstream). The session/label still refresh.
    function test_linkIdentity_reLinkSameId_noDuplicateEntry() public {
        address wallet = _registerXAlice(); // x.com / alice / id 12345

        (string[] memory before,) = registry.getUserIds(wallet);
        assertEq(before.length, 1, "precondition: one entry");

        // Re-link the SAME id "12345" to the same wallet with a fresh session key.
        address freshSession = vm.addr(0xFEED01);
        ProofBundle memory p = _linkProofWithId(
            "x.com",
            "alice",
            "12345",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            freshSession,
            wallet,
            block.timestamp
        );
        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("x.com", "alice", "12345", p.proof, "api.x.com/2/users/me"));
        _execLink(wallet, linkData);

        // No duplicate entry — still exactly one (platform, id) for this wallet.
        (string[] memory platforms, string[] memory userIds) = registry.getUserIds(wallet);
        assertEq(platforms.length, 1, "duplicate HandleEntry appended on re-link");
        assertEq(userIds[0], "12345");
        // Still resolves correctly; the fresh session is now authorized.
        assertEq(registry.resolveById("x.com", "12345"), wallet);
        assertTrue(WebWallet(payable(wallet)).isSession(freshSession));
    }

    function test_linkIdentity_notRegisteredWallet_reverts() public {
        ProofBundle memory ghProof =
            _buildProof("github.com", "alice", "api.github.com/user", '"login":"', userSessionAddr, block.timestamp);

        vm.expectRevert(Registry.NotRegisteredWallet.selector);
        registry.linkIdentity("github.com", "alice", "", ghProof.proof, "api.github.com/user");
    }

    // ─── Multisig threshold with (platform, handle) pairs ───────────

    function test_execute_multisigThreshold_distinctPairsRequired() public {
        address wallet = _registerXAlice();

        // Register a second session for same (x.com, alice)
        uint256 user2Pk = 0xA006;
        address user2Addr = vm.addr(user2Pk);

        ProofBundle memory b2 = _buildProofWithId(
            "x.com", "alice", "12345", "api.x.com/2/users/me", '"username":"', '"id":"', '"', user2Addr, block.timestamp
        );
        registry.register_session(b2.proof, "x.com", "alice", "12345", "api.x.com/2/users/me");

        // Link a second identity (use a fresh session address for the new identity)
        ProofBundle memory ghProof = _linkProofWithId(
            "github.com",
            "alice",
            "777",
            "api.github.com/user",
            '"login":"',
            '"id":',
            ",",
            linkSessionAddr,
            wallet,
            block.timestamp
        );
        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("github.com", "alice", "777", ghProof.proof, "api.github.com/user"));
        uint256 currentNonce = WebWallet(payable(wallet)).nonce();
        bytes32 execDigest = keccak256(
            abi.encode(address(registry), uint256(0), keccak256(linkData), currentNonce, block.chainid, wallet)
        );
        bytes[] memory sg1 = new bytes[](1);
        sg1[0] = _sign(userPk, execDigest);
        WebWallet(payable(wallet)).execute(address(registry), 0, linkData, sg1);

        // Register a session for github.com/alice
        uint256 ghSessionPk = 0xA008;
        address ghAddr = vm.addr(ghSessionPk);

        ProofBundle memory ghSessionProof = _buildProofWithId(
            "github.com", "alice", "777", "api.github.com/user", '"login":"', '"id":', ",", ghAddr, block.timestamp
        );
        registry.register_session(ghSessionProof.proof, "github.com", "alice", "777", "api.github.com/user");

        // Execute with 2 sigs from same pair (x.com/alice) — counts as 1 distinct pair
        bytes memory noopData = abi.encodeWithSignature("resolve(string,string)", "x", "y");
        currentNonce = WebWallet(payable(wallet)).nonce();
        execDigest = keccak256(
            abi.encode(address(registry), uint256(0), keccak256(noopData), currentNonce, block.chainid, wallet)
        );

        bytes[] memory sg3 = new bytes[](2);
        sg3[0] = _sign(userPk, execDigest);
        sg3[1] = _sign(user2Pk, execDigest);

        // threshold=1, 2 sigs from 1 pair → 1 distinct pair >= 1 ✓
        WebWallet(payable(wallet)).execute(address(registry), 0, noopData, sg3);
    }

    // ─── linkIdentity registers session on wallet ───────────────────

    function test_linkIdentity_registersSessionOnWallet() public {
        address wallet = _registerXAlice();

        ProofBundle memory ghProof = _linkProofWithId(
            "github.com",
            "alice",
            "777",
            "api.github.com/user",
            '"login":"',
            '"id":',
            ",",
            linkSessionAddr,
            wallet,
            block.timestamp
        );

        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("github.com", "alice", "777", ghProof.proof, "api.github.com/user"));

        uint256 currentNonce = WebWallet(payable(wallet)).nonce();
        bytes32 execDigest = keccak256(
            abi.encode(address(registry), uint256(0), keccak256(linkData), currentNonce, block.chainid, wallet)
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(userPk, execDigest);
        WebWallet(payable(wallet)).execute(address(registry), 0, linkData, sigs);

        // Verify that linkSessionAddr is now a session key on the wallet
        bytes32 ghKey = keccak256(abi.encode("github.com", "777"));
        WebWallet w = WebWallet(payable(wallet));
        assertTrue(w.isSession(linkSessionAddr));
        assertEq(w.sessionCount(ghKey), 1);
        assertEq(w.sessionAt(ghKey, 0), linkSessionAddr);
    }

    // ─── getHandles returns empty for unknown wallet ────────────────

    function test_getHandles_returnsEmptyForUnknownWallet() public view {
        (string[] memory platforms, string[] memory handles) = registry.getHandles(address(0xDEAD));
        assertEq(platforms.length, 0);
        assertEq(handles.length, 0);
    }

    // ─── register_session zero address ──────────────────────────────

    function test_registerSession_zeroAddress_reverts() public {
        ProofBundle memory b = _buildProofWithId(
            "x.com",
            "alice",
            "12345",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            address(0),
            block.timestamp
        );
        vm.expectRevert("zero session");
        registry.register_session(b.proof, "x.com", "alice", "12345", "api.x.com/2/users/me");
    }

    // ─── register_session domain hash mismatch ──────────────────────

    function test_registerSession_unsupportedPlatform_reverts() public {
        ProofBundle memory b = _buildXProof(block.timestamp);
        // Pass unregistered domain
        vm.expectRevert(Registry.UnsupportedPlatform.selector);
        registry.register_session(b.proof, "wrong.com", "alice", "", "api.x.com/2/users/me");
    }

    // ─── platform userId ────────────────────────────────────────────

    function test_registerSession_storesUserId() public {
        ProofBundle memory b = _buildProofWithId(
            "x.com",
            "alice",
            "12345",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            userSessionAddr,
            block.timestamp
        );
        registry.register_session(b.proof, "x.com", "alice", "12345", "api.x.com/2/users/me");

        address wallet = registry.walletOf("x.com", "12345");
        (string[] memory platforms, string[] memory userIds) = registry.getUserIds(wallet);
        assertEq(platforms.length, 1);
        assertEq(platforms[0], "x.com");
        assertEq(userIds[0], "12345");
    }

    function test_registerSession_wrongUserId_reverts() public {
        // Proof commits to id 12345, but caller claims 99999 → id leaf mismatch.
        ProofBundle memory b = _buildProofWithId(
            "x.com",
            "alice",
            "12345",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            userSessionAddr,
            block.timestamp
        );
        vm.expectRevert(Registry.InvalidMerkleProof.selector);
        registry.register_session(b.proof, "x.com", "alice", "99999", "api.x.com/2/users/me");
    }

    function test_registerSession_idOnUnsupportedPlatform_reverts() public {
        // A platform with empty idPrefix → passing a userId must revert.
        registry.setPlatform("noid.com", "api.noid.com/me", '"username":"', "", "");
        ProofBundle memory b = _buildProofWithId(
            "noid.com",
            "alice",
            "999",
            "api.noid.com/me",
            '"username":"',
            '"id":"',
            '"',
            userSessionAddr,
            block.timestamp
        );
        vm.expectRevert("id not supported");
        registry.register_session(b.proof, "noid.com", "alice", "999", "api.noid.com/me");
    }

    // GitHub: bare-number id "id":<n>, (suffix ',') — stores the numeric id.
    function test_registerSession_githubNumericId_stored() public {
        ProofBundle memory b = _buildProofWithId(
            "github.com",
            "octocat",
            "583231",
            "api.github.com/user",
            '"login":"',
            '"id":',
            ",",
            userSessionAddr,
            block.timestamp
        );
        registry.register_session(b.proof, "github.com", "octocat", "583231", "api.github.com/user");

        address wallet = registry.walletOf("github.com", "583231");
        assertTrue(wallet != address(0));
        assertEq(registry.resolveById("github.com", "583231"), wallet);
        (, string[] memory userIds) = registry.getUserIds(wallet);
        assertEq(userIds[0], "583231");
    }

    // GitHub: a truncated id (claim "583" against real "583231,") must not verify —
    // the ',' suffix anchors the number's end, blocking prefix-squatting.
    function test_registerSession_githubTruncatedId_reverts() public {
        ProofBundle memory b = _buildProofWithId(
            "github.com",
            "octocat",
            "583231",
            "api.github.com/user",
            '"login":"',
            '"id":',
            ",",
            userSessionAddr,
            block.timestamp
        );
        vm.expectRevert(Registry.InvalidMerkleProof.selector);
        registry.register_session(b.proof, "github.com", "octocat", "583", "api.github.com/user");
    }

    // ─── id-layer: registration / resolution (T1–T12) ───────────────

    // Register x.com/alice under id 12345 via the id path.
    function _registerXAliceId(string memory userId, address sessionAddr, uint256 ts)
        internal
        returns (address wallet)
    {
        ProofBundle memory b = _buildProofWithId(
            "x.com", "alice", userId, "api.x.com/2/users/me", '"username":"', '"id":"', '"', sessionAddr, ts
        );
        registry.register_session(b.proof, "x.com", "alice", userId, "api.x.com/2/users/me");
        wallet = registry.walletOf("x.com", userId);
    }

    // T1: register by id deploys wallet, sets walletOf/handleHint/idMeta.
    function test_T1_registerById_setsIdState() public {
        address wallet = _registerXAliceId("12345", userSessionAddr, block.timestamp);

        assertTrue(wallet != address(0)); // I1: walletOf set to a non-zero wallet
        assertEq(registry.walletOf("x.com", "12345"), wallet);
        assertEq(registry.handleHint("x.com", "alice"), "12345");
        (string memory h, uint256 verifiedAt) = registry.idMeta("x.com", "12345");
        assertEq(h, "alice");
        assertEq(verifiedAt, block.timestamp);
    }

    // T2: resolve(handle) follows handleHint → walletOf.
    function test_T2_resolve_viaHint() public {
        address wallet = _registerXAliceId("12345", userSessionAddr, block.timestamp);
        assertEq(registry.resolve("x.com", "alice"), wallet);
    }

    // T3: resolveById(id) → wallet.
    function test_T3_resolveById() public {
        address wallet = _registerXAliceId("12345", userSessionAddr, block.timestamp);
        assertEq(registry.resolveById("x.com", "12345"), wallet);
    }

    // T4: recycle — B proves a handle A held; resolve→B, resolveById(A)→A's wallet.
    function test_T4_recycle_handlePointsToNewOwner() public {
        address walletA = _registerXAliceId("100", userSessionAddr, block.timestamp);

        // B proves the same handle "alice" under a fresh id 200.
        uint256 bPk = 0xB001;
        address bAddr = vm.addr(bPk);
        address walletB = _registerXAliceId("200", bAddr, block.timestamp);

        assertTrue(walletA != walletB);
        // I2/I3: hint re-points to B; A still reachable by id.
        assertEq(registry.resolve("x.com", "alice"), walletB);
        assertEq(registry.resolveById("x.com", "100"), walletA);
        assertEq(registry.resolveById("x.com", "200"), walletB);
        // A's idMeta untouched.
        (string memory hA,) = registry.idMeta("x.com", "100");
        assertEq(hA, "alice");
    }

    // Rename: id 100 re-registers under a new handle. The OLD handle's hint must
    // be cleared so resolve(old) no longer returns this wallet.
    function test_rename_clearsStaleHandleHint() public {
        address wallet = _registerXAliceId("100", userSessionAddr, block.timestamp);
        assertEq(registry.resolve("x.com", "alice"), wallet);

        // Same id 100 now proves handle "alice2" with a fresh session key.
        address sess2 = vm.addr(0xA11CE2);
        ProofBundle memory b = _buildProofWithId(
            "x.com", "alice2", "100", "api.x.com/2/users/me", '"username":"', '"id":"', '"', sess2, block.timestamp
        );
        vm.expectEmit(false, false, false, true, address(registry));
        emit Registry.HandleChanged("x.com", "100", "alice2");
        registry.register_session(b.proof, "x.com", "alice2", "100", "api.x.com/2/users/me");

        assertEq(registry.resolve("x.com", "alice2"), wallet);
        assertEq(registry.resolveById("x.com", "100"), wallet);
        // Old handle hint cleared → no longer resolves to the wallet.
        assertEq(registry.resolve("x.com", "alice"), address(0));
        assertEq(registry.handleHint("x.com", "alice"), "");
        // getHandles stays frozen (claim-key stable); getCurrentHandles is current.
        (, string[] memory frozenHs) = registry.getHandles(wallet);
        assertEq(frozenHs[0], "alice");
        (, string[] memory curHs) = registry.getCurrentHandles(wallet);
        assertEq(curHs.length, 1);
        assertEq(curHs[0], "alice2");
    }

    // T5: linkIdentity binds a new id to an existing wallet.
    function test_T5_linkIdentity_newId() public {
        address wallet = _registerXAliceId("100", userSessionAddr, block.timestamp);

        ProofBundle memory ghProof = _linkProofWithId(
            "x.com",
            "alice2",
            "300",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            linkSessionAddr,
            wallet,
            block.timestamp
        );
        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("x.com", "alice2", "300", ghProof.proof, "api.x.com/2/users/me"));
        _execLink(wallet, linkData);

        assertEq(registry.walletOf("x.com", "300"), wallet);
        assertEq(registry.resolveById("x.com", "300"), wallet);
    }

    // T6: linkIdentity for an id already linked elsewhere → revert IdentityAlreadyLinked.
    function test_T6_linkIdentity_idAlreadyLinked_reverts() public {
        _registerXAliceId("100", userSessionAddr, block.timestamp); // wallet A owns id 100

        // B's wallet attempts to link id 100 (already A's) → conflict.
        uint256 bPk = 0xB002;
        address bAddr = vm.addr(bPk);
        address walletB = _registerXAliceId("200", bAddr, block.timestamp);

        ProofBundle memory p = _buildProofWithId(
            "x.com",
            "alice",
            "100",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            linkSessionAddr,
            block.timestamp
        );
        bytes memory linkData =
            abi.encodeCall(Registry.linkIdentity, ("x.com", "alice", "100", p.proof, "api.x.com/2/users/me"));

        uint256 currentNonce = WebWallet(payable(walletB)).nonce();
        bytes32 execDigest = keccak256(
            abi.encode(address(registry), uint256(0), keccak256(linkData), currentNonce, block.chainid, walletB)
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(bPk, execDigest); // bAddr is B's session

        vm.expectRevert(); // wrapped ExecutionFailed(IdentityAlreadyLinked) — I5
        WebWallet(payable(walletB)).execute(address(registry), 0, linkData, sigs);
    }

    // T7: refreshHandleHint by a stranger with a fresh proof re-points the hint.
    function test_T7_refreshHandleHint_permissionless() public {
        address wallet = _registerXAliceId("100", userSessionAddr, block.timestamp);

        // Stranger calls refreshHandleHint with a fresh proof for (alice, 100).
        ProofBundle memory p = _buildProofWithId(
            "x.com",
            "alice",
            "100",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            address(0xCAFE),
            block.timestamp
        );
        vm.prank(address(0xBEEF));
        registry.refreshHandleHint("x.com", "100", "alice", p.proof, "api.x.com/2/users/me");

        assertEq(registry.handleHint("x.com", "alice"), "100");
        assertEq(registry.resolve("x.com", "alice"), wallet);
    }

    // T8: refreshHandleHint for an unknown id → revert.
    function test_T8_refreshHandleHint_unknownId_reverts() public {
        ProofBundle memory p = _buildProofWithId(
            "x.com",
            "alice",
            "999",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            address(0xCAFE),
            block.timestamp
        );
        vm.expectRevert(Registry.UnknownId.selector);
        registry.refreshHandleHint("x.com", "999", "alice", p.proof, "api.x.com/2/users/me");
    }

    // T9: refresh/register with a wrong id leaf → revert InvalidMerkleProof (I4).
    function test_T9_wrongIdLeaf_reverts() public {
        // Proof commits to id 100, caller claims 999 → id leaf mismatch.
        ProofBundle memory p = _buildProofWithId(
            "x.com",
            "alice",
            "100",
            "api.x.com/2/users/me",
            '"username":"',
            '"id":"',
            '"',
            userSessionAddr,
            block.timestamp
        );
        vm.expectRevert(Registry.InvalidMerkleProof.selector);
        registry.register_session(p.proof, "x.com", "alice", "999", "api.x.com/2/users/me");
    }

    // T10: github (bare-number id) registers + resolves via the id path.
    function test_T10_githubId_resolves() public {
        uint256 ghPk = 0xC001;
        address ghAddr = vm.addr(ghPk);
        ProofBundle memory b = _buildProofWithId(
            "github.com", "octocat", "583231", "api.github.com/user", '"login":"', '"id":', ",", ghAddr, block.timestamp
        );
        registry.register_session(b.proof, "github.com", "octocat", "583231", "api.github.com/user");

        address wallet = registry.walletOf("github.com", "583231");
        assertTrue(wallet != address(0));
        assertEq(registry.resolve("github.com", "octocat"), wallet);
        assertEq(registry.resolveById("github.com", "583231"), wallet);
    }

    // T11: getUserIds returns (platform, id) after an id-register (2.6).
    function test_T11_getUserIds_afterIdRegister() public {
        address wallet = _registerXAliceId("12345", userSessionAddr, block.timestamp);
        (string[] memory platforms, string[] memory userIds) = registry.getUserIds(wallet);
        assertEq(platforms.length, 1);
        assertEq(platforms[0], "x.com");
        assertEq(userIds[0], "12345");
    }

    // ─── ERC-7201 storage ───────────────────────────────────────────

    /// The state must be under the ERC-7201 root and not in sequential slots.
    /// This test reads the root with `vm.load` and does not use the constant in
    /// the contract. The test fails if the constant is wrong. The test also
    /// fails if a later edit adds a plain state variable. That variable lands
    /// at slot 0. It collides with nothing today, but it breaks the append-only
    /// guarantee that the namespace gives.
    function test_storageLivesUnderTheErc7201Root() public view {
        bytes32 root = keccak256(abi.encode(uint256(keccak256("dyaka.storage.Registry")) - 1)) & ~bytes32(uint256(0xff));

        // `notaryContract` is the first field of RegistryStorage. The field is
        // at the root.
        assertTrue(registry.notaryContract() != address(0), "the fixture must set a notary contract");
        assertEq(
            address(uint160(uint256(vm.load(address(registry), root)))),
            registry.notaryContract(),
            "notaryContract is not at the namespace root"
        );

        // No data is in the sequential slots that the contract used before.
        for (uint256 i = 0; i < 10; i++) {
            assertEq(vm.load(address(registry), bytes32(i)), bytes32(0), "a sequential slot is in use");
        }
    }

    /// The getters keep the shape that the public variables generated. Every
    /// off-chain binding (alloy `sol!`, viem ABI) continues to work after the
    /// layout change.
    function test_namespacedGettersKeepThePublicVariableAbi() public {
        address wallet = _registerXAliceId("12345", userSessionAddr, block.timestamp);

        assertEq(registry.walletOf("x.com", "12345"), wallet);
        (string memory handle, uint256 verifiedAt) = registry.idMeta("x.com", "12345");
        assertEq(handle, "alice");
        assertTrue(verifiedAt != 0);
        assertEq(registry.handleHint("x.com", "alice"), "12345");

        (string memory platform, string memory boundHandle, string memory userId) =
            registry.contract_to_handles(wallet, 0);
        assertEq(platform, "x.com");
        assertEq(boundHandle, "alice");
        assertEq(userId, "12345");

        // All four fields. A previous review of this change caught a getter
        // that returned only the first two and dropped `idPrefix` and
        // `idSuffix`. The contract still compiled and the ABI still had the
        // selector, so nothing failed until an id-bound proof was verified.
        (string memory endpoint, string memory handlePrefix, string memory idPrefix, string memory idSuffix) =
            registry.platformConfigs("x.com");
        assertEq(endpoint, "api.x.com/2/users/me");
        assertEq(handlePrefix, '"username":"');
        assertEq(idPrefix, '"id":"');
        assertEq(idSuffix, '"');
    }

    // ─── initialize double-init ─────────────────────────────────────

    function test_initialize_revertsOnDoubleInit() public {
        vm.expectRevert();
        registry.initialize(address(notaryContract), backendAddr, address(factory), owner);
    }
}
