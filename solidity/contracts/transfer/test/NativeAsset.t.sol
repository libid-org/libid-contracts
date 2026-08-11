// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../../login/Registry.sol";
import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {ResourceInfo, SenderInfo, BackendSig, NotaryTlsProof} from "../bank/BankTypes.sol";
import {NativeAmountMismatch, NativeTransferFailed, AlreadyRegistered} from "../bank/BankErrors.sol";
import {NotaryRegistry} from "../../login/NotaryRegistry.sol";
import {WalletFactory} from "../../login/WalletFactory.sol";
import {WebWallet} from "../../login/WebWallet.sol";
import {MockERC20} from "../MockERC20.sol";

/// @dev Refuses incoming ETH so a native withdraw's low-level call fails.
contract RejectEther {
    receive() external payable {
        revert("no ether");
    }
}

contract NativeAssetTest is Test, BankDiamondDeployer {
    uint256 constant NOTARY_KEY = uint256(keccak256("notary"));
    uint256 constant BACKEND_KEY = uint256(keccak256("backend"));
    address NOTARY;
    address BACKEND;

    Registry registry;
    IBank bank;
    WalletFactory factory;

    uint256 constant ALICE_PK = 0xA001;
    uint256 constant BOB_PK = 0xB001;
    uint256 private _transferCounter;

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
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(Registry.initialize, (NOTARY, BACKEND, address(factory), address(this)))
                )
            )
        );
        factory.setRegistry(address(registry));
        NotaryRegistry nrImpl = new NotaryRegistry();
        NotaryRegistry notaryReg = NotaryRegistry(
            address(
                new ERC1967Proxy(address(nrImpl), abi.encodeCall(NotaryRegistry.initialize, (address(this), NOTARY)))
            )
        );
        bank = IBank(deployBankDiamond(address(this), address(notaryReg), BACKEND, address(registry)));

        // Register native asset
        bank.registerToken("ETH", address(0));

        // Register platforms used in tests (X-style quoted id binding).
        registry.setPlatform("api.x.com", "api.test.com/endpoint", '"username":"', '"id":"', '"');
        registry.setPlatform("api.github.com", "api.test.com/endpoint", '"username":"', '"id":"', '"');

        vm.warp(1_000_000);
        vm.deal(address(this), 1000 ether);
    }

    /// Deterministic immutable id for a handle (escrow keyed by id).
    function _idFor(string memory handle) internal pure returns (string memory) {
        return string(abi.encodePacked("id_", handle));
    }

    // ─── Helpers ─────────────────────────────────────────────────

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

    function _alice() internal returns (WebWallet) {
        return _walletFor("x", "alice", ALICE_PK);
    }

    function _bob() internal returns (WebWallet) {
        return _walletFor("x", "bob", BOB_PK);
    }

    function _execute(WebWallet wallet, address target, uint256 value, bytes memory data, uint256 pk) internal {
        uint256 currentNonce = wallet.nonce();
        bytes32 digest =
            keccak256(abi.encode(target, value, keccak256(data), currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(pk, digest);
        wallet.execute(target, value, data, sigs);
    }

    function _execute(WebWallet wallet, address target, bytes memory data, uint256 pk) internal {
        _execute(wallet, target, 0, data, pk);
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

    /// 5-leaf proof builder (adds the author-id recv leaf) — id-only Bank always
    /// verifies the author-id Merkle leaf. Ported verbatim from Integration.t.sol
    /// (`_h` is the sorted-pair hash, same as Integration's `_hp`).
    function _buildBankProofWithId(
        string memory apiHost,
        string memory requestPath,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        bytes memory revealedAuthorId,
        uint256 ts
    ) internal view returns (NotaryTlsProof memory proof) {
        bytes32 clientRandom = bytes32(uint256(333));
        bytes32 serverRandom = bytes32(uint256(444));
        bytes memory serverEphKey = hex"cafebabe";
        bytes32 domainHash = keccak256(bytes(apiHost));

        bytes32 leafD = _leaf("domain:", bytes(apiHost));
        bytes32 leafE = _leaf("endpoint:", bytes(requestPath));
        bytes32 leafB = _leaf("recv:", revealedBody);
        bytes32 leafA = _leaf("recv:", revealedAuthor);
        bytes32 leafId = _leaf("recv:", revealedAuthorId);

        bytes32 hDE = _h(leafD, leafE);
        bytes32 hBA = _h(leafB, leafA);
        bytes32 root4 = _h(hDE, hBA);
        bytes32 transcriptRoot = _h(root4, leafId);

        bytes32[] memory bodyPath = new bytes32[](3);
        (bodyPath[0], bodyPath[1], bodyPath[2]) = (leafA, hDE, leafId);
        bytes32[] memory authorPath = new bytes32[](3);
        (authorPath[0], authorPath[1], authorPath[2]) = (leafB, hDE, leafId);
        bytes32[] memory domainPath = new bytes32[](3);
        (domainPath[0], domainPath[1], domainPath[2]) = (leafE, hBA, leafId);
        bytes32[] memory endpointPath = new bytes32[](3);
        (endpointPath[0], endpointPath[1], endpointPath[2]) = (leafD, hBA, leafId);
        bytes32[] memory authorIdPath = new bytes32[](1);
        authorIdPath[0] = root4;

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

        proof = NotaryTlsProof({
            notarySig: _sign(NOTARY_KEY, notaryDigest),
            domainHash: domainHash,
            clientRandom: clientRandom,
            serverRandom: serverRandom,
            serverEphemeralKey: serverEphKey,
            transcriptRoot: transcriptRoot,
            timestamp: ts,
            bodyMerklePath: bodyPath,
            authorMerklePath: authorPath,
            domainMerklePath: domainPath,
            endpointMerklePath: endpointPath,
            authorIdMerklePath: authorIdPath,
            receiverIdMerklePath: new bytes32[](0),
            revealedReceiverId: "",
            quotedRefMerklePath: new bytes32[](0),
            revealedQuotedRef: "",
            quotedAuthorMerklePath: new bytes32[](0),
            revealedQuotedAuthorId: ""
        });
    }

    function _buildBackendSigWithId(
        bytes32 uid,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        bytes memory revealedAuthorId,
        string memory receiverUserId,
        uint256 ts
    ) internal pure returns (BackendSig memory) {
        bytes32 digest = keccak256(
            abi.encodePacked(uid, revealedBody, revealedAuthor, revealedAuthorId, keccak256(bytes(receiverUserId)), ts)
        );
        return BackendSig({sig: _sign(BACKEND_KEY, digest), timestamp: ts});
    }

    // ─── Tests ───────────────────────────────────────────────────

    function test_registerNativeToken() public view {
        // Native ETH registered in setUp — assert the reverse map records it.
        assertEq(bank.tokenName(address(0)), "ETH");
    }

    function test_depositNativeToRegisteredUser() public {
        WebWallet alice = _alice();
        bank.deposit{value: 1 ether}("api.x.com", "alice", _idFor("alice"), address(0), 1 ether);
        assertEq(bank.balanceOf(address(alice), address(0)), 1 ether);
    }

    function test_depositNativeToUnregisteredUser() public {
        bank.deposit{value: 2 ether}("api.x.com", "unknown", _idFor("unknown"), address(0), 2 ether);
        bytes32 key = keccak256(abi.encode("id:v1", "api.x.com", _idFor("unknown")));
        assertEq(bank.unregisteredBalances(key, address(0)), 2 ether);
    }

    function test_withdrawNativeViaExecute() public {
        WebWallet alice = _alice();
        bank.deposit{value: 5 ether}("api.x.com", "alice", _idFor("alice"), address(0), 5 ether);

        uint256 balBefore = address(alice).balance;
        bytes memory data = abi.encodeCall(IBank.withdraw, (address(alice), address(0), 3 ether));
        _execute(alice, address(bank), data, ALICE_PK);
        assertEq(address(alice).balance, balBefore + 3 ether);
        assertEq(bank.balanceOf(address(alice), address(0)), 2 ether);
    }

    function test_transferWithinNative() public {
        WebWallet alice = _alice();
        WebWallet bob = _bob();
        bank.deposit{value: 10 ether}("api.x.com", "alice", _idFor("alice"), address(0), 10 ether);

        bytes memory data =
            abi.encodeCall(IBank.transfer_within, ("api.x.com", "bob", _idFor("bob"), address(0), 4 ether));
        _execute(alice, address(bank), data, ALICE_PK);

        assertEq(bank.balanceOf(address(alice), address(0)), 6 ether);
        assertEq(bank.balanceOf(address(bob), address(0)), 4 ether);
    }

    function test_transferWithinNative_insufficientBalance_reverts() public {
        WebWallet alice = _alice();
        _bob();

        bytes memory data =
            abi.encodeCall(IBank.transfer_within, ("api.x.com", "bob", _idFor("bob"), address(0), 1 ether));
        // Build the execute call manually to use vm.expectRevert
        uint256 currentNonce = alice.nonce();
        bytes32 digest = keccak256(
            abi.encode(address(bank), uint256(0), keccak256(data), currentNonce, block.chainid, address(alice))
        );
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(ALICE_PK, digest);
        vm.expectRevert();
        alice.execute(address(bank), 0, data, sigs);
    }

    function test_webTransferNative() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);

        // Deposit native for alice
        bank.deposit{value: 10 ether}("api.github.com", "alice", _idFor("alice"), address(0), 10 ether);

        // Build webTransfer proof
        _transferCounter++;
        string memory resourceId = string(abi.encodePacked("repo/", vm.toString(_transferCounter), "/comment/1"));
        string memory requestPath =
            string(abi.encodePacked("/repos/owner/repo/issues/comments/", vm.toString(_transferCounter)));
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 3 ETH");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);

        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "ETH",
            "3",
            3 ether,
            ""
        );

        address aliceWallet = registry.resolve("api.github.com", "alice");
        address bobWallet = registry.resolve("api.github.com", "bob");
        assertEq(bank.balanceOf(aliceWallet, address(0)), 7 ether);
        assertEq(bank.balanceOf(bobWallet, address(0)), 3 ether);
    }

    function test_depositNative_wrongAmount_reverts() public {
        _alice();
        vm.expectRevert(NativeAmountMismatch.selector);
        bank.deposit{value: 1 ether}("api.x.com", "alice", _idFor("alice"), address(0), 2 ether);
    }

    function test_balanceOfNative() public {
        WebWallet alice = _alice();
        bank.deposit{value: 7 ether}("api.x.com", "alice", _idFor("alice"), address(0), 7 ether);
        assertEq(bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(0)), 7 ether);
        assertEq(bank.balanceOf(address(alice), address(0)), 7 ether);
    }

    function test_balanceOfTotalNative() public {
        WebWallet alice = _alice();
        // Give wallet some native balance directly
        vm.deal(address(alice), 3 ether);
        bank.deposit{value: 5 ether}("api.x.com", "alice", _idFor("alice"), address(0), 5 ether);

        // balanceOfTotal should include wallet's native balance + bank balance
        assertEq(bank.balanceOfTotal(address(alice), address(0)), 5 ether + 3 ether);
        assertEq(bank.balanceOfTotal("api.x.com", "alice", _idFor("alice"), address(0)), 5 ether + 3 ether);
    }

    function test_walletSendNativeToEOA() public {
        WebWallet alice = _alice();
        vm.deal(address(alice), 10 ether);
        address recipient = address(0xBEEF);

        // Alice sends ETH to recipient via execute() with value
        _execute(alice, recipient, 2 ether, "", ALICE_PK);

        assertEq(recipient.balance, 2 ether);
        assertEq(address(alice).balance, 8 ether);
    }

    // ═══════════════════════════════════════════════════════════════
    //  MUTATION-GUARD NEGATIVE TESTS
    // ═══════════════════════════════════════════════════════════════

    // 16. Withdraw native to a contract whose receive() reverts → the low-level
    //     call fails → NativeTransferFailed. Removing the guard would silently
    //     "succeed" (funds debited, transfer failed), killing the mutant.
    function test_NativeTransferFailed_reverts() public {
        WebWallet alice = _alice();
        bank.deposit{value: 5 ether}("api.x.com", "alice", _idFor("alice"), address(0), 5 ether);

        RejectEther sink = new RejectEther();
        vm.prank(address(alice));
        vm.expectRevert(NativeTransferFailed.selector);
        bank.withdraw(address(sink), address(0), 3 ether);
    }

    // 17. Re-registering the native asset (address(0), already registered in setUp)
    //     hits the native branch of AdminFacet.registerToken → AlreadyRegistered.
    function test_AlreadyRegistered_native_reverts() public {
        // "ETH" -> address(0) was registered in setUp.
        vm.expectRevert(AlreadyRegistered.selector);
        bank.registerToken("ETH", address(0));
    }

    receive() external payable {}
}
