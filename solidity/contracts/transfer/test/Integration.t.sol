// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../../login/Registry.sol";
import {IBank} from "../bank/IBank.sol";
import {ResourceInfo, SenderInfo, BackendSig, NotaryTlsProof} from "../bank/BankTypes.sol";
import {
    InvalidMerkleProof,
    InvalidBackendSignature,
    TransferAlreadyUsed,
    SenderNotRegistered,
    ZeroAmount,
    TokenNotRegistered,
    NoTemplateMatch,
    AmountWeiMismatch,
    ReplyTargetMismatch,
    RecipientLessNeedsReplyTarget,
    QuotedAuthorDifferentObject,
    QuotedAuthorMismatch,
    QuotedAuthorMissingQuotedId,
    RefNotQuote,
    QuotedAuthorLeafNotIncludes,
    UnknownResourceType,
    RequestPathMismatch,
    AuthorNotInRevealedField,
    TemplateNotFound,
    InvalidNotarySignature,
    DomainHashMismatch,
    MerklePathTooLong,
    ZeroToken,
    SourceUrlNotHttps,
    SourceUrlDomainMismatch,
    ReplyLeafTooShort,
    ReplyLeafNotInReplyTo,
    QuotedRefTooShort,
    QuotedRefNotObject,
    QuotedRefNotFlatObject,
    QuotedRefMissingId,
    QuotedAuthorLeafTooShort,
    QuotedAuthorMissingAuthorId,
    EmptyQuotedValue
} from "../bank/BankErrors.sol";
import {LibString} from "../bank/libraries/LibString.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {NotaryRegistry} from "../../login/NotaryRegistry.sol";
import {WalletFactory} from "../../login/WalletFactory.sol";
import {WebWallet} from "../../login/WebWallet.sol";
import {MockERC20} from "../MockERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev V2 mock — just adds version() returning 2.
contract MockWebWalletV2 is WebWallet {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract IntegrationTest is Test, BankDiamondDeployer {
    // ─── Known test keys ────────────────────────────────────────────
    uint256 constant NOTARY_KEY = uint256(keccak256("notary"));
    uint256 constant BACKEND_KEY = uint256(keccak256("backend"));

    address NOTARY;
    address BACKEND;

    // ─── Contracts ──────────────────────────────────────────────────
    Registry registry;
    IBank bank;
    WalletFactory factory;
    MockERC20 token;

    address owner;

    // ─── Named session keys ─────────────────────────────────────────
    uint256 constant ALICE_PK = 0xA001;
    uint256 constant ALICE_PK2 = 0xA002;
    uint256 constant ALICE_PK3 = 0xA003;
    uint256 constant BOB_PK = 0xB001;
    uint256 constant CHARLIE_PK = 0xC001;
    uint256 constant LINK_PK1 = 0xD001;
    uint256 constant LINK_PK2 = 0xD002;
    uint256 constant LINK_PK3 = 0xD003;

    // ─── Transfer counter for unique UIDs ───────────────────────────
    uint256 private _transferCounter;

    // ─── setUp ──────────────────────────────────────────────────────

    function setUp() public {
        NOTARY = vm.addr(NOTARY_KEY);
        BACKEND = vm.addr(BACKEND_KEY);
        owner = address(this);

        WebWallet walletImpl = new WebWallet();
        Registry rImpl = new Registry();
        WalletFactory fImpl = new WalletFactory();

        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl), abi.encodeCall(WalletFactory.initialize, (owner, address(walletImpl), address(1)))
                )
            )
        );

        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl), abi.encodeCall(Registry.initialize, (NOTARY, BACKEND, address(factory), owner))
                )
            )
        );

        factory.setRegistry(address(registry));

        NotaryRegistry nrImpl = new NotaryRegistry();
        NotaryRegistry notaryReg = NotaryRegistry(
            address(new ERC1967Proxy(address(nrImpl), abi.encodeCall(NotaryRegistry.initialize, (owner, NOTARY))))
        );
        // Bank is now an EIP-2535 diamond (BankInit seeds the same templates/prefixes).
        bank = IBank(deployBankDiamond(owner, address(notaryReg), BACKEND, address(registry)));

        token = new MockERC20("Test", "TST");
        bank.registerToken("TST", address(token));

        // Register platforms used in tests (X-style quoted id binding).
        registry.setPlatform("api.x.com", "api.test.com/endpoint", '"username":"', '"id":"', '"');
        registry.setPlatform("api.github.com", "api.test.com/endpoint", '"username":"', '"id":"', '"');

        vm.warp(1_000_000);
    }

    /// Deterministic immutable id for a handle (tests key escrow by id).
    function _idFor(string memory handle) internal pure returns (string memory) {
        return string(abi.encodePacked("id_", handle));
    }

    // ═══════════════════════════════════════════════════════════════
    //  FLUENT HELPERS
    // ═══════════════════════════════════════════════════════════════

    // ─── Wallet creation ────────────────────────────────────────────

    function _alice() internal returns (WebWallet) {
        return _walletFor("x", "alice", ALICE_PK);
    }

    function _bob() internal returns (WebWallet) {
        return _walletFor("x", "bob", BOB_PK);
    }

    function _charlie() internal returns (WebWallet) {
        return _walletFor("x", "charlie", CHARLIE_PK);
    }

    /// Map platform shortname to API domain for Registry registration.
    /// In production, OAuth registers under the TLS domain (e.g. "api.x.com").
    /// Bank.webTransfer uses the apiHost to resolve the sender in the Registry.
    function _domain(string memory platform) internal pure returns (string memory) {
        if (keccak256(bytes(platform)) == keccak256("x")) return "api.x.com";
        if (keccak256(bytes(platform)) == keccak256("github")) return "api.github.com";
        return platform;
    }

    function _walletFor(string memory platform, string memory handle, uint256 pk) internal returns (WebWallet) {
        string memory domain = _domain(platform);
        string memory userId = _idFor(handle);
        address sessionAddr = vm.addr(pk);
        Registry.FullTlsProof memory proof = _buildRegistryProofWithId(
            domain, handle, userId, "api.test.com/endpoint", '"username":"', sessionAddr, address(0), block.timestamp
        );
        registry.register_session(proof, domain, handle, userId, "api.test.com/endpoint");
        return WebWallet(payable(registry.resolve(domain, handle)));
    }

    // ─── Funding ────────────────────────────────────────────────────

    function _fund(string memory platform, string memory handle, uint256 amount) internal {
        token.mint(address(this), amount);
        token.approve(address(bank), amount);
        bank.deposit(_domain(platform), handle, _idFor(handle), address(token), amount);
    }

    function _fundWallet(WebWallet wallet, uint256 amount) internal {
        token.mint(address(wallet), amount);
    }

    // ─── Transfers ──────────────────────────────────────────────────

    function _transfer(
        string memory senderPlatform,
        string memory senderHandle,
        string memory receiverPlatform,
        string memory receiverHandle,
        uint256 amount
    ) internal returns (bytes32 uid) {
        // Convert wei to human-readable: amount / 1e18 as integer string
        string memory amountStr = vm.toString(amount / 1e18);
        return _transferWithAmountStr(senderPlatform, senderHandle, receiverPlatform, receiverHandle, amountStr, amount);
    }

    function _transferWithAmountStr(
        string memory senderPlatform,
        string memory senderHandle,
        string memory receiverPlatform,
        string memory receiverHandle,
        string memory amountStr,
        uint256 amountWei
    ) internal returns (bytes32 uid) {
        _transferCounter++;
        string memory resourceId = string(abi.encodePacked("repo/", vm.toString(_transferCounter), "/comment/1"));
        string memory requestPath =
            string(abi.encodePacked("/repos/owner/repo/issues/comments/", vm.toString(_transferCounter)));

        uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));

        // Selective disclosure: body = just the comment text, author = separate field.
        // id-only: the sender's author-id is always proven (id-path).
        bytes memory body = abi.encodePacked("@dyaka-agent honor @", receiverHandle, " with ", amountStr, " TST");
        bytes memory authorBytes = bytes(senderHandle);
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor(senderHandle), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor(receiverHandle), block.timestamp);

        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        bank.webTransferV2(
            resource,
            SenderInfo({author: senderHandle, revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            receiverHandle,
            _idFor(receiverHandle),
            "TST",
            amountStr,
            amountWei,
            ""
        );
    }

    /// Security regression: a forged revealedAuthorId (victim id, not Merkle-proven)
    /// is rejected by _verifyRecvLeaf — no unsigned id can redirect resolveById.
    function test_webTransfer_forgedAuthorId_reverts() public {
        _walletFor("github", "alice", ALICE_PK); // attacker (has a valid proof of own comment)
        _walletFor("github", "bob", BOB_PK); // victim
        _fund("github", "bob", 1000e18);

        string memory resourceId = "repo/evil/comment/1";
        string memory requestPath = "/repos/owner/repo/issues/comments/777";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @attacker with 400 TST");
        bytes memory authorBytes = bytes("alice");

        NotaryTlsProof memory notaryProof =
            _buildBankProof("api.github.com", requestPath, body, authorBytes, block.timestamp);
        BackendSig memory backendSig = _buildBackendSig(uid, body, authorBytes, _idFor("attacker"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        // Forged author-id snippet pointing at the victim, with NO valid
        // authorIdMerklePath (the proof above has none) → _verifyRecvLeaf rejects.
        bytes memory forgedId = abi.encodePacked('"id":', _idFor("bob"), ",");
        vm.expectRevert(InvalidMerkleProof.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: forgedId}),
            body,
            notaryProof,
            backendSig,
            "attacker",
            _idFor("attacker"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // C1: the proven body honors bob, but a front-runner swaps receiverHandle to
    // their own identity. The on-chain recipient==receiverHandle bind rejects it.
    function test_webTransfer_recipientSwap_reverts() public {
        string memory resourceId = "repo/x/comment/1";
        string memory requestPath = "/repos/owner/repo/issues/comments/1";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 400 TST");
        bytes memory authorBytes = bytes("alice");

        NotaryTlsProof memory notaryProof =
            _buildBankProof("api.github.com", requestPath, body, authorBytes, block.timestamp);
        // Backend signed for the real recipient bob.
        BackendSig memory backendSig = _buildBackendSig(uid, body, authorBytes, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(NoTemplateMatch.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: ""}),
            body,
            notaryProof,
            backendSig,
            "attacker", // swapped — body says @bob
            _idFor("attacker"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // C1: front-runner keeps receiverHandle=bob (matches body) but swaps the
    // receiverUserId. It is bound into the backend digest -> signature rejects it.
    function test_webTransfer_receiverIdSwap_reverts() public {
        string memory resourceId = "repo/x/comment/2";
        string memory requestPath = "/repos/owner/repo/issues/comments/2";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        // Backend signed for the REAL receiver bob; the call swaps in attacker's id.
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(InvalidBackendSignature.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("attacker"), // swapped id — bound in the digest
            "TST",
            "400",
            400e18,
            ""
        );
    }

    /// @dev Transfer with a specific uid (for replay testing)
    function _transferWithUid(
        string memory resourceId,
        string memory senderPlatform,
        string memory senderHandle,
        string memory receiverPlatform,
        string memory receiverHandle,
        uint256 amount
    ) internal {
        string memory amountStr = vm.toString(amount / 1e18);
        _transferWithUidAndAmountStr(
            resourceId, senderPlatform, senderHandle, receiverPlatform, receiverHandle, amountStr, amount
        );
    }

    function _transferWithUidAndAmountStr(
        string memory resourceId,
        string memory senderPlatform,
        string memory senderHandle,
        string memory receiverPlatform,
        string memory receiverHandle,
        string memory amountStr,
        uint256 amountWei
    ) internal {
        string memory requestPath = "/repos/owner/repo/issues/comments/fixed";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));

        bytes memory body = abi.encodePacked("@dyaka-agent honor @", receiverHandle, " with ", amountStr, " TST");
        bytes memory authorBytes = bytes(senderHandle);
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor(senderHandle), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor(receiverHandle), block.timestamp);

        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        bank.webTransferV2(
            resource,
            SenderInfo({author: senderHandle, revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            receiverHandle,
            _idFor(receiverHandle),
            "TST",
            amountStr,
            amountWei,
            ""
        );
    }

    // ─── Execute helpers ────────────────────────────────────────────

    function _execute(WebWallet wallet, address target, bytes memory data, uint256 pk) internal {
        uint256[] memory pks = new uint256[](1);
        pks[0] = pk;
        _executeMulti(wallet, target, 0, data, pks);
    }

    function _executeMulti(WebWallet wallet, address target, uint256 value, bytes memory data, uint256[] memory pks)
        internal
    {
        uint256 currentNonce = wallet.nonce();
        bytes32 digest =
            keccak256(abi.encode(target, value, keccak256(data), currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            sigs[i] = _sign(pks[i], digest);
        }
        wallet.execute(target, value, data, sigs);
    }

    function _executeBatch(
        WebWallet wallet,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory datas,
        uint256[] memory pks
    ) internal {
        uint256 currentNonce = wallet.nonce();
        bytes32 dataHashes = keccak256(abi.encode(datas));
        bytes32 digest =
            keccak256(abi.encode(targets, values, dataHashes, currentNonce, block.chainid, address(wallet)));
        bytes[] memory sigs = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            sigs[i] = _sign(pks[i], digest);
        }
        wallet.executeBatch(targets, values, datas, sigs);
    }

    // ─── Assertions ─────────────────────────────────────────────────

    function _assertBankBalance(string memory platform, string memory handle, uint256 expected) internal view {
        assertEq(bank.balanceOf(_domain(platform), handle, _idFor(handle), address(token)), expected);
    }

    function _assertBankBalance(WebWallet wallet, uint256 expected) internal view {
        assertEq(bank.balanceOf(address(wallet), address(token)), expected);
    }

    function _assertTokenBalance(WebWallet wallet, uint256 expected) internal view {
        assertEq(token.balanceOf(address(wallet)), expected);
    }

    function _assertUnregisteredBalance(string memory platform, string memory handle, uint256 expected) internal view {
        bytes32 key = keccak256(abi.encode("id:v1", _domain(platform), _idFor(handle)));
        assertEq(bank.unregisteredBalances(key, address(token)), expected);
    }

    function _assertRegisteredBalance(WebWallet wallet, uint256 expected) internal view {
        assertEq(bank.registeredBalances(address(wallet), address(token)), expected);
    }

    // ─── Identity helpers ───────────────────────────────────────────

    function _linkIdentity(WebWallet wallet, string memory platform, string memory handle, uint256 signerPk) internal {
        _linkIdentityWithSessionPk(wallet, platform, handle, signerPk, signerPk);
    }

    function _linkIdentityWithSessionPk(
        WebWallet wallet,
        string memory platform,
        string memory handle,
        uint256 signerPk,
        uint256 newSessionPk
    ) internal {
        string memory domain = _domain(platform);
        string memory userId = _idFor(handle);
        Registry.FullTlsProof memory proof = _buildRegistryProofWithId(
            domain,
            handle,
            userId,
            "api.test.com/endpoint",
            '"username":"',
            vm.addr(newSessionPk),
            address(wallet),
            block.timestamp
        );
        bytes memory data =
            abi.encodeCall(Registry.linkIdentity, (domain, handle, userId, proof, "api.test.com/endpoint"));
        _execute(wallet, address(registry), data, signerPk);
    }

    function _addSession(string memory platform, string memory handle, uint256 pk) internal {
        string memory domain = _domain(platform);
        string memory userId = _idFor(handle);
        address sessionAddr = vm.addr(pk);
        Registry.FullTlsProof memory proof = _buildRegistryProofWithId(
            domain, handle, userId, "api.test.com/endpoint", '"username":"', sessionAddr, address(0), block.timestamp
        );
        registry.register_session(proof, domain, handle, userId, "api.test.com/endpoint");
    }

    function _setThreshold(WebWallet wallet, uint8 t, uint256 signerPk) internal {
        bytes memory data = abi.encodeCall(WebWallet.setThreshold, (t));
        _execute(wallet, address(wallet), data, signerPk);
    }

    function _revokeSession(
        WebWallet wallet,
        string memory platform,
        string memory handle,
        address sessionAddr,
        uint256 signerPk
    ) internal {
        bytes memory data = abi.encodeCall(
            WebWallet.revokeSession, (_domain(platform), handle, _idFor(handle), sessionAddr)
        );
        _execute(wallet, address(wallet), data, signerPk);
    }

    // ═══════════════════════════════════════════════════════════════
    //  LOW-LEVEL PROOF BUILDERS
    // ═══════════════════════════════════════════════════════════════

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

    function _buildRegistryProof(
        string memory domain,
        string memory username,
        string memory endpoint,
        string memory handlePrefix,
        address userAddress,
        uint256 ts
    ) internal view returns (Registry.FullTlsProof memory proof) {
        return _buildRegistryProofForWallet(domain, username, endpoint, handlePrefix, userAddress, address(0), ts);
    }

    function _buildRegistryProofForWallet(
        string memory domain,
        string memory username,
        string memory endpoint,
        string memory handlePrefix,
        address userAddress,
        address walletAddress,
        uint256 ts
    ) internal view returns (Registry.FullTlsProof memory proof) {
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
        bytes32 backendDigest = keccak256(abi.encode(userAddress, walletAddress, transcriptRoot, ts));

        proof = Registry.FullTlsProof({
            notarySignature: _sign(NOTARY_KEY, notaryDigest),
            backendSignature: _sign(BACKEND_KEY, backendDigest),
            userAddress: userAddress,
            walletAddress: walletAddress,
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

    // 4-leaf tree (D, U, E, Id) — id bound via the quoted "id":"<id>" recv leaf.
    function _buildRegistryProofWithId(
        string memory domain,
        string memory username,
        string memory userId,
        string memory endpoint,
        string memory handlePrefix,
        address userAddress,
        address walletAddress,
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
        bytes32 root = _h(hDU, hEId);

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
        bytes32 backendDigest = keccak256(abi.encode(userAddress, walletAddress, root, ts));

        proof = Registry.FullTlsProof({
            notarySignature: _sign(NOTARY_KEY, notaryDigest),
            backendSignature: _sign(BACKEND_KEY, backendDigest),
            userAddress: userAddress,
            walletAddress: walletAddress,
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

    function _h(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _buildBankProof(
        string memory apiHost,
        string memory requestPath,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        uint256 ts
    ) internal view returns (NotaryTlsProof memory proof) {
        bytes32 clientRandom = bytes32(uint256(333));
        bytes32 serverRandom = bytes32(uint256(444));
        bytes memory serverEphKey = hex"cafebabe";
        bytes32 domainHash = keccak256(bytes(apiHost));

        // 4 leaves: domain, endpoint, body (recv), author (recv)
        bytes32 leafD = _leaf("domain:", bytes(apiHost));
        bytes32 leafE = _leaf("endpoint:", bytes(requestPath));
        bytes32 leafB = _leaf("recv:", revealedBody);
        bytes32 leafA = _leaf("recv:", revealedAuthor);

        // Build Merkle tree from [leafD, leafE, leafB, leafA]
        bytes32 hDE =
            leafD < leafE ? keccak256(abi.encodePacked(leafD, leafE)) : keccak256(abi.encodePacked(leafE, leafD));

        bytes32 hBA =
            leafB < leafA ? keccak256(abi.encodePacked(leafB, leafA)) : keccak256(abi.encodePacked(leafA, leafB));

        bytes32 transcriptRoot =
            hDE < hBA ? keccak256(abi.encodePacked(hDE, hBA)) : keccak256(abi.encodePacked(hBA, hDE));

        // Merkle paths for each leaf (sibling + uncle)
        bytes32[] memory bodyPath = new bytes32[](2);
        bodyPath[0] = leafA; // sibling
        bodyPath[1] = hDE; // uncle

        bytes32[] memory authorPath = new bytes32[](2);
        authorPath[0] = leafB; // sibling
        authorPath[1] = hDE; // uncle

        bytes32[] memory domainPath = new bytes32[](2);
        domainPath[0] = leafE; // sibling
        domainPath[1] = hBA; // uncle

        bytes32[] memory endpointPath = new bytes32[](2);
        endpointPath[0] = leafD; // sibling
        endpointPath[1] = hBA; // uncle

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
            authorIdMerklePath: new bytes32[](0),
            receiverIdMerklePath: new bytes32[](0),
            revealedReceiverId: "",
            quotedRefMerklePath: new bytes32[](0),
            revealedQuotedRef: "",
            quotedAuthorMerklePath: new bytes32[](0),
            revealedQuotedAuthorId: ""
        });
    }

    function _hp(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /// 5-leaf proof builder (adds the author-id recv leaf) so the id-resolution
    /// path can be exercised on-chain. The id leaf is appended at the tree top:
    /// its path is the old 4-leaf root, and the other leaves' paths gain it.
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

        bytes32 hDE = _hp(leafD, leafE);
        bytes32 hBA = _hp(leafB, leafA);
        bytes32 root4 = _hp(hDE, hBA);
        bytes32 transcriptRoot = _hp(root4, leafId);

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

    // Happy path: a non-empty proven revealedAuthorId resolves the sender via
    // _extractId -> resolveById (not the handle), and the transfer settles.
    function test_webTransfer_idPath_resolvesByExtractedId() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1000e18);

        string memory resourceId = "repo/x/comment/idpath";
        string memory requestPath = "/repos/owner/repo/issues/comments/5";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        uint256 aliceBefore = bank.balanceOf("api.github.com", "alice", _idFor("alice"), address(token));
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );

        assertEq(bank.balanceOf("api.github.com", "alice", _idFor("alice"), address(token)), aliceBefore - 400e18);
        assertEq(bank.balanceOf("api.github.com", "bob", _idFor("bob"), address(token)), 400e18);
    }

    // ── recipient-less (reply-inferred) honor: recipient bound by the proven
    //    `in_reply_to_user_id` leaf, NOT by the body ─────────────────────────

    // 6-leaf proof builder: adds the reply-target recv leaf alongside author-id.
    // `_hp` is commutative, so sibling order within a level does not matter.
    function _buildBankProofWithReceiverId(
        string memory apiHost,
        string memory requestPath,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        bytes memory revealedAuthorId,
        bytes memory revealedReceiverId,
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
        bytes32 leafR = _leaf("recv:", revealedReceiverId);

        bytes32 hDE = _hp(leafD, leafE);
        bytes32 hBA = _hp(leafB, leafA);
        bytes32 root4 = _hp(hDE, hBA);
        bytes32 hIdR = _hp(leafId, leafR);
        bytes32 transcriptRoot = _hp(root4, hIdR);

        bytes32[] memory bodyPath = new bytes32[](3);
        (bodyPath[0], bodyPath[1], bodyPath[2]) = (leafA, hDE, hIdR);
        bytes32[] memory authorPath = new bytes32[](3);
        (authorPath[0], authorPath[1], authorPath[2]) = (leafB, hDE, hIdR);
        bytes32[] memory domainPath = new bytes32[](3);
        (domainPath[0], domainPath[1], domainPath[2]) = (leafE, hBA, hIdR);
        bytes32[] memory endpointPath = new bytes32[](3);
        (endpointPath[0], endpointPath[1], endpointPath[2]) = (leafD, hBA, hIdR);
        bytes32[] memory authorIdPath = new bytes32[](2);
        (authorIdPath[0], authorIdPath[1]) = (leafR, root4);
        bytes32[] memory receiverIdPath = new bytes32[](2);
        (receiverIdPath[0], receiverIdPath[1]) = (leafId, root4);

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
            receiverIdMerklePath: receiverIdPath,
            revealedReceiverId: revealedReceiverId,
            quotedRefMerklePath: new bytes32[](0),
            revealedQuotedRef: "",
            quotedAuthorMerklePath: new bytes32[](0),
            revealedQuotedAuthorId: ""
        });
    }

    // Happy path: a recipient-less body ("honor with ...", no @recipient) settles
    // to the id proven by the notarized `in_reply_to_user_id` leaf.
    function test_webTransfer_recipientLess_bindsProvenReplyTarget() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-implicit-1";
        string memory requestPath = "/2/tweets?ids=tweet-implicit-1";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        // X prepends the parent @bob; the command itself carries no @recipient.
        bytes memory body = abi.encodePacked("@bob @dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory receiverId = abi.encodePacked('"in_reply_to_user_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithReceiverId(
            "api.x.com", requestPath, body, authorBytes, authorId, receiverId, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        uint256 aliceBefore = bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token));
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob", // display handle (reply parent); recipient bound by the leaf, not the body
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );

        assertEq(bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token)), aliceBefore - 400e18);
        assertEq(bank.balanceOf("api.x.com", "bob", _idFor("bob"), address(token)), 400e18);
    }

    // The proven reply target (carol) must equal the backend-supplied receiverUserId
    // (bob) — a swapped receiver id reverts even with a valid leaf.
    function test_webTransfer_recipientLess_forgedReplyTarget_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-implicit-2";
        string memory requestPath = "/2/tweets?ids=tweet-implicit-2";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@carol @dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        // Leaf proves carol is the reply target...
        bytes memory receiverId = abi.encodePacked('"in_reply_to_user_id":"', _idFor("carol"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithReceiverId(
            "api.x.com", requestPath, body, authorBytes, authorId, receiverId, block.timestamp
        );
        // ...but the backend signs bob as the receiver id → mismatch.
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(ReplyTargetMismatch.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // A recipient-less body with NO proven reply target (empty receiver-id leaf,
    // e.g. a standalone tweet) must revert — recipient-less honors are reply-only.
    function test_webTransfer_recipientLess_noReplyTarget_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-implicit-3";
        string memory requestPath = "/2/tweets?ids=tweet-implicit-3";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');

        // 5-leaf builder → revealedReceiverId "" and empty receiverIdMerklePath.
        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.x.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(RecipientLessNeedsReplyTarget.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // Preflight parity: verifyProof MUST reject a recipient-less body with no proven
    // reply target (empty receiver-id leaf) — the same way webTransferV2 does —
    // instead of green-lighting a proof the transfer would then revert on.
    function test_verifyProof_recipientLess_noReplyTarget_reverts() public {
        string memory resourceId = "tweet-implicit-vp";
        string memory requestPath = "/2/tweets?ids=tweet-implicit-vp";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');

        // 5-leaf builder → revealedReceiverId "" and empty receiverIdMerklePath.
        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.x.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(RecipientLessNeedsReplyTarget.selector);
        bank.verifyProof(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // With a valid proven reply-target leaf matching the receiver id, verifyProof
    // returns true (the recipient-less gate must not over-reject the happy path).
    function test_verifyProof_recipientLess_validReplyTarget_ok() public {
        string memory resourceId = "tweet-implicit-vp2";
        string memory requestPath = "/2/tweets?ids=tweet-implicit-vp2";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@bob @dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory receiverId = abi.encodePacked('"in_reply_to_user_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithReceiverId(
            "api.x.com", requestPath, body, authorBytes, authorId, receiverId, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        assertTrue(
            bank.verifyProof(
                resource,
                SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
                body,
                notaryProof,
                backendSig,
                _idFor("bob")
            )
        );
    }

    // ── recipient-less (quote-inferred) honor: recipient = author of the quoted
    //    tweet, joined across the quoted-reference and includes-author leaves ────

    // 8-leaf-shaped proof builder: adds the quoted-reference and quoted-author recv
    // leaves (the quoted-author is self-paired to fill the tree). `_hp` is
    // commutative, so sibling order within a level does not matter.
    function _buildBankProofWithQuotedAuthor(
        string memory apiHost,
        string memory requestPath,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        bytes memory revealedAuthorId,
        bytes memory revealedQuotedRef,
        bytes memory revealedQuotedAuthorId,
        uint256 ts
    ) internal view returns (NotaryTlsProof memory proof) {
        bytes32 domainHash = keccak256(bytes(apiHost));
        bytes32 leafD = _leaf("domain:", bytes(apiHost));
        bytes32 leafE = _leaf("endpoint:", bytes(requestPath));
        bytes32 leafB = _leaf("recv:", revealedBody);
        bytes32 leafA = _leaf("recv:", revealedAuthor);
        bytes32 leafId = _leaf("recv:", revealedAuthorId);
        bytes32 leafQr = _leaf("recv:", revealedQuotedRef);
        bytes32 leafQa = _leaf("recv:", revealedQuotedAuthorId);

        bytes32 hDE = _hp(leafD, leafE);
        bytes32 hBA = _hp(leafB, leafA);
        bytes32 root4 = _hp(hDE, hBA);
        bytes32 hIdQr = _hp(leafId, leafQr);
        bytes32 hQaQa = _hp(leafQa, leafQa); // pad: quoted-author self-paired
        bytes32 rightSub = _hp(hIdQr, hQaQa);
        bytes32 transcriptRoot = _hp(root4, rightSub);

        proof.notarySig = _sign(
            NOTARY_KEY,
            keccak256(
                abi.encode(
                    block.chainid,
                    address(registry),
                    domainHash,
                    bytes32(uint256(333)),
                    bytes32(uint256(444)),
                    keccak256(hex"cafebabe"),
                    transcriptRoot,
                    ts
                )
            )
        );
        proof.domainHash = domainHash;
        proof.clientRandom = bytes32(uint256(333));
        proof.serverRandom = bytes32(uint256(444));
        proof.serverEphemeralKey = hex"cafebabe";
        proof.transcriptRoot = transcriptRoot;
        proof.timestamp = ts;
        proof.bodyMerklePath = _path3(leafA, hDE, rightSub);
        proof.authorMerklePath = _path3(leafB, hDE, rightSub);
        proof.domainMerklePath = _path3(leafE, hBA, rightSub);
        proof.endpointMerklePath = _path3(leafD, hBA, rightSub);
        proof.authorIdMerklePath = _path3(leafQr, hQaQa, root4);
        proof.receiverIdMerklePath = new bytes32[](0);
        proof.revealedReceiverId = "";
        proof.quotedRefMerklePath = _path3(leafId, hQaQa, root4);
        proof.revealedQuotedRef = revealedQuotedRef;
        proof.quotedAuthorMerklePath = _path3(leafQa, hIdQr, root4);
        proof.revealedQuotedAuthorId = revealedQuotedAuthorId;
    }

    function _path3(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](3);
        (p[0], p[1], p[2]) = (a, b, c);
    }

    // Happy path: a recipient-less body ("honor with ...", no @recipient) on a QUOTE
    // tweet settles to the author of the quoted tweet, proven by the quoted-reference
    // + includes-author leaves.
    function test_webTransfer_recipientLess_bindsQuotedAuthor() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-1";
        string memory requestPath = "/2/tweets?ids=tweet-quote-1";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        // bob authored the quoted tweet "qt-99".
        bytes memory quotedRef = abi.encodePacked('{"type":"quoted","id":"qt-99"}');
        bytes memory quotedAuthor = abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        uint256 aliceBefore = bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token));
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob", // display handle; recipient bound by the quoted-author leaf, not the body
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );

        assertEq(bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token)), aliceBefore - 400e18);
        assertEq(bank.balanceOf("api.x.com", "bob", _idFor("bob"), address(token)), 400e18);
    }

    // Real X emits `referenced_tweets` objects id-FIRST: `{"id":…,"type":"quoted"}`.
    // The quote binding must be field-order-independent — this is the exact shape
    // the live quote honor produces (the type-first happy path above proves the
    // other order). Regression for the on-chain half of the live quote fix.
    function test_webTransfer_recipientLess_bindsQuotedAuthor_idFirstOrder() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-idfirst";
        string memory requestPath = "/2/tweets?ids=tweet-quote-idfirst";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        // id-FIRST, as X actually serializes it.
        bytes memory quotedRef = abi.encodePacked('{"id":"qt-99","type":"quoted"}');
        bytes memory quotedAuthor = abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        uint256 aliceBefore = bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token));
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );

        assertEq(bank.balanceOf("api.x.com", "alice", _idFor("alice"), address(token)), aliceBefore - 400e18);
        assertEq(bank.balanceOf("api.x.com", "bob", _idFor("bob"), address(token)), 400e18);
    }

    // L6: the extracted author_id must sit in the SAME includes-tweet object as the
    // qid join. A leaf whose FIRST object (author=carol) is a decoy and whose qid
    // (qt-99) lives in a LATER object must revert — even when the backend signs the
    // decoy author — so a mis-ordered includes.tweets can't credit a non-author.
    function test_webTransfer_recipientLess_quote_authorInDifferentObject_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-obj";
        string memory requestPath = "/2/tweets?ids=tweet-quote-obj";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory quotedRef = abi.encodePacked('{"type":"quoted","id":"qt-99"}');
        // First object (decoy, carol) has a different id; qt-99 lives in the SECOND.
        bytes memory quotedAuthor = abi.encodePacked(
            '"tweets":[{"id":"other","author_id":"',
            _idFor("carol"),
            '"},{"id":"qt-99","author_id":"',
            _idFor("bob"),
            '"'
        );

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        // Backend signs carol (the decoy first-object author) as receiver.
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("carol"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(QuotedAuthorDifferentObject.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "carol",
            _idFor("carol"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // The proven quoted author (carol) must equal the backend receiverUserId (bob) —
    // a swapped author id reverts even with a valid, joined leaf.
    function test_webTransfer_recipientLess_quote_forgedAuthor_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-2";
        string memory requestPath = "/2/tweets?ids=tweet-quote-2";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory quotedRef = abi.encodePacked('{"type":"quoted","id":"qt-99"}');
        // Leaf proves carol authored the quoted tweet...
        bytes memory quotedAuthor = abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("carol"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        // ...but the backend signs bob as the receiver id → mismatch.
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(QuotedAuthorMismatch.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // Wrong-object hijack: the author leaf carries bob's author_id but for a DIFFERENT
    // tweet id than the one proven quoted (qt-99) → the join fails and reverts.
    function test_webTransfer_recipientLess_quote_wrongQuotedId_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-3";
        string memory requestPath = "/2/tweets?ids=tweet-quote-3";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory quotedRef = abi.encodePacked('{"type":"quoted","id":"qt-99"}');
        // author leaf binds bob but to tweet "qt-OTHER", not the quoted qt-99.
        bytes memory quotedAuthor = abi.encodePacked('"tweets":[{"id":"qt-OTHER","author_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(QuotedAuthorMissingQuotedId.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // A non-quoted reference (e.g. a `replied_to` entry) must not pass as a quote
    // binding: the ref leaf must contain `"type":"quoted"` (order-independent).
    function test_webTransfer_recipientLess_quote_notQuotedRef_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-4";
        string memory requestPath = "/2/tweets?ids=tweet-quote-4";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        // A replied_to reference, not a quoted one.
        bytes memory quotedRef = abi.encodePacked('{"type":"replied_to","id":"qt-99"}');
        bytes memory quotedAuthor = abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(RefNotQuote.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // Leading-decoy hijack: the recv transcript is fully committed, so a proof
    // generator can reveal ANY authentic substring as the author leaf — e.g. a
    // `data`-object span whose FIRST author_id is the sender (or any non-quoted
    // author) followed by the referenced `"id":"<qid>"`. The join would pass, but
    // the extracted author would be the wrong party. The `"tweets":[{` prefix check
    // rejects any leaf that is not the includes.tweets array.
    function test_webTransfer_recipientLess_quote_nonIncludesLeaf_reverts() public {
        _walletFor("x", "alice", ALICE_PK);
        _walletFor("x", "bob", BOB_PK);
        _fund("x", "alice", 1000e18);

        string memory resourceId = "tweet-quote-5";
        string memory requestPath = "/2/tweets?ids=tweet-quote-5";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory quotedRef = abi.encodePacked('{"type":"quoted","id":"qt-99"}');
        // A data-object-style span (NOT `"tweets":[{`): first author_id + the
        // referenced quoted id. Join passes, author = bob, but it is not includes.
        bytes memory quotedAuthor =
            abi.encodePacked('"author_id":"', _idFor("bob"), '","referenced_tweets":[{"type":"quoted","id":"qt-99"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(QuotedAuthorLeafNotIncludes.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // Preflight parity: verifyProof accepts a valid quote binding (must not over-reject).
    function test_verifyProof_recipientLess_quote_ok() public {
        string memory resourceId = "tweet-quote-vp";
        string memory requestPath = "/2/tweets?ids=tweet-quote-vp";
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka_agent honor with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        bytes memory quotedRef = abi.encodePacked('{"type":"quoted","id":"qt-99"}');
        bytes memory quotedAuthor = abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"');

        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com", requestPath, body, authorBytes, authorId, quotedRef, quotedAuthor, block.timestamp
        );
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.x.com", resourceType: "tweet", resourceId: resourceId, requestPath: requestPath
        });

        assertTrue(
            bank.verifyProof(
                resource,
                SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
                body,
                notaryProof,
                backendSig,
                _idFor("bob")
            )
        );
    }

    function _buildBackendSig(
        bytes32 uid,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        string memory receiverUserId,
        uint256 ts
    ) internal pure returns (BackendSig memory) {
        // Mirrors Bank._verifyBackendSignature (empty revealedAuthorId adds nothing).
        bytes32 digest =
            keccak256(abi.encodePacked(uid, revealedBody, revealedAuthor, keccak256(bytes(receiverUserId)), ts));
        return BackendSig({sig: _sign(BACKEND_KEY, digest), timestamp: ts});
    }

    // ═══════════════════════════════════════════════════════════════
    //  TESTS
    // ═══════════════════════════════════════════════════════════════

    // 1. Alice registers and her wallet is discoverable
    function test_registeredUserIsDiscoverable() public {
        WebWallet alice = _alice();

        assertTrue(address(alice) != address(0));
        assertEq(registry.resolve("api.x.com", "alice"), address(alice));

        (string[] memory platforms, string[] memory handles) = registry.getHandles(address(alice));
        assertEq(platforms.length, 1);
        assertEq(platforms[0], "api.x.com");
        assertEq(handles[0], "alice");
    }

    // 2. Depositing to registered user lands in registered balance
    function test_depositToRegisteredUser() public {
        WebWallet alice = _alice();

        _fund("x", "alice", 500e18);

        _assertBankBalance(alice, 500e18);
        _assertBankBalance("x", "alice", 500e18);
    }

    // 3. Depositing to unregistered user lands in unregistered balance
    function test_depositToUnregisteredUser() public {
        _fund("x", "charlie", 200e18);

        _assertUnregisteredBalance("x", "charlie", 200e18);
        _assertBankBalance("x", "charlie", 200e18);
    }

    // 4. Unregistered balance migrates when user registers and does a write
    function test_unregisteredBalanceMigratesOnWrite() public {
        _fund("x", "charlie", 300e18);

        WebWallet charlie = _charlie();
        _assertBankBalance(charlie, 300e18);
        _assertUnregisteredBalance("x", "charlie", 300e18);
        _assertRegisteredBalance(charlie, 0);

        _fund("x", "charlie", 10e18);

        _assertRegisteredBalance(charlie, 310e18);
        _assertUnregisteredBalance("x", "charlie", 0);
    }

    // 5. Alice sends TST to registered Bob via web transfer
    function test_webTransferRegisteredToRegistered() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1000e18);

        _transfer("github", "alice", "github", "bob", 400e18);

        _assertBankBalance("github", "alice", 600e18);
        _assertBankBalance("github", "bob", 400e18);
    }

    // 6. Alice sends TST to unregistered Charlie; Charlie registers and sees balance
    function test_webTransferToUnregisteredThenRegister() public {
        _walletFor("github", "alice", ALICE_PK);
        _fund("github", "alice", 500e18);

        _transfer("github", "alice", "github", "charlie", 150e18);

        _assertUnregisteredBalance("github", "charlie", 150e18);

        WebWallet charlie = _walletFor("github", "charlie", CHARLIE_PK);
        _assertBankBalance(charlie, 150e18);
    }

    // 6b. webTransfer with unregistered token by address (address-based overload)
    function test_webTransferByTokenAddress_unregistered_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);

        // Deploy a new token that is NOT registered in Bank
        MockERC20 unregToken = new MockERC20("Unregistered", "UNREG");
        unregToken.mint(address(this), 10_000e18);

        // Fund alice's wallet directly and approve bank
        WebWallet aliceWallet = WebWallet(payable(registry.resolve("api.github.com", "alice")));
        require(unregToken.transfer(address(aliceWallet), 1000e18), "transfer failed");
        // Alice approves Bank to pull tokens (auto top-up)
        bytes memory approveData = abi.encodeCall(IERC20.approve, (address(bank), type(uint256).max));
        _execute(aliceWallet, address(unregToken), approveData, ALICE_PK);

        // Use address-based webTransfer overload
        _transferCounter++;
        string memory resourceId = string(abi.encodePacked("repo/", vm.toString(_transferCounter), "/comment/1"));
        string memory requestPath =
            string(abi.encodePacked("/repos/owner/repo/issues/comments/", vm.toString(_transferCounter)));
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        // Body must contain the lowercase hex address of the token and the human-readable amount
        string memory tokenAddrHex = vm.toLowercase(vm.toString(address(unregToken)));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 400 ", tokenAddrHex);
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);

        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        // The web-transfer surface is gated to REGISTERED tokens — the by-address
        // overload must reject an unregistered ERC-20 (else autoTopUp would pull an
        // arbitrary approved token into the ledger).
        vm.expectRevert(TokenNotRegistered.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            address(unregToken),
            "400",
            400e18,
            ""
        );
    }

    // 7. Same comment cannot be used for two transfers (replay protection)
    function test_replayProtectionOnWebTransfer() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1000e18);

        _transferWithUid("replay/1", "github", "alice", "github", "bob", 100e18);

        vm.expectRevert(TransferAlreadyUsed.selector);
        _transferWithUid("replay/1", "github", "alice", "github", "bob", 100e18);
    }

    // 8. Alice withdraws from bank to her wallet via execute()
    function test_withdrawViaExecute() public {
        WebWallet alice = _alice();
        _fund("x", "alice", 500e18);

        bytes memory data = abi.encodeCall(IBank.withdraw, (address(alice), address(token), 200e18));
        _execute(alice, address(bank), data, ALICE_PK);

        _assertTokenBalance(alice, 200e18);
        _assertBankBalance(alice, 300e18);
    }

    // 9. Wallet approves ERC20 and deposits for Bob in one batch
    function test_batchApproveAndDeposit() public {
        WebWallet alice = _alice();
        _bob();
        _fundWallet(alice, 300e18);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        uint256[] memory pks = new uint256[](1);

        targets[0] = address(token);
        targets[1] = address(bank);
        values[0] = 0;
        values[1] = 0;
        datas[0] = abi.encodeCall(IERC20.approve, (address(bank), 300e18));
        datas[1] = abi.encodeCall(IBank.deposit, ("api.x.com", "bob", _idFor("bob"), address(token), 300e18));
        pks[0] = ALICE_PK;

        _executeBatch(alice, targets, values, datas, pks);

        _assertBankBalance("x", "bob", 300e18);
    }

    // 10. Multisig with 3 handles from same platform (threshold=3)
    function test_multisigThreeSamePlatform() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);

        _linkIdentityWithSessionPk(alice, "x", "alice2", ALICE_PK, ALICE_PK2);

        _linkIdentityWithSessionPk(alice, "x", "alice3", ALICE_PK, ALICE_PK3);

        _setThreshold(alice, 3, ALICE_PK);

        // 2 sigs → fails
        bytes memory data = abi.encodeCall(Registry.resolve, ("api.x.com", "alice"));
        {
            uint256[] memory pks2 = new uint256[](2);
            pks2[0] = ALICE_PK;
            pks2[1] = ALICE_PK2;
            uint256 n = alice.nonce();
            bytes32 digest =
                keccak256(abi.encode(address(registry), uint256(0), keccak256(data), n, block.chainid, address(alice)));
            bytes[] memory sigs = new bytes[](2);
            sigs[0] = _sign(pks2[0], digest);
            sigs[1] = _sign(pks2[1], digest);
            vm.expectRevert(WebWallet.ThresholdNotMet.selector);
            alice.execute(address(registry), 0, data, sigs);
        }

        // 3 sigs → succeeds
        {
            uint256[] memory pks3 = new uint256[](3);
            pks3[0] = ALICE_PK;
            pks3[1] = ALICE_PK2;
            pks3[2] = ALICE_PK3;
            _executeMulti(alice, address(registry), 0, data, pks3);
        }
    }

    // 11. Multisig with handles across different platforms (threshold=2)
    function test_multisigCrossPlatform() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);

        _linkIdentityWithSessionPk(alice, "github", "alice_gh", ALICE_PK, ALICE_PK2);

        _setThreshold(alice, 2, ALICE_PK);

        bytes memory data = abi.encodeCall(Registry.resolve, ("api.x.com", "alice"));

        // 1 sig → fails
        {
            uint256 n = alice.nonce();
            bytes32 digest =
                keccak256(abi.encode(address(registry), uint256(0), keccak256(data), n, block.chainid, address(alice)));
            bytes[] memory sigs = new bytes[](1);
            sigs[0] = _sign(ALICE_PK, digest);
            vm.expectRevert(WebWallet.ThresholdNotMet.selector);
            alice.execute(address(registry), 0, data, sigs);
        }

        // 2 sigs same identity → fails
        {
            _addSession("x", "alice", ALICE_PK3);
            uint256 n = alice.nonce();
            bytes32 digest =
                keccak256(abi.encode(address(registry), uint256(0), keccak256(data), n, block.chainid, address(alice)));
            bytes[] memory sigs = new bytes[](2);
            sigs[0] = _sign(ALICE_PK, digest);
            sigs[1] = _sign(ALICE_PK3, digest);
            vm.expectRevert(WebWallet.ThresholdNotMet.selector);
            alice.execute(address(registry), 0, data, sigs);
        }

        // 1 x + 1 github → succeeds
        {
            uint256[] memory pks = new uint256[](2);
            pks[0] = ALICE_PK;
            pks[1] = ALICE_PK2;
            _executeMulti(alice, address(registry), 0, data, pks);
        }
    }

    // 12. Upgrade wallet to V2, then execute transfer
    function test_upgradeToV2ThenExecute() public {
        WebWallet alice = _alice();

        MockWebWalletV2 v2Impl = new MockWebWalletV2();
        factory.upgradeWalletImplementation(address(v2Impl));

        bytes memory upgradeData = abi.encodeCall(WebWallet.upgradeToLatest, ());
        _execute(alice, address(alice), upgradeData, ALICE_PK);

        assertEq(MockWebWalletV2(payable(address(alice))).version(), 2);

        _fund("x", "alice", 500e18);

        bytes memory withdrawData = abi.encodeCall(IBank.withdraw, (address(alice), address(token), 200e18));
        _execute(alice, address(bank), withdrawData, ALICE_PK);

        _assertTokenBalance(alice, 200e18);
        _assertBankBalance(alice, 300e18);
    }

    // 13. Revoked session key no longer counts toward threshold
    function test_revokedSessionKeyFails() public {
        WebWallet alice = _alice();
        _addSession("x", "alice", ALICE_PK2);

        // Both keys work initially
        bytes memory data = abi.encodeCall(Registry.resolve, ("api.x.com", "alice"));
        _execute(alice, address(registry), data, ALICE_PK);

        // Revoke key1
        _revokeSession(alice, "x", "alice", vm.addr(ALICE_PK), ALICE_PK2);

        // key1 sig fails
        {
            uint256 n = alice.nonce();
            bytes32 digest =
                keccak256(abi.encode(address(registry), uint256(0), keccak256(data), n, block.chainid, address(alice)));
            bytes[] memory sigs = new bytes[](1);
            sigs[0] = _sign(ALICE_PK, digest);
            vm.expectRevert(WebWallet.ThresholdNotMet.selector);
            alice.execute(address(registry), 0, data, sigs);
        }

        // key2 succeeds
        _execute(alice, address(registry), data, ALICE_PK2);
    }

    // 14. linkIdentity adds new platform, balance aggregates across platforms
    function test_linkIdentityAggregatesBalance() public {
        WebWallet alice = _walletFor("x", "alice", ALICE_PK);

        _fund("github", "alice_gh", 250e18);

        _linkIdentityWithSessionPk(alice, "github", "alice_gh", ALICE_PK, LINK_PK1);

        _assertBankBalance(alice, 250e18);

        _fund("x", "alice", 100e18);
        _assertBankBalance(alice, 350e18);
    }

    // 15. Upgrade then verify state preserved
    function test_upgradePreservesState() public {
        WebWallet alice = _alice();
        _fund("x", "alice", 500e18);
        _linkIdentityWithSessionPk(alice, "github", "alice_gh", ALICE_PK, LINK_PK1);
        _setThreshold(alice, 2, ALICE_PK);

        // Upgrade
        MockWebWalletV2 v2Impl = new MockWebWalletV2();
        factory.upgradeWalletImplementation(address(v2Impl));
        {
            uint256[] memory pks = new uint256[](2);
            pks[0] = ALICE_PK;
            pks[1] = LINK_PK1;
            bytes memory upgradeData = abi.encodeCall(WebWallet.upgradeToLatest, ());
            _executeMulti(alice, address(alice), 0, upgradeData, pks);
        }

        // Verify state preserved
        assertEq(MockWebWalletV2(payable(address(alice))).version(), 2);
        assertEq(alice.threshold(), 2);
        assertEq(alice.identityCount(), 2);
        assertTrue(alice.isSession(vm.addr(ALICE_PK)));
        assertTrue(alice.isSession(vm.addr(LINK_PK1)));
        _assertBankBalance(alice, 500e18);
    }

    // 16. executeBatch: approve + deposit for another user atomically
    function test_batchApproveAndDepositForSelf() public {
        WebWallet alice = _alice();
        _fundWallet(alice, 1000e18);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        uint256[] memory pks = new uint256[](1);

        targets[0] = address(token);
        targets[1] = address(bank);
        values[0] = 0;
        values[1] = 0;
        datas[0] = abi.encodeCall(IERC20.approve, (address(bank), 500e18));
        datas[1] = abi.encodeCall(IBank.deposit, ("api.x.com", "alice", _idFor("alice"), address(token), 500e18));
        pks[0] = ALICE_PK;

        _executeBatch(alice, targets, values, datas, pks);

        _assertBankBalance(alice, 500e18);
        _assertTokenBalance(alice, 500e18);
    }

    // 17. linkIdentity registers session on wallet (cross-contract)
    function test_linkIdentityRegistersSession() public {
        WebWallet alice = _alice();
        _linkIdentityWithSessionPk(alice, "github", "alice_gh", ALICE_PK, LINK_PK1);

        // Session is keyed by the immutable (platform, userId), not the handle.
        bytes32 ghKey = keccak256(abi.encode("api.github.com", _idFor("alice_gh")));
        assertTrue(alice.isSession(vm.addr(LINK_PK1)));
        assertEq(alice.sessionCount(ghKey), 1);
        assertEq(alice.sessionAt(ghKey, 0), vm.addr(LINK_PK1));
    }

    // 18. webTransfer sender not registered
    function test_webTransfer_senderNotRegistered_reverts() public {
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "bob", 100e18);
        // alice is not registered on github
        vm.expectRevert(SenderNotRegistered.selector);
        _transfer("github", "alice_unregistered", "github", "bob", 50e18);
    }

    // 19. webTransfer insufficient balance
    function test_webTransfer_insufficientBalance_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 100e18);
        vm.expectRevert(); // _autoTopUp tries safeTransferFrom without allowance
        _transfer("github", "alice", "github", "bob", 200e18);
    }

    // 20. webTransfer zero amount
    function test_webTransfer_zeroAmount_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 100e18);
        vm.expectRevert(ZeroAmount.selector);
        _transferWithAmountStr("github", "alice", "github", "bob", "0", 0);
    }

    // ─── parseDecimalAmount tests ───────────────────────────────────

    // 21. Fractional transfer with 0.05 (18 decimals)
    function test_webTransfer_fractionalAmount() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1e18);

        _transferWithAmountStr("github", "alice", "github", "bob", "0.05", 5e16);

        _assertBankBalance("github", "alice", 1e18 - 5e16);
        _assertBankBalance("github", "bob", 5e16);
    }

    // 22. Fractional transfer with 1.5 (18 decimals)
    function test_webTransfer_decimalOnePointFive() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 10e18);

        _transferWithAmountStr("github", "alice", "github", "bob", "1.5", 1.5e18);

        _assertBankBalance("github", "alice", 10e18 - 1.5e18);
        _assertBankBalance("github", "bob", 1.5e18);
    }

    // 23. Integer amount still works with amountStr
    function test_webTransfer_integerAmountStr() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1000e18);

        _transferWithAmountStr("github", "alice", "github", "bob", "100", 100e18);

        _assertBankBalance("github", "alice", 900e18);
        _assertBankBalance("github", "bob", 100e18);
    }

    // 24. Amount wei mismatch reverts
    function test_webTransfer_amountWeiMismatch_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1000e18);

        vm.expectRevert(AmountWeiMismatch.selector);
        _transferWithAmountStr("github", "alice", "github", "bob", "100", 99e18);
    }

    // ─── Token registration tests ───────────────────────────────────

    /// Unregistered token name must not silently resolve to native asset.
    function test_webTransfer_unregisteredTokenName_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 100e18);

        // Build a transfer that uses "$FAKE" as token name — not registered.
        _transferCounter++;
        string memory resourceId = string(abi.encodePacked("repo/", vm.toString(_transferCounter), "/comment/1"));
        string memory requestPath =
            string(abi.encodePacked("/repos/owner/repo/issues/comments/", vm.toString(_transferCounter)));

        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 50 $FAKE");
        bytes memory authorBytes = bytes("alice");

        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        NotaryTlsProof memory notaryProof =
            _buildBankProof("api.github.com", requestPath, body, authorBytes, block.timestamp);
        BackendSig memory backendSig = _buildBackendSig(uid, body, authorBytes, "", block.timestamp);

        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(TokenNotRegistered.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: ""}),
            body,
            notaryProof,
            backendSig,
            "bob",
            "",
            "$FAKE",
            "50",
            50e18,
            ""
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  MUTATION-GUARD NEGATIVE TESTS
    //  One per revert-guard the mutation sweep found uncaught. Each feeds
    //  the bad input and asserts the exact custom error fires.
    // ═══════════════════════════════════════════════════════════════

    /// @dev Recompute the notary digest LibProof signs (chainid + registry bound).
    function _notaryDigest(NotaryTlsProof memory p) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(registry),
                p.domainHash,
                p.clientRandom,
                p.serverRandom,
                keccak256(p.serverEphemeralKey),
                p.transcriptRoot,
                p.timestamp
            )
        );
    }

    /// @dev A fully valid id-only github honor proof + backend sig + resource, for
    ///      verifyProof-direct guard tests that then tamper ONE field.
    function _validGithubProof(string memory resourceType, string memory requestPath, bytes memory body)
        internal
        view
        returns (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource)
    {
        string memory resourceId = "repo/guard/comment/1";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", resourceType, ":", resourceId));
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        notaryProof = _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        backendSig = _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        resource = ResourceInfo({
            platform: "api.github.com", resourceType: resourceType, resourceId: resourceId, requestPath: requestPath
        });
    }

    // 1. Unknown resource type (no seeded prefix) → UnknownResourceType.
    function test_UnknownResourceType_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("bogus", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(UnknownResourceType.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 2. Valid prefix ("issue_comment" → "/repos/") but the request path lacks it.
    //    The endpoint leaf is built over the SAME wrong path so it still verifies;
    //    the prefix check (before sigs) fires first → RequestPathMismatch.
    function test_RequestPathMismatch_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/wrong/path", body);
        vm.expectRevert(RequestPathMismatch.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 3. sender.author is not a substring of revealedAuthor → AuthorNotInRevealedField
    //    (the author-id leaf is valid, so the check that fires is this one).
    function test_AuthorNotInRevealedField_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(AuthorNotInRevealedField.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "notinside",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 4. verifyProof with the platform's templates cleared → TemplateNotFound (the
    //    empty-templates guard at the verifyProof level).
    function test_TemplateNotFound_emptyTemplates_reverts() public {
        bank.clearPlatformTemplates("api.github.com");
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(TemplateNotFound.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 5. A valid proof over an unrelated body that matches no template → matchAny
    //    returns false → TemplateNotFound.
    function test_TemplateNotFound_noMatch_reverts() public {
        bytes memory body = abi.encodePacked("totally unrelated text");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(TemplateNotFound.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 6. Notary digest signed by a non-notary key → InvalidNotarySignature.
    function test_InvalidNotarySignature_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        notaryProof.notarySig = _sign(uint256(0xBAD), _notaryDigest(notaryProof));
        vm.expectRevert(InvalidNotarySignature.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 7. proof.domainHash points at a different domain (and the notary signs THAT),
    //    but the domain leaf is over the real platform → DomainHashMismatch.
    function test_DomainHashMismatch_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        notaryProof.domainHash = keccak256("wrong.domain");
        notaryProof.notarySig = _sign(NOTARY_KEY, _notaryDigest(notaryProof));
        vm.expectRevert(DomainHashMismatch.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 8. An over-long merkle path (33 > 32) on the first-verified (body) leaf →
    //    MerklePathTooLong (before the Merkle check).
    function test_MerklePathTooLong_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        notaryProof.bodyMerklePath = new bytes32[](33);
        vm.expectRevert(MerklePathTooLong.selector);
        bank.verifyProof(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            _idFor("bob")
        );
    }

    // 9. _executeTransfer: sender's id was never registered (receiver is) → the
    //    sender resolveById returns 0 → SenderNotRegistered.
    function test_SenderNotRegistered_executeTransfer_reverts() public {
        _walletFor("github", "bob", BOB_PK); // receiver registered
        _fund("github", "bob", 1000e18);

        string memory resourceId = "repo/snr/comment/1";
        string memory requestPath = "/repos/owner/repo/issues/comments/1";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 400 TST");
        bytes memory authorBytes = bytes("ghost");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("ghost"), '"');

        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(SenderNotRegistered.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "ghost", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // 11. The by-ADDRESS webTransferV2 overload with token == address(0) → ZeroToken.
    function test_ZeroToken_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(ZeroToken.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            address(0),
            "5",
            5e18,
            ""
        );
    }

    // 12. sourceUrl present but not https → SourceUrlNotHttps.
    function test_SourceUrlNotHttps_reverts() public {
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(SourceUrlNotHttps.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "5",
            5e18,
            "http://github.com/owner/repo"
        );
    }

    // 13. sourceUrl https but not under the platform web prefix → SourceUrlDomainMismatch.
    //    The underlying transfer is otherwise valid (removing the guard settles it).
    function test_SourceUrlDomainMismatch_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);
        _fund("github", "alice", 1000e18);

        string memory resourceId = "repo/srcurl/comment/1";
        string memory requestPath = "/repos/owner/repo/issues/comments/1";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 400 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(SourceUrlDomainMismatch.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            "https://evil.com/owner/repo"
        );
    }

    // ── Recipient-less structural guards (LibRecipient) ──────────────────
    // Reached end-to-end: a valid recipient-less X body makes verifyTemplate flag
    // recipientLess, so webTransferV2 calls verifyRecipientIdLeaf with the tampered
    // reply/quote field BEFORE the rest of proof verification.

    ResourceInfo internal _rlResource = ResourceInfo({
        platform: "api.x.com",
        resourceType: "tweet",
        resourceId: "tweet-rl-guard",
        requestPath: "/2/tweets?ids=tweet-rl-guard"
    });

    function _rlBody() internal pure returns (bytes memory) {
        return abi.encodePacked("@dyaka_agent honor with 400 TST");
    }

    function _rlSender() internal view returns (SenderInfo memory) {
        return SenderInfo({
            author: "alice",
            revealedAuthor: bytes("alice"),
            revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
        });
    }

    function _rlBackendSig() internal view returns (BackendSig memory) {
        bytes32 uid = keccak256(abi.encodePacked("api.x.com", ":", "tweet", ":", "tweet-rl-guard"));
        return _buildBackendSigWithId(
            uid,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            _idFor("bob"),
            block.timestamp
        );
    }

    function _rlSubmit(NotaryTlsProof memory notaryProof) internal {
        bank.webTransferV2(
            _rlResource,
            _rlSender(),
            _rlBody(),
            notaryProof,
            _rlBackendSig(),
            "bob",
            _idFor("bob"),
            "TST",
            "400",
            400e18,
            ""
        );
    }

    // 20. revealedReceiverId shorter than the "in_reply_to_user_id": key.
    function test_ReplyLeafTooShort_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithReceiverId(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes('"in_reply"'),
            block.timestamp
        );
        vm.expectRevert(ReplyLeafTooShort.selector);
        _rlSubmit(notaryProof);
    }

    // 21. revealedReceiverId long enough but not the in_reply_to_user_id key.
    function test_ReplyLeafNotInReplyTo_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithReceiverId(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes('"in_reply_to_user_XX":"9"'),
            block.timestamp
        );
        vm.expectRevert(ReplyLeafNotInReplyTo.selector);
        _rlSubmit(notaryProof);
    }

    // 28. reply target value is empty ("") → EmptyQuotedValue (via _readQuotedValue).
    function test_EmptyQuotedValue_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithReceiverId(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes('"in_reply_to_user_id":""'),
            block.timestamp
        );
        vm.expectRevert(EmptyQuotedValue.selector);
        _rlSubmit(notaryProof);
    }

    // 22. quoted ref shorter than 2 bytes → QuotedRefTooShort.
    function test_QuotedRefTooShort_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes("{"),
            abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"'),
            block.timestamp
        );
        vm.expectRevert(QuotedRefTooShort.selector);
        _rlSubmit(notaryProof);
    }

    // 23. quoted ref not a {...} object → QuotedRefNotObject.
    function test_QuotedRefNotObject_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes("XY"),
            abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"'),
            block.timestamp
        );
        vm.expectRevert(QuotedRefNotObject.selector);
        _rlSubmit(notaryProof);
    }

    // 24. quoted ref with a nested { } inside → QuotedRefNotFlatObject.
    function test_QuotedRefNotFlatObject_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes("{{}}"),
            abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"'),
            block.timestamp
        );
        vm.expectRevert(QuotedRefNotFlatObject.selector);
        _rlSubmit(notaryProof);
    }

    // 25. flat quoted ref with type:quoted but no "id" → QuotedRefMissingId.
    function test_QuotedRefMissingId_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes('{"type":"quoted"}'),
            abi.encodePacked('"tweets":[{"id":"qt-99","author_id":"', _idFor("bob"), '"'),
            block.timestamp
        );
        vm.expectRevert(QuotedRefMissingId.selector);
        _rlSubmit(notaryProof);
    }

    // 26. includes-tweets leaf shorter than the "tweets":[{ key → QuotedAuthorLeafTooShort.
    function test_QuotedAuthorLeafTooShort_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes('{"type":"quoted","id":"qt-99"}'),
            bytes('"tweets"'),
            block.timestamp
        );
        vm.expectRevert(QuotedAuthorLeafTooShort.selector);
        _rlSubmit(notaryProof);
    }

    // 27. includes-tweets leaf has the qid join but no author_id → QuotedAuthorMissingAuthorId.
    function test_QuotedAuthorMissingAuthorId_reverts() public {
        NotaryTlsProof memory notaryProof = _buildBankProofWithQuotedAuthor(
            "api.x.com",
            _rlResource.requestPath,
            _rlBody(),
            bytes("alice"),
            abi.encodePacked('"author_id":"', _idFor("alice"), '"'),
            bytes('{"type":"quoted","id":"qt-99"}'),
            bytes('"tweets":[{"id":"qt-99"'),
            block.timestamp
        );
        vm.expectRevert(QuotedAuthorMissingAuthorId.selector);
        _rlSubmit(notaryProof);
    }

    // 29. amountStr with two decimal points → MultipleDecimalPoints (parseDecimalAmount).
    //    The explicit github template matches "1.2.3" as the amount, then _webTransfer
    //    parses it. amount (999e18) is deliberately non-matching so removing the guard
    //    yields AmountWeiMismatch, not this error.
    function test_MultipleDecimalPoints_reverts() public {
        _walletFor("github", "alice", ALICE_PK);
        _walletFor("github", "bob", BOB_PK);

        string memory resourceId = "repo/dec/comment/1";
        string memory requestPath = "/repos/owner/repo/issues/comments/1";
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 1.2.3 TST");
        bytes memory authorBytes = bytes("alice");
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor("alice"), '"');
        NotaryTlsProof memory notaryProof =
            _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        BackendSig memory backendSig =
            _buildBackendSigWithId(uid, body, authorBytes, authorId, _idFor("bob"), block.timestamp);
        ResourceInfo memory resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });

        vm.expectRevert(LibString.MultipleDecimalPoints.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({author: "alice", revealedAuthor: authorBytes, revealedAuthorId: authorId}),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "1.2.3",
            999e18,
            ""
        );
    }

    // 31. by-name webTransferV2 for a platform with NO templates → LibTemplate
    //     .verifyTemplate hits count == 0 → TemplateNotFound (distinct from the
    //     verifyProof-level guard; removing it yields NoTemplateMatch instead).
    function test_TemplateNotFound_verifyTemplateEmpty_reverts() public {
        bank.clearPlatformTemplates("api.github.com");
        bytes memory body = abi.encodePacked("@dyaka-agent honor @bob with 5 TST");
        (NotaryTlsProof memory notaryProof, BackendSig memory backendSig, ResourceInfo memory resource) =
            _validGithubProof("issue_comment", "/repos/owner/repo/issues/comments/1", body);
        vm.expectRevert(TemplateNotFound.selector);
        bank.webTransferV2(
            resource,
            SenderInfo({
                author: "alice",
                revealedAuthor: bytes("alice"),
                revealedAuthorId: abi.encodePacked('"author_id":"', _idFor("alice"), '"')
            }),
            body,
            notaryProof,
            backendSig,
            "bob",
            _idFor("bob"),
            "TST",
            "5",
            5e18,
            ""
        );
    }
}
