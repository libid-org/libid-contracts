// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {ResourceInfo, SenderInfo, BackendSig, NotaryTlsProof} from "../bank/BankTypes.sol";
import {TransferFacet} from "../bank/facets/TransferFacet.sol";
import {VaultFacet} from "../bank/facets/VaultFacet.sol";
import {AdminFacet} from "../bank/facets/AdminFacet.sol";
import {IRegistry} from "../../login/IRegistry.sol";
import {MockERC20} from "../MockERC20.sol";
import {InvalidMerkleProof, NoTemplateMatch} from "../bank/BankErrors.sol";

/// @dev Minimal Notary — accepts an EIP-191 signature from the one signer.
contract MockNotary {
    address public immutable notary;

    constructor(address signer_) {
        notary = signer_;
    }

    function verify(bytes32 digest, bytes calldata proof) external view returns (bool) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        return ECDSA.recover(ethHash, proof) == notary;
    }
}

/// @dev Minimal Registry — id→wallet resolution set directly (no proof harness).
contract MockRegistry is IRegistry {
    mapping(bytes32 => address) internal _byId;
    mapping(address => string[]) internal _platforms;
    mapping(address => string[]) internal _ids;

    function setId(string calldata platform, string calldata id, address wallet) external {
        _byId[keccak256(abi.encode(platform, id))] = wallet;
        _platforms[wallet].push(platform);
        _ids[wallet].push(id);
    }

    function resolveById(string calldata platform, string calldata id) external view returns (address) {
        return _byId[keccak256(abi.encode(platform, id))];
    }

    function getUserIds(address wallet) external view returns (string[] memory, string[] memory) {
        return (_platforms[wallet], _ids[wallet]);
    }

    function getHandles(address wallet) external view returns (string[] memory, string[] memory) {
        return (_platforms[wallet], _ids[wallet]);
    }

    function resolve(string calldata, string calldata) external pure returns (address) {
        return address(0);
    }

    function handleHint(string calldata, string calldata) external pure returns (string memory) {
        return "";
    }
}

/// @title BankDiamondHonorTest — end-to-end honor flow on the assembled diamond.
/// @dev Validates the ported TransferFacet orchestration (LibProof + LibTemplate +
///      LibEscrow) with real notary/backend signatures + Merkle proofs, using mock
///      Registry/Notary so the identity layer needs no proof harness. Proof
///      math mirrors Integration.t.sol's `_buildBankProofWithId`.
contract BankDiamondHonorTest is Test, BankDiamondDeployer {
    uint256 constant NOTARY_KEY = 0xA11CE;
    uint256 constant BACKEND_KEY = 0xB0B;
    address constant ALICE_WALLET = address(0xA1);
    address constant BOB_WALLET = address(0xB2);

    address diamond;
    MockRegistry registry;
    MockERC20 token;

    function setUp() public {
        MockNotary notaryReg = new MockNotary(vm.addr(NOTARY_KEY));
        registry = new MockRegistry();
        diamond = deployBankDiamond(address(this), address(notaryReg), vm.addr(BACKEND_KEY), address(registry));

        token = new MockERC20("Test", "TST");
        AdminFacet(diamond).registerToken("TST", address(token));

        // alice + bob are registered (id → wallet); fund alice via deposit.
        registry.setId("api.github.com", _idFor("alice"), ALICE_WALLET);
        registry.setId("api.github.com", _idFor("bob"), BOB_WALLET);

        token.mint(address(this), 1000e18);
        token.approve(diamond, 1000e18);
        VaultFacet(diamond).deposit("api.github.com", "alice", _idFor("alice"), address(token), 1000e18);
    }

    function test_honorHappyPath_movesBalances() public {
        (
            ResourceInfo memory resource,
            SenderInfo memory sender,
            bytes memory body,
            NotaryTlsProof memory proof,
            BackendSig memory bsig
        ) = _honor(
            "repo/x/comment/1", "/repos/o/r/issues/comments/1", "@dyaka-agent honor @bob with 400 TST", "alice", "bob"
        );

        uint256 aliceBefore = VaultFacet(diamond).balanceOf("api.github.com", "alice", _idFor("alice"), address(token));
        TransferFacet(diamond)
            .webTransferV2(resource, sender, body, proof, bsig, "bob", _idFor("bob"), "TST", "400", 400e18, "");

        assertEq(
            VaultFacet(diamond).balanceOf("api.github.com", "alice", _idFor("alice"), address(token)),
            aliceBefore - 400e18
        );
        assertEq(VaultFacet(diamond).balanceOf("api.github.com", "bob", _idFor("bob"), address(token)), 400e18);
    }

    /// Forged author-id (victim id) with no proven author-id leaf → recv-leaf rejects.
    function test_honorForgedAuthorId_reverts() public {
        (
            ResourceInfo memory resource,
            SenderInfo memory sender,
            bytes memory body,
            NotaryTlsProof memory proof,
            BackendSig memory bsig
        ) = _honor(
            "repo/x/comment/2", "/repos/o/r/issues/comments/2", "@dyaka-agent honor @bob with 400 TST", "alice", "bob"
        );

        sender.revealedAuthorId = abi.encodePacked('"author_id":"', _idFor("bob"), '"'); // forged, not in proof
        vm.expectRevert(InvalidMerkleProof.selector);
        TransferFacet(diamond)
            .webTransferV2(resource, sender, body, proof, bsig, "bob", _idFor("bob"), "TST", "400", 400e18, "");
    }

    /// Body honors bob but caller swaps receiverHandle → recipient bind rejects.
    function test_honorRecipientSwap_reverts() public {
        (
            ResourceInfo memory resource,
            SenderInfo memory sender,
            bytes memory body,
            NotaryTlsProof memory proof,
            BackendSig memory bsig
        ) = _honor(
            "repo/x/comment/3", "/repos/o/r/issues/comments/3", "@dyaka-agent honor @bob with 400 TST", "alice", "bob"
        );

        vm.expectRevert(NoTemplateMatch.selector);
        TransferFacet(diamond)
            .webTransferV2(
                resource, sender, body, proof, bsig, "attacker", _idFor("attacker"), "TST", "400", 400e18, ""
            );
    }

    // ── proof helpers (mirror Integration.t.sol) ─────────────────────────

    function _honor(
        string memory resourceId,
        string memory requestPath,
        string memory bodyStr,
        string memory senderHandle,
        string memory receiverHandle
    )
        internal
        view
        returns (
            ResourceInfo memory resource,
            SenderInfo memory sender,
            bytes memory body,
            NotaryTlsProof memory proof,
            BackendSig memory bsig
        )
    {
        body = bytes(bodyStr);
        bytes memory authorBytes = bytes(senderHandle);
        bytes memory authorId = abi.encodePacked('"author_id":"', _idFor(senderHandle), '"');
        bytes32 uid = keccak256(abi.encodePacked("api.github.com", ":", "issue_comment", ":", resourceId));

        proof = _buildBankProofWithId("api.github.com", requestPath, body, authorBytes, authorId, block.timestamp);
        bsig = _buildBackendSig(uid, body, authorBytes, authorId, _idFor(receiverHandle), block.timestamp);
        resource = ResourceInfo({
            platform: "api.github.com", resourceType: "issue_comment", resourceId: resourceId, requestPath: requestPath
        });
        sender = SenderInfo({author: senderHandle, revealedAuthor: authorBytes, revealedAuthorId: authorId});
    }

    function _idFor(string memory handle) internal pure returns (string memory) {
        return string(abi.encodePacked("id-", handle));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _leaf(string memory prefix, bytes memory value) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
    }

    function _hp(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _buildBankProofWithId(
        string memory apiHost,
        string memory requestPath,
        bytes memory revealedBody,
        bytes memory revealedAuthor,
        bytes memory revealedAuthorId,
        uint256 ts
    ) internal view returns (NotaryTlsProof memory proof) {
        bytes32 domainHash = keccak256(bytes(apiHost));
        bytes memory serverEphKey = hex"cafebabe";

        bytes32 leafD = _leaf("domain:", bytes(apiHost));
        bytes32 leafE = _leaf("endpoint:", bytes(requestPath));
        bytes32 leafB = _leaf("recv:", revealedBody);
        bytes32 leafA = _leaf("recv:", revealedAuthor);
        bytes32 leafId = _leaf("recv:", revealedAuthorId);

        bytes32 hDE = _hp(leafD, leafE);
        bytes32 hBA = _hp(leafB, leafA);
        bytes32 root4 = _hp(hDE, hBA);
        bytes32 transcriptRoot = _hp(root4, leafId);

        proof.domainHash = domainHash;
        proof.clientRandom = bytes32(uint256(333));
        proof.serverRandom = bytes32(uint256(444));
        proof.serverEphemeralKey = serverEphKey;
        proof.transcriptRoot = transcriptRoot;
        proof.timestamp = ts;

        proof.bodyMerklePath = _path3(leafA, hDE, leafId);
        proof.authorMerklePath = _path3(leafB, hDE, leafId);
        proof.domainMerklePath = _path3(leafE, hBA, leafId);
        proof.endpointMerklePath = _path3(leafD, hBA, leafId);
        proof.authorIdMerklePath = new bytes32[](1);
        proof.authorIdMerklePath[0] = root4;

        bytes32 notaryDigest = keccak256(
            abi.encode(
                block.chainid,
                address(registry),
                domainHash,
                proof.clientRandom,
                proof.serverRandom,
                keccak256(serverEphKey),
                transcriptRoot,
                ts
            )
        );
        proof.notarySig = _sign(NOTARY_KEY, notaryDigest);
    }

    function _buildBackendSig(
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

    function _path3(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](3);
        (p[0], p[1], p[2]) = (a, b, c);
    }
}
