// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {LibCoreStorage} from "../storage/LibCoreStorage.sol";
import {NotaryTlsProof} from "../BankTypes.sol";
import {
    InvalidNotarySignature,
    InvalidBackendSignature,
    InvalidMerkleProof,
    MerklePathTooLong,
    DomainHashMismatch
} from "../BankErrors.sol";
import {INotary} from "../../../notary/INotary.sol";

/// @title LibProof — TLS-notary proof + backend-signature verification.
/// @dev Merkle-leaf membership (recv / domain / endpoint), the notary attestation
///      signature, and the backend authorization signature. Reads trusted-party
///      pointers from `LibCoreStorage`; ECDSA/Merkle via OpenZeppelin.
library LibProof {
    /// @dev The shared leaf verifier: reject an over-long path, hash the
    ///      double-keccak leaf from `preimage`, and check Merkle membership.
    ///      Every leaf kind differs only in its `preimage` (a `prefix`+data blob).
    function verifyLeaf(bytes32[] calldata path, bytes32 root, bytes memory preimage) internal pure {
        if (path.length > 32) revert MerklePathTooLong();
        bytes32 leaf = keccak256(bytes.concat(keccak256(preimage)));
        if (!MerkleProof.verify(path, root, leaf)) revert InvalidMerkleProof();
    }

    /// @dev A recv-transcript leaf (`"recv:"` + revealed bytes) — used for the
    ///      body, author, author-id, reply-target, and quote leaves.
    function verifyRecvLeaf(bytes32[] calldata path, bytes32 root, bytes calldata data) internal pure {
        verifyLeaf(path, root, abi.encodePacked("recv:", data));
    }

    /// @dev The domain leaf; also binds `domain` to the proof's `expectedDomainHash`.
    function verifyDomainLeaf(bytes32[] calldata path, bytes32 root, string calldata domain, bytes32 expectedDomainHash)
        internal
        pure
    {
        if (keccak256(bytes(domain)) != expectedDomainHash) revert DomainHashMismatch();
        verifyLeaf(path, root, abi.encodePacked("domain:", domain));
    }

    /// @dev The endpoint (request-path) leaf.
    function verifyEndpointLeaf(bytes32[] calldata path, bytes32 root, string calldata endpoint) internal pure {
        verifyLeaf(path, root, abi.encodePacked("endpoint:", endpoint));
    }

    /// @dev Verify the notary attestation over the TLS-session digest.
    ///      Binds `block.chainid` + the current `registry` so a proof can't cross
    ///      chains or survive a Registry migration. The shared Notary contract
    ///      (`cs.notary`) owns the attestation check itself.
    function verifyNotarySignature(NotaryTlsProof calldata proof) internal view {
        LibCoreStorage.CoreStorage storage cs = LibCoreStorage.store();
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                cs.registry,
                proof.domainHash,
                proof.clientRandom,
                proof.serverRandom,
                keccak256(proof.serverEphemeralKey),
                proof.transcriptRoot,
                proof.timestamp
            )
        );
        if (!INotary(cs.notary).verify(digest, proof.notarySig)) revert InvalidNotarySignature();
    }

    /// @dev Verify the backend authorization signature. `receiverUserId` is signed
    ///      (hashed, to stay unambiguous next to the variable-length byte fields)
    ///      so a relayer can't redirect credit to another id.
    function verifyBackendSignature(
        bytes32 uid,
        bytes calldata revealedSubsection,
        bytes calldata revealedAuthor,
        bytes calldata revealedAuthorId,
        string calldata receiverUserId,
        bytes calldata sig,
        uint256 timestamp
    ) internal view {
        // Each of the three dynamic byte fields is independently Merkle-verified
        // against transcriptRoot (verifyRecvLeaf on body/author/authorId), so a
        // boundary re-split can't be forged — plain encodePacked is safe here.
        bytes32 digest = keccak256(
            abi.encodePacked(
                uid, revealedSubsection, revealedAuthor, revealedAuthorId, keccak256(bytes(receiverUserId)), timestamp
            )
        );
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), sig);
        if (signer != LibCoreStorage.store().backend) revert InvalidBackendSignature();
    }
}
