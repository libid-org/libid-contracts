// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BankTypes — shared calldata structs for the Bank facets + logic libs.
/// @dev The honor-transfer call surface (resource / sender / backend-sig / TLS
///      proof). Extracted from the monolith so facets and `LibProof` /
///      `LibRecipient` reference one definition.

struct ResourceInfo {
    string platform; // API domain (e.g. "api.x.com", "api.github.com")
    string resourceType;
    string resourceId;
    string requestPath;
}

/// `revealedAuthorId` present → id parsed on-chain, id-keyed; empty → handle path.
struct SenderInfo {
    string author;
    bytes revealedAuthor;
    bytes revealedAuthorId;
}

struct BackendSig {
    bytes sig;
    uint256 timestamp;
}

struct NotaryTlsProof {
    bytes notarySig;
    bytes32 domainHash;
    bytes32 clientRandom;
    bytes32 serverRandom;
    bytes serverEphemeralKey;
    bytes32 transcriptRoot;
    uint256 timestamp;
    bytes32[] bodyMerklePath;
    bytes32[] authorMerklePath;
    bytes32[] domainMerklePath;
    bytes32[] endpointMerklePath;
    bytes32[] authorIdMerklePath; // empty for the legacy handle path
    bytes32[] receiverIdMerklePath; // recipient-less reply honor: reply-target id leaf
    bytes revealedReceiverId; // revealed "in_reply_to_user_id":"<id>" snippet
    bytes32[] quotedRefMerklePath; // recipient-less quote honor: referenced_tweets quoted leaf
    bytes revealedQuotedRef; // revealed {"type":"quoted","id":"<qid>"} snippet
    bytes32[] quotedAuthorMerklePath; // recipient-less quote honor: includes quoted-tweet author leaf
    bytes revealedQuotedAuthorId; // revealed includes span binding "id":"<qid>" + "author_id":"<rid>"
}
