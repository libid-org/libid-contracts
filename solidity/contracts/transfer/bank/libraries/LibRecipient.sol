// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibString} from "./LibString.sol";
import {LibProof} from "./LibProof.sol";
import {NotaryTlsProof} from "../BankTypes.sol";
import {
    RecipientLessNeedsReplyTarget,
    ReplyLeafTooShort,
    ReplyLeafNotInReplyTo,
    ReplyTargetMismatch,
    ReplyTargetIdNotQuoted,
    QuotedRefTooShort,
    QuotedRefNotObject,
    QuotedRefNotFlatObject,
    RefNotQuote,
    QuotedRefMissingId,
    QuotedAuthorLeafTooShort,
    QuotedAuthorLeafNotIncludes,
    QuotedAuthorMissingQuotedId,
    QuotedAuthorMissingAuthorId,
    QuotedAuthorDifferentObject,
    QuotedAuthorMismatch,
    EmptyQuotedValue
} from "../BankErrors.sol";

/// @title LibRecipient — recipient binding for the recipient-less honor form.
/// @dev The body proves no `{recipient}`, so the recipient comes from a notarized
///      reply target (`in_reply_to_user_id`) or the quoted tweet's author. Each
///      binding is pinned to its specific field so a proof generator can't reveal
///      an arbitrary transcript id. Uses `LibProof.verifyRecvLeaf` for Merkle
///      membership and `LibString` for structural checks / value extraction.
library LibRecipient {
    /// @dev Reply leaf takes precedence; otherwise a quote binding is required.
    function verifyRecipientIdLeaf(NotaryTlsProof calldata proof, string calldata receiverUserId) internal pure {
        if (proof.revealedReceiverId.length > 0) {
            verifyReplyTargetLeaf(proof, receiverUserId);
            return;
        }
        if (proof.revealedQuotedRef.length == 0) revert RecipientLessNeedsReplyTarget();
        verifyQuotedAuthorLeaf(proof, receiverUserId);
    }

    /// @dev Reply binding: the revealed `"in_reply_to_user_id":"<id>"` leaf, with
    ///      its id equal to the backend-signed `receiverUserId`. Pinned to the
    ///      reply-target field (not "some id in the transcript").
    function verifyReplyTargetLeaf(NotaryTlsProof calldata proof, string calldata receiverUserId) internal pure {
        bytes calldata leaf = proof.revealedReceiverId;
        bytes memory key = bytes('"in_reply_to_user_id":');
        if (leaf.length < key.length) revert ReplyLeafTooShort();
        for (uint256 i = 0; i < key.length; i++) {
            if (leaf[i] != key[i]) revert ReplyLeafNotInReplyTo();
        }
        LibProof.verifyRecvLeaf(proof.receiverIdMerklePath, proof.transcriptRoot, leaf);
        if (keccak256(bytes(extractReplyTargetId(leaf, key.length))) != keccak256(bytes(receiverUserId))) {
            revert ReplyTargetMismatch();
        }
    }

    /// @dev Quote binding: recipient = author of the quoted tweet, joined across
    ///      two notarized leaves so the bound id is unambiguously the quoted
    ///      author (not the sender, a mention, or a reply parent):
    ///        - `revealedQuotedRef`  — a flat `{…}` `referenced_tweets` object
    ///          containing `"type":"quoted"` and the quoted parent's `"id":"<qid>"`
    ///          (field order not assumed).
    ///        - `revealedQuotedAuthorId` — an `includes.tweets` slice STARTING with
    ///          `"tweets":[{` (so its first `author_id` is a real includes-tweet
    ///          author, not the sender's `data.author_id`) that contains the join
    ///          `"id":"<qid>"` in the SAME object as the extracted `author_id`.
    ///      Require the extracted author == `receiverUserId`.
    function verifyQuotedAuthorLeaf(NotaryTlsProof calldata proof, string calldata receiverUserId) internal pure {
        bytes calldata refLeaf = proof.revealedQuotedRef;
        if (refLeaf.length < 2) revert QuotedRefTooShort();
        if (refLeaf[0] != "{" || refLeaf[refLeaf.length - 1] != "}") revert QuotedRefNotObject();
        for (uint256 i = 1; i + 1 < refLeaf.length; i++) {
            if (refLeaf[i] == "{" || refLeaf[i] == "}") revert QuotedRefNotFlatObject();
        }
        if (!LibString.contains(refLeaf, bytes('"type":"quoted"'), false)) revert RefNotQuote();
        LibProof.verifyRecvLeaf(proof.quotedRefMerklePath, proof.transcriptRoot, refLeaf);
        (bool hasQid, uint256 qidPos) = LibString.indexOf(refLeaf, bytes('"id":"'), 0, false);
        if (!hasQid) revert QuotedRefMissingId();
        string memory qid = _readQuotedValue(refLeaf, qidPos + 6); // '"id":"'.length == 6

        bytes calldata authorLeaf = proof.revealedQuotedAuthorId;
        bytes memory tweetsKey = bytes('"tweets":[{');
        if (authorLeaf.length <= tweetsKey.length) revert QuotedAuthorLeafTooShort();
        for (uint256 i = 0; i < tweetsKey.length; i++) {
            if (authorLeaf[i] != tweetsKey[i]) revert QuotedAuthorLeafNotIncludes();
        }
        LibProof.verifyRecvLeaf(proof.quotedAuthorMerklePath, proof.transcriptRoot, authorLeaf);

        // Join: the leaf must contain the quoted tweet object (id == qid).
        (bool hasId, uint256 idPos) = LibString.indexOf(authorLeaf, abi.encodePacked('"id":"', qid, '"'), 0, false);
        if (!hasId) revert QuotedAuthorMissingQuotedId();
        // Bind the extracted author to the SAME includes-tweet object as the qid
        // join: no `}` (object close) between the `author_id` and the qid match.
        (bool hasAuthor, uint256 authorPos) = LibString.indexOf(authorLeaf, bytes('"author_id":"'), 0, false);
        if (!hasAuthor) revert QuotedAuthorMissingAuthorId();
        uint256 lo = authorPos < idPos ? authorPos : idPos;
        uint256 hi = authorPos < idPos ? idPos : authorPos;
        for (uint256 i = lo; i < hi; i++) {
            if (authorLeaf[i] == "}") revert QuotedAuthorDifferentObject();
        }
        string memory rid = _readQuotedValue(authorLeaf, authorPos + 13); // '"author_id":"'.length == 13
        if (keccak256(bytes(rid)) != keccak256(bytes(receiverUserId))) revert QuotedAuthorMismatch();
    }

    /// @dev The `in_reply_to_user_id` value, anchored at `prefixLen` (the length of
    ///      the already-verified `"in_reply_to_user_id":` prefix). Requires the
    ///      opening quote, so a trailing colon-separated id can't override it.
    function extractReplyTargetId(bytes calldata leaf, uint256 prefixLen) internal pure returns (string memory) {
        if (prefixLen >= leaf.length || leaf[prefixLen] != '"') revert ReplyTargetIdNotQuoted();
        return _readQuotedValue(leaf, prefixLen + 1);
    }

    /// @dev Read a `"…"` value: from `valueStart` up to the next `"`. The shared
    ///      extraction behind all three id fields. Reverts on an empty value.
    function _readQuotedValue(bytes calldata leaf, uint256 valueStart) internal pure returns (string memory) {
        uint256 ve = valueStart;
        while (ve < leaf.length && leaf[ve] != '"') ve++;
        if (ve <= valueStart) revert EmptyQuotedValue();
        return string(leaf[valueStart:ve]);
    }
}
