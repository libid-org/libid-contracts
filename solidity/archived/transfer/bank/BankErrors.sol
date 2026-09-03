// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Shared Bank custom errors ─────────────────────────────────────────────
// File-level errors imported by the Bank facets + logic libraries. Replaces the
// monolith's mix of `error` declarations and `require("string")` reverts with a
// single, cheap (4-byte selector) error set. Library-private errors (e.g.
// LibString's parse errors) stay in their library.

// Admin / config
error ZeroAddress();
error EmptyName();
error AlreadyRegistered();
error NotRegistered();

// Token registry
error TokenNotRegistered();

// Template matching
error TemplateNotFound();
error NoTemplateMatch(); // no template matched with the correct recipient/amount/token
error TemplateMissingToken(); // template has {amount} but no {token}
error TemplateMissingAmount(); // template has {recipient} but no {amount}
error TemplateMissingTokenAfterRecipient(); // template has {recipient}/{amount} but no {token}

// Proof / signatures
error InvalidNotarySignature();
error InvalidBackendSignature();
error InvalidMerkleProof();
error MerklePathTooLong();
error DomainHashMismatch();

// Recipient binding (reply-inferred / quote-inferred honor)
error RecipientLessNeedsReplyTarget();
error ReplyLeafTooShort();
error ReplyLeafNotInReplyTo();
error ReplyTargetMismatch();
error ReplyTargetIdNotQuoted();
error QuotedRefTooShort();
error QuotedRefNotObject();
error QuotedRefNotFlatObject();
error RefNotQuote();
error QuotedRefMissingId();
error QuotedAuthorLeafTooShort();
error QuotedAuthorLeafNotIncludes();
error QuotedAuthorMissingQuotedId();
error QuotedAuthorMissingAuthorId();
error QuotedAuthorDifferentObject();
error QuotedAuthorMismatch();
error EmptyQuotedValue(); // an extracted "…" reply-target / quoted id / author-id value is empty

// Transfer / escrow
error TransferAlreadyUsed();
error ZeroAmount();
error InsufficientBalance();
error SenderNotRegistered();
error UserIdRequired();
error UnknownResourceType();
error RequestPathMismatch();
error AmountWeiMismatch();
error ZeroToken();
error AuthorNotInRevealedField();

// Native asset
error NativeTransferFailed();
error NativeAmountMismatch();
error NativeSentWithErc20();

// Allowance
error InsufficientAllowance(address token, address owner, address spender, uint256 required, uint256 actual);

// Source URL
error SourceUrlNotHttps();
error SourceUrlDomainMismatch();

// Lifecycle
error EnforcedPause();
error ReentrantCall();
error AlreadyInitialized();
