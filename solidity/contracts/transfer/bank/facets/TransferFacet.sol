// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {BankModifiers} from "../BankModifiers.sol";
import {ResourceInfo, SenderInfo, BackendSig, NotaryTlsProof} from "../BankTypes.sol";
import {IRegistry} from "../../../login/IRegistry.sol";

import {LibProof} from "../libraries/LibProof.sol";
import {LibTemplate} from "../libraries/LibTemplate.sol";
import {LibRecipient} from "../libraries/LibRecipient.sol";
import {LibEscrow} from "../libraries/LibEscrow.sol";
import {LibString} from "../libraries/LibString.sol";

import {LibCoreStorage} from "../storage/LibCoreStorage.sol";
import {LibEscrowStorage} from "../storage/LibEscrowStorage.sol";
import {LibTemplateStorage} from "../storage/LibTemplateStorage.sol";
import {LibTokenStorage} from "../storage/LibTokenStorage.sol";

import {
    UnknownResourceType,
    RequestPathMismatch,
    AuthorNotInRevealedField,
    TemplateNotFound,
    TokenNotRegistered,
    ZeroToken,
    AmountWeiMismatch,
    TransferAlreadyUsed,
    ZeroAmount,
    SenderNotRegistered,
    SourceUrlNotHttps,
    SourceUrlDomainMismatch
} from "../BankErrors.sol";

/// @title TransferFacet — the honor-transfer flow (proof → verify → move funds).
/// @dev Orchestrates the logic libs: `LibProof` (notary + backend + Merkle leaves),
///      `LibTemplate` (command match), `LibRecipient` (recipient-less binding), and
///      `LibEscrow` (id resolve + ledgers). Fresh deploy is id-only — the sender
///      is resolved from the proven author-id, the receiver from the proven
///      recipient id; handles are display-only (event fields). The two
///      `webTransferV2` overloads (token by-name / by-address) share `_webTransfer`.
contract TransferFacet is BankModifiers {
    event WebTransferV3(
        address indexed senderWallet,
        address indexed receiverWallet,
        string receiverPlatform,
        string receiverHandle,
        string receiverUserId,
        address indexed token,
        uint256 amount,
        string sourceUrl
    );
    event TransferWithin(
        address indexed sender,
        string receiverPlatform,
        string receiverHandle,
        string receiverUserId,
        address indexed token,
        uint256 amount
    );

    // ── Preflight ────────────────────────────────────────────────────────

    /// @notice Verify a TLS-notarized comment proof with no state changes. Reverts
    ///         with a descriptive error on any failure. Returns true when valid.
    function verifyProof(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverUserId
    ) public view returns (bool) {
        bytes32 uid = _uid(resource);

        string memory prefix = LibTemplateStorage.store().resourceTypePrefixes[keccak256(bytes(resource.resourceType))];
        if (bytes(prefix).length == 0) revert UnknownResourceType();
        if (!LibString.contains(bytes(resource.requestPath), bytes(prefix), false)) revert RequestPathMismatch();

        LibProof.verifyNotarySignature(notaryTlsProof);
        LibProof.verifyRecvLeaf(notaryTlsProof.bodyMerklePath, notaryTlsProof.transcriptRoot, revealedSubsection);
        LibProof.verifyRecvLeaf(notaryTlsProof.authorMerklePath, notaryTlsProof.transcriptRoot, sender.revealedAuthor);
        LibProof.verifyDomainLeaf(
            notaryTlsProof.domainMerklePath, notaryTlsProof.transcriptRoot, resource.platform, notaryTlsProof.domainHash
        );
        LibProof.verifyEndpointLeaf(
            notaryTlsProof.endpointMerklePath, notaryTlsProof.transcriptRoot, resource.requestPath
        );
        if (!LibString.contains(sender.revealedAuthor, bytes(sender.author), false)) revert AuthorNotInRevealedField();

        // id-only: the author id is always proven and parsed at resolve time.
        LibProof.verifyRecvLeaf(
            notaryTlsProof.authorIdMerklePath, notaryTlsProof.transcriptRoot, sender.revealedAuthorId
        );

        LibProof.verifyBackendSignature(
            uid,
            revealedSubsection,
            sender.revealedAuthor,
            sender.revealedAuthorId,
            receiverUserId,
            backendSigData.sig,
            backendSigData.timestamp
        );

        bytes32 platformKey = keccak256(bytes(resource.platform));
        if (LibTemplateStorage.store().platformTemplates[platformKey].length == 0) revert TemplateNotFound();
        (bool matched,,, bool recipientLess) = LibTemplate.matchAnyTemplate(revealedSubsection, platformKey);
        if (!matched) revert TemplateNotFound();

        // Recipient-less honor: the body does not prove the recipient, so preflight
        // must apply the SAME reply-target binding that webTransferV2 enforces —
        // else verifyProof would green-light a proof the transfer then reverts.
        if (recipientLess) {
            LibRecipient.verifyRecipientIdLeaf(notaryTlsProof, receiverUserId);
        }

        return true;
    }

    /// @dev The transfer uid: keccak of platform:resourceType:resourceId.
    function _uid(ResourceInfo calldata resource) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(resource.platform, ":", resource.resourceType, ":", resource.resourceId));
    }

    // ── Web transfer (comment proof → funds) ─────────────────────────────

    /// @notice Execute a web transfer (token by name) with source URL.
    function webTransferV2(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverHandle,
        string calldata receiverUserId,
        string calldata tokenName_,
        string calldata amountStr,
        uint256 amount,
        string calldata sourceUrl
    ) external nonReentrant whenNotPaused {
        _validateSourceUrl(resource, sourceUrl);

        LibTokenStorage.TokenStorage storage tks = LibTokenStorage.store();
        address token = tks.tokenByName[keccak256(bytes(tokenName_))];
        if (token == address(0)) {
            if (!LibString.caseInsensitiveEqual(tks.tokenName[address(0)], tokenName_)) revert TokenNotRegistered();
        }

        // Arg-binding: reverts unless a template matches these recipient/amount/token.
        // Its recipientLess result is AUTHORITATIVE and must gate the reply/quote
        // binding here — verifyProof's matchAnyTemplate can classify differently when
        // a literal template matches first, which would skip the binding.
        if (LibTemplate.verifyTemplate(revealedSubsection, resource.platform, receiverHandle, amountStr, tokenName_)) {
            LibRecipient.verifyRecipientIdLeaf(notaryTlsProof, receiverUserId);
        }

        (address senderWallet, address receiverWallet) = _webTransfer(
            resource,
            sender,
            revealedSubsection,
            notaryTlsProof,
            backendSigData,
            receiverUserId,
            token,
            amountStr,
            amount
        );
        emit WebTransferV3(
            senderWallet, receiverWallet, resource.platform, receiverHandle, receiverUserId, token, amount, sourceUrl
        );
    }

    /// @notice Execute a web transfer (token by address) with source URL.
    function webTransferV2(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverHandle,
        string calldata receiverUserId,
        address token,
        string calldata amountStr,
        uint256 amount,
        string calldata sourceUrl
    ) external nonReentrant whenNotPaused {
        _validateSourceUrl(resource, sourceUrl);
        if (token == address(0)) revert ZeroToken();
        // Gate the web-transfer surface to registered tokens (parity with the
        // by-name overload + VaultFacet.deposit): verifyTemplate matches on the hex
        // address, so without this an unregistered ERC-20 would be pulled into the
        // ledger via autoTopUp.
        if (bytes(LibTokenStorage.store().tokenName[token]).length == 0) revert TokenNotRegistered();

        // Arg-binding (see the by-name overload): its recipientLess result gates
        // the reply/quote binding — authoritative over verifyProof's matchAnyTemplate.
        if (LibTemplate.verifyTemplate(
                revealedSubsection, resource.platform, receiverHandle, amountStr, Strings.toHexString(token)
            )) {
            LibRecipient.verifyRecipientIdLeaf(notaryTlsProof, receiverUserId);
        }

        (address senderWallet, address receiverWallet) = _webTransfer(
            resource,
            sender,
            revealedSubsection,
            notaryTlsProof,
            backendSigData,
            receiverUserId,
            token,
            amountStr,
            amount
        );
        emit WebTransferV3(
            senderWallet, receiverWallet, resource.platform, receiverHandle, receiverUserId, token, amount, sourceUrl
        );
    }

    /// @dev Shared body of both `webTransferV2` overloads: amount-wei check, proof
    ///      verification, and the balance move. The recipient-less binding + token
    ///      resolution differ by overload and stay there.
    function _webTransfer(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverUserId,
        address token,
        string calldata amountStr,
        uint256 amount
    ) internal returns (address senderWallet, address receiverWallet) {
        if (amount != LibString.parseDecimalAmount(amountStr, LibEscrow.tokenDecimals(token))) revert AmountWeiMismatch();

        bytes32 uid =
            _verifyAndGetUid(resource, sender, revealedSubsection, notaryTlsProof, backendSigData, receiverUserId);
        (senderWallet, receiverWallet) = _executeTransfer(uid, resource.platform, sender, receiverUserId, token, amount);
    }

    // ── Transfer within the Bank (WebWallet → WebWallet) ─────────────────

    /// @notice Transfer between internal Bank balances without touching the
    ///         chain. Caller must be a registered WebWallet. Lazy-migrates +
    ///         auto-tops-up.
    function transfer_within(
        string calldata receiverPlatform,
        string calldata receiverHandle,
        string calldata receiverUserId,
        address token,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();

        (string[] memory platforms,) = IRegistry(LibCoreStorage.store().registry).getHandles(msg.sender);
        if (platforms.length == 0) revert SenderNotRegistered();

        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        LibEscrow.migrate(msg.sender, token);
        LibEscrow.autoTopUp(msg.sender, token, amount);
        es.registeredBalances[msg.sender][token] -= amount;

        address receiverWallet = LibEscrow.resolveById(receiverPlatform, receiverUserId);
        if (receiverWallet != address(0)) {
            LibEscrow.migrate(receiverWallet, token);
            es.registeredBalances[receiverWallet][token] += amount;
        } else {
            es.unregisteredBalances[LibEscrow.escrowKey(receiverPlatform, receiverUserId)][token] += amount;
        }

        emit TransferWithin(msg.sender, receiverPlatform, receiverHandle, receiverUserId, token, amount);
    }

    // ── Internals ────────────────────────────────────────────────────────

    /// @dev Verify proof and compute UID. Reverts if invalid or already used.
    function _verifyAndGetUid(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverUserId
    ) internal view returns (bytes32 uid) {
        uid = _uid(resource);
        if (LibCoreStorage.store().usedTransfers[uid]) revert TransferAlreadyUsed();
        verifyProof(resource, sender, revealedSubsection, notaryTlsProof, backendSigData, receiverUserId);
    }

    /// @dev Validate caller-provided sourceUrl: https + platform web domain. Empty
    ///      sourceUrl skips validation.
    function _validateSourceUrl(ResourceInfo calldata resource, string calldata sourceUrl) internal view {
        if (bytes(sourceUrl).length == 0) return;
        if (!LibString.startsWith(bytes(sourceUrl), bytes("https://"))) revert SourceUrlNotHttps();

        string memory webPrefix = LibTemplateStorage.store().platformWebPrefixes[keccak256(bytes(resource.platform))];
        if (bytes(webPrefix).length > 0 && !LibString.startsWith(bytes(sourceUrl), bytes(webPrefix))) {
            revert SourceUrlDomainMismatch();
        }
    }

    /// @dev Move funds after verification: deduct sender, credit receiver or escrow,
    ///      mark uid used. Both parties resolved by proven id (recycle-proof).
    function _executeTransfer(
        bytes32 uid,
        string calldata platform,
        SenderInfo calldata sender,
        string calldata receiverUserId,
        address token,
        uint256 amount
    ) internal returns (address senderWallet, address receiverWallet) {
        if (amount == 0) revert ZeroAmount();

        senderWallet = LibEscrow.resolveById(platform, LibString.extractId(sender.revealedAuthorId));
        if (senderWallet == address(0)) revert SenderNotRegistered();

        LibEscrowStorage.EscrowStorage storage es = LibEscrowStorage.store();
        LibEscrow.migrate(senderWallet, token);
        LibEscrow.autoTopUp(senderWallet, token, amount);
        es.registeredBalances[senderWallet][token] -= amount;

        receiverWallet = LibEscrow.resolveById(platform, receiverUserId);
        if (receiverWallet != address(0)) {
            LibEscrow.migrate(receiverWallet, token);
            es.registeredBalances[receiverWallet][token] += amount;
        } else {
            es.unregisteredBalances[LibEscrow.escrowKey(platform, receiverUserId)][token] += amount;
        }

        LibCoreStorage.store().usedTransfers[uid] = true;
    }
}
