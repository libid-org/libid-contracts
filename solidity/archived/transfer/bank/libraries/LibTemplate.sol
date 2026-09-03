// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Bytes} from "@openzeppelin/contracts/utils/Bytes.sol";

import {LibString} from "./LibString.sol";
import {LibTemplateStorage} from "../storage/LibTemplateStorage.sol";
import {
    TemplateNotFound,
    NoTemplateMatch,
    TemplateMissingToken,
    TemplateMissingAmount,
    TemplateMissingTokenAfterRecipient
} from "../BankErrors.sol";

/// @title LibTemplate — honor-command template parsing + matching.
/// @dev Parses a template string into `{prefix}{recipient}{afterRecipient}{amount}
///      {afterAmount}{token}{suffix}` parts and matches a revealed comment body
///      against them, extracting recipient/amount/token. Reads/writes
///      `LibTemplateStorage`; uses `LibString` for search/extraction (+ OZ
///      `Bytes.slice` for memory substrings, `Strings.toHexString` for by-address).
library LibTemplate {
    /// @dev Store a template string and parse it into parts. Recognizes:
    ///        - `{recipient}`+`{amount}`+`{token}` — explicit recipient form.
    ///        - `{amount}`+`{token}` (no `{recipient}`) — recipient-less form
    ///          (recipient inferred off-chain from the reply/quote parent).
    ///        - no `{amount}` — a plain literal template (body must contain it).
    function addTemplate(string memory platform, string memory template) internal {
        LibTemplateStorage.TemplateStorage storage ts = LibTemplateStorage.store();
        bytes32 key = keccak256(bytes(platform));
        ts.platformTemplates[key].push(template);

        bytes memory t = bytes(template);
        (bool foundRcp, uint256 rcpPos) = LibString.indexOf(t, bytes("{recipient}"), 0, false);
        if (!foundRcp) {
            (bool amtOnly, uint256 amtOnlyPos) = LibString.indexOf(t, bytes("{amount}"), 0, false);
            if (!amtOnly) {
                ts.templateParts[key].push(
                    LibTemplateStorage.TemplateParts({
                        prefix: template, afterRecipient: "", afterAmount: "", suffix: "", hasPlaceholders: false
                    })
                );
                return;
            }
            (bool tokOnly, uint256 tokOnlyPos) = LibString.indexOf(t, bytes("{token}"), amtOnlyPos + 8, false);
            if (!tokOnly) revert TemplateMissingToken();
            ts.templateParts[key].push(
                LibTemplateStorage.TemplateParts({
                    prefix: string(Bytes.slice(t, 0, amtOnlyPos)),
                    afterRecipient: "",
                    afterAmount: string(Bytes.slice(t, amtOnlyPos + 8, tokOnlyPos)),
                    suffix: string(Bytes.slice(t, tokOnlyPos + 7, t.length)),
                    hasPlaceholders: true
                })
            );
            return;
        }
        (bool foundAmt, uint256 amtPos) = LibString.indexOf(t, bytes("{amount}"), rcpPos + 11, false);
        if (!foundAmt) revert TemplateMissingAmount();
        (bool foundTok, uint256 tokPos) = LibString.indexOf(t, bytes("{token}"), amtPos + 8, false);
        if (!foundTok) revert TemplateMissingTokenAfterRecipient();

        ts.templateParts[key].push(
            LibTemplateStorage.TemplateParts({
                prefix: string(Bytes.slice(t, 0, rcpPos)),
                afterRecipient: string(Bytes.slice(t, rcpPos + 11, amtPos)),
                afterAmount: string(Bytes.slice(t, amtPos + 8, tokPos)),
                suffix: string(Bytes.slice(t, tokPos + 7, t.length)),
                hasPlaceholders: true
            })
        );
    }

    /// @dev Whether the i-th template for a platform is an explicit `{recipient}`
    ///      form. Derived at call time from the raw template string.
    function templateHasRecipient(bytes32 platformKey, uint256 i) internal view returns (bool) {
        LibTemplateStorage.TemplateStorage storage ts = LibTemplateStorage.store();
        (bool found,) = LibString.indexOf(bytes(ts.platformTemplates[platformKey][i]), bytes("{recipient}"), 0, false);
        return found;
    }

    /// @dev Try all templates for a platform; return the first match.
    /// @return matched Whether any template matched.
    /// @return amt Extracted amount (empty for a literal template).
    /// @return tok Extracted token (empty for a literal template).
    /// @return recipientLess True when the matched template is a placeholder form
    ///         with NO `{recipient}` — the recipient is then bound off-body via the
    ///         proven reply-target id leaf.
    function matchAnyTemplate(bytes calldata data, bytes32 platformKey)
        internal
        view
        returns (bool, string memory, string memory, bool)
    {
        LibTemplateStorage.TemplateStorage storage ts = LibTemplateStorage.store();
        uint256 count = ts.templateParts[platformKey].length;
        for (uint256 i = 0; i < count; i++) {
            (bool matched, string memory amt, string memory tok,) = matchTemplate(data, platformKey, i);
            if (matched) {
                LibTemplateStorage.TemplateParts storage parts = ts.templateParts[platformKey][i];
                bool recipientLess = parts.hasPlaceholders && !templateHasRecipient(platformKey, i);
                return (true, amt, tok, recipientLess);
            }
        }
        return (false, "", "", false);
    }

    /// @dev Match one template (by index) against the revealed body. Returns
    ///      `(matched, extractedAmount, extractedToken, extractedRecipient)`.
    ///      Literal templates yield empty amount/token/recipient.
    function matchTemplate(bytes calldata data, bytes32 platformKey, uint256 templateIndex)
        internal
        view
        returns (bool, string memory, string memory, string memory)
    {
        LibTemplateStorage.TemplateParts storage p =
            LibTemplateStorage.store().templateParts[platformKey][templateIndex];
        bytes memory prefix = bytes(p.prefix);

        // 1. Prefix (case-insensitive).
        (bool foundPrefix, uint256 prefixPos) = LibString.indexOf(data, prefix, 0, true);
        if (!foundPrefix) return (false, "", "", "");

        // Simple literal template — a prefix match is sufficient.
        if (!p.hasPlaceholders) return (true, "", "", "");

        bytes memory afterRecipient = bytes(p.afterRecipient);
        bytes memory afterAmount = bytes(p.afterAmount);
        bytes memory suffix = bytes(p.suffix);

        uint256 recipientStart = prefixPos + prefix.length;

        // 2. afterRecipient (skip over the recipient value).
        (bool foundAfterRcp, uint256 afterRcpPos) = LibString.indexOf(data, afterRecipient, recipientStart, true);
        if (!foundAfterRcp) return (false, "", "", "");
        string memory recipient = LibString.substringCalldata(data, recipientStart, afterRcpPos);
        uint256 amountStart = afterRcpPos + afterRecipient.length;

        // 3. afterAmount (skip over the amount value).
        (bool foundAfterAmt, uint256 afterAmtPos) = LibString.indexOf(data, afterAmount, amountStart, true);
        if (!foundAfterAmt) return (false, "", "", "");
        string memory amount = LibString.substringCalldata(data, amountStart, afterAmtPos);
        uint256 tokenStart = afterAmtPos + afterAmount.length;

        // 4. suffix (or, when empty, the token runs to the next non-token char).
        string memory token;
        if (suffix.length > 0) {
            (bool foundSuffix, uint256 suffixPos) = LibString.indexOf(data, suffix, tokenStart, true);
            if (!foundSuffix) return (false, "", "", "");
            token = LibString.substringCalldata(data, tokenStart, suffixPos);
        } else {
            uint256 tokenEnd = tokenStart;
            while (tokenEnd < data.length) {
                if (!LibString.isTokenChar(data[tokenEnd])) break;
                tokenEnd++;
            }
            token = LibString.substringCalldata(data, tokenStart, tokenEnd);
        }

        if (bytes(amount).length == 0 || bytes(token).length == 0) return (false, "", "", "");
        return (true, amount, token, recipient);
    }

    /// @dev Verify a template match and check the extracted amount + token
    ///      against `amountStr` / `expectedToken`. Reverts if nothing matches.
    ///      Returns `recipientLess` — true when a recipient-less template matched
    ///      (the caller binds the recipient via the proven reply-target id leaf).
    ///      The by-name vs by-address distinction is the caller's: it passes the
    ///      token NAME or `Strings.toHexString(tokenAddress)` as `expectedToken`.
    function verifyTemplate(
        bytes calldata body,
        string calldata platform,
        string calldata receiverHandle,
        string calldata amountStr,
        string memory expectedToken
    ) internal view returns (bool recipientLess) {
        bytes32 platformKey = keccak256(bytes(platform));
        uint256 count = LibTemplateStorage.store().platformTemplates[platformKey].length;
        if (count == 0) revert TemplateNotFound();
        for (uint256 i = 0; i < count; i++) {
            (bool matched, string memory amt, string memory tok, string memory rcp) =
                matchTemplate(body, platformKey, i);
            if (
                matched && keccak256(bytes(amt)) == keccak256(bytes(amountStr))
                    && LibString.caseInsensitiveEqual(tok, expectedToken)
            ) {
                if (!templateHasRecipient(platformKey, i)) return true;
                if (LibString.caseInsensitiveEqual(rcp, receiverHandle)) return false;
            }
        }
        revert NoTemplateMatch();
    }
}
