// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibTemplate} from "../bank/libraries/LibTemplate.sol";
import {LibRecipient} from "../bank/libraries/LibRecipient.sol";
import {ReplyTargetIdNotQuoted} from "../bank/BankErrors.sol";

/// @dev Unit harness over the diamond's template/recipient libraries (same code
///      the diamond runs, its own diamond-storage slot). No legacy Bank.
contract BankTemplateHarness {
    function addTemplate(string calldata platform, string calldata template) external {
        LibTemplate.addTemplate(platform, template);
    }

    /// @dev Reverts unless some template matches `body` AND extracts exactly
    ///      `amt`/`tok` (mirrors the on-chain webTransfer-by-name check). Returns
    ///      `recipientLess` — true when a recipient-less template matched (the
    ///      recipient is then bound off-body via the reply-target id leaf).
    function checkByName(
        bytes calldata body,
        string calldata platform,
        string calldata receiverHandle,
        string calldata amt,
        string calldata tok
    ) external view returns (bool recipientLess) {
        return LibTemplate.verifyTemplate(body, platform, receiverHandle, amt, tok);
    }

    /// @dev Mirrors the `verifyProof` classification path: returns whether any
    ///      template matched and whether the match is recipient-less (derived from
    ///      the matched template SHAPE, not the extracted recipient value).
    function matchAny(bytes calldata body, string calldata platform)
        external
        view
        returns (bool matched, bool recipientLess)
    {
        (matched,,, recipientLess) = LibTemplate.matchAnyTemplate(body, keccak256(bytes(platform)));
    }

    function extractReplyTarget(bytes calldata leaf, uint256 prefixLen) external pure returns (string memory) {
        return LibRecipient.extractReplyTargetId(leaf, prefixLen);
    }
}

/// @notice Recipient-less honor templates: `@bot honor with {amount} {token}`
///         (recipient inferred off-chain from the reply/quote parent). Proves the
///         engine extracts amount/token without a `{recipient}` placeholder, flags
///         the match as recipient-less, the explicit form still works (and is not
///         flagged), and the two forms do not cross-match.
contract ImplicitTemplateTest is Test {
    BankTemplateHarness h;

    function setUp() public {
        h = new BankTemplateHarness();
        // Mirror initialize()'s X templates: explicit + recipient-less, "of" first.
        h.addTemplate("api.x.com", "@dyaka_agent honor @{recipient} with {amount} of {token}");
        h.addTemplate("api.x.com", "@dyaka_agent honor @{recipient} with {amount} {token}");
        h.addTemplate("api.x.com", "@dyaka_agent honor with {amount} of {token}");
        h.addTemplate("api.x.com", "@dyaka_agent honor with {amount} {token}");
    }

    function test_implicit_withOf() public view {
        // Recipient-less body: no receiverHandle in the body → flagged recipientLess.
        assertTrue(h.checkByName(bytes("@dyaka_agent honor with 1.5 of $TIA"), "api.x.com", "", "1.5", "$TIA"));
    }

    // ── reply-target id extraction is anchored to the field, not the last colon ──
    // `"in_reply_to_user_id":` is 22 bytes.
    uint256 constant PREFIX_LEN = 22;

    function test_extractReplyTarget_plain() public view {
        assertEq(h.extractReplyTarget(bytes('"in_reply_to_user_id":"12345"'), PREFIX_LEN), "12345");
    }

    function test_extractReplyTarget_ignoresTrailingMentionId() public view {
        // A longer revealed snippet whose LAST colon precedes an attacker id must
        // still yield the reply target — not the trailing mention id.
        bytes memory leaf = bytes('"in_reply_to_user_id":"victim","entities":{"mentions":[{"id":"attacker"');
        assertEq(h.extractReplyTarget(leaf, PREFIX_LEN), "victim");
    }

    function test_extractReplyTarget_rejectsUnquoted() public {
        vm.expectRevert(ReplyTargetIdNotQuoted.selector);
        h.extractReplyTarget(bytes('"in_reply_to_user_id":12345'), PREFIX_LEN);
    }

    function test_implicit_withoutOf() public view {
        assertTrue(h.checkByName(bytes("@dyaka_agent honor with 100 USDC"), "api.x.com", "", "100", "USDC"));
    }

    function test_implicit_surroundingText() public view {
        assertTrue(
            h.checkByName(bytes("thanks! @dyaka_agent honor with 0.05 ETH keep it up"), "api.x.com", "", "0.05", "ETH")
        );
    }

    function test_explicit_stillMatches_andIsNotRecipientLess() public view {
        // Explicit body: recipient handle proven by the body must equal receiverHandle,
        // and the match is NOT flagged recipient-less.
        assertFalse(h.checkByName(bytes("@dyaka_agent honor @bob with 100 USDC"), "api.x.com", "bob", "100", "USDC"));
    }

    function test_explicit_wrongHandle_reverts() public {
        // Explicit body, but receiverHandle doesn't match the body's @bob → no match.
        vm.expectRevert();
        h.checkByName(bytes("@dyaka_agent honor @bob with 100 USDC"), "api.x.com", "carol", "100", "USDC");
    }

    function test_wrongToken_reverts() public {
        vm.expectRevert();
        h.checkByName(bytes("@dyaka_agent honor with 100 USDC"), "api.x.com", "", "100", "USDT");
    }

    // ── cross-matching isolation ───────────────────────────────────

    // Only recipient-less templates registered -> an explicit-recipient body
    // ("honor @bob with ...") must NOT match (prefix "honor with " absent).
    function test_noCrossMatch_explicitBodyVsImplicitOnly() public {
        BankTemplateHarness h2 = new BankTemplateHarness();
        h2.addTemplate("api.x.com", "@dyaka_agent honor with {amount} of {token}");
        h2.addTemplate("api.x.com", "@dyaka_agent honor with {amount} {token}");
        vm.expectRevert();
        h2.checkByName(bytes("@dyaka_agent honor @bob with 100 USDC"), "api.x.com", "bob", "100", "USDC");
    }

    // Only explicit templates registered -> a recipient-less body must NOT match
    // (prefix "honor @" absent).
    function test_noCrossMatch_implicitBodyVsExplicitOnly() public {
        BankTemplateHarness h2 = new BankTemplateHarness();
        h2.addTemplate("api.x.com", "@dyaka_agent honor @{recipient} with {amount} of {token}");
        h2.addTemplate("api.x.com", "@dyaka_agent honor @{recipient} with {amount} {token}");
        vm.expectRevert();
        h2.checkByName(bytes("@dyaka_agent honor with 100 USDC"), "api.x.com", "", "100", "USDC");
    }

    // ── malformed explicit body (empty extracted recipient) ────────────
    //
    // A body shaped like the EXPLICIT template ("honor @ …") but with an empty
    // recipient must NOT be promoted to the recipient-less (reply-target-id-bound)
    // path just because the extracted recipient string is empty. It is classified
    // by the matched template SHAPE, which has a {recipient} placeholder.

    // by-name path: an explicit template extracting an empty recipient does not
    // early-accept as recipient-less; it falls through to the handle check, which
    // fails for the empty recipient vs the real intended handle → reverts (rejected).
    function test_malformedExplicitBody_rejected_byName() public {
        vm.expectRevert();
        h.checkByName(bytes("@dyaka_agent honor @ with 5 $TST"), "api.x.com", "bob", "5", "$TST");
    }

    // verifyProof classification path: the malformed explicit body matches but is
    // NOT flagged recipient-less, so verifyProof would not require/accept the
    // reply-target id leaf for it.
    function test_malformedExplicitBody_notRecipientLess_matchAny() public view {
        (bool matched, bool recipientLess) = h.matchAny(bytes("@dyaka_agent honor @ with 5 $TST"), "api.x.com");
        assertTrue(matched, "malformed explicit body still matches an explicit template");
        assertFalse(recipientLess, "malformed explicit body must NOT be classified recipient-less");
    }

    // Regression guard: a genuine recipient-less body (no {recipient} in the
    // template shape) IS still classified recipient-less by the same path.
    function test_genuineImplicitBody_isRecipientLess_matchAny() public view {
        (bool matched, bool recipientLess) = h.matchAny(bytes("@dyaka_agent honor with 100 USDC"), "api.x.com");
        assertTrue(matched, "genuine recipient-less body matches");
        assertTrue(recipientLess, "genuine recipient-less body must be classified recipient-less");
    }
}
