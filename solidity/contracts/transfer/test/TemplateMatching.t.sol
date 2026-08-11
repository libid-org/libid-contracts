// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {TemplateMissingToken, TemplateMissingAmount, TemplateMissingTokenAfterRecipient} from "../bank/BankErrors.sol";
import {LibTemplate} from "../bank/libraries/LibTemplate.sol";
import {LibString} from "../bank/libraries/LibString.sol";
import {LibTemplateStorage} from "../bank/storage/LibTemplateStorage.sol";

/// @dev Unit harness for the template/id libraries the diamond actually runs. It
///      calls `LibTemplate`/`LibString` directly (its own diamond-storage slot),
///      so these tests exercise the SAME code the diamond does — no legacy Bank.
contract LibTemplateHarness {
    function setPlatformTemplate(string calldata platform, string calldata tmpl) external {
        LibTemplate.addTemplate(platform, tmpl);
    }

    function platformTemplates(bytes32 key, uint256 i) external view returns (string memory) {
        return LibTemplateStorage.store().platformTemplates[key][i];
    }

    function matchTemplate(bytes calldata data, bytes32 key, uint256 i)
        external
        view
        returns (bool, string memory, string memory, string memory)
    {
        return LibTemplate.matchTemplate(data, key, i);
    }

    function matchAnyTemplate(bytes calldata data, bytes32 key)
        external
        view
        returns (bool, string memory, string memory)
    {
        (bool matched, string memory amt, string memory tok,) = LibTemplate.matchAnyTemplate(data, key);
        return (matched, amt, tok);
    }

    function extractId(bytes calldata s) external pure returns (string memory) {
        return LibString.extractId(s);
    }
}

contract TemplateMatchingTest is Test, BankDiamondDeployer {
    // `bank` is the diamond. `harness` calls the same libraries directly for the
    // internal matcher/extractId paths the diamond has no external surface for.
    IBank bank;
    LibTemplateHarness harness;

    function setUp() public {
        bank = IBank(deployBankDiamond(address(this), address(1), address(2), address(3)));
        harness = new LibTemplateHarness();
        // Mirror the diamond's seeded templates into the harness so the library
        // matching tests run against the exact same defaults (no hardcoding).
        _mirror("api.x.com");
        _mirror("api.github.com");
    }

    function _mirror(string memory platform) internal {
        uint256 n = bank.platformTemplateCount(platform);
        for (uint256 i = 0; i < n; i++) {
            harness.setPlatformTemplate(platform, bank.getPlatformTemplate(platform, i));
        }
    }

    // ─── Template Parsing ─────────────────────────────────────────

    function test_defaultGithubTemplateParts_withOf() public view {
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("api.github.com", 0);
        assertEq(prefix, "@dyaka-agent honor @");
        assertEq(afterRecipient, " with ");
        assertEq(afterAmount, " of ");
        assertEq(suffix, "");
    }

    function test_defaultGithubTemplateParts_withoutOf() public view {
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("api.github.com", 1);
        assertEq(prefix, "@dyaka-agent honor @");
        assertEq(afterRecipient, " with ");
        assertEq(afterAmount, " ");
        assertEq(suffix, "");
    }

    function test_defaultXTemplateParts_withOf() public view {
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("api.x.com", 0);
        assertEq(prefix, "@dyaka_agent honor @");
        assertEq(afterRecipient, " with ");
        assertEq(afterAmount, " of ");
        assertEq(suffix, "");
    }

    function test_defaultXTemplateParts_withoutOf() public view {
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("api.x.com", 1);
        assertEq(prefix, "@dyaka_agent honor @");
        assertEq(afterRecipient, " with ");
        assertEq(afterAmount, " ");
        assertEq(suffix, "");
    }

    /// The diamond stores the raw template string verbatim, read via getPlatformTemplate.
    function test_fullTemplateStringStored() public view {
        assertEq(
            bank.getPlatformTemplate("api.github.com", 0), "@dyaka-agent honor @{recipient} with {amount} of {token}"
        );
        assertEq(bank.getPlatformTemplate("api.github.com", 1), "@dyaka-agent honor @{recipient} with {amount} {token}");
    }

    function test_setPlatformTemplateViaAdmin() public {
        bank.setPlatformTemplate("newplatform", "@bot honor @{recipient} with {amount} {token}");
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("newplatform", 0);
        assertEq(prefix, "@bot honor @");
        assertEq(afterRecipient, " with ");
        assertEq(afterAmount, " ");
        assertEq(suffix, "");
        assertEq(bank.getPlatformTemplate("newplatform", 0), "@bot honor @{recipient} with {amount} {token}");
    }

    function test_templateWithMiddleWord() public {
        bank.setPlatformTemplate("test", "@dyaka-bot send @{recipient} then {amount} of {token}");
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("test", 0);
        assertEq(prefix, "@dyaka-bot send @");
        assertEq(afterRecipient, " then ");
        assertEq(afterAmount, " of ");
        assertEq(suffix, "");
    }

    function test_templateWithSuffix() public {
        bank.setPlatformTemplate("test", "pay @{recipient} now {amount} in {token} done");
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("test", 0);
        assertEq(prefix, "pay @");
        assertEq(afterRecipient, " now ");
        assertEq(afterAmount, " in ");
        assertEq(suffix, " done");
    }

    /// A template with {amount}/{token} but NO {recipient} is a recipient-less
    /// placeholder template (recipient inferred off-chain): prefix runs up to
    /// {amount} and afterRecipient is empty.
    function test_setTemplateWithoutRecipient_isRecipientLess() public {
        bank.setPlatformTemplate("implicit", "@dyaka-agent honor with {amount} {token}");
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("implicit", 0);
        assertEq(prefix, "@dyaka-agent honor with ");
        assertEq(afterRecipient, "");
        assertEq(afterAmount, " ");
        assertEq(suffix, "");
    }

    /// A recipient-less template still requires {token} after {amount}.
    function test_setTemplateRecipientLessRequiresToken() public {
        vm.expectRevert(TemplateMissingToken.selector);
        bank.setPlatformTemplate("bad", "@dyaka-agent honor with {amount}");
    }

    /// A template with no placeholders at all stays a simple literal.
    function test_setTemplateNoPlaceholders_isLiteral() public {
        bank.setPlatformTemplate("simple", "@dyaka-agent gm fam");
        (string memory prefix,,,) = bank.getTemplateParts("simple", 0);
        assertEq(prefix, "@dyaka-agent gm fam");
    }

    function test_setTemplateRequiresAmountPlaceholder() public {
        vm.expectRevert(TemplateMissingAmount.selector);
        bank.setPlatformTemplate("bad", "@dyaka-agent honor @{recipient} with {token}");
    }

    function test_setTemplateRequiresTokenPlaceholder() public {
        vm.expectRevert(TemplateMissingTokenAfterRecipient.selector);
        bank.setPlatformTemplate("bad", "@dyaka-agent honor @{recipient} with {amount}");
    }

    function test_setTemplateRecipientMustBeBeforeAmount() public {
        vm.expectRevert(TemplateMissingAmount.selector);
        bank.setPlatformTemplate("bad", "@dyaka-agent {amount} @{recipient} {token}");
    }

    // ─── Multiple Templates ──────────────────────────────────────

    function test_multipleTemplatesPerPlatform() public {
        bank.setPlatformTemplate("multi", "simple template A");
        bank.setPlatformTemplate("multi", "simple template B");
        assertEq(bank.platformTemplateCount("multi"), 2);
        assertEq(bank.getPlatformTemplate("multi", 0), "simple template A");
        assertEq(bank.getPlatformTemplate("multi", 1), "simple template B");
    }

    function test_clearPlatformTemplates() public {
        bank.setPlatformTemplate("clearme", "template A");
        bank.setPlatformTemplate("clearme", "template B");
        assertEq(bank.platformTemplateCount("clearme"), 2);
        bank.clearPlatformTemplates("clearme");
        assertEq(bank.platformTemplateCount("clearme"), 0);
    }

    function test_matchAnyTemplate_matchesSecondTemplate() public {
        harness.setPlatformTemplate("multi", "first pattern");
        harness.setPlatformTemplate("multi", "second pattern");
        bytes memory data = bytes("this contains second pattern here");
        (bool ok,,) = harness.matchAnyTemplate(data, keccak256("multi"));
        assertTrue(ok);
    }

    function test_matchAnyTemplate_noMatch() public {
        harness.setPlatformTemplate("multi", "first pattern");
        harness.setPlatformTemplate("multi", "second pattern");
        bytes memory data = bytes("this matches nothing");
        (bool ok,,) = harness.matchAnyTemplate(data, keccak256("multi"));
        assertFalse(ok);
    }

    // ─── Template Matching (JSON delimiters) ──────────────────────

    function test_matchTemplate_plainText_withoutOf() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.0001 $TIA");
        // Template index 1 = without "of"
        (bool ok, string memory amount, string memory token,) = harness.matchTemplate(data, keccak256("api.x.com"), 1);
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_plainText_withOf() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.0001 of $TIA");
        // Template index 0 = with "of"
        (bool ok, string memory amount, string memory token,) = harness.matchTemplate(data, keccak256("api.x.com"), 0);
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchAnyTemplate_withOf() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.0001 of $TIA");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchAnyTemplate_withoutOf() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.0001 $TIA");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_textBeforeCommand() public view {
        bytes memory data = bytes(
            "This is a comment with some text before the template.\n\n@dyaka_agent honor @alice with 0.0001 of $TIA, because we are generous."
        );
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_textBeforeCommand_github() public view {
        bytes memory data = bytes(
            "This is the comment with some works before the main template.\n\n@dyaka-agent honor @alice-test-account with 0.0001 of $TIA, because we are generous."
        );
        (bool ok, string memory amount, string memory token) =
            harness.matchAnyTemplate(data, keccak256("api.github.com"));
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_jsonEncoded() public view {
        bytes memory data = bytes('@dyaka_agent honor @alice with 0.0001 $TIA"');
        (bool ok, string memory amount, string memory token,) = harness.matchTemplate(data, keccak256("api.x.com"), 1);
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_jsonWithCommaAfterToken() public view {
        bytes memory data = bytes('@dyaka_agent honor @alice with 0.0001 $TIA","next_field');
        (bool ok, string memory amount, string memory token,) = harness.matchTemplate(data, keccak256("api.x.com"), 1);
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_jsonWithBraceAfterToken() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.0001 $TIA}");
        (bool ok, string memory amount, string memory token,) = harness.matchTemplate(data, keccak256("api.x.com"), 1);
        assertTrue(ok);
        assertEq(amount, "0.0001");
        assertEq(token, "$TIA");
    }

    // ─── Token character whitelist tests ─────────────────────────

    function test_matchTemplate_trailingExclamation() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.1 $TIA! great work");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "0.1");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_trailingQuestion() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.1 $TIA?");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "0.1");
        assertEq(token, "$TIA");
    }

    function test_matchTemplate_trailingPeriodNewline() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 0.1 $TIA.\nMore text");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        // Dot is a valid token char, so it gets included
        assertEq(amount, "0.1");
        assertEq(token, "$TIA.");
    }

    function test_matchTemplate_dottedToken() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 100 USDC.e");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "100");
        assertEq(token, "USDC.e");
    }

    function test_matchTemplate_dottedTokenInSentence() public view {
        bytes memory data = bytes("@dyaka_agent honor @alice with 100 USDC.e for her work");
        (bool ok, string memory amount, string memory token) = harness.matchAnyTemplate(data, keccak256("api.x.com"));
        assertTrue(ok);
        assertEq(amount, "100");
        assertEq(token, "USDC.e");
    }

    // ── extractId (sender id parsing) ─────────────────────────────

    function test_extractId_quoted() public view {
        assertEq(harness.extractId(bytes('"author_id":"1234567890"')), "1234567890");
    }

    function test_extractId_bareComma() public view {
        assertEq(harness.extractId(bytes('"id":123,')), "123");
    }

    function test_extractId_bareBrace() public view {
        assertEq(harness.extractId(bytes('"id":456}')), "456");
    }

    function test_extractId_quotedNonNumeric() public view {
        // Quoted ids are taken verbatim (X snowflakes, or test ids like id_alice).
        assertEq(harness.extractId(bytes('"author_id":"id_alice"')), "id_alice");
    }

    function test_extractId_malformed_reverts() public {
        vm.expectRevert(LibString.MalformedAuthorId.selector);
        harness.extractId(bytes("noColonHere"));
    }

    function test_extractId_emptyBare_reverts() public {
        vm.expectRevert(LibString.EmptyAuthorId.selector);
        harness.extractId(bytes('"id":,'));
    }
}
