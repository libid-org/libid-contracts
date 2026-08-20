// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyFields} from "../CeremonyFields.sol";

contract CeremonyFieldsTest is Test {
    function jsonString(bytes calldata d, string calldata n) external pure returns (bytes memory) {
        return CeremonyFields.jsonString(d, n);
    }

    function jsonInteger(bytes calldata d, string calldata n) external pure returns (bytes memory) {
        return CeremonyFields.jsonInteger(d, n);
    }

    function formField(bytes calldata d, string calldata n) external pure returns (bytes memory) {
        return CeremonyFields.formField(d, n);
    }

    // ─── JSON strings ───────────────────────────────────────────────

    function test_readsAnXIdentityResponse() public view {
        bytes memory body = bytes('{"data":{"id":"2244994945","username":"alice"}}');
        assertEq(string(this.jsonString(body, "id")), "2244994945");
        assertEq(string(this.jsonString(body, "username")), "alice");
    }

    /// @dev A display name carrying a lookalike field does NOT match, and the
    ///      reason is ASM-PROV-06 rather than anything this library does: the
    ///      platform returns well-formed JSON, so a quote inside a string value
    ///      is escaped, and `\\"username\\":\\"` is not the unescaped delimiter
    ///      `"username":"`. The real field still reads. Pinned because the
    ///      whole template approach rests on it.
    function test_anEscapedLookalikeIsNotAMatch() public view {
        bytes memory body = bytes('{"name":"hi \\"username\\":\\"victim\\" ok","username":"alice"}');
        assertEq(string(this.jsonString(body, "username")), "alice");
    }

    /// @dev The case REQ-COMMON-19A actually closes: the same field name at two
    ///      nesting levels, both unescaped. Reading the first would let an
    ///      envelope answer for the payload; reading the last would too.
    ///      Refusing to answer is what closes it.
    function test_refusesAFieldThatAppearsTwice() public {
        bytes memory body = bytes('{"data":{"username":"alice"},"includes":{"username":"attacker"}}');
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.AmbiguousField.selector, "username"));
        this.jsonString(body, "username");
    }

    function test_refusesAMissingField() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FieldNotFound.selector, "username"));
        this.jsonString(bytes('{"id":"7"}'), "username");
    }

    function test_refusesAValueWithNoClosingQuote() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.UnterminatedField.selector, "username"));
        this.jsonString(bytes('{"username":"alice'), "username");
    }

    /// @dev The full delimiter includes the opening quote of the value, so a
    ///      numeric `id` is simply not a match for the string template.
    function test_aBareIntegerIsNotAStringField() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FieldNotFound.selector, "id"));
        this.jsonString(bytes('{"id":7}'), "id");
    }

    function test_readsAnEmptyValue() public view {
        assertEq(this.jsonString(bytes('{"username":""}'), "username").length, 0);
    }

    // ─── JSON integers ──────────────────────────────────────────────

    /// @dev GitHub's `/user.id` is a bare integer, and the terminator is what
    ///      proves the revealed digits are the whole number rather than a
    ///      prefix of a longer one.
    function test_readsAGitHubIdWithEitherTerminator() public view {
        assertEq(string(this.jsonInteger(bytes('{"id":1,"login":"octocat"}'), "id")), "1");
        assertEq(string(this.jsonInteger(bytes('{"login":"octocat","id":583231}'), "id")), "583231");
    }

    function test_refusesAnyOtherTerminator() public {
        // A space would let `123 456` read as `123`.
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.BadIntegerTerminator.selector, "id", bytes1(" ")));
        this.jsonInteger(bytes('{"id":123 456}'), "id");
    }

    function test_refusesANoncanonicalInteger() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.NoncanonicalInteger.selector, "id"));
        this.jsonInteger(bytes('{"id":007,"a":1}'), "id");

        // `-1`, `1.5` and `1e3` all fail: the first byte is not a digit, or the
        // terminator is not `,`/`}`.
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.NoncanonicalInteger.selector, "id"));
        this.jsonInteger(bytes('{"id":-1}'), "id");
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.BadIntegerTerminator.selector, "id", bytes1(".")));
        this.jsonInteger(bytes('{"id":1.5}'), "id");
    }

    function test_zeroIsCanonical() public view {
        assertEq(string(this.jsonInteger(bytes('{"id":0}'), "id")), "0");
    }

    function test_refusesAQuotedIntegerForTheIntegerTemplate() public {
        // `"id":"1"` — the digits scan finds none after the delimiter.
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.NoncanonicalInteger.selector, "id"));
        this.jsonInteger(bytes('{"id":"1"}'), "id");
    }

    // ─── Form fields ────────────────────────────────────────────────

    function test_readsAnXTokenRequestBody() public view {
        bytes memory body = bytes(
            "grant_type=authorization_code&client_id=abc123&code=xyz&redirect_uri=https%3A%2F%2Fa.example&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I"
        );
        assertEq(string(this.formField(body, "grant_type")), "authorization_code");
        assertEq(string(this.formField(body, "client_id")), "abc123");
        assertEq(string(this.formField(body, "code_verifier")), "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I");
    }

    /// @dev Without the leading boundary, `client_id=` matches inside
    ///      `evil_client_id=` and the attacker's value answers.
    function test_aFieldNameMustStartAtABoundary() public view {
        bytes memory body = bytes("evil_client_id=attacker&client_id=real");
        assertEq(string(this.formField(body, "client_id")), "real");
    }

    /// @dev The duplicate-field case ASM-PROV-07 leaves open in HIDDEN ranges is
    ///      closed here for revealed ones: two `code_verifier` fields make the
    ///      read ambiguous rather than letting the first or last answer.
    function test_refusesADuplicateFormField() public {
        bytes memory body = bytes("code_verifier=GOOD&code_verifier=EVIL");
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.AmbiguousField.selector, "code_verifier"));
        this.formField(body, "code_verifier");
    }

    function test_readsTheFirstAndLastFieldOfABody() public view {
        bytes memory body = bytes("a=1&b=2&c=3");
        assertEq(string(this.formField(body, "a")), "1");
        assertEq(string(this.formField(body, "c")), "3");
    }

    // ─── The client-identifier charset ──────────────────────────────

    /// @dev REQ-COMMON-16B. Real identifiers fit: GitHub's `Iv1.` prefix needs
    ///      the dot, X's are base64url-ish.
    function test_acceptsRealClientIdentifiers() public pure {
        assertTrue(CeremonyFields.isSerializerSafe(bytes("Iv1.8a61f9b3a7aba766")));
        assertTrue(CeremonyFields.isSerializerSafe(bytes("Ov23liABCDEfghij")));
        assertTrue(CeremonyFields.isSerializerSafe(bytes("a-b_c.d*e")));
    }

    /// @dev Anything outside the set means the revealed bytes are the
    ///      SERIALIZATION, not the identifier -- returning them would hand a
    ///      Consumer `my%2Bapp` where the client is `my+app`.
    function test_refusesPercentEncodedAndDelimiterBytes() public pure {
        assertFalse(CeremonyFields.isSerializerSafe(bytes("my%2Bapp")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("my+app")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("a&b")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("a=b")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("")));
        assertFalse(CeremonyFields.isSerializerSafe(hex"c3a9")); // non-ASCII
    }
}
