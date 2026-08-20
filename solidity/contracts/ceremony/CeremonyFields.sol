// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CeremonyFields
/// @notice Reading one field out of the revealed bytes of an attestation.
///
/// @dev Nothing here parses a document. ceremony-common section 9 says so
///      plainly: no complete HTTP request grammar, no complete HTTP response
///      grammar, no complete JSON grammar is proved or parsed anywhere in the
///      protocol. A JSON field is matched by its exact delimiter template, a
///      form field by its own boundary template, and that is all.
///
///      What makes a template safe to trust is REQ-COMMON-19A: the Platform
///      Verifier must reject a transcript in which a field's full delimiter
///      matches at more than one position. An authenticated response carries
///      text the account holder chooses -- a display name, a bio -- and that
///      text can embed a lookalike field. Reading the first match would let it
///      answer for the real one; reading the last would too. Refusing to answer
///      at all is what closes it.
library CeremonyFields {
    /// @dev The delimiter appears more than once, so no reading of it is
    ///      authoritative (REQ-COMMON-19A).
    error AmbiguousField(string name);
    error FieldNotFound(string name);
    /// @dev A JSON string value ran to the end of the revealed bytes without a
    ///      closing quote, so its extent is not established.
    error UnterminatedField(string name);
    /// @dev A GitHub `id` must be followed by `,` or `}` and no other byte: the
    ///      terminator is what proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one (REQ-PLAT-51).
    error BadIntegerTerminator(string name, bytes1 found);
    /// @dev Leading zeros, a sign, a fraction, an exponent, or no digits at all.
    error NoncanonicalInteger(string name);

    /// @notice What a field lookup found in one range.
    enum Found {
        None,
        One,
        Several
    }

    /// @notice `jsonString`, reporting instead of reverting.
    ///
    /// @dev A caller searching several revealed ranges needs to distinguish
    ///      "not in this range" from "malformed", because a field legitimately
    ///      lives in exactly one of them.
    function tryJsonString(bytes memory data, string memory name)
        internal
        pure
        returns (Found found, bytes memory value)
    {
        bytes memory needle = abi.encodePacked('"', name, '":"');
        uint256 at;
        (found, at) = _findUnique(data, needle);
        if (found != Found.One) return (found, "");

        at += needle.length;
        uint256 end = at;
        while (end < data.length && data[end] != '"') {
            ++end;
        }
        // A value with no closing quote inside THIS range has no established
        // extent, and splicing the rest from a neighbouring range is exactly
        // what these reads must not do.
        if (end == data.length) return (Found.None, "");

        value = new bytes(end - at);
        for (uint256 i = 0; i < value.length; ++i) {
            value[i] = data[at + i];
        }
        return (Found.One, value);
    }

    /// @notice `jsonInteger`, reporting instead of reverting.
    function tryJsonInteger(bytes memory data, string memory name)
        internal
        pure
        returns (Found found, bytes memory digits)
    {
        bytes memory needle = abi.encodePacked('"', name, '":');
        uint256 at;
        (found, at) = _findUnique(data, needle);
        if (found != Found.One) return (found, "");

        at += needle.length;
        uint256 end = at;
        while (end < data.length && data[end] >= "0" && data[end] <= "9") {
            ++end;
        }
        if (end == at) revert NoncanonicalInteger(name);
        if (end - at > 1 && data[at] == "0") revert NoncanonicalInteger(name);
        if (end == data.length) return (Found.None, "");
        if (data[end] != "," && data[end] != "}") revert BadIntegerTerminator(name, data[end]);

        digits = new bytes(end - at);
        for (uint256 i = 0; i < digits.length; ++i) {
            digits[i] = data[at + i];
        }
        return (Found.One, digits);
    }

    function _findUnique(bytes memory data, bytes memory needle) private pure returns (Found found, uint256 at) {
        uint256 hit = type(uint256).max;
        for (uint256 i = 0; i + needle.length <= data.length; ++i) {
            if (!_matchesAt(data, needle, i)) continue;
            if (hit != type(uint256).max) return (Found.Several, 0);
            hit = i;
        }
        if (hit == type(uint256).max) return (Found.None, 0);
        return (Found.One, hit);
    }

    /// @notice The value of `"name":"value"`, by its full delimiter.
    function jsonString(bytes memory data, string memory name) internal pure returns (bytes memory value) {
        bytes memory needle = abi.encodePacked('"', name, '":"');
        uint256 at = _uniqueMatch(data, needle, name) + needle.length;

        uint256 end = at;
        while (end < data.length && data[end] != '"') {
            ++end;
        }
        if (end == data.length) revert UnterminatedField(name);

        value = new bytes(end - at);
        for (uint256 i = 0; i < value.length; ++i) {
            value[i] = data[at + i];
        }
    }

    /// @notice The digits of `"name":123`, with the structural byte after them.
    ///
    /// @dev The profile fixes that byte as `,` or `}` and no other
    ///      (REQ-PLAT-51). JSON member order does not say which one closes the
    ///      field, so both are accepted and nothing else is.
    function jsonInteger(bytes memory data, string memory name) internal pure returns (bytes memory digits) {
        bytes memory needle = abi.encodePacked('"', name, '":');
        uint256 at = _uniqueMatch(data, needle, name) + needle.length;

        uint256 end = at;
        while (end < data.length && data[end] >= "0" && data[end] <= "9") {
            ++end;
        }
        if (end == at) revert NoncanonicalInteger(name);
        // A canonical unsigned integer is `0` or has no leading zero. A quoted,
        // signed, fractional or exponent form never reaches here: the first
        // byte would not be a digit, or the terminator check below refuses it.
        if (end - at > 1 && data[at] == "0") revert NoncanonicalInteger(name);
        if (end == data.length) revert UnterminatedField(name);
        if (data[end] != "," && data[end] != "}") {
            revert BadIntegerTerminator(name, data[end]);
        }

        digits = new bytes(end - at);
        for (uint256 i = 0; i < digits.length; ++i) {
            digits[i] = data[at + i];
        }
    }

    /// @notice The value of `name=value` in an `application/x-www-form-urlencoded`
    ///         body.
    ///
    /// @dev The match must begin at byte zero or immediately after `&`, and the
    ///      value must end at `&` or the end of the revealed bytes. Without the
    ///      leading boundary, `client_id=` would also match inside
    ///      `evil_client_id=`.
    function formField(bytes memory data, string memory name) internal pure returns (bytes memory value) {
        bytes memory needle = abi.encodePacked(name, "=");
        uint256 found = type(uint256).max;

        for (uint256 i = 0; i + needle.length <= data.length; ++i) {
            if (i != 0 && data[i - 1] != "&") continue;
            if (!_matchesAt(data, needle, i)) continue;
            if (found != type(uint256).max) revert AmbiguousField(name);
            found = i;
        }
        if (found == type(uint256).max) revert FieldNotFound(name);

        uint256 at = found + needle.length;
        uint256 end = at;
        while (end < data.length && data[end] != "&") {
            ++end;
        }

        value = new bytes(end - at);
        for (uint256 i = 0; i < value.length; ++i) {
            value[i] = data[at + i];
        }
    }

    /// @notice Whether every byte lies in the serializer's byte-identical ASCII
    ///         subset, `[A-Za-z0-9*._-]`.
    ///
    /// @dev REQ-COMMON-16B. The WHATWG form serializer passes exactly this set
    ///      through unchanged and percent-encodes everything else, so bytes
    ///      outside it are the SERIALIZATION rather than the identifier.
    ///      Returning those would hand a Consumer `my%2Bapp` where the client is
    ///      `my+app`.
    function isSerializerSafe(bytes memory value) internal pure returns (bool) {
        if (value.length == 0) return false;
        for (uint256 i = 0; i < value.length; ++i) {
            bytes1 c = value[i];
            bool ok = (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "*" || c == "."
                || c == "_" || c == "-";
            if (!ok) return false;
        }
        return true;
    }

    function _uniqueMatch(bytes memory data, bytes memory needle, string memory name)
        private
        pure
        returns (uint256 at)
    {
        uint256 found = type(uint256).max;
        for (uint256 i = 0; i + needle.length <= data.length; ++i) {
            if (!_matchesAt(data, needle, i)) continue;
            if (found != type(uint256).max) revert AmbiguousField(name);
            found = i;
        }
        if (found == type(uint256).max) revert FieldNotFound(name);
        return found;
    }

    function _matchesAt(bytes memory data, bytes memory needle, uint256 at) private pure returns (bool) {
        for (uint256 j = 0; j < needle.length; ++j) {
            if (data[at + j] != needle[j]) return false;
        }
        return true;
    }
}
