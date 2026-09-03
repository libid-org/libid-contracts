// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibString — Bank-specific byte/string primitives NOT covered by OZ.
/// @dev Only what OpenZeppelin doesn't provide: multi-byte substring search
///      (OZ `Bytes.indexOf` is single-byte), case-insensitive compare/search
///      (OZ `Strings.equal` is case-sensitive), token-char classification, tight
///      author-id parsing, and decimal-amount scaling. For the rest, callers use
///      OZ directly: `Strings.toHexString(address)` and `Bytes.slice(...)` for a
///      memory substring. require-strings replaced with custom errors.
library LibString {
    error InvalidRange();
    error MalformedAuthorId();
    error EmptyAuthorId();
    error MultipleDecimalPoints();

    /// @dev Find `needle` in memory `haystack` from `from` (case-sensitive).
    /// @dev The single substring-search primitive. Find `needle` in `haystack`
    ///      from `from`; `ci` = ASCII case-insensitive. Memory haystack unifies
    ///      the memory/calldata variants — a calldata arg is copied in, and the
    ///      found position is identical byte-for-byte, so a caller may slice its
    ///      ORIGINAL calldata by the returned position. `(true, from)` for an
    ///      empty needle.
    function indexOf(bytes memory haystack, bytes memory needle, uint256 from, bool ci)
        internal
        pure
        returns (bool, uint256)
    {
        if (needle.length == 0) return (true, from);
        if (from + needle.length > haystack.length) return (false, 0);
        uint256 searchLen = haystack.length - needle.length + 1;
        for (uint256 i = from; i < searchLen; i++) {
            bool found = true;
            for (uint256 j = 0; j < needle.length; j++) {
                bytes1 h = haystack[i + j];
                bytes1 n = needle[j];
                if (ci ? toLower(h) != toLower(n) : h != n) {
                    found = false;
                    break;
                }
            }
            if (found) return (true, i);
        }
        return (false, 0);
    }

    /// @dev Substring of calldata bytes `[start, end)`. (For a MEMORY substring
    ///      use OZ `Bytes.slice` — this calldata variant is native slicing.)
    function substringCalldata(bytes calldata data, uint256 start, uint256 end) internal pure returns (string memory) {
        if (end < start || end > data.length) revert InvalidRange();
        return string(data[start:end]);
    }

    /// @dev Case-insensitive string equality.
    function caseInsensitiveEqual(string memory a, string memory b) internal pure returns (bool) {
        bytes memory ab = bytes(a);
        bytes memory bb = bytes(b);
        if (ab.length != bb.length) return false;
        for (uint256 i = 0; i < ab.length; i++) {
            if (toLower(ab[i]) != toLower(bb[i])) return false;
        }
        return true;
    }

    /// @dev Whether `haystack` contains `needle`; `ci` = case-insensitive.
    ///      Thin wrapper over [`indexOf`].
    function contains(bytes memory haystack, bytes memory needle, bool ci) internal pure returns (bool) {
        (bool found,) = indexOf(haystack, needle, 0, ci);
        return found;
    }

    /// @dev Whether `haystack` begins with `prefix` (case-sensitive). Distinct from
    ///      `contains` — the match must be at position 0.
    function startsWith(bytes memory haystack, bytes memory prefix) internal pure returns (bool) {
        if (haystack.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; i++) {
            if (haystack[i] != prefix[i]) return false;
        }
        return true;
    }

    /// @dev Parse id from a tight author-id snippet: quoted `"k":"<id>"` or bare
    ///      `"k":<id>[,}]`. Value is after the LAST colon.
    function extractId(bytes calldata s) internal pure returns (string memory) {
        uint256 n = s.length;
        uint256 c = n;
        while (c > 0) {
            c--;
            if (s[c] == ":") break;
        }
        if (c >= n || s[c] != ":") revert MalformedAuthorId();
        uint256 i = c + 1;
        bool quoted = i < n && s[i] == '"';
        if (quoted) i++;
        uint256 start = i;
        if (quoted) {
            while (i < n && s[i] != '"') i++;
        } else {
            while (i < n && s[i] >= 0x30 && s[i] <= 0x39) i++;
        }
        if (i <= start) revert EmptyAuthorId();
        return string(s[start:i]);
    }

    /// @dev Valid token-name character: a-z, A-Z, 0-9, `$`, `_`, `.`.
    function isTokenChar(bytes1 c) internal pure returns (bool) {
        return (c >= 0x41 && c <= 0x5A) // A-Z
            || (c >= 0x61 && c <= 0x7A) // a-z
            || (c >= 0x30 && c <= 0x39) // 0-9
            || c == "$" || c == "_" || c == ".";
    }

    /// @dev ASCII lower-casing of a single byte.
    function toLower(bytes1 b) internal pure returns (bytes1) {
        if (b >= 0x41 && b <= 0x5A) {
            return bytes1(uint8(b) + 32);
        }
        return b;
    }

    /// @dev Human decimal amount (e.g. "0.05", "100") → wei at `decimals`.
    ///      Digits beyond `decimals` precision are truncated.
    function parseDecimalAmount(string memory s, uint8 decimals) internal pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 intPart = 0;
        uint256 fracPart = 0;
        uint8 fracDigits = 0;
        bool inFrac = false;
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ".") {
                if (inFrac) revert MultipleDecimalPoints();
                inFrac = true;
            } else if (b[i] >= "0" && b[i] <= "9") {
                if (!inFrac) {
                    intPart = intPart * 10 + uint256(uint8(b[i]) - 48);
                } else if (fracDigits < decimals) {
                    fracPart = fracPart * 10 + uint256(uint8(b[i]) - 48);
                    fracDigits++;
                }
            }
        }
        uint256 scale = 10 ** decimals;
        uint256 fracScale = 10 ** (decimals - fracDigits);
        return intPart * scale + fracPart * fracScale;
    }
}
