// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Turns a platform handle into the one form the identity system keys.
///
/// @dev The transform is closed. It reads bytes, it does not fold Unicode, and
///      it never consults a table outside this file. Handles on the supported
///      platforms are ASCII, so a closed transform gives Solidity, Rust and
///      TypeScript the same answer with no shared library between them.
///
///      Normalization runs on the write path, not only in a client. The handle
///      arrives inside a proof, so the contract must derive the key itself. A
///      caller that supplied a pre-hashed key could name any handle it liked.
///
///      Every rule below is exercised by the vector table in
///      `contracts/identity/handles.json`, which Rust and TypeScript run too.
library HandleNormalizer {
    /// Nothing is left after the transform.
    error EmptyHandle();
    /// More bytes than the platform allows.
    error HandleTooLong();
    /// A byte the platform does not allow.
    error BadCharacter();
    /// Allowed bytes in an arrangement the platform does not allow.
    error BadShape();

    /// @notice What one platform accepts. Stored per platform, so a new
    ///         platform is configuration rather than code.
    ///
    /// @param maxLength       Bytes allowed after trimming and the `@` strip.
    /// @param stripLeadingAt  Remove one leading `@`. X and GitHub do. An email
    ///                        keeps its own `@`, so Google does not.
    /// @param isEmail         Validate as an address instead of a bare handle.
    /// @param allowUnderscore Allowed by X, not by GitHub.
    /// @param allowHyphen     Allowed by GitHub, not by X. A hyphen may not
    ///                        start or end the handle, and two may not touch.
    struct Rules {
        uint16 maxLength;
        bool stripLeadingAt;
        bool isEmail;
        bool allowUnderscore;
        bool allowHyphen;
    }

    /// @notice What was wrong with a handle, for the readers that answer rather
    ///         than revert.
    enum Problem {
        None,
        Empty,
        TooLong,
        BadChar,
        Shape
    }

    /// @notice The normalized handle, or a revert naming what was wrong.
    ///
    /// @dev The write path. A handle that arrives inside a proof and does not
    ///      normalize is a broken proof, and failing loudly is right.
    function normalize(string memory raw, Rules memory rules) internal pure returns (string memory out) {
        Problem problem;
        (problem, out) = tryNormalize(raw, rules);
        if (problem == Problem.Empty) revert EmptyHandle();
        if (problem == Problem.TooLong) revert HandleTooLong();
        if (problem == Problem.BadChar) revert BadCharacter();
        if (problem == Problem.Shape) revert BadShape();
    }

    /// @notice The same transform, reporting instead of reverting.
    ///
    /// @dev The read path. A resolver is asked "who holds this text", and text
    ///      nobody could hold answers "nobody". A caller resolving whatever a
    ///      user typed must be able to tell that from a platform it cannot
    ///      reach, and a stray space in a recipient field must not revert the
    ///      transaction around it.
    function tryNormalize(string memory raw, Rules memory rules)
        internal
        pure
        returns (Problem problem, string memory normalized)
    {
        bytes memory input = bytes(raw);

        // Trim ASCII spaces only. A tab or a newline is not whitespace to be
        // removed here; it is a byte the platform does not allow, and the
        // character check below refuses it. Trimming it instead would accept
        // "ali\tce" as "alice" in one language and refuse it in another.
        uint256 start = 0;
        uint256 end = input.length;
        while (start < end && input[start] == 0x20) {
            start++;
        }
        while (end > start && input[end - 1] == 0x20) {
            end--;
        }

        if (rules.stripLeadingAt && end > start && input[start] == 0x40) {
            start++;
        }

        uint256 length = end - start;
        if (length == 0) return (Problem.Empty, "");
        if (length > rules.maxLength) return (Problem.TooLong, "");

        bytes memory out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            bytes1 c = input[start + i];
            // Fold A-Z down. Nothing else changes, so two addresses that differ
            // in more than case stay two identities.
            if (c >= 0x41 && c <= 0x5A) {
                c = bytes1(uint8(c) + 0x20);
            }
            if (!_allowed(c, rules)) return (Problem.BadChar, "");
            out[i] = c;
        }

        if (rules.isEmail) {
            if (!_hasEmailShape(out)) return (Problem.Shape, "");
        } else if (rules.allowHyphen) {
            if (!_hasHyphenShape(out)) return (Problem.Shape, "");
        }
        return (Problem.None, string(out));
    }

    /// @dev One byte, after folding. Anything outside the platform's set is a
    ///      `BadCharacter`, including every byte above 0x7f, so a multi-byte
    ///      character can never reach the key.
    function _allowed(bytes1 c, Rules memory rules) private pure returns (bool) {
        if (c >= 0x61 && c <= 0x7A) return true; // a-z
        if (c >= 0x30 && c <= 0x39) return true; // 0-9
        if (rules.isEmail) {
            // The set a Google address uses. The dot, the plus and the tag stay
            // exactly as proved: this transform must never map two addresses to
            // one identity.
            return c == 0x2E || c == 0x2B || c == 0x2D || c == 0x5F || c == 0x40;
        }
        if (rules.allowUnderscore && c == 0x5F) return true;
        if (rules.allowHyphen && c == 0x2D) return true;
        return false;
    }

    /// @dev Exactly one `@`, and not at either edge.
    function _hasEmailShape(bytes memory value) private pure returns (bool) {
        uint256 at = type(uint256).max;
        for (uint256 i = 0; i < value.length; i++) {
            if (value[i] == 0x40) {
                if (at != type(uint256).max) return false; // a second one
                at = i;
            }
        }
        if (at == type(uint256).max) return false; // none
        return at != 0 && at != value.length - 1; // an empty side
    }

    /// @dev A hyphen may not start or end the handle, and two may not touch.
    function _hasHyphenShape(bytes memory value) private pure returns (bool) {
        if (value[0] == 0x2D || value[value.length - 1] == 0x2D) return false;
        for (uint256 i = 1; i < value.length; i++) {
            if (value[i] == 0x2D && value[i - 1] == 0x2D) return false;
        }
        return true;
    }
}
