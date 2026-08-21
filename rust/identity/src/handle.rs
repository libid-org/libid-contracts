//! Turns a platform handle into the one form the identity system keys.
//!
//! This mirrors `contracts/identity/HandleNormalizer.sol` byte for byte. The
//! two are hand written and share nothing but the vector table in
//! `contracts/identity/handles.json`, so a difference between them fails a test
//! instead of looking up a key the chain never wrote.

/// Why a handle was refused. The kinds match the Solidity errors and the
/// TypeScript ones, because the vector table names which refusal it expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    /// Nothing is left after the transform.
    Empty,
    /// More bytes than the platform allows.
    TooLong,
    /// A byte the platform does not allow.
    BadCharacter,
    /// Allowed bytes in an arrangement the platform does not allow.
    BadShape,
}

impl HandleError {
    /// The index the vector table uses for this kind.
    pub const fn kind(self) -> u8 {
        match self {
            Self::Empty => super::handle_vectors::ERROR_EMPTY,
            Self::TooLong => super::handle_vectors::ERROR_TOOLONG,
            Self::BadCharacter => super::handle_vectors::ERROR_BADCHARACTER,
            Self::BadShape => super::handle_vectors::ERROR_BADSHAPE,
        }
    }
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the handle is empty",
            Self::TooLong => "the handle is too long for this platform",
            Self::BadCharacter => {
                "the handle has a character this platform does not allow"
            }
            Self::BadShape => {
                "the handle has an arrangement this platform does not allow"
            }
        })
    }
}

impl std::error::Error for HandleError {}

/// What one platform accepts. Held per platform, so a new platform is
/// configuration rather than code.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    /// Bytes allowed after trimming and the `@` strip.
    pub max_length: usize,
    /// Remove one leading `@`. X and GitHub do. An email keeps its own `@`, so
    /// Google does not.
    pub strip_leading_at: bool,
    /// Validate as an address instead of a bare handle.
    pub is_email: bool,
    /// Allowed by X, not by GitHub.
    pub allow_underscore: bool,
    /// A hyphen may not start or end the handle, and two may not touch.
    pub allow_hyphen: bool,
}

use super::handle_vectors as v;

impl Rules {
    /// X: letters, digits and underscore.
    ///
    /// Every field comes from the generated table rather than being restated
    /// here. A deploy writes these rules on chain, so a value that drifted from
    /// the Solidity side would key every handle on the platform differently —
    /// and the vector table cannot catch a difference no vector exercises.
    pub const X: Self = Self {
        max_length: v::MAX_LENGTH_X,
        strip_leading_at: v::STRIP_LEADING_AT_X,
        is_email: v::IS_EMAIL_X,
        allow_underscore: v::ALLOW_UNDERSCORE_X,
        allow_hyphen: v::ALLOW_HYPHEN_X,
    };

    /// GitHub: letters, digits and hyphen.
    pub const GITHUB: Self = Self {
        max_length: v::MAX_LENGTH_GITHUB,
        strip_leading_at: v::STRIP_LEADING_AT_GITHUB,
        is_email: v::IS_EMAIL_GITHUB,
        allow_underscore: v::ALLOW_UNDERSCORE_GITHUB,
        allow_hyphen: v::ALLOW_HYPHEN_GITHUB,
    };

    /// Google: an address, used exactly as proved.
    pub const GOOGLE: Self = Self {
        max_length: v::MAX_LENGTH_GOOGLE,
        strip_leading_at: v::STRIP_LEADING_AT_GOOGLE,
        is_email: v::IS_EMAIL_GOOGLE,
        allow_underscore: v::ALLOW_UNDERSCORE_GOOGLE,
        allow_hyphen: v::ALLOW_HYPHEN_GOOGLE,
    };

    /// The rules for a platform key from the vector table.
    pub fn for_platform(key: &str) -> Option<Self> {
        match key {
            "x" => Some(Self::X),
            "github" => Some(Self::GITHUB),
            "google" => Some(Self::GOOGLE),
            _ => None,
        }
    }
}

/// The normalized handle, or the reason it was refused.
pub fn normalize(raw: &str, rules: Rules) -> Result<String, HandleError> {
    let input = raw.as_bytes();

    // Trim ASCII spaces only. A tab or a newline is not whitespace to remove
    // here; it is a byte the platform does not allow, and the character check
    // below refuses it. Trimming it would accept "ali\tce" as "alice" here and
    // refuse it in Solidity.
    let mut start = 0usize;
    let mut end = input.len();
    while start < end && input[start] == b' ' {
        start += 1;
    }
    while end > start && input[end - 1] == b' ' {
        end -= 1;
    }

    if rules.strip_leading_at && end > start && input[start] == b'@' {
        start += 1;
    }

    let slice = &input[start..end];
    if slice.is_empty() {
        return Err(HandleError::Empty);
    }
    if slice.len() > rules.max_length {
        return Err(HandleError::TooLong);
    }

    let mut out = Vec::with_capacity(slice.len());
    for &byte in slice {
        // Fold A-Z down. Nothing else changes, so two addresses that differ in
        // more than case stay two identities.
        let c = if byte.is_ascii_uppercase() {
            byte + 0x20
        } else {
            byte
        };
        if !allowed(c, rules) {
            return Err(HandleError::BadCharacter);
        }
        out.push(c);
    }

    if rules.is_email {
        require_email_shape(&out)?;
    } else if rules.allow_hyphen {
        require_hyphen_shape(&out)?;
    }

    // Every byte passed `allowed`, so the result is ASCII.
    Ok(String::from_utf8(out).expect("normalized bytes are ASCII"))
}

/// One byte, after folding. Anything outside the platform's set is refused,
/// including every byte above 0x7f, so a multi-byte character never reaches a
/// key.
fn allowed(c: u8, rules: Rules) -> bool {
    if c.is_ascii_lowercase() || c.is_ascii_digit() {
        return true;
    }
    if rules.is_email {
        // The set a Google address uses. The dot, the plus and the tag stay
        // exactly as proved: this transform must never map two addresses onto
        // one identity.
        return matches!(c, b'.' | b'+' | b'-' | b'_' | b'@');
    }
    if rules.allow_underscore && c == b'_' {
        return true;
    }
    if rules.allow_hyphen && c == b'-' {
        return true;
    }
    false
}

/// Exactly one `@`, and not at either edge.
fn require_email_shape(value: &[u8]) -> Result<(), HandleError> {
    let mut at: Option<usize> = None;
    for (i, &c) in value.iter().enumerate() {
        if c == b'@' {
            if at.is_some() {
                return Err(HandleError::BadShape); // a second one
            }
            at = Some(i);
        }
    }
    match at {
        None => Err(HandleError::BadShape),
        Some(0) => Err(HandleError::BadShape),
        Some(i) if i == value.len() - 1 => Err(HandleError::BadShape),
        Some(_) => Ok(()),
    }
}

/// A hyphen may not start or end the handle, and two may not touch.
fn require_hyphen_shape(value: &[u8]) -> Result<(), HandleError> {
    if value[0] == b'-' || value[value.len() - 1] == b'-' {
        return Err(HandleError::BadShape);
    }
    for i in 1..value.len() {
        if value[i] == b'-' && value[i - 1] == b'-' {
            return Err(HandleError::BadShape);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle_vectors::VECTORS;

    /// The shared table, run against this normalizer. Solidity and TypeScript
    /// run the same cases, so a language that disagrees fails here.
    #[test]
    fn every_vector_matches_the_shared_table() {
        for (i, v) in VECTORS.iter().enumerate() {
            let rules = Rules::for_platform(v.platform)
                .unwrap_or_else(|| panic!("vector {i}: unknown platform {}", v.platform));
            match normalize(v.input, rules) {
                Ok(got) => {
                    assert!(v.accepted, "vector {i}: expected a refusal, got {got:?}");
                    assert_eq!(got, v.output, "vector {i}: wrong normalized handle");
                }
                Err(e) => {
                    assert!(
                        !v.accepted,
                        "vector {i}: expected {:?}, got {e:?}",
                        v.output
                    );
                    assert_eq!(
                        e.kind(),
                        v.error_kind,
                        "vector {i}: refused for the wrong reason ({e:?})"
                    );
                }
            }
        }
    }

    /// The table must keep covering both outcomes. A regeneration that dropped
    /// every refusal would leave the test green and prove nothing.
    #[test]
    fn the_table_covers_both_outcomes() {
        let accepted = VECTORS.iter().filter(|v| v.accepted).count();
        let refused = VECTORS.len() - accepted;
        assert!(accepted > 0, "the table accepts nothing");
        assert!(refused > 0, "the table refuses nothing");
    }

    /// Case folding is the only change to an accepted handle. Anything else
    /// could map two platform accounts onto one identity.
    #[test]
    fn folding_is_the_only_change() {
        assert_eq!(
            normalize("A.B+tag@Example.COM", Rules::GOOGLE).unwrap(),
            "a.b+tag@example.com"
        );
        assert_eq!(normalize("Alice_1", Rules::X).unwrap(), "alice_1");
        assert_eq!(normalize("Octo-Cat", Rules::GITHUB).unwrap(), "octo-cat");
    }
}
