//! The generated strings hash to the numbers the chain pins.
//!
//! Generation makes the Solidity, Rust and TypeScript tables agree with each
//! other. It does not make them RIGHT: a wrong edit to `profiles.json` reaches
//! all three at once, and they would agree perfectly on a platform no verifier
//! is registered for.
//!
//! So the vectors below are the numbers `CeremonyProfile.t.sol` asserts,
//! computed with `cast keccak` outside either implementation. They are what
//! notices an edit that changes an id, which is a change no deployed verifier
//! follows.

use libid_profiles::{
    GITHUB,
    GOOGLE,
    LAUNCH,
    X,
};
use tiny_keccak::{
    Hasher,
    Keccak,
};

fn keccak(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(value.as_bytes());
    hasher.finalize(&mut out);
    out
}

/// Decode 64 lowercase hex characters, so a vector reads as the hex `cast
/// keccak` prints and can be compared against the Solidity test by eye.
fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "a 32-byte vector is 64 hex characters");
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("lowercase hex only"),
    };
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = nibble(bytes[i * 2]) << 4 | nibble(bytes[i * 2 + 1]);
    }
    out
}

#[test]
fn platform_ids_are_the_ones_the_contract_pins() {
    assert_eq!(
        keccak(GOOGLE.platform),
        hex32("8f2f90d8304f6eb382d037c47a041d8c8b4d18bdd8b082fa32828e016a584ca7")
    );
    assert_eq!(
        keccak(X.platform),
        hex32("7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83")
    );
    assert_eq!(
        keccak(GITHUB.platform),
        hex32("07a17bd3c7c8d7b88e93a4d9007e3bc230b0a586a434de0bed6500e9f343deb7")
    );
}

#[test]
fn authority_ids_are_the_ones_the_contract_pins() {
    let x_token = X.token.expect("x notarizes a token session");
    let x_identity = X.identity.expect("x notarizes an identity session");
    let api_x = hex32("4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d");
    assert_eq!(keccak(x_token.session.authority), api_x);
    // X serves both sessions from one host; GitHub does not.
    assert_eq!(keccak(x_identity.session.authority), api_x);

    let gh_token = GITHUB.token.expect("github notarizes a token session");
    let gh_identity = GITHUB
        .identity
        .expect("github notarizes an identity session");
    assert_eq!(
        keccak(gh_token.session.authority),
        hex32("06785da520052bf40d5bf506fb493c41162f55d4e17dffa8b21f02598e981533")
    );
    assert_eq!(
        keccak(gh_identity.session.authority),
        hex32("a5d9c1d593bc385a23a2d56116aab1951e3c66296476c7a7396a515105e8b2c1")
    );
    assert_ne!(
        gh_token.session.authority, gh_identity.session.authority,
        "GitHub's exchange and identity read are served by different hosts"
    );
}

#[test]
fn the_request_lines_end_in_the_space_that_separates_paths() {
    // Without it `GET /user ` would prefix `GET /users/me`, and one profile's
    // path would answer for another's.
    for profile in LAUNCH {
        for session in [
            profile.token.map(|s| s.session),
            profile.identity.map(|s| s.session),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                session.request_line.ends_with(' '),
                "{:?}",
                session.request_line
            );
            assert_eq!(
                session.request_line,
                format!("{} {} ", session.method, session.path)
            );
        }
    }
}

#[test]
fn the_authorities_are_written_as_the_notary_hashes_them() {
    // `authorityId` is keccak256 of the lowercased server name with no
    // trailing dot. A profile string in any other spelling passes the vectors
    // above and produces a different id at run time.
    for profile in LAUNCH {
        for session in [
            profile.token.map(|s| s.session),
            profile.identity.map(|s| s.session),
        ]
        .into_iter()
        .flatten()
        {
            let authority = session.authority;
            assert_eq!(authority, authority.to_ascii_lowercase());
            assert!(!authority.ends_with('.'));
        }
    }
}

#[test]
fn the_counts_follow_the_sessions() {
    // Google's path stops at the Platform Verifier and pays no Notary Fee.
    assert_eq!(GOOGLE.attestation_count(), 0);
    assert_eq!(X.attestation_count(), 2);
    assert_eq!(GITHUB.attestation_count(), 2);
}

#[test]
fn the_launch_list_is_closed() {
    assert_eq!(LAUNCH.len(), 3);
    assert_eq!(libid_profiles::launch("x"), Some(&X));
    // A suffixed platform string is not one of these profiles (TEST-PLAT-17).
    assert_eq!(libid_profiles::launch("x2"), None);
    assert_eq!(libid_profiles::launch("mastodon"), None);
    for profile in LAUNCH {
        assert_eq!(profile.ceremony_version, 1);
    }
}

#[test]
fn the_token_request_head_is_the_headers_beside_it() {
    // Two representations of one agreement: the list a prover builds its
    // request from, and the block the Platform Verifier matches against. They
    // are generated together, and this is what says the two say the same thing.
    for profile in LAUNCH {
        let Some(token) = profile.token else {
            continue;
        };
        // The block is those same lines joined, which is the shape a verifier
        // splits and matches as a set. It carries no `content-length`: that
        // value is the body's own and the verifier reads it off the transcript.
        assert_eq!(
            token.request_header_block,
            token.request_headers.join("\r\n")
        );

        assert!(
            !token
                .request_headers
                .iter()
                .any(|header| header.starts_with("content-length:")),
            "the HTTP client appends the length; a listed one would move it"
        );
        let host = format!("host: {}", token.session.authority);
        assert!(
            token.request_headers.contains(&host.as_str()),
            "the pinned `host` header and the pinned authority must name one server"
        );
    }
}
