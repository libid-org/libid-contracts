//! hyper writes the head this table pins.
//!
//! `X_TOKEN_REQUEST_HEAD` and its Rust twin claim something about a library
//! rather than about a profile: that hyper writes `HTTP/1.1`, lowercases every
//! field name, keeps the order the headers were set in, and appends
//! `content-length` last. A verifier compares against those bytes, so if any
//! part of that is wrong the profile pins a head no honest session produces and
//! every genuine attestation is refused.
//!
//! Reading hyper's source establishes it; this asserts it. The request is built
//! from `request_headers` -- the same list the generator lays the head out from
//! -- and driven through the real `hyper::client::conn::http1` encoder over an
//! in-memory duplex, so what is compared is the bytes hyper actually wrote.
//!
//! What that comparison can and cannot catch is worth stating, because both
//! sides come from one source and move together. It catches a reordering and it
//! catches `content-length` landing anywhere but last -- hyper doing either
//! would break the comparison however the profile is written. It cannot catch
//! the lowercasing claim, because the names in the profile are already
//! lowercase and would match whether hyper folded case or not; that one needs
//! an input the profile does not supply, which is what the last test below is.
//!
//! The GitHub exchange is the reason this exists. It runs in the deployment's
//! backend, which is the prover for that session and reaches the wire through
//! `libid-tlsn::prover_generic` -- the same hyper. Nothing sends that request
//! yet, so the head is pinned before its sender is written, and this is what
//! keeps the two from disagreeing when it is.

use hyper_util::rt::TokioIo;
use libid_profiles::{
    TokenSession,
    GITHUB,
    X,
};
use tokio::io::AsyncReadExt;

/// The bytes hyper puts on the wire for one token session's request head.
///
/// `prover_generic` rewrites the URI to origin-form before sending, so the
/// request-target here is the path, as it is on the wire.
async fn head_hyper_writes(session: &TokenSession, body: &'static [u8]) -> Vec<u8> {
    let mut request = hyper::Request::builder()
        .method(session.session.method)
        .uri(session.session.path);

    // In the order the profile lists them, which is the order the head is laid
    // out in. hyper preserves it; that is half of what this test is for.
    for header in session.request_headers {
        let (name, value) = header.split_once(": ").expect("`name: value`");
        request = request.header(name, value);
    }

    // No `content-length` is set here, deliberately: hyper appends its own for
    // a known-length body, and a builder that set one would land it where the
    // caller put it rather than last. The profile's note says so, and the
    // generator refuses a list that states one.
    let request = request
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
        .expect("valid request");

    let (client, mut server) = tokio::io::duplex(1 << 13);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .expect("handshake");
    tokio::spawn(connection);
    let sending = tokio::spawn(async move { sender.send_request(request).await });

    let mut wire = Vec::new();
    let mut buf = [0u8; 2048];
    while !wire.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = server.read(&mut buf).await.expect("read");
        assert!(read > 0, "the connection closed before the request head");
        wire.extend_from_slice(&buf[..read]);
    }

    // No response ever comes; the pending send fails, which is expected.
    drop(server);
    let _ = sending.await;

    let end = wire
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head boundary");
    wire.truncate(end + 4);
    wire
}

async fn assert_head_matches(session: &TokenSession, body: &'static [u8]) {
    let wire = head_hyper_writes(session, body).await;
    let expected = format!("{}{}\r\n\r\n", session.request_head, body.len());
    assert_eq!(
        String::from_utf8_lossy(&wire),
        expected,
        "hyper wrote a head the profile does not pin"
    );
}

#[tokio::test]
async fn the_x_token_request_head_is_the_one_pinned() {
    let session = X.token.expect("x notarizes a token session");
    // Shaped like the real body: five form fields, no reserved bytes.
    let body = b"grant_type=authorization_code&client_id=abc&code=xyz&redirect_uri=https%3A%2F%2Fexample.test%2Fcb&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";
    assert_head_matches(&session, body).await;
}

#[tokio::test]
async fn the_github_exchange_head_is_the_one_pinned() {
    let session = GITHUB.token.expect("github notarizes a token session");
    // GitHub's body carries the secret last, per REQ-COMMON-22.
    let body = b"client_id=Iv1.abc&code=xyz&redirect_uri=https%3A%2F%2Fexample.test%2Fcb&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I&client_secret=deadbeef";
    assert_head_matches(&session, body).await;
}

#[tokio::test]
async fn the_declared_length_is_the_body_and_moves_with_it() {
    // The verifier compares the declared length against the body the notary
    // signed, so the digits after the pinned run have to be the body's own
    // count -- including when that count needs more than one digit.
    let session = X.token.expect("x notarizes a token session");
    for body in [
        &b"a=1"[..],
        &b"a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10"[..],
    ] {
        let body: &'static [u8] = Box::leak(body.to_vec().into_boxed_slice());
        let wire = head_hyper_writes(&session, body).await;
        let tail = format!("content-length: {}\r\n\r\n", body.len());
        assert!(
            String::from_utf8_lossy(&wire).ends_with(&tail),
            "expected the head to end {tail:?}"
        );
    }
}

#[tokio::test]
async fn hyper_writes_field_names_in_lower_case() {
    // The generator lays the head out in lowercase and its `validate` refuses
    // any other spelling, which is only correct because hyper writes them that
    // way whatever case the builder used. The profile cannot demonstrate that
    // -- its own names are already lowercase -- so this hands hyper a name it
    // would have to fold, and a verifier comparing against a lowercase head
    // depends on the answer.
    let (client, mut server) = tokio::io::duplex(1 << 12);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .expect("handshake");
    tokio::spawn(connection);

    let request = hyper::Request::builder()
        .method("POST")
        .uri("/2/oauth2/token")
        .header("Host", "api.x.com")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(http_body_util::Full::new(hyper::body::Bytes::from_static(
            b"a=1",
        )))
        .expect("valid request");
    let sending = tokio::spawn(async move { sender.send_request(request).await });

    let mut wire = Vec::new();
    let mut buf = [0u8; 1024];
    while !wire.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = server.read(&mut buf).await.expect("read");
        assert!(read > 0, "the connection closed before the request head");
        wire.extend_from_slice(&buf[..read]);
    }
    drop(server);
    let _ = sending.await;

    let head = String::from_utf8_lossy(&wire).to_string();
    assert!(head.contains("\r\nhost: api.x.com\r\n"), "{head:?}");
    assert!(
        head.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"),
        "{head:?}"
    );
    assert!(
        !head.contains("Host:"),
        "hyper kept the caller's case: {head:?}"
    );
    assert!(!head.contains("Content-Type:"), "{head:?}");
}
