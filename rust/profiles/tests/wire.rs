//! hyper writes a head this table admits.
//!
//! The profile fixes which headers a token request carries, not the order they
//! go in, so what a verifier checks is a set: every line the profile lists,
//! once each, nothing else, plus the `content-length` HTTP framing owns. This
//! asserts that hyper, given the profile's headers, writes exactly that -- the
//! request built from `request_headers` and driven through the real
//! `hyper::client::conn::http1` encoder over an in-memory duplex, so what is
//! compared is the bytes hyper actually wrote.
//!
//! Order is deliberately not asserted. Nothing promises where a client puts a
//! header, and the browser reaches the wire through tlsn's wasm prover, whose
//! `HttpRequest` holds them in a `HashMap` -- a test demanding an order would
//! pass here and fail there for a reason neither end could name.
//!
//! What this still catches is a header hyper adds or drops on its own, and a
//! `content-length` it does not append for a known-length body. The lowercase
//! claim needs an input the profile cannot supply, which is the last case.
//!
//! The GitHub exchange is the reason this exists. It runs in the deployment's
//! backend, which is the prover for that session and reaches the wire through
//! `libid-tlsn::prover_generic` -- the same hyper.

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

    // In the profile's order, which decides nothing: the verifier matches the
    // head as a set, and the order hyper writes is not asserted below.
    for header in session.request_headers {
        let (name, value) = header.split_once(": ").expect("`name: value`");
        request = request.header(name, value);
    }

    // No `content-length` is set here: hyper appends its own for a known-length
    // body, and the profile cannot state one -- its value is the body's own
    // count, which the verifier reads from the head rather than compares.
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

/// The head's header lines, in whatever order hyper wrote them.
fn header_lines(wire: &[u8]) -> Vec<String> {
    let head = String::from_utf8(wire.to_vec()).expect("ascii head");
    let head = head.trim_end_matches("\r\n\r\n");
    head.split("\r\n").skip(1).map(str::to_owned).collect()
}

fn assert_head_admits(session: &TokenSession, wire: &[u8], body_len: usize) {
    let mut written = header_lines(wire);
    written.sort();

    let mut expected: Vec<String> = session
        .request_headers
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    expected.push(format!("content-length: {body_len}"));
    expected.sort();

    assert_eq!(
        written, expected,
        "hyper wrote a head the profile does not admit"
    );
}

#[tokio::test]
async fn the_x_token_request_head_is_one_the_profile_admits() {
    let session = X.token.expect("x notarizes a token session");
    // Shaped like the real body: five form fields, no reserved bytes.
    let body = b"grant_type=authorization_code&client_id=abc&code=xyz&redirect_uri=https%3A%2F%2Fexample.test%2Fcb&code_verifier=5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo";
    let wire = head_hyper_writes(&session, body).await;
    assert_head_admits(&session, &wire, body.len());
}

#[tokio::test]
async fn the_github_exchange_head_is_one_the_profile_admits() {
    let session = GITHUB.token.expect("github notarizes a token session");
    // GitHub's body carries the secret last, per REQ-COMMON-22.
    let body = b"client_id=Iv1.abc&code=xyz&redirect_uri=https%3A%2F%2Fexample.test%2Fcb&code_verifier=5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo&client_secret=deadbeef";
    let wire = head_hyper_writes(&session, body).await;
    assert_head_admits(&session, &wire, body.len());
}

#[tokio::test]
async fn the_declared_length_is_the_body_and_moves_with_it() {
    // The verifier compares the declared length against the body the notary
    // signed, so the digits hyper writes have to be the body's own count --
    // including when that count needs more than one digit.
    let session = X.token.expect("x notarizes a token session");
    for body in [
        &b"a=1"[..],
        &b"a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10"[..],
    ] {
        let body: &'static [u8] = Box::leak(body.to_vec().into_boxed_slice());
        let wire = head_hyper_writes(&session, body).await;
        assert!(
            header_lines(&wire).contains(&format!("content-length: {}", body.len())),
            "the declared length is not the body's own"
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
