//! Phase 4 wiring test: the S3 plane driven by the CLI's own `Client` against a
//! real `ciss` server in-process (the plan's harness convention — not mocked
//! HTTP). Asserts the metered round-trip plus the security edges: a
//! present-but-invalid session is refused 401 (distinct from a good one), a
//! missing object is an oracle-free 404, and a dead server is a clear
//! "unreachable" — not a raw reqwest string.

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::server::{App, Blobs, Db};
use ciss_cli::client::{session_for, Client, Session};

/// Serve a fresh in-memory `ciss` App on an ephemeral loopback port; return its
/// base URL. The task is detached — each test gets its own port, and the process
/// is short-lived.
async fn spawn_server() -> String {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

/// `put` reports the content address + metered bytes + receipt; `get` returns
/// byte-identical content (verified against the cid); `meter` reflects both
/// transfers. The core capability: bytes transferred, shown.
#[tokio::test]
async fn s3_put_get_meter_round_trips_and_meters() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let keypair = derive_keypair("client-master", "client");
    let session = session_for(&keypair);
    let did = session.did.clone();

    let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
    let expected_cid = sha256_hex(&payload);

    let put = client.put_s3(&session, "greeting.txt", &payload).await.expect("put");
    assert_eq!(put.cid, expected_cid, "server content-addresses by sha256");
    assert_eq!(put.bytes, payload.len() as u64, "metered bytes == file length");
    assert_eq!(put.receipt_mode, "unilateral", "raw S3 boundary is unilateral");
    assert!(
        put.etag.as_deref().unwrap_or_default().contains(&expected_cid),
        "ETag echoes the content address, got {:?}",
        put.etag,
    );

    let got = client.get_s3(None, &did, &expected_cid).await.expect("get");
    assert_eq!(got.bytes, payload, "GET returns byte-identical content");
    assert!(got.etag.as_deref().unwrap_or_default().contains(&expected_cid));

    let meter = client.get_meter(&session).await.expect("meter");
    assert_eq!(meter.upload_bytes, payload.len() as u64, "upload postage == bytes");
    assert_eq!(meter.download_bytes, payload.len() as u64, "download postage == bytes");
    assert_eq!(meter.receipt_count, 2, "one upload + one download receipt");
    assert_eq!(meter.running_total_bytes, 2 * payload.len() as u64);
}

/// A present-but-invalid session (right DID + pubkey, garbage signature) must be
/// refused 401 — the same code as no credential — so a mutation that accepts any
/// header as valid is caught. This is the auth boundary the CLI must not paper over.
#[tokio::test]
async fn put_with_a_tampered_session_is_refused_401() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let keypair = derive_keypair("client-master", "client");
    let good = session_for(&keypair);

    // Same identity, but a valid-length yet wrong signature (64 zero bytes).
    let tampered = Session::from_parts(good.did.clone(), keypair.public_key_hex(), "00".repeat(64));
    let err = client
        .put_s3(&tampered, "x.txt", b"data")
        .await
        .expect_err("a bad signature must be refused");
    let msg = err.to_string();
    assert!(msg.contains("401"), "invalid session maps to 401, got {msg:?}");
    assert!(msg.contains("session"), "message is actionable, got {msg:?}");

    // And the good session on the same server still works — the refusal was the
    // credential, not the server.
    client.put_s3(&good, "x.txt", b"data").await.expect("valid session accepted");
}

/// A `get` for a cid that does not exist is a 404 whose message names the
/// oracle-free ambiguity (not found vs. not visible) — never a 403 that would
/// confirm existence.
#[tokio::test]
async fn get_missing_object_is_404_oracle_free() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let keypair = derive_keypair("client-master", "client");
    let did = session_for(&keypair).did;

    let missing = "0".repeat(64);
    let err = client.get_s3(None, &did, &missing).await.expect_err("missing object");
    let msg = err.to_string();
    assert!(msg.contains("404"), "missing object is 404, got {msg:?}");
    assert!(
        msg.contains("not found") || msg.contains("not visible"),
        "404 names the oracle-free ambiguity, got {msg:?}",
    );
}

/// A dead server is reported as unreachable with the URL, not a raw transport error.
#[tokio::test]
async fn unreachable_server_is_a_clear_error() {
    // Port 1 is not listening; the connect is refused.
    let client = Client::new("http://127.0.0.1:1");
    let keypair = derive_keypair("client-master", "client");
    let session = session_for(&keypair);
    let err = client
        .put_s3(&session, "x.txt", b"data")
        .await
        .expect_err("connect must fail");
    assert!(
        err.to_string().contains("unreachable"),
        "a dead server is 'unreachable', got {:?}",
        err.to_string(),
    );
}
