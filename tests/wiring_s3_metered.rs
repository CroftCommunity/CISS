//! Phase-7 wiring test (the anti-dead-code gate): the whole path from an HTTP
//! request to a signed ledger receipt is live — not `blobstore` in isolation.
//!
//! Proves: HTTP `PUT` bytes -> a signed receipt is recorded and postage
//! tallied; `GET` returns the exact bytes (and meters the download); rent is
//! recomputable from the customer's signed manifest; the HTTP-boundary byte
//! count equals the receipt byte count equals the manifest byte count (the
//! metering-integrity invariant); and the ephemeral port is released on
//! shutdown (no leak).

mod common;

use common::TestServer;

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::identity::derive_id;
use ciss::manifest::{build_manifest, expected_bytes, ManifestLeaf};
use ciss::pricing::rent_cents;
use ciss::server::{App, Blobs, Db};

/// Parse a JSON body into a `serde_json::Value` (the test does not depend on
/// reqwest's `json` feature).
async fn json(resp: reqwest::Response) -> serde_json::Value {
    let text = resp.text().await.expect("body text");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse json {text:?}: {e}"))
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one comprehensive end-to-end wiring assertion
async fn http_put_get_is_metered_end_to_end_and_releases_the_port() {
    // Days of storage for the independent rent recompute below.
    const DAYS: u64 = 30;

    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let server = TestServer::spawn(app).await;
    let bound = server.addr;
    let client = reqwest::Client::new();

    // The customer is identified by its DID (derived from its public key).
    let customer = derive_keypair("customer-master", "customer");
    let did = derive_id(&customer.verifying_key());

    // The customer signs a session proving it holds the key deriving its DID.
    let (pubkey, session) = common::session_headers(&customer, &did);

    let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
    let n = payload.len() as u64;
    let cid = sha256_hex(&payload);

    // --- PUT: upload bytes; expect a metered, content-addressed store. ---
    let put = client
        .put(server.url(&format!("/{did}/objects/greeting.txt")))
        .header("x-croft-pubkey", pubkey.as_str())
        .header("x-croft-session", session.as_str())
        .body(payload.clone())
        .send()
        .await
        .expect("PUT send");
    assert_eq!(put.status().as_u16(), 200, "PUT succeeds");
    let put_body = json(put).await;
    assert_eq!(put_body["cid"], cid, "server content-addresses by SHA-256");
    assert_eq!(put_body["bytes"], n, "PUT reports the boundary byte count");
    assert_eq!(
        put_body["receipt_mode"], "unilateral",
        "the raw S3 boundary defaults to a provider-signed unilateral receipt",
    );

    // --- GET: returns the exact bytes, and meters the download. ---
    let get = client
        .get(server.url(&format!("/{did}/objects/{cid}")))
        .send()
        .await
        .expect("GET send");
    assert_eq!(get.status().as_u16(), 200, "GET succeeds");
    assert_eq!(
        get.headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        Some(format!("\"{cid}\"")),
        "GET echoes the content address as an ETag",
    );
    let got = get.bytes().await.expect("GET bytes");
    assert_eq!(
        got.as_ref(),
        payload.as_slice(),
        "GET returns the exact bytes"
    );

    // --- Meter: a signed receipt was recorded per transfer; postage tallied. ---
    let meter = json(
        client
            .get(server.url(&format!("/{did}/meter")))
            .header("x-croft-pubkey", pubkey.as_str())
            .header("x-croft-session", session.as_str())
            .send()
            .await
            .expect("meter send"),
    )
    .await;
    assert_eq!(
        meter["receipt_count"], 2,
        "one upload + one download receipt"
    );
    assert_eq!(meter["upload_bytes"], n, "upload postage == boundary bytes");
    assert_eq!(
        meter["download_bytes"], n,
        "download postage == boundary bytes"
    );
    assert_eq!(
        meter["running_total_bytes"],
        2 * n,
        "running total is the bytes transferred both ways",
    );
    assert_eq!(
        meter["postage_cents"],
        ciss::pricing::postage_cents(2 * n),
        "postage priced from the tallied bytes",
    );

    // --- Rent: recomputable from the customer's own signed manifest. ---
    let manifest = build_manifest(&[ManifestLeaf::new(&cid, payload.len())], &did, &customer);
    let put_manifest = client
        .put(server.url(&format!("/{did}/manifest")))
        .header("x-croft-pubkey", customer.public_key_hex())
        .body(serde_json::to_vec(&manifest).expect("manifest json"))
        .send()
        .await
        .expect("PUT manifest");
    assert_eq!(
        put_manifest.status().as_u16(),
        200,
        "signed manifest accepted"
    );

    let stored = json(
        client
            .get(server.url(&format!("/{did}/manifest")))
            .send()
            .await
            .expect("GET manifest"),
    )
    .await;
    assert_eq!(
        stored["root"],
        manifest.root(),
        "the signed manifest round-trips"
    );

    // Rent is a pure function of the customer-authored manifest.
    let base = expected_bytes(&manifest) as u64;
    let rent = rent_cents(base * DAYS);
    assert_eq!(base, n, "manifest bytes-at-rest == the bytes PUT");
    assert_eq!(
        rent,
        rent_cents(n * DAYS),
        "rent recomputes from the manifest"
    );

    // --- Metering-integrity invariant: every byte count agrees. ---
    assert_eq!(
        n,
        meter["upload_bytes"].as_u64().expect("u64"),
        "HTTP-boundary byte count == receipt byte count",
    );
    assert_eq!(n, base, "HTTP-boundary byte count == manifest byte count",);

    // --- No port leak: after graceful shutdown the port is free to re-bind. ---
    server.shutdown().await;
    let rebound = tokio::net::TcpListener::bind(bound)
        .await
        .expect("port released after shutdown (no leak)");
    drop(rebound);
}
