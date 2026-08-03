//! Phase-8 wiring test (the anti-dead-code gate): an atproto `uploadBlob` /
//! `getBlob` / `listBlobs` round-trip reaches the *same* metered byte-path as
//! the S3 plane — not `pds_api` in isolation.
//!
//! Proves: `uploadBlob` requires a bearer session (401 without) and returns the
//! exact D2-confirmed `blob` shape with a real CIDv1 `ref.$link`; `getBlob`
//! returns the exact bytes addressed by that CIDv1; `listBlobs` reports the
//! uploaded CIDv1; and the transfers are metered (an upload + a download receipt
//! land in the ledger, byte counts intact) — the atproto surface and the S3
//! surface share one metering plane.

mod common;

use common::TestServer;

use ciss::cidv1;
use ciss::server::{App, Blobs, Db};

/// Parse a JSON body into a `serde_json::Value`.
async fn json(resp: reqwest::Response) -> serde_json::Value {
    let text = resp.text().await.expect("body text");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse json {text:?}: {e}"))
}

#[tokio::test]
async fn atproto_blob_roundtrip_is_metered_and_matches_the_confirmed_shape() {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();

    // A mock atproto session: the bearer token IS the acting DID (SEAM).
    let did = "did:plc:ciss-phase8-test";
    let payload = b"a blob crosses the atproto boundary".to_vec();
    let n = payload.len() as u64;
    let expected_link = cidv1::blob_cid_string(&payload);
    assert!(
        expected_link.starts_with("bafkrei"),
        "a raw+sha-256 CIDv1 always begins bafkrei",
    );

    // --- uploadBlob without a session: a loud 401, never an anonymous write. ---
    let no_auth = client
        .post(server.url("/xrpc/com.atproto.repo.uploadBlob"))
        .body(payload.clone())
        .send()
        .await
        .expect("uploadBlob (no auth) send");
    assert_eq!(
        no_auth.status().as_u16(),
        401,
        "uploadBlob requires a bearer session",
    );

    // --- uploadBlob with a session: returns the exact D2-confirmed blob shape. ---
    let upload = client
        .post(server.url("/xrpc/com.atproto.repo.uploadBlob"))
        .header("authorization", format!("Bearer {did}"))
        .header("content-type", "text/plain")
        .body(payload.clone())
        .send()
        .await
        .expect("uploadBlob send");
    assert_eq!(upload.status().as_u16(), 200, "authed uploadBlob succeeds");
    let body = json(upload).await;
    let blob = &body["blob"];
    assert_eq!(blob["$type"], "blob", "blob.$type is the literal \"blob\"");
    assert_eq!(
        blob["ref"]["$link"], expected_link,
        "ref.$link is the real CIDv1 (raw + sha-256) of the bytes",
    );
    assert_eq!(
        blob["mimeType"], "text/plain",
        "mimeType echoes the request Content-Type",
    );
    assert_eq!(blob["size"], n, "size is the byte count");

    // --- getBlob: the exact bytes, addressed by the CIDv1. ---
    let get = client
        .get(server.url(&format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid={expected_link}"
        )))
        .send()
        .await
        .expect("getBlob send");
    assert_eq!(get.status().as_u16(), 200, "getBlob succeeds");
    let got = get.bytes().await.expect("getBlob bytes");
    assert_eq!(
        got.as_ref(),
        payload.as_slice(),
        "getBlob returns the exact uploaded bytes",
    );

    // --- getBlob with a non-CIDv1 address: a loud 400, not a 404 or a 500. ---
    let bad = client
        .get(server.url(&format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid=not-a-cid"
        )))
        .send()
        .await
        .expect("getBlob (bad cid) send");
    assert_eq!(
        bad.status().as_u16(),
        400,
        "a malformed CID is a bad request"
    );

    // --- listBlobs: reports the uploaded CIDv1. ---
    let list = json(
        client
            .get(server.url(&format!("/xrpc/com.atproto.sync.listBlobs?did={did}")))
            .send()
            .await
            .expect("listBlobs send"),
    )
    .await;
    let cids = list["cids"].as_array().expect("cids is an array");
    assert_eq!(cids.len(), 1, "one blob uploaded -> one CID listed");
    assert_eq!(cids[0], expected_link, "listBlobs reports the CIDv1");

    // --- Metering: the atproto transfers landed in the shared ledger. ---
    let meter = json(
        client
            .get(server.url(&format!("/{did}/meter")))
            .send()
            .await
            .expect("meter send"),
    )
    .await;
    assert_eq!(
        meter["receipt_count"], 2,
        "atproto uploadBlob + getBlob each metered a receipt",
    );
    assert_eq!(
        meter["upload_bytes"], n,
        "uploadBlob postage == boundary bytes (same metered path as S3 PUT)",
    );
    assert_eq!(
        meter["download_bytes"], n,
        "getBlob postage == boundary bytes (same metered path as S3 GET)",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn list_blobs_reports_distinct_uploads_only() {
    // Distinguishes the source of `listBlobs` from downloads and pins dedup:
    // upload A twice + upload B, then download A. listBlobs must be the distinct
    // *uploaded* CIDs [A, B] — not the downloaded set {A}, not [A, A, B].
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();
    let did = "did:plc:ciss-listblobs";

    let a = b"blob A".to_vec();
    let b = b"blob B and then some".to_vec();
    let link_a = cidv1::blob_cid_string(&a);
    let link_b = cidv1::blob_cid_string(&b);

    let upload = |bytes: Vec<u8>| {
        client
            .post(server.url("/xrpc/com.atproto.repo.uploadBlob"))
            .header("authorization", format!("Bearer {did}"))
            .body(bytes)
            .send()
    };
    upload(a.clone()).await.expect("upload A");
    upload(a.clone()).await.expect("upload A again (dedup)");
    upload(b.clone()).await.expect("upload B");

    // Download A — a download receipt for A now exists, so an Upload-vs-Download
    // filter flip would drop B from the listing.
    client
        .get(server.url(&format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid={link_a}"
        )))
        .send()
        .await
        .expect("download A");

    let list = json(
        client
            .get(server.url(&format!("/xrpc/com.atproto.sync.listBlobs?did={did}")))
            .send()
            .await
            .expect("listBlobs send"),
    )
    .await;
    let cids = list["cids"].as_array().expect("cids array");
    assert_eq!(
        cids.len(),
        2,
        "two distinct blobs uploaded -> two listed (A deduped, B present)",
    );
    assert_eq!(cids[0], link_a, "first-upload order: A first");
    assert_eq!(cids[1], link_b, "then B");

    server.shutdown().await;
}
