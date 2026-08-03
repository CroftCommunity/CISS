//! E86 end-to-end abuse suite: drive the live metered boundary and actively try
//! to break it. Each test is an attack the boundary must refuse or contain.
//!
//! Covered: the server content-addresses (a client cannot misname bytes);
//! tamper-at-rest is caught on the way out; manifest forgery (wrong key, wrong
//! signer, key not bound to the DID, post-sign tampering) is rejected; no bytes
//! means no receipt (walkaway); replays dedup at rest yet meter per transfer;
//! malformed input and out-of-v0 verbs fail cleanly.

mod common;

use common::TestServer;

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::identity::derive_id;
use ciss::manifest::{build_manifest, ManifestLeaf};
use ciss::server::{App, Blobs, Db};

async fn body_json(resp: reqwest::Response) -> serde_json::Value {
    let text = resp.text().await.expect("body");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("json {text:?}: {e}"))
}

#[tokio::test]
async fn server_content_addresses_so_a_client_cannot_misname_bytes() {
    let app = App::new("prov", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();
    let did = derive_id(&derive_keypair("cust", "c").verifying_key());

    let payload = b"authentic bytes".to_vec();
    // The client PUTs under a lying object key; the server ignores the key for
    // addressing and returns the TRUE fingerprint.
    let put = client
        .put(server.url(&format!("/{did}/objects/pretend-this-is-something-else")))
        .body(payload.clone())
        .send()
        .await
        .expect("put");
    assert_eq!(put.status().as_u16(), 200);
    assert_eq!(
        body_json(put).await["cid"],
        sha256_hex(&payload),
        "the server, not the client, chooses the content address",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn tamper_at_rest_is_caught_on_the_way_out() {
    let root = std::env::temp_dir().join(format!("ciss-abuse-tamper-{}", std::process::id()));
    let app = App::new("prov", Blobs::Fs(root.clone()), Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();
    let did = derive_id(&derive_keypair("cust", "c").verifying_key());

    let payload = b"trust but verify".to_vec();
    let cid = sha256_hex(&payload);
    let put = client
        .put(server.url(&format!("/{did}/objects/doc")))
        .body(payload.clone())
        .send()
        .await
        .expect("put");
    assert_eq!(put.status().as_u16(), 200);

    // Corrupt the stored bytes out-of-band (a hostile or buggy backend).
    let at_rest = root.join("blocks").join(&did).join(&cid);
    std::fs::write(&at_rest, b"corrupted at rest").expect("overwrite blob");

    let get = client
        .get(server.url(&format!("/{did}/objects/{cid}")))
        .send()
        .await
        .expect("get");
    assert_eq!(
        get.status().as_u16(),
        500,
        "the boundary re-fingerprints and refuses tampered bytes",
    );
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn manifest_forgery_is_rejected_every_way() {
    let app = App::new("prov", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();

    let customer = derive_keypair("cust", "c");
    let did = derive_id(&customer.verifying_key());
    let attacker = derive_keypair("cust", "attacker");
    let leaves = [ManifestLeaf::new(&sha256_hex(b"x"), 1)];

    // (a) key not bound to the DID: present the attacker's key for `did`.
    let honest = build_manifest(&leaves, &did, &customer);
    let r = client
        .put(server.url(&format!("/{did}/manifest")))
        .header("x-croft-pubkey", attacker.public_key_hex())
        .body(serde_json::to_vec(&honest).unwrap())
        .send()
        .await
        .expect("put");
    assert_eq!(
        r.status().as_u16(),
        403,
        "presented key must derive the DID"
    );

    // (b) signed by the attacker but claiming to be the customer's manifest.
    let forged = build_manifest(&leaves, &did, &attacker);
    let r = client
        .put(server.url(&format!("/{did}/manifest")))
        .header("x-croft-pubkey", customer.public_key_hex())
        .body(serde_json::to_vec(&forged).unwrap())
        .send()
        .await
        .expect("put");
    assert_eq!(
        r.status().as_u16(),
        400,
        "a signature from the wrong key is refused"
    );

    // (c) tampered after signing: inflate a leaf size in the serialized JSON.
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&honest).unwrap()).unwrap();
    tampered["leaves"][0]["size"] = serde_json::json!(999_999);
    let r = client
        .put(server.url(&format!("/{did}/manifest")))
        .header("x-croft-pubkey", customer.public_key_hex())
        .body(serde_json::to_vec(&tampered).unwrap())
        .send()
        .await
        .expect("put");
    assert_eq!(
        r.status().as_u16(),
        400,
        "post-sign tampering breaks the root"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn no_bytes_no_receipt_walkaway_leaves_the_ledger_empty() {
    let app = App::new("prov", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();
    let did = derive_id(&derive_keypair("cust", "ghost").verifying_key());

    // Fetch an object that was never uploaded: 404, and no receipt is minted.
    let get = client
        .get(server.url(&format!("/{did}/objects/{}", sha256_hex(b"never"))))
        .send()
        .await
        .expect("get");
    assert_eq!(
        get.status().as_u16(),
        404,
        "a missing object is a clean 404"
    );

    let meter = body_json(
        client
            .get(server.url(&format!("/{did}/meter")))
            .send()
            .await
            .expect("meter"),
    )
    .await;
    assert_eq!(meter["receipt_count"], 0, "no transfer, no bill");
    server.shutdown().await;
}

#[tokio::test]
async fn replays_dedup_at_rest_but_meter_per_transfer() {
    let app = App::new("prov", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();
    let did = derive_id(&derive_keypair("cust", "c").verifying_key());

    let payload = b"replayed payload".to_vec();
    let n = payload.len() as u64;
    for _ in 0..2 {
        let put = client
            .put(server.url(&format!("/{did}/objects/dup")))
            .body(payload.clone())
            .send()
            .await
            .expect("put");
        assert_eq!(put.status().as_u16(), 200);
    }
    let meter = body_json(
        client
            .get(server.url(&format!("/{did}/meter")))
            .send()
            .await
            .expect("meter"),
    )
    .await;
    // Postage is charged per transfer even though the bytes dedup at rest.
    assert_eq!(meter["receipt_count"], 2, "each transfer is metered");
    assert_eq!(meter["upload_bytes"], 2 * n, "postage tallies both PUTs");
    // Uploads only: the download tally must stay zero (pins the meter's
    // direction split — an upload must not be counted as a download).
    assert_eq!(meter["download_bytes"], 0, "no downloads happened");
    server.shutdown().await;
}

#[tokio::test]
async fn malformed_input_and_out_of_v0_verbs_fail_cleanly() {
    let app = App::new("prov", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();
    let did = derive_id(&derive_keypair("cust", "c").verifying_key());

    // Garbage manifest body.
    let r = client
        .put(server.url(&format!("/{did}/manifest")))
        .header(
            "x-croft-pubkey",
            derive_keypair("cust", "c").public_key_hex(),
        )
        .body(b"{not valid json".to_vec())
        .send()
        .await
        .expect("put");
    assert_eq!(r.status().as_u16(), 400, "malformed manifest is a 400");

    // An unsupported method on a known route: axum answers 405 (clean refusal).
    let r = client
        .delete(server.url(&format!("/{did}/objects/whatever")))
        .send()
        .await
        .expect("delete");
    assert_eq!(
        r.status().as_u16(),
        405,
        "an unsupported method is a clean 405"
    );

    // An out-of-v0 path (e.g. multipart) hits the SEAM fallback.
    let r = client
        .get(server.url(&format!("/{did}/multipart/upload-id")))
        .send()
        .await
        .expect("unmatched path");
    assert_eq!(
        r.status().as_u16(),
        501,
        "out-of-v0 paths are 501 (SEAM fallback)"
    );
    server.shutdown().await;
}
