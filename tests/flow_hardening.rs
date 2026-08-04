//! Workflow tier — response-hardening guards (Phase 5). Finding IDs refer to
//! `docs/SECURITY-REVIEW-2026-08-03.md`.

mod common;

use common::World;

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::identity::derive_id;

/// I4 — a 5xx must not leak internal state (here, the content-hash oracle of a
/// tampered object). The body is a fixed public string.
#[tokio::test]
async fn a_tampered_read_returns_a_generic_error_body() {
    let world = World::spawn_fs().await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();

    let cid = owner
        .put_object(&did, "doc", b"trust but verify")
        .await
        .ok()
        .cid();

    // Corrupt the bytes at rest, out of band.
    let path = world
        .data_dir()
        .expect("fs world")
        .join("blocks")
        .join(&did)
        .join(&cid);
    std::fs::write(&path, b"corrupted at rest").expect("overwrite");

    let out = world.anonymous().get_object(&did, &cid).await; // reads are public
    out.refused(500);
    assert_eq!(
        out.text(),
        "internal error",
        "a 5xx body must not leak the content hash / io / sqlite detail",
    );
    // Belt-and-braces: the actual fingerprint of the corrupted bytes is not shown.
    out.omits(&sha256_hex(b"corrupted at rest"));

    world.shutdown().await;
}

/// I9 — served blobs carry nosniff + attachment + a locked-down CSP, so
/// attacker-uploaded bytes cannot execute or be sniffed as same-origin HTML.
#[tokio::test]
async fn served_blobs_carry_download_hardening_headers() {
    let world = World::spawn().await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();
    let cid = owner
        .put_object(&did, "x", b"<script>alert(document.domain)</script>")
        .await
        .ok()
        .cid();

    let resp = reqwest::Client::new()
        .get(world.url(&format!("/{did}/objects/{cid}")))
        .send()
        .await
        .expect("get");
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(header("x-content-type-options").as_deref(), Some("nosniff"));
    assert_eq!(header("content-disposition").as_deref(), Some("attachment"));
    assert!(
        header("content-security-policy").is_some(),
        "a CSP is present on served blobs",
    );

    world.shutdown().await;
}

/// I13 — an invalid / non-media-type Content-Type is not stored and echoed back;
/// the response falls back to the default rather than reflecting a garbage value.
#[tokio::test]
async fn an_invalid_content_type_is_not_reflected() {
    let world = World::spawn().await;
    // Reconstruct the owner's session for a raw uploadBlob with a custom header.
    let keypair = derive_keypair("flow-master", "owner");
    let did = derive_id(&keypair.verifying_key());
    let (pubkey, session) = common::session_headers(&keypair, &did);

    let resp = reqwest::Client::new()
        .post(world.url("/xrpc/com.atproto.repo.uploadBlob"))
        .header("x-croft-pubkey", pubkey.as_str())
        .header("x-croft-session", session.as_str())
        .header("content-type", "<script>alert(1)</script>")
        .body(b"payload".to_vec())
        .send()
        .await
        .expect("uploadBlob");
    let body: serde_json::Value =
        serde_json::from_str(&resp.text().await.expect("text")).expect("json");
    assert_eq!(
        body["blob"]["mimeType"], "application/octet-stream",
        "a non-media-type Content-Type is not reflected",
    );

    world.shutdown().await;
}
