//! Workflow tier — atproto identity (Model R: service-auth JWT + DID resolution).
//!
//! These stories exercise the whole authenticated `did:` path end-to-end over HTTP:
//! a persona mints a real secp256k1 service-auth JWT, the server resolves the `iss`
//! DID (via a hermetic fixture resolver), verifies the signature + `aud`/`lxm`/`exp`
//! bindings, and attributes the transfer to the *resolved* DID. Every guard was a
//! finding: A2 (a forged token names but cannot become a victim), the `lxm`/`aud`
//! bindings (no cross-method/cross-service replay), `exp`, resolver fail-closed with
//! a pinned-admin break-glass (ADR 0001 §5), and PDS-compat public reads.

mod common;

use common::{World, SERVICE_DID, UPLOAD_LXM};

/// The `$link` CIDv1 from an `uploadBlob` response.
fn blob_link(out: &common::Outcome) -> String {
    out.json()["blob"]["ref"]["$link"]
        .as_str()
        .expect("a blob ref $link")
        .to_owned()
}

#[tokio::test]
async fn a_valid_service_auth_jwt_uploads_and_is_attributed_to_the_resolved_did() {
    let world = World::spawn_atproto(&["alice"]).await;
    let alice = world.atproto_actor("alice");

    let out = alice.upload_blob(b"hello atproto").await;
    out.ok();
    let link = blob_link(&out);

    // Attribution: the blob lands under the resolved DID's namespace.
    world.anonymous().list_blobs(alice.did()).await.discloses(&link);
    world.shutdown().await;
}

#[tokio::test]
async fn a_forged_token_naming_a_victim_is_refused_and_signs_no_receipt() {
    // The attacker mints a token claiming iss = the victim's DID, but signs it with
    // the attacker's own key. Resolved against the victim's key, the signature
    // fails — and nothing is stored under the victim (A2 for the did: space).
    let world = World::spawn_atproto(&["attacker", "victim"]).await;
    let attacker = world.atproto_actor("attacker");
    let victim = world.atproto_actor("victim");

    let forged = attacker.sign_token(victim.did(), SERVICE_DID, UPLOAD_LXM, u64::MAX, "forge-1");
    attacker
        .upload_blob_with_token(&forged, b"planted")
        .await
        .refused(401);

    let listed = world.anonymous().list_blobs(victim.did()).await;
    listed.ok();
    assert_eq!(
        listed.json()["cids"].as_array().map(Vec::len),
        Some(0),
        "the victim namespace must hold nothing",
    );
    world.shutdown().await;
}

#[tokio::test]
async fn a_token_bound_to_a_different_method_is_refused() {
    let world = World::spawn_atproto(&["alice"]).await;
    let alice = world.atproto_actor("alice");
    // Minted for getBlob, presented to uploadBlob.
    let token = alice.sign_token(
        alice.did(),
        SERVICE_DID,
        "com.atproto.sync.getBlob",
        common_now() + 300,
        "m1",
    );
    alice.upload_blob_with_token(&token, b"x").await.refused(401);
    world.shutdown().await;
}

#[tokio::test]
async fn a_token_for_another_service_is_refused() {
    let world = World::spawn_atproto(&["alice"]).await;
    let alice = world.atproto_actor("alice");
    let token = alice.sign_token(
        alice.did(),
        "did:web:evil.example",
        UPLOAD_LXM,
        common_now() + 300,
        "a1",
    );
    alice.upload_blob_with_token(&token, b"x").await.refused(401);
    world.shutdown().await;
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let world = World::spawn_atproto(&["alice"]).await;
    let alice = world.atproto_actor("alice");
    let token = alice.sign_token(alice.did(), SERVICE_DID, UPLOAD_LXM, 1, "e1");
    alice.upload_blob_with_token(&token, b"x").await.refused(401);
    world.shutdown().await;
}

#[tokio::test]
async fn a_replayed_token_is_refused_the_second_time() {
    let world = World::spawn_atproto(&["alice"]).await;
    let alice = world.atproto_actor("alice");
    let token = alice.valid_upload_token("replay-1");
    alice.upload_blob_with_token(&token, b"once").await.ok();
    alice
        .upload_blob_with_token(&token, b"once")
        .await
        .refused(401);
    world.shutdown().await;
}

#[tokio::test]
async fn when_the_resolver_is_down_a_pinned_admin_still_authenticates() {
    // Break-glass: the network resolver answers nothing, but the pinned admin DID
    // resolves locally, so admin auth survives an outage (ADR 0001 §5).
    let world = World::spawn_atproto_resolver_down(&["admin"]).await;
    let admin = world.atproto_actor("admin");
    admin.upload_blob(b"admin bytes").await.ok();
    world.shutdown().await;
}

#[tokio::test]
async fn when_the_resolver_is_down_a_non_admin_fails_closed() {
    let world = World::spawn_atproto_resolver_down(&["admin"]).await;
    let stranger = world.atproto_actor("stranger");
    stranger.upload_blob(b"stranger bytes").await.refused(401);
    world.shutdown().await;
}

#[tokio::test]
async fn a_world_readable_blob_stays_publicly_readable() {
    // PDS-compat: once stored, a blob is fetchable with no auth (getBlob is public).
    let world = World::spawn_atproto(&["alice"]).await;
    let alice = world.atproto_actor("alice");
    let out = alice.upload_blob(b"public bytes").await;
    out.ok();
    let link = blob_link(&out);

    world
        .anonymous()
        .get_blob(alice.did(), &link)
        .await
        .returns(b"public bytes");
    world.shutdown().await;
}

#[tokio::test]
async fn ciss_serves_its_own_did_web_document() {
    // did:web:ciss.croft.ing resolves at https://ciss.croft.ing/.well-known/did.json
    // so external clients can address CISS as a service-auth `aud`.
    let world = World::spawn().await;
    let resp = reqwest::get(world.url("/.well-known/did.json"))
        .await
        .expect("request");
    assert_eq!(resp.status(), 200, "did.json must be public");
    let body = resp.bytes().await.expect("body");
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("json doc");
    assert_eq!(doc["id"], "did:web:ciss.croft.ing");
    assert!(doc["service"].is_array(), "a service entry");
    assert_eq!(
        doc["service"][0]["serviceEndpoint"],
        "https://ciss.croft.ing",
    );
    world.shutdown().await;
}

/// The current unix time in seconds (flows that mint custom-`exp` tokens).
fn common_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
