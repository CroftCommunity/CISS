//! Gated reads — the workflow corpus (Phase 5: the `id:`-owner / Model-A
//! lifecycle over real HTTP). An `id:` owner sets a read policy by PUTting a
//! self-signed policy record; reads honor it live through the same server.
//!
//! This is the comprehensive should-work **and** should-NOT proof for Model A:
//! grant/revoke/override behave, and every denial (a non-grantee read, a forged
//! policy, a rolled-back seq) is refused — a regression that opens the gate must
//! break a test here. The `did:`-owner (Model C) lifecycle lands in Phase 6, and
//! the full cross-form matrix in Phase 7.

mod common;

use common::{TestServer, World, SERVICE_DID, SET_POLICY_LXM};

use ciss::crypto::{derive_keypair, sha256_hex, Keypair};
use ciss::identity::derive_id;
use ciss::policy::{PolicyRecord, ReadClass};
use ciss::server::{App, Blobs, Db};

/// Unix seconds now (for minting custom-`exp` tokens in the Model-C flow).
fn now_s() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const MASTER: &str = "flow-gated-reads-master";

/// An actor's `(pubkey, session)` headers for the `id:` session space.
fn actor(label: &str) -> (Keypair, String, String, String) {
    let kp = derive_keypair(MASTER, label);
    let did = derive_id(&kp.verifying_key());
    let (pubkey, session) = common::session_headers(&kp, &did);
    (kp, did, pubkey, session)
}

/// A signed namespace policy record body (Model A), serialized for the wire.
fn namespace_policy(
    owner_did: &str,
    class: ReadClass,
    readers: &[String],
    seq: u64,
    owner_kp: &Keypair,
) -> Vec<u8> {
    let record = PolicyRecord::sign_owner(owner_did, None, class, readers, seq, owner_kp);
    serde_json::to_vec(&record).expect("serialize policy")
}

#[tokio::test]
async fn id_owner_policy_lifecycle_over_http() {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();

    let (owner_kp, owner_did, owner_pk, owner_sess) = actor("owner");
    let (_alice_kp, alice_did, alice_pk, alice_sess) = actor("alice");
    let (_bob_kp, bob_did, bob_pk, bob_sess) = actor("bob");
    let (attacker_kp, _attacker_did, _apk, _asess) = actor("attacker");

    // --- The owner uploads two blobs (S3 plane, owner session). ---
    let secret = b"the secret blob".to_vec();
    let public = b"a public blob".to_vec();
    let secret_cid = sha256_hex(&secret);
    let public_cid = sha256_hex(&public);
    for (key, bytes) in [("s", &secret), ("p", &public)] {
        let r = client
            .put(server.url(&format!("/{owner_did}/objects/{key}")))
            .header("x-croft-pubkey", owner_pk.as_str())
            .header("x-croft-session", owner_sess.as_str())
            .body(bytes.clone())
            .send()
            .await
            .expect("upload");
        assert_eq!(r.status().as_u16(), 200, "owner uploads a blob");
    }

    // A GET of `secret_cid` as some actor (headers optional for anon).
    let get = |pk: Option<(&str, &str)>, cid: &str| {
        let mut req = client.get(server.url(&format!("/{owner_did}/objects/{cid}")));
        if let Some((p, s)) = pk {
            req = req.header("x-croft-pubkey", p).header("x-croft-session", s);
        }
        req.send()
    };
    let put_policy = |body: Vec<u8>| {
        client
            .put(server.url(&format!("/{owner_did}/policy")))
            .body(body)
            .send()
    };

    // Before any policy: the secret blob is world-readable (PDS-compat).
    assert_eq!(
        get(None, &secret_cid).await.expect("anon get").status().as_u16(),
        200,
        "no policy yet -> world-readable",
    );

    // --- The owner gates the whole namespace to grantees:[alice] (seq 1). ---
    let set = put_policy(namespace_policy(
        &owner_did,
        ReadClass::Grantees,
        std::slice::from_ref(&alice_did),
        1,
        &owner_kp,
    ))
    .await
    .expect("set policy");
    assert_eq!(set.status().as_u16(), 200, "owner sets a policy");

    // alice reads; bob and anon get 404 (oracle-free, not 403); owner reads.
    assert_eq!(
        get(Some((&alice_pk, &alice_sess)), &secret_cid).await.unwrap().status().as_u16(),
        200,
        "the grantee reads",
    );
    assert_eq!(
        get(Some((&bob_pk, &bob_sess)), &secret_cid).await.unwrap().status().as_u16(),
        404,
        "a non-grantee gets 404, not the bytes",
    );
    assert_eq!(
        get(None, &secret_cid).await.unwrap().status().as_u16(),
        404,
        "anon gets 404 under a gate",
    );
    assert_eq!(
        get(Some((&owner_pk, &owner_sess)), &secret_cid).await.unwrap().status().as_u16(),
        200,
        "the owner always reads its own gated object",
    );

    // --- Grant bob (seq 2): bob now reads. ---
    let grant_bob = put_policy(namespace_policy(
        &owner_did,
        ReadClass::Grantees,
        &[alice_did.clone(), bob_did.clone()],
        2,
        &owner_kp,
    ))
    .await
    .expect("grant bob");
    assert_eq!(grant_bob.status().as_u16(), 200);
    assert_eq!(
        get(Some((&bob_pk, &bob_sess)), &secret_cid).await.unwrap().status().as_u16(),
        200,
        "a newly-granted reader reads",
    );

    // --- Revoke bob (seq 3): bob is denied again (revocation bites). ---
    let revoke = put_policy(namespace_policy(
        &owner_did,
        ReadClass::Grantees,
        std::slice::from_ref(&alice_did),
        3,
        &owner_kp,
    ))
    .await
    .expect("revoke bob");
    assert_eq!(revoke.status().as_u16(), 200);
    assert_eq!(
        get(Some((&bob_pk, &bob_sess)), &secret_cid).await.unwrap().status().as_u16(),
        404,
        "a revoked reader is denied again",
    );

    // --- Per-object world override: the public blob is exposed again. ---
    let override_record =
        PolicyRecord::sign_owner(&owner_did, Some(&public_cid), ReadClass::World, &[], 1, &owner_kp);
    let set_obj = client
        .put(server.url(&format!("/{owner_did}/objects/{public_cid}/policy")))
        .body(serde_json::to_vec(&override_record).unwrap())
        .send()
        .await
        .expect("object policy");
    assert_eq!(set_obj.status().as_u16(), 200);
    assert_eq!(
        get(None, &public_cid).await.unwrap().status().as_u16(),
        200,
        "a per-object world override exposes just that blob",
    );
    assert_eq!(
        get(None, &secret_cid).await.unwrap().status().as_u16(),
        404,
        "the namespace gate still hides the other object",
    );

    // --- Adversarial: a forged policy (attacker signs for the owner's namespace)
    // is refused (403), and access is unchanged. ---
    let forged = namespace_policy(
        &owner_did,
        ReadClass::World,
        &[],
        99,
        &attacker_kp, // wrong signer — does not derive owner_did
    );
    assert_eq!(
        put_policy(forged).await.unwrap().status().as_u16(),
        403,
        "a forged policy is refused",
    );
    assert_eq!(
        get(Some((&bob_pk, &bob_sess)), &secret_cid).await.unwrap().status().as_u16(),
        404,
        "the forged policy changed nothing",
    );

    // --- Anti-rollback: a lower/equal seq is refused (409), no un-revoke. ---
    let rollback = namespace_policy(
        &owner_did,
        ReadClass::Grantees,
        &[alice_did.clone(), bob_did.clone()],
        1, // <= stored seq (3)
        &owner_kp,
    );
    assert_eq!(
        put_policy(rollback).await.unwrap().status().as_u16(),
        409,
        "a rolled-back seq is refused",
    );
    assert_eq!(
        get(Some((&bob_pk, &bob_sess)), &secret_cid).await.unwrap().status().as_u16(),
        404,
        "the rollback did not un-revoke bob",
    );

    // --- Read-back (Q4 owner-only reader-set visibility). ---
    let read_policy = |pk: Option<(&str, &str)>| {
        let mut req = client.get(server.url(&format!("/{owner_did}/policy")));
        if let Some((p, s)) = pk {
            req = req.header("x-croft-pubkey", p).header("x-croft-session", s);
        }
        req.send()
    };
    let owner_view = read_policy(Some((&owner_pk, &owner_sess))).await.unwrap();
    assert_eq!(owner_view.status().as_u16(), 200);
    let owner_json: serde_json::Value =
        serde_json::from_str(&owner_view.text().await.unwrap()).unwrap();
    assert!(owner_json.get("readers").is_some(), "the owner sees the reader set");

    let alice_view = read_policy(Some((&alice_pk, &alice_sess))).await.unwrap();
    assert_eq!(alice_view.status().as_u16(), 200);
    let alice_json: serde_json::Value =
        serde_json::from_str(&alice_view.text().await.unwrap()).unwrap();
    assert!(alice_json.get("readers").is_none(), "a grantee never sees the reader set");
    assert_eq!(alice_json["may_read"], true, "a grantee learns only its own access");

    assert_eq!(
        read_policy(Some((&bob_pk, &bob_sess))).await.unwrap().status().as_u16(),
        404,
        "a non-grantee cannot read the policy back",
    );

    server.shutdown().await;
}

/// Model C: a `did:` owner (external identity provider) sets a read policy by
/// presenting a service-auth JWT — CISS verifies it and provider-attests the
/// record. The gate then behaves identically to a Model-A (owner-signed) policy,
/// and every JWT defect (wrong `lxm`/`aud`, expired, replayed, wrong target DID)
/// is refused with no policy change.
#[tokio::test]
async fn did_owner_policy_via_service_auth_jwt() {
    let world = World::spawn_atproto(&["owner"]).await;
    let owner = world.atproto_actor("owner");
    let owner_did = owner.did().to_owned(); // did:web:owner.test

    // The `did:` owner uploads a blob to its namespace (atproto uploadBlob, JWT).
    let secret = b"a model-c gated blob".to_vec();
    owner.upload_blob(&secret).await.ok();
    let hex = sha256_hex(&secret);

    // Readers are `id:` personas (grantees may be any DID); they read via the S3
    // surface with their session.
    let alice = world.actor("alice");
    let bob = world.actor("bob");
    let anon = world.anonymous();

    // The `did:` owner grants alice via a valid set-policy JWT (Model C).
    let intent = serde_json::json!({
        "read_class": "grantees",
        "readers": [alice.did()],
        "seq": 1,
    })
    .to_string();
    owner
        .put_policy_with_token(&owner_did, &owner.valid_set_policy_token("jti-set-1"), &intent)
        .await
        .ok();

    // The gate behaves identically to Model A: alice reads, bob and anon 404.
    alice.get_object(&owner_did, &hex).await.returns(&secret);
    bob.get_object(&owner_did, &hex).await.refused(404);
    anon.get_object(&owner_did, &hex).await.refused(404);

    // --- Every JWT defect is refused, and access is unchanged (bob stays 404). ---
    let assert_bob_still_denied = |w: &World| {
        let owner_did = owner_did.clone();
        let hex = hex.clone();
        let bob = w.actor("bob");
        async move { bob.get_object(&owner_did, &hex).await.refused(404) }
    };

    // Wrong lxm: a token minted for uploadBlob cannot set policy.
    let wrong_lxm = owner.sign_token(
        &owner_did,
        SERVICE_DID,
        "com.atproto.repo.uploadBlob",
        now_s() + 300,
        "jti-wrong-lxm",
    );
    owner
        .put_policy_with_token(&owner_did, &wrong_lxm, &intent)
        .await
        .refused(403);
    assert_bob_still_denied(&world).await;

    // Wrong aud: a token minted for another service.
    let wrong_aud = owner.sign_token(
        &owner_did,
        "did:web:evil.test",
        SET_POLICY_LXM,
        now_s() + 300,
        "jti-wrong-aud",
    );
    owner
        .put_policy_with_token(&owner_did, &wrong_aud, &intent)
        .await
        .refused(403);

    // Expired token.
    let expired = owner.sign_token(
        &owner_did,
        SERVICE_DID,
        SET_POLICY_LXM,
        now_s() - 10,
        "jti-expired",
    );
    owner
        .put_policy_with_token(&owner_did, &expired, &intent)
        .await
        .refused(403);

    // Replayed jti: the same token used twice — the second use is refused.
    let replay_tok = owner.valid_set_policy_token("jti-replay");
    let higher = serde_json::json!({
        "read_class": "grantees",
        "readers": [alice.did(), bob.did()],
        "seq": 2,
    })
    .to_string();
    owner
        .put_policy_with_token(&owner_did, &replay_tok, &higher)
        .await
        .ok();
    // First use granted bob (seq 2); the replay (same jti) must be refused.
    owner
        .put_policy_with_token(&owner_did, &replay_tok, &higher)
        .await
        .refused(403);

    // Wrong target: a valid token for owner cannot set policy on another DID's
    // namespace (auth.did != target).
    let victim = world.atproto_actor("owner"); // reuse the key; target a foreign DID
    let foreign_did = "did:web:victim.test";
    victim
        .put_policy_with_token(
            foreign_did,
            &victim.valid_set_policy_token("jti-foreign"),
            &intent,
        )
        .await
        .refused(403);

    world.shutdown().await;
}

/// Phase 7 corpus: a `did:` **reader** reads a gated blob end-to-end over the
/// atproto surface (a getBlob service-auth JWT), and a grant on one owner's
/// namespace never admits the grantee to a *different* owner's gated namespace.
#[tokio::test]
async fn did_reader_reads_gated_blob_and_grants_do_not_cross_namespaces() {
    let world = World::spawn_atproto(&["owner_a", "owner_b", "reader", "stranger"]).await;
    let owner_a = world.atproto_actor("owner_a");
    let owner_b = world.atproto_actor("owner_b");
    let reader = world.atproto_actor("reader");
    let stranger = world.atproto_actor("stranger");
    let did_a = owner_a.did().to_owned();
    let did_b = owner_b.did().to_owned();

    // Each owner uploads a blob and gates its namespace to `reader` only on A.
    let blob_a = b"owner A's gated blob".to_vec();
    let blob_b = b"owner B's gated blob".to_vec();
    owner_a.upload_blob(&blob_a).await.ok();
    owner_b.upload_blob(&blob_b).await.ok();
    let cidv1_a = ciss::cidv1::blob_cid_string(&blob_a);
    let cidv1_b = ciss::cidv1::blob_cid_string(&blob_b);

    let grant_reader = serde_json::json!({
        "read_class": "grantees",
        "readers": [reader.did()],
        "seq": 1,
    })
    .to_string();
    // A gates to reader; B gates to nobody (owner-only).
    owner_a
        .put_policy_with_token(&did_a, &owner_a.valid_set_policy_token("jti-a"), &grant_reader)
        .await
        .ok();
    let owner_only = serde_json::json!({ "read_class": "owner", "readers": [], "seq": 1 }).to_string();
    owner_b
        .put_policy_with_token(&did_b, &owner_b.valid_set_policy_token("jti-b"), &owner_only)
        .await
        .ok();

    // The did: reader reads A's blob via a getBlob JWT (end-to-end Phase 6 auth).
    reader
        .get_blob_with_token(&did_a, &cidv1_a, &reader.valid_getblob_token("jti-read-a"))
        .await
        .returns(&blob_a);

    // A stranger did: with a valid getBlob JWT is still denied (404, not the bytes).
    stranger
        .get_blob_with_token(&did_a, &cidv1_a, &stranger.valid_getblob_token("jti-stranger"))
        .await
        .refused(404);

    // Cross-namespace: reader is granted on A, but B's gate does not admit it.
    reader
        .get_blob_with_token(&did_b, &cidv1_b, &reader.valid_getblob_token("jti-read-b"))
        .await
        .refused(404);

    // Even owner_a cannot read owner_b's owner-only blob (grants are per-namespace).
    owner_a
        .get_blob_with_token(&did_b, &cidv1_b, &owner_a.valid_getblob_token("jti-a-reads-b"))
        .await
        .refused(404);

    world.shutdown().await;
}

/// A `did:` owner reads its own policy back over HTTP via a getPolicy service-auth
/// JWT — and sees the full record (including `readers[]`), exactly like an `id:`
/// owner. A `did:` **grantee** sees only its own access; a stranger 404s (Q4
/// owner-only visibility, over the `did:` auth path).
#[tokio::test]
async fn did_owner_reads_back_own_policy() {
    let world = World::spawn_atproto(&["owner", "grantee", "stranger"]).await;
    let owner = world.atproto_actor("owner");
    let grantee = world.atproto_actor("grantee");
    let stranger = world.atproto_actor("stranger");
    let owner_did = owner.did().to_owned();

    // The did: owner gates its namespace to the grantee (Model C).
    let intent = serde_json::json!({
        "read_class": "grantees",
        "readers": [grantee.did()],
        "seq": 1,
    })
    .to_string();
    owner
        .put_policy_with_token(&owner_did, &owner.valid_set_policy_token("jti-set"), &intent)
        .await
        .ok();

    // The did: owner reads its policy back and sees the full record.
    let owner_view = owner
        .get_policy_with_token(&owner_did, &owner.valid_get_policy_token("jti-owner-read"))
        .await;
    owner_view.ok();
    let owner_json = owner_view.json();
    assert!(
        owner_json.get("readers").is_some(),
        "the did: owner sees the full reader set",
    );

    // A did: grantee sees only its own access, never the reader set.
    let grantee_view = grantee
        .get_policy_with_token(&owner_did, &grantee.valid_get_policy_token("jti-grantee-read"))
        .await;
    grantee_view.ok();
    let grantee_json = grantee_view.json();
    assert!(
        grantee_json.get("readers").is_none(),
        "a grantee never sees the reader set",
    );
    assert_eq!(grantee_json["may_read"], true, "a grantee learns only its own access");

    // A did: stranger cannot read the policy back (oracle-free 404).
    stranger
        .get_policy_with_token(&owner_did, &stranger.valid_get_policy_token("jti-stranger-read"))
        .await
        .refused(404);

    world.shutdown().await;
}
