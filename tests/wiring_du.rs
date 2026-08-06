//! Wiring test for usage inspection (`du`, ADR 0003 / invariant Z9): self usage is
//! allowed, cross-DID is forbidden unless `CISS_ADMIN_USAGE` is on AND the caller
//! is an admin-pin DID. Sizes come from the ledger; the endpoint reports
//! `{objects:[{cid,bytes}], total_bytes}`.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::TestServer;

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::identity::derive_id;
use ciss::server::{App, Blobs, Db};
use ciss_auth::{did_key_secp256k1, mint_service_auth_jwt};
use ciss_resolve::{DidResolver, StaticResolver};
use k256::ecdsa::SigningKey;

const SERVICE_DID: &str = "did:web:ciss.test";
const DU_LXM: &str = "ing.croft.ciss.du";
const FAR_FUTURE: u64 = 4_000_000_000;

async fn json(resp: reqwest::Response) -> serde_json::Value {
    let text = resp.text().await.expect("body");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("json {text:?}: {e}"))
}

/// Upload `bytes` under `did`'s session (S3 plane) and return the cid.
async fn put(client: &reqwest::Client, server: &TestServer, kp: &ciss::crypto::Keypair, did: &str, key: &str, bytes: &[u8]) -> String {
    let (pubkey, session) = common::session_headers(kp, did);
    let r = client
        .put(server.url(&format!("/{did}/objects/{key}")))
        .header("x-croft-pubkey", pubkey)
        .header("x-croft-session", session)
        .body(bytes.to_vec())
        .send()
        .await
        .expect("put");
    assert_eq!(r.status().as_u16(), 200, "put ok");
    sha256_hex(bytes)
}

/// Self `du` reports each object's size + the total; a stranger's cross-DID `du`
/// is forbidden with the flag off (the default).
#[tokio::test]
async fn self_du_reports_sizes_and_a_stranger_is_forbidden() {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();

    let owner = derive_keypair("du-owner", "owner");
    let owner_did = derive_id(&owner.verifying_key());
    let a = put(&client, &server, &owner, &owner_did, "a", b"hello").await; // 5
    let b = put(&client, &server, &owner, &owner_did, "b", b"world!!").await; // 7

    // Self du: both objects with correct sizes + total.
    let (pk, sess) = common::session_headers(&owner, &owner_did);
    let body = json(
        client
            .get(server.url(&format!("/{owner_did}/du")))
            .header("x-croft-pubkey", pk)
            .header("x-croft-session", sess)
            .send()
            .await
            .expect("self du"),
    )
    .await;
    assert_eq!(body["total_bytes"], 12, "total is 5 + 7");
    let objs = body["objects"].as_array().expect("objects");
    let size_of = |cid: &str| {
        objs.iter()
            .find(|o| o["cid"] == cid)
            .and_then(|o| o["bytes"].as_u64())
            .unwrap_or_else(|| panic!("cid {cid} not in du"))
    };
    assert_eq!(size_of(&a), 5);
    assert_eq!(size_of(&b), 7);

    // A stranger (different id:) querying the owner's du → 403 (flag off).
    let stranger = derive_keypair("du-stranger", "stranger");
    let stranger_did = derive_id(&stranger.verifying_key());
    let (spk, ssess) = common::session_headers(&stranger, &stranger_did);
    let r = client
        .get(server.url(&format!("/{owner_did}/du")))
        .header("x-croft-pubkey", spk)
        .header("x-croft-session", ssess)
        .send()
        .await
        .expect("stranger du");
    assert_eq!(r.status().as_u16(), 403, "cross-DID du forbidden with the flag off");
}

fn mint_du(sk: &SigningKey, did: &str) -> String {
    mint_service_auth_jwt(sk, did, SERVICE_DID, DU_LXM, FAR_FUTURE, Some("jti-du"))
}

/// Cross-DID admin `du` requires BOTH the flag on and admin-set membership.
#[tokio::test]
async fn admin_cross_did_du_requires_flag_and_membership() {
    let admin_sk = SigningKey::from_slice(&[0x51u8; 32]).expect("scalar");
    let admin_did = "did:web:admin.test";
    let outsider_sk = SigningKey::from_slice(&[0x52u8; 32]).expect("scalar");
    let outsider_did = "did:web:outsider.test";

    let build = |enabled: bool| {
        let resolver: Arc<dyn DidResolver> = Arc::new(
            StaticResolver::default()
                .with(admin_did, did_key_secp256k1(admin_sk.verifying_key()))
                .with(outsider_did, did_key_secp256k1(outsider_sk.verifying_key())),
        );
        App::new("provider-master", Blobs::Memory, Db::Memory)
            .expect("app")
            .with_did_resolver(resolver, SERVICE_DID)
            .with_admin_usage(HashSet::from([admin_did.to_owned()]), enabled)
    };

    // Owner uploads one object (id: session) into a fresh world.
    let owner = derive_keypair("du-owner2", "owner");
    let owner_did = derive_id(&owner.verifying_key());

    // --- flag ON: admin may read cross-DID; a non-admin did: may not. ---
    let server = TestServer::spawn(build(true)).await;
    let client = reqwest::Client::new();
    put(&client, &server, &owner, &owner_did, "x", b"twelve bytes").await; // 12

    let admin_ok = client
        .get(server.url(&format!("/{owner_did}/du")))
        .bearer_auth(mint_du(&admin_sk, admin_did))
        .send()
        .await
        .expect("admin du");
    assert_eq!(admin_ok.status().as_u16(), 200, "admin cross-DID du allowed with flag on");
    assert_eq!(json(admin_ok).await["total_bytes"], 12);

    let outsider = client
        .get(server.url(&format!("/{owner_did}/du")))
        .bearer_auth(mint_du(&outsider_sk, outsider_did))
        .send()
        .await
        .expect("outsider du");
    assert_eq!(outsider.status().as_u16(), 403, "a non-admin did: is forbidden even with the flag on");

    // --- flag OFF: even the admin is forbidden cross-DID. ---
    let server_off = TestServer::spawn(build(false)).await;
    put(&client, &server_off, &owner, &owner_did, "x", b"twelve bytes").await;
    let admin_off = client
        .get(server_off.url(&format!("/{owner_did}/du")))
        .bearer_auth(mint_du(&admin_sk, admin_did))
        .send()
        .await
        .expect("admin du flag off");
    assert_eq!(admin_off.status().as_u16(), 403, "cross-DID du forbidden when the flag is off");
}
