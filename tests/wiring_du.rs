//! Wiring test for usage inspection (`du`, ADR 0003 / invariant Z9). `du` is
//! **self-only**: a caller reports on its own namespace; cross-DID is never served
//! (not even to admins). `CISS_ADMIN_ONLY_DU` is a lockdown: when set, only an
//! admin-pin DID may run `du` at all — still only for its own namespace.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::TestServer;

use ciss::crypto::{derive_keypair, sha256_hex, Keypair};
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

/// Upload under an `id:` session; returns the cid.
async fn put_id(client: &reqwest::Client, server: &TestServer, kp: &Keypair, did: &str, key: &str, bytes: &[u8]) -> String {
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

fn du_token(sk: &SigningKey, did: &str) -> String {
    mint_service_auth_jwt(sk, did, SERVICE_DID, DU_LXM, FAR_FUTURE, Some("jti-du"))
}

/// Status of a `du` under an `id:` session for `caller` querying `target`.
async fn du_id_status(client: &reqwest::Client, server: &TestServer, kp: &Keypair, caller_did: &str, target: &str) -> u16 {
    let (pk, sess) = common::session_headers(kp, caller_did);
    client
        .get(server.url(&format!("/{target}/du")))
        .header("x-croft-pubkey", pk)
        .header("x-croft-session", sess)
        .send()
        .await
        .expect("du")
        .status()
        .as_u16()
}

/// Default (flag off): any authenticated caller may `du` its **own** namespace;
/// a cross-DID query (or an anonymous one) is refused 403.
#[tokio::test]
async fn du_is_self_only_by_default() {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();

    let owner = derive_keypair("du-owner", "owner");
    let owner_did = derive_id(&owner.verifying_key());
    put_id(&client, &server, &owner, &owner_did, "a", b"hello").await; // 5
    put_id(&client, &server, &owner, &owner_did, "b", b"world!!").await; // 7

    // Self du → sizes + total.
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
    assert_eq!(body["total_bytes"], 12);
    assert_eq!(body["objects"].as_array().expect("objects").len(), 2);

    // A stranger querying the owner's du → 403 (cross-DID never served).
    let stranger = derive_keypair("du-stranger", "stranger");
    let stranger_did = derive_id(&stranger.verifying_key());
    assert_eq!(
        du_id_status(&client, &server, &stranger, &stranger_did, &owner_did).await,
        403,
        "cross-DID du is 403",
    );

    // Anonymous du → 403.
    let anon = client.get(server.url(&format!("/{owner_did}/du"))).send().await.expect("anon du");
    assert_eq!(anon.status().as_u16(), 403, "anonymous du is 403");
}

/// `CISS_ADMIN_ONLY_DU` lockdown: only admin-pin DIDs may run `du` — still only for
/// their own namespace (cross-DID stays 403 even for an admin).
#[tokio::test]
async fn admin_only_lockdown_restricts_du_to_admins_still_self_only() {
    let admin_sk = SigningKey::from_slice(&[0x51u8; 32]).expect("scalar");
    let admin_did = "did:web:admin.test";

    let build = |locked: bool| {
        let resolver: Arc<dyn DidResolver> =
            Arc::new(StaticResolver::default().with(admin_did, did_key_secp256k1(admin_sk.verifying_key())));
        App::new("provider-master", Blobs::Memory, Db::Memory)
            .expect("app")
            .with_did_resolver(resolver, SERVICE_DID)
            .with_admin_only_du(HashSet::from([admin_did.to_owned()]), locked)
    };

    let owner = derive_keypair("du-owner2", "owner");
    let owner_did = derive_id(&owner.verifying_key());

    // --- lockdown ON ---
    let server = TestServer::spawn(build(true)).await;
    let client = reqwest::Client::new();
    put_id(&client, &server, &owner, &owner_did, "x", b"twelve bytes").await;

    // Non-admin owner, self du → 403 (locked to admins).
    assert_eq!(
        du_id_status(&client, &server, &owner, &owner_did, &owner_did).await,
        403,
        "with the lockdown on, a non-admin cannot du even its own namespace",
    );

    // Admin, self du → 200 (admin, own namespace — empty is fine).
    let admin_self = client
        .get(server.url(&format!("/{admin_did}/du")))
        .bearer_auth(du_token(&admin_sk, admin_did))
        .send()
        .await
        .expect("admin self du");
    assert_eq!(admin_self.status().as_u16(), 200, "an admin may du its own namespace under the lockdown");

    // Admin, cross-DID (the owner's namespace) → 403 (self-only always).
    let admin_cross = client
        .get(server.url(&format!("/{owner_did}/du")))
        .bearer_auth(du_token(&admin_sk, admin_did))
        .send()
        .await
        .expect("admin cross du");
    assert_eq!(admin_cross.status().as_u16(), 403, "even an admin cannot du another DID");

    // --- lockdown OFF: the same non-admin owner may du its own namespace. ---
    let server_off = TestServer::spawn(build(false)).await;
    put_id(&client, &server_off, &owner, &owner_did, "x", b"twelve bytes").await;
    assert_eq!(
        du_id_status(&client, &server_off, &owner, &owner_did, &owner_did).await,
        200,
        "with the lockdown off, any authenticated caller may du its own namespace",
    );
}
