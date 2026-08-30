//! Wiring test for `GET /{did}/meter` under a `did:` service-auth JWT (TODO §4).
//! The meter is owner-only (billing is private); historically the endpoint
//! authenticated only the interim `id:` session plane, so a `did:` account could
//! not read its own meter remotely. It accepts both planes now, like `du`.

mod common;

use std::sync::Arc;

use common::TestServer;

use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::server::{App, Blobs, Db};
use ciss_auth::{did_key_secp256k1, mint_service_auth_jwt};
use ciss_resolve::{DidResolver, StaticResolver};
use k256::ecdsa::SigningKey;

const SERVICE_DID: &str = "did:web:ciss.test";
const METER_LXM: &str = "ing.croft.ciss.meter";
const DU_LXM: &str = "ing.croft.ciss.du";
const FAR_FUTURE: u64 = 4_000_000_000;

fn spawn_with(dids: &[(&str, &SigningKey)]) -> App {
    let mut resolver = StaticResolver::default();
    for (did, sk) in dids {
        resolver = resolver.with(*did, did_key_secp256k1(sk.verifying_key()));
    }
    let resolver: Arc<dyn DidResolver> = Arc::new(resolver);
    App::new("provider-master", Blobs::Memory, Db::Memory)
        .expect("app")
        .with_did_resolver(resolver, SERVICE_DID)
}

/// A `did:` account reads its OWN meter with a meter-scoped service-auth JWT.
#[tokio::test]
async fn a_did_account_reads_its_own_meter_with_a_service_auth_jwt() {
    let sk = SigningKey::from_slice(&[0x61u8; 32]).expect("scalar");
    let did = "did:web:meterer.test";
    let server = TestServer::spawn(spawn_with(&[(did, &sk)])).await;
    let client = reqwest::Client::new();

    let token = mint_service_auth_jwt(&sk, did, SERVICE_DID, METER_LXM, FAR_FUTURE, Some("jti-meter"));
    let resp = client
        .get(server.url(&format!("/{did}/meter")))
        .bearer_auth(token)
        .send()
        .await
        .expect("meter");
    assert_eq!(resp.status().as_u16(), 200, "a did: owner may read its own meter");
    let body: serde_json::Value =
        serde_json::from_str(&resp.text().await.expect("body")).expect("meter json");
    assert_eq!(body["receipt_count"], 0, "fresh account, empty meter");
    assert_eq!(body["running_total_bytes"], 0);
}

/// A JWT bound to a different method (`du`) does not open the meter: the token's
/// `lxm` is part of the grant, not a formality.
#[tokio::test]
async fn a_du_scoped_jwt_does_not_read_the_meter() {
    let sk = SigningKey::from_slice(&[0x62u8; 32]).expect("scalar");
    let did = "did:web:meterer2.test";
    let server = TestServer::spawn(spawn_with(&[(did, &sk)])).await;
    let client = reqwest::Client::new();

    let wrong = mint_service_auth_jwt(&sk, did, SERVICE_DID, DU_LXM, FAR_FUTURE, Some("jti-wrong"));
    let resp = client
        .get(server.url(&format!("/{did}/meter")))
        .bearer_auth(wrong)
        .send()
        .await
        .expect("meter");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "an lxm-mismatched token is an unauthenticated caller (401: authenticate and retry)",
    );
}

/// Cross-DID stays refused: the meter is the owner's, full stop.
#[tokio::test]
async fn a_did_account_cannot_read_another_accounts_meter() {
    let reader_sk = SigningKey::from_slice(&[0x63u8; 32]).expect("scalar");
    let reader = "did:web:reader.test";
    let victim = "did:web:victim.test";
    let server = TestServer::spawn(spawn_with(&[(reader, &reader_sk)])).await;
    let client = reqwest::Client::new();

    let token =
        mint_service_auth_jwt(&reader_sk, reader, SERVICE_DID, METER_LXM, FAR_FUTURE, Some("jti-x"));
    let resp = client
        .get(server.url(&format!("/{victim}/meter")))
        .bearer_auth(token)
        .send()
        .await
        .expect("meter");
    assert_eq!(resp.status().as_u16(), 403, "cross-DID meter reads are never served");
}

/// Regression: the `id:` session plane keeps working on the same endpoint.
#[tokio::test]
async fn an_id_session_still_reads_its_own_meter() {
    let server = TestServer::spawn(
        App::new("provider-master", Blobs::Memory, Db::Memory).expect("app"),
    )
    .await;
    let client = reqwest::Client::new();

    let owner = derive_keypair("meter-owner", "owner");
    let owner_did = derive_id(&owner.verifying_key());
    let (pk, sess) = common::session_headers(&owner, &owner_did);
    let resp = client
        .get(server.url(&format!("/{owner_did}/meter")))
        .header("x-croft-pubkey", pk)
        .header("x-croft-session", sess)
        .send()
        .await
        .expect("meter");
    assert_eq!(resp.status().as_u16(), 200, "the id: plane is unchanged");
}
