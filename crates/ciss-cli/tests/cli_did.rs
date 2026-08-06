//! Phase 7 wiring test (offline, authoritative for the code path): the `did:`
//! caller drives the atproto plane with a **service-auth JWT bearer**. A token
//! minted by the Phase-6 helper stands in for the PDS's `getServiceAuth`; its
//! signer is registered with a `StaticResolver`, so CISS verifies it with no
//! network. The live `getServiceAuth` round-trip against bsky is Phase 9's demo.

use std::sync::Arc;

use ciss::crypto::sha256_hex;
use ciss::server::{App, Blobs, Db};
use ciss_auth::{did_key_secp256k1, mint_service_auth_jwt};
use ciss_cli::client::Client;
use ciss_resolve::{DidResolver, StaticResolver};
use k256::ecdsa::SigningKey;

/// This test service's DID — the `aud` a valid token must name.
const SERVICE_DID: &str = "did:web:ciss.test";
/// The `did:` caller (an atproto account stand-in).
const CALLER_DID: &str = "did:web:tester.test";
/// The lexicon method uploadBlob binds `lxm` to (mirrors the server).
const UPLOAD_LXM: &str = "com.atproto.repo.uploadBlob";
/// A far-future expiry so the token is valid against the real clock the server uses.
const FAR_FUTURE: u64 = 4_000_000_000;

fn caller_key() -> SigningKey {
    SigningKey::from_slice(&[0x22u8; 32]).expect("valid scalar")
}

/// Spawn an in-process App whose resolver maps `CALLER_DID` to the caller key's
/// `did:key`, with `SERVICE_DID` as the expected `aud`.
async fn spawn_server() -> String {
    let resolver: Arc<dyn DidResolver> = Arc::new(
        StaticResolver::default().with(CALLER_DID, did_key_secp256k1(caller_key().verifying_key())),
    );
    let app = App::new("provider-master", Blobs::Memory, Db::Memory)
        .expect("build app")
        .with_did_resolver(resolver, SERVICE_DID);
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

fn mint(sk: &SigningKey, aud: &str, lxm: &str, exp: u64) -> String {
    mint_service_auth_jwt(sk, CALLER_DID, aud, lxm, exp, Some("jti-test"))
}

/// A valid service-auth JWT uploads a blob into the caller's repo, and the blob
/// reads back byte-identically over the public getBlob (bridged cid).
#[tokio::test]
async fn did_bearer_upload_stores_and_reads_back() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let sk = caller_key();

    let payload = b"a blob authorized by a did: service-auth token".to_vec();
    let cid = sha256_hex(&payload);
    let token = mint(&sk, SERVICE_DID, UPLOAD_LXM, FAR_FUTURE);

    let up = client.upload_blob_bearer(&token, &payload).await.expect("bearer upload");
    assert_eq!(up.cid, cid, "uploadBlob content-addresses to the same sha256 hex");

    let got = client.get_blob(CALLER_DID, &cid).await.expect("public read back");
    assert_eq!(got.bytes, payload, "blob reads back byte-identically");
}

/// Each way a service-auth token can be wrong — expired, wrong `aud`, wrong `lxm`
/// — is refused 401 at the atproto boundary (the token authorizes nothing, so the
/// caller is Anonymous to an owner-gated write).
#[tokio::test]
async fn did_bearer_bad_tokens_are_refused_401() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let sk = caller_key();
    let body = b"x".to_vec();

    let cases = [
        ("expired", mint(&sk, SERVICE_DID, UPLOAD_LXM, 1)),
        ("wrong aud", mint(&sk, "did:web:evil.test", UPLOAD_LXM, FAR_FUTURE)),
        ("wrong lxm", mint(&sk, SERVICE_DID, "com.atproto.sync.getBlob", FAR_FUTURE)),
    ];
    for (name, token) in cases {
        let err = client
            .upload_blob_bearer(&token, &body)
            .await
            .unwrap_err_or_else_msg(name);
        assert!(err.contains("401"), "{name}: expected 401, got {err:?}");
    }
}

/// Small helper: assert the call failed and return the error string.
trait ExpectErrMsg {
    fn unwrap_err_or_else_msg(self, label: &str) -> String;
}
impl<T> ExpectErrMsg for Result<T, anyhow::Error> {
    fn unwrap_err_or_else_msg(self, label: &str) -> String {
        match self {
            Ok(_) => panic!("{label}: expected an error, got Ok"),
            Err(e) => e.to_string(),
        }
    }
}
