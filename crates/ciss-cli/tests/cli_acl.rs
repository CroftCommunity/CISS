//! Phase 8a wiring test: Model-A gated reads. An `id:` owner self-signs a policy
//! over one object; the gate must be **oracle-free** (a non-grantee read is 404,
//! never 403), **non-enumerable** (`ls` omits hidden cids), **leak-free** (a
//! grantee's policy view carries no reader set), and **anti-rollback** (a stale
//! `seq` is 409).

use std::sync::Arc;

use ciss::crypto::{derive_keypair, sha256_hex, Keypair};
use ciss::identity::derive_id;
use ciss::policy::{PolicyRecord, ReadClass};
use ciss::server::{App, Blobs, Db};
use ciss_auth::{did_key_secp256k1, mint_service_auth_jwt};
use ciss_cli::client::{session_for, Client, Session};
use ciss_resolve::{DidResolver, StaticResolver};
use k256::ecdsa::SigningKey;

async fn spawn_server() -> String {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

struct Actor {
    keypair: Keypair,
    did: String,
    session: Session,
}

fn actor(name: &str) -> Actor {
    let keypair = derive_keypair("acl-master", name);
    let did = derive_id(&keypair.verifying_key());
    let session = session_for(&keypair);
    Actor { keypair, did, session }
}

/// Owner gates an object to a single grantee; the three-party read matrix holds,
/// `ls` omits the cid for non-grantees, and the policy views don't leak the
/// reader set.
#[tokio::test]
async fn model_a_three_party_gate_is_oracle_free_and_leak_free() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let owner = actor("owner");
    let grantee = actor("grantee");
    let stranger = actor("stranger");

    // Owner uploads an object into its own namespace.
    let payload = b"a private memo".to_vec();
    let cid = sha256_hex(&payload);
    client.put_s3(&owner.session, "memo.txt", &payload).await.expect("owner upload");

    // Owner sets a grantees policy naming the grantee (seq 1).
    let record = PolicyRecord::sign_owner(
        &owner.did,
        Some(&cid),
        ReadClass::Grantees,
        std::slice::from_ref(&grantee.did),
        1,
        &owner.keypair,
    );
    let seq = client
        .put_object_policy(&owner.did, &cid, &serde_json::to_vec(&record).unwrap())
        .await
        .expect("set policy");
    assert_eq!(seq, 1, "first policy is seq 1");

    // Read matrix: owner and grantee get the bytes; stranger and anonymous get a
    // 404 (never 403 — the oracle-free rule).
    assert_eq!(
        client.get_s3(Some(&owner.session), &owner.did, &cid).await.expect("owner read").bytes,
        payload,
        "the owner reads its own gated object",
    );
    assert_eq!(
        client.get_s3(Some(&grantee.session), &owner.did, &cid).await.expect("grantee read").bytes,
        payload,
        "a grantee reads the gated object",
    );
    let stranger_err = client
        .get_s3(Some(&stranger.session), &owner.did, &cid)
        .await
        .expect_err("stranger is denied");
    assert!(stranger_err.to_string().contains("404"), "stranger read is 404, not 403");
    let anon_err = client
        .get_s3(None, &owner.did, &cid)
        .await
        .expect_err("anonymous is denied");
    assert!(anon_err.to_string().contains("404"), "anonymous read is 404, not 403");

    // ls: owner and grantee see the cid; stranger and anonymous omit it.
    assert!(
        client.list_blobs(Some(&owner.session), &owner.did).await.unwrap().contains(&cid),
        "owner lists the cid",
    );
    assert!(
        client.list_blobs(Some(&grantee.session), &owner.did).await.unwrap().contains(&cid),
        "grantee lists the cid",
    );
    assert!(
        !client.list_blobs(Some(&stranger.session), &owner.did).await.unwrap().contains(&cid),
        "stranger's ls omits the gated cid (not an enumeration oracle)",
    );
    assert!(
        !client.list_blobs(None, &owner.did).await.unwrap().contains(&cid),
        "anonymous ls omits the gated cid",
    );

    // Policy views: owner sees the full record incl. readers[]; grantee sees only
    // {read_class, may_read} — no reader set; stranger sees nothing (404 -> None).
    let owner_view = client
        .get_object_policy(Some(&owner.session), &owner.did, &cid)
        .await
        .unwrap()
        .expect("owner sees a policy");
    assert!(
        owner_view.to_string().contains(&grantee.did),
        "owner's policy view includes the reader set",
    );
    let grantee_view = client
        .get_object_policy(Some(&grantee.session), &owner.did, &cid)
        .await
        .unwrap()
        .expect("grantee sees its access");
    assert_eq!(grantee_view["may_read"], serde_json::json!(true), "grantee may_read");
    assert!(
        !grantee_view.to_string().contains(&stranger.did)
            && grantee_view.get("readers").is_none(),
        "grantee's view must not leak the reader set, got {grantee_view}",
    );
    assert!(
        client
            .get_object_policy(Some(&stranger.session), &owner.did, &cid)
            .await
            .unwrap()
            .is_none(),
        "stranger's policy read is an oracle-free 404 (None)",
    );
}

// ---------------------------------------------------------------------------
// Model C: a did: owner sets a provider-attested policy via a service-auth JWT.
// ---------------------------------------------------------------------------

const SERVICE_DID: &str = "did:web:ciss.test";
const UPLOAD_LXM: &str = "com.atproto.repo.uploadBlob";
const SET_POLICY_LXM: &str = "ing.croft.ciss.setPolicy";
const GETBLOB_LXM: &str = "com.atproto.sync.getBlob";
const FAR_FUTURE: u64 = 4_000_000_000;

/// A `did:` persona: a secp256k1 key and its `did:web:<name>.test` DID.
struct Persona {
    did: String,
    sk: SigningKey,
}

fn persona(name: &str, seed_byte: u8) -> Persona {
    let mut seed = [seed_byte; 32];
    seed[0] ^= name.len() as u8;
    Persona {
        did: format!("did:web:{name}.test"),
        sk: SigningKey::from_slice(&seed).expect("valid scalar"),
    }
}

impl Persona {
    /// A single-use `jti` unique per (persona, method), so distinct tokens never
    /// collide in the server's replay guard.
    fn jti(&self, lxm: &str) -> String {
        format!("jti-{}-{lxm}", self.did)
    }
    /// Mint a valid service-auth token for `lxm` (aud = the test service DID).
    fn token(&self, lxm: &str) -> String {
        let jti = self.jti(lxm);
        mint_service_auth_jwt(&self.sk, &self.did, SERVICE_DID, lxm, FAR_FUTURE, Some(&jti))
    }
    /// An expired token — a present-but-invalid credential.
    fn expired_token(&self, lxm: &str) -> String {
        let jti = format!("{}-expired", self.jti(lxm));
        mint_service_auth_jwt(&self.sk, &self.did, SERVICE_DID, lxm, 1, Some(&jti))
    }
}

async fn spawn_atproto(personas: &[&Persona]) -> String {
    let mut resolver = StaticResolver::default();
    for p in personas {
        resolver = resolver.with(p.did.clone(), did_key_secp256k1(p.sk.verifying_key()));
    }
    let resolver: Arc<dyn DidResolver> = Arc::new(resolver);
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

/// A `did:` owner uploads a blob, sets a Model-C `grantees` policy (a PolicyIntent
/// + a `setPolicy` service-auth JWT the provider attests), and the gate holds: a
/// granted `did:` reader reads it, an ungranted one gets 404, and a bad JWT on the
/// set is a hard 403 (distinct from a read's oracle-free 404).
#[tokio::test]
async fn model_c_did_owner_gate_and_bad_jwt_is_403() {
    let owner = persona("owner", 0x31);
    let grantee = persona("grantee", 0x32);
    let stranger = persona("stranger", 0x33);
    let base = spawn_atproto(&[&owner, &grantee, &stranger]).await;
    let client = Client::new(&base);

    // Owner uploads a blob into its repo (Phase 7 bearer upload).
    let payload = b"a model-C gated blob".to_vec();
    let cid = sha256_hex(&payload);
    client
        .upload_blob_bearer(&owner.token(UPLOAD_LXM), &payload)
        .await
        .expect("owner upload");

    // Owner sets a grantees policy naming the grantee, via intent + setPolicy JWT.
    let intent = serde_json::json!({
        "read_class": "grantees",
        "readers": [grantee.did],
        "seq": 1,
    })
    .to_string();
    let seq = client
        .put_object_policy_intent(&owner.did, &cid, intent.as_bytes(), &owner.token(SET_POLICY_LXM))
        .await
        .expect("Model-C set policy");
    assert_eq!(seq, 1, "provider-attested policy stored at seq 1");

    // A granted did: reader reads the blob via a getBlob bearer.
    let got = client
        .get_blob_bearer(&owner.did, &cid, &grantee.token(GETBLOB_LXM))
        .await
        .expect("grantee reads the gated blob");
    assert_eq!(got.bytes, payload);

    // An ungranted did: reader is denied 404 (oracle-free).
    let err = client
        .get_blob_bearer(&owner.did, &cid, &stranger.token(GETBLOB_LXM))
        .await
        .expect_err("ungranted reader denied");
    assert!(err.to_string().contains("404"), "ungranted read is 404, got {err}");

    // A present-but-invalid JWT on the set is a hard 403 — the spec's Model-C
    // fail, distinct from a read's 404.
    let err = client
        .put_object_policy_intent(
            &owner.did,
            &cid,
            intent.as_bytes(),
            &owner.expired_token(SET_POLICY_LXM),
        )
        .await
        .expect_err("bad set token");
    assert!(err.to_string().contains("403"), "bad Model-C credential is 403, got {err}");
}

/// A stale/equal `seq` is refused 409 — the anti-rollback wall. The CLI's
/// auto-`seq` avoids this in the happy path; here we force it to prove the guard.
#[tokio::test]
async fn a_stale_policy_seq_is_refused_409() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let owner = actor("owner");
    let grantee = actor("grantee");

    let payload = b"rollover".to_vec();
    let cid = sha256_hex(&payload);
    client.put_s3(&owner.session, "x.txt", &payload).await.expect("upload");

    let readers = std::slice::from_ref(&grantee.did);
    let make = |seq| {
        serde_json::to_vec(&PolicyRecord::sign_owner(
            &owner.did,
            Some(&cid),
            ReadClass::Grantees,
            readers,
            seq,
            &owner.keypair,
        ))
        .unwrap()
    };

    assert_eq!(client.put_object_policy(&owner.did, &cid, &make(2)).await.unwrap(), 2);
    // Re-submitting seq 2 (equal) or a lower seq must be refused 409.
    let err = client
        .put_object_policy(&owner.did, &cid, &make(2))
        .await
        .expect_err("a non-newer seq must be refused");
    assert!(err.to_string().contains("409"), "stale seq is 409, got {err}");
}
