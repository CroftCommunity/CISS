//! Shared test harness for the Phase-7+ HTTP boundary tests.
//!
//! Two layers live here:
//!
//! - [`TestServer`] — spins the real axum server on an ephemeral loopback port,
//!   drives it over real HTTP (reqwest), and shuts it down cleanly so a port-leak
//!   is observable. The `e*`/`wiring_*` suites use this directly.
//! - [`World`] + [`Actor`] — the **workflow** persona layer (see
//!   `docs/TESTING-STRATEGY.md`). A `World` owns a running server and named
//!   namespaces; an `Actor` holds an identity + credential and exposes high-level
//!   operations that return an assertable [`Outcome`], so a flow reads as a story.
//!   The `flow_*` suites use this.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ciss::server::{App, Blobs, Db};
use ciss_auth::ResolvedKeys;
use ciss_resolve::{PinnedResolver, StaticResolver};
use tokio::sync::oneshot;

/// This test service's atproto DID — the `aud` a valid service-auth JWT must name.
pub const SERVICE_DID: &str = "did:web:ciss.test";
/// The XRPC method the atproto upload path binds `lxm` to.
pub const UPLOAD_LXM: &str = "com.atproto.repo.uploadBlob";

/// A running test server bound to an ephemeral port, driven over real HTTP.
pub struct TestServer {
    /// The bound loopback address (ephemeral port).
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Bind `127.0.0.1:0`, serve `app`'s router with graceful shutdown, return
    /// a handle. `app` is dropped after the router is built — the router holds
    /// its own `Arc` clones of the shared state, so the server stays live.
    pub async fn spawn(app: App) -> Self {
        let router = app.router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });
        Self {
            addr,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// A full URL for `path` against this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Signal graceful shutdown and wait for the server task to finish, so a
    /// caller can then assert the port was released.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Workflow persona layer: World + Actor + Outcome.
// ---------------------------------------------------------------------------

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_data_dir() -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("ciss-flow-{}-{seq}", std::process::id()))
}

/// Percent-encode a query-string *value* (path segments interpolate `id:`/`did:`
/// directly, matching the server's routes, so only query values need this).
fn enc(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// A running server plus the personas acting against it — the workflow fixture.
///
/// `spawn` uses the in-memory backends (the default for a flow); `spawn_fs` uses
/// the filesystem backend and exposes [`World::data_dir`], for flows that must
/// stage bytes on disk (the availability / path-safety guards).
pub struct World {
    server: Option<TestServer>,
    base: String,
    client: reqwest::Client,
    data_dir: Option<PathBuf>,
}

impl World {
    /// A world on the in-memory blob + SQLite backends.
    pub async fn spawn() -> Self {
        let app = App::new("test-provider", Blobs::Memory, Db::Memory).expect("build app");
        Self::from_app(app, None).await
    }

    /// A world with explicit storage-quota limits (for V5 quota flows): an
    /// in-memory backend with the given store ceiling and optional per-DID cap.
    pub async fn spawn_with_limits(store_ceiling: u64, did_cap: Option<u64>) -> Self {
        let limits = ciss::server::Limits {
            store_ceiling,
            did_cap,
        };
        let app = App::with_limits("test-provider", Blobs::Memory, Db::Memory, limits)
            .expect("build app");
        Self::from_app(app, None).await
    }

    /// A world on the filesystem blob backend (in-memory ledger), rooted at a
    /// fresh temp dir exposed via [`World::data_dir`].
    pub async fn spawn_fs() -> Self {
        let dir = unique_data_dir();
        std::fs::create_dir_all(&dir).expect("mkdir data dir");
        let app = App::new("test-provider", Blobs::Fs(dir.clone()), Db::Memory).expect("build app");
        Self::from_app(app, Some(dir)).await
    }

    async fn from_app(app: App, data_dir: Option<PathBuf>) -> Self {
        let server = TestServer::spawn(app).await;
        let base = format!("http://{}", server.addr);
        Self {
            server: Some(server),
            base,
            client: reqwest::Client::new(),
            data_dir,
        }
    }

    /// The filesystem root (only for `spawn_fs` worlds) — for staging bytes on
    /// disk under `blocks/{did}/{cid}`.
    pub fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    /// A raw URL against this world's server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A legitimate actor named `name`: it holds the keypair whose id it acts as,
    /// so it can sign a real session (x-croft-pubkey + x-croft-session) proving
    /// key possession for that DID (ADR 0001).
    pub fn actor(&self, name: &str) -> Actor {
        let keypair = ciss::crypto::derive_keypair("flow-master", name);
        let did = ciss::identity::derive_id(&keypair.verifying_key());
        Actor {
            client: self.client.clone(),
            base: self.base.clone(),
            did,
            keypair: Some(keypair),
        }
    }

    /// An anonymous caller — no key, so it can sign no session.
    pub fn anonymous(&self) -> Actor {
        Actor {
            client: self.client.clone(),
            base: self.base.clone(),
            did: String::new(),
            keypair: None,
        }
    }

    /// An impersonator: it *names* `victim_did` but holds no key for it, so it can
    /// sign no valid session. Models the forged-bearer attack (A2): the boundary
    /// must treat it as unauthenticated.
    pub fn impersonator(&self, victim_did: &str) -> Actor {
        Actor {
            client: self.client.clone(),
            base: self.base.clone(),
            did: victim_did.to_owned(),
            keypair: None,
        }
    }

    /// A world with a **healthy** fixture DID resolver wired for the named atproto
    /// personas. Each name gets a deterministic secp256k1 key; the resolver maps
    /// its `did:web:<name>.test` DID to the derived `did:key`, so the persona can
    /// mint service-auth JWTs the server verifies with no network (Model R).
    pub async fn spawn_atproto(names: &[&str]) -> Self {
        let mut resolver = StaticResolver::default();
        for name in names {
            let kp = atproto_keypair(name);
            resolver = resolver.with(kp.did.clone(), kp.did_key());
        }
        Self::from_atproto(Arc::new(resolver)).await
    }

    /// A world simulating a **resolver outage**: only the pinned admin personas
    /// resolve (locally, break-glass); every other DID fails closed. Models the
    /// poisoning/outage resistance of the pinned-admin set (ADR 0001 §5).
    pub async fn spawn_atproto_resolver_down(admin_names: &[&str]) -> Self {
        let mut pins = HashMap::new();
        for name in admin_names {
            let kp = atproto_keypair(name);
            pins.insert(kp.did.clone(), ResolvedKeys::new(kp.did_key()));
        }
        // Empty inner resolver => every non-pinned DID is NotFound (the outage).
        let resolver = PinnedResolver::new(StaticResolver::default(), pins);
        Self::from_atproto(Arc::new(resolver)).await
    }

    async fn from_atproto(resolver: Arc<dyn ciss_resolve::DidResolver>) -> Self {
        let app = App::new("test-provider", Blobs::Memory, Db::Memory)
            .expect("build app")
            .with_did_resolver(resolver, SERVICE_DID);
        Self::from_app(app, None).await
    }

    /// An atproto persona `name` — holds a secp256k1 key and mints service-auth
    /// JWTs as `did:web:<name>.test`.
    pub fn atproto_actor(&self, name: &str) -> AtprotoActor {
        AtprotoActor {
            client: self.client.clone(),
            base: self.base.clone(),
            key: atproto_keypair(name),
        }
    }

    /// Tear down the server and remove any filesystem root.
    pub async fn shutdown(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
        // The filesystem root is removed by `Drop`, which runs as `self` falls.
    }
}

impl Drop for World {
    /// Backstop cleanup: a flow that panics before `shutdown` (a RED spec) must
    /// not leak its temp data dir. Dropping the held `TestServer` signals its
    /// graceful shutdown, so the server task ends too.
    fn drop(&mut self) {
        if let Some(dir) = &self.data_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A DID derived from a persona name, matching the crate's own derivation so a
/// flow's DIDs are the real thing.
pub fn derive_did(name: &str) -> String {
    use ciss::crypto::derive_keypair;
    use ciss::identity::derive_id;
    derive_id(&derive_keypair("flow-master", name).verifying_key())
}

/// The `(x-croft-pubkey, x-croft-session)` header values for `keypair` acting as
/// `did` — for raw-reqwest wiring tests that authenticate without the [`Actor`]
/// DSL. The session is a signature over the domain-separated challenge the server
/// reconstructs.
pub fn session_headers(keypair: &ciss::crypto::Keypair, did: &str) -> (String, String) {
    let challenge = format!("ciss-session/v1/{did}");
    (keypair.public_key_hex(), keypair.sign_message(&challenge))
}

/// A persona acting against a [`World`] over real HTTP. Holds its identity and
/// (optionally) a session credential; every operation returns an [`Outcome`].
pub struct Actor {
    client: reqwest::Client,
    base: String,
    did: String,
    keypair: Option<ciss::crypto::Keypair>,
}

impl Actor {
    /// This actor's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Attach a signed session (x-croft-pubkey + x-croft-session) if this actor
    /// holds a key. An actor with no key sends no session and is anonymous to the
    /// boundary.
    fn auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.keypair {
            Some(keypair) => {
                let challenge = format!("ciss-session/v1/{}", self.did);
                builder
                    .header("x-croft-pubkey", keypair.public_key_hex())
                    .header("x-croft-session", keypair.sign_message(&challenge))
            }
            None => builder,
        }
    }

    async fn run(builder: reqwest::RequestBuilder) -> Outcome {
        let resp = builder.send().await.expect("request send");
        let status = resp.status().as_u16();
        let body = resp.bytes().await.expect("body bytes").to_vec();
        Outcome { status, body }
    }

    // ---- S3 plane ----

    /// `PUT /{namespace}/objects/{key}` — store an object (S3 plane).
    pub async fn put_object(&self, namespace: &str, key: &str, bytes: &[u8]) -> Outcome {
        let url = format!("{}/{namespace}/objects/{key}", self.base);
        Self::run(self.auth(self.client.put(url).body(bytes.to_vec()))).await
    }

    /// `GET /{namespace}/objects/{cid}` — fetch an object (S3 plane).
    pub async fn get_object(&self, namespace: &str, cid: &str) -> Outcome {
        let url = format!("{}/{namespace}/objects/{cid}", self.base);
        Self::run(self.auth(self.client.get(url))).await
    }

    /// `GET /{namespace}/meter` — read the billing meter (S3 plane).
    pub async fn read_meter(&self, namespace: &str) -> Outcome {
        let url = format!("{}/{namespace}/meter", self.base);
        Self::run(self.auth(self.client.get(url))).await
    }

    // ---- atproto plane ----

    /// `POST /xrpc/com.atproto.repo.uploadBlob` — store a blob in the session's
    /// repo (atproto plane). Uses this actor's session as the bearer.
    pub async fn upload_blob(&self, bytes: &[u8]) -> Outcome {
        let url = format!("{}/xrpc/com.atproto.repo.uploadBlob", self.base);
        Self::run(self.auth(self.client.post(url).body(bytes.to_vec()))).await
    }

    /// `GET /xrpc/com.atproto.sync.getBlob?did=&cid=` — fetch a blob (public).
    pub async fn get_blob(&self, did: &str, cid_link: &str) -> Outcome {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            self.base,
            enc(did),
            enc(cid_link),
        );
        Self::run(self.auth(self.client.get(url))).await
    }

    /// `GET /xrpc/com.atproto.sync.listBlobs?did=` — the DID's blob CIDs (public).
    pub async fn list_blobs(&self, did: &str) -> Outcome {
        let url = format!(
            "{}/xrpc/com.atproto.sync.listBlobs?did={}",
            self.base,
            enc(did),
        );
        Self::run(self.auth(self.client.get(url))).await
    }

    /// `GET /healthz`.
    pub async fn healthz(&self) -> Outcome {
        Self::run(self.client.get(format!("{}/healthz", self.base))).await
    }
}

/// A deterministic secp256k1 identity for an atproto persona (Model R).
struct AtprotoKeypair {
    did: String,
    sk: k256::ecdsa::SigningKey,
}

/// Derive a persona's secp256k1 key + `did:web:<name>.test` DID deterministically,
/// so the fixture resolver map and the actor always agree on the key.
fn atproto_keypair(name: &str) -> AtprotoKeypair {
    // A valid, non-zero scalar seed built from the name (no extra hash dep needed).
    let mut seed = [1u8; 32];
    for (i, b) in name.bytes().enumerate() {
        seed[i % 32] ^= b;
    }
    let sk = k256::ecdsa::SigningKey::from_slice(&seed).expect("valid scalar");
    AtprotoKeypair {
        did: format!("did:web:{name}.test"),
        sk,
    }
}

impl AtprotoKeypair {
    /// The persona's atproto signing key as a secp256k1 `did:key:` string.
    fn did_key(&self) -> String {
        let point = self.sk.verifying_key().to_encoded_point(true);
        let bytes = [&[0xe7u8, 0x01], point.as_bytes()].concat();
        format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, bytes))
    }
}

/// An atproto persona: authenticates to the atproto plane with a service-auth JWT
/// (Model R) signed by its own repo key, verified server-side against the DID it
/// resolves to. Public reads use the plain [`Actor`] (`World::anonymous`).
pub struct AtprotoActor {
    client: reqwest::Client,
    base: String,
    key: AtprotoKeypair,
}

impl AtprotoActor {
    /// This persona's DID.
    pub fn did(&self) -> &str {
        &self.key.did
    }

    /// Sign a service-auth JWT with this persona's key and explicit claims — so a
    /// flow can forge `iss`, misname `aud`/`lxm`, or expire it.
    pub fn sign_token(&self, iss: &str, aud: &str, lxm: &str, exp_unix: u64, jti: &str) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use k256::ecdsa::{signature::Signer, Signature};
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256K"}"#);
        let claims =
            format!(r#"{{"iss":"{iss}","aud":"{aud}","lxm":"{lxm}","exp":{exp_unix},"jti":"{jti}"}}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig: Signature = self.key.sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    /// A valid upload token: `iss`=self, `aud`=service, `lxm`=upload, unexpired.
    pub fn valid_upload_token(&self, jti: &str) -> String {
        self.sign_token(&self.key.did, SERVICE_DID, UPLOAD_LXM, now_s() + 300, jti)
    }

    /// `uploadBlob` presenting `token` as the bearer.
    pub async fn upload_blob_with_token(&self, token: &str, bytes: &[u8]) -> Outcome {
        let url = format!("{}/xrpc/com.atproto.repo.uploadBlob", self.base);
        Actor::run(
            self.client
                .post(url)
                .header("authorization", format!("Bearer {token}"))
                .body(bytes.to_vec()),
        )
        .await
    }

    /// `uploadBlob` with a fresh valid service-auth JWT (unique `jti` per content).
    pub async fn upload_blob(&self, bytes: &[u8]) -> Outcome {
        let token = self.valid_upload_token(&jti_for(bytes));
        self.upload_blob_with_token(&token, bytes).await
    }
}

/// The current time in unix seconds.
fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A content-derived `jti` so distinct uploads don't collide in the replay guard.
fn jti_for(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("jti-{h:016x}")
}

/// The result of an [`Actor`] operation — status + body, with intent-named
/// assertions so a flow states what it expects, not raw status codes.
pub struct Outcome {
    status: u16,
    body: Vec<u8>,
}

impl Outcome {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The response body as bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The response body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// A short, bounded preview of the body for assertion messages — a large
    /// (or binary) body must never be dumped whole into a panic.
    fn preview(&self) -> String {
        const MAX: usize = 256;
        let head = String::from_utf8_lossy(&self.body[..self.body.len().min(MAX)]);
        if self.body.len() > MAX {
            format!("{head}… ({} bytes total)", self.body.len())
        } else {
            head.into_owned()
        }
    }

    /// The response body parsed as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("expected JSON body, got {:?}: {e}", self.text()))
    }

    /// Assert a 2xx and return self for chaining.
    #[track_caller]
    pub fn ok(&self) -> &Self {
        assert!(
            (200..300).contains(&self.status),
            "expected success, got {} ({:?})",
            self.status,
            self.preview(),
        );
        self
    }

    /// Assert the operation was refused with exactly `status`.
    #[track_caller]
    pub fn refused(&self, status: u16) {
        assert_eq!(
            self.status,
            status,
            "expected refusal {status}, got {} ({:?})",
            self.status,
            self.preview(),
        );
    }

    /// Assert a 200 whose body is exactly `bytes`.
    #[track_caller]
    pub fn returns(&self, bytes: &[u8]) {
        self.ok();
        assert_eq!(self.body, bytes, "unexpected body bytes");
    }

    /// The `cid` field of a JSON response body (an S3 `PUT` result).
    pub fn cid(&self) -> String {
        self.json()["cid"]
            .as_str()
            .expect("a cid field in the response")
            .to_owned()
    }

    /// Assert the (text) body does NOT contain `needle` — the gate does not leak.
    #[track_caller]
    pub fn omits(&self, needle: &str) {
        assert!(
            !self.text().contains(needle),
            "expected body to omit {needle:?}, but it was disclosed: {:?}",
            self.text(),
        );
    }

    /// Assert the (text) body DOES contain `needle` (used to demonstrate a leak).
    #[track_caller]
    pub fn discloses(&self, needle: &str) {
        assert!(
            self.text().contains(needle),
            "expected body to disclose {needle:?}, but it did not: {:?}",
            self.text(),
        );
    }
}
