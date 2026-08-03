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

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ciss::server::{App, Blobs, Db};
use tokio::sync::oneshot;

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

    /// A legitimate actor named `name`: a DID derived from the name, holding a
    /// session for that DID.
    ///
    /// Today the mock boundary treats the bearer string as the acting DID, so a
    /// legit actor's session is its DID. When real sessions land (ADR 0001,
    /// Phase 3) this becomes a verifiable token minted from the actor's key; the
    /// flow API does not change.
    pub fn actor(&self, name: &str) -> Actor {
        let did = derive_did(name);
        Actor {
            client: self.client.clone(),
            base: self.base.clone(),
            session: Some(did.clone()),
            did,
        }
    }

    /// An anonymous caller — no credential of any kind.
    pub fn anonymous(&self) -> Actor {
        Actor {
            client: self.client.clone(),
            base: self.base.clone(),
            did: String::new(),
            session: None,
        }
    }

    /// An impersonator: a caller presenting a bearer that *names* `victim_did`
    /// without possessing its key. Models the forged-bearer attack (A2). Today
    /// the boundary accepts it; the guard asserts it must be refused.
    pub fn impersonator(&self, victim_did: &str) -> Actor {
        Actor {
            client: self.client.clone(),
            base: self.base.clone(),
            did: victim_did.to_owned(),
            session: Some(victim_did.to_owned()),
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

/// A persona acting against a [`World`] over real HTTP. Holds its identity and
/// (optionally) a session credential; every operation returns an [`Outcome`].
pub struct Actor {
    client: reqwest::Client,
    base: String,
    did: String,
    session: Option<String>,
}

impl Actor {
    /// This actor's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    fn auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.session {
            Some(token) => builder.header("authorization", format!("Bearer {token}")),
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
