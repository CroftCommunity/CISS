//! The S3-compatible HTTP boundary — Layer 2, where the network boundary *is*
//! the metering boundary.
//!
//! Every byte that crosses this boundary is metered: an object `PUT`/`GET`
//! produces a signed transfer receipt (postage) recorded in the customer's
//! per-DID ledger, and rent derives from the customer's own signed manifest.
//! The backend ([`crate::blobstore`]) stays dumb; content addressing and the
//! ledger live here.
//!
//! This is the **novel** part of the design (Phase 0 D6: a client-facing
//! S3-compatible interface has no PDS prior art — both rsky-pds and the official
//! PDS use S3 only as an internal backend). It is built from the S3 API + the
//! plan, learning the `BlobStore` shape from rsky-pds without forking it.
//!
//! v0 surface (the minimal metered subset): `PUT`/`GET` objects,
//! `PUT`/`GET` the customer manifest, and a `GET` meter read. The rest of the
//! S3 verb surface (DELETE, LIST, HEAD, multipart) is a `SEAM:` behind the
//! fallback. Requests flow through a small [`Op`] dispatch boundary so a later
//! per-DID compute-observability wrapper (`ROADMAP_TODO` E83) can scope a heavy
//! op into a per-DID cgroup without a rewrite.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};

use crate::blobstore::{BlobError, BlobStore, FsBlobStore, MemoryBlobStore};
use crate::crypto::{derive_keypair, public_key_from_hex, sha256_hex, Keypair};
use crate::identity::derive_id;
use crate::manifest::Manifest;
use crate::persist::{PersistError, Store};
use crate::pricing::postage_cents;
use crate::receipts::{
    make_unilateral_receipt, select_mode, Direction, Receipt, ReceiptCore, ReceiptMode,
    TransferContext,
};

/// Header a client uses to present its public key when writing a signed manifest.
const PUBKEY_HEADER: &str = "x-croft-pubkey";

/// Convert a `usize` byte count to `u64`; the length of any real transfer fits.
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).expect("a byte count fits in u64 on any real machine")
}

/// The provider's own identity (keypair + derived id). Signs unilateral
/// (our-side measurement) receipts at the boundary.
struct Provider {
    id: String,
    keypair: Keypair,
}

impl Provider {
    fn from_seed(seed: &str) -> Self {
        let keypair = derive_keypair(seed, "provider");
        let id = derive_id(&keypair.verifying_key());
        Self { id, keypair }
    }
}

/// Which blob backend the server runs on.
pub enum Blobs {
    /// In-memory backend (default; the test backend).
    Memory,
    /// Local filesystem backend rooted at the given directory.
    Fs(PathBuf),
}

/// Where the per-DID metering records (SQLite) live.
pub enum Db {
    /// In-memory SQLite (`:memory:`) — real persistence code, no file.
    Memory,
    /// A file-backed SQLite database at the given path.
    File(PathBuf),
}

/// Shared server state — all `Arc`-wrapped so the router can clone it per
/// request. The `Store` is behind a `Mutex` because a `rusqlite::Connection` is
/// `!Sync` (the Phase-4b pooling `SEAM:`): v0 resolves it as a single-writer
/// guard. `SEAM:` a real deployment shards a `Store` per DID (one SQLite file
/// each) behind a small pool; here every DID co-locates in one connection,
/// keyed by the `did` column.
#[derive(Clone)]
struct AppState {
    provider: Arc<Provider>,
    blobs: Arc<dyn BlobStore>,
    store: Arc<Mutex<Store>>,
    /// The accounting day stamped on receipts. `SEAM:` v0 uses a fixed day;
    /// a real clock (byte-day rent integrates over wall-clock days) lands with
    /// the statement-close scheduler.
    day: u64,
}

/// The cooperative metered-storage server.
pub struct App {
    state: AppState,
}

impl App {
    /// Build a server: a provider identity derived from `seed`, a blob backend,
    /// and a per-DID metering store.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] if the metering store cannot be opened.
    pub fn new(seed: &str, blobs: Blobs, db: Db) -> Result<Self, ServerError> {
        let provider = Arc::new(Provider::from_seed(seed));
        let blobs: Arc<dyn BlobStore> = match blobs {
            Blobs::Memory => Arc::new(MemoryBlobStore::new()),
            Blobs::Fs(root) => Arc::new(FsBlobStore::new(root)),
        };
        let store = match db {
            Db::Memory => Store::open_in_memory()?,
            Db::File(path) => Store::open(path.to_str().ok_or(ServerError::BadConfig)?)?,
        };
        Ok(Self {
            state: AppState {
                provider,
                blobs,
                store: Arc::new(Mutex::new(store)),
                day: 0,
            },
        })
    }

    /// The provider's derived id (the boundary's signing identity).
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.state.provider.id
    }

    /// Build the axum router for this server. Clones the shared state, so the
    /// `App` may be dropped afterward (the router holds its own `Arc`s) or kept
    /// alive to run [`App::checkpoint`] on shutdown.
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/{did}/objects/{addr}",
                put(put_object_handler).get(get_object_handler),
            )
            .route(
                "/{did}/manifest",
                put(put_manifest_handler).get(get_manifest_handler),
            )
            .route("/{did}/meter", get(get_meter_handler))
            .fallback(unimplemented_s3)
            .with_state(self.state.clone())
    }

    /// Flush the metering store's write-ahead log (`wal_checkpoint(TRUNCATE)`).
    ///
    /// The graceful-shutdown seam (E87): after the server drains in-flight
    /// requests, `main` calls this so a restart sees a checkpointed database.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] if the checkpoint fails.
    pub fn checkpoint(&self) -> Result<(), ServerError> {
        lock_store(&self.state.store).checkpoint_truncate()?;
        Ok(())
    }
}

/// Recover the store guard even if a prior writer panicked: the metering
/// records are append-only and each op holds the guard for a single
/// load+append, so there is no half-written cross-record state to corrupt.
fn lock_store(store: &Mutex<Store>) -> MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A request routed through the dispatch boundary.
enum Op {
    PutObject {
        did: String,
        key: String,
        bytes: Vec<u8>,
    },
    GetObject {
        did: String,
        cid: String,
    },
    PutManifest {
        did: String,
        pubkey_hex: String,
        body: Vec<u8>,
    },
    GetManifest {
        did: String,
    },
    GetMeter {
        did: String,
    },
}

impl Op {
    /// Whether this op is compute-heavy enough to scope into a per-DID cgroup.
    ///
    /// `SEAM:` (E83, "watch in place") a later per-DID compute-observability
    /// wrapper scopes a *heavy* op — CAR export, MST rebuild, audit sampling, a
    /// seal ceremony — into a per-DID cgroup here, without touching the HTTP
    /// handlers. v0 has only cheap ops (blob PUT/GET, manifest, meter), which
    /// are never scoped (spawn cost exceeds their compute), so this is `false`
    /// for every v0 op. It is a real classification point, not a stub.
    fn is_heavy(&self) -> bool {
        match self {
            Op::PutObject { .. }
            | Op::GetObject { .. }
            | Op::PutManifest { .. }
            | Op::GetManifest { .. }
            | Op::GetMeter { .. } => false,
        }
    }
}

/// The result of a dispatched op, ready to render as an HTTP response.
enum OpOutcome {
    Stored {
        cid: String,
        bytes: u64,
        mode: ReceiptMode,
    },
    Bytes {
        cid: String,
        data: Vec<u8>,
    },
    ManifestSaved {
        root: String,
        total_bytes: u64,
    },
    ManifestBody {
        json: String,
    },
    Meter {
        receipt_count: u64,
        upload_bytes: u64,
        download_bytes: u64,
        running_total_bytes: u64,
        postage_cents: u64,
    },
}

/// The single dispatch boundary. Every handler routes through here so the E83
/// per-DID scope wrapper has one attach point.
fn dispatch(state: &AppState, op: Op) -> Result<OpOutcome, ServerError> {
    // SEAM (E83): a heavy op would enter a per-DID cgroup scope here; v0 ops are
    // all cheap, so dispatch runs in-process. The classification is live so the
    // wrapper slots in without a handler rewrite.
    if op.is_heavy() {
        tracing::debug!("heavy op — would enter per-DID compute scope (E83 seam)");
    }
    match op {
        Op::PutObject { did, key, bytes } => op_put_object(state, &did, &key, &bytes),
        Op::GetObject { did, cid } => op_get_object(state, &did, &cid),
        Op::PutManifest {
            did,
            pubkey_hex,
            body,
        } => op_put_manifest(state, &did, &pubkey_hex, &body),
        Op::GetManifest { did } => op_get_manifest(state, &did),
        Op::GetMeter { did } => op_get_meter(state, &did),
    }
}

/// The running total of bytes metered for a DID so far (both directions) — the
/// source of truth is the ledger, so we sum it rather than cache a counter.
/// `SEAM:` cache this per DID for O(1) rather than O(n) per transfer.
fn running_total(receipts: &[Receipt]) -> usize {
    receipts.iter().map(Receipt::bytes).sum()
}

/// The running total after a new transfer of `boundary` bytes: the prior ledger
/// total plus this transfer.
fn next_running_total(prior: &[Receipt], boundary: usize) -> usize {
    running_total(prior) + boundary
}

fn op_put_object(
    state: &AppState,
    did: &str,
    key: &str,
    bytes: &[u8],
) -> Result<OpOutcome, ServerError> {
    let boundary = bytes.len();
    let cid = sha256_hex(bytes);

    // The S3 object key is a client-chosen label; v0 addresses by content, so
    // the key is narration only. `SEAM:` a mutable key->CID name index (S3
    // arbitrary-key GET) is deferred — v0 GETs by CID, matching atproto
    // getBlob(cid).
    tracing::debug!(%did, object_key = %key, %cid, "object key -> content address");

    // Layer 1: dumb backend write. It reports the bytes it wrote.
    let written = state.blobs.put(did, &cid, bytes)?;
    tracing::debug!(%did, %cid, bytes = written, "blob written to backend");

    // Metering-integrity invariant: the boundary byte count must equal what the
    // backend persisted. Any mismatch is a loud failure, not a silent tally.
    if written != boundary {
        tracing::error!(
            %did, %cid, boundary, written,
            "byte-count mismatch between the HTTP boundary and the backend"
        );
        return Err(ServerError::ByteCountMismatch { boundary, written });
    }

    let store = lock_store(&state.store);
    let prior = store.load_receipts(did)?;
    let total = next_running_total(&prior, boundary);

    // Upload: customer -> provider. receiver = provider, sender = customer.
    let core = ReceiptCore::new(
        Direction::Upload,
        &cid,
        (0, boundary),
        total,
        state.day,
        &state.provider.id,
        did,
    );
    let mode = select_mode(
        &TransferContext {
            bytes: boundary,
            trust_distance: None,
        },
        ReceiptMode::Unilateral,
    );
    let receipt = build_boundary_receipt(state, core, mode)?;
    store.append_receipt(did, &receipt)?;
    tracing::info!(
        %did, %cid, receipt = receipt.content_hash(), mode = ?receipt.mode(),
        running_total = total, ledger_index = prior.len(),
        "upload receipt recorded"
    );

    Ok(OpOutcome::Stored {
        cid,
        bytes: as_u64(boundary),
        mode: receipt.mode(),
    })
}

fn op_get_object(state: &AppState, did: &str, cid: &str) -> Result<OpOutcome, ServerError> {
    let data = state.blobs.get(did, cid).map_err(|e| match e {
        BlobError::Missing { .. } => ServerError::NotFound,
        io @ BlobError::Io { .. } => ServerError::Blob(io),
    })?;

    // Layer 2 re-verifies the content address the dumb backend does not check:
    // a byte-flip at rest is caught here, on the way out, and named.
    let actual = sha256_hex(&data);
    if actual != cid {
        tracing::warn!(
            %did, requested = %cid, %actual,
            "tamper at rest: stored bytes do not fingerprint to the content address"
        );
        return Err(ServerError::Tampered {
            cid: cid.to_owned(),
            actual,
        });
    }

    let boundary = data.len();
    let store = lock_store(&state.store);
    let prior = store.load_receipts(did)?;
    let total = next_running_total(&prior, boundary);

    // Download: provider -> customer. receiver = customer, sender = provider.
    let core = ReceiptCore::new(
        Direction::Download,
        cid,
        (0, boundary),
        total,
        state.day,
        did,
        &state.provider.id,
    );
    let mode = select_mode(
        &TransferContext {
            bytes: boundary,
            trust_distance: None,
        },
        ReceiptMode::Unilateral,
    );
    let receipt = build_boundary_receipt(state, core, mode)?;
    store.append_receipt(did, &receipt)?;
    tracing::info!(
        %did, %cid, receipt = receipt.content_hash(), mode = ?receipt.mode(),
        running_total = total, ledger_index = prior.len(),
        "download receipt recorded"
    );

    Ok(OpOutcome::Bytes {
        cid: cid.to_owned(),
        data,
    })
}

/// Build the boundary receipt for a transfer. v0 supports only the
/// provider-signed `Unilateral` (our-side measurement) mode: the raw S3
/// boundary has no channel for the customer's in-band signature.
///
/// `SEAM:` `Bilateral` co-signing needs the customer to countersign in-band —
/// the Phase-8 auth handshake / a later client-signing spike. Until then a
/// policy that selects `Bilateral` is a loud error, never a silent downgrade to
/// unilateral.
fn build_boundary_receipt(
    state: &AppState,
    core: ReceiptCore,
    mode: ReceiptMode,
) -> Result<Receipt, ServerError> {
    match mode {
        ReceiptMode::Unilateral => Ok(make_unilateral_receipt(
            core,
            &state.provider.id,
            &state.provider.keypair,
        )),
        ReceiptMode::Bilateral => Err(ServerError::BilateralUnsupported),
    }
}

fn op_put_manifest(
    state: &AppState,
    did: &str,
    pubkey_hex: &str,
    body: &[u8],
) -> Result<OpOutcome, ServerError> {
    let manifest: Manifest = serde_json::from_slice(body)
        .map_err(|_| ServerError::BadManifest("body is not a valid manifest"))?;
    let key = public_key_from_hex(pubkey_hex).map_err(|_| ServerError::BadPubkey)?;

    // The DID *is* the fingerprint of the key (identity::derive_id), so the
    // presented key must derive the claimed DID — no external key registry
    // needed. `SEAM:` a real deployment resolves did:key/did:plc + an OAuth
    // session (the Phase-8 auth SEAM); this binds key<->DID cryptographically.
    if derive_id(&key) != did {
        return Err(ServerError::DidKeyMismatch);
    }
    if manifest.signer_id() != did {
        return Err(ServerError::BadManifest(
            "manifest signer_id is not the DID",
        ));
    }
    if !manifest.verify(&key) {
        return Err(ServerError::BadManifest("manifest signature/root invalid"));
    }

    lock_store(&state.store).save_manifest(did, &manifest)?;
    tracing::info!(%did, root = manifest.root(), total_bytes = manifest.total_bytes(), "manifest stored");
    Ok(OpOutcome::ManifestSaved {
        root: manifest.root().to_owned(),
        total_bytes: as_u64(manifest.total_bytes()),
    })
}

fn op_get_manifest(state: &AppState, did: &str) -> Result<OpOutcome, ServerError> {
    let manifest = lock_store(&state.store)
        .load_manifest(did)?
        .ok_or(ServerError::NotFound)?;
    Ok(OpOutcome::ManifestBody {
        json: serde_json::to_string(&manifest)?,
    })
}

fn op_get_meter(state: &AppState, did: &str) -> Result<OpOutcome, ServerError> {
    let receipts = lock_store(&state.store).load_receipts(did)?;
    let upload_bytes: usize = receipts
        .iter()
        .filter(|r| r.core().direction == Direction::Upload)
        .map(Receipt::bytes)
        .sum();
    let download_bytes: usize = receipts
        .iter()
        .filter(|r| r.core().direction == Direction::Download)
        .map(Receipt::bytes)
        .sum();
    let total = upload_bytes + download_bytes;
    Ok(OpOutcome::Meter {
        receipt_count: as_u64(receipts.len()),
        upload_bytes: as_u64(upload_bytes),
        download_bytes: as_u64(download_bytes),
        running_total_bytes: as_u64(total),
        postage_cents: postage_cents(as_u64(total)),
    })
}

// ---- HTTP handlers: extract inputs, route through the dispatch boundary. ----

async fn put_object_handler(
    State(state): State<AppState>,
    Path((did, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    tracing::info!(method = "PUT", %did, key = %key, bytes = body.len(), "object boundary");
    dispatch(
        &state,
        Op::PutObject {
            did,
            key,
            bytes: body.to_vec(),
        },
    )
}

async fn get_object_handler(
    State(state): State<AppState>,
    Path((did, addr)): Path<(String, String)>,
) -> Result<OpOutcome, ServerError> {
    tracing::info!(method = "GET", %did, cid = %addr, "object boundary");
    dispatch(&state, Op::GetObject { did, cid: addr })
}

async fn put_manifest_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    let pubkey_hex = headers
        .get(PUBKEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    dispatch(
        &state,
        Op::PutManifest {
            did,
            pubkey_hex,
            body: body.to_vec(),
        },
    )
}

async fn get_manifest_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<OpOutcome, ServerError> {
    dispatch(&state, Op::GetManifest { did })
}

async fn get_meter_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<OpOutcome, ServerError> {
    dispatch(&state, Op::GetMeter { did })
}

/// The unimplemented S3 verb surface.
///
/// `SEAM:` DELETE, LIST/ListObjects, HEAD, multipart, and bucket operations are
/// out of the v0 metered subset. They land behind this fallback as features are
/// built; v0 is the minimal PUT/GET metering plane.
async fn unimplemented_s3() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "not implemented in v0 (SEAM: S3 verb surface beyond PUT/GET)",
    )
        .into_response()
}

/// An `ETag` header value for a content address (`"<cid>"`, quoted per HTTP).
fn etag(cid: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{cid}\""))
        .expect("a hex content address is a valid header value")
}

impl IntoResponse for OpOutcome {
    fn into_response(self) -> Response {
        match self {
            OpOutcome::Stored { cid, bytes, mode } => {
                let mode_str = match mode {
                    ReceiptMode::Unilateral => "unilateral",
                    ReceiptMode::Bilateral => "bilateral",
                };
                let mut resp = Json(serde_json::json!({
                    "cid": cid,
                    "bytes": bytes,
                    "receipt_mode": mode_str,
                }))
                .into_response();
                resp.headers_mut().insert("etag", etag(&cid));
                resp
            }
            OpOutcome::Bytes { cid, data } => {
                let mut resp = (StatusCode::OK, data).into_response();
                resp.headers_mut().insert("etag", etag(&cid));
                resp
            }
            OpOutcome::ManifestSaved { root, total_bytes } => Json(serde_json::json!({
                "root": root,
                "total_bytes": total_bytes,
            }))
            .into_response(),
            OpOutcome::ManifestBody { json } => {
                ([("content-type", "application/json")], json).into_response()
            }
            OpOutcome::Meter {
                receipt_count,
                upload_bytes,
                download_bytes,
                running_total_bytes,
                postage_cents,
            } => Json(serde_json::json!({
                "receipt_count": receipt_count,
                "upload_bytes": upload_bytes,
                "download_bytes": download_bytes,
                "running_total_bytes": running_total_bytes,
                "postage_cents": postage_cents,
            }))
            .into_response(),
        }
    }
}

/// A failure at the boundary. Maps to an HTTP status; 5xx failures are logged.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The metering store failed.
    #[error("persistence error: {0}")]
    Persist(#[from] PersistError),
    /// The blob backend failed.
    #[error("blob backend error: {0}")]
    Blob(#[from] BlobError),
    /// No such object or manifest.
    #[error("not found")]
    NotFound,
    /// Stored bytes no longer fingerprint to the requested content address.
    #[error("tampered object {cid} (stored bytes fingerprint as {actual})")]
    Tampered {
        /// The requested content address.
        cid: String,
        /// The fingerprint the stored bytes actually produce.
        actual: String,
    },
    /// A manifest was malformed or failed verification.
    #[error("invalid manifest: {0}")]
    BadManifest(&'static str),
    /// The presented public key was not valid.
    #[error("public key is not valid")]
    BadPubkey,
    /// The presented key does not derive the claimed DID.
    #[error("public key does not derive the claimed DID")]
    DidKeyMismatch,
    /// A bilateral receipt was requested at the raw S3 boundary (unsupported).
    #[error("bilateral co-signing is not supported at the raw S3 boundary (SEAM)")]
    BilateralUnsupported,
    /// The boundary byte count disagreed with the backend (metering integrity).
    #[error("metering integrity: HTTP boundary {boundary} bytes != backend {written} bytes")]
    ByteCountMismatch {
        /// Bytes seen at the HTTP boundary.
        boundary: usize,
        /// Bytes the backend reported writing.
        written: usize,
    },
    /// A record failed to serialize.
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// The server was misconfigured (e.g. a non-UTF-8 database path).
    #[error("bad configuration")]
    BadConfig,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = match self {
            ServerError::NotFound => StatusCode::NOT_FOUND,
            ServerError::BadManifest(_) | ServerError::BadPubkey => StatusCode::BAD_REQUEST,
            ServerError::DidKeyMismatch => StatusCode::FORBIDDEN,
            ServerError::BilateralUnsupported => StatusCode::NOT_IMPLEMENTED,
            ServerError::Tampered { .. } | ServerError::ByteCountMismatch { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ServerError::Persist(_)
            | ServerError::Blob(_)
            | ServerError::Json(_)
            | ServerError::BadConfig => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = self.to_string();
        if status.is_server_error() {
            tracing::error!(%status, error = %message, "boundary request failed");
        }
        (status, message).into_response()
    }
}

/// Whether a systemd socket-activation fd should be inherited: `LISTEN_FDS` is
/// exactly `1` and `LISTEN_PID` names this process.
///
/// `SEAM:` (E87) the zero-downtime-upgrade seam. When systemd socket-activates
/// the service it passes the listening fd (fd 3) and sets these env vars; the
/// kernel backlog then buffers connections across a restart. The chosen upgrade
/// *strategy* is selected by the E87 spike; v0 provides the inherit decision.
#[must_use]
pub fn inherit_fd_requested(
    listen_fds: Option<&str>,
    listen_pid: Option<&str>,
    my_pid: u32,
) -> bool {
    let one_fd = listen_fds.map(str::trim) == Some("1");
    let names_us = listen_pid
        .and_then(|p| p.trim().parse::<u32>().ok())
        .is_some_and(|pid| pid == my_pid);
    one_fd && names_us
}

#[cfg(test)]
mod tests {
    use super::{inherit_fd_requested, next_running_total, running_total, App, Blobs, Db, Op};
    use crate::crypto::derive_keypair;
    use crate::receipts::{
        make_unilateral_receipt, select_mode, Direction, ReceiptCore, ReceiptMode, TransferContext,
    };

    #[test]
    fn running_total_accumulates_bytes_across_the_ledger() {
        let provider = derive_keypair("s", "provider");
        let receipt = |bytes: usize, rt: usize| {
            make_unilateral_receipt(
                ReceiptCore::new(Direction::Upload, "cid", (0, bytes), rt, 0, "id:p", "id:c"),
                "id:p",
                &provider,
            )
        };
        assert_eq!(running_total(&[]), 0, "an empty ledger totals zero");
        let r10 = receipt(10, 10);
        assert_eq!(
            running_total(std::slice::from_ref(&r10)),
            10,
            "one receipt totals its bytes",
        );
        let r25 = receipt(25, 35);
        assert_eq!(
            running_total(&[r10.clone(), r25]),
            35,
            "sums across receipts"
        );
        // next = prior total + this transfer (pins +, so +->* and +->- fail).
        assert_eq!(next_running_total(&[], 25), 25);
        assert_eq!(next_running_total(std::slice::from_ref(&r10), 25), 35);
    }

    #[test]
    fn provider_id_is_deterministic_from_the_seed() {
        let a = App::new("seed", Blobs::Memory, Db::Memory).expect("a");
        let b = App::new("seed", Blobs::Memory, Db::Memory).expect("b");
        assert_eq!(
            a.provider_id(),
            b.provider_id(),
            "same seed -> same provider id"
        );
        assert!(a.provider_id().starts_with("id:"));
    }

    #[test]
    fn checkpoint_succeeds_on_a_fresh_store() {
        let app = App::new("seed", Blobs::Memory, Db::Memory).expect("app");
        app.checkpoint().expect("wal_checkpoint(TRUNCATE) succeeds");
    }

    #[test]
    fn v0_ops_are_never_scoped_heavy() {
        // The E83 seam classifies every v0 op as cheap (never cgroup-scoped).
        // This pins that invariant so a mutant flipping is_heavy -> true fails.
        let ops = [
            Op::PutObject {
                did: "id:x".into(),
                key: "k".into(),
                bytes: vec![],
            },
            Op::GetObject {
                did: "id:x".into(),
                cid: "c".into(),
            },
            Op::PutManifest {
                did: "id:x".into(),
                pubkey_hex: String::new(),
                body: vec![],
            },
            Op::GetManifest { did: "id:x".into() },
            Op::GetMeter { did: "id:x".into() },
        ];
        for op in ops {
            assert!(!op.is_heavy(), "v0 ops are cheap and never cgroup-scoped");
        }
    }

    #[test]
    fn v0_trust_policy_defaults_to_unilateral() {
        // The boundary builds unilateral receipts; the select_mode SEAM returns
        // the default in v0. Pins that so the boundary's mode is provable.
        let mode = select_mode(
            &TransferContext {
                bytes: 10,
                trust_distance: None,
            },
            ReceiptMode::Unilateral,
        );
        assert_eq!(mode, ReceiptMode::Unilateral);
    }

    #[test]
    fn socket_activation_inherit_decision() {
        let pid = 4242;
        // Requested: exactly one fd, and LISTEN_PID names us.
        assert!(inherit_fd_requested(Some("1"), Some("4242"), pid));
        // Not requested: no env, wrong pid, or more than one fd.
        assert!(
            !inherit_fd_requested(None, None, pid),
            "no env -> fresh bind"
        );
        assert!(
            !inherit_fd_requested(Some("1"), Some("9999"), pid),
            "another process's fds -> fresh bind",
        );
        assert!(
            !inherit_fd_requested(Some("2"), Some("4242"), pid),
            "more than one fd is not the v0 single-socket case",
        );
    }
}
