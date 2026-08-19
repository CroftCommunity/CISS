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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use zeroize::{Zeroize, Zeroizing};

use crate::blobstore::{BlobError, BlobStore, FsBlobStore, MemoryBlobStore};
use ciss_auth::{Principal, ReplayGuard, ServiceAuthParams};
use ciss_resolve::{DidResolver, StaticResolver};

use crate::crypto::{derive_keypair, public_key_from_hex, sha256_hex, Keypair};
use crate::identifiers::{ContentAddr, Did};
use crate::identity::derive_id;
use crate::manifest::Manifest;
use crate::persist::{PersistError, Store};
use crate::assertion::{make_ack, SignedAssertion};
use crate::dials::{
    account_mode_body_fold, ceiling_body_fold, receipt_mode_body_fold, AccountMode,
    AccountModeBody, CeilingDialBody, ReceiptModeBody, ReceiptModeChoice,
    ACCOUNT_MODE_DIAL_KIND, CEILING_DIAL_KIND, PERIOD_BODY_FOLD, PERIOD_DIAL_KIND,
    RECEIPT_MODE_DIAL_KIND,
};
use crate::policy::{policy_body_fold, policy_body_valid, PolicyBody, ReadClass, ResolvedPolicy, POLICY_KIND};
use crate::pricing::postage_cents;
use crate::receipts::{
    make_unilateral_receipt, select_mode, Direction, Receipt, ReceiptCore, ReceiptMode,
    TransferContext,
};

/// Header a client uses to present its public key (for a signed manifest, and as
/// the session identity for a signed-session write).
const PUBKEY_HEADER: &str = "x-croft-pubkey";

/// Header carrying the caller's session signature over the session challenge.
const SESSION_HEADER: &str = "x-croft-session";

/// Domain-separated session-challenge prefix. The caller signs
/// `{SESSION_CHALLENGE_PREFIX}{did}` (where `did` is the id its key derives) to
/// prove key possession — so it can only authenticate as its own DID. `SEAM:`
/// (ADR 0001) this interim signed session is replaced by atproto OAuth/DPoP with
/// a server-issued nonce; the [`Principal`] boundary does not change.
const SESSION_CHALLENGE_PREFIX: &str = "ciss-session/v1/";

/// The lexicon method id a Model-C set-policy service-auth JWT must be bound to
/// (`lxm`). A CISS-defined method (Q2): the `did:` owner's provider signs a token
/// authorizing exactly this action, so a token minted for another method cannot
/// be replayed to set policy.
pub(crate) const PUT_ASSERTION_LXM: &str = "ing.croft.ciss.putAssertion";

/// The lexicon method a `did:` caller's **policy read-back** JWT binds to. Lets a
/// `did:` owner (whose key lives at an external provider, so it holds no `id:`
/// session) read its own policy back over the `did:` auth path.
pub(crate) const GET_POLICY_LXM: &str = "ing.croft.ciss.getPolicy";

/// The lexicon method a `did:` caller's usage-inspection (`du`) service-auth JWT
/// must bind to (ADR 0003).
pub(crate) const DU_LXM: &str = "ing.croft.ciss.du";

/// The lexicon method a `did:` caller's **assertion erasure** JWT binds to
/// (ADR 0005 / A2). Owner-only, like the write it undoes.
pub(crate) const DELETE_ASSERTION_LXM: &str = "ing.croft.ciss.deleteAssertion";

/// The lexicon method a `did:` caller's **assertion listing** JWT binds to
/// (ADR 0005 / A2). Owner-only and self-only (the `du` discipline).
pub(crate) const LIST_ASSERTIONS_LXM: &str = "ing.croft.ciss.listAssertions";

/// The lexicon method a `did:` caller's **chain compaction** JWT binds to
/// (ADR 0005 / A4 — the billing-marker shred). Owner-only.
pub(crate) const COMPACT_CHAIN_LXM: &str = "ing.croft.ciss.compactChain";

/// How long a single data-plane request may run before it is dropped (V4).
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// The maximum number of data-plane requests served concurrently. Bounds
/// aggregate memory (each in-flight request buffers at most one capped object)
/// and blocking-pool pressure. `/healthz` is exempt.
const MAX_INFLIGHT_REQUESTS: usize = 64;

/// Convert a `usize` byte count to `u64`; the length of any real transfer fits.
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).expect("a byte count fits in u64 on any real machine")
}

/// The provider's own identity (keypair + derived id). Signs unilateral
/// (our-side measurement) receipts at the boundary, and — via a **separate**
/// derived key — attests policy records for `did:` owners (Model C).
struct Provider {
    id: String,
    keypair: Keypair,
    /// A dedicated key for provider policy attestations (Model C), derived from
    /// the same seed under a distinct label so the receipt/billing `keypair`
    /// stays single-purpose (Q3 — separates metering crypto from authZ crypto,
    /// gives independent rotation, no new secret at rest).
    attest_keypair: Keypair,
}

impl Provider {
    fn from_seed(seed: &str) -> Self {
        let keypair = derive_keypair(seed, "provider");
        let attest_keypair = derive_keypair(seed, "policy-attest");
        let id = derive_id(&keypair.verifying_key());
        Self {
            id,
            keypair,
            attest_keypair,
        }
    }

    /// The provider's public key (hex) — a non-secret verification anchor.
    fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// The provider's attestation public key — the key `ProviderAttested`
    /// records and every assertion ack verify under (never the receipt key).
    fn attest_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.attest_keypair.verifying_key()
    }

    /// The attestation public key, hex — published in the well-known
    /// document so customers can verify acks offline (D2).
    fn attest_verifying_key_hex(&self) -> String {
        self.attest_keypair.public_key_hex()
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

/// The default whole-store ceiling when `CISS_MAX_STORE_BYTES` is unset: 50 GiB.
const DEFAULT_STORE_CEILING_BYTES: u64 = 50 * 1024 * 1024 * 1024;
/// Env var for the whole-store distinct-bytes ceiling.
const STORE_CEILING_ENV: &str = "CISS_MAX_STORE_BYTES";
/// Env var for the optional per-DID distinct-bytes cap (unset ⇒ opportunistic).
const DID_CAP_ENV: &str = "CISS_MAX_DID_BYTES";
/// `meta` keys under which the effective limits are persisted (so the read
/// surface / CLI report what is actually enforced).
const STORE_CEILING_META: &str = "store_ceiling";
const DID_CAP_META: &str = "did_cap";

/// The storage-quota limits (finding V5). The whole-store ceiling is always
/// enforced; the per-DID cap is optional — absent means DIDs fill the store
/// opportunistically (the default).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The whole-store distinct-bytes ceiling.
    pub store_ceiling: u64,
    /// The optional per-DID distinct-bytes cap; `None` ⇒ opportunistic.
    pub did_cap: Option<u64>,
}

impl Limits {
    /// Resolve limits from the environment: `CISS_MAX_STORE_BYTES` (default
    /// 50 GiB) and the optional `CISS_MAX_DID_BYTES` (unset / empty / `0` ⇒ no
    /// per-DID cap).
    #[must_use]
    pub fn from_env() -> Self {
        let store_ceiling = std::env::var(STORE_CEILING_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_STORE_CEILING_BYTES);
        let did_cap = std::env::var(DID_CAP_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0);
        Self {
            store_ceiling,
            did_cap,
        }
    }
}

/// Shared server state — all `Arc`-wrapped so the router can clone it per
/// request. The `Store` is behind a `Mutex` because a `rusqlite::Connection` is
/// `!Sync` (the Phase-4b pooling `SEAM:`): v0 resolves it as a single-writer
/// guard. `SEAM:` a real deployment shards a `Store` per DID (one SQLite file
/// each) behind a small pool; here every DID co-locates in one connection,
/// keyed by the `did` column.
/// When chain compaction fires (ADR 0005 / A4) — a configured policy, because
/// compaction is the one irreversible, history-destroying act. Automatic on
/// checkpoint ack for dev/tests and the starting case; deferred to a deliberate
/// compaction call (a billing marker) in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompactionPolicy {
    /// Compact behind a checkpoint the moment it is written and acked (default).
    #[default]
    OnAck,
    /// Never compact on write; only an explicit compaction call shreds history.
    Deferred,
}

#[derive(Clone)]
pub(crate) struct AppState {
    provider: Arc<Provider>,
    blobs: Arc<dyn BlobStore>,
    store: Arc<Mutex<Store>>,
    /// The storage-quota limits (V5).
    limits: Limits,
    /// The accounting day stamped on receipts. `SEAM:` v0 uses a fixed day;
    /// a real clock (byte-day rent integrates over wall-clock days) lands with
    /// the statement-close scheduler.
    day: u64,
    /// Resolves an atproto DID to its signing key for service-auth JWT
    /// verification (Model R). Defaults to an empty [`StaticResolver`] (all `did:`
    /// auth fails closed) until a real resolver is wired via
    /// [`App::with_did_resolver`]; the production network resolver lands at deploy.
    resolver: Arc<dyn DidResolver>,
    /// Replay guard for verified service-auth JWTs (`jti` seen-set).
    replay: Arc<ReplayGuard>,
    /// This service's atproto DID — the `aud` a service-auth JWT must name.
    service_did: Arc<str>,
    /// When `admin_only_du` is set, the DIDs permitted to run `du` (the break-glass
    /// admin pins, at deploy). `du` is always self-only regardless; this set only
    /// governs *who* may run it under the lockdown.
    admin_dids: Arc<std::collections::HashSet<String>>,
    /// The `CISS_ADMIN_ONLY_DU` lockdown flag (ADR 0003). When set, only a DID in
    /// `admin_dids` may run `du` — still only for its own namespace. Off by
    /// default: any authenticated caller may `du` its own namespace.
    admin_only_du: bool,
    /// When chain compaction fires (ADR 0005 / A4). `OnAck` by default.
    compaction: CompactionPolicy,
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
        Self::with_limits(seed, blobs, db, Limits::from_env())
    }

    /// Build a server with explicit storage-quota [`Limits`] (the injection point
    /// for tests that need a small ceiling; the deployment path resolves limits
    /// from the environment).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] if the metering store cannot be opened.
    pub fn with_limits(seed: &str, blobs: Blobs, db: Db, limits: Limits) -> Result<Self, ServerError> {
        let store = open_store(db)?;
        persist_limits(&store, limits)?;
        Ok(Self::assemble(Provider::from_seed(seed), blobs, store, limits))
    }

    /// Build a server whose provider signing key comes from a **unit-supplied
    /// secret**, never from the canonical database (I8). The seed is read from a
    /// systemd credential (`$CREDENTIALS_DIRECTORY/provider-seed`) or the
    /// `CISS_PROVIDER_SEED` environment variable; under systemd with neither wired
    /// it **fails closed** rather than run a throwaway identity. Outside systemd
    /// (dev) it falls back to an ephemeral random seed with a loud warning.
    ///
    /// The provider's **public** key is persisted to the metering store as a
    /// durable, non-secret verification anchor, so historical receipts stay
    /// verifiable even if the private key is later rotated or lost. The private
    /// seed is never written to SQLite (and so never reaches an off-box backup).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] if the store cannot be opened, the secret is
    /// missing under systemd, or the pubkey anchor cannot be persisted.
    pub fn with_provider_from_secret(blobs: Blobs, db: Db) -> Result<Self, ServerError> {
        let store = open_store(db)?;
        let seed = resolve_provider_seed()?;
        let provider = Provider::from_seed(&seed);
        // Durable, non-secret verification anchor — never the seed.
        store.put_meta(PROVIDER_PUBKEY_KEY, &provider.public_key_hex())?;
        let limits = Limits::from_env();
        persist_limits(&store, limits)?;
        tracing::info!(
            provider = %provider.id,
            store_ceiling = limits.store_ceiling,
            did_cap = ?limits.did_cap,
            "provider identity loaded from secret",
        );
        Ok(Self::assemble(provider, blobs, store, limits))
    }

    fn assemble(provider: Provider, blobs: Blobs, store: Store, limits: Limits) -> Self {
        let blobs: Arc<dyn BlobStore> = match blobs {
            Blobs::Memory => Arc::new(MemoryBlobStore::new()),
            Blobs::Fs(root) => Arc::new(FsBlobStore::new(root)),
        };
        Self {
            state: AppState {
                provider: Arc::new(provider),
                blobs,
                store: Arc::new(Mutex::new(store)),
                limits,
                day: 0,
                // Fail-closed default: no DID resolves until a real resolver is
                // wired (tests inject a fixture; deploy composes the network stack).
                resolver: Arc::new(StaticResolver::default()),
                replay: Arc::new(ReplayGuard::new()),
                service_did: Arc::from(default_service_did().as_str()),
                // Usage inspection (`du`, ADR 0003): always self-only. Off by
                // default; an operator locks `du` to admins via `with_admin_only_du`.
                admin_dids: Arc::new(std::collections::HashSet::new()),
                admin_only_du: false,
                // Compaction defaults to on-ack (the starting case / tests);
                // production sets Deferred to shred only at a billing marker.
                compaction: CompactionPolicy::default(),
            },
        }
    }

    /// Set the chain compaction policy (ADR 0005 / A4). Default [`CompactionPolicy::OnAck`]
    /// compacts a chain the moment a checkpoint is acked; [`CompactionPolicy::Deferred`]
    /// leaves compaction to an explicit call (a billing marker) so a checkpoint
    /// write never destroys history on its own.
    #[must_use]
    pub fn with_compaction_policy(mut self, policy: CompactionPolicy) -> Self {
        self.state.compaction = policy;
        self
    }

    /// Lock `du` to admins (`CISS_ADMIN_ONLY_DU`, ADR 0003 / invariant Z9). `du` is
    /// always **self-only** (cross-DID is never served); this only governs *who*
    /// may run it. With `enabled` set, only a DID in `admin_dids` (the break-glass
    /// admin pins, at deploy) may run `du` on its own namespace. Off by default:
    /// any authenticated caller may `du` its own namespace.
    #[must_use]
    pub fn with_admin_only_du(
        mut self,
        admin_dids: std::collections::HashSet<String>,
        enabled: bool,
    ) -> Self {
        self.state.admin_dids = Arc::new(admin_dids);
        self.state.admin_only_du = enabled;
        self
    }

    /// Wire the atproto DID resolver and this service's `aud` DID (Model R). The
    /// injection point for tests (a fixture [`StaticResolver`]) and, at deploy, the
    /// composed network resolver. Without it, `did:` service-auth fails closed.
    #[must_use]
    pub fn with_did_resolver(
        mut self,
        resolver: Arc<dyn DidResolver>,
        service_did: impl Into<Arc<str>>,
    ) -> Self {
        self.state.resolver = resolver;
        self.state.service_did = service_did.into();
        self
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
        // The metered data plane, guarded by a request timeout (a stuck request
        // is dropped, not held — finding V4) and a global in-flight cap (bounds
        // aggregate memory across concurrent requests — findings V1/V5). Both
        // sit *below* `/healthz` so a saturated data plane never delays the
        // liveness probe (croft-stack contract §2).
        let data = Router::new()
            .route(
                "/{did}/objects/{addr}",
                put(put_object_handler).get(get_object_handler),
            )
            .route(
                "/{did}/manifest",
                put(put_manifest_handler).get(get_manifest_handler),
            )
            .route(
                "/{did}/assertion/{kind}",
                put(put_assertion_handler)
                    .get(get_assertion_handler)
                    .delete(delete_assertion_handler),
            )
            .route(
                "/{did}/assertion/{kind}/{subkey}",
                put(put_assertion_subkey_handler)
                    .get(get_assertion_subkey_handler)
                    .delete(delete_assertion_subkey_handler),
            )
            // The owner-only subkey listing (A2) — plural `assertions`, distinct
            // from the singular read-back route above.
            .route("/{did}/assertions/{kind}", get(list_assertions_handler))
            // Explicit chain compaction (A4, the billing-marker path).
            .route(
                "/{did}/assertion/{kind}/{subkey}/compact",
                axum::routing::post(compact_chain_handler),
            )
            .route(
                "/{did}/receipt/{hash}/countersign",
                axum::routing::post(countersign_receipt_handler),
            )
            .route("/{did}/meter", get(get_meter_handler))
            .route("/{did}/du", get(du_handler))
            // The atproto PDS blob surface (Phase 8) — a thin layer over the
            // same metered byte-path, mounted at its XRPC paths.
            .merge(crate::pds_api::routes())
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(REQUEST_TIMEOUT_SECS),
            ))
            .layer(GlobalConcurrencyLimitLayer::new(MAX_INFLIGHT_REQUESTS));

        Router::new()
            // Liveness/readiness probe: fast, side-effect-free, unlimited — never
            // behind the data plane's timeout or concurrency gate.
            .route("/healthz", get(healthz_handler))
            // CISS's did:web document — public, so external atproto clients can
            // resolve `did:web:ciss.croft.ing` and address it as a service-auth
            // `aud`. Cheap + side-effect-free, so it sits beside `/healthz`.
            .route("/.well-known/did.json", get(well_known_did_handler))
            // OAuth resource-server discovery (RFC 9728) — the pointer half
            // of the RS surface (E101): public, cheap, side-effect-free.
            .route(
                "/.well-known/oauth-protected-resource",
                get(oauth_protected_resource_handler),
            )
            .merge(data)
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

/// The `meta` key under which the provider's PUBLIC key is persisted — a
/// non-secret verification anchor so historical receipts stay verifiable even if
/// the private key is later rotated or lost. The private seed is never stored
/// here (I8).
const PROVIDER_PUBKEY_KEY: &str = "provider_pubkey";

/// The systemd credential name (under `$CREDENTIALS_DIRECTORY`) carrying the
/// provider's signing seed.
const PROVIDER_SEED_CREDENTIAL: &str = "provider-seed";

/// The environment variable carrying the provider seed (a dev / non-systemd
/// alternative to the systemd credential).
const PROVIDER_SEED_ENV: &str = "CISS_PROVIDER_SEED";

/// Persist the effective storage limits to the store's `meta` so the read
/// surface (`did_usage` + these keys) and the `ciss usage` CLI report exactly
/// what the running service enforces.
fn persist_limits(store: &Store, limits: Limits) -> Result<(), ServerError> {
    store.put_meta(STORE_CEILING_META, &limits.store_ceiling.to_string())?;
    store.put_meta(
        DID_CAP_META,
        &limits.did_cap.map(|c| c.to_string()).unwrap_or_default(),
    )?;
    Ok(())
}

/// Open the metering store from a [`Db`] config.
fn open_store(db: Db) -> Result<Store, ServerError> {
    match db {
        Db::Memory => Ok(Store::open_in_memory()?),
        Db::File(path) => Ok(Store::open(path.to_str().ok_or(ServerError::BadConfig)?)?),
    }
}

/// Return the persisted provider seed, generating and persisting a fresh random
/// one on first start. The seed lives in the canonical SQLite so it is backed up
/// with the ledger it signs.
/// What to do about the provider seed given the available sources (a pure,
/// testable decision — see [`resolve_provider_seed`] for the impure wiring).
#[derive(Debug, PartialEq, Eq)]
enum SeedDecision {
    /// Use this configured seed.
    Use(Zeroizing<String>),
    /// No secret configured, but not under systemd (dev): generate an ephemeral
    /// identity with a warning.
    GenerateEphemeral,
    /// No secret configured under systemd (a real unit): fail closed.
    FailClosed,
}

/// Decide the seed source. A systemd credential wins over the env var; with
/// neither, we fail closed under systemd and dev-generate otherwise.
fn decide_seed(
    credential: Option<Zeroizing<String>>,
    env: Option<Zeroizing<String>>,
    under_systemd: bool,
) -> SeedDecision {
    if let Some(seed) = credential.filter(|s| !s.is_empty()) {
        return SeedDecision::Use(seed);
    }
    if let Some(seed) = env.filter(|s| !s.is_empty()) {
        return SeedDecision::Use(seed);
    }
    if under_systemd {
        SeedDecision::FailClosed
    } else {
        SeedDecision::GenerateEphemeral
    }
}

/// Read the provider seed from the systemd credential directory, if present.
fn seed_from_credential() -> Result<Option<Zeroizing<String>>, ServerError> {
    let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return Ok(None);
    };
    let path = PathBuf::from(dir).join(PROVIDER_SEED_CREDENTIAL);
    match std::fs::read_to_string(&path) {
        Ok(seed) => Ok(Some(Zeroizing::new(seed.trim().to_owned()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ServerError::BadConfig),
    }
}

/// Resolve the provider signing seed from the unit-supplied secret (I8): a
/// systemd credential, else the env var; under systemd with neither, fail closed
/// rather than run a throwaway identity; outside systemd (dev), generate an
/// ephemeral seed with a loud warning. The seed is held in a `Zeroizing` wrapper
/// so the in-memory copy is scrubbed on drop, and is never written to the store.
fn resolve_provider_seed() -> Result<Zeroizing<String>, ServerError> {
    let credential = seed_from_credential()?;
    let env = std::env::var(PROVIDER_SEED_ENV).ok().map(Zeroizing::new);
    let under_systemd = std::env::var_os("INVOCATION_ID").is_some();
    match decide_seed(credential, env, under_systemd) {
        SeedDecision::Use(seed) => Ok(seed),
        SeedDecision::FailClosed => Err(ServerError::ProviderSeedMissing),
        SeedDecision::GenerateEphemeral => {
            tracing::warn!(
                "no provider seed configured (no {PROVIDER_SEED_CREDENTIAL} credential or \
                 {PROVIDER_SEED_ENV}); using an EPHEMERAL dev identity — receipts will not \
                 verify across a restart"
            );
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|_| ServerError::BadConfig)?;
            let seed = Zeroizing::new(hex::encode(bytes));
            bytes.zeroize();
            Ok(seed)
        }
    }
}

/// Recover the store guard even if a prior writer panicked: the metering
/// records are append-only and each op holds the guard for a single
/// load+append, so there is no half-written cross-record state to corrupt.
fn lock_store(store: &Mutex<Store>) -> MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A verified Model-C set-policy authorization: the `did:` owner authenticated by
/// a service-auth JWT (the JWT `iss`), plus the single-use `jti` that authorized
/// the action (recorded on the attested record for audit). Produced by the async
/// handler *before* dispatch, since JWT verification resolves the DID over the
/// network and dispatch runs on the blocking pool.
pub(crate) struct AuthedWrite {
    did: String,
    jti: Option<String>,
}

/// A request routed through the dispatch boundary.
pub(crate) enum Op {
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
    /// The content addresses (hex SHA-256) a DID has uploaded — the source for
    /// the atproto `listBlobs` surface. Derived from the DID's upload receipts,
    /// so it needs no backend enumeration primitive.
    ListBlobs {
        did: String,
    },
    /// Set/replace the read policy for a target (namespace when `cid` is `None`,
    /// else a single object). Model A (`authed = None`): `body` is a serialized,
    /// owner-signed [`crate::policy::PolicyRecord`]. Model C (`authed = Some`):
    /// `body` is a [`crate::policy::PolicyIntent`] and CISS builds + provider-
    /// attests the record for the JWT-authenticated `did:` owner.
    PutAssertion {
        did: String,
        kind: String,
        subkey: Option<String>,
        body: Vec<u8>,
        authed: Option<AuthedWrite>,
    },
    /// Read back a stored assertion + its ack (kind-specific visibility; the
    /// `policy` kind keeps its Q4 owner-only reader-set rule).
    GetAssertion {
        did: String,
        kind: String,
        subkey: Option<String>,
    },
    /// Erase a stored assertion (ADR 0005 / A2). Owner-only; allowed only for a
    /// kind declaring `Erasable`. A `Permanent` kind is refused with its reason.
    DeleteAssertion {
        did: String,
        kind: String,
        subkey: Option<String>,
    },
    /// List the subkeys a DID holds for one kind (ADR 0005 / A2). Owner-only and
    /// self-only (no existence oracle); allowed only for a `Listable` kind.
    ListAssertions {
        did: String,
        kind: String,
    },
    /// Read a chain's full entry history plus its recomputed, verified total
    /// (ADR 0005 / A3 — the `?chain=1` read). Owner-only.
    GetChain {
        did: String,
        kind: String,
        subkey: Option<String>,
    },
    /// Compact a chain behind its latest acknowledged checkpoint (ADR 0005 / A4 —
    /// the explicit billing-marker path). Owner-only; refused if no checkpoint
    /// exists to compact behind (no shredding before agreement).
    CompactChain {
        did: String,
        kind: String,
        subkey: Option<String>,
    },
    /// The customer countersigns a bilateral receipt (self-authorizing: the
    /// signature must verify under the key deriving the DID).
    CountersignReceipt {
        did: String,
        content_hash: String,
        sig: String,
    },
    /// Usage report for a DID: per-object sizes + total (ADR 0003). Always
    /// self-only; `CISS_ADMIN_ONLY_DU` further restricts to admins (checked in-handler).
    Du {
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
            | Op::GetMeter { .. }
            | Op::ListBlobs { .. }
            | Op::PutAssertion { .. }
            | Op::GetAssertion { .. }
            | Op::DeleteAssertion { .. }
            | Op::ListAssertions { .. }
            | Op::GetChain { .. }
            | Op::CompactChain { .. }
            | Op::CountersignReceipt { .. }
            | Op::Du { .. } => false,
        }
    }
}

/// The result of a dispatched op, ready to render as an HTTP response.
pub(crate) enum OpOutcome {
    Stored {
        cid: String,
        bytes: u64,
        mode: ReceiptMode,
        receipt_hash: String,
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
        drawdown_download_bytes: u64,
    },
    /// The distinct content addresses (hex SHA-256) a DID has uploaded, in
    /// first-upload order. The atproto layer maps each to a CIDv1 `$link`.
    BlobList {
        cids: Vec<String>,
    },
    /// An assertion was accepted and stored, at sequence `seq`, with the
    /// provider ack (pre-serialized JSON) the customer keeps as proof.
    AssertionSaved {
        seq: u64,
        ack_json: String,
    },
    /// An assertion read-back body — the full `{assertion, ack}` (owner) or a
    /// kind-limited view (e.g. the policy grantee's `{read_class, may_read}`,
    /// Q4). Pre-serialized JSON.
    PolicyBody {
        json: String,
    },
    /// A usage report body: `{objects:[{cid,bytes},…], total_bytes}` (ADR 0003).
    /// Pre-serialized JSON.
    UsageBody {
        json: String,
    },
    /// A chain read (ADR 0005 / A3): `{entries: [...], total}` — the full signed
    /// history and the recomputed, verified total. Pre-serialized JSON.
    ChainBody {
        json: String,
    },
    /// A chain was compacted behind its checkpoint at `behind` (ADR 0005 / A4).
    /// Renders `{compacted_behind: seq}` at 200.
    ChainCompacted {
        behind: u64,
    },
    /// An assertion was erased (ADR 0005 / A2). Renders `{erased: true}` at 200.
    AssertionErased,
    /// The subkeys a DID holds for a listable kind (ADR 0005 / A2). Renders
    /// `{subkeys: [...]}` at 200 — the owner's own keys, never a cross-DID view.
    AssertionSubkeys {
        subkeys: Vec<String>,
    },
}

/// Authenticate a request into a [`Principal`]. **Non-rejecting**: a missing or
/// invalid session yields [`Principal::Anonymous`]; whether that is allowed is an
/// authorization decision made at dispatch (401 vs 403), never inferred from the
/// mere presence of a credential (ADR 0001).
///
/// The caller presents `x-croft-pubkey` (its public key) and `x-croft-session`
/// (a signature over `ciss-session/v1/<did>`). The acting DID is the id the key
/// derives, so a caller can only ever authenticate as the DID it holds the key
/// for — naming a victim DID without its key cannot produce a valid session.
pub(crate) fn authenticate(headers: &HeaderMap) -> Principal {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let (Some(pubkey_hex), Some(sig_hex)) = (header(PUBKEY_HEADER), header(SESSION_HEADER)) else {
        return Principal::Anonymous;
    };
    let Ok(key) = public_key_from_hex(pubkey_hex) else {
        return Principal::Anonymous;
    };
    let did = derive_id(&key);
    let challenge = format!("{SESSION_CHALLENGE_PREFIX}{did}");
    ciss_auth::verify_session(&did, pubkey_hex, challenge.as_bytes(), sig_hex)
        .unwrap_or(Principal::Anonymous)
}

/// Authenticate an atproto-plane request into a [`Principal`], **non-rejecting**
/// (an invalid credential yields [`Principal::Anonymous`], never the DID it named).
///
/// Two mechanisms, selected by header:
/// - `Authorization: Bearer <service-auth jwt>` → Model R: resolve the `iss` DID,
///   verify the JWT (sig + `aud`==this service + `lxm`==`lxm` + `exp`), replay-check.
/// - `x-croft-*` → the interim `id:` signed session (unchanged).
pub(crate) async fn authenticate_atproto(state: &AppState, headers: &HeaderMap, lxm: &str) -> Principal {
    if let Some(jwt) = bearer_token(headers) {
        return verify_service_auth(state, jwt, lxm).await;
    }
    authenticate(headers)
}

/// The `Authorization: Bearer <token>` value, if present.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Verify a service-auth JWT (Model R). Returns [`Principal::Anonymous`] on any
/// failure — never a fall-through to the DID the token named.
///
/// Auth-impacting decisions are logged: a **grant** at DEBUG (the DID + method
/// authorized), a **denied attempt** at INFO with the reason (visible in
/// production without debug), so an operator can see who was let in and why an
/// attempt failed. Tokens and keys are never logged — only DIDs (public), the
/// method, and the reason.
async fn verify_service_auth(state: &AppState, jwt: &str, lxm: &str) -> Principal {
    verify_service_auth_full(state, jwt, lxm).await.0
}

/// As [`verify_service_auth`], but also returns the verified token's `jti` on
/// success — for callers that record which single-use token authorized an action
/// (Model C provider attestation). Returns `(Principal::Anonymous, None)` on any
/// failure.
async fn verify_service_auth_full(
    state: &AppState,
    jwt: &str,
    lxm: &str,
) -> (Principal, Option<String>) {
    let Ok(iss) = ciss_auth::peek_iss(jwt) else {
        tracing::info!(lxm, reason = "malformed token", "service-auth denied");
        return (Principal::Anonymous, None);
    };
    // The `iss` must be an atproto `did:*`, never an internal `id:` (Phase 1
    // space typing): the atproto plane cannot assert a native identifier.
    let Ok(did) = Did::parse(&iss) else {
        tracing::info!(%iss, lxm, reason = "malformed iss", "service-auth denied");
        return (Principal::Anonymous, None);
    };
    if did.require_atproto().is_err() {
        tracing::info!(%iss, lxm, reason = "iss not an atproto did", "service-auth denied");
        return (Principal::Anonymous, None);
    }
    let now = now_unix_s();
    let params = ServiceAuthParams {
        expected_iss: &iss,
        expected_aud: &state.service_did,
        expected_lxm: lxm,
        now_unix_s: now,
    };
    // Resolve, verify; on a signature mismatch retry once with a force-refreshed
    // key (survives a key rotation between cache-fill and now).
    let Ok(keys) = state.resolver.resolve(&iss, false).await else {
        tracing::info!(%iss, lxm, reason = "did resolution failed", "service-auth denied");
        return (Principal::Anonymous, None);
    };
    let verified = match ciss_auth::verify_service_auth_jwt(jwt, &keys, &params) {
        Ok(v) => v,
        Err(ciss_auth::JwtError::SignatureInvalid) => {
            let Ok(fresh) = state.resolver.resolve(&iss, true).await else {
                tracing::info!(%iss, lxm, reason = "did resolution failed", "service-auth denied");
                return (Principal::Anonymous, None);
            };
            match ciss_auth::verify_service_auth_jwt(jwt, &fresh, &params) {
                Ok(v) => v,
                Err(reason) => {
                    tracing::info!(%iss, lxm, %reason, "service-auth denied");
                    return (Principal::Anonymous, None);
                }
            }
        }
        Err(reason) => {
            tracing::info!(%iss, lxm, %reason, "service-auth denied");
            return (Principal::Anonymous, None);
        }
    };
    // Replay defense: a token carrying a `jti` is single-use within its window.
    if let Some(jti) = &verified.jti {
        if state
            .replay
            .check_and_record(jti, verified.exp_unix_s, now)
            .is_err()
        {
            tracing::info!(%iss, lxm, reason = "replayed jti", "service-auth denied");
            return (Principal::Anonymous, None);
        }
    }
    // Grant: this DID is authorized for this method (the auth-impacting decision).
    tracing::debug!(did = %verified.did, lxm, aud = %state.service_did, "service-auth granted");
    let jti = verified.jti.clone();
    (verified.principal(), jti)
}

/// The current time in unix seconds (for JWT `exp`).
fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// This service's atproto DID (the `aud` a service-auth JWT must name) — from
/// `CISS_SERVICE_DID`, else the deployed default.
fn default_service_did() -> String {
    std::env::var("CISS_SERVICE_DID").unwrap_or_else(|_| "did:web:ciss.croft.ing".to_owned())
}

/// `GET /.well-known/did.json` — CISS's did:web document, so external atproto
/// clients can resolve the configured service DID and address it as a service-auth
/// `aud`. Public, cheap, side-effect-free (sits beside `/healthz`); reflects the
/// configured `service_did`. `SEAM:` publishing CISS's provider key here (so
/// receipts are externally verifiable via the DID) is a tracked follow-on.
async fn well_known_did_handler(State(state): State<AppState>) -> Response {
    let did = state.service_did.as_ref();
    let service_endpoint = did
        .strip_prefix("did:web:")
        .map(|host| format!("https://{host}"))
        .unwrap_or_default();
    let doc = serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        // The attestation key: what Model-C records and every assertion ACK
        // verify against — published so a customer can prove, offline, that
        // an assertion took effect (D2).
        "verificationMethod": [{
            "id": format!("{did}#assertion-ack"),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyHex": state.provider.attest_verifying_key_hex(),
        }, {
            // The receipt/billing key: what unilateral receipts and the
            // provider half of bilateral receipts verify under (D4).
            "id": format!("{did}#receipts"),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyHex": state.provider.public_key_hex(),
        }],
        "service": [{
            "id": "#ciss_storage",
            "type": "CissItemStorage",
            "serviceEndpoint": service_endpoint,
        }],
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        doc.to_string(),
    )
        .into_response()
}

/// The authorization server whose grants this resource server points clients
/// at (RFC 9728 `authorization_servers`). Under the piggyback-bsky model
/// (ADR 0001) bsky is the AS for the accounts CISS serves; CISS issues
/// nothing. A self-hosted-PDS caller has a different AS — widening this to a
/// configured list is part of E101's token-verification half, not the pointer.
const OAUTH_AUTHORIZATION_SERVER: &str = "https://bsky.social";

/// `GET /.well-known/oauth-protected-resource` — RFC 9728 resource-server
/// discovery: names this resource and who issues tokens for it. The **pointer
/// half** of the OAuth-RS surface (`ROADMAP_TODO` E101): it makes CISS
/// discoverable to atproto-OAuth clients; *accepting* their DPoP-bound tokens
/// is E101's other half and remains parked — until it lands, the only
/// accepted credentials stay `id:` sessions and service-auth JWTs.
async fn oauth_protected_resource_handler(State(state): State<AppState>) -> Response {
    let resource = state
        .service_did
        .strip_prefix("did:web:")
        .map(|host| format!("https://{host}"))
        .unwrap_or_default();
    let doc = serde_json::json!({
        "resource": resource,
        "authorization_servers": [OAUTH_AUTHORIZATION_SERVER],
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        doc.to_string(),
    )
        .into_response()
}

/// Owner-gated authorization: the principal must be the verified owner of `did`.
/// An anonymous caller is a 401 (authenticate and retry); an authenticated caller
/// who is not the owner is a 403 (no retry will help).
fn require_owner(principal: &Principal, did: &str) -> Result<(), ServerError> {
    match principal.did() {
        None => {
            tracing::info!(resource = %did, reason = "unauthenticated", "owner-authz denied");
            Err(ServerError::Unauthorized)
        }
        Some(owner) if owner == did => {
            // The auth-impacting grant: this DID is authorized for its own namespace.
            tracing::debug!(did = %owner, resource = %did, "owner-authz granted");
            Ok(())
        }
        Some(other) => {
            tracing::info!(actor = %other, resource = %did, reason = "not owner", "owner-authz denied");
            Err(ServerError::Forbidden)
        }
    }
}

/// Authorize an op against the caller's [`Principal`] — the ADR 0001 namespace
/// mode bits, v0: object/blob reads and the (self-signed) manifest are
/// world-readable (PDS-compat), while object writes and the billing meter are
/// owner-only. `SEAM:` per-namespace mode bits + a grant model land here (gated
/// reads for the history-convergence tier); v0 is the flat PDS-compat default.
fn authorize(principal: &Principal, op: &Op) -> Result<(), ServerError> {
    match op {
        // Owner-only mutation/inspection: the billing meter, and the A2
        // assertion lifecycle (erase, list). DELETE and LIST are gated here,
        // before any existence check, so a non-owner LIST is never an oracle.
        Op::PutObject { did, .. }
        | Op::GetMeter { did }
        | Op::DeleteAssertion { did, .. }
        | Op::ListAssertions { did, .. }
        | Op::GetChain { did, .. }
        | Op::CompactChain { did, .. } => require_owner(principal, did),
        Op::GetObject { .. }
        | Op::PutManifest { .. }
        | Op::GetManifest { .. }
        | Op::ListBlobs { .. }
        // PutAssertion is self-authorizing (the signed record proves owner
        // authority in op_put_assertion, like PutManifest); GetAssertion
        // applies kind-specific visibility inside op_get_assertion. Du checks
        // self-or-admin (ADR 0003) inside op_du. All checked in-handler.
        | Op::PutAssertion { .. }
        | Op::GetAssertion { .. }
        // CountersignReceipt is self-authorizing (the countersignature must
        // verify under the DID's own key, checked in-op).
        | Op::CountersignReceipt { .. }
        | Op::Du { .. } => Ok(()),
    }
}

/// Gate a read op by its target's resolved read policy (gated reads, ADR 0001
/// §2). Runs after the base [`authorize`] in [`dispatch`], where the `Store` is
/// reachable (the pure `authorize` cannot resolve policy). A denied read maps to
/// [`ServerError::NotFound`] — a 404 indistinguishable from "no such object", so a
/// gated object is never an existence oracle. The `world` default (and any object
/// with no policy row, which resolves to `world`) is allowed on the fast path
/// without a log line; only non-`world` decisions are traced.
///
/// Reads are **membership-only**: the policy signature was verified once at write
/// time (Phases 5/6) before the row was stored, and the row is CISS's own SQLite,
/// so there is no per-read signature check on the hot path. A stored row that
/// fails to parse resolves fail-closed (owner-only) inside `resolve_policy`.
///
/// Only `GetObject` is gated here; `ListBlobs` filters per-cid in its own handler
/// (Phase 4). Non-read ops return `Ok(())` unchanged.
fn authorize_read(state: &AppState, principal: &Principal, op: &Op) -> Result<(), ServerError> {
    let Op::GetObject { did, cid } = op else {
        return Ok(());
    };
    let resolved = lock_store(&state.store).resolve_policy(did, Some(cid))?;
    if resolved.read_class() == ReadClass::World {
        return Ok(());
    }
    let caller = principal.did();
    if resolved.allows(caller, did) {
        tracing::debug!(
            resource = %did, %cid, read_class = ?resolved.read_class(),
            "gated-read granted"
        );
        Ok(())
    } else {
        tracing::info!(
            resource = %did, %cid, actor = ?caller, reason = "not a grantee",
            "gated-read denied"
        );
        Err(ServerError::NotFound)
    }
}

/// The single dispatch boundary. Every handler routes through here so the E83
/// per-DID scope wrapper has one attach point, and so authorization has a single
/// choke point (ADR 0001).
pub(crate) fn dispatch(
    state: &AppState,
    principal: &Principal,
    op: Op,
) -> Result<OpOutcome, ServerError> {
    authorize(principal, &op)?;
    authorize_read(state, principal, &op)?;
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
        Op::ListBlobs { did } => op_list_blobs(state, principal, &did),
        Op::PutAssertion {
            did,
            kind,
            subkey,
            body,
            authed,
        } => op_put_assertion(state, &did, &kind, subkey.as_deref(), &body, authed.as_ref()),
        Op::GetAssertion { did, kind, subkey } => {
            op_get_assertion(state, principal, &did, &kind, subkey.as_deref())
        }
        Op::DeleteAssertion { did, kind, subkey } => {
            op_delete_assertion(state, &did, &kind, subkey.as_deref())
        }
        Op::ListAssertions { did, kind } => op_list_assertions(state, &did, &kind),
        Op::GetChain { did, kind, subkey } => op_get_chain(state, &did, &kind, subkey.as_deref()),
        Op::CompactChain { did, kind, subkey } => op_compact_chain(state, &did, &kind, subkey.as_deref()),
        Op::CountersignReceipt { did, content_hash, sig } => {
            op_countersign_receipt(state, &did, &content_hash, &sig)
        }
        Op::Du { did } => op_du(state, principal, &did),
    }
}

/// Dispatch an op off the async runtime. Every op does synchronous filesystem
/// and SQLite work under a mutex; running that directly in an `async fn` would
/// park a tokio worker (a slow disk, a deep ledger, or contention could then
/// stall the whole server, including `/healthz` — finding V2). `spawn_blocking`
/// moves it onto the blocking pool so the async workers stay free. The handlers
/// call this, not [`dispatch`] directly.
pub(crate) async fn dispatch_blocking(
    state: &AppState,
    principal: Principal,
    op: Op,
) -> Result<OpOutcome, ServerError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || dispatch(&state, &principal, op))
        .await
        .map_err(|_| ServerError::TaskJoin)?
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
    tracing::debug!(%did, object_key = ?key, %cid, "object key -> content address");

    // Storage quota (V5): a *new* (non-dedup) store consumes disk, so it is gated
    // before writing; a dedup store adds no disk and is always allowed. The
    // whole-store ceiling is always enforced; the per-DID cap only if configured.
    // D3 gates, comparison-before-serving. Drawdown closes the books to new
    // blobs entirely; the spend ceiling refuses a billable write that would
    // take the period's postage past the customer's asserted cap (marginal
    // rules mirror the client twin: 0¢-marginal never blocked, exactly-at-X
    // passes). Reads never pass through here — B6.
    {
        let store = lock_store(&state.store);
        if store.account_mode(did)? == AccountMode::Drawdown {
            return Err(ServerError::DrawdownActive);
        }
        if let Some(ceiling_cents) = store.spend_dial(did)? {
            let baseline = store.period_baseline(did)?;
            let period_bytes =
                store.running_totals(did)?.total_bytes().saturating_sub(baseline);
            let spent_cents = crate::pricing::postage_cents(period_bytes);
            let needed_cents =
                crate::pricing::postage_cents(period_bytes.saturating_add(as_u64(boundary)));
            if needed_cents > ceiling_cents && needed_cents > spent_cents {
                return Err(ServerError::SpendCeiling {
                    needed_cents,
                    spent_cents,
                    ceiling_cents,
                });
            }
        }
    }

    let is_new_store = !state.blobs.has(did, &cid);
    if is_new_store {
        let size = as_u64(boundary);
        let (store_used, did_stored) = {
            let store = lock_store(&state.store);
            (store.store_usage()?, store.did_stored_bytes(did)?)
        };
        if store_used.saturating_add(size) > state.limits.store_ceiling {
            tracing::warn!(%did, store_used, ceiling = state.limits.store_ceiling, "store at capacity");
            return Err(ServerError::StoreFull);
        }
        // The effective per-DID cap is min(provider cap, the customer's own
        // at-rest dial) — the provider's protects the box, the customer's
        // protects themselves; neither loosens the other (D2).
        let dial_cap = {
            let store = lock_store(&state.store);
            store.at_rest_dial(did)?
        };
        let effective = match (state.limits.did_cap, dial_cap) {
            (Some(p), Some(d)) => Some(p.min(d)),
            (Some(p), None) => Some(p),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        if let Some(cap) = effective {
            if did_stored.saturating_add(size) > cap {
                tracing::warn!(%did, did_stored, cap, "did storage quota exceeded");
                return Err(ServerError::DidQuotaExceeded);
            }
        }
    }

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
    let totals = store.running_totals(did)?;
    let total = usize::try_from(totals.total_bytes()).expect("byte total fits usize") + boundary;

    // Upload: customer -> provider. receiver = provider, sender = customer.
    // The receipt carries the account mode in effect at transfer time
    // (drawdown legibility, B6) — signed into the core, so the drain
    // classification is an attested fact, not an annotation.
    let core = ReceiptCore::new(
        Direction::Upload,
        &cid,
        (0, boundary),
        total,
        state.day,
        store.account_mode(did)?,
        &state.provider.id,
        did,
    );
    let mode = boundary_receipt_mode(&store, did, boundary)?;
    let receipt = build_boundary_receipt(state, core, mode);
    // A new store adds to the DID's distinct bytes at rest; a dedup store does not.
    if is_new_store {
        store.add_stored_bytes(did, as_u64(boundary))?;
    }
    store.append_receipt(did, &receipt)?;
    tracing::info!(
        %did, %cid, receipt = receipt.content_hash(), mode = ?receipt.mode(),
        running_total = total, ledger_index = totals.receipt_count,
        "upload receipt recorded"
    );

    Ok(OpOutcome::Stored {
        cid,
        bytes: as_u64(boundary),
        mode: receipt.mode(),
        receipt_hash: receipt.content_hash().to_owned(),
    })
}

fn op_get_object(state: &AppState, did: &str, cid: &str) -> Result<OpOutcome, ServerError> {
    let data = state.blobs.get(did, cid).map_err(|e| match e {
        BlobError::Missing { .. } => ServerError::NotFound,
        BlobError::TooLarge { size, max, .. } => ServerError::ObjectTooLarge { size, max },
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
    let totals = store.running_totals(did)?;
    let total = usize::try_from(totals.total_bytes()).expect("byte total fits usize") + boundary;

    // Download: provider -> customer. receiver = customer, sender = provider.
    // In drawdown this is the drain: served (B6), fully metered, and the
    // mode tag makes it separable for the statement-time billing judgment.
    let core = ReceiptCore::new(
        Direction::Download,
        cid,
        (0, boundary),
        total,
        state.day,
        store.account_mode(did)?,
        did,
        &state.provider.id,
    );
    let mode = boundary_receipt_mode(&store, did, boundary)?;
    let receipt = build_boundary_receipt(state, core, mode);
    store.append_receipt(did, &receipt)?;
    tracing::info!(
        %did, %cid, receipt = receipt.content_hash(), mode = ?receipt.mode(),
        running_total = total, ledger_index = totals.receipt_count,
        "download receipt recorded"
    );

    Ok(OpOutcome::Bytes {
        cid: cid.to_owned(),
        data,
    })
}

/// Build the boundary receipt for a transfer. `Unilateral` is the
/// provider-signed default; `Bilateral` (customer-asserted via the
/// receipt-mode dial, D4) produces a provider-signed receipt **awaiting the
/// customer's countersignature** — the walkaway-tolerant partial the receipt
/// model already carries; `POST …/countersign` completes it.
///
/// (Historical `SEAM:` note — `Bilateral` used to be a `501`; the dial +
/// the Phase-8 auth handshake / a later client-signing spike. Until then a
/// policy that selects `Bilateral` is a loud error, never a silent downgrade to
/// unilateral.
/// Resolve the receipt mode for a boundary transfer: the customer's
/// receipt-mode dial sets the default (D4), then the per-transfer policy
/// seam (`select_mode`) has the last word.
fn boundary_receipt_mode(
    store: &crate::persist::Store,
    did: &str,
    boundary: usize,
) -> Result<ReceiptMode, ServerError> {
    let default_mode = match store.receipt_mode_dial(did)? {
        ReceiptModeChoice::Bilateral => ReceiptMode::Bilateral,
        ReceiptModeChoice::Unilateral => ReceiptMode::Unilateral,
    };
    Ok(select_mode(
        &TransferContext {
            bytes: boundary,
            trust_distance: None,
        },
        default_mode,
    ))
}

fn build_boundary_receipt(
    state: &AppState,
    core: ReceiptCore,
    mode: ReceiptMode,
) -> Receipt {
    match mode {
        ReceiptMode::Unilateral => {
            make_unilateral_receipt(core, &state.provider.id, &state.provider.keypair)
        }
        ReceiptMode::Bilateral => {
            // Provider-signed, awaiting the customer countersign (a partial
            // bilateral — the walkaway-tolerant shape the model carries).
            let content_hash = core.content_hash();
            let mut sigs = std::collections::BTreeMap::new();
            sigs.insert(
                state.provider.id.clone(),
                state.provider.keypair.sign_message(&content_hash),
            );
            Receipt::from_parts(core, content_hash, ReceiptMode::Bilateral, sigs)
        }
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

    // Replay/rollback protection (I5): a stored manifest may only be replaced by a
    // strictly-newer one. Load + compare + save under one lock so the check is
    // atomic against a concurrent writer.
    let store = lock_store(&state.store);
    // Drawdown: the keep-set may only shrink (draining reduces rent on the
    // way out); growth re-opens the books, which only a mode dial may do.
    if store.account_mode(did)? == AccountMode::Drawdown {
        let existing_total = store.load_manifest(did)?.map_or(0, |m| m.total_bytes());
        if manifest.total_bytes() > existing_total {
            return Err(ServerError::DrawdownActive);
        }
    }
    if let Some(existing) = store.load_manifest(did)? {
        if manifest.seq() <= existing.seq() {
            // The uniform typed staleness (D1.4): the manifest conforms to
            // the substrate's refusal — a 409 the client detects by status,
            // not by matching English (the M3 text-match wart, healed).
            return Err(ServerError::AssertionStale {
                kind: "manifest".to_owned(),
                attempted: manifest.seq(),
            });
        }
    }
    store.save_manifest(did, &manifest)?;
    tracing::info!(%did, root = manifest.root(), seq = manifest.seq(), total_bytes = manifest.total_bytes(), "manifest stored");
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
    // Read the O(1) cached totals rather than re-summing the whole ledger (V3).
    let totals = lock_store(&state.store).running_totals(did)?;
    Ok(OpOutcome::Meter {
        receipt_count: totals.receipt_count,
        upload_bytes: totals.upload_bytes,
        download_bytes: totals.download_bytes,
        running_total_bytes: totals.total_bytes(),
        postage_cents: postage_cents(totals.total_bytes()),
        drawdown_download_bytes: totals.drawdown_download_bytes,
    })
}

/// The distinct content addresses a DID has uploaded, in first-upload order.
/// The ledger's upload receipts are the source of truth for "which blobs this
/// DID stored" — no backend enumeration primitive is required.
fn op_list_blobs(
    state: &AppState,
    principal: &Principal,
    did: &str,
) -> Result<OpOutcome, ServerError> {
    let store = lock_store(&state.store);
    let receipts = store.load_receipts(did)?;

    // The distinct uploaded cids, in first-upload order (the ledger is the source
    // of truth for "which blobs this DID stored").
    let mut distinct: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for receipt in &receipts {
        if receipt.core().direction == Direction::Upload {
            let cid = &receipt.core().cid;
            if seen.insert(cid.clone()) {
                distinct.push(cid.clone());
            }
        }
    }

    // Fast path: a fully-ungated DID (no namespace policy, no object policy) needs
    // no per-cid checks — every uploaded cid is world-readable (PDS-compat).
    let namespace = store.resolve_policy(did, None)?;
    if namespace.read_class() == ReadClass::World && !store.has_object_policies(did)? {
        return Ok(OpOutcome::BlobList { cids: distinct });
    }

    // Gated DID: resolve the namespace once, then one object lookup per cid, and
    // keep only the cids this caller may read. A hidden cid is neither listed nor
    // counted — omission, not a 403, so `listBlobs` is not an enumeration oracle.
    let caller = principal.did();
    let mut cids: Vec<String> = Vec::new();
    let mut hidden = 0usize;
    for cid in distinct {
        let resolved = match store.resolve_object_policy(did, &cid)? {
            Some(object) => object,
            None => namespace.clone(),
        };
        if resolved.allows(caller, did) {
            cids.push(cid);
        } else {
            hidden += 1;
        }
    }
    tracing::debug!(%did, shown = cids.len(), hidden, "listBlobs filtered");
    Ok(OpOutcome::BlobList { cids })
}

/// Usage report for `did` (ADR 0003, invariant Z9): per-object sizes (upload bytes
/// summed per distinct cid, in first-upload order) + total. Reads the maintained
/// receipt ledger — no filesystem walk.
///
/// Authorization (ADR 0003 / invariant Z9): **self-only** — the caller may report
/// on its **own** namespace. Cross-DID / store-wide usage is **never** exposed over
/// the wire (an operator uses the on-box `ciss usage` report). A non-owner —
/// including an anonymous caller — is refused `403`, with a response that does not
/// vary by whether `did` exists (no existence oracle).
fn op_du(state: &AppState, principal: &Principal, did: &str) -> Result<OpOutcome, ServerError> {
    let caller = principal.did();
    // Self-only, always: cross-DID usage is never exposed over the wire.
    if caller != Some(did) {
        tracing::info!(resource = %did, actor = ?caller, reason = "not owner", "du denied");
        return Err(ServerError::Forbidden);
    }
    // Lockdown (CISS_ADMIN_ONLY_DU): when set, only an admin-pin DID may run `du`
    // at all — still only for its own namespace (checked above).
    if state.admin_only_du && !caller.is_some_and(|c| state.admin_dids.contains(c)) {
        tracing::info!(resource = %did, reason = "du locked to admins", "du denied");
        return Err(ServerError::Forbidden);
    }

    let store = lock_store(&state.store);
    let receipts = store.load_receipts(did)?;
    let mut order: Vec<String> = Vec::new();
    let mut sizes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for receipt in &receipts {
        if receipt.core().direction == Direction::Upload {
            let cid = &receipt.core().cid;
            let bytes = receipt.core().bytes as u64;
            if let Some(v) = sizes.get_mut(cid) {
                *v += bytes;
            } else {
                order.push(cid.clone());
                sizes.insert(cid.clone(), bytes);
            }
        }
    }
    let objects: Vec<serde_json::Value> = order
        .iter()
        .map(|cid| serde_json::json!({ "cid": cid, "bytes": sizes[cid] }))
        .collect();
    let total: u64 = sizes.values().sum();
    let json = serde_json::json!({ "objects": objects, "total_bytes": total }).to_string();
    Ok(OpOutcome::UsageBody { json })
}

/// The kind registry: parse + structurally validate a kind's body and
/// return its canonical fold. The substrate binds did/kind/subkey/seq; the
/// fold binds everything kind-specific. An unknown kind is refused — kinds
/// are code, not data.
fn kind_fold(
    kind: &str,
    subkey: Option<&str>,
    body: &serde_json::Value,
) -> Result<String, ServerError> {
    match kind {
        POLICY_KIND => {
            // A per-object policy's subkey must be a well-formed content
            // address (the old `obj:` target validation, structurally).
            if let Some(sk) = subkey {
                ContentAddr::parse(sk)
                    .map_err(|_| ServerError::BadAssertion("policy subkey is not a content address"))?;
            }
            let body: PolicyBody = serde_json::from_value(body.clone())
                .map_err(|_| ServerError::BadAssertion("body is not a valid policy body"))?;
            if !policy_body_valid(&body) {
                return Err(ServerError::BadAssertion("policy readers do not fit the read class"));
            }
            Ok(policy_body_fold(&body))
        }
        CEILING_DIAL_KIND => {
            if subkey.is_some() {
                return Err(ServerError::BadAssertion("the ceiling dial takes no subkey"));
            }
            let body: CeilingDialBody = serde_json::from_value(body.clone())
                .map_err(|_| ServerError::BadAssertion("body is not a valid ceiling dial"))?;
            Ok(ceiling_body_fold(&body))
        }
        PERIOD_DIAL_KIND => {
            if subkey.is_some() {
                return Err(ServerError::BadAssertion("the period dial takes no subkey"));
            }
            if body.as_object().is_none_or(|o| !o.is_empty()) {
                return Err(ServerError::BadAssertion("the period dial body is empty ({})"));
            }
            Ok(PERIOD_BODY_FOLD.to_owned())
        }
        ACCOUNT_MODE_DIAL_KIND => {
            if subkey.is_some() {
                return Err(ServerError::BadAssertion("the account-mode dial takes no subkey"));
            }
            let body: AccountModeBody = serde_json::from_value(body.clone())
                .map_err(|_| ServerError::BadAssertion("body is not a valid account-mode dial"))?;
            Ok(account_mode_body_fold(&body))
        }
        RECEIPT_MODE_DIAL_KIND => {
            if subkey.is_some() {
                return Err(ServerError::BadAssertion("the receipt-mode dial takes no subkey"));
            }
            let body: ReceiptModeBody = serde_json::from_value(body.clone())
                .map_err(|_| ServerError::BadAssertion("body is not a valid receipt-mode dial"))?;
            Ok(receipt_mode_body_fold(&body))
        }
        crate::kv::FLAG_KIND => {
            if !crate::kv::subkey_valid(subkey) {
                return Err(ServerError::BadAssertion("kv kinds require a valid subkey"));
            }
            let body: crate::kv::FlagBody = serde_json::from_value(body.clone())
                .map_err(|_| ServerError::BadAssertion("body is not a valid kv flag"))?;
            Ok(crate::kv::flag_body_fold(&body))
        }
        crate::chain_kind::CHAIN_COUNTER_KIND => {
            // A chain totals a per-subkey account, so a subkey is required (the
            // same discipline as the kv kinds). The body is either a step or a
            // checkpoint (ADR 0005 / A4); the fold differs so the two can never be
            // confused.
            if !crate::kv::subkey_valid(subkey) {
                return Err(ServerError::BadAssertion("chain.counter requires a valid subkey"));
            }
            let step: crate::chain_kind::ChainStep = serde_json::from_value(body.clone())
                .map_err(|_| ServerError::BadAssertion("body is not a valid chain.counter entry"))?;
            Ok(step.fold())
        }
        _ => Err(ServerError::BadAssertion("unknown assertion kind")),
    }
}

/// The effective provider bound a customer's at-rest dial may not exceed:
/// `min(store_ceiling, did_cap-if-set)`. Provider limits supersede — a dial
/// above this is refused at set (no point storing an unreachable number),
/// and enforcement applies `min()` regardless (provider caps can change
/// after a dial was accepted).
fn provider_at_rest_bound(limits: &Limits) -> u64 {
    limits.did_cap.map_or(limits.store_ceiling, |cap| cap.min(limits.store_ceiling))
}

/// Store a customer assertion (Model A: a full self-signed record; Model C:
/// a JWT-authorized intent CISS attests). The record must name the routed
/// target, its body must satisfy its kind, its `seq` must advance the stored
/// record's, and its authorization must verify — each failure a distinct
/// status. Verified records are persisted with the provider ack; reads honor
/// them immediately via the dispatch gate.
fn op_put_assertion(
    state: &AppState,
    did: &str,
    kind: &str,
    subkey: Option<&str>,
    body: &[u8],
    authed: Option<&AuthedWrite>,
) -> Result<OpOutcome, ServerError> {
    /// The Model-C wire body: the JWT authorizes the *action*; CISS builds
    /// and attests the record from these fields.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Intent {
        seq: u64,
        body: serde_json::Value,
    }
    let record = if let Some(auth) = authed {
        // Model C: the JWT authenticated the owner; the body is an intent
        // `{seq, body}`; CISS builds and attests the record.
        if auth.did != did {
            tracing::info!(
                actor = %auth.did, resource = %did, reason = "did != target",
                "assertion-put denied"
            );
            return Err(ServerError::AssertionUnauthorized);
        }
        let intent: Intent = serde_json::from_slice(body)
            .map_err(|_| ServerError::BadAssertion("body is not a valid assertion intent"))?;
        let fold = kind_fold(kind, subkey, &intent.body)?;
        SignedAssertion::attest_provider(
            kind,
            did,
            subkey,
            intent.seq,
            intent.body,
            &fold,
            auth.jti.as_deref().unwrap_or(""),
            &state.provider.attest_keypair,
        )
    } else {
        // Model A: an `id:` owner submitted a full self-signed record.
        let record: SignedAssertion = serde_json::from_slice(body)
            .map_err(|_| ServerError::BadAssertion("body is not a valid signed assertion"))?;
        if record.did != did || record.kind != kind || record.subkey.as_deref() != subkey {
            return Err(ServerError::BadAssertion("assertion target does not match the route"));
        }
        record
    };

    let fold = kind_fold(kind, subkey, &record.body)?;

    // Body ceiling (ADR 0005, the sizing axis): every kind declares a
    // body-byte ceiling; a body above it is refused at the boundary with the
    // limit quoted. An independent bound from the kind's count guards (e.g.
    // policy's MAX_READERS) — a reader set can be valid by count and oversized
    // by bytes. kind_fold above already refused unknown kinds, so the spec
    // lookup succeeds for every kind that reaches here.
    if let Some(spec) = crate::kind_spec::kind_spec(kind) {
        let bytes = serde_json::to_vec(&record.body).map_or(usize::MAX, |v| v.len());
        let ceiling = spec.sizing.body_ceiling;
        if bytes > ceiling {
            return Err(ServerError::BodyAboveCeiling { kind: kind.to_owned(), bytes, ceiling });
        }
    }

    // Kind-specific set-time enforcement: the ceiling dial cannot assert
    // above the provider's effective bound (user ruling: provider limits
    // supersede). The refusal quotes the real bound so the customer can act.
    if kind == CEILING_DIAL_KIND {
        if let Ok(body) = serde_json::from_value::<CeilingDialBody>(record.body.clone()) {
            if let Some(asserted) = body.at_rest_bytes {
                let bound = provider_at_rest_bound(&state.limits);
                if asserted > bound {
                    return Err(ServerError::AssertionAboveBound { asserted, bound });
                }
            }
        }
    }

    let store = lock_store(&state.store);
    let prior_seq = store.assertion_seq(did, kind, subkey)?;

    // Anti-rollback at verify time: a replayed/equal/lower seq is refused
    // with the uniform typed staleness, named before the signature check.
    if let Some(prior) = prior_seq {
        if record.seq <= prior {
            tracing::info!(
                resource = %did, kind, subkey = ?subkey, seq = record.seq, prior,
                reason = "lower seq", "assertion-put denied"
            );
            return Err(ServerError::AssertionStale { kind: kind.to_owned(), attempted: record.seq });
        }
    }

    // Authorization + structural validation (seq was checked above, so None).
    if !record.verify(&fold, None, &state.provider.attest_verifying_key()) {
        tracing::info!(
            resource = %did, kind, subkey = ?subkey, reason = "unauthorized assertion",
            "assertion-put denied"
        );
        return Err(ServerError::AssertionUnauthorized);
    }

    // The provider acknowledgment: the countersignature that lets the
    // customer prove — not merely hope — that the assertion took effect.
    let ack = make_ack(&record, &state.provider.attest_keypair)?;

    // Chain kinds (ADR 0005 / A3) append verified history rather than upsert a
    // latest value. The signature and seq anti-rollback above already hold; the
    // entry must also *follow* the chain, checked in the helper.
    if crate::kind_spec::kind_spec(kind)
        .is_some_and(|s| s.retention == crate::kind_spec::Retention::Chain)
    {
        return append_verified_chain_entry(&store, state.compaction, did, kind, subkey, &record, &ack);
    }

    store.save_assertion(&record, &ack)?;

    // Accepting a period dial snapshots the meter's cumulative total as the
    // new period's baseline — a monotonic byte-count marker (never a clock);
    // the dial's own seq is the period ordinal.
    if kind == PERIOD_DIAL_KIND {
        let baseline = store.running_totals(did)?.total_bytes();
        store.put_meta(&format!("period_baseline:{did}"), &baseline.to_string())?;
        tracing::info!(%did, baseline, period = record.seq, "spend period started");
    }
    tracing::debug!(
        resource = %did, kind, subkey = ?subkey, seq = record.seq, "assertion stored"
    );
    Ok(OpOutcome::AssertionSaved {
        seq: record.seq,
        ack_json: serde_json::to_string(&ack)?,
    })
}

/// Append a verified `chain.counter` entry (ADR 0005 / A3). The entry must
/// continue the stored chain — its total follows `prev.total + delta`, its seq is
/// contiguous, and it links the current head's hash — or it is refused with the
/// real values quoted. Extracted from [`op_put_assertion`], which has already
/// verified the signature and the seq anti-rollback before calling here.
fn append_verified_chain_entry(
    store: &Store,
    compaction: CompactionPolicy,
    did: &str,
    kind: &str,
    subkey: Option<&str>,
    record: &SignedAssertion,
    ack: &crate::assertion::Ack,
) -> Result<OpOutcome, ServerError> {
    use crate::chain_kind::{
        checkpoint_hash, entry_hash, verify_checkpoint, verify_step, ChainStep, GENESIS_PREV_HASH,
    };
    let step: ChainStep = serde_json::from_value(record.body.clone())
        .map_err(|_| ServerError::BadAssertion("body is not a valid chain.counter entry"))?;
    match step {
        ChainStep::Step(body) => {
            let prev = store.latest_chain_entry(did, kind, subkey)?;
            verify_step(prev.as_ref(), &body, record.seq)
                .map_err(|brk| ServerError::ChainBroken(brk.reason()))?;
            let hash = entry_hash(did, kind, subkey, record.seq, &body);
            store.append_chain_entry(record, ack, &body, &hash)?;
        }
        ChainStep::Checkpoint(body) => {
            // A checkpoint closes over a real predecessor; an empty chain has
            // nothing to close.
            let prev = store.latest_chain_entry(did, kind, subkey)?.ok_or_else(|| {
                ServerError::ChainBroken("a checkpoint needs a chain to close (none exists)".to_owned())
            })?;
            let expected_prev = store
                .latest_checkpoint_hash(did, kind, subkey)?
                .unwrap_or_else(|| GENESIS_PREV_HASH.to_owned());
            verify_checkpoint(&prev, &expected_prev, &body, record.seq)
                .map_err(|brk| ServerError::ChainBroken(brk.reason()))?;
            let hash = checkpoint_hash(did, kind, subkey, record.seq, &body);
            store.append_checkpoint_entry(record, ack, &body, &hash)?;
            // On-ack compaction (the default / starting case): the checkpoint's
            // provider ack is the agreement, so entries behind it may be shredded
            // now. Deferred policy leaves this to an explicit billing-marker call.
            if compaction == CompactionPolicy::OnAck {
                let compacted = store.compact_behind_latest_checkpoint(did, kind, subkey)?;
                tracing::debug!(
                    resource = %did, kind, subkey = ?subkey, behind = ?compacted,
                    "chain compacted on checkpoint ack"
                );
            }
        }
    }
    tracing::debug!(resource = %did, kind, subkey = ?subkey, seq = record.seq, "chain entry appended");
    Ok(OpOutcome::AssertionSaved { seq: record.seq, ack_json: serde_json::to_string(ack)? })
}

/// Read back a stored assertion + ack, with kind-specific visibility. The
/// `policy` kind keeps its Q4 rule: the owner sees the full signed record;
/// a grantee sees only that it may read (never the reader set); anyone else
/// gets the oracle-free 404. Every other kind is owner-only (a dial is
/// nobody's business but the parties').
fn op_get_assertion(
    state: &AppState,
    principal: &Principal,
    did: &str,
    kind: &str,
    subkey: Option<&str>,
) -> Result<OpOutcome, ServerError> {
    let (record, ack) = lock_store(&state.store)
        .load_assertion(did, kind, subkey)?
        .ok_or(ServerError::NotFound)?;
    let caller = principal.did();

    if caller == Some(did) {
        let full = serde_json::json!({
            "assertion": record,
            "ack": ack,
        });
        return Ok(OpOutcome::PolicyBody { json: full.to_string() });
    }

    if kind == POLICY_KIND {
        // A non-owner sees a policy only if it may read the target, and then
        // only its own access — never the reader set.
        let body = serde_json::from_value::<PolicyBody>(record.body.clone()).ok();
        if let Some(body) = body {
            if ResolvedPolicy::from_body(&body).allows(caller, did) {
                let view = serde_json::json!({
                    "read_class": body.read_class,
                    "may_read": true,
                });
                return Ok(OpOutcome::PolicyBody { json: view.to_string() });
            }
        }
    }
    Err(ServerError::NotFound)
}

/// Erase a stored assertion (ADR 0005 / A2). Allowed only for a kind declaring
/// `Erasable`; a `Permanent` kind is refused with its reason. Owner authority is
/// checked upstream (`require_owner`). A hard delete leaves **no residue** — the
/// row and its seq are gone, so a re-write starts fresh at seq 1 (the pinned
/// post-erase semantics). The erasable kinds are the private-instance kv kinds,
/// whose write boundary is loopback; post-erase replay of an old signed record is
/// out of that threat model (a loopback attacker already holds the tenant key).
fn op_delete_assertion(
    state: &AppState,
    did: &str,
    kind: &str,
    subkey: Option<&str>,
) -> Result<OpOutcome, ServerError> {
    let spec =
        crate::kind_spec::kind_spec(kind).ok_or(ServerError::BadAssertion("unknown assertion kind"))?;
    if spec.erasure == crate::kind_spec::Erasure::Permanent {
        return Err(ServerError::ErasureNotAllowed { kind: kind.to_owned() });
    }
    if lock_store(&state.store).delete_assertion(did, kind, subkey)? {
        Ok(OpOutcome::AssertionErased)
    } else {
        Err(ServerError::NotFound)
    }
}

/// List the subkeys a DID holds for one kind (ADR 0005 / A2). Allowed only for a
/// kind declaring `Listable`; a `PointOnly` kind is refused. Owner-and-self-only
/// is enforced upstream (`require_owner` runs before this op), so the result is
/// always the caller's own keys and a non-owner's refusal is never an existence
/// oracle — it is decided before any row is consulted.
fn op_list_assertions(state: &AppState, did: &str, kind: &str) -> Result<OpOutcome, ServerError> {
    let spec =
        crate::kind_spec::kind_spec(kind).ok_or(ServerError::BadAssertion("unknown assertion kind"))?;
    if spec.enumeration == crate::kind_spec::Enumeration::PointOnly {
        return Err(ServerError::EnumerationNotAllowed { kind: kind.to_owned() });
    }
    let subkeys = lock_store(&state.store).list_assertion_subkeys(did, kind)?;
    Ok(OpOutcome::AssertionSubkeys { subkeys })
}

/// Read a chain's entries and its recomputed, verified total (ADR 0005 / A3 —
/// the `?chain=1` read). Owner-only (checked upstream). Recomputation walks the
/// stored history and re-derives every hash link, so a chain tampered with in the
/// store — not just at write time — is caught here and surfaced, not served as if
/// sound. (A4 will bound the walk to the nearest checkpoint; A3 returns all.)
fn op_get_chain(
    state: &AppState,
    did: &str,
    kind: &str,
    subkey: Option<&str>,
) -> Result<OpOutcome, ServerError> {
    if !crate::kind_spec::kind_spec(kind)
        .is_some_and(|s| s.retention == crate::kind_spec::Retention::Chain)
    {
        return Err(ServerError::BadAssertion("kind does not support a chain read"));
    }
    let entries = lock_store(&state.store).chain_entries(did, kind, subkey)?;
    let chain: Vec<crate::chain_kind::ChainEntry> = entries.iter().map(|(e, _)| e.clone()).collect();
    let total = crate::chain_kind::recompute_total(&chain)
        .map_err(|brk| ServerError::ChainBroken(brk.reason()))?;
    let records: Vec<serde_json::Value> = entries
        .iter()
        .map(|(_, json)| serde_json::from_str(json).unwrap_or(serde_json::Value::Null))
        .collect();
    let json = serde_json::json!({ "entries": records, "total": total }).to_string();
    Ok(OpOutcome::ChainBody { json })
}

/// Compact a chain behind its latest acknowledged checkpoint (ADR 0005 / A4 — the
/// explicit billing-marker path). Owner-only (checked upstream). Refused if the
/// chain has no checkpoint to compact behind — the no-shredding-before-agreement
/// rule, surfaced as a 409. Used directly under the `Deferred` policy, and always
/// available to trigger a compaction at a business boundary.
fn op_compact_chain(
    state: &AppState,
    did: &str,
    kind: &str,
    subkey: Option<&str>,
) -> Result<OpOutcome, ServerError> {
    if !crate::kind_spec::kind_spec(kind)
        .is_some_and(|s| s.retention == crate::kind_spec::Retention::Chain)
    {
        return Err(ServerError::BadAssertion("kind does not support compaction"));
    }
    match lock_store(&state.store).compact_behind_latest_checkpoint(did, kind, subkey)? {
        Some(behind) => Ok(OpOutcome::ChainCompacted { behind }),
        None => Err(ServerError::ChainBroken(
            "no acknowledged checkpoint to compact behind".to_owned(),
        )),
    }
}

/// The customer's countersignature on a bilateral receipt: verify the sig
/// over the content hash under the key deriving the DID (self-authorizing —
/// no session needed beyond the signature itself), then complete the stored
/// receipt. The completed receipt is returned: a doubly-signed fact.
fn op_countersign_receipt(
    state: &AppState,
    did: &str,
    content_hash: &str,
    sig_payload: &str,
) -> Result<OpOutcome, ServerError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Countersign {
        signer: String,
        sig: String,
    }
    let body: Countersign = serde_json::from_str(sig_payload)
        .map_err(|_| ServerError::BadAssertion("body is not a valid countersign"))?;
    let key = public_key_from_hex(&body.signer).map_err(|_| ServerError::BadPubkey)?;
    if derive_id(&key) != did {
        return Err(ServerError::AssertionUnauthorized);
    }
    if !crate::crypto::verify_message(&key, content_hash, &body.sig) {
        tracing::info!(%did, content_hash, "countersign denied: bad signature");
        return Err(ServerError::AssertionUnauthorized);
    }
    let store = lock_store(&state.store);
    let completed = store
        .countersign_receipt(did, content_hash, did, &body.sig)?
        .ok_or(ServerError::NotFound)?;
    tracing::info!(%did, content_hash, "receipt countersigned — doubly-signed");
    Ok(OpOutcome::PolicyBody { json: serde_json::to_string(&completed)? })
}

// ---- HTTP handlers: extract inputs, route through the dispatch boundary. ----

async fn put_object_handler(
    State(state): State<AppState>,
    Path((did, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate(&headers);
    tracing::info!(method = "PUT", did = %did, key = ?key, bytes = body.len(), "object boundary");
    dispatch_blocking(
        &state,
        principal,
        Op::PutObject {
            did: did.into_string(),
            key,
            bytes: body.to_vec(),
        },
    )
    .await
}

async fn get_object_handler(
    State(state): State<AppState>,
    Path((did, addr)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let addr = ContentAddr::parse(&addr)?;
    // Authenticate the reader (an `id:` session) so a grantee is recognized by the
    // gated-read gate; an unauthenticated read is anonymous and sees only world
    // objects. This S3-plane path is `id:`-session only by design; a `did:` grantee
    // reads a gated blob via the atproto `getBlob` surface (which also accepts a
    // service-auth JWT — see `pds_api::get_blob`).
    let principal = authenticate(&headers);
    tracing::info!(method = "GET", did = %did, cid = %addr, "object boundary");
    dispatch_blocking(
        &state,
        principal,
        Op::GetObject {
            did: did.into_string(),
            cid: addr.into_string(),
        },
    )
    .await
}

async fn put_manifest_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let pubkey_hex = headers
        .get(PUBKEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    // The manifest is self-authorizing: op_put_manifest requires the presented
    // key to derive the DID and to have signed the manifest, so it proves owner
    // key-possession without the session header.
    dispatch_blocking(
        &state,
        Principal::Anonymous,
        Op::PutManifest {
            did: did.into_string(),
            pubkey_hex,
            body: body.to_vec(),
        },
    )
    .await
}

async fn get_manifest_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    // The manifest is a signed, world-readable record (PDS-compat).
    dispatch_blocking(&state, Principal::Anonymous, Op::GetManifest { did: did.into_string() }).await
}

/// Resolve the set-policy authorization from the request headers. A `Bearer`
/// service-auth JWT selects **Model C** (a `did:` owner): it is verified here
/// (async — DID resolution) against the `PUT_ASSERTION_LXM` method, yielding the
/// authenticated DID + `jti`. A present-but-invalid JWT is a hard 403. No bearer
/// selects **Model A** (the body carries a self-signed record instead).
async fn assertion_write_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthedWrite>, ServerError> {
    match bearer_token(headers) {
        Some(jwt) => {
            let (principal, jti) = verify_service_auth_full(state, jwt, PUT_ASSERTION_LXM).await;
            match principal.did() {
                Some(did) => Ok(Some(AuthedWrite {
                    did: did.to_owned(),
                    jti,
                })),
                None => Err(ServerError::AssertionUnauthorized),
            }
        }
        None => Ok(None),
    }
}

/// `PUT /{did}/assertion/{kind}` (and `…/{kind}/{subkey}`) — store a
/// customer assertion. Model A: the body is a self-signed
/// [`SignedAssertion`]. Model C: a `Bearer` service-auth JWT authorizes a
/// `did:` owner and the body is an intent `{seq, body}` CISS attests.
async fn put_assertion_handler(
    State(state): State<AppState>,
    Path((did, kind)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let authed = assertion_write_auth(&state, &headers).await?;
    dispatch_blocking(
        &state,
        Principal::Anonymous,
        Op::PutAssertion {
            did: did.into_string(),
            kind,
            subkey: None,
            body: body.to_vec(),
            authed,
        },
    )
    .await
}

/// `PUT /{did}/assertion/{kind}/{subkey}` — the subkeyed form (e.g. a
/// per-object policy, whose subkey is the object cid).
async fn put_assertion_subkey_handler(
    State(state): State<AppState>,
    Path((did, kind, subkey)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let authed = assertion_write_auth(&state, &headers).await?;
    dispatch_blocking(
        &state,
        Principal::Anonymous,
        Op::PutAssertion {
            did: did.into_string(),
            kind,
            subkey: Some(subkey),
            body: body.to_vec(),
            authed,
        },
    )
    .await
}

/// `POST /{did}/receipt/{hash}/countersign` — the customer completes a
/// bilateral receipt with its countersignature (body: `{signer, sig}`).
async fn countersign_receipt_handler(
    State(state): State<AppState>,
    Path((did, hash)): Path<(String, String)>,
    body: Bytes,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    dispatch_blocking(
        &state,
        Principal::Anonymous,
        Op::CountersignReceipt {
            did: did.into_string(),
            content_hash: hash,
            sig: String::from_utf8_lossy(&body).into_owned(),
        },
    )
    .await
}

/// `GET /{did}/assertion/{kind}` — read back an assertion + ack.
/// Authenticated so the owner sees the full record; the `policy` kind keeps
/// its Q4 grantee view. Accepts a `did:` service-auth JWT or an `id:` session.
async fn get_assertion_handler(
    State(state): State<AppState>,
    Path((did, kind)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, GET_POLICY_LXM).await;
    dispatch_blocking(
        &state,
        principal,
        Op::GetAssertion {
            did: did.into_string(),
            kind,
            subkey: None,
        },
    )
    .await
}

/// The `?chain=1` switch on the subkeyed read: present → the full chain read
/// (entries + recomputed total), absent → the ordinary latest-record read-back.
#[derive(serde::Deserialize)]
struct AssertionReadQuery {
    chain: Option<String>,
}

/// `GET /{did}/assertion/{kind}/{subkey}` — the subkeyed read-back. With
/// `?chain=1` on a chain kind it returns the entry history and the recomputed,
/// verified total (A3) instead of just the latest record.
async fn get_assertion_subkey_handler(
    State(state): State<AppState>,
    Path((did, kind, subkey)): Path<(String, String, String)>,
    Query(query): Query<AssertionReadQuery>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, GET_POLICY_LXM).await;
    let op = if query.chain.is_some() {
        Op::GetChain { did: did.into_string(), kind, subkey: Some(subkey) }
    } else {
        Op::GetAssertion { did: did.into_string(), kind, subkey: Some(subkey) }
    };
    dispatch_blocking(&state, principal, op).await
}

/// `DELETE /{did}/assertion/{kind}` — erase a namespace-scoped assertion (no
/// subkey). Owner-only; refused for a `Permanent` kind (A2).
async fn delete_assertion_handler(
    State(state): State<AppState>,
    Path((did, kind)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, DELETE_ASSERTION_LXM).await;
    dispatch_blocking(
        &state,
        principal,
        Op::DeleteAssertion { did: did.into_string(), kind, subkey: None },
    )
    .await
}

/// `DELETE /{did}/assertion/{kind}/{subkey}` — erase a subkeyed assertion (e.g. a
/// `kv.flag`). Owner-only; refused for a `Permanent` kind (A2).
async fn delete_assertion_subkey_handler(
    State(state): State<AppState>,
    Path((did, kind, subkey)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, DELETE_ASSERTION_LXM).await;
    dispatch_blocking(
        &state,
        principal,
        Op::DeleteAssertion { did: did.into_string(), kind, subkey: Some(subkey) },
    )
    .await
}

/// `GET /{did}/assertions/{kind}` — the owner-only subkey listing for a
/// `Listable` kind (A2). Self-only, no existence oracle; refused for a
/// `PointOnly` kind.
async fn list_assertions_handler(
    State(state): State<AppState>,
    Path((did, kind)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, LIST_ASSERTIONS_LXM).await;
    dispatch_blocking(
        &state,
        principal,
        Op::ListAssertions { did: did.into_string(), kind },
    )
    .await
}

/// `POST /{did}/assertion/{kind}/{subkey}/compact` — compact the chain behind its
/// latest acknowledged checkpoint (A4, the explicit billing-marker path).
/// Owner-only; refused if there is no checkpoint to compact behind.
async fn compact_chain_handler(
    State(state): State<AppState>,
    Path((did, kind, subkey)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, COMPACT_CHAIN_LXM).await;
    dispatch_blocking(
        &state,
        principal,
        Op::CompactChain { did: did.into_string(), kind, subkey: Some(subkey) },
    )
    .await
}

async fn get_meter_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    // The billing meter is private: owner-only (require_owner at dispatch).
    let principal = authenticate(&headers);
    dispatch_blocking(&state, principal, Op::GetMeter { did: did.into_string() }).await
}

/// `GET /{did}/du` — per-object sizes + total for `did` (ADR 0003). **Self-only**
/// (the owner of `did`); cross-DID is never served. `CISS_ADMIN_ONLY_DU` further
/// restricts `du` to admin-pin DIDs. Accepts an `id:` session or a `did:`
/// service-auth JWT bound to `du`.
async fn du_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: HeaderMap,
) -> Result<OpOutcome, ServerError> {
    let did = Did::parse(&did)?;
    let principal = authenticate_atproto(&state, &headers, DU_LXM).await;
    dispatch_blocking(&state, principal, Op::Du { did: did.into_string() }).await
}

/// Liveness/readiness: `200 ok`. Side-effect-free — it neither reads the store
/// nor the backend, so it stays fast under load (croft-stack contract §2).
async fn healthz_handler() -> Response {
    (StatusCode::OK, "ok").into_response()
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

/// Security headers for a served blob (I9): never content-sniff, always download
/// rather than render, and a locked-down CSP — so attacker-uploaded bytes served
/// from this origin cannot execute or be sniffed as same-origin HTML/JS.
pub(crate) const BLOB_SECURITY_HEADERS: [(&str, &str); 3] = [
    ("x-content-type-options", "nosniff"),
    ("content-disposition", "attachment"),
    ("content-security-policy", "default-src 'none'; sandbox"),
];

/// An `ETag` header value for a content address (`"<cid>"`, quoted per HTTP).
fn etag(cid: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{cid}\""))
        .expect("a hex content address is a valid header value")
}

impl IntoResponse for OpOutcome {
    fn into_response(self) -> Response {
        match self {
            OpOutcome::Stored { cid, bytes, mode, receipt_hash } => {
                let mode_str = match mode {
                    ReceiptMode::Unilateral => "unilateral",
                    ReceiptMode::Bilateral => "bilateral",
                };
                let mut resp = Json(serde_json::json!({
                    "cid": cid,
                    "bytes": bytes,
                    "receipt_mode": mode_str,
                    "receipt_hash": receipt_hash,
                }))
                .into_response();
                resp.headers_mut().insert("etag", etag(&cid));
                resp
            }
            OpOutcome::Bytes { cid, data } => {
                let mut resp = (StatusCode::OK, data).into_response();
                let headers = resp.headers_mut();
                headers.insert("etag", etag(&cid));
                for (name, value) in BLOB_SECURITY_HEADERS {
                    headers.insert(name, HeaderValue::from_static(value));
                }
                resp
            }
            OpOutcome::ManifestSaved { root, total_bytes } => Json(serde_json::json!({
                "root": root,
                "total_bytes": total_bytes,
            }))
            .into_response(),
            OpOutcome::ManifestBody { json }
            | OpOutcome::PolicyBody { json }
            | OpOutcome::UsageBody { json }
            | OpOutcome::ChainBody { json } => {
                ([("content-type", "application/json")], json).into_response()
            }
            OpOutcome::Meter {
                receipt_count,
                upload_bytes,
                download_bytes,
                running_total_bytes,
                postage_cents,
                drawdown_download_bytes,
            } => Json(serde_json::json!({
                "receipt_count": receipt_count,
                "upload_bytes": upload_bytes,
                "download_bytes": download_bytes,
                "running_total_bytes": running_total_bytes,
                "postage_cents": postage_cents,
                "drawdown_download_bytes": drawdown_download_bytes,
            }))
            .into_response(),
            OpOutcome::BlobList { cids } => {
                Json(serde_json::json!({ "cids": cids })).into_response()
            }
            OpOutcome::AssertionSaved { seq, ack_json } => Json(serde_json::json!({
                "seq": seq,
                "ack": serde_json::from_str::<serde_json::Value>(&ack_json)
                    .unwrap_or(serde_json::Value::Null),
            }))
            .into_response(),
            OpOutcome::ChainCompacted { behind } => {
                Json(serde_json::json!({ "compacted_behind": behind })).into_response()
            }
            OpOutcome::AssertionErased => Json(serde_json::json!({ "erased": true })).into_response(),
            OpOutcome::AssertionSubkeys { subkeys } => {
                Json(serde_json::json!({ "subkeys": subkeys })).into_response()
            }
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
    /// The request needs a verified session and none was presented.
    #[error("unauthorized: a verified session is required")]
    Unauthorized,
    /// The caller is authenticated but is not the owner of the target namespace.
    #[error("forbidden: not the owner of this namespace")]
    Forbidden,
    /// A blob CID could not be parsed as a CIDv1 raw + sha-256 address.
    #[error("bad blob CID: {0}")]
    BadCid(#[from] crate::cidv1::CidError),
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
    /// No provider signing seed was supplied under systemd (startup, fail-closed).
    #[error("no provider seed configured (wire the systemd credential or the env var)")]
    ProviderSeedMissing,
    /// A request identifier (`did`/content address) failed boundary validation.
    #[error("invalid identifier: {0}")]
    BadIdentifier(#[from] crate::identifiers::IdentifierError),
    /// The whole store is at its distinct-bytes ceiling (V5).
    #[error("store at capacity")]
    StoreFull,
    /// The DID is at its per-DID distinct-bytes cap (V5).
    #[error("did storage quota exceeded")]
    DidQuotaExceeded,
    /// The requested object is larger than the read limit (resource safety).
    #[error("object is {size} bytes, over the {max}-byte limit")]
    ObjectTooLarge {
        /// The object's size.
        size: u64,
        /// The read ceiling.
        max: u64,
    },
    /// A blocking dispatch task failed to join (e.g. panicked) — never expected.
    #[error("internal task failure")]
    TaskJoin,
    /// An assertion was malformed, of an unknown kind, or its target did not
    /// match the route.
    #[error("invalid assertion: {0}")]
    BadAssertion(&'static str),
    /// An assertion failed authorization (bad/forged signature, wrong signer,
    /// or an `OwnerSigned` record naming a non-`id:` target).
    #[error("forbidden: assertion is not authorized for this target")]
    AssertionUnauthorized,
    /// A dial asserted a limit above the provider's effective bound —
    /// provider limits supersede, so the dial is refused at set time with
    /// the real bound quoted (there is no point storing an unreachable
    /// number; enforcement applies `min()` regardless).
    #[error("assertion refused: {asserted} exceeds the provider bound {bound}")]
    AssertionAboveBound {
        /// The customer's asserted limit.
        asserted: u64,
        /// The effective provider bound (`min(store_ceiling, did_cap)`).
        bound: u64,
    },
    /// An assertion body exceeded the kind's declared body ceiling (ADR 0005,
    /// the sizing axis). Refused at the write boundary with the limit quoted —
    /// the ceiling-dial refusal pattern, generalized to every kind.
    #[error("assertion refused: {kind} body is {bytes} bytes, over the {ceiling}-byte ceiling")]
    BodyAboveCeiling {
        /// The kind whose ceiling was exceeded.
        kind: String,
        /// The serialized body size that was refused.
        bytes: usize,
        /// The kind's declared body ceiling.
        ceiling: usize,
    },
    /// DELETE was attempted on a kind that declares `Permanent` erasure (ADR
    /// 0005): the record is superseded by a higher-seq write, never deleted.
    #[error("{kind} is permanent (ADR 0005): superseded by a new record, never deleted")]
    ErasureNotAllowed {
        /// The permanent kind whose erasure was refused.
        kind: String,
    },
    /// LIST was attempted on a kind that declares `PointOnly` enumeration (ADR
    /// 0005): the key is the price of asking; the kind is not enumerable.
    #[error("{kind} is point-only (ADR 0005): address it by key, it does not enumerate")]
    EnumerationNotAllowed {
        /// The point-only kind whose listing was refused.
        kind: String,
    },
    /// A `chain.counter` entry does not continue the stored chain (ADR 0005 / A3):
    /// its total does not follow, its seq is not the successor's, or it links to
    /// the wrong head. The reason quotes the real values.
    #[error("chain.counter refused: {0}")]
    ChainBroken(String),
    /// A billable write would take the period's postage past the customer's
    /// asserted spend ceiling — refused BEFORE serving, with the quote
    /// (E89: throttle/defer, never mint debt). Owner egress is exempt
    /// (B6): served and billed, never refused.
    #[error(
        "spend ceiling: this transfer would reach {needed_cents}¢ \
         (spent {spent_cents}¢, ceiling {ceiling_cents}¢) — deferred, nothing served"
    )]
    SpendCeiling {
        /// The cents the period would reach if this transfer served.
        needed_cents: u64,
        /// Cents already spent this period.
        spent_cents: u64,
        /// The customer's asserted ceiling.
        ceiling_cents: u64,
    },
    /// The account is in drawdown (a customer-asserted mode dial): the
    /// books are closed to new writes — no new blobs, keep-set commits
    /// only with a non-increasing total. Egress is unaffected. Reversible
    /// by a new mode dial.
    #[error("account in drawdown: the books are closed to new writes (egress unaffected); re-enable with a new account-mode dial")]
    DrawdownActive,
    /// A write did not advance the stored sequence (anti-rollback) — the
    /// uniform typed staleness every self-assertion kind (and the manifest)
    /// surfaces as HTTP 409.
    #[error("conflict: stale {kind} seq {attempted} does not supersede the stored record")]
    AssertionStale {
        /// Which record kind was stale (`policy`, `dial/…`, or `manifest`).
        kind: String,
        /// The refused sequence number.
        attempted: u64,
    },
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = match self {
            ServerError::NotFound => StatusCode::NOT_FOUND,
            ServerError::BadManifest(_)
            | ServerError::BadPubkey
            | ServerError::BadCid(_)
            | ServerError::BadAssertion(_)
            | ServerError::AssertionAboveBound { .. }
            | ServerError::BodyAboveCeiling { .. }
            | ServerError::BadIdentifier(_) => StatusCode::BAD_REQUEST,
            ServerError::DidKeyMismatch
            | ServerError::Forbidden
            | ServerError::AssertionUnauthorized => StatusCode::FORBIDDEN,
            ServerError::AssertionStale { .. }
            | ServerError::DrawdownActive
            | ServerError::ChainBroken(_) => StatusCode::CONFLICT,
            ServerError::ErasureNotAllowed { .. } | ServerError::EnumerationNotAllowed { .. } => {
                StatusCode::METHOD_NOT_ALLOWED
            }
            ServerError::SpendCeiling { .. } => StatusCode::PAYMENT_REQUIRED,
            ServerError::Unauthorized => StatusCode::UNAUTHORIZED,
            ServerError::ObjectTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            ServerError::StoreFull | ServerError::DidQuotaExceeded => {
                StatusCode::INSUFFICIENT_STORAGE
            }
            ServerError::Tampered { .. } | ServerError::ByteCountMismatch { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ServerError::Persist(_)
            | ServerError::Blob(_)
            | ServerError::Json(_)
            | ServerError::BadConfig
            | ServerError::ProviderSeedMissing
            | ServerError::TaskJoin => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // Split internal from external representation (I4): a 5xx must not leak
        // internal state — the content-hash of tampered bytes, an OS io-error, a
        // raw SQLite/serde message. Log the full detail; return a fixed public
        // string. 4xx messages describe the *client's own* request (a bad
        // manifest, a malformed identifier), so they are safe to return — as are
        // the quota 507s, which are intentional, non-leaking capacity signals (V5).
        let quota = matches!(self, ServerError::StoreFull | ServerError::DidQuotaExceeded);
        let body = if status.is_server_error() && !quota {
            tracing::error!(%status, error = %self, "boundary request failed");
            "internal error".to_owned()
        } else {
            self.to_string()
        };
        (status, body).into_response()
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
    use super::{decide_seed, inherit_fd_requested, App, Blobs, Db, Op, SeedDecision};
    use crate::receipts::{select_mode, ReceiptMode, TransferContext};
    use zeroize::Zeroizing;

    fn seed(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    #[test]
    fn seed_source_precedence_and_fail_closed() {
        // A credential wins over the env var.
        assert_eq!(
            decide_seed(Some(seed("cred")), Some(seed("env")), true),
            SeedDecision::Use(seed("cred")),
        );
        // The env var is used when there is no credential.
        assert_eq!(
            decide_seed(None, Some(seed("env")), true),
            SeedDecision::Use(seed("env")),
        );
        // An empty credential is ignored (falls through to the env var).
        assert_eq!(
            decide_seed(Some(seed("")), Some(seed("env")), true),
            SeedDecision::Use(seed("env")),
        );
        // Under systemd with no secret: fail closed (never an ephemeral identity).
        assert_eq!(decide_seed(None, None, true), SeedDecision::FailClosed);
        // Outside systemd (dev) with no secret: generate an ephemeral seed.
        assert_eq!(decide_seed(None, None, false), SeedDecision::GenerateEphemeral);
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
            Op::ListBlobs { did: "id:x".into() },
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

    // --- Gated reads (Phase 3): the dispatch-level authorization choke point.
    // These exercise the real `dispatch` gate (dispatch → resolve_policy → allows
    // → op_get_object | NotFound) with a policy seeded directly into the store
    // (the HTTP set-policy route lands in Phase 5). ---

    mod gated_reads {
        use super::super::{dispatch, lock_store, App, Blobs, Db, Op, OpOutcome, ServerError};
        use crate::crypto::derive_keypair;
        use crate::identity::derive_id;
        use crate::assertion::{make_ack, SignedAssertion};
        use crate::policy::{policy_body_fold, PolicyBody, ReadClass, POLICY_KIND};

        /// Model-A-sign a policy assertion + ack (test helper on the substrate).
        fn signed_policy(
            did: &str,
            cid: Option<&str>,
            class: ReadClass,
            readers: &[String],
            seq: u64,
            owner: &crate::crypto::Keypair,
        ) -> (SignedAssertion, crate::assertion::Ack) {
            let body = PolicyBody { read_class: class, readers: readers.to_vec() };
            let record = SignedAssertion::sign_owner(
                POLICY_KIND,
                did,
                cid,
                seq,
                serde_json::to_value(&body).expect("json"),
                &policy_body_fold(&body),
                owner,
            );
            let ack =
                make_ack(&record, &crate::crypto::derive_keypair("m", "attest")).expect("ack");
            (record, ack)
        }
        use ciss_auth::Principal;

        fn upload(app: &App, owner: &Principal, did: &str, bytes: &[u8]) -> String {
            match dispatch(
                &app.state,
                owner,
                Op::PutObject {
                    did: did.to_owned(),
                    key: "k".to_owned(),
                    bytes: bytes.to_vec(),
                },
            )
            .expect("owner uploads a blob")
            {
                OpOutcome::Stored { cid, .. } => cid,
                _ => panic!("expected a Stored outcome from PutObject"),
            }
        }

        #[test]
        fn public_read_is_unbroken_without_a_policy() {
            // Regression guard: with no policy row, a read stays world-readable
            // (PDS-compat) — the gate must never over-reach.
            let app = App::new("gate-seed", Blobs::Memory, Db::Memory).expect("app");
            let owner_kp = derive_keypair("gate", "owner");
            let did = derive_id(&owner_kp.verifying_key());
            let owner = Principal::Authenticated(did.clone());
            let cid = upload(&app, &owner, &did, b"public bytes");

            let out = dispatch(
                &app.state,
                &Principal::Anonymous,
                Op::GetObject {
                    did: did.clone(),
                    cid,
                },
            );
            assert!(out.is_ok(), "anon reads a public (ungated) object");
        }

        #[test]
        fn gated_object_denies_non_grantee_with_notfound() {
            let app = App::new("gate-seed", Blobs::Memory, Db::Memory).expect("app");
            let owner_kp = derive_keypair("gate", "owner");
            let did = derive_id(&owner_kp.verifying_key());
            let owner = Principal::Authenticated(did.clone());
            let alice = "did:plc:alice".to_owned();
            let cid = upload(&app, &owner, &did, b"secret bytes");

            // The owner gates the whole namespace to grantees:[alice].
            let (policy, ack) = signed_policy(&did,
                None,
                ReadClass::Grantees,
                std::slice::from_ref(&alice),
                1,
                &owner_kp,);
            lock_store(&app.state.store)
                .save_assertion(&policy, &ack)
                .expect("seed policy");

            let get = |p: &Principal| {
                dispatch(
                    &app.state,
                    p,
                    Op::GetObject {
                        did: did.clone(),
                        cid: cid.clone(),
                    },
                )
            };

            // A denied read is a 404 (oracle-free), never the bytes.
            assert!(
                matches!(get(&Principal::Anonymous), Err(ServerError::NotFound)),
                "anon is denied with 404, not the bytes",
            );
            assert!(
                matches!(
                    get(&Principal::Authenticated("did:plc:bob".to_owned())),
                    Err(ServerError::NotFound)
                ),
                "a non-grantee is denied with 404",
            );
            // The grantee and the owner read.
            assert!(get(&Principal::Authenticated(alice)).is_ok(), "the grantee reads");
            assert!(get(&owner).is_ok(), "the owner reads its own gated object");
        }

        #[test]
        fn owner_only_policy_admits_only_the_owner() {
            let app = App::new("gate-seed", Blobs::Memory, Db::Memory).expect("app");
            let owner_kp = derive_keypair("gate", "owner");
            let did = derive_id(&owner_kp.verifying_key());
            let owner = Principal::Authenticated(did.clone());
            let cid = upload(&app, &owner, &did, b"owner-only bytes");

            let (policy, ack) =
                signed_policy(&did, None, ReadClass::Owner, &[], 1, &owner_kp);
            lock_store(&app.state.store)
                .save_assertion(&policy, &ack)
                .expect("seed policy");

            let get = |p: &Principal| {
                dispatch(
                    &app.state,
                    p,
                    Op::GetObject {
                        did: did.clone(),
                        cid: cid.clone(),
                    },
                )
            };
            assert!(get(&owner).is_ok(), "owner reads");
            assert!(
                matches!(get(&Principal::Anonymous), Err(ServerError::NotFound)),
                "anon denied",
            );
            assert!(
                matches!(
                    get(&Principal::Authenticated("did:plc:alice".to_owned())),
                    Err(ServerError::NotFound)
                ),
                "a stranger denied",
            );
        }

        fn list(app: &App, p: &Principal, did: &str) -> Vec<String> {
            match dispatch(
                &app.state,
                p,
                Op::ListBlobs {
                    did: did.to_owned(),
                },
            )
            .expect("listBlobs")
            {
                OpOutcome::BlobList { cids } => cids,
                _ => panic!("expected a BlobList outcome"),
            }
        }

        #[test]
        fn list_blobs_omits_a_hidden_object_cid() {
            // A per-object gate on one blob under an (ungated) world namespace: the
            // hidden cid is neither listed nor counted for a non-grantee, while the
            // public cid stays visible to everyone.
            let app = App::new("gate-seed", Blobs::Memory, Db::Memory).expect("app");
            let owner_kp = derive_keypair("gate", "owner");
            let did = derive_id(&owner_kp.verifying_key());
            let owner = Principal::Authenticated(did.clone());
            let alice = "did:plc:alice".to_owned();

            let public = upload(&app, &owner, &did, b"public blob");
            let secret = upload(&app, &owner, &did, b"secret blob");
            let (policy, ack) = signed_policy(&did,
                Some(&secret),
                ReadClass::Grantees,
                std::slice::from_ref(&alice),
                1,
                &owner_kp,);
            lock_store(&app.state.store)
                .save_assertion(&policy, &ack)
                .expect("seed object policy");

            assert_eq!(
                list(&app, &Principal::Anonymous, &did),
                vec![public.clone()],
                "anon sees only the public cid; the hidden cid is neither listed nor counted",
            );
            assert_eq!(
                list(&app, &Principal::Authenticated("did:plc:bob".to_owned()), &did),
                vec![public.clone()],
                "a non-grantee sees only the public cid",
            );

            let grantee = list(&app, &Principal::Authenticated(alice), &did);
            assert_eq!(grantee.len(), 2, "the grantee sees public + granted");
            assert!(grantee.contains(&public) && grantee.contains(&secret));

            assert_eq!(list(&app, &owner, &did).len(), 2, "the owner sees all");
        }

        #[test]
        fn namespace_gate_hides_every_cid_from_anon() {
            // A namespace-wide grantees policy: an anon caller sees an empty listing
            // (no world cids), while the owner still sees all uploads.
            let app = App::new("gate-seed", Blobs::Memory, Db::Memory).expect("app");
            let owner_kp = derive_keypair("gate", "owner");
            let did = derive_id(&owner_kp.verifying_key());
            let owner = Principal::Authenticated(did.clone());
            let alice = "did:plc:alice".to_owned();

            upload(&app, &owner, &did, b"one");
            upload(&app, &owner, &did, b"two");
            let (policy, ack) = signed_policy(&did,
                None,
                ReadClass::Grantees,
                std::slice::from_ref(&alice),
                1,
                &owner_kp,);
            lock_store(&app.state.store)
                .save_assertion(&policy, &ack)
                .expect("seed namespace policy");

            assert!(
                list(&app, &Principal::Anonymous, &did).is_empty(),
                "anon sees nothing under a namespace gate",
            );
            assert_eq!(
                list(&app, &Principal::Authenticated(alice), &did).len(),
                2,
                "the grantee sees both",
            );
            assert_eq!(list(&app, &owner, &did).len(), 2, "the owner sees all");
        }
    }
}
