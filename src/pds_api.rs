//! The minimal atproto PDS blob surface — a thin layer over the metered
//! byte-path, so the store is a PDS-like node on the Bluesky network.
//!
//! The three endpoints from the Phase-0 D2 confirmed floor (canonical lexicon,
//! not the SPA docs):
//!
//! - `POST /xrpc/com.atproto.repo.uploadBlob` — **auth required**, body is raw
//!   bytes, response `{"blob":{"$type":"blob","ref":{"$link":"<CIDv1>"},
//!   "mimeType":"<ct>","size":<int>}}`.
//! - `GET /xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>` — **public**,
//!   returns the raw bytes.
//! - `GET /xrpc/com.atproto.sync.listBlobs?did=<did>` — **public**, returns
//!   `{"cids":[<CIDv1>,...]}`.
//!
//! Every endpoint routes through the same [`crate::server::dispatch`] boundary
//! as the S3 plane, so an atproto transfer is metered identically (a signed
//! receipt per byte-crossing). The atproto layer's only extra work is the
//! address translation: the network speaks CIDv1 (`ref.$link`), the metered
//! backend is keyed by the same digest in hex — [`crate::cidv1`] bridges them.
//!
//! `SEAM:` this is the *blob* floor. The full PDS surface (`getRepo`,
//! `getRecord`, `subscribeRepos`, …) is out of v0 and tracked, not stubbed.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ciss_auth::Principal;
use serde::Deserialize;

use crate::cidv1;
use crate::identifiers::Did;
use crate::server::{authenticate_atproto, dispatch_blocking, AppState, Op, OpOutcome, ServerError};

/// The mime returned when a request declares none, and echoed by `getBlob`.
const DEFAULT_MIME: &str = "application/octet-stream";

/// The maximum length of an accepted media type.
const MAX_MEDIA_TYPE_LEN: usize = 128;

/// Whether `s` is a simple, bounded `type/subtype` media type over a safe charset
/// (no control bytes, no `<`/`>`, no parameters) — I13.
fn is_valid_media_type(s: &str) -> bool {
    s.len() <= MAX_MEDIA_TYPE_LEN
        && s.split_once('/').is_some_and(|(t, sub)| !t.is_empty() && !sub.is_empty())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'+' | b'-'))
}

/// The media type to store/echo for an upload: the declared value if it is a
/// valid, bounded media type, else the default (never a reflected garbage value).
fn sanitize_media_type(declared: Option<&str>) -> String {
    match declared.map(str::trim) {
        Some(s) if is_valid_media_type(s) => s.to_owned(),
        _ => DEFAULT_MIME.to_owned(),
    }
}

/// The atproto blob endpoints, ready to merge into the server's router.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
}

/// `com.atproto.repo.uploadBlob` — store a blob in the authed repo, metered.
async fn upload_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServerError> {
    // The acting DID is the caller's verified identity — either a Model-R
    // service-auth JWT (atproto `did:`, verified against its resolved key) or the
    // interim `id:` signed session — never a DID named in an unverified header
    // (ADR 0001; closes the mock-bearer A2 on both identity spaces).
    let principal = authenticate_atproto(&state, &headers, "com.atproto.repo.uploadBlob").await;
    let did = principal
        .did()
        .ok_or(ServerError::Unauthorized)?
        .to_owned();
    // Validate the declared media type (I13): an unbounded or non-media-type
    // Content-Type must not be stored and echoed back to atproto clients. An
    // invalid value falls back to the default rather than reflecting garbage.
    let mime = sanitize_media_type(headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()));
    tracing::info!(endpoint = "uploadBlob", %did, bytes = body.len(), mime = ?mime, "atproto blob boundary");

    let outcome = dispatch_blocking(
        &state,
        principal,
        Op::PutObject {
            did,
            key: "uploadBlob".to_owned(),
            bytes: body.to_vec(),
        },
    )
    .await?;
    let OpOutcome::Stored { cid, bytes, .. } = outcome else {
        // A PutObject dispatch always yields Stored; any other variant is an
        // internal invariant break — surfaced loudly, never mis-shaped.
        return Err(ServerError::BadConfig);
    };
    let link = cidv1::from_sha256_hex(&cid)?;
    tracing::info!(endpoint = "uploadBlob", blob_cid = %link, size = bytes, "blob stored + metered");

    Ok(Json(serde_json::json!({
        "blob": {
            "$type": "blob",
            "ref": { "$link": link },
            "mimeType": mime,
            "size": bytes,
        }
    }))
    .into_response())
}

/// Query for `getBlob`: the owning DID and the blob's CIDv1.
#[derive(Deserialize)]
struct GetBlobParams {
    did: String,
    cid: String,
}

/// `com.atproto.sync.getBlob` — return a blob's raw bytes (public), metered.
async fn get_blob(
    State(state): State<AppState>,
    Query(params): Query<GetBlobParams>,
) -> Result<Response, ServerError> {
    let did = Did::parse(&params.did)?;
    let hex = cidv1::to_sha256_hex(&params.cid)?;
    tracing::info!(endpoint = "getBlob", did = %did, blob_cid = %params.cid, "atproto blob boundary");

    // getBlob is public (PDS-compat world read).
    let outcome = dispatch_blocking(
        &state,
        Principal::Anonymous,
        Op::GetObject {
            did: did.into_string(),
            cid: hex,
        },
    )
    .await?;
    let OpOutcome::Bytes { data, .. } = outcome else {
        return Err(ServerError::BadConfig);
    };

    // SEAM: atproto getBlob echoing the original upload mime is behavioral and
    // UNCONFIRMED in the lexicon (D2); v0 returns octet-stream rather than guess.
    let mut resp = ([(CONTENT_TYPE, DEFAULT_MIME)], data).into_response();
    for (name, value) in crate::server::BLOB_SECURITY_HEADERS {
        resp.headers_mut()
            .insert(name, axum::http::HeaderValue::from_static(value));
    }
    Ok(resp)
}

/// Query for `listBlobs`: the owning DID.
#[derive(Deserialize)]
struct ListBlobsParams {
    did: String,
}

/// `com.atproto.sync.listBlobs` — the CIDv1 addresses a DID has uploaded (public).
async fn list_blobs(
    State(state): State<AppState>,
    Query(params): Query<ListBlobsParams>,
) -> Result<Response, ServerError> {
    let did = Did::parse(&params.did)?;
    tracing::info!(endpoint = "listBlobs", did = %did, "atproto blob boundary");

    // listBlobs is public (PDS-compat world read).
    let outcome =
        dispatch_blocking(&state, Principal::Anonymous, Op::ListBlobs { did: did.into_string() })
            .await?;
    let OpOutcome::BlobList { cids } = outcome else {
        return Err(ServerError::BadConfig);
    };
    // Map each hex backend key to its CIDv1 $link.
    let links = cids
        .iter()
        .map(|hex| cidv1::from_sha256_hex(hex))
        .collect::<Result<Vec<String>, _>>()?;

    // SEAM: pagination (cursor/since/limit) is deferred; v0 returns every blob
    // and omits `cursor` — atproto's "no more pages" signal.
    Ok(Json(serde_json::json!({ "cids": links })).into_response())
}
