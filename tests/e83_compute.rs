//! E83 stage 1 wiring — per-caller compute observability
//! (`docs/notes/rate-limiting-design.md` §5, stage 1).
//!
//! The design's RED anchor: after N requests by a caller, the on-box usage
//! surface shows N with durations. The observation path is the real one —
//! requests flow through the live HTTP boundary into dispatch, the ledger
//! flushes to SQLite at checkpoint, and a *separate* read-only store (the
//! `ciss usage` path: another process opening the same file) reads it back.

mod common;

use ciss::persist::Store;
use ciss::server::{App, Blobs, Db};

#[tokio::test]
async fn dispatched_requests_land_in_the_compute_usage_table_per_caller() {
    let dir = std::env::temp_dir().join(format!("ciss-e83-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let db_path = dir.join("meter.sqlite");
    let app = App::new(
        "test-provider",
        Blobs::Memory,
        Db::File(db_path.clone()),
    )
    .expect("build app");

    // Serve the app while keeping it — checkpoint runs after shutdown.
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serve = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Three anonymous world-readable object reads (404s still cost dispatch
    // and must be attributed — to the shared anonymous row).
    let stranger = ciss::crypto::derive_keypair("e83", "stranger");
    let stranger_did = ciss::identity::derive_id(&stranger.verifying_key());
    for _ in 0..3 {
        let resp = client
            .get(format!("{base}/{stranger_did}/objects/{}", "0".repeat(64)))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), 404, "no such object");
    }

    // One authenticated owner write — attributed to the caller's identity.
    let keypair = ciss::crypto::derive_keypair("e83", "alice");
    let did = ciss::identity::derive_id(&keypair.verifying_key());
    let (pubkey, session) = common::session_headers(&keypair, &did);
    let resp = client
        .put(format!("{base}/{did}/objects/e83-probe"))
        .header("x-croft-pubkey", pubkey)
        .header("x-croft-session", session)
        .body(b"e83 bytes".to_vec())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "owner PUT stores");

    let _ = tx.send(());
    serve.await.expect("server task");

    // Checkpoint flushes the in-memory ledger into the canonical file...
    app.checkpoint().expect("checkpoint");
    drop(app);

    // ...where the on-box reporting path (a separate read-only open, exactly
    // what `ciss usage` does from another process) can see it.
    let store = Store::open_readonly(db_path.to_str().expect("utf8 path")).expect("open");
    let rows = store.load_compute_usage().expect("load compute usage");

    let anon_reads = rows
        .iter()
        .find(|r| r.caller == ciss::compute::ANONYMOUS_CALLER && r.class == "object-read")
        .expect("anonymous object-read row");
    assert_eq!(anon_reads.requests, 3, "three anonymous reads counted");

    let alice_writes = rows
        .iter()
        .find(|r| r.caller == did && r.class == "object-write")
        .expect("owner object-write row");
    assert_eq!(alice_writes.requests, 1, "one attributed write");

    let _ = std::fs::remove_dir_all(&dir);
}
