//! The E87 graceful-shutdown seam, end to end: a file-backed store accumulates
//! a write-ahead log as transfers are metered, and `App::checkpoint` truncates
//! it (`wal_checkpoint(TRUNCATE)`) so a restart opens a clean database.
//!
//! Pins the checkpoint's observable effect: a `checkpoint -> Ok(())` no-op
//! would leave the WAL non-empty and fail here.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ciss::server::{App, Blobs, Db};
use tokio::sync::oneshot;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_db() -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ciss-checkpoint-{}-{seq}.sqlite",
        std::process::id()
    ))
}

/// The WAL sidecar SQLite writes alongside a database file is `<db>-wal`.
fn wal_path(db: &Path) -> PathBuf {
    PathBuf::from(format!("{}-wal", db.display()))
}

fn wal_len(db: &Path) -> u64 {
    std::fs::metadata(wal_path(db))
        .map(|m| m.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn checkpoint_truncates_the_wal_after_a_metered_write() {
    let db = temp_db();
    let app = App::new("prov", Blobs::Memory, Db::File(db.clone())).expect("app");
    let router = app.router(); // clones the shared store Arc; `app` keeps a handle

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });

    // A metered PUT writes a receipt through the shared connection -> WAL grows.
    reqwest::Client::new()
        .put(format!("http://{addr}/id:x/objects/k"))
        .body(b"some bytes to meter".to_vec())
        .send()
        .await
        .expect("put");
    assert!(wal_len(&db) > 0, "a metered write populated the WAL");

    // Drain the server; `app` still owns a store handle, so the connection
    // stays open (no auto-checkpoint on close yet).
    let _ = tx.send(());
    let _ = handle.await;

    app.checkpoint().expect("checkpoint");
    assert_eq!(wal_len(&db), 0, "checkpoint truncated the WAL to zero");

    // Cleanup.
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(wal_path(&db));
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-shm", db.display())));
}
