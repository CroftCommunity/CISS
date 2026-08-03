//! Phase-9 wiring test (the croft-stack tenant contract): the deployment
//! constructor `App::with_persistent_provider` self-manages its layout, serves
//! `GET /healthz` → `ok`, and keeps a **stable** provider identity across
//! restarts (persisted seed) while distinct data dirs get distinct identities.
//!
//! This mirrors how the systemd unit runs the binary: point it at a data dir,
//! everything under it, no external seed/secret wiring.

mod common;

use std::path::PathBuf;

use common::TestServer;

use ciss::server::{App, Blobs, Db};

/// A unique, empty data dir under the OS temp dir for one test.
fn fresh_data_dir(tag: &str) -> PathBuf {
    let unique = format!("ciss-contract-{}-{tag}-{}", std::process::id(), line!());
    let dir = std::env::temp_dir().join(unique);
    let _ = std::fs::remove_dir_all(&dir);
    let blocks = dir.join("blocks");
    std::fs::create_dir_all(&blocks).expect("create data layout");
    dir
}

/// Build the deployment-style app at `data_dir`, exactly as the binary does:
/// the blob backend is rooted at the data dir (content under `blocks/`, staging
/// under `tmp/`) and the metering store is `meter.sqlite` beside it.
fn app_at(data_dir: &std::path::Path) -> App {
    App::with_persistent_provider(
        Blobs::Fs(data_dir.to_path_buf()),
        Db::File(data_dir.join("meter.sqlite")),
    )
    .expect("build persistent app")
}

#[test]
fn provider_identity_persists_across_restart_and_is_per_data_dir() {
    let dir_a = fresh_data_dir("a");
    let dir_b = fresh_data_dir("b");

    let first = app_at(&dir_a);
    let id1 = first.provider_id().to_owned();
    drop(first); // release the SQLite handle, as a restart would

    // meter.sqlite is created on open (contract: create declared paths).
    assert!(
        dir_a.join("meter.sqlite").exists(),
        "the canonical SQLite is created on start",
    );
    assert!(dir_a.join("blocks").is_dir(), "the blobs dir exists");

    let restarted = app_at(&dir_a);
    assert_eq!(
        restarted.provider_id(),
        id1,
        "the persisted seed yields the same provider identity across a restart",
    );

    let other = app_at(&dir_b);
    assert_ne!(
        other.provider_id(),
        id1,
        "a fresh data dir gets its own randomly-generated provider identity",
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test]
async fn healthz_returns_ok() {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("app");
    let server = TestServer::spawn(app).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(server.url("/healthz"))
        .send()
        .await
        .expect("healthz send");
    assert_eq!(resp.status().as_u16(), 200, "healthz is 200");
    assert_eq!(
        resp.text().await.expect("body"),
        "ok",
        "healthz body is the literal ok",
    );

    server.shutdown().await;
}
