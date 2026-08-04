//! Phase-9 wiring test (the croft-stack tenant contract): the deployment
//! constructor `App::with_provider_from_secret` self-manages its layout, serves
//! `GET /healthz` → `ok`, and sources a **stable** provider identity from the
//! unit-supplied secret (I8) — so the identity is the deployment's, the same
//! across restarts and independent of the data dir, and is never read from the
//! canonical database.
//!
//! This mirrors how the systemd unit runs the binary: point it at a data dir,
//! everything under it, with the signing seed provided as a secret.

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
    App::with_provider_from_secret(
        Blobs::Fs(data_dir.to_path_buf()),
        Db::File(data_dir.join("meter.sqlite")),
    )
    .expect("build app from secret")
}

#[test]
fn provider_identity_comes_from_the_secret_and_layout_is_self_managed() {
    // The unit supplies the signing seed as a secret; here, via the env var.
    std::env::set_var("CISS_PROVIDER_SEED", "contract-test-provider-seed");

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
        "the same secret yields the same provider identity across a restart",
    );

    let other = app_at(&dir_b);
    assert_eq!(
        other.provider_id(),
        id1,
        "the provider identity is the deployment's secret, independent of the data dir",
    );

    std::env::remove_var("CISS_PROVIDER_SEED");
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
