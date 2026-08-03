//! Workflow tier — availability / path-safety guards (see
//! `docs/TESTING-STRATEGY.md`). RED specification: run with
//! `cargo test --test flow_availability -- --ignored` to watch them fail against
//! today's server. Finding IDs refer to `docs/SECURITY-REVIEW-2026-08-03.md`.
//!
//! Note: the V2 runtime-wedge guard (synchronous I/O freezing the tokio workers)
//! lands in Phase 2 alongside its fix — proving it requires a dedicated-runtime
//! server harness so the prober is not starved by the same saturation it is
//! measuring. It is intentionally not in this file.

mod common;

use ciss::crypto::sha256_hex;
use common::World;

/// Percent-encode an absolute filesystem path so it survives as a single route
/// path-segment and is decoded back by the server (the traversal vector).
fn as_path_segment(abs: &std::path::Path) -> String {
    abs.to_str()
        .expect("utf-8 path")
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// A3 — `did`/`cid` are joined straight into a filesystem path, so a
/// percent-encoded absolute path escapes the data dir. A write must be refused
/// before it touches the filesystem.
#[tokio::test]
#[ignore = "RED spec (A3) — un-ignore in Phase 1/2: identifiers are validated before FS use"]
async fn a_write_with_a_traversal_path_is_refused() {
    let world = World::spawn_fs().await;
    let data_dir = world.data_dir().expect("fs world").to_owned();
    // A sibling of the data dir — writing here proves an escape.
    let escape_target = data_dir.with_extension("ESCAPED");
    let _ = std::fs::remove_dir_all(&escape_target);

    let did_segment = as_path_segment(&escape_target);
    let out = world
        .anonymous()
        .put_object(&did_segment, "k", b"bytes outside the data dir")
        .await;

    out.refused(400); // TODAY: 200, and the bytes land in `escape_target`.

    assert!(
        !escape_target.exists(),
        "a request wrote outside the data dir: {escape_target:?}",
    );
    world.shutdown().await;
}

/// V1 — `FsBlobStore::get` reads a whole file into memory with no size check, so
/// a tiny GET can drive an arbitrary allocation. An oversized object must be
/// refused (or streamed), never buffered whole.
#[tokio::test]
#[ignore = "RED spec (V1) — un-ignore in Phase 2: per-object size cap on reads"]
async fn a_get_of_an_oversized_object_is_refused_not_buffered() {
    let world = World::spawn_fs().await;
    let data_dir = world.data_dir().expect("fs world");

    // Stage an oversized object directly on disk under blocks/{did}/{cid}, with
    // cid == its true fingerprint so it passes the content-address check and the
    // only thing standing between the request and a full read is a size cap.
    let did = "id:whale";
    let bytes = vec![0u8; 16 * 1024 * 1024]; // 16 MiB — larger than any sane blob cap.
    let cid = sha256_hex(&bytes);
    let path = data_dir.join("blocks").join(did).join(&cid);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir blocks");
    std::fs::write(&path, &bytes).expect("stage oversized blob");

    let out = world.anonymous().get_object(did, &cid).await;

    out.refused(413); // TODAY: 200 with all 16 MiB buffered into RAM first.
    world.shutdown().await;
}
