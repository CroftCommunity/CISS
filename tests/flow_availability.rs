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
async fn a_get_of_an_oversized_object_is_refused_not_buffered() {
    let world = World::spawn_fs().await;
    let data_dir = world.data_dir().expect("fs world");

    // Stage an oversized object directly on disk under blocks/{did}/{cid}, with
    // cid == its true fingerprint so it passes the content-address check and the
    // only thing standing between the request and a full read is a size cap.
    let did = "id:00000000000badd0"; // a valid id:<16 hex> (Phase-1 identifier check).
    let bytes = vec![0u8; 16 * 1024 * 1024]; // 16 MiB — larger than the read cap.
    let cid = sha256_hex(&bytes);
    let path = data_dir.join("blocks").join(did).join(&cid);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir blocks");
    std::fs::write(&path, &bytes).expect("stage oversized blob");

    let out = world.anonymous().get_object(did, &cid).await;

    out.refused(413); // TODAY: 200 with all 16 MiB buffered into RAM first.
    world.shutdown().await;
}

/// V2 — a non-regular node (a FIFO with no writer) staged at a valid content
/// path must be refused promptly, never read. Before the fix, `fs::read` blocks
/// forever on the FIFO and parks a worker; after it, the backend stats first,
/// sees a non-regular node, and returns a fast 404. A 3 s client timeout makes a
/// pre-fix hang observable as a failure rather than an infinite test.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fifo_at_a_content_path_is_refused_promptly_not_blocked_on() {
    use std::os::unix::ffi::OsStrExt;

    let world = World::spawn_fs().await;
    let data_dir = world.data_dir().expect("fs world");

    // A valid identifier + content address (they pass Phase-1 validation), but
    // the on-disk node is a FIFO rather than a regular file.
    let did = "id:0000000000000000";
    let cid = "a".repeat(64);
    let path = data_dir.join("blocks").join(did).join(&cid);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir blocks");
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("cstring");
    // SAFETY: libc::mkfifo with a valid NUL-terminated path and mode 0o600.
    let rc = unsafe { libc_mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .expect("client");
    let started = std::time::Instant::now();
    let res = client
        .get(world.url(&format!("/{did}/objects/{cid}")))
        .send()
        .await;
    let elapsed = started.elapsed();

    let status = res.expect("the request must return promptly, not hang").status();
    assert_eq!(status.as_u16(), 404, "a non-regular node is not a stored blob");
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "the request must return promptly (took {elapsed:?})",
    );
    world.shutdown().await;
}

#[cfg(unix)]
extern "C" {
    #[link_name = "mkfifo"]
    fn libc_mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32;
}
