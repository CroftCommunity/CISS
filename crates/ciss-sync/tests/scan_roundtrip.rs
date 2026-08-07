//! Phase 1 test 7 — the phase's wiring-equivalent: a fixture tree through the
//! public API only (`scan_tree` → `FsManifest` → codec), proving the pieces
//! compose outside their own modules.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use ciss_sync::{scan_tree, DagCbor, ManifestCodec};

fn build_tree(root: &std::path::Path) {
    fs::create_dir_all(root.join("docs/nested")).expect("mkdir");
    fs::write(root.join("hello.txt"), b"hello ciss-sync").expect("write");
    fs::write(root.join("docs/notes.md"), vec![7u8; 200_000]).expect("write");
    // Big enough to force multiple chunks (> 1 MiB max chunk size).
    let big: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(root.join("docs/nested/big.bin"), big).expect("write");
    let script = root.join("run.sh");
    fs::write(&script, b"#!/bin/sh\necho hi\n").expect("write");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[test]
fn scan_tree_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    build_tree(dir.path());

    let m1 = scan_tree(dir.path()).expect("scan");
    let m2 = scan_tree(dir.path()).expect("rescan");
    assert_eq!(m1, m2, "an unchanged tree must scan identically");
    assert_eq!(
        m1.content_id().expect("cid"),
        m2.content_id().expect("cid"),
        "content_id must be stable across scans"
    );

    // Keys are relative, forward-slash, deterministic order.
    let paths: Vec<&str> = m1.entries.keys().map(String::as_str).collect();
    assert_eq!(paths, vec!["docs/nested/big.bin", "docs/notes.md", "hello.txt", "run.sh"]);

    // The multi-chunk file really is multi-chunk; sizes add up.
    let big = &m1.entries["docs/nested/big.bin"];
    assert!(big.chunks.len() > 1, "a 3 MiB file must split into several chunks");
    assert_eq!(big.chunks.iter().map(|c| u64::from(c.len)).sum::<u64>(), big.size);

    // The executable bit survives the scan.
    assert_eq!(m1.entries["run.sh"].mode & 0o777, 0o755);

    // The manifest round-trips through the canonical codec.
    let bytes = DagCbor.encode(&m1).expect("encode");
    assert_eq!(DagCbor.decode(&bytes).expect("decode"), m1);
}
