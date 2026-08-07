//! Phase 1: the minimal local index — an mtime/size "probably-unchanged"
//! fast-path that skips re-chunking. Correctness never rides on it: a hit
//! reuses a stored entry, a miss re-chunks, and the manifests must be equal
//! either way.

use std::fs;

use ciss_sync::{scan_tree, scan_tree_indexed, Index};

#[test]
fn index_fast_path_hits_on_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), b"alpha").expect("write");
    fs::write(dir.path().join("b.txt"), vec![3u8; 150_000]).expect("write");

    // The index lives OUTSIDE the scanned tree — scanning your own mutating
    // sqlite file would poison both the manifest and the counters.
    let index_home = tempfile::tempdir().expect("tempdir");
    let mut index = Index::open(index_home.path().join("index.sqlite")).expect("open");

    let first = scan_tree_indexed(dir.path(), &mut index).expect("scan 1");
    assert_eq!(index.hits(), 0, "a cold index cannot hit");
    assert_eq!(index.misses(), 2);

    let second = scan_tree_indexed(dir.path(), &mut index).expect("scan 2");
    assert_eq!(second, first, "the fast-path must not change the manifest");
    assert_eq!(index.hits(), 2, "an unchanged tree must hit for every file");

    // The indexed scan agrees with the pure scan — the fast-path is an
    // optimization, never an alternative truth.
    assert_eq!(scan_tree(dir.path()).expect("pure scan"), first);
}

#[test]
fn index_miss_on_modified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("mut.txt");
    fs::write(&target, b"before").expect("write");

    let index_home = tempfile::tempdir().expect("tempdir");
    let mut index = Index::open(index_home.path().join("index.sqlite")).expect("open");
    let first = scan_tree_indexed(dir.path(), &mut index).expect("scan 1");

    // Rewrite with different content (APFS mtime is ns-granular; the size
    // change alone also defeats the fast-path).
    let rewritten = b"after, and longer than before";
    fs::write(&target, rewritten).expect("rewrite");
    let second = scan_tree_indexed(dir.path(), &mut index).expect("scan 2");

    assert_ne!(second, first, "a modified file must produce a new manifest");
    assert_eq!(second.entries["mut.txt"].size, rewritten.len() as u64);
}
