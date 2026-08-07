//! M2 Phase 1: the storage primitives — the budgeted content-addressed chunk
//! cache (LRU + pin, verify-on-read), the placeholder store, and the per-tree
//! sync state root. Pure, offline, through the public API only.

use ciss_sync::{ChunkCache, FileEntry, SyncState};

fn cid_of(bytes: &[u8]) -> String {
    ciss::crypto::sha256_hex(bytes)
}

fn entry(seed: u8) -> FileEntry {
    let bytes = vec![seed; 100_000];
    let chunks = ciss_sync::chunk_file(&bytes).into_iter().map(|c| c.chunk_ref).collect();
    FileEntry { mode: 0o644, mtime_secs: 1_754_000_000, mtime_nanos: 1, size: 100_000, chunks }
}

#[test]
fn cache_budget_lru() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Budget fits exactly two 100-byte blobs.
    let mut cache = ChunkCache::open(dir.path().join("cache"), 200).expect("open");

    let a = vec![1u8; 100];
    let b = vec![2u8; 100];
    let c = vec![3u8; 100];
    let (cid_a, cid_b, cid_c) = (cid_of(&a), cid_of(&b), cid_of(&c));

    assert!(cache.insert(&cid_a, &a).expect("insert a"));
    assert!(cache.insert(&cid_b, &b).expect("insert b"));
    assert_eq!(cache.total_bytes().expect("total"), 200, "exact-budget fit is allowed");

    // Touch `a` so `b` becomes the LRU victim when `c` arrives.
    assert!(cache.get(&cid_a).expect("get a").is_some());
    assert!(cache.insert(&cid_c, &c).expect("insert c"));
    assert!(cache.get(&cid_b).expect("get b").is_none(), "LRU entry must be evicted");
    assert!(cache.get(&cid_a).expect("get a").is_some(), "recently used entry survives");
    assert!(cache.get(&cid_c).expect("get c").is_some());
    assert!(cache.total_bytes().expect("total") <= 200);

    // A pinned entry survives even as the LRU victim.
    assert!(cache.pin(&cid_a).expect("pin"));
    assert!(cache.get(&cid_c).expect("touch c").is_some()); // a is now LRU
    let d = vec![4u8; 100];
    cache.insert(&cid_of(&d), &d).expect("insert d");
    assert!(cache.get(&cid_a).expect("get a").is_some(), "pinned entry must never be evicted");

    // Oversize: refused outright, never stored-then-evicted.
    let huge = vec![5u8; 300];
    assert!(!cache.insert(&cid_of(&huge), &huge).expect("insert huge"), "oversize refused");
    assert!(cache.get(&cid_of(&huge)).expect("get huge").is_none());

    // A blob exactly the size of the budget is allowed (the cap is `>`, not `>=`).
    let mut exact = ChunkCache::open(dir.path().join("exact"), 200).expect("open");
    let full = vec![6u8; 200];
    assert!(exact.insert(&cid_of(&full), &full).expect("insert exact-budget blob"));
    assert!(exact.get(&cid_of(&full)).expect("get").is_some());

    // Budget zero: nothing is ever cached, nothing errors.
    let mut zero = ChunkCache::open(dir.path().join("zero"), 0).expect("open");
    assert!(!zero.insert(&cid_a, &a).expect("insert into zero-budget"));
}

#[test]
fn cache_pin_unpin_contracts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cache = ChunkCache::open(dir.path().join("cache"), 300).expect("open");
    assert_eq!(cache.budget(), 300);

    let a = vec![1u8; 100];
    let b = vec![2u8; 100];
    let (cid_a, cid_b) = (cid_of(&a), cid_of(&b));
    assert!(cache.insert(&cid_a, &a).expect("insert"));

    // Pin/unpin report whether the entry existed.
    assert!(cache.pin(&cid_a).expect("pin existing"));
    assert!(!cache.pin("00ff").expect("pin missing"));
    assert!(cache.unpin(&cid_a).expect("unpin existing"));
    assert!(!cache.unpin("00ff").expect("unpin missing"));

    // Once unpinned, the entry is evictable again: shrink effective room by
    // pinning `b` + inserting until `a` must go.
    assert!(cache.insert(&cid_b, &b).expect("insert b"));
    assert!(cache.pin(&cid_b).expect("pin b"));
    let c = vec![3u8; 200];
    assert!(cache.insert(&cid_of(&c), &c).expect("insert c evicting a"));
    assert!(cache.get(&cid_a).expect("get a").is_none(), "unpinned entry evicted");
    assert!(cache.get(&cid_b).expect("get b").is_some(), "pinned entry kept");

    // When pinned bytes leave no room for a new blob, insertion is refused
    // outright (the pinned set can never be evicted to make room).
    let mut tight = ChunkCache::open(dir.path().join("tight"), 150).expect("open");
    assert!(tight.insert(&cid_a, &a).expect("insert"));
    assert!(tight.pin(&cid_a).expect("pin"));
    assert!(!tight.insert(&cid_b, &b).expect("refused: pinned leaves no room"));
    assert!(tight.get(&cid_b).expect("get").is_none());
}

#[test]
fn cache_corrupt_entry_is_a_miss() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cache = ChunkCache::open(dir.path().join("cache"), 1_000_000).expect("open");

    let bytes = vec![9u8; 5_000];
    let cid = cid_of(&bytes);
    assert!(cache.insert(&cid, &bytes).expect("insert"));

    // Flip a byte in the stored blob behind the cache's back.
    let blob_path = cache.blob_path(&cid);
    let mut on_disk = std::fs::read(&blob_path).expect("read blob");
    on_disk[42] ^= 0xFF;
    std::fs::write(&blob_path, &on_disk).expect("corrupt blob");

    // A corrupt entry is a miss — removed, never returned (fail-safe).
    assert!(cache.get(&cid).expect("get").is_none(), "corrupt bytes must not be served");
    assert!(!blob_path.exists(), "the corrupt blob is deleted");
    assert_eq!(cache.total_bytes().expect("total"), 0, "accounting drops the corrupt entry");
}

#[test]
fn placeholder_roundtrip_and_state_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");

    {
        let mut state = SyncState::open(&state_dir).expect("open");
        state.placeholders.record("docs/gone.bin", &entry(7)).expect("record");
        state.placeholders.record("a.txt", &entry(8)).expect("record");
        assert_eq!(state.placeholders.get("docs/gone.bin").expect("get").expect("some"), entry(7));

        let all = state.placeholders.all().expect("all");
        assert_eq!(all.keys().collect::<Vec<_>>(), vec!["a.txt", "docs/gone.bin"]);

        state.placeholders.remove("a.txt").expect("remove");
        assert!(state.placeholders.get("a.txt").expect("get").is_none());
        state.placeholders.remove("a.txt").expect("remove is idempotent");

        // Re-recording a path replaces its entry.
        state.placeholders.record("docs/gone.bin", &entry(9)).expect("re-record");
        assert_eq!(
            state.placeholders.get("docs/gone.bin").expect("get").expect("some"),
            entry(9)
        );
    }

    // Everything survives a reopen: placeholders, the scan index table, and
    // the cache budget config.
    {
        let mut state = SyncState::open(&state_dir).expect("reopen");
        assert_eq!(
            state.placeholders.all().expect("all").keys().collect::<Vec<_>>(),
            vec!["docs/gone.bin"]
        );
        // The index shares the state root (M1 learning: outside the tree).
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("mkdir");
        std::fs::write(tree.join("f.txt"), b"indexed").expect("write");
        let m = ciss_sync::scan_tree_indexed(&tree, &mut state.index).expect("scan");
        assert_eq!(m.entries.len(), 1);
    }
}

#[test]
fn tree_id_is_stable_and_distinct() {
    let a = SyncState::tree_id("default", std::path::Path::new("/home/u/notes"));
    let b = SyncState::tree_id("default", std::path::Path::new("/home/u/notes"));
    let c = SyncState::tree_id("default", std::path::Path::new("/home/u/other"));
    let d = SyncState::tree_id("work", std::path::Path::new("/home/u/notes"));
    assert_eq!(a, b, "same profile+path → same id");
    assert_ne!(a, c, "different path → different id");
    assert_ne!(a, d, "different profile → different id");
    assert_eq!(a.len(), 16, "16-hex id");
}
