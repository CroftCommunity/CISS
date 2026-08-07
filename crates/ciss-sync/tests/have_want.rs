//! Phase 2 unit guards: the have/want diff (the upload set is exactly
//! `local − have`) and the server-cid equality check (G3 — a lying or
//! misrouting server must be a hard error, never a silently wrong address).

use std::collections::HashSet;

use ciss_sync::{missing_blobs, verify_server_cid, SyncError};

fn blob(cid: &str, size: u64) -> (String, u64) {
    (cid.to_owned(), size)
}

#[test]
fn have_want_diff() {
    let local = vec![blob("aa", 1), blob("bb", 2), blob("cc", 3)];

    // Empty have-set: everything uploads, order preserved.
    let want = missing_blobs(local.clone(), &HashSet::new());
    assert_eq!(want, local);

    // Full have-set: nothing uploads.
    let all: HashSet<String> = local.iter().map(|(c, _)| c.clone()).collect();
    assert!(missing_blobs(local.clone(), &all).is_empty());

    // Partial overlap: exactly the complement uploads.
    let some: HashSet<String> = [String::from("bb")].into();
    assert_eq!(missing_blobs(local, &some), vec![blob("aa", 1), blob("cc", 3)]);
}

#[test]
fn server_cid_matches_local() {
    // Agreement passes.
    assert!(verify_server_cid("abc123", "abc123").is_ok());

    // Disagreement is a hard error naming both sides (G3).
    let err = verify_server_cid("abc123", "def456").expect_err("mismatch must fail");
    match err {
        SyncError::CidMismatch { expected, got } => {
            assert_eq!(expected, "abc123");
            assert_eq!(got, "def456");
        }
        other => panic!("wrong error variant: {other:?}"),
    }
}

#[test]
fn ci_gate_bite_check() {
    assert!(false, "deliberate red: verifying the CI gate bites");
}
