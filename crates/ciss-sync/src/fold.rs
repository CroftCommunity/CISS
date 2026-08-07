//! The fold: the current tree as a **pure, deterministic, clock-free**
//! function of the heads and the base. Every device computes it locally and
//! gets the same answer — HEAD is derived, never asserted (the corpus's
//! doctrine, made executable).
//!
//! Per-path three-way decision against the last converged base:
//! - nobody changed it → keep it; everyone deleted it → it's gone;
//! - exactly one side changed (edit, add, or delete) → take that change;
//! - divergent same-content edits → converged (metadata tiebreak by entry
//!   digest — deterministic, never a clock);
//! - modify vs delete → the modification wins (non-lossy default);
//! - divergent different-content edits → **conflict**: the entry with the
//!   smallest digest keeps the path, every other lands at
//!   `<path>.conflict-<device_id>` — both contents preserved, on every
//!   device, identically.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::SyncError;
use crate::manifest::{FileEntry, FsManifest};

/// One preserved conflict: who kept the path, who moved aside.
#[derive(Debug, Clone)]
pub struct ConflictNote {
    /// The contested path.
    pub path: String,
    /// The device whose entry kept the path (smallest entry digest).
    pub winner: String,
    /// The device whose entry was preserved at `loser_path`.
    pub loser: String,
    /// Where the losing content was preserved.
    pub loser_path: String,
}

/// The fold's result: the converged tree + the conflicts it preserved.
#[derive(Debug, Clone)]
pub struct FoldOutcome {
    /// The deterministic current tree.
    pub tree: FsManifest,
    /// Conflicts materialized as conflict-copies inside `tree`.
    pub conflicts: Vec<ConflictNote>,
}

/// A deterministic digest of an entry's full content+metadata — the
/// clock-free tiebreaker.
fn entry_digest(entry: &FileEntry) -> Result<String, SyncError> {
    let bytes = serde_ipld_dagcbor::to_vec(entry)
        .map_err(|e| SyncError::Encode(format!("entry digest: {e}")))?;
    Ok(crate::chunk::Hash32({
        use sha2::Digest as _;
        sha2::Sha256::digest(&bytes).into()
    })
    .to_hex())
}

/// Whether two entries carry the same *content* (chunks + size; metadata may
/// differ and is tie-broken deterministically).
fn same_content(a: &FileEntry, b: &FileEntry) -> bool {
    a.size == b.size && a.chunks == b.chunks
}

/// Fold `heads` (`device_id → its tree`) against `base` into one tree.
///
/// # Errors
///
/// [`SyncError::Encode`] if an entry cannot be digested for the tiebreak.
pub fn fold(
    heads: &BTreeMap<String, FsManifest>,
    base: Option<&FsManifest>,
) -> Result<FoldOutcome, SyncError> {
    let mut paths: BTreeSet<&String> = BTreeSet::new();
    for tree in heads.values() {
        paths.extend(tree.entries.keys());
    }
    if let Some(b) = base {
        paths.extend(b.entries.keys());
    }

    let mut tree = FsManifest::new();
    let mut conflicts = Vec::new();
    for path in paths {
        let base_entry = base.and_then(|b| b.entries.get(path));
        // The devices that CHANGED this path relative to base (edit/add/del).
        let mut changed: Vec<(&String, Option<&FileEntry>)> = Vec::new();
        let mut unchanged_entry: Option<&FileEntry> = base_entry;
        for (device, head_tree) in heads {
            let entry = head_tree.entries.get(path);
            let is_changed = match (base_entry, entry) {
                (Some(b), Some(e)) => !same_content(b, e),
                (None, Some(_)) | (Some(_), None) => true,
                (None, None) => false,
            };
            if is_changed {
                changed.push((device, entry));
            } else if entry.is_some() {
                unchanged_entry = entry;
            }
        }

        // Distinct changed *contents* (a delete counts as one "content").
        let mut edits: Vec<(&String, &FileEntry)> = Vec::new();
        let mut any_delete = false;
        for (device, entry) in &changed {
            match entry {
                Some(e) => {
                    if !edits.iter().any(|(_, kept)| same_content(kept, e)) {
                        edits.push((device, e));
                    }
                }
                None => any_delete = true,
            }
        }

        match (edits.len(), any_delete) {
            // Nobody changed it: keep whatever the base/heads carry.
            (0, false) => {
                if let Some(e) = unchanged_entry {
                    tree.insert(path, e.clone());
                }
            }
            // Only deletions: it's gone.
            (0, true) => {}
            // One surviving content (possibly alongside deletes): it wins —
            // modify beats delete, and same-content edits converge.
            (1, _) => tree.insert(path, edits[0].1.clone()),
            // Real divergence: smallest entry digest keeps the path, every
            // other content is preserved as a conflict-copy.
            (_, _) => {
                let mut ranked: Vec<(String, &String, &FileEntry)> = edits
                    .into_iter()
                    .map(|(device, e)| Ok((entry_digest(e)?, device, e)))
                    .collect::<Result<_, SyncError>>()?;
                ranked.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
                let (_, winner_device, winner_entry) = &ranked[0];
                tree.insert(path, (*winner_entry).clone());
                for (_, loser_device, loser_entry) in &ranked[1..] {
                    let loser_path = format!("{path}.conflict-{loser_device}");
                    tree.insert(&loser_path, (*loser_entry).clone());
                    conflicts.push(ConflictNote {
                        path: path.clone(),
                        winner: (*winner_device).clone(),
                        loser: (*loser_device).clone(),
                        loser_path,
                    });
                    tracing::warn!(path = %path, winner = %winner_device, loser = %loser_device, "conflict preserved");
                }
            }
        }
    }
    Ok(FoldOutcome { tree, conflicts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::chunk_file;

    fn entry(content: &[u8], mtime: i64) -> FileEntry {
        FileEntry {
            mode: 0o644,
            mtime_secs: mtime,
            mtime_nanos: 0,
            size: content.len() as u64,
            chunks: chunk_file(content).into_iter().map(|c| c.chunk_ref).collect(),
        }
    }

    fn tree(entries: &[(&str, FileEntry)]) -> FsManifest {
        let mut m = FsManifest::new();
        for (p, e) in entries {
            m.insert(p, e.clone());
        }
        m
    }

    #[test]
    fn fold_is_deterministic_and_order_free() {
        let a = tree(&[("x.txt", entry(b"aaa", 1))]);
        let b = tree(&[("y.txt", entry(b"bbb", 2))]);
        let mut h1 = BTreeMap::new();
        h1.insert("dev-a".to_owned(), a.clone());
        h1.insert("dev-b".to_owned(), b.clone());
        let mut h2 = BTreeMap::new();
        h2.insert("dev-b".to_owned(), b);
        h2.insert("dev-a".to_owned(), a);
        let o1 = fold(&h1, None).expect("fold");
        let o2 = fold(&h2, None).expect("fold");
        assert_eq!(o1.tree, o2.tree, "insertion order can never matter");
        assert_eq!(o1.tree.entries.len(), 2);
    }

    #[test]
    fn same_content_different_metadata_converges_without_conflict() {
        let mut heads = BTreeMap::new();
        heads.insert("dev-a".to_owned(), tree(&[("f", entry(b"same", 10))]));
        heads.insert("dev-b".to_owned(), tree(&[("f", entry(b"same", 99))]));
        let o = fold(&heads, None).expect("fold");
        assert!(o.conflicts.is_empty(), "identical content is never a conflict");
        assert_eq!(o.tree.entries.len(), 1);
    }

    #[test]
    fn divergent_same_length_content_is_a_conflict() {
        // Same size, different bytes: same_content must compare chunks, not
        // just sizes (kills the `&&`→`||` and `→true` mutants the flow tests
        // only catch at the root package).
        let mut heads = BTreeMap::new();
        heads.insert("dev-a".to_owned(), tree(&[("f", entry(b"AAAA", 1))]));
        heads.insert("dev-b".to_owned(), tree(&[("f", entry(b"BBBB", 1))]));
        let o = fold(&heads, None).expect("fold");
        assert_eq!(o.conflicts.len(), 1, "different bytes of equal length still conflict");
        assert_eq!(o.tree.entries.len(), 2, "winner at f, loser at f.conflict-<dev>");
    }

    #[test]
    fn conflict_winner_is_the_smaller_entry_digest_not_the_device_name() {
        // Pin the tiebreak to the content address: find two contents whose
        // digest order OPPOSES the device-name order, and assert the digest
        // (not the alphabetically-first device) picks the winner.
        let e1 = entry(b"content one", 1);
        let e2 = entry(b"content two", 1);
        let d1 = entry_digest(&e1).expect("digest");
        let d2 = entry_digest(&e2).expect("digest");
        // Give the alphabetically-FIRST device the LARGER digest.
        let (first_dev_entry, winner_entry) =
            if d1 < d2 { (e2.clone(), e1.clone()) } else { (e1.clone(), e2.clone()) };
        let mut heads = BTreeMap::new();
        heads.insert("dev-a".to_owned(), tree(&[("f", first_dev_entry.clone())]));
        heads.insert("dev-b".to_owned(), tree(&[("f", winner_entry.clone())]));
        let o = fold(&heads, None).expect("fold");
        assert_eq!(
            o.tree.entries["f"], winner_entry,
            "the smaller entry digest keeps the path, regardless of device order"
        );
        assert_eq!(o.tree.entries["f.conflict-dev-a"], first_dev_entry);
        assert_eq!(o.conflicts[0].winner, "dev-b");
    }

    #[test]
    fn deletion_propagates_when_unopposed() {
        let base = tree(&[("gone.txt", entry(b"old", 1)), ("kept.txt", entry(b"keep", 1))]);
        let mut heads = BTreeMap::new();
        heads.insert("dev-a".to_owned(), tree(&[("kept.txt", entry(b"keep", 1))]));
        heads.insert(
            "dev-b".to_owned(),
            tree(&[("gone.txt", entry(b"old", 1)), ("kept.txt", entry(b"keep", 1))]),
        );
        let o = fold(&heads, Some(&base)).expect("fold");
        assert!(!o.tree.entries.contains_key("gone.txt"), "A's delete propagates");
        assert!(o.tree.entries.contains_key("kept.txt"));
    }
}
