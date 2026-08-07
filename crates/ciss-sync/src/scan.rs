//! Walk a directory tree into an [`FsManifest`].
//!
//! Deterministic by construction: entries land in a `BTreeMap` keyed by
//! relative forward-slash paths, so directory read order never matters.
//! Symlinks are skipped with a warning (M1 scope: regular files only; empty
//! directories are not represented).

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::chunk::chunk_file;
use crate::error::SyncError;
use crate::index::Index;
use crate::manifest::{FileEntry, FsManifest};

fn io_err(path: &Path, source: std::io::Error) -> SyncError {
    SyncError::Io { path: path.to_path_buf(), source }
}

/// (mtime seconds, sub-second nanos) — the manifest's assertion-only mtime.
fn mtime_parts(meta: &fs::Metadata, path: &Path) -> Result<(i64, u32), SyncError> {
    let modified = meta.modified().map_err(|e| io_err(path, e))?;
    match modified.duration_since(UNIX_EPOCH) {
        Ok(d) => Ok((
            i64::try_from(d.as_secs()).map_err(|_| SyncError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other("mtime beyond i64 seconds"),
            })?,
            d.subsec_nanos(),
        )),
        // Pre-epoch mtimes: negative seconds, nanos folded in.
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).map_err(|_| SyncError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other("mtime beyond i64 seconds"),
            })?;
            Ok((-secs, d.subsec_nanos()))
        }
    }
}

fn entry_for(path: &Path, meta: &fs::Metadata) -> Result<FileEntry, SyncError> {
    let bytes = fs::read(path).map_err(|e| io_err(path, e))?;
    let (mtime_secs, mtime_nanos) = mtime_parts(meta, path)?;
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = 0o644;
    Ok(FileEntry {
        mode,
        mtime_secs,
        mtime_nanos,
        size: bytes.len() as u64,
        chunks: chunk_file(&bytes).into_iter().map(|c| c.chunk_ref).collect(),
    })
}

fn walk(
    root: &Path,
    dir: &Path,
    manifest: &mut FsManifest,
    mut index: Option<&mut Index>,
) -> Result<(), SyncError> {
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| io_err(&path, e))?;

        if file_type.is_symlink() {
            tracing::warn!(path = %path.display(), "skipping symlink (out of M1 scope)");
            continue;
        }
        if file_type.is_dir() {
            walk(root, &path, manifest, index.as_deref_mut())?;
            continue;
        }
        if !file_type.is_file() {
            tracing::warn!(path = %path.display(), "skipping non-regular file");
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .expect("not possible: every walked path is under the root");
        let key = rel
            .to_str()
            .ok_or_else(|| SyncError::NonUtf8Path(rel.to_path_buf()))?
            .replace(std::path::MAIN_SEPARATOR, "/");

        let meta = entry.metadata().map_err(|e| io_err(&path, e))?;
        let (mtime_secs, mtime_nanos) = mtime_parts(&meta, &path)?;

        let file_entry = if let Some(idx) = index.as_deref_mut() {
            if let Some(hit) = idx.lookup(&key, mtime_secs, mtime_nanos, meta.len())? {
                hit
            } else {
                let fresh = entry_for(&path, &meta)?;
                idx.store(&key, &fresh)?;
                fresh
            }
        } else {
            entry_for(&path, &meta)?
        };
        tracing::debug!(path = %key, size = file_entry.size, chunks = file_entry.chunks.len(), "scanned");
        manifest.insert(&key, file_entry);
    }
    Ok(())
}

/// Scan `root` into a manifest, chunking every file.
///
/// # Errors
///
/// [`SyncError::Io`] on filesystem failures, [`SyncError::NonUtf8Path`] for
/// paths that cannot be manifest keys.
pub fn scan_tree(root: &Path) -> Result<FsManifest, SyncError> {
    let mut manifest = FsManifest::new();
    walk(root, root, &mut manifest, None)?;
    Ok(manifest)
}

/// Scan `root` using `index` as an mtime/size "probably-unchanged" fast-path:
/// a hit reuses the stored entry (skipping the read + chunking), a miss
/// re-chunks and refreshes the index. Correctness never rides on the index —
/// an equal `(path, mtime, size)` triple is the only thing a hit trusts.
///
/// # Errors
///
/// As [`scan_tree`], plus [`SyncError::Index`] on sqlite failures.
pub fn scan_tree_indexed(root: &Path, index: &mut Index) -> Result<FsManifest, SyncError> {
    let mut manifest = FsManifest::new();
    walk(root, root, &mut manifest, Some(index))?;
    Ok(manifest)
}
