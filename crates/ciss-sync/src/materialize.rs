//! The one verified-write path: assembled, size-checked content lands at its
//! final path only via tmp-write → metadata → rename. Shared by `restore`
//! and `hydrate` so the two flows cannot drift — a failure before the rename
//! never leaves a partial file at the destination.

use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use crate::error::SyncError;
use crate::manifest::FileEntry;

fn io_err(path: &Path, source: std::io::Error) -> SyncError {
    SyncError::Io { path: path.to_path_buf(), source }
}

/// Write `content` (already chunk-verified by the caller) to `final_path`
/// atomically, restoring `mode` and `mtime` from the entry. The size is
/// checked against the entry before anything touches the destination.
pub(crate) fn write_verified_file(
    final_path: &Path,
    manifest_path: &str,
    entry: &FileEntry,
    content: &[u8],
) -> Result<(), SyncError> {
    if content.len() as u64 != entry.size {
        return Err(SyncError::Decode(format!(
            "{manifest_path}: reassembled {} bytes, manifest says {}",
            content.len(),
            entry.size
        )));
    }
    let parent = final_path.parent().expect("manifest paths are relative, never bare root");
    fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    let tmp_path = parent.join(format!(
        ".ciss-restore-{}.tmp",
        final_path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    fs::write(&tmp_path, content).map_err(|e| io_err(&tmp_path, e))?;
    restore_metadata(&tmp_path, entry)?;
    fs::rename(&tmp_path, final_path).map_err(|e| io_err(final_path, e))?;
    Ok(())
}

/// Apply `mode` and `mtime` to the file. The mtime is an assertion being
/// replayed, never an ordering input; a pre-epoch mtime is skipped with a
/// warning rather than guessed at.
fn restore_metadata(path: &Path, entry: &FileEntry) -> Result<(), SyncError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(entry.mode))
            .map_err(|e| io_err(path, e))?;
    }
    if entry.mtime_secs >= 0 {
        let mtime = UNIX_EPOCH
            + Duration::new(
                u64::try_from(entry.mtime_secs).expect("not possible: checked non-negative"),
                entry.mtime_nanos,
            );
        let file = fs::File::open(path).map_err(|e| io_err(path, e))?;
        file.set_modified(mtime).map_err(|e| io_err(path, e))?;
    } else {
        tracing::warn!(path = %path.display(), "pre-epoch mtime not restored");
    }
    Ok(())
}
