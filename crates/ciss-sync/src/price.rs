//! The cost twin's pre-flight half (M5): price a sync **before** any byte
//! moves. The quote reuses the push planner (same logical tree, same
//! have/want diff) and the server's own linked tariff
//! (`ciss::pricing::postage_cents`), so the number the client sees is the
//! number the meter would charge — by construction, not by convention.

use std::path::Path;

use crate::backup::plan_push;
use crate::error::SyncError;
use crate::state::SyncState;
use crate::transport::{BlobTransport, ManifestSlot};

/// The complete cost picture of a sync, computed without transferring
/// anything: at-rest now, the transfer priced, and at-rest after — the
/// three numbers stack (the ceiling caps the *transfer*; at-rest is
/// always queryable and reasoned about separately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceQuote {
    /// Files in the logical tree.
    pub files: u64,
    /// Chunks the server lacks (what a backup would upload).
    pub chunks_to_upload: u64,
    /// Chunks the server already holds (dedup — priced at zero).
    pub chunks_skipped: u64,
    /// Bytes a backup would transfer (chunks + fs-manifest if missing).
    pub bytes: u64,
    /// Transfer postage in integer cents, by the server's own tariff —
    /// the number the spending ceiling caps.
    pub postage_cents: u64,
    /// Bytes currently at rest (the committed keep-set — the rent base).
    pub at_rest_bytes: u64,
    /// The rent base after this sync commits (this tree's own closure;
    /// a multi-device keep-set also retains the other heads' closures).
    pub at_rest_bytes_after: u64,
    /// Rent run-rate for the post-sync rent base, in integer cents per
    /// day, by the server's own tariff.
    pub rent_cents_per_day: u64,
}

/// Price backing up `dir` to `server`: the have/want transfer diff in bytes
/// and cents, plus the at-rest (rent-base) picture before and after.
/// Read-only on the server; nothing is uploaded or committed.
///
/// # Errors
///
/// Scan/transport failures, exactly as [`crate::backup`]'s planning half.
pub async fn price_backup<S>(
    dir: &Path,
    server: &S,
    state: Option<&mut SyncState>,
) -> Result<PriceQuote, SyncError>
where
    S: BlobTransport + ManifestSlot + Sync,
{
    let plan = plan_push(dir, server, state).await?;
    let at_rest_bytes: u64 = server
        .keep_set()
        .await?
        .map_or(0, |leaves| leaves.iter().map(|(_, size)| size).sum());
    let at_rest_bytes_after: u64 = plan.needed.iter().map(|(_, size)| size).sum();
    let quote = PriceQuote {
        files: plan.manifest.entries.len() as u64,
        chunks_to_upload: plan.chunks_to_upload,
        chunks_skipped: plan.chunks_total - plan.chunks_to_upload,
        bytes: plan.want_bytes,
        postage_cents: ciss::pricing::postage_cents(plan.want_bytes),
        at_rest_bytes,
        at_rest_bytes_after,
        rent_cents_per_day: ciss::pricing::rent_cents(at_rest_bytes_after),
    };
    tracing::info!(
        files = quote.files,
        chunks = quote.chunks_to_upload,
        skipped = quote.chunks_skipped,
        bytes = quote.bytes,
        postage_cents = quote.postage_cents,
        at_rest_bytes = quote.at_rest_bytes,
        at_rest_bytes_after = quote.at_rest_bytes_after,
        rent_cents_per_day = quote.rent_cents_per_day,
        "priced (pre-flight)"
    );
    Ok(quote)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor edge is the tariff's, pinned here so a drifted delegation
    /// (anything other than the server's own function) fails loudly.
    #[test]
    fn quote_cents_are_the_server_tariff() {
        for (bytes, cents) in [(0u64, 0u64), (999, 0), (1_000, 1), (8_192, 8), (2_097_473, 2_097)]
        {
            assert_eq!(ciss::pricing::postage_cents(bytes), cents, "{bytes} bytes");
            let quote = PriceQuote {
                files: 1,
                chunks_to_upload: 1,
                chunks_skipped: 0,
                bytes,
                postage_cents: ciss::pricing::postage_cents(bytes),
                at_rest_bytes: 0,
                at_rest_bytes_after: bytes,
                rent_cents_per_day: ciss::pricing::rent_cents(bytes),
            };
            assert_eq!(quote.postage_cents, cents);
        }
    }

    /// A store that already holds a fixed cid set; put/get are unreachable
    /// in a pricing pass (pricing must move nothing).
    struct Holding(std::collections::HashSet<String>);

    #[async_trait::async_trait]
    impl BlobTransport for Holding {
        async fn have(&self) -> Result<std::collections::HashSet<String>, SyncError> {
            Ok(self.0.clone())
        }
        async fn put(&self, _cid: &str, _bytes: &[u8]) -> Result<(), SyncError> {
            unreachable!("pricing must never upload")
        }
        async fn get(&self, _cid: &str) -> Result<Vec<u8>, SyncError> {
            unreachable!("pricing must never download")
        }
    }

    #[async_trait::async_trait]
    impl ManifestSlot for Holding {
        async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
            Ok(None)
        }
        async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
            Ok(None)
        }
        async fn frontier(&self) -> Result<Option<crate::transport::FrontierView>, SyncError> {
            Ok(None)
        }
        async fn commit_keep_set(&self, _: &[(String, u64)], _: u64) -> Result<(), SyncError> {
            unreachable!("pricing must never commit")
        }
        async fn commit_frontier(
            &self,
            _: &[(String, u64)],
            _: u64,
            _: &std::collections::BTreeMap<String, String>,
        ) -> Result<(), SyncError> {
            unreachable!("pricing must never commit")
        }
    }

    /// Dedup is priced in: with one of two files already held, the skipped
    /// count is exactly the held chunk — `total - to_upload`, not any other
    /// arithmetic — and only the missing bytes are quoted.
    #[tokio::test]
    async fn skipped_counts_the_already_held_chunks() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("held.txt"), b"already on the server").expect("write");
        std::fs::write(dir.path().join("new.txt"), b"not yet uploaded").expect("write");

        let held_chunks = crate::chunk::chunk_file(b"already on the server");
        assert_eq!(held_chunks.len(), 1, "a tiny file is one chunk");
        let have: std::collections::HashSet<String> =
            held_chunks.iter().map(|c| c.chunk_ref.sha256_hex()).collect();

        let quote =
            price_backup(dir.path(), &Holding(have), None).await.expect("price");
        assert_eq!(quote.files, 2);
        assert_eq!(quote.chunks_skipped, 1, "the held file's chunk is skipped");
        assert_eq!(quote.chunks_to_upload, 1, "the new file's chunk uploads");
        let manifest_overhead = quote.bytes - b"not yet uploaded".len() as u64;
        assert!(manifest_overhead > 0, "the fs-manifest blob rides in the quote");
    }
}
