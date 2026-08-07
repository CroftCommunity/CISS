//! Phase 1 tests 1–4: chunker determinism, the size caps (integrity guard),
//! 1-byte-insert locality, and dual-hash consistency against the server's
//! own sha-256 (the local truth the transport's server-cid assert rides on).

use ciss_sync::{chunk_file, CHUNK_AVG_BYTES, CHUNK_MAX_BYTES, CHUNK_MIN_BYTES};

/// Deterministic pseudo-random bytes so failures reproduce exactly.
fn lcg_data(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

#[test]
fn chunk_boundaries_deterministic() {
    let data = lcg_data(4 * 1024 * 1024, 7);
    let a = chunk_file(&data);
    let b = chunk_file(&data);
    assert_eq!(a, b, "same bytes must produce identical chunk lists");
    assert!(a.len() > 1, "a 4 MiB corpus must split into multiple chunks");

    // Golden boundary pin (mutation audit 2026-08-07): the exact cut points of
    // this corpus under min 64 KiB / avg 256 KiB / max 1 MiB. Retuning the
    // parameters is a *reflected* decision (see the plan's tuning rationale) —
    // it must arrive here as a conscious edit, never a silent drift.
    // The digest covers the tuning parameters AND the cut points, so either
    // moving breaks the pin (a min-size drift can be invisible in the cuts of
    // any one corpus — pinning the params closes that hole).
    let mut boundary_list = format!("{CHUNK_MIN_BYTES}:{CHUNK_AVG_BYTES}:{CHUNK_MAX_BYTES}|");
    boundary_list
        .extend(a.iter().map(|c| format!("{}:{};", c.range.start, c.range.len())));
    assert_eq!(
        ciss::crypto::sha256_hex(boundary_list.as_bytes()),
        "49cb2b4e36ed3eb6f2d4eb51ddc663520196a670211e4a7b8f50835d22d451d0",
        "chunk boundaries moved — tuning constants or the cutter changed"
    );
}

#[test]
fn chunk_len_caps() {
    // Empty input: no chunks, not one empty chunk.
    assert!(chunk_file(&[]).is_empty());

    // One byte: exactly one chunk of length 1.
    let one = chunk_file(&[0x42]);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].range, 0..1);
    assert_eq!(one[0].chunk_ref.len, 1);

    // Below the minimum chunk size: still a single chunk.
    let small = lcg_data(CHUNK_MIN_BYTES / 4, 1);
    let chunks = chunk_file(&small);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].range, 0..small.len());

    // Exactly the max chunk size: the cutter is free to cut earlier at
    // content-defined boundaries — the invariant is the cap plus exact tiling,
    // not a chunk count.
    let at_max = lcg_data(CHUNK_MAX_BYTES, 2);
    let chunks = chunk_file(&at_max);
    assert!(chunks.iter().all(|c| (c.chunk_ref.len as usize) <= CHUNK_MAX_BYTES));
    assert_eq!(chunks.iter().map(|c| c.range.len()).sum::<usize>(), at_max.len());

    // One byte over the max: even if no content boundary exists, the cap
    // forces at least one split; no chunk exceeds it.
    let over_max = lcg_data(CHUNK_MAX_BYTES + 1, 3);
    let chunks = chunk_file(&over_max);
    assert!(chunks.len() >= 2, "over-max input must split");
    assert!(chunks.iter().all(|c| (c.chunk_ref.len as usize) <= CHUNK_MAX_BYTES));

    // Every chunk of a large corpus respects both this crate's cap and the
    // server's hard object cap, and the chunks tile the input exactly.
    let data = lcg_data(6 * 1024 * 1024, 4);
    let chunks = chunk_file(&data);
    let mut expected_start = 0usize;
    for c in &chunks {
        assert!(c.chunk_ref.len as usize <= CHUNK_MAX_BYTES);
        assert!(u64::from(c.chunk_ref.len) < ciss::blobstore::MAX_OBJECT_BYTES);
        assert_eq!(c.range.start, expected_start, "chunks must tile contiguously");
        assert_eq!(c.range.len(), c.chunk_ref.len as usize);
        expected_start = c.range.end;
    }
    assert_eq!(expected_start, data.len(), "chunks must cover the whole input");
}

#[test]
fn one_byte_insert_locality() {
    let data = lcg_data(4 * 1024 * 1024, 11);
    let before = chunk_file(&data);

    let mut edited = data.clone();
    edited.insert(2 * 1024 * 1024, 0xAB);
    let after = chunk_file(&edited);

    // Chunks strictly before the edit point are untouched.
    let edit_at = 2 * 1024 * 1024;
    for (b, a) in before.iter().zip(after.iter()) {
        if b.range.end <= edit_at && a.range.end <= edit_at {
            assert_eq!(b, a, "chunks before the edit window must be identical");
        } else {
            break;
        }
    }

    // Content-defined boundaries re-align: almost every chunk survives.
    let before_refs: std::collections::HashSet<_> =
        before.iter().map(|c| c.chunk_ref.clone()).collect();
    let unchanged = after.iter().filter(|c| before_refs.contains(&c.chunk_ref)).count();
    assert!(
        unchanged + 3 >= after.len(),
        "a 1-byte insert must invalidate at most a few chunks (kept {unchanged} of {})",
        after.len()
    );
}

#[test]
fn dual_hash_consistency() {
    let data = lcg_data(2 * 1024 * 1024 + 12_345, 21);
    for c in chunk_file(&data) {
        let bytes = &data[c.range.clone()];
        // sha-256 must equal the server's own derivation — this is the local
        // truth behind the transport's server-cid==local assert (G3).
        assert_eq!(c.chunk_ref.sha256_hex(), ciss::crypto::sha256_hex(bytes));
        assert_eq!(c.chunk_ref.blake3_hex(), blake3::hash(bytes).to_hex().to_string());
        assert_eq!(c.chunk_ref.len as usize, bytes.len());
    }
}
