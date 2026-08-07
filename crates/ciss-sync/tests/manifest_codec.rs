//! Phase 1 tests 5–6: DAG-CBOR canonical determinism + the golden `content_id`
//! (integrity guard), and the rule that the pretty-JSON inspect view is never
//! the addressed form.

use ciss_sync::{
    chunk_file, DagCbor, FileEntry, FsManifest, ManifestCodec, PrettyJson, FS_MANIFEST_KIND,
};

/// A fixed two-entry manifest; every byte is pinned so the golden hash holds.
fn fixture(order_flipped: bool) -> FsManifest {
    let entry = |seed: u8, len: usize| {
        let bytes = vec![seed; len];
        let chunks = chunk_file(&bytes).into_iter().map(|c| c.chunk_ref).collect();
        FileEntry { mode: 0o644, mtime_secs: 1_754_000_000, mtime_nanos: 500, size: len as u64, chunks }
    };
    let mut m = FsManifest::new();
    if order_flipped {
        m.insert("b.txt", entry(2, 100));
        m.insert("a/deep.bin", entry(1, 300_000));
    } else {
        m.insert("a/deep.bin", entry(1, 300_000));
        m.insert("b.txt", entry(2, 100));
    }
    m
}

#[test]
fn dagcbor_roundtrip_and_golden_content_id() {
    let m = fixture(false);

    // Byte-determinism: repeat encodes and insertion order cannot move a byte.
    let e1 = DagCbor.encode(&m).expect("encode");
    let e2 = DagCbor.encode(&m).expect("encode");
    let e3 = DagCbor.encode(&fixture(true)).expect("encode");
    assert_eq!(e1, e2, "repeat encode must be byte-identical");
    assert_eq!(e1, e3, "entry insertion order must not change the bytes");

    // Round-trip is exact.
    let back = DagCbor.decode(&e1).expect("decode");
    assert_eq!(back, m);
    assert_eq!(back.kind, FS_MANIFEST_KIND);

    // The kind self-tag leads on the wire: outer map header, then key "kind"
    // (canonical DAG-CBOR orders keys length-first, so the 4-byte "kind"
    // precedes the 7-byte "entries"). This is the domain separation in the
    // hashed pre-image — if it moves or vanishes, the address changes silently.
    assert_eq!(e1[1], 0x64, "first map key must be a 4-byte text string");
    assert_eq!(&e1[2..6], b"kind");

    // Golden pin (captured from the first GREEN run, 2026-08-07): any silent
    // codec/schema change must break loudly here.
    assert_eq!(
        m.content_id().expect("content_id"),
        "f198fa543d3cf6c454f5050712db8daef5449b14f223b5f610db21067016153c",
        "golden content_id changed — the canonical encoding moved"
    );
}

#[test]
fn pretty_json_is_not_addressed() {
    let m = fixture(false);

    // The inspect view round-trips for tooling…
    let json = PrettyJson.encode(&m).expect("json encode");
    let back = PrettyJson.decode(&json).expect("json decode");
    assert_eq!(back, m);

    // …but the addressed identity is defined over the DAG-CBOR bytes only.
    let cbor = DagCbor.encode(&m).expect("encode");
    assert_eq!(m.content_id().expect("content_id"), ciss::crypto::sha256_hex(&cbor));
    assert_ne!(m.content_id().expect("content_id"), ciss::crypto::sha256_hex(&json));
}
