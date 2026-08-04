//! Workflow tier — storage-quota guards (V5). The whole-store ceiling is always
//! enforced; the per-DID cap is optional (absent ⇒ opportunistic fill); a dedup
//! write never consumes quota. Finding IDs refer to
//! `docs/SECURITY-REVIEW-2026-08-03.md`.

mod common;

use common::World;

/// V5 — a new store that would push the whole store past its ceiling is refused
/// with 507 ("store at capacity").
#[tokio::test]
async fn a_new_store_over_the_store_ceiling_is_refused() {
    // Ceiling 100 bytes, no per-DID cap (opportunistic).
    let world = World::spawn_with_limits(100, None).await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();

    owner.put_object(&did, "a", &[b'a'; 60]).await.ok(); // 60 stored
    let out = owner.put_object(&did, "b", &[b'b'; 60]).await; // 60+60 > 100
    out.refused(507);
    assert_eq!(out.text(), "store at capacity");

    world.shutdown().await;
}

/// V5 — with a per-DID cap set, a DID's new store past it is refused with 507
/// ("did storage quota exceeded"), distinctly from the store-full signal.
#[tokio::test]
async fn a_new_store_over_the_per_did_cap_is_refused() {
    // Generous store ceiling, per-DID cap 100 bytes.
    let world = World::spawn_with_limits(1_000_000, Some(100)).await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();

    owner.put_object(&did, "a", &[b'a'; 60]).await.ok();
    let out = owner.put_object(&did, "b", &[b'b'; 60]).await;
    out.refused(507);
    assert_eq!(out.text(), "did storage quota exceeded");

    world.shutdown().await;
}

/// V5 — a dedup write (re-storing an already-stored object) consumes no disk, so
/// it is allowed even when a new store of the same size would be refused.
#[tokio::test]
async fn a_dedup_write_is_allowed_even_when_full() {
    let world = World::spawn_with_limits(50, None).await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();

    let obj = [b'a'; 40];
    owner.put_object(&did, "a", &obj).await.ok(); // 40 stored (10 left under 50)

    // A new distinct object would exceed the ceiling...
    owner
        .put_object(&did, "b", &[b'b'; 40])
        .await
        .refused(507);
    // ...but re-storing the SAME object is a dedup — no new disk — so it's allowed.
    owner.put_object(&did, "a-again", &obj).await.ok();

    world.shutdown().await;
}

/// V5 — the quota gates only NEW writes: reads and metering are never refused,
/// even when the store is effectively full.
#[tokio::test]
async fn reads_and_metering_are_not_blocked_by_a_full_store() {
    let world = World::spawn_with_limits(50, None).await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();

    let cid = owner.put_object(&did, "a", &[b'a'; 40]).await.ok().cid(); // 40/50
    // A new distinct object is refused (store effectively full)...
    owner.put_object(&did, "b", &[b'b'; 40]).await.refused(507);
    // ...but the existing object still reads, and the meter still reads.
    owner.get_object(&did, &cid).await.returns(&[b'a'; 40]);
    owner.read_meter(&did).await.ok();

    world.shutdown().await;
}

/// V5 — with no per-DID cap, DIDs share the store opportunistically: one DID's
/// fill reduces what the next can store, and a store past the shared ceiling is
/// refused regardless of which DID it is (opportunistic, not per-DID-fair).
#[tokio::test]
async fn dids_share_the_store_opportunistically() {
    let world = World::spawn_with_limits(100, None).await;
    let alice = world.actor("alice");
    let bob = world.actor("bob");
    let a = alice.did().to_owned();
    let b = bob.did().to_owned();

    alice.put_object(&a, "x", &[b'a'; 60]).await.ok(); // store: 60/100
    bob.put_object(&b, "y", &[b'b'; 30]).await.ok(); // store: 90/100
    // Bob has stored only 30, but the *shared* store is near its ceiling, so his
    // next distinct object is refused.
    bob.put_object(&b, "z", &[b'c'; 30]).await.refused(507); // 90 + 30 > 100

    world.shutdown().await;
}

/// V5 — with no per-DID cap, a single DID fills opportunistically up to the store
/// ceiling with no per-DID refusal.
#[tokio::test]
async fn without_a_per_did_cap_a_did_fills_opportunistically() {
    let world = World::spawn_with_limits(1_000_000, None).await;
    let owner = world.actor("owner");
    let did = owner.did().to_owned();

    // Several distinct objects, each far above any small per-DID default — all
    // succeed because no per-DID cap is configured.
    for i in 0..5u8 {
        owner
            .put_object(&did, "k", &[i; 10_000])
            .await
            .ok();
    }

    world.shutdown().await;
}
