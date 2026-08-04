//! Workflow tier — security-regression guards (see `docs/TESTING-STRATEGY.md`).
//!
//! These are audit findings expressed as multi-actor stories. They were RED
//! against the pre-auth server and are GREEN once Phase 3 (ADR 0001) lands, then
//! stay as permanent regression walls. Finding IDs refer to
//! `docs/SECURITY-REVIEW-2026-08-03.md`.

mod common;

use common::World;

/// A2 — an unauthenticated write is refused. Proves the harness reports failure,
/// and pins that uploadBlob is never an anonymous write.
#[tokio::test]
async fn an_unauthenticated_upload_is_refused() {
    let world = World::spawn().await;
    let out = world.anonymous().upload_blob(b"anon write").await;
    out.refused(401);
    world.shutdown().await;
}

/// A1 — the S3 plane authorizes writes: an anonymous caller cannot write into a
/// namespace it does not own.
#[tokio::test]
async fn anonymous_cannot_write_into_a_foreign_namespace() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    let out = world
        .anonymous()
        .put_object(&victim, "payroll.csv", b"VICTIM PRIVATE DATA")
        .await;

    out.refused(401); // no session -> unauthenticated.
    world.shutdown().await;
}

/// A1 — an authenticated but *foreign* caller (not the owner) cannot write into
/// another DID's namespace.
#[tokio::test]
async fn a_foreign_actor_cannot_write_into_anothers_namespace() {
    let world = World::spawn().await;
    let owner = common::derive_did("owner");
    let attacker = world.actor("attacker");

    let out = attacker.put_object(&owner, "k", b"planted by attacker").await;

    out.refused(403); // authenticated as attacker, but not the owner.
    world.shutdown().await;
}

/// A1 — the billing meter is private: only the owner may read it.
#[tokio::test]
async fn anonymous_cannot_read_a_foreign_meter() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    let out = world.anonymous().read_meter(&victim).await;

    out.refused(401);
    world.shutdown().await;
}

/// A2 — a caller that merely *names* a victim DID, without its key, cannot
/// authenticate as it, so it cannot write into the victim's repo.
#[tokio::test]
async fn a_forged_session_naming_a_victim_is_refused() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    let out = world.impersonator(&victim).upload_blob(b"planted").await;

    out.refused(401); // no valid session for the victim DID.
    world.shutdown().await;
}

/// A2 — the sharp edge: the provider must never sign a transfer receipt naming a
/// DID that did not consent. A forged upload is refused, so the victim's ledger
/// stays empty (checked by the victim reading its own, owner-gated, meter).
#[tokio::test]
async fn provider_signs_no_receipt_for_an_unconsented_did() {
    let world = World::spawn().await;
    let victim = world.actor("victim");

    // An impersonator attempts an upload attributed to the victim (refused).
    world
        .impersonator(victim.did())
        .upload_blob(b"planted")
        .await
        .refused(401);

    // The victim reads its own meter: no receipt was minted against it.
    let meter = victim.read_meter(victim.did()).await;
    meter.ok();
    assert_eq!(
        meter.json()["receipt_count"].as_u64().unwrap_or(u64::MAX),
        0,
        "the provider must not sign a receipt against an unconsented DID",
    );

    world.shutdown().await;
}
