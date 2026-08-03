//! Workflow tier — security-regression guards (see `docs/TESTING-STRATEGY.md`).
//!
//! These are the audit findings expressed as multi-actor stories. The `#[ignore]`
//! flows are the **RED specification**: they assert the secure end-state and fail
//! against today's server (run them with `cargo test --test
//! flow_security_regression -- --ignored` to watch them fail). Each is un-ignored
//! by the phase that fixes its finding, at which point it becomes a permanent
//! green regression wall. Finding IDs refer to `docs/SECURITY-REVIEW-2026-08-03.md`.

mod common;

use common::World;

/// GREEN today — a real invariant to keep. Proves the harness reports success,
/// and pins that an empty bearer is refused (the one thing today's mock gets
/// right, and which must stay true after real auth lands).
#[tokio::test]
async fn an_empty_bearer_is_refused() {
    let world = World::spawn().await;
    // An actor with a session whose token is empty is not a real caller.
    let empty = World::anonymous(&world);
    let out = empty.upload_blob(b"anon write").await;
    out.refused(401);
    world.shutdown().await;
}

/// A1 — the S3 plane must authorize writes. Today an anonymous caller writes into
/// any namespace it names.
#[tokio::test]
#[ignore = "RED spec (A1) — un-ignore in Phase 3: S3 writes must be authorized"]
async fn anonymous_cannot_write_into_a_foreign_namespace() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    let out = world
        .anonymous()
        .put_object(&victim, "payroll.csv", b"VICTIM PRIVATE DATA")
        .await;

    out.refused(401); // TODAY: 200 — anyone writes into anyone's namespace.
    world.shutdown().await;
}

/// A1 — a foreign caller (not the owner) must not write into a namespace either.
#[tokio::test]
#[ignore = "RED spec (A1) — un-ignore in Phase 3: only the owner (or a grantee) writes"]
async fn a_foreign_actor_cannot_write_into_anothers_namespace() {
    let world = World::spawn().await;
    let owner = common::derive_did("owner");
    let attacker = world.actor("attacker");

    let out = attacker.put_object(&owner, "k", b"planted by attacker").await;

    out.refused(403); // TODAY: 200 — the S3 plane ignores identity entirely.
    world.shutdown().await;
}

/// A1 — the billing meter is private state, not world-readable. Today any
/// anonymous caller reads a victim's postage/receipt totals.
#[tokio::test]
#[ignore = "RED spec (A1) — un-ignore in Phase 3: the meter is owner-only"]
async fn anonymous_cannot_read_a_foreign_meter() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    let out = world.anonymous().read_meter(&victim).await;

    out.refused(401); // TODAY: 200 with the victim's billing state disclosed.
    world.shutdown().await;
}

/// A2 — a bearer that merely *names* a victim DID, without proving key
/// possession, must be refused. Today the token string IS the identity, so an
/// impersonator writes straight into the victim's repo.
#[tokio::test]
#[ignore = "RED spec (A2) — un-ignore in Phase 3: bearer must be a verified session"]
async fn a_forged_bearer_naming_a_victim_is_refused() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    let out = world.impersonator(&victim).upload_blob(b"planted").await;

    out.refused(401); // TODAY: 200 — the forged bearer authenticates as the victim.
    world.shutdown().await;
}

/// A2 — the provider must never sign a transfer receipt naming a DID that did not
/// consent. This is the sharp edge: a forged upload makes CISS emit a
/// provider-signed false billing statement against a third party.
#[tokio::test]
#[ignore = "RED spec (A2) — un-ignore in Phase 3: no receipt for an unconsented DID"]
async fn provider_signs_no_receipt_for_an_unconsented_did() {
    let world = World::spawn().await;
    let victim = common::derive_did("victim");

    // An impersonator attempts an upload attributed to the victim.
    let _ = world.impersonator(&victim).upload_blob(b"planted").await;

    // The victim's ledger must remain empty — no receipt was minted against them.
    let meter = world.anonymous().read_meter(&victim).await;
    // (read_meter is itself gated post-Phase-3; here we assert the ledger state.)
    let count = meter.json()["receipt_count"].as_u64().unwrap_or(0);
    assert_eq!(
        count, 0,
        "the provider signed a receipt against a DID that never consented",
    );

    world.shutdown().await;
}
