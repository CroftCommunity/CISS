//! Workflow tier — input-scoping guards (Phase 1). A `did`/`cid` carrying a
//! newline, control byte, path separator, empty value, or absurd length must be
//! refused at the boundary, before it reaches a log line, a filesystem path, or
//! a SQL bind. Closes I3 (journald log forging) and I10 (junk identifiers), and
//! is the boundary half of the A3 path-traversal fix. Finding IDs refer to
//! `docs/SECURITY-REVIEW-2026-08-03.md`.

mod common;

use common::World;

/// I3 — a `did` carrying a newline would forge a journald log line. It must be
/// refused before it is ever logged.
#[tokio::test]
async fn a_did_with_a_newline_is_refused() {
    let world = World::spawn().await;
    // `%0A` decodes to a newline in the path segment.
    let out = world.anonymous().read_meter("id:aaaa%0Abbbb").await;
    out.refused(400);
    world.shutdown().await;
}

/// I10 — a `did` carrying a NUL / control byte is not a valid identifier.
#[tokio::test]
async fn a_did_with_a_control_byte_is_refused() {
    let world = World::spawn().await;
    let out = world.anonymous().read_meter("id:aaaa%00bbbb").await;
    out.refused(400);
    world.shutdown().await;
}

/// I10 / A3 — a `did` carrying a path separator must be refused (it would select
/// a nested or escaping filesystem path).
#[tokio::test]
async fn a_did_with_a_path_separator_is_refused() {
    let world = World::spawn().await;
    let out = world
        .anonymous()
        .put_object("id:aaaa%2Fbbbb", "k", b"x")
        .await;
    out.refused(400);
    world.shutdown().await;
}

/// I10 — the empty string is not a valid tenant identity.
#[tokio::test]
async fn an_empty_did_is_refused() {
    let world = World::spawn().await;
    let resp = reqwest::Client::new()
        .get(world.url("//meter"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 400, "empty did must be refused");
    world.shutdown().await;
}

/// I10 — an absurdly long `did` is refused (no unbounded identifier).
#[tokio::test]
async fn an_overlong_did_is_refused() {
    let world = World::spawn().await;
    let did = format!("id:{}", "a".repeat(4096));
    let out = world.anonymous().read_meter(&did).await;
    out.refused(400);
    world.shutdown().await;
}

/// A well-formed `did` and content address still work (the guard rejects junk,
/// not legitimate identifiers) — the PDS-compat path stays open.
#[tokio::test]
async fn a_well_formed_identifier_is_accepted() {
    let world = World::spawn().await;
    let legit = world.actor("legit");
    let did = legit.did().to_owned();
    // A store (authenticated) + public fetch round-trip over valid identifiers.
    let cid = legit.put_object(&did, "note", b"hello").await.ok().cid();
    world.anonymous().get_object(&did, &cid).await.returns(b"hello");
    world.shutdown().await;
}
