//! Workflow tier — M5 P2: the client-side spending ceiling. A sync priced
//! over the ceiling **defers before any byte moves** — no partial upload,
//! no keep-set commit, nothing billed (E89: throttle/defer, never mint
//! debt). And the ceiling can never hold data hostage: restore runs with
//! the ceiling exhausted (exit-exempt, POSTURE invariant B6 — "they can
//! never keep your furniture").

mod common;

use std::fs;
use std::time::Duration;

use ciss_cli::client::{self, Client};
use ciss_cli::sync::HttpCiss;
use ciss_iroh::MeshPeer;
use ciss_sync::{backup, backup_frontier, restore, BlobTransport, SyncError, SyncState};
use common::World;

fn syncer(world: &World) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", "ceilinged");
    HttpCiss::new(Client::new(world.url("")), keypair)
}

#[tokio::test]
async fn over_ceiling_defers_whole_and_exit_stays_exempt() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("notes.txt"), b"cost-twin drill").expect("write");
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 111).map(|i| (i % 247) as u8).collect();
    fs::write(dir.path().join("big.bin"), &big).expect("write");

    let home = tempfile::tempdir().expect("tempdir");
    let mut state = SyncState::open(home.path().join("s")).expect("state");

    // A 2 MiB tree prices at ~2097¢; a 100¢ ceiling must defer it whole.
    state.ledger().set_ceiling_cents(Some(100)).expect("set ceiling");
    let err = backup(dir.path(), &server, Some(&mut state))
        .await
        .expect_err("a sync priced over the ceiling must defer");
    let needed = match &err {
        SyncError::CeilingDeferred { scope, needed_cents, spent_cents, ceiling_cents } => {
            assert_eq!(scope, "tree", "the deferring scope is named");
            assert!(*needed_cents > 2000, "the quote is the real price: {needed_cents}");
            assert_eq!(*spent_cents, 0);
            assert_eq!(*ceiling_cents, 100);
            *needed_cents
        }
        other => panic!("expected CeilingDeferred, got: {other}"),
    };

    // Deferred means DEFERRED: no blobs landed, no keep-set committed.
    let keypair = ciss::crypto::derive_keypair("flow-master", "ceilinged");
    let session = client::session_for(&keypair);
    let du = server.client().du(Some(&session), &session.did).await.expect("du");
    assert_eq!(du.objects.len(), 0, "no partial upload");
    assert!(
        server.client().get_manifest(&session.did).await.expect("get").is_none(),
        "no keep-set commit"
    );
    assert_eq!(state.ledger().spent_cents().expect("spent"), 0, "nothing was billed or ledgered");

    // "Spend stops at X" means X itself is spendable: a ceiling set to
    // EXACTLY the priced total lets the sync through — the deferral error's
    // own number is the actionable "set it here and proceed". A per-profile
    // aggregate ledger is attached too: both scopes must see the transfer.
    state.ledger().set_ceiling_cents(Some(needed)).expect("exact ceiling");
    let profile_home = tempfile::tempdir().expect("tempdir");
    let profile =
        ciss_sync::SpendLedger::open(profile_home.path().join("ledger.sqlite"), "profile")
            .expect("profile ledger");
    state.attach_profile_ledger(profile);
    let report = backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    assert!(report.bytes_uploaded > 2 * 1024 * 1024);
    assert_eq!(
        state.ledger().spent_cents().expect("spent"),
        ciss::pricing::postage_cents(report.bytes_uploaded),
        "the ledger prices total bytes exactly as a server statement would"
    );
    assert_eq!(
        state.profile_ledger().expect("attached").spent_bytes().expect("profile"),
        report.bytes_uploaded,
        "the profile aggregate saw the same transfer"
    );

    // The profile ceiling binds independently: a tiny profile ceiling defers
    // a new tree's sync even though that tree has no ceiling of its own.
    state.profile_ledger().expect("attached").set_ceiling_cents(Some(1)).expect("profile cap");
    let dir2 = tempfile::tempdir().expect("tempdir");
    fs::write(dir2.path().join("more.bin"), vec![9u8; 500_000]).expect("write");
    let home2 = tempfile::tempdir().expect("tempdir");
    let mut state2 = SyncState::open(home2.path().join("s")).expect("state");
    state2.attach_profile_ledger(
        ciss_sync::SpendLedger::open(profile_home.path().join("ledger.sqlite"), "profile")
            .expect("profile ledger"),
    );
    let err2 = backup(dir2.path(), &server, Some(&mut state2))
        .await
        .expect_err("the account-level ceiling binds every tree");
    match &err2 {
        SyncError::CeilingDeferred { scope, .. } => assert_eq!(scope, "profile"),
        other => panic!("expected profile CeilingDeferred, got: {other}"),
    }

    // A period reset preserves history: the rows survive, the new period
    // starts at zero, and the monotonic counter — never the clock — is the
    // authority.
    let tree_ledger = state.ledger();
    let before_reset = tree_ledger.spent_bytes().expect("spent");
    let new_period = tree_ledger.reset_spend().expect("reset");
    assert_eq!(new_period, 1);
    assert_eq!(tree_ledger.spent_bytes().expect("spent"), 0, "new period starts empty");
    assert_eq!(
        tree_ledger.spent_bytes_in(0).expect("history"),
        before_reset,
        "reset preserved the old period's rows"
    );

    // An unchanged re-sync transfers 0 bytes → 0¢ → never blocked, even at
    // a ceiling the ledger has already reached.
    state.ledger().set_ceiling_cents(Some(1)).expect("exhausted ceiling");
    let again = backup(dir.path(), &server, Some(&mut state)).await.expect("free re-sync");
    assert_eq!(again.bytes_uploaded, 0, "0-byte sync spends nothing and is never deferred");
    let spend_rows: i64 = rusqlite::Connection::open(state.dir().join("state.sqlite"))
        .expect("open state db")
        .query_row("SELECT COUNT(*) FROM spend", [], |r| r.get(0))
        .expect("count");
    assert_eq!(spend_rows, 1, "a 0-byte sync leaves no ledger row — only the real transfer did");

    // B6 — exit-exempt: with the ceiling exhausted, restore still runs.
    let dst = tempfile::tempdir().expect("tempdir");
    let r = restore(dst.path(), &server, Some(&report.fs_manifest_cid))
        .await
        .expect("egress of your own data is never gated by the ceiling");
    assert_eq!(r.files, 2);
    assert_eq!(fs::read(dst.path().join("big.bin")).expect("read"), big);

    world.shutdown().await;
}

/// The ceiling caps *billed* spend only: a p2p transfer costs nothing on
/// the meter (M4's whole point), so an exhausted ceiling neither defers it
/// nor lets it inflate the ledger. The server path (above) still defers.
#[tokio::test]
async fn p2p_transfers_are_free_never_deferred_never_ledgered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 99).map(|i| (i % 251) as u8).collect();
    fs::write(dir.path().join("big.bin"), &big).expect("write");
    let home = tempfile::tempdir().expect("tempdir");
    let mut state = SyncState::open(home.path().join("s")).expect("state");
    state.ledger().set_ceiling_cents(Some(1)).expect("exhausted ceiling");

    let key_a = ciss::crypto::derive_keypair("ceiling-p2p", "lineage");
    let key_b = ciss::crypto::derive_keypair("ceiling-p2p", "lineage");
    let mesh_a = MeshPeer::spawn(key_a, "dev-a", &[], None, None).await.expect("spawn a");
    // A listener so the mesh has a peer to announce to (backup commits fine
    // solo, but a real mesh is the honest shape).
    let mesh_b =
        MeshPeer::spawn(key_b, "dev-b", &[mesh_a.addr()], None, None).await.expect("spawn b");

    let report = backup_frontier(dir.path(), &mesh_a, &mut state, "dev-a")
        .await
        .expect("a free transfer is never deferred by the ceiling");
    assert!(report.bytes_uploaded > 2 * 1024 * 1024, "the bytes really moved (to the mesh)");
    assert_eq!(
        state.ledger().spent_bytes().expect("spent"),
        0,
        "free bytes never inflate the spend ledger"
    );

    mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("mesh formed");
    mesh_a.shutdown().await;
    mesh_b.shutdown().await;
}

/// The multi-device blind spot, closed: another device's billed spend —
/// invisible to this ledger — is pulled in by reconciling against the
/// meter's account total, and the profile ceiling then binds against
/// account truth, not one device's view.
#[tokio::test]
async fn reconcile_pulls_in_other_devices_spend() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("mine.bin"), vec![3u8; 600_000]).expect("write");
    let home = tempfile::tempdir().expect("tempdir");
    let mut state = SyncState::open(home.path().join("s")).expect("state");
    let profile_home = tempfile::tempdir().expect("tempdir");
    state.attach_profile_ledger(
        ciss_sync::SpendLedger::open(profile_home.path().join("ledger.sqlite"), "profile")
            .expect("profile ledger"),
    );

    let report = backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    let keypair = ciss::crypto::derive_keypair("flow-master", "ceilinged");
    let session = client::session_for(&keypair);

    // First reconcile: adopt (history == this ledger's rows, nothing added).
    let meter = server.client().get_meter(&session).await.expect("meter");
    let ledger = state.profile_ledger().expect("attached");
    matches!(
        ledger.reconcile_to_meter(meter.running_total_bytes).expect("reconcile"),
        ciss_sync::ReconcileOutcome::Adopted { .. }
    )
    .then_some(())
    .expect("first reconcile adopts");
    let before = ledger.spent_bytes().expect("spent");
    assert_eq!(before, report.bytes_uploaded);

    // "Another device": the same account uploads bytes this ledger never
    // sees (a bare client put, no SyncState anywhere).
    let foreign = vec![9u8; 250_000];
    BlobTransport::put(&server, &{
        use sha2::Digest as _;
        sha2::Sha256::digest(&foreign).iter().map(|b| format!("{b:02x}")).collect::<String>()
    }, &foreign)
    .await
    .expect("other device's upload");
    assert_eq!(ledger.spent_bytes().expect("spent"), before, "this ledger saw nothing");

    // Reconcile: the account truth lands in the profile ledger.
    let meter = server.client().get_meter(&session).await.expect("meter");
    match ledger.reconcile_to_meter(meter.running_total_bytes).expect("reconcile") {
        ciss_sync::ReconcileOutcome::CaughtUp { bytes } => {
            assert_eq!(bytes, 250_000, "exactly the other device's bytes");
        }
        other => panic!("expected CaughtUp, got {other:?}"),
    }
    assert_eq!(ledger.spent_bytes().expect("spent"), before + 250_000);

    // And the ceiling now binds against the ACCOUNT total: a ceiling just
    // under it defers the next priced sync.
    ledger.set_ceiling_cents(Some(ledger.spent_cents().expect("cents"))).expect("cap at spent");
    let dir2 = tempfile::tempdir().expect("tempdir");
    fs::write(dir2.path().join("more.bin"), vec![5u8; 900_000]).expect("write");
    let home2 = tempfile::tempdir().expect("tempdir");
    let mut state2 = SyncState::open(home2.path().join("s")).expect("state");
    state2.attach_profile_ledger(
        ciss_sync::SpendLedger::open(profile_home.path().join("ledger.sqlite"), "profile")
            .expect("profile ledger"),
    );
    let err = backup(dir2.path(), &server, Some(&mut state2))
        .await
        .expect_err("the account-truth ceiling defers");
    match &err {
        SyncError::CeilingDeferred { scope, .. } => assert_eq!(scope, "profile"),
        other => panic!("expected profile CeilingDeferred, got: {other}"),
    }

    world.shutdown().await;
}
