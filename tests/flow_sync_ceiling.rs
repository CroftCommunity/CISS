//! Workflow tier — M5 P2: the client-side spending ceiling. A sync priced
//! over the ceiling **defers before any byte moves** — no partial upload,
//! no keep-set commit, nothing billed (E89: throttle/defer, never mint
//! debt). And the ceiling can never hold data hostage: restore runs with
//! the ceiling exhausted (exit-exempt, POSTURE invariant B6 — "they can
//! never keep your furniture").

mod common;

use std::fs;

use ciss_cli::client::{self, Client};
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup, restore, SyncError, SyncState};
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
    state.set_ceiling_cents(Some(100)).expect("set ceiling");
    let err = backup(dir.path(), &server, Some(&mut state))
        .await
        .expect_err("a sync priced over the ceiling must defer");
    match &err {
        SyncError::CeilingDeferred { needed_cents, spent_cents, ceiling_cents } => {
            assert!(*needed_cents > 2000, "the quote is the real price: {needed_cents}");
            assert_eq!(*spent_cents, 0);
            assert_eq!(*ceiling_cents, 100);
        }
        other => panic!("expected CeilingDeferred, got: {other}"),
    }

    // Deferred means DEFERRED: no blobs landed, no keep-set committed.
    let keypair = ciss::crypto::derive_keypair("flow-master", "ceilinged");
    let session = client::session_for(&keypair);
    let du = server.client().du(Some(&session), &session.did).await.expect("du");
    assert_eq!(du.objects.len(), 0, "no partial upload");
    assert!(
        server.client().get_manifest(&session.did).await.expect("get").is_none(),
        "no keep-set commit"
    );
    assert_eq!(state.spent_cents().expect("spent"), 0, "nothing was billed or ledgered");

    // Raise the ceiling: the same sync goes through and the ledger records
    // the spend at the statement's own aggregation (cents over total bytes).
    state.set_ceiling_cents(Some(10_000)).expect("raise ceiling");
    let report = backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    assert!(report.bytes_uploaded > 2 * 1024 * 1024);
    assert_eq!(
        state.spent_cents().expect("spent"),
        ciss::pricing::postage_cents(report.bytes_uploaded),
        "the ledger prices total bytes exactly as a server statement would"
    );

    // An unchanged re-sync transfers 0 bytes → 0¢ → never blocked, even at
    // a ceiling the ledger has already reached.
    state.set_ceiling_cents(Some(1)).expect("exhausted ceiling");
    let again = backup(dir.path(), &server, Some(&mut state)).await.expect("free re-sync");
    assert_eq!(again.bytes_uploaded, 0, "0-byte sync spends nothing and is never deferred");

    // B6 — exit-exempt: with the ceiling exhausted, restore still runs.
    let dst = tempfile::tempdir().expect("tempdir");
    let r = restore(dst.path(), &server, Some(&report.fs_manifest_cid))
        .await
        .expect("egress of your own data is never gated by the ceiling");
    assert_eq!(r.files, 2);
    assert_eq!(fs::read(dst.path().join("big.bin")).expect("read"), big);

    world.shutdown().await;
}
