//! Workflow tier — D3: the spend-period ceiling and the drawdown dial.
//!
//! The ceiling dial's spend half: the server refuses billable WRITES that
//! would take the period's postage past the customer's asserted cap —
//! comparison-before-serving, refuse-with-quote (402), the same marginal
//! rules as the client twin (0¢-marginal never blocked; exactly-at-X
//! passes). Periods are customer-initiated signed dials whose acceptance
//! snapshots the meter baseline (monotonic, never clock-derived). B6 in
//! code: owner egress is served past the ceiling — and billed (the
//! furniture rule: served, metered, never refused). The drawdown dial
//! closes the books to new writes (shrink-only keep-set) while egress
//! stays served; it is reversible by dial, and re-enabling means the
//! metering counts toward the bill again.

mod common;

use ciss::assertion::SignedAssertion;
use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::dials::{
    account_mode_body_fold, ceiling_body_fold, AccountMode, AccountModeBody, CeilingDialBody,
    ACCOUNT_MODE_DIAL_KIND, CEILING_DIAL_KIND, PERIOD_DIAL_KIND,
};
use ciss::identity::derive_id;
use ciss_cli::client::{session_for, Client};
use common::World;

fn ceiling_dial(
    did: &str,
    seq: u64,
    at_rest: Option<u64>,
    spend: Option<u64>,
    kp: &ciss::crypto::Keypair,
) -> Vec<u8> {
    let body = CeilingDialBody { at_rest_bytes: at_rest, spend_cents: spend };
    serde_json::to_vec(&SignedAssertion::sign_owner(
        CEILING_DIAL_KIND,
        did,
        None,
        seq,
        serde_json::to_value(body).expect("json"),
        &ceiling_body_fold(&body),
        kp,
    ))
    .expect("serialize")
}

fn period_dial(did: &str, seq: u64, kp: &ciss::crypto::Keypair) -> Vec<u8> {
    serde_json::to_vec(&SignedAssertion::sign_owner(
        PERIOD_DIAL_KIND,
        did,
        None,
        seq,
        serde_json::json!({}),
        "new_period",
        kp,
    ))
    .expect("serialize")
}

fn mode_dial(did: &str, seq: u64, mode: AccountMode, kp: &ciss::crypto::Keypair) -> Vec<u8> {
    let body = AccountModeBody { mode };
    serde_json::to_vec(&SignedAssertion::sign_owner(
        ACCOUNT_MODE_DIAL_KIND,
        did,
        None,
        seq,
        serde_json::to_value(body).expect("json"),
        &account_mode_body_fold(&body),
        kp,
    ))
    .expect("serialize")
}

/// The spend ceiling end-to-end: refuse-with-quote at 402 before serving,
/// exactly-at-X passes, owner egress serves (and bills) past the ceiling,
/// and a signed new-period dial resets the count via a baseline snapshot.
#[tokio::test]
async fn spend_ceiling_refuses_with_quote_and_periods_reset() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "spender");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Ceiling: 2¢ of postage this period.
    client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &ceiling_dial(&did, 1, None, Some(2), &kp))
        .await
        .expect("spend ceiling asserted");

    // 1_000 bytes → period total 1_000 → 1¢ ≤ 2¢: serves.
    client.put_s3(&session, "a.bin", &vec![1u8; 1_000]).await.expect("1¢ fits");
    // +1_000 → 2_000 → exactly 2¢: "stops at X" means X is spendable.
    client.put_s3(&session, "b.bin", &vec![2u8; 1_000]).await.expect("exactly-at-X passes");
    // +1_000 → 3¢ > 2¢: refused BEFORE serving, with the quote.
    let err = client
        .put_s3(&session, "c.bin", &vec![3u8; 1_000])
        .await
        .expect_err("over the spend ceiling is refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("402"), "refuse-with-quote is 402: {msg}");
    assert!(msg.contains('3') && msg.contains('2'), "the quote carries needed and ceiling: {msg}");

    // B6: owner egress serves past the ceiling — and is billed (served,
    // metered, never refused): the meter grows beyond the cap via reads.
    let blob_a_cid = sha256_hex(&vec![1u8; 1_000]);
    let got = client.get_s3(Some(&session), &did, &blob_a_cid).await.expect("egress serves");
    assert_eq!(got.bytes.len(), 1_000);
    let meter = client.get_meter(&session).await.expect("meter");
    assert!(
        meter.running_total_bytes > 2_000,
        "egress billed past the ceiling (furniture rule): {}",
        meter.running_total_bytes
    );

    // A signed new-period dial snapshots the baseline: spend resets, writes flow.
    client
        .put_assertion(&did, PERIOD_DIAL_KIND, None, &period_dial(&did, 1, &kp))
        .await
        .expect("new period asserted");
    client.put_s3(&session, "c.bin", &vec![3u8; 1_000]).await.expect("fresh period: 1¢ fits");

    world.shutdown().await;
}

/// The drawdown dial: books closed to new blobs, keep-set shrink-only,
/// egress served and billed, reversible by dial — and once re-enabled the
/// account is responsible again (writes and metering resume normally).
#[tokio::test]
async fn drawdown_closes_the_books_reversibly() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "drawdowner");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Seed: two blobs + a keep-set naming both.
    let blob1 = vec![5u8; 400];
    let blob2 = vec![6u8; 500];
    client.put_s3(&session, "one.bin", &blob1).await.expect("seed 1");
    client.put_s3(&session, "two.bin", &blob2).await.expect("seed 2");
    let (c1, c2) = (sha256_hex(&blob1), sha256_hex(&blob2));
    let leaves = |cids: &[(&str, u64)]| {
        cids.iter().map(|(c, n)| ciss::manifest::ManifestLeaf::new(c, *n as usize)).collect::<Vec<_>>()
    };
    let m1 = ciss::manifest::build_manifest(&leaves(&[(&c1, 400), (&c2, 500)]), &did, &kp, 1);
    client.put_manifest(&session, &m1).await.expect("keep-set committed");

    // Enter drawdown (a signed dial).
    client
        .put_assertion(&did, ACCOUNT_MODE_DIAL_KIND, None, &mode_dial(&did, 1, AccountMode::Drawdown, &kp))
        .await
        .expect("drawdown asserted");

    // Books closed: a NEW blob is refused; egress still serves.
    let err = client
        .put_s3(&session, "new.bin", &[9u8; 100])
        .await
        .expect_err("drawdown closes the books to new blobs");
    assert!(format!("{err:#}").contains("409"), "books-closed is a state conflict: {err:#}");
    let got = client.get_s3(Some(&session), &did, &c1).await.expect("egress serves in drawdown");
    assert_eq!(got.bytes, blob1);

    // Keep-set: shrink-only. Dropping a leaf (draining) is allowed; growth
    // is refused — draining reduces rent on the way out.
    let shrunk = ciss::manifest::build_manifest(&leaves(&[(&c1, 400)]), &did, &kp, 2);
    client.put_manifest(&session, &shrunk).await.expect("shrinking keep-set allowed");
    let grown =
        ciss::manifest::build_manifest(&leaves(&[(&c1, 400), (&c2, 500)]), &did, &kp, 3);
    let err = client
        .put_manifest(&session, &grown)
        .await
        .expect_err("a growing keep-set is refused in drawdown");
    assert!(format!("{err:#}").contains("409"), "shrink-only: {err:#}");

    // Reversible by dial: back to active, and the account is responsible
    // again — the refused write now lands.
    client
        .put_assertion(&did, ACCOUNT_MODE_DIAL_KIND, None, &mode_dial(&did, 2, AccountMode::Active, &kp))
        .await
        .expect("re-enable asserted");
    client.put_s3(&session, "new.bin", &[9u8; 100]).await.expect("re-enabled: writes resume");
    client.put_manifest(&session, &grown).await.expect("keep-set may grow again");

    world.shutdown().await;
}
