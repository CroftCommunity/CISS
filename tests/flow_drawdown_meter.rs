//! Workflow tier — drawdown legibility (the B6 scaffolding, ruled
//! 2026-08-11): drawdown egress stays fully METERED at the going rate;
//! whether it bills in full, prorated, or at a special rate is a **human
//! utility judgment** at statement time — never an automatic exemption
//! (automatic free exit invites freezing a large account to use it as an
//! unmetered fileshare). The system's job is separability: egress that
//! occurs while the account is in drawdown is tagged on its signed
//! receipts and surfaced as its own meter line, so the judgment has a
//! number to act on (and `grace.rs` a figure to credit against).

mod common;

use ciss::assertion::SignedAssertion;
use ciss::crypto::derive_keypair;
use ciss::dials::{account_mode_body_fold, AccountMode, AccountModeBody, ACCOUNT_MODE_DIAL_KIND};
use ciss::identity::derive_id;
use ciss_cli::client::{session_for, Client};
use common::World;

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

/// The drawdown drain is a separable meter line: active-mode egress never
/// counts toward it, in-drawdown egress counts fully (while still billing
/// into the ordinary download total — metered, never exempted), and egress
/// after re-enabling stops counting again. The tag follows the mode in
/// effect at transfer time, so the ledger tells the whole episode's story.
#[tokio::test]
async fn drawdown_egress_is_metered_and_separable() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "drainer");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Store 1000 bytes while active.
    let body = vec![7u8; 1_000];
    let put = client.put_s3(&session, "keep.bin", &body).await.expect("upload serves");
    let meter = client.get_meter(&session).await.expect("meter");
    assert_eq!(meter.drawdown_download_bytes, 0, "nothing drained yet");

    // Active-mode egress is ordinary traffic — not part of the drain line.
    client.get_s3(Some(&session), &did, &put.cid).await.expect("active download");
    let meter = client.get_meter(&session).await.expect("meter");
    assert_eq!(meter.download_bytes, 1_000);
    assert_eq!(meter.drawdown_download_bytes, 0, "active egress is not a drain");

    // Close the books.
    client
        .put_assertion(&did, ACCOUNT_MODE_DIAL_KIND, None, &mode_dial(&did, 1, AccountMode::Drawdown, &kp))
        .await
        .expect("drawdown asserted");

    // The drain: served (B6), fully metered into the ordinary total, AND
    // tagged onto the separable drawdown line.
    client.get_s3(Some(&session), &did, &put.cid).await.expect("drawdown egress serves");
    let meter = client.get_meter(&session).await.expect("meter");
    assert_eq!(meter.download_bytes, 2_000, "drawdown egress still meters in full");
    assert_eq!(meter.drawdown_download_bytes, 1_000, "…and is separable as the drain");

    // Re-enable: the account is responsible again; egress leaves the drain line.
    client
        .put_assertion(&did, ACCOUNT_MODE_DIAL_KIND, None, &mode_dial(&did, 2, AccountMode::Active, &kp))
        .await
        .expect("re-enabled");
    client.get_s3(Some(&session), &did, &put.cid).await.expect("post-episode download");
    let meter = client.get_meter(&session).await.expect("meter");
    assert_eq!(meter.download_bytes, 3_000);
    assert_eq!(meter.drawdown_download_bytes, 1_000, "the episode's drain figure is closed");

    world.shutdown().await;
}
