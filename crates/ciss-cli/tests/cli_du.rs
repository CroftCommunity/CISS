//! Phase du wiring test: `du` reports per-object sizes + total for your own
//! namespace (self usage), and a cross-DID query is forbidden (403) with the
//! admin flag off (the in-process App default).

use ciss::crypto::derive_keypair;
use ciss::server::{App, Blobs, Db};
use ciss_cli::client::{session_for, Client};

async fn spawn_server() -> String {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn du_self_reports_sizes_and_cross_did_is_forbidden() {
    let base = spawn_server().await;
    let client = Client::new(&base);

    let owner = derive_keypair("du-owner", "owner");
    let owner_session = session_for(&owner);
    let owner_did = owner_session.did.clone();

    client.put_s3(&owner_session, "a", b"hello").await.expect("put a"); // 5
    client.put_s3(&owner_session, "b", b"world!!").await.expect("put b"); // 7

    // Self du: two objects, sizes 5 and 7, total 12.
    let usage = client.du(Some(&owner_session), &owner_did).await.expect("self du");
    assert_eq!(usage.total_bytes, 12, "total is 5 + 7");
    assert_eq!(usage.objects.len(), 2, "both objects listed");
    let total_from_objects: u64 = usage.objects.iter().map(|o| o.bytes).sum();
    assert_eq!(total_from_objects, usage.total_bytes, "per-object sizes sum to the total");

    // A stranger querying the owner's du → 403 (admin flag off by default).
    let stranger_session = session_for(&derive_keypair("du-stranger", "stranger"));
    let err = client
        .du(Some(&stranger_session), &owner_did)
        .await
        .expect_err("cross-DID du must be forbidden");
    assert!(err.to_string().contains("403"), "cross-DID du is 403, got {err}");
}
