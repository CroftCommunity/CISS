//! Phase 5 wiring test: the atproto blob plane and its interchangeability with
//! the S3 plane. The load-bearing proof is cross-plane fetch — a file stored one
//! way is byte-identical when fetched the other — which is exactly the CIDv1↔hex
//! bridge working. `ls` reflects the stored cids.

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::server::{App, Blobs, Db};
use ciss_cli::client::{session_for, Client};

async fn spawn_server() -> String {
    let app = App::new("provider-master", Blobs::Memory, Db::Memory).expect("build app");
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

/// A file `put --via s3` is fetchable `--via pds`, and a blob `put --via pds` is
/// fetchable `--via s3` — same bytes, same content address, both planes. This is
/// the interchangeability the client promises.
#[tokio::test]
async fn s3_and_pds_planes_are_interchangeable_over_one_digest() {
    let base = spawn_server().await;
    let client = Client::new(&base);
    let keypair = derive_keypair("client-master", "client");
    let session = session_for(&keypair);
    let did = session.did.clone();

    // s3 put -> pds get.
    let a = b"stored via the s3 plane".to_vec();
    let a_cid = sha256_hex(&a);
    let put = client.put_s3(&session, "a.txt", &a).await.expect("s3 put");
    assert_eq!(put.cid, a_cid);
    let via_pds = client.get_blob(&did, &put.cid).await.expect("pds get of an s3-stored object");
    assert_eq!(via_pds.bytes, a, "cross-plane fetch is byte-identical (s3->pds)");

    // pds put -> s3 get.
    let b = b"stored via the atproto uploadBlob plane".to_vec();
    let b_cid = sha256_hex(&b);
    let up = client.upload_blob(&session, &b).await.expect("pds put");
    assert_eq!(up.cid, b_cid, "uploadBlob's CIDv1 bridges back to the same sha256 hex");
    assert_eq!(up.bytes, b.len() as u64);
    let via_s3 = client.get_s3(&did, &up.cid).await.expect("s3 get of a pds-stored blob");
    assert_eq!(via_s3.bytes, b, "cross-plane fetch is byte-identical (pds->s3)");

    // ls reflects both stored cids (hex, matching the s3 addressing).
    let cids = client.list_blobs(&did).await.expect("list blobs");
    assert!(cids.contains(&a_cid), "ls lists the s3-stored cid, got {cids:?}");
    assert!(cids.contains(&b_cid), "ls lists the pds-stored cid, got {cids:?}");
}
