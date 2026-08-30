//! `did:` meter (TODO §4): the CLI's client reads the account's own meter with a
//! meter-scoped service-auth JWT, exactly like `du_bearer` — offline, against the
//! real in-process App with an injected resolver (no PDS).

use std::sync::Arc;

use ciss::server::{App, Blobs, Db};
use ciss_auth::{did_key_secp256k1, mint_service_auth_jwt};
use ciss_cli::client::Client;
use ciss_resolve::{DidResolver, StaticResolver};
use k256::ecdsa::SigningKey;

const SERVICE_DID: &str = "did:web:ciss.test";
const METER_LXM: &str = "ing.croft.ciss.meter";
const FAR_FUTURE: u64 = 4_000_000_000;

async fn spawn_server(did: &str, sk: &SigningKey) -> String {
    let resolver: Arc<dyn DidResolver> =
        Arc::new(StaticResolver::default().with(did, did_key_secp256k1(sk.verifying_key())));
    let app = App::new("provider-master", Blobs::Memory, Db::Memory)
        .expect("build app")
        .with_did_resolver(resolver, SERVICE_DID);
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_did_account_reads_its_own_meter_through_the_client() {
    let sk = SigningKey::from_slice(&[0x71u8; 32]).expect("scalar");
    let did = "did:web:meter-cli.test";
    let base = spawn_server(did, &sk).await;
    let client = Client::new(&base);

    let token = mint_service_auth_jwt(&sk, did, SERVICE_DID, METER_LXM, FAR_FUTURE, Some("jti-m"));
    let meter = client.get_meter_bearer(&token, did).await.expect("did: meter");
    assert_eq!(meter.receipt_count, 0, "fresh account, empty meter");
    assert_eq!(meter.running_total_bytes, 0);
}
