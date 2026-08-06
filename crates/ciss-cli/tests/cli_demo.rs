//! Phase 9 end-to-end demo, as an asserting test (not a bare script, so it can
//! never silently drift from the code). Drives the **real `ciss-ctl` binary**
//! against an in-process `ciss` server through the whole capability tour:
//! identity → metered upload on both planes → meter → gated ACL → three-party
//! read. Each step is asserted, not just exit-0'd.
//!
//! A separate, `#[ignore]`d test exercises the **live** `did:` `getServiceAuth`
//! round-trip against bsky (network + `.env` creds), so the default suite stays
//! hermetic.

use std::path::{Path, PathBuf};
use std::process::Command;

use ciss::crypto::sha256_hex;
use ciss::server::{App, Blobs, Db};

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

fn home() -> PathBuf {
    let dir = std::env::temp_dir().join("ciss-ctl-demo-home");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir home");
    dir
}

/// Run `ciss-ctl` under a profile against `server`, returning (stdout, ok).
fn ctl(home: &Path, server: &str, profile: &str, args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_ciss-ctl"))
        .env("XDG_CONFIG_HOME", home)
        .args(["--server", server, "--profile", profile])
        .args(args)
        .output()
        .expect("run ciss-ctl");
    (String::from_utf8_lossy(&out.stdout).into_owned(), out.status.success())
}

/// The full hermetic capability tour, asserting each step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_capability_tour() {
    let base = spawn_server().await;
    let home = home();
    let dir = home.join("work");
    std::fs::create_dir_all(&dir).unwrap();

    // 1. Two identities.
    let (owner_did, ok) = ctl(&home, &base, "owner", &["key", "gen"]);
    let owner_did = owner_did.trim().to_owned();
    assert!(ok && owner_did.starts_with("id:"), "owner key gen: {owner_did:?}");
    let (grantee_did, ok) = ctl(&home, &base, "grantee", &["key", "gen"]);
    let grantee_did = grantee_did.trim().to_owned();
    assert!(ok && grantee_did.starts_with("id:"), "grantee key gen");
    ctl(&home, &base, "stranger", &["key", "gen"]);

    // 2. Metered upload on the S3 plane; cid == sha256(file).
    let file = dir.join("memo.txt");
    let contents = b"the capability tour memo".to_vec();
    std::fs::write(&file, &contents).unwrap();
    let (put_json, ok) = ctl(&home, &base, "owner", &["--json", "put", file.to_str().unwrap()]);
    assert!(ok, "put --via s3");
    let cid = serde_json::from_str::<serde_json::Value>(&put_json).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(cid, sha256_hex(&contents), "cid is the content address");

    // 3. Cross-plane fetch: stored via s3, read via pds — byte-identical.
    let out = dir.join("via_pds.out");
    let (_, ok) = ctl(
        &home,
        &base,
        "owner",
        &["get", &cid, "--via", "pds", "-o", out.to_str().unwrap()],
    );
    assert!(ok, "get --via pds");
    assert_eq!(std::fs::read(&out).unwrap(), contents, "cross-plane bytes identical");

    // 4. Meter reflects the transfers.
    let (meter, ok) = ctl(&home, &base, "owner", &["meter"]);
    assert!(ok && meter.contains("upload bytes"), "meter: {meter:?}");

    // 5. Gate the object to the grantee (Model A).
    let (set_out, ok) = ctl(
        &home,
        &base,
        "owner",
        &["acl", "set", &cid, "--class", "grantees", "--readers", &grantee_did],
    );
    assert!(ok && set_out.contains("seq=1"), "acl set: {set_out:?}");

    // 6. Three-party read: grantee reads, stranger is denied 404.
    let gout = dir.join("grantee.out");
    let (_, ok) = ctl(
        &home,
        &base,
        "grantee",
        &["get", &cid, "--owner", &owner_did, "-o", gout.to_str().unwrap()],
    );
    assert!(ok, "grantee reads the gated object");
    assert_eq!(std::fs::read(&gout).unwrap(), contents);

    let (_, ok) = ctl(
        &home,
        &base,
        "stranger",
        &["get", &cid, "--owner", &owner_did, "-o", dir.join("s.out").to_str().unwrap()],
    );
    assert!(!ok, "stranger read must be denied (404 -> non-zero exit)");

    // 7. Owner's acl get shows the reader set; ls omits the cid for the stranger.
    let (acl_get, ok) = ctl(&home, &base, "owner", &["acl", "get", &cid]);
    assert!(ok && acl_get.contains(&grantee_did), "owner acl get shows readers");
    let (owner_ls, _) = ctl(&home, &base, "owner", &["ls"]);
    assert!(owner_ls.contains(&cid), "owner ls lists the cid");
    let (stranger_ls, _) = ctl(&home, &base, "stranger", &["ls"]);
    assert!(!stranger_ls.contains(&cid), "stranger ls omits the gated cid");
}

/// Live `did:` round-trip: log in to a real PDS, mint a service-auth JWT, and
/// upload to an in-process CISS wired with the **production** resolver (so the
/// account's `did:plc` resolves via plc.directory). Ignored by default — it needs
/// `CISS_PDS_HOST`/`CISS_PDS_IDENTIFIER`/`CISS_PDS_APP_PASSWORD` and network.
///
/// Run with: `cargo test -p ciss-cli --test cli_demo -- --ignored live_did`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: requires bsky app-password creds (CISS_PDS_*) and network"]
async fn live_did_service_auth_round_trip() {
    let (Ok(pds_host), Ok(identifier), Ok(app_password)) = (
        std::env::var("CISS_PDS_HOST"),
        std::env::var("CISS_PDS_IDENTIFIER"),
        std::env::var("CISS_PDS_APP_PASSWORD"),
    ) else {
        eprintln!("skipping live_did: CISS_PDS_* not set");
        return;
    };
    let cred = ciss_cli::atproto::PdsCredential { pds_host, identifier, app_password };

    // In-process CISS with the production (live) resolver; its service DID is the
    // aud the CLI will discover and target.
    let cfg = ciss::did_resolver::ResolveConfig::from_env().expect("resolve config");
    let resolver = ciss::did_resolver::build_resolver(&cfg);
    let service_did = "did:web:ciss.croft.ing";
    let app = App::new("provider-master", Blobs::Memory, Db::Memory)
        .expect("build app")
        .with_did_resolver(resolver, service_did);
    let router = app.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    let base = format!("http://{addr}");

    let server = ciss_cli::client::Client::new(&base);
    let pds = reqwest::Client::new();
    let (token, account_did) = ciss_cli::atproto::mint_service_auth(
        &pds,
        &cred,
        service_did,
        "com.atproto.repo.uploadBlob",
    )
    .await
    .expect("live getServiceAuth");

    let payload = b"a blob uploaded via a live did: service-auth token".to_vec();
    let up = server.upload_blob_bearer(&token, &payload).await.expect("live bearer upload");
    assert_eq!(up.cid, sha256_hex(&payload), "content-addressed");
    let got = server.get_blob(None, &account_did, &up.cid).await.expect("read back");
    assert_eq!(got.bytes, payload, "live did: blob round-trips");
}
