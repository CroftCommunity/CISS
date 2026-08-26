//! Live enforcement rungs against the deployed surface (https://ciss.croft.ing).
//!
//! green-real grade for the matrix's LIVE rows (workspace method:
//! CroftC/.claude/ENFORCEMENT.md). Skip-guarded: runs only with CISS_LIVE=1 and
//! SKIPS LOUDLY otherwise — never silently (the 418-tests-on-one-laptop lesson).
//! Probes are read-only or refused-before-effect; they mirror docs/CLIENT-TESTING.md
//! §0 verbatim and must never write real data.

const BASE: &str = "https://ciss.croft.ing";

/// The well-formed 64-hex DID nobody holds a key for (CLIENT-TESTING.md §0).
const UNOWNED_DID: &str =
    "id:0000000000000000000000000000000000000000000000000000000000000000";

fn live() -> bool {
    if std::env::var("CISS_LIVE").as_deref() == Ok("1") {
        true
    } else {
        eprintln!("SKIPPED (live rung) — run with CISS_LIVE=1 against {BASE}");
        false
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("client")
}

#[tokio::test]
async fn live_identity_is_served() {
    if !live() {
        return;
    }
    let resp = client()
        .get(format!("{BASE}/.well-known/did.json"))
        .send()
        .await
        .expect("reach the deployed server");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("did:web:ciss.croft.ing"),
        "did.json must carry the service DID; got: {body}"
    );
}

#[tokio::test]
async fn live_unauthenticated_write_is_refused_401() {
    if !live() {
        return;
    }
    let resp = client()
        .put(format!("{BASE}/{UNOWNED_DID}/objects/x"))
        .body("probe")
        .send()
        .await
        .expect("reach the deployed server");
    assert_eq!(
        resp.status(),
        401,
        "unauthenticated write must be refused before any effect"
    );
}

#[tokio::test]
async fn live_malformed_did_is_refused_400_before_auth() {
    if !live() {
        return;
    }
    let resp = client()
        .put(format!("{BASE}/id:not-a-did/objects/x"))
        .body("probe")
        .send()
        .await
        .expect("reach the deployed server");
    assert_eq!(
        resp.status(),
        400,
        "malformed DID must be rejected before auth is even checked"
    );
}
