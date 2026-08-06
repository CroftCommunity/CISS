//! Object ACL subcommands (gated reads) — Model A: an `id:` owner self-signs a
//! [`ciss::policy::PolicyRecord`] via `sign_owner` and PUTs it. Denial is
//! oracle-free (a non-grantee read is 404, never 403), enforced server-side; the
//! client's job is to build the record and pick a monotonic `seq`.

use anyhow::{bail, Context, Result};

use ciss::crypto::Keypair;
use ciss::identity::derive_id;
use ciss::policy::{PolicyRecord, ReadClass};

use crate::client::{session_for, Client};

/// Parse the `--class` value into a [`ReadClass`].
fn parse_class(s: &str) -> Result<ReadClass> {
    match s {
        "world" => Ok(ReadClass::World),
        "grantees" => Ok(ReadClass::Grantees),
        "owner" => Ok(ReadClass::Owner),
        other => bail!("--class must be world|grantees|owner, got {other:?}"),
    }
}

/// `ciss-ctl acl set <cid> --class <c> [--readers did,…]`: build and PUT a
/// self-signed policy for an object in the caller's own namespace.
///
/// The `seq` is chosen as `current + 1` (read back first), so the happy path
/// never trips the server's anti-rollback (`409`); a concurrent writer racing the
/// same `seq` is what the `409` guards.
///
/// # Errors
///
/// Fails if `--class` is invalid, the current policy cannot be read, or the PUT
/// is refused.
pub async fn set(
    client: &Client,
    keypair: &Keypair,
    cid: &str,
    class: &str,
    readers: &[String],
    json_out: bool,
) -> Result<()> {
    let read_class = parse_class(class)?;
    let did = derive_id(&keypair.verifying_key());
    let session = session_for(keypair);

    let current = client.get_object_policy(Some(&session), &did, cid).await?;
    let next_seq = current
        .as_ref()
        .and_then(|v| v["seq"].as_u64())
        .unwrap_or(0)
        + 1;

    let record = PolicyRecord::sign_owner(&did, Some(cid), read_class, readers, next_seq, keypair);
    let body = serde_json::to_vec(&record).context("serialize policy record")?;
    let seq = client.put_object_policy(&did, cid, &body).await?;

    if json_out {
        println!("{}", serde_json::json!({"cid": cid, "read_class": class, "seq": seq}));
    } else {
        println!("policy set: {cid} class={class} seq={seq}");
    }
    Ok(())
}

/// `acl set` for a **Model-C** `did:` owner: PUT a `PolicyIntent` authorized by a
/// service-auth JWT (`set_token`, `lxm=setPolicy`); CISS builds and attests the
/// record. The monotonic `seq` is read back first (`get_token`, `lxm=getPolicy`)
/// so the happy path avoids the anti-rollback `409`.
///
/// # Errors
///
/// Fails on an invalid `--class`, a policy read/write error, or a rejected token
/// (a bad Model-C credential is a hard `403`).
pub async fn set_model_c(
    client: &Client,
    owner_did: &str,
    cid: &str,
    class: &str,
    readers: &[String],
    // `(getPolicy token, setPolicy token)` — the read-back and the write credential.
    tokens: (&str, &str),
    json_out: bool,
) -> Result<()> {
    let (get_token, set_token) = tokens;
    parse_class(class)?; // validate before minting/sending
    let current = client.get_object_policy_bearer(owner_did, cid, get_token).await?;
    let next_seq = current
        .as_ref()
        .and_then(|v| v["seq"].as_u64())
        .unwrap_or(0)
        + 1;
    let intent = serde_json::json!({
        "read_class": class,
        "readers": readers,
        "seq": next_seq,
    })
    .to_string();
    let seq = client
        .put_object_policy_intent(owner_did, cid, intent.as_bytes(), set_token)
        .await?;
    if json_out {
        println!("{}", serde_json::json!({"cid": cid, "read_class": class, "seq": seq, "model": "C"}));
    } else {
        println!("policy set (Model C): {cid} class={class} seq={seq}");
    }
    Ok(())
}

/// `acl get` for a `did:` owner: read the policy via a `getPolicy` service-auth JWT.
///
/// # Errors
///
/// Fails on a connect error; a 404 (no policy, or not visible) is a clear message.
pub async fn get_model_c(
    client: &Client,
    owner_did: &str,
    cid: &str,
    get_token: &str,
    json_out: bool,
) -> Result<()> {
    match client.get_object_policy_bearer(owner_did, cid, get_token).await? {
        Some(policy) => {
            if json_out {
                println!("{policy}");
            } else {
                println!("{}", serde_json::to_string_pretty(&policy).unwrap_or_else(|_| policy.to_string()));
            }
            Ok(())
        }
        None => bail!("no policy on {cid} (or it is not visible to you)"),
    }
}

/// `ciss-ctl acl get <cid>`: read the policy on an object in the caller's own
/// namespace (the owner view — the full record including the reader set).
///
/// # Errors
///
/// Fails on a connect error; a 404 (no policy, or not visible) is reported as a
/// clear message.
pub async fn get(client: &Client, keypair: &Keypair, cid: &str, json_out: bool) -> Result<()> {
    let did = derive_id(&keypair.verifying_key());
    let session = session_for(keypair);
    match client.get_object_policy(Some(&session), &did, cid).await? {
        Some(policy) => {
            if json_out {
                println!("{policy}");
            } else {
                println!("{}", serde_json::to_string_pretty(&policy).unwrap_or_else(|_| policy.to_string()));
            }
            Ok(())
        }
        None => bail!("no policy on {cid} (or it is not visible to you)"),
    }
}
