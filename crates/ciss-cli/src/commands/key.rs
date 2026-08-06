//! Identity/profile inspection: `key list`.

use anyhow::Result;

use crate::config::Config;
use crate::{atproto, identity};

/// `ciss-ctl key list`: enumerate every profile that has an identity on disk, with
/// its kind and DID/account — so you can orient before doing key work. Read-only,
/// no network. Never errors on an empty or partial store.
///
/// # Errors
///
/// Fails only if the profiles directory exists but cannot be read.
pub fn list(config: &Config, active_profile: &str, json_out: bool) -> Result<()> {
    let rows: Vec<(String, Option<String>, Option<String>, bool)> = config
        .profiles()?
        .into_iter()
        .map(|profile| {
            let pc = config.for_profile(&profile);
            let id = identity::profile_did(&pc);
            let did = atproto::profile_identifier(&pc);
            let active = profile == active_profile;
            (profile, id, did, active)
        })
        .collect();

    if json_out {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|(profile, id, did, active)| {
                serde_json::json!({ "profile": profile, "active": active, "id": id, "did": did })
            })
            .collect();
        println!("{}", serde_json::json!(arr));
        return Ok(());
    }

    if rows.is_empty() {
        println!("(no identities yet — run `ciss-ctl key gen` or `ciss-ctl login`)");
        return Ok(());
    }

    for (profile, id, did, active) in &rows {
        let marker = if *active { "* " } else { "  " };
        let (kind, ident) = match (id, did) {
            (Some(id), _) => ("id ", id.as_str()),
            (None, Some(did)) => ("did", did.as_str()),
            (None, None) => ("?  ", "(empty)"),
        };
        println!("{marker}{profile:<12} {kind}  {ident}");
    }
    println!("  (* = active profile; select another with --profile <name>)");
    Ok(())
}
