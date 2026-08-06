//! Object subcommands over the S3 plane: `put`, `get`, `meter`.
//!
//! `get` writes the fetched bytes only after they are content-verified (in
//! [`crate::client::Client::get_s3`]) and via a temp-then-rename, so a failure
//! never leaves a partial or mismatched file on disk.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::client::{Client, Session};

/// `ciss-ctl put <file> --via s3`: upload and report the receipt.
///
/// # Errors
///
/// Fails if the file cannot be read/named, or the upload is refused.
pub async fn put(client: &Client, session: &Session, file: &Path, json_out: bool) -> Result<()> {
    let body = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let key = file
        .file_name()
        .and_then(|s| s.to_str())
        .context("input file has no usable name")?;
    let res = client.put_s3(session, key, &body).await?;
    if json_out {
        println!(
            "{}",
            serde_json::json!({
                "cid": res.cid,
                "bytes": res.bytes,
                "receipt_mode": res.receipt_mode,
                "etag": res.etag,
            })
        );
    } else {
        println!("uploaded via s3");
        println!("  cid:     {}", res.cid);
        println!("  bytes:   {}", res.bytes);
        println!("  receipt: {}", res.receipt_mode);
        if let Some(etag) = &res.etag {
            println!("  etag:    {etag}");
        }
    }
    Ok(())
}

/// `ciss-ctl get <cid> --via s3`: fetch, verify against the cid, and write out.
///
/// # Errors
///
/// Fails if the object is unreachable/denied, the body does not match the cid,
/// or the output cannot be written.
pub async fn get(
    client: &Client,
    did: &str,
    cid: &str,
    output: Option<&Path>,
    json_out: bool,
) -> Result<()> {
    let res = client.get_s3(did, cid).await?;
    match output {
        Some(path) => {
            write_atomic(path, &res.bytes)?;
            if json_out {
                println!(
                    "{}",
                    serde_json::json!({
                        "cid": cid,
                        "bytes": res.bytes.len(),
                        "output": path.display().to_string(),
                    })
                );
            } else {
                println!(
                    "wrote {} bytes to {} (cid verified)",
                    res.bytes.len(),
                    path.display()
                );
            }
        }
        None => {
            std::io::stdout()
                .write_all(&res.bytes)
                .context("write bytes to stdout")?;
        }
    }
    Ok(())
}

/// `ciss-ctl meter`: show the running meter for the active identity.
///
/// # Errors
///
/// Fails if the meter read is refused or unreachable.
pub async fn meter(client: &Client, session: &Session, json_out: bool) -> Result<()> {
    let m = client.get_meter(session).await?;
    if json_out {
        println!(
            "{}",
            serde_json::json!({
                "receipt_count": m.receipt_count,
                "upload_bytes": m.upload_bytes,
                "download_bytes": m.download_bytes,
                "running_total_bytes": m.running_total_bytes,
                "postage_cents": m.postage_cents,
            })
        );
    } else {
        println!("receipts:            {}", m.receipt_count);
        println!("upload bytes:        {}", m.upload_bytes);
        println!("download bytes:      {}", m.download_bytes);
        println!("running total bytes: {}", m.running_total_bytes);
        println!("postage (cents):     {}", m.postage_cents);
    }
    Ok(())
}

/// Write `bytes` to `path` via a temp file + rename, so a partial write never
/// surfaces as the destination.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("ciss-download-tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("finalize {}", path.display()))?;
    Ok(())
}
