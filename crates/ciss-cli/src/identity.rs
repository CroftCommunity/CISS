//! Native ed25519 identity: generate, persist (seed only, 0600), reload, report.
//!
//! The identity is a raw 32-byte seed. The public key and the `id:` DID are pure
//! functions of it (`ciss::crypto` / `ciss::identity`), so only the seed is
//! stored — reconstructed into the server's own `Keypair` on load, which keeps
//! the client's signing byte-identical to the wire.

use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use ciss::crypto::Keypair;
use ciss::identity::derive_id;

use crate::config::Config;

/// Role label carried by the reconstructed keypair. Metadata only — it does not
/// affect the key or the derived DID.
const KEY_LABEL: &str = "client";

/// Generate a fresh native ed25519 identity, persist the seed, and return its DID.
///
/// # Errors
///
/// Fails if an identity already exists for the profile (never clobbers a key),
/// if the OS entropy source is unavailable, or if the key file cannot be written.
pub fn generate(config: &Config) -> Result<String> {
    let key_path = config.key_path();
    if key_path.exists() {
        bail!(
            "an identity already exists at {} (remove it to generate a new one)",
            key_path.display()
        );
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).context("gather entropy for a new key")?;
    write_seed(config, &seed)?;
    let did = derive_id(&Keypair::from_seed(&seed, KEY_LABEL).verifying_key());
    seed.zeroize();
    Ok(did)
}

/// Import an OpenSSH ed25519 private key as this profile's identity.
///
/// Extracts the raw 32-byte seed via the `ssh-key` parser (D1) and persists it
/// exactly as a native key, so an imported identity is indistinguishable from a
/// generated one downstream. Encrypted keys are out of v1 and refused clearly.
///
/// # Errors
///
/// Fails if an identity already exists (never clobbers), if the file is not a
/// parseable OpenSSH key, if it is encrypted, or if it is not ed25519.
pub fn import(config: &Config, path: &Path) -> Result<String> {
    let key_path = config.key_path();
    if key_path.exists() {
        bail!(
            "an identity already exists at {} (remove it to import a different key)",
            key_path.display()
        );
    }

    let pem = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let key = ssh_key::PrivateKey::from_openssh(&pem)
        .with_context(|| format!("parse OpenSSH private key {}", path.display()))?;
    if key.is_encrypted() {
        bail!(
            "{} is an encrypted (passphrase-protected) key; ciss-ctl v1 imports only \
             unencrypted ed25519 keys — decrypt it first with `ssh-keygen -p -f <path>`",
            path.display()
        );
    }
    let kp = key.key_data().ed25519().ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not an ed25519 key (algorithm: {})",
            path.display(),
            key.algorithm()
        )
    })?;

    let mut seed: [u8; 32] = kp.private.to_bytes();
    write_seed(config, &seed)?;
    let did = derive_id(&Keypair::from_seed(&seed, KEY_LABEL).verifying_key());
    seed.zeroize();
    Ok(did)
}

/// The active identity's DID.
///
/// # Errors
///
/// Fails if no identity has been generated/imported for the profile.
pub fn whoami(config: &Config) -> Result<String> {
    Ok(derive_id(&load_keypair(config)?.verifying_key()))
}

/// The profile's `id:` DID if it has a local key, else `None` (a non-erroring
/// inspect, for listing/orientation — unlike [`whoami`], which errors).
#[must_use]
pub fn profile_did(config: &Config) -> Option<String> {
    let keypair = load_keypair(config).ok()?;
    Some(derive_id(&keypair.verifying_key()))
}

/// The active identity's DID and public-key hex.
///
/// # Errors
///
/// Fails if no identity has been generated/imported for the profile.
pub fn show(config: &Config) -> Result<(String, String)> {
    let kp = load_keypair(config)?;
    Ok((derive_id(&kp.verifying_key()), kp.public_key_hex()))
}

/// Reconstruct the profile's keypair from its stored seed.
///
/// # Errors
///
/// Fails with a `key gen`-pointing message if no key exists, or if the stored
/// seed is not 32 bytes of hex.
pub fn load_keypair(config: &Config) -> Result<Keypair> {
    let key_path = config.key_path();
    let contents = std::fs::read_to_string(&key_path).map_err(|e| {
        anyhow::anyhow!(
            "no identity for this profile ({}: {e}). run `ciss-ctl key gen`",
            key_path.display()
        )
    })?;
    let mut seed = decode_seed(contents.trim())?;
    let kp = Keypair::from_seed(&seed, KEY_LABEL);
    seed.zeroize();
    Ok(kp)
}

/// Persist a raw seed as hex in the profile's key file at mode 0600, creating the
/// profile directory (0700 on unix) if needed.
fn write_seed(config: &Config, seed: &[u8; 32]) -> Result<()> {
    let dir = config.profile_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    tighten_dir(&dir)?;
    let mut hex_seed = hex::encode(seed);
    let res = write_secret_file(&config.key_path(), hex_seed.as_bytes());
    hex_seed.zeroize();
    res
}

fn decode_seed(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("stored seed is not valid hex")?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("seed must be 32 bytes, got {}", v.len()))
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // `create_new` is the race-free no-clobber guard; `mode(0o600)` closes the
    // window where the seed would otherwise exist world-readable before a chmod.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create key file {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write key file {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    // No unix mode bits; still refuse to clobber.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create key file {}", path.display()))?;
    use std::io::Write;
    f.write_all(bytes)
        .with_context(|| format!("write key file {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn tighten_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))
}

#[cfg(not(unix))]
fn tighten_dir(_dir: &Path) -> Result<()> {
    Ok(())
}
