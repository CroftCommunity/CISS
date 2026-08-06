//! Client configuration: where a profile's key material and credentials live.
//!
//! Layout (fixed in Phase 2, forward-compatible with the `did:` credential in
//! Phase 7):
//!
//! ```text
//! $XDG_CONFIG_HOME/ciss-ctl/
//!   profiles/
//!     <profile>/
//!       identity.key   # raw ed25519 seed hex, mode 0600 (id: profiles)
//! ```
//!
//! `$XDG_CONFIG_HOME` wins when set and non-empty; otherwise `$HOME/.config`.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// The resolved config root and the active profile name.
pub struct Config {
    root: PathBuf,
    profile: String,
}

impl Config {
    /// Resolve the config root for `profile` from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error if neither `$XDG_CONFIG_HOME` nor `$HOME` is set, so the
    /// key location cannot be determined (fail loud rather than guess).
    pub fn new(profile: &str) -> Result<Self> {
        Ok(Self {
            root: config_root()?,
            profile: profile.to_owned(),
        })
    }

    /// The directory holding this profile's key/credential files.
    #[must_use]
    pub fn profile_dir(&self) -> PathBuf {
        self.root.join("profiles").join(&self.profile)
    }

    /// The `id:` identity key file (raw seed hex, mode 0600).
    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.profile_dir().join("identity.key")
    }

    /// The `did:` PDS credential file (host + identifier + app password; no
    /// signing key — the repo key stays at the PDS, Model R). JSON, mode 0600.
    #[must_use]
    pub fn credential_path(&self) -> PathBuf {
        self.profile_dir().join("pds.json")
    }
}

/// `$XDG_CONFIG_HOME/ciss-ctl`, or `$HOME/.config/ciss-ctl` as the XDG-default
/// fallback. An empty `$XDG_CONFIG_HOME` is treated as unset (per the XDG spec).
fn config_root() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("ciss-ctl"));
        }
    }
    let home = std::env::var_os("HOME")
        .context("cannot locate config: neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".config").join("ciss-ctl"))
}
