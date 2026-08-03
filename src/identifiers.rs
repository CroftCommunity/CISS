//! Boundary identifier validation: the untrusted `did` and content-address
//! strings a client puts in a request path or query.
//!
//! These values flow to filesystem paths, SQLite keys, ledger fields, and log
//! lines, so they are validated **at the HTTP boundary before anything else
//! touches them** — a validated [`Did`] cannot carry a path separator (traversal),
//! a newline or control byte (journald log forging), an empty value, or an absurd
//! length. This is Phase 1 of the hardening plan; it closes findings I3 and I10
//! and is the boundary half of A3.
//!
//! The types are newtypes parsed at the boundary and unwrapped for the existing
//! `String`-keyed dispatch path — so validation is a gate, not a rewrite.

use std::fmt;

/// The maximum length of a `did` identifier. atproto DIDs are far shorter; this
/// is a generous ceiling that still refuses an unbounded identifier.
const MAX_DID_LEN: usize = 256;

/// The length in hex characters of a sha-256 content address.
const CONTENT_ADDR_HEX_LEN: usize = 64;

/// Why an identifier was rejected at the boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentifierError {
    /// The identifier was empty.
    #[error("identifier is empty")]
    Empty,
    /// The identifier exceeded the length ceiling.
    #[error("identifier is too long ({len} > {max})")]
    TooLong {
        /// The rejected length.
        len: usize,
        /// The ceiling.
        max: usize,
    },
    /// The identifier did not match an accepted identifier shape.
    #[error("identifier is malformed")]
    Malformed,
}

/// A validated request identifier for a tenant: either this codebase's own
/// `id:<16 hex>` form or an atproto `did:<method>:<msid>` DID.
///
/// Construct only via [`Did::parse`]; holding a `Did` is proof the string is a
/// safe storage/log/SQL key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Did(String);

impl Did {
    /// Parse and validate a `did` from an untrusted request string.
    ///
    /// Accepts exactly `id:[0-9a-f]{16}` or `did:[a-z0-9]+:<msid>` where `msid`
    /// is a non-empty run of `[A-Za-z0-9._%:-]` (no path separator, whitespace,
    /// or control byte). Everything else is [`IdentifierError`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] for an empty, over-long, or malformed value.
    pub fn parse(raw: &str) -> Result<Self, IdentifierError> {
        if raw.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if raw.len() > MAX_DID_LEN {
            return Err(IdentifierError::TooLong {
                len: raw.len(),
                max: MAX_DID_LEN,
            });
        }
        if is_valid_did(raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(IdentifierError::Malformed)
        }
    }

    /// The validated identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the newtype, yielding the owned validated string for the
    /// `String`-keyed dispatch path.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated content address (lowercase hex sha-256) used as an S3-plane
/// object key. Rejects anything that is not exactly 64 lowercase hex characters,
/// so it can never name a filesystem path outside a tenant's content namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAddr(String);

impl ContentAddr {
    /// Parse and validate a content address from an untrusted request string.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] unless the value is exactly 64 lowercase hex
    /// characters.
    pub fn parse(raw: &str) -> Result<Self, IdentifierError> {
        if raw.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if raw.len() != CONTENT_ADDR_HEX_LEN || !is_lower_hex(raw) {
            return Err(IdentifierError::Malformed);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated content address as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the newtype, yielding the owned validated string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ContentAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether every byte is a lowercase hex digit.
fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `raw` is an accepted `did` shape (`id:<16 hex>` or `did:<method>:<msid>`).
fn is_valid_did(raw: &str) -> bool {
    if let Some(rest) = raw.strip_prefix("id:") {
        return rest.len() == 16 && is_lower_hex(rest);
    }
    if let Some(rest) = raw.strip_prefix("did:") {
        let Some((method, msid)) = rest.split_once(':') else {
            return false;
        };
        let method_ok =
            !method.is_empty() && method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let msid_ok = !msid.is_empty() && msid.bytes().all(is_msid_byte);
        return method_ok && msid_ok;
    }
    false
}

/// The bytes allowed in an atproto DID method-specific identifier: alphanumerics
/// and `. _ - : %`. Deliberately excludes `/`, `\`, whitespace, and control bytes.
fn is_msid_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'%')
}

#[cfg(test)]
mod tests {
    use super::{ContentAddr, Did, IdentifierError, MAX_DID_LEN};

    #[test]
    fn accepts_the_two_legitimate_did_shapes() {
        assert!(Did::parse("id:0123456789abcdef").is_ok(), "id:<16 hex>");
        assert!(Did::parse("did:plc:ciss-phase8-test").is_ok(), "did:plc:...");
        assert!(Did::parse("did:web:example.com").is_ok(), "did:web:...");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Did::parse(""), Err(IdentifierError::Empty));
    }

    #[test]
    fn rejects_control_and_separator_bytes() {
        // A newline (log forging), a NUL, and a path separator (traversal).
        assert_eq!(Did::parse("id:aaaa\nbbbb"), Err(IdentifierError::Malformed));
        assert_eq!(Did::parse("id:aaaa\0bbbb"), Err(IdentifierError::Malformed));
        assert_eq!(Did::parse("id:aaaa/bbbb"), Err(IdentifierError::Malformed));
        assert_eq!(Did::parse("did:web:a/b/../c"), Err(IdentifierError::Malformed));
        // An ANSI escape byte.
        assert_eq!(Did::parse("id:aa\x1b[31maa"), Err(IdentifierError::Malformed));
    }

    #[test]
    fn rejects_wrong_length_id_and_uppercase_hex() {
        assert_eq!(Did::parse("id:abc"), Err(IdentifierError::Malformed));
        assert_eq!(
            Did::parse("id:0123456789ABCDEF"),
            Err(IdentifierError::Malformed),
            "id hex must be lowercase (matches derive_id output)",
        );
    }

    #[test]
    fn rejects_unknown_scheme_and_bare_string() {
        assert_eq!(Did::parse("admin"), Err(IdentifierError::Malformed));
        assert_eq!(Did::parse("id:"), Err(IdentifierError::Malformed));
        assert_eq!(Did::parse("did:plc:"), Err(IdentifierError::Malformed));
        assert_eq!(Did::parse("did:plc"), Err(IdentifierError::Malformed));
    }

    #[test]
    fn rejects_overlong() {
        let long = format!("id:{}", "a".repeat(4096));
        assert_eq!(
            Did::parse(&long),
            Err(IdentifierError::TooLong {
                len: long.len(),
                max: MAX_DID_LEN,
            }),
        );
    }

    #[test]
    fn content_addr_accepts_only_64_lowercase_hex() {
        let good = "a".repeat(64);
        assert!(ContentAddr::parse(&good).is_ok());
        assert_eq!(ContentAddr::parse(""), Err(IdentifierError::Empty));
        assert_eq!(
            ContentAddr::parse(&"a".repeat(63)),
            Err(IdentifierError::Malformed),
            "too short",
        );
        assert_eq!(
            ContentAddr::parse(&"A".repeat(64)),
            Err(IdentifierError::Malformed),
            "uppercase hex is not the backend key form",
        );
        assert_eq!(
            ContentAddr::parse("../../../../etc/passwd"),
            Err(IdentifierError::Malformed),
            "a traversal path is not a content address",
        );
    }

    #[test]
    fn round_trips_the_validated_string() {
        let did = Did::parse("did:plc:abc123").expect("valid");
        assert_eq!(did.as_str(), "did:plc:abc123");
        assert_eq!(did.into_string(), "did:plc:abc123");
    }
}
