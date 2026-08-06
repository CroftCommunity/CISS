//! Phase 2 wiring test: native identity generation, `whoami`, and the on-disk
//! key file's shape.
//!
//! Drives the real `ciss-ctl` binary under an isolated `$XDG_CONFIG_HOME`, and
//! cross-checks the reported DID against an independent `derive_id` over the
//! stored seed — so a mutation that mis-derives the DID, or leaks the key file
//! mode/contents, is caught.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The key file the CLI writes for the `default` profile, relative to
/// `$XDG_CONFIG_HOME`. This is the layout contract Phase 2 fixes.
const DEFAULT_KEY_REL: &str = "ciss-ctl/profiles/default/identity.key";

fn tmp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ciss-ctl-it-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create tmp home");
    dir
}

fn ciss(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ciss-ctl"));
    c.env("XDG_CONFIG_HOME", home);
    c
}

/// `key gen` then `whoami` reports an `id:` DID equal to `derive_id` over the
/// stored seed's public half — the client's identity is a pure function of the
/// persisted key, verified independently of the CLI's own derivation.
#[test]
fn key_gen_then_whoami_prints_the_derived_id_did() {
    let home = tmp_home("gen-whoami");

    let gen = ciss(&home).args(["key", "gen"]).output().expect("run key gen");
    assert!(gen.status.success(), "key gen should succeed: {gen:?}");

    let who = ciss(&home).arg("whoami").output().expect("run whoami");
    assert!(who.status.success(), "whoami should succeed: {who:?}");
    let did = String::from_utf8(who.stdout).expect("utf8").trim().to_owned();
    assert!(did.starts_with("id:"), "whoami should print an id: DID, got {did:?}");
    assert_eq!(did.len(), "id:".len() + 64, "full 64-hex digest");

    // Independent recomputation from the stored seed.
    let seed_hex = std::fs::read_to_string(home.join(DEFAULT_KEY_REL))
        .expect("read seed file")
        .trim()
        .to_owned();
    let seed_bytes: [u8; 32] = hex::decode(&seed_hex)
        .expect("seed is hex")
        .try_into()
        .expect("seed is 32 bytes");
    let kp = ciss::crypto::Keypair::from_seed(&seed_bytes, "client");
    let expected = ciss::identity::derive_id(&kp.verifying_key());
    assert_eq!(did, expected, "whoami DID must equal derive_id over the stored seed");
}

/// The key file is `0600` and holds only the raw seed — never the public key or
/// the DID (those are derivable; only the secret needs protecting, and nothing
/// else should sit in a mode-0600 file inviting a reader to trust it as public).
#[test]
#[cfg(unix)]
fn key_file_is_0600_and_seed_only() {
    use std::os::unix::fs::PermissionsExt;

    let home = tmp_home("keyfile-mode");
    let gen = ciss(&home).args(["key", "gen"]).output().expect("run key gen");
    assert!(gen.status.success(), "key gen should succeed: {gen:?}");

    let key_path = home.join(DEFAULT_KEY_REL);
    let mode = std::fs::metadata(&key_path).expect("stat key").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "key file must be 0600, got {mode:o}");

    let contents = std::fs::read_to_string(&key_path).expect("read key");
    let seed_hex = contents.trim();
    let seed_bytes: [u8; 32] = hex::decode(seed_hex).expect("hex").try_into().expect("32 bytes");
    let kp = ciss::crypto::Keypair::from_seed(&seed_bytes, "client");
    assert!(
        !contents.contains(&kp.public_key_hex()),
        "key file must not contain the public key",
    );
    assert!(!contents.contains("id:"), "key file must not contain the DID");
}

/// A second `key gen` must not silently clobber an existing identity — losing a
/// key is losing every object it owns. Fail loud instead.
#[test]
fn key_gen_refuses_to_clobber_an_existing_identity() {
    let home = tmp_home("no-clobber");
    let first = ciss(&home).args(["key", "gen"]).output().expect("first key gen");
    assert!(first.status.success());
    let first_seed = std::fs::read_to_string(home.join(DEFAULT_KEY_REL)).expect("read seed");

    let second = ciss(&home).args(["key", "gen"]).output().expect("second key gen");
    assert!(!second.status.success(), "second key gen must fail, not clobber");
    let stderr = String::from_utf8(second.stderr).expect("utf8");
    assert!(
        stderr.contains("exists") || stderr.contains("already"),
        "error should name the existing key; got {stderr:?}",
    );
    let after = std::fs::read_to_string(home.join(DEFAULT_KEY_REL)).expect("read seed");
    assert_eq!(first_seed, after, "the original seed must be untouched");
}

/// The `id:` DID of the committed passphrase-less fixture key, computed
/// independently of both the CLI and the `ssh-key` crate: decode the `.pub`
/// blob, take the trailing raw 32-byte ed25519 public key, `sha256`, prefix
/// `id:`. Pinning it as a golden value makes any mis-extraction (wrong bytes,
/// truncation, hashing the OpenSSH wrapper) a hard failure.
const FIXTURE_GOLDEN_DID: &str =
    "id:0e15628ba24e2c2189cab9dece781a0da579864bd261e7f5433bb8022b88feeb";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// `key import` of an OpenSSH ed25519 key yields the same `id:` DID as deriving
/// natively from that key's raw seed — the round-trip parity D1 proved, now a
/// standing regression wall against a decode drift.
#[test]
fn key_import_yields_the_golden_id_did() {
    let home = tmp_home("import-golden");
    let imp = ciss(&home)
        .args(["key", "import"])
        .arg(fixture("id_ed25519"))
        .output()
        .expect("run key import");
    assert!(imp.status.success(), "key import should succeed: {imp:?}");

    let who = ciss(&home).arg("whoami").output().expect("run whoami");
    assert!(who.status.success(), "whoami after import should succeed: {who:?}");
    let did = String::from_utf8(who.stdout).expect("utf8").trim().to_owned();
    assert_eq!(did, FIXTURE_GOLDEN_DID, "imported DID must match the golden value");

    // And the stored form is a native seed: `whoami` re-derives the same DID from
    // the persisted seed, so an import is indistinguishable from a native key.
    let seed_hex = std::fs::read_to_string(home.join(DEFAULT_KEY_REL)).expect("read seed");
    let seed: [u8; 32] = hex::decode(seed_hex.trim()).expect("hex").try_into().expect("32 bytes");
    let kp = ciss::crypto::Keypair::from_seed(&seed, "client");
    assert_eq!(ciss::identity::derive_id(&kp.verifying_key()), FIXTURE_GOLDEN_DID);
}

/// An encrypted (passphrase-protected) OpenSSH key is out of v1 — the CLI must
/// refuse it with a clear message, not silently fail to extract a seed.
#[test]
fn key_import_rejects_encrypted_keys() {
    let home = tmp_home("import-encrypted");
    let imp = ciss(&home)
        .args(["key", "import"])
        .arg(fixture("id_ed25519_encrypted"))
        .output()
        .expect("run key import");
    assert!(!imp.status.success(), "importing an encrypted key must fail");
    let stderr = String::from_utf8(imp.stderr).expect("utf8");
    assert!(
        stderr.contains("encrypted") || stderr.contains("passphrase"),
        "error should name the encryption; got {stderr:?}",
    );
    assert!(
        !home.join(DEFAULT_KEY_REL).exists(),
        "a rejected import must not leave a key file behind",
    );
}

/// `key import` must not clobber an existing identity any more than `key gen`.
#[test]
fn key_import_refuses_to_clobber_an_existing_identity() {
    let home = tmp_home("import-no-clobber");
    assert!(ciss(&home).args(["key", "gen"]).output().expect("gen").status.success());
    let before = std::fs::read_to_string(home.join(DEFAULT_KEY_REL)).expect("read seed");

    let imp = ciss(&home)
        .args(["key", "import"])
        .arg(fixture("id_ed25519"))
        .output()
        .expect("run key import");
    assert!(!imp.status.success(), "import over an existing key must fail");
    let after = std::fs::read_to_string(home.join(DEFAULT_KEY_REL)).expect("read seed");
    assert_eq!(before, after, "the original seed must be untouched");
}

/// `whoami` with no identity yet must fail loudly, pointing at `key gen`.
#[test]
fn whoami_without_an_identity_errors() {
    let home = tmp_home("no-identity");
    let who = ciss(&home).arg("whoami").output().expect("run whoami");
    assert!(!who.status.success(), "whoami without a key must fail");
    let stderr = String::from_utf8(who.stderr).expect("utf8");
    assert!(
        stderr.contains("key gen") || stderr.contains("no identity"),
        "error should point at key gen; got {stderr:?}",
    );
}
