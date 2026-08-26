//! The enforcement-matrix meta-gate (workspace method: CroftC/.claude/ENFORCEMENT.md).
//!
//! An unwired scenario silently reads as covered; that is the failure mode this file
//! exists to kill. Three properties, mirroring croft-stack's enforcement_matrix.bats:
//! every PIN names a test function that exists; no unresolved GAP rows; and every
//! `JwtError` variant the auth crate can emit has a row in the matrix.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn matrix() -> String {
    let doc = repo_root().join("docs/ENFORCEMENT-SCENARIOS.md");
    fs::read_to_string(&doc).expect("docs/ENFORCEMENT-SCENARIOS.md must exist")
}

/// Recursively find a file by name under `dir`, skipping target/.
fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target" || n == ".git") {
                continue;
            }
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|n| n == name) {
            return Some(path);
        }
    }
    None
}


/// Find a file whose path ends with `suffix` (e.g. "ciss-auth/src/lib.rs").
fn find_by_suffix(dir: &Path, suffix: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target" || n == ".git") {
                continue;
            }
            if let Some(found) = find_by_suffix(&path, suffix) {
                return Some(found);
            }
        } else if path.to_string_lossy().ends_with(suffix) {
            return Some(path);
        }
    }
    None
}

#[test]
fn the_matrix_exists_and_carries_all_three_outcome_classes() {
    let doc = matrix();
    assert!(doc.contains("MUST ADMIT"), "matrix has no MUST ADMIT rows");
    assert!(doc.contains("MUST REFUSE"), "matrix has no MUST REFUSE rows");
    // CISS has no degrade mode today; if one is added, its rows belong here too.
}

#[test]
fn every_pin_names_a_test_function_that_exists() {
    let doc = matrix();
    let root = repo_root();
    let mut fails = Vec::new();
    let mut pins = 0;
    for token in doc.split_whitespace() {
        let Some(rest) = token.strip_prefix("PIN:") else { continue };
        let Some((file, func)) = rest.split_once("::") else { continue };
        if !file.ends_with(".rs") {
            continue;
        }
        pins += 1;
        let func = func.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
        // A pin may carry a path fragment (dir/file.rs) to disambiguate common
        // basenames like lib.rs; a bare basename resolves by filename search.
        let path = if file.contains('/') {
            find_by_suffix(&root, file)
        } else {
            find_file(&root, file)
        };
        let Some(path) = path else {
            fails.push(format!("MISSING FILE for PIN:{file}::{func}"));
            continue;
        };
        let src = fs::read_to_string(&path).unwrap_or_default();
        if !src.contains(&format!("fn {func}(")) {
            fails.push(format!("MISSING TEST {func} in {} (PIN:{file}::{func})", path.display()));
        }
    }
    assert!(pins > 20, "suspiciously few pins parsed ({pins}) — parser broken?");
    assert!(fails.is_empty(), "unwired pins:\n{}", fails.join("\n"));
}

#[test]
fn no_unresolved_gap_rows() {
    let doc = matrix();
    // Rows only (table lines) — prose describing the rule must not trip the gate.
    let gaps: Vec<&str> = doc
        .lines()
        .filter(|l| l.trim_start().starts_with('|') && l.contains("GAP"))
        .collect();
    assert!(gaps.is_empty(), "unresolved GAP rows:\n{}", gaps.join("\n"));
}

#[test]
fn every_jwt_error_variant_has_a_matrix_row() {
    let doc = matrix();
    let auth = fs::read_to_string(repo_root().join("crates/ciss-auth/src/lib.rs"))
        .expect("ciss-auth lib.rs");
    let body = auth
        .split("pub enum JwtError {")
        .nth(1)
        .expect("JwtError enum present")
        .split('}')
        .next()
        .unwrap();
    let mut missing = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        // Variant lines end with ',' and start with a capital letter; skip attrs/docs.
        let Some(name) = line.strip_suffix(',') else { continue };
        if name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && name.chars().all(|c| c.is_alphanumeric())
            && !doc.contains(name)
        {
            missing.push(name.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "JwtError variants the code can emit with no matrix row: {missing:?}"
    );
}
