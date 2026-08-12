//! **Reachability gate** — is every module actually reachable from the running service?
//!
//! # Why this exists
//!
//! On 2026-08-11 five modules were found to have **no caller anywhere outside themselves**:
//! `seal`, `grace`, `dial`, `audit`, `clock`. All five are real code with real tests — `seal.rs`
//! alone has five inline tests plus two dedicated suites — and none of them can be reached from
//! the HTTP boundary. `statements.rs` is half-wired: it can be stored and loaded, but nothing in
//! the server ever constructs a `Statement`, so no period ever closes.
//!
//! Nothing was broken. But the README's architecture diagram lists *"statements · audit · seal ·
//! grace"* and calls the E0–E9 core *"proven"* — which is true **of the library** and invites the
//! false next clause, that the boundary exposes it.
//!
//! # Why the existing suite could not catch it
//!
//! The suite is two halves that never meet. The `e0..e9_*` tests import library modules directly
//! and construct **no server**; the `wiring_*` / `flow_*` tests drive the real router over HTTP.
//! **No test asserted a path between them.** So a module can be exhaustively covered and entirely
//! unreachable, with both halves green.
//!
//! **Coverage measures whether code is executed by tests. It says nothing about reachability from
//! the entry point.** A thoroughly-tested orphan has excellent coverage and zero reachability, and
//! no coverage tool distinguishes them.
//!
//! # What this gate does, and the shape that matters
//!
//! It counts callers for each `src/*.rs` module and compares against an **explicit allowlist of
//! known-unreachable modules**, each with a reason.
//!
//! - A module **not** on the allowlist with zero callers **fails** — new drift is caught the day it
//!   appears, without waiting on a cleanup that is its own project.
//! - A module **on** the allowlist that becomes reachable **also fails**, demanding its removal. The
//!   allowlist cannot rot into a permanent excuse; it can only shrink or be argued with.
//!
//! See `docs/notes/2026-08-11-reachability-audit.md`.

use std::collections::BTreeMap;
use std::path::Path;

/// Modules known to be unreachable from the boundary, with why. **This list should only shrink.**
///
/// Each entry is a capability the service does not currently have, despite the library having the
/// code for it. Removing an entry means the capability became real.
const KNOWN_UNREACHABLE: &[(&str, &str)] = &[
    (
        "seal",
        "seal/tombstone tiers — no boundary verb; needs a design decision on who signs the ceremony",
    ),
    (
        "grace",
        "grace ledger — no boundary verb; needs a design decision on who co-signs a grace event",
    ),
    (
        "dial",
        "audit-tier assurance dial — part of the unwired billing-period machinery",
    ),
    (
        "audit",
        "k-sample spot check — needs a boundary verb for 'prove you still hold a sample'",
    ),
    (
        "clock",
        "deterministic day counter — first consumer will be retention (docs/plans/2026-08-11-object-lifecycle.md)",
    ),
];

/// Modules that are infrastructure rather than capability, and legitimately have no callers.
const NOT_CAPABILITIES: &[&str] = &["lib", "main"];

/// Count files, other than the module's own source, that name `module` through a path or `use`.
fn caller_count(module: &str) -> usize {
    let needles = [
        format!("crate::{module}::"),
        format!("ciss::{module}::"),
        format!("use crate::{module};"),
        format!("use ciss::{module};"),
        format!("use crate::{module}::"),
        format!("use ciss::{module}::"),
    ];
    let own = format!("src/{module}.rs");
    let mut count = 0;
    for dir in ["src", "crates"] {
        for path in walk(Path::new(dir)) {
            let p = path.to_string_lossy().replace('\\', "/");
            if p.ends_with(&own) || !p.ends_with(".rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if needles.iter().any(|n| text.contains(n.as_str())) {
                count += 1;
            }
        }
    }
    count
}

fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn every_module_is_reachable_or_explicitly_known_not_to_be() {
    let known: BTreeMap<&str, &str> = KNOWN_UNREACHABLE.iter().copied().collect();

    let mut newly_orphaned: Vec<String> = Vec::new();
    let mut newly_reachable: Vec<String> = Vec::new();

    for path in walk(Path::new("src")) {
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let Some(module) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if NOT_CAPABILITIES.contains(&module) {
            continue;
        }

        let callers = caller_count(module);
        match (callers, known.get(module)) {
            // Unreachable and not acknowledged: this is the drift the gate exists to stop.
            (0, None) => newly_orphaned.push(format!(
                "  `src/{module}.rs` has NO caller outside itself.\n     \
                 It is unreachable from the running service. Either wire it to the boundary, or \
                 add it to KNOWN_UNREACHABLE with the reason it is not wired yet."
            )),
            // Acknowledged and now wired: good news, but the list must be kept honest.
            (n, Some(reason)) if n > 0 => newly_reachable.push(format!(
                "  `src/{module}.rs` now has {n} caller(s) — it is reachable.\n     \
                 Remove it from KNOWN_UNREACHABLE. (Listed reason was: {reason})"
            )),
            _ => {}
        }
    }

    let mut report = String::new();
    if !newly_orphaned.is_empty() {
        report.push_str(
            "\n\nUNREACHABLE MODULE(S) — built and tested, but nothing can reach them:\n\n",
        );
        report.push_str(&newly_orphaned.join("\n"));
    }
    if !newly_reachable.is_empty() {
        report.push_str("\n\nSTALE ALLOWLIST ENTRIES — these became reachable:\n\n");
        report.push_str(&newly_reachable.join("\n"));
    }

    assert!(
        report.is_empty(),
        "{report}\n\nWhy this gate exists: coverage measures whether code is EXECUTED by tests, not \
         whether it is REACHABLE from the entry point. A thoroughly-tested orphan has excellent \
         coverage and zero reachability. See docs/notes/2026-08-11-reachability-audit.md.\n"
    );
}

/// The allowlist is a debt list. This pins its size so it cannot quietly grow.
///
/// Raising this number should require saying out loud that the service gained another capability it
/// cannot reach — which is exactly the conversation the 2026-08-11 audit wished had happened
/// earlier.
#[test]
fn the_unreachable_allowlist_does_not_grow() {
    assert!(
        KNOWN_UNREACHABLE.len() <= 5,
        "KNOWN_UNREACHABLE has grown to {}. It is a debt list: it should shrink as capabilities are \
         wired, never grow. If a new module genuinely cannot be wired yet, raise this bound \
         deliberately and record why.",
        KNOWN_UNREACHABLE.len()
    );
}
