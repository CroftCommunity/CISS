//! Phase 1 wiring test: the `ciss-ctl` binary parses global flags and exposes the
//! planned subcommand surface.
//!
//! Runs the built binary via the `CARGO_BIN_EXE_ciss-ctl` path cargo sets for
//! integration tests — no mocked process, the real dispatch path.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ciss-ctl"))
}

/// `--version` prints the crate version, so a user (and Homebrew's `brew test`)
/// can confirm which build is installed.
#[test]
fn version_flag_prints_crate_version() {
    let out = bin().arg("--version").output().expect("run --version");
    assert!(out.status.success(), "--version should exit 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "--version output {stdout:?} should contain crate version {}",
        env!("CARGO_PKG_VERSION"),
    );
}

/// `--help` lists every planned subcommand, so the surface is discoverable and a
/// dropped command is caught here rather than at runtime.
#[test]
fn help_lists_every_planned_subcommand() {
    let out = bin().arg("--help").output().expect("run --help");
    assert!(out.status.success(), "--help should exit 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    for cmd in ["key", "whoami", "put", "get", "meter", "ls", "acl"] {
        assert!(
            stdout.contains(cmd),
            "--help output should list subcommand {cmd:?}; got:\n{stdout}",
        );
    }
}

/// The documented global flags parse (they may be no-ops until their phase lands,
/// but the parser must accept them so later phases only add behaviour, not syntax).
#[test]
fn global_flags_are_accepted() {
    let out = bin()
        .args(["--server", "http://localhost:9999", "--json", "whoami"])
        .output()
        .expect("run with global flags");
    // `whoami` is an explicit not-yet-implemented stub in Phase 1: parsing must
    // succeed (no clap usage error), even though the command itself errors.
    let stderr = String::from_utf8(out.stderr).expect("utf8 stderr");
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("error: unrecognized"),
        "global flags should parse; got stderr:\n{stderr}",
    );
}
