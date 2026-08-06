//! `ciss-ctl` internals as a library, so integration tests can drive the client
//! against an in-process `ciss` server (the plan's test-harness convention) and
//! the thin `main.rs` binary is just argument parsing + dispatch.

pub mod atproto;
pub mod client;
pub mod commands;
pub mod config;
pub mod identity;
