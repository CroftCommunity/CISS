//! `ciss` — CISS, the Croft Item Storage Server: a cooperative metered-storage
//! server, a Rust port of the proven `item-storage-protocol` (the E0–E9 ledger)
//! grown into a network-accessible, custom PDS-like store with metering built in.
//!
//! This crate ports the dependency-free TypeScript oracle
//! (`experiments/item-storage-protocol-standalone/`, which runs 81/81 across
//! E0–E11) module-by-module under TDD, then closes the `SEAM:`s (network
//! boundary, real blob backend, real CIDs). The build plan is
//! `discovery/alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md`.
//!
//! Current span: **E0–E9 — the complete ledger core.** Identity (E0: keypairs,
//! id derivation, sign/verify), content-addressed items + a customer-signed
//! Merkle manifest (E1–E2), transfer receipts + an append-only signed ledger with
//! canonical serialization (E3: two-mode postage metering, Bilateral | Unilateral),
//! balance-forward statements with byte-day rent + rollup/purge + per-user SQLite
//! persistence (E4), random-sample spot-check audits with the detection math over
//! a seeded RNG plus the cost-priced assurance dial (E5–E6), and the seal /
//! tombstone tiers (E7–E8: pin-a-root + fail-closed write ceremony + rotation
//! watch) with the grace ledger (E9: co-signed grace events that net to zero).
//! The E0–E9 mutation gate is green (see `ROADMAP_TODO` E86). Phases 7–9 (the
//! S3/atproto network boundary, deploy) follow the build plan.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]

pub mod assertion;
pub mod audit;
pub mod blobstore;
pub mod canonical;
pub mod cidv1;
pub mod clock;
pub mod crypto;
pub mod dial;
pub mod dials;
pub mod did_resolver;
pub mod grace;
pub mod identifiers;
pub mod identity;
pub mod item;
pub mod kv;
pub mod ledger;
pub mod manifest;
pub mod pds_api;
pub mod persist;
pub mod policy;
pub mod pricing;
pub mod receipts;
pub mod rng;
pub mod seal;
pub mod server;
pub mod statements;
