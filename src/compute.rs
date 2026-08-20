//! Per-caller compute observability (E83, stage 1 of the request-path burden
//! design — `docs/notes/rate-limiting-design.md`).
//!
//! An in-memory, **bounded** ledger of who asked for what and how long
//! dispatch spent on it: per caller, per operation class — request count and
//! total dispatch duration. Observation only: no enforcement rides on these
//! numbers (stage 2 is gated on the live data this stage produces).
//!
//! Design constraints carried from the design record:
//! - **Derived, rebuildable-shaped data** — never ledger material. Losing it
//!   on restart is acceptable; it is telemetry, not a signed fact.
//! - **Bounded memory.** The per-caller key space only grows with real,
//!   authenticated identities (anonymous traffic is one shared row), but it is
//!   still capped: past [`MAX_TRACKED_CALLERS`] the least-recently-seen caller
//!   is evicted. Trading CPU-exhaustion defense for memory exhaustion would be
//!   a bad swap.
//! - **Monotonic time only.** Durations come from `std::time::Instant` at the
//!   dispatch boundary; nothing here reads a wall clock (the standing rule:
//!   wall-clock is reference, never authority).
//! - What is measured is **dispatch time**: authorization + the op body
//!   (compute, store-mutex wait, blob I/O). It deliberately excludes network
//!   drain — a slow reader inflates nothing here. Finer dimensions (component
//!   timers, mutex hold, poll time) are later stage-1 increments.

use std::collections::HashMap;

/// The caller label for unauthenticated requests — one shared row, so
/// anonymous traffic cannot grow the map.
pub const ANONYMOUS_CALLER: &str = "anon";

/// Callers tracked before least-recently-seen eviction. Each tracked caller
/// is a real authenticated identity (or the one shared anonymous row), so the
/// bound is a memory backstop, not an expected operating point.
pub const MAX_TRACKED_CALLERS: usize = 1024;

/// One caller × class cell: how many requests, and dispatch time in total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ComputeCell {
    /// Requests dispatched.
    pub requests: u64,
    /// Total dispatch duration, microseconds (saturating).
    pub micros: u64,
}

/// One row of a ledger snapshot: caller, operation class, and the cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeRow {
    /// The caller (a DID, an `id:` identity, or [`ANONYMOUS_CALLER`]).
    pub caller: String,
    /// The operation class label (fixed set — one per dispatch `Op`).
    pub class: &'static str,
    /// The counters.
    pub cell: ComputeCell,
}

/// The bounded in-memory ledger. One per server, behind its own small mutex —
/// deliberately **not** behind the store mutex (bumping a counter must not
/// contend with the canonical write path).
#[derive(Debug, Default)]
pub struct ComputeLedger {
    /// caller → (class → cell).
    cells: HashMap<String, HashMap<&'static str, ComputeCell>>,
    /// Monotonic tick for least-recently-seen eviction.
    tick: u64,
    /// caller → last tick seen.
    seen: HashMap<String, u64>,
}

impl ComputeLedger {
    /// A fresh, empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one dispatched request: `caller` ran an op of `class` for
    /// `micros` microseconds. Evicts the least-recently-seen caller when the
    /// tracked set would exceed [`MAX_TRACKED_CALLERS`].
    pub fn record(&mut self, caller: &str, class: &'static str, micros: u64) {
        if !self.cells.contains_key(caller) && self.cells.len() >= MAX_TRACKED_CALLERS {
            if let Some(evict) = self
                .seen
                .iter()
                .min_by_key(|(_, tick)| **tick)
                .map(|(caller, _)| caller.clone())
            {
                self.cells.remove(&evict);
                self.seen.remove(&evict);
            }
        }
        self.tick += 1;
        self.seen.insert(caller.to_owned(), self.tick);
        let cell = self
            .cells
            .entry(caller.to_owned())
            .or_default()
            .entry(class)
            .or_default();
        cell.requests = cell.requests.saturating_add(1);
        cell.micros = cell.micros.saturating_add(micros);
    }

    /// Every caller × class cell, sorted by caller then class (deterministic
    /// for tests and for the persistence flush).
    #[must_use]
    pub fn snapshot(&self) -> Vec<ComputeRow> {
        let mut rows: Vec<ComputeRow> = self
            .cells
            .iter()
            .flat_map(|(caller, classes)| {
                classes.iter().map(|(class, cell)| ComputeRow {
                    caller: caller.clone(),
                    class,
                    cell: *cell,
                })
            })
            .collect();
        rows.sort_by(|a, b| a.caller.cmp(&b.caller).then(a.class.cmp(b.class)));
        rows
    }

    /// Callers currently tracked.
    #[must_use]
    pub fn tracked_callers(&self) -> usize {
        self.cells.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{ComputeLedger, ANONYMOUS_CALLER, MAX_TRACKED_CALLERS};

    #[test]
    fn recorded_requests_show_up_per_caller_and_class_with_durations() {
        let mut ledger = ComputeLedger::new();
        ledger.record("id:alice", "object-read", 120);
        ledger.record("id:alice", "object-read", 80);
        ledger.record("id:alice", "manifest-write", 500);
        ledger.record(ANONYMOUS_CALLER, "object-read", 40);

        let rows = ledger.snapshot();
        assert_eq!(rows.len(), 3, "three caller x class cells");

        let alice_reads = rows
            .iter()
            .find(|r| r.caller == "id:alice" && r.class == "object-read")
            .expect("alice object-read row");
        assert_eq!(alice_reads.cell.requests, 2);
        assert_eq!(alice_reads.cell.micros, 200, "durations accumulate");

        let anon = rows
            .iter()
            .find(|r| r.caller == ANONYMOUS_CALLER)
            .expect("anonymous row");
        assert_eq!(anon.cell.requests, 1);
    }

    #[test]
    fn snapshot_is_deterministically_ordered() {
        let mut ledger = ComputeLedger::new();
        ledger.record("id:b", "du", 1);
        ledger.record("id:a", "meter-read", 1);
        ledger.record("id:a", "du", 1);
        let rows = ledger.snapshot();
        let keys: Vec<(&str, &str)> = rows.iter().map(|r| (r.caller.as_str(), r.class)).collect();
        assert_eq!(
            keys,
            vec![("id:a", "du"), ("id:a", "meter-read"), ("id:b", "du")],
            "sorted by caller then class"
        );
    }

    #[test]
    fn the_tracked_set_is_bounded_and_evicts_the_least_recently_seen() {
        let mut ledger = ComputeLedger::new();
        for i in 0..MAX_TRACKED_CALLERS {
            ledger.record(&format!("id:{i:04}"), "object-read", 1);
        }
        // Refresh caller 0 so it is no longer the least recently seen.
        ledger.record("id:0000", "object-read", 1);
        // One over the cap: someone must go, and it must be the LRS caller
        // (id:0001), never the just-refreshed id:0000.
        ledger.record("id:new", "object-read", 1);

        assert_eq!(ledger.tracked_callers(), MAX_TRACKED_CALLERS, "bounded");
        let rows = ledger.snapshot();
        assert!(rows.iter().any(|r| r.caller == "id:new"), "newcomer tracked");
        assert!(rows.iter().any(|r| r.caller == "id:0000"), "refreshed kept");
        assert!(
            !rows.iter().any(|r| r.caller == "id:0001"),
            "least-recently-seen evicted"
        );
    }

    #[test]
    fn durations_saturate_rather_than_wrap() {
        let mut ledger = ComputeLedger::new();
        ledger.record("id:a", "object-read", u64::MAX - 10);
        ledger.record("id:a", "object-read", 100);
        let rows = ledger.snapshot();
        assert_eq!(rows[0].cell.micros, u64::MAX, "saturating add");
        assert_eq!(rows[0].cell.requests, 2);
    }
}
