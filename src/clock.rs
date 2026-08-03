//! A deterministic day clock. Time only advances when explicitly told to, so
//! timestamps and the byte-day rent integral are reproducible run to run (no
//! wall-clock reads).
//!
//! Ports `item-storage-protocol-standalone/src/clock.ts` (the day-counter core;
//! the ISO helper is omitted — the ledger treats timestamps as opaque strings).

/// A simulated clock measured in whole days since a fixed epoch.
#[derive(Debug, Default)]
pub struct SimClock {
    day: u64,
}

impl SimClock {
    /// A new clock at day 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current day.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.day
    }

    /// Advance the clock by `n` days. Time cannot run backward (`n: u64`).
    pub fn advance_days(&mut self, n: u64) {
        self.day += n;
    }
}

#[cfg(test)]
mod tests {
    use super::SimClock;

    #[test]
    fn advances_monotonically_from_zero() {
        let mut clock = SimClock::new();
        assert_eq!(clock.now(), 0);
        clock.advance_days(30);
        assert_eq!(clock.now(), 30);
        clock.advance_days(5);
        assert_eq!(clock.now(), 35);
    }
}
