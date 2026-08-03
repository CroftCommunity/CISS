//! The price list. Every figure is in integer cents so anything that must
//! balance balances to the cent, with no floating-point drift. Rent is priced
//! per byte-day, postage per byte. "At cost" is the point: the assurance dial
//! (Phase 5) has a true, linear price.
//!
//! Ports `item-storage-protocol-standalone/src/pricing.ts`. These are mock rates
//! chosen for legible arithmetic, not real tariffs. Audit pricing arrives with
//! the dial in Phase 5.

/// Rent numerator (cents).
pub const RENT_NUMERATOR: u64 = 1;
/// Rent denominator: 1 cent per this many byte-days.
pub const RENT_DENOMINATOR: u64 = 10_000;
/// Postage: 1 cent per this many bytes transferred.
pub const POSTAGE_BYTES_PER_CENT: u64 = 1_000;
/// Audit read cost: 1 cent per this many bytes retrieved (same physics as postage).
pub const AUDIT_BYTES_PER_CENT: u64 = 1_000;
/// Fixed overhead booked per audit, on top of the bytes-read cost.
pub const AUDIT_OVERHEAD_CENTS: u64 = 2;

/// Rent in cents for a byte-day total: `floor(byte_days / RENT_DENOMINATOR)`.
#[must_use]
pub fn rent_cents(byte_days: u64) -> u64 {
    byte_days * RENT_NUMERATOR / RENT_DENOMINATOR
}

/// Postage in cents for a byte total: `floor(bytes / POSTAGE_BYTES_PER_CENT)`.
#[must_use]
pub fn postage_cents(bytes: u64) -> u64 {
    bytes / POSTAGE_BYTES_PER_CENT
}

/// Audit cost in cents: the bytes read priced like postage, plus a fixed
/// per-audit overhead. Equals `floor(bytes_read / AUDIT_BYTES_PER_CENT)` cents
/// for the bytes, then `audit_count * AUDIT_OVERHEAD_CENTS` cents on top. "At
/// cost" is the point: the assurance dial has a true, linear price with no
/// margin encoded into paranoia.
#[must_use]
pub fn audit_cents(bytes_read: u64, audit_count: u64) -> u64 {
    bytes_read / AUDIT_BYTES_PER_CENT + audit_count * AUDIT_OVERHEAD_CENTS
}

#[cfg(test)]
mod tests {
    use super::{postage_cents, rent_cents};

    #[test]
    fn rent_floors_byte_days() {
        assert_eq!(rent_cents(0), 0);
        assert_eq!(rent_cents(9_999), 0); // below one cent
        assert_eq!(rent_cents(10_000), 1);
        assert_eq!(rent_cents(25_000), 2); // floor(2.5)
    }

    #[test]
    fn postage_floors_bytes() {
        assert_eq!(postage_cents(0), 0);
        assert_eq!(postage_cents(999), 0);
        assert_eq!(postage_cents(1_000), 1);
        assert_eq!(postage_cents(8_192), 8); // floor(8.192)
    }

    #[test]
    fn audit_cost_is_bytes_at_cost_plus_fixed_overhead() {
        use super::audit_cents;
        assert_eq!(audit_cents(0, 0), 0);
        assert_eq!(audit_cents(0, 1), 2); // just the per-audit overhead
        assert_eq!(audit_cents(1_000, 1), 3); // 1 (bytes) + 2 (overhead)
        assert_eq!(audit_cents(5_120, 1), 7); // floor(5.12) + 2
        assert_eq!(audit_cents(2_000, 3), 8); // 2 (bytes) + 6 (3 audits)
    }
}
