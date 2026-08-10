//! Dial kinds on the self-assertion substrate (dials plan D2+): customer
//! settings with teeth. Each dial is a kind — a typed body, a canonical
//! fold, structural validation — riding the substrate's envelope
//! (signatures, Model A/C, seq anti-rollback, the provider ack).
//!
//! D2 ships the **ceiling dial**'s at-rest half: the customer's own storage
//! limit. Provider limits supersede (a dial above `min(store_ceiling,
//! did_cap)` is refused at set with the bound quoted), enforcement is
//! always `min(provider bounds, dial)` at the existing quota gate, and
//! reads are never touched (B6 — a cap throttles new spending, it never
//! holds data hostage). The spend-period fields arrive with D3.

use serde::{Deserialize, Serialize};

/// The assertion kind tag for the ceiling dial. Dotted (not slashed): kind
/// tags ride URL path segments.
pub const CEILING_DIAL_KIND: &str = "dial.ceiling";

/// The ceiling dial's body (D2: the at-rest half).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeilingDialBody {
    /// The customer's asserted at-rest cap in bytes; `None` clears it
    /// (clearing is itself a signed, seq'd dial — absence of enforcement is
    /// only ever customer-authorized).
    pub at_rest_bytes: Option<u64>,
}

/// The canonical fold of a ceiling dial body.
#[must_use]
pub fn ceiling_body_fold(body: &CeilingDialBody) -> String {
    match body.at_rest_bytes {
        Some(v) => format!("at_rest_bytes={v}"),
        None => "at_rest_bytes=none".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fold distinguishes every state: distinct values, and set-vs-clear.
    #[test]
    fn fold_binds_the_cap() {
        let a = ceiling_body_fold(&CeilingDialBody { at_rest_bytes: Some(1_500) });
        let b = ceiling_body_fold(&CeilingDialBody { at_rest_bytes: Some(1_501) });
        let none = ceiling_body_fold(&CeilingDialBody { at_rest_bytes: None });
        assert_ne!(a, b, "the value is bound");
        assert_ne!(a, none, "set vs cleared is bound");
        assert_eq!(none, "at_rest_bytes=none");
    }
}
