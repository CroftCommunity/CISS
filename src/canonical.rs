//! Canonical serialization: the one byte-string every signature and hash is
//! taken over. Determinism is the whole game — object keys are sorted
//! recursively and no incidental whitespace is emitted, so identical logical
//! values always produce identical bytes and every ledger run is reproducible.
//!
//! Ports `item-storage-protocol-standalone/src/canonical.ts`.
//!
//! `SEAM:` production atproto signs/hashes over `DAG-CBOR` (RFC 8949
//! deterministic encoding), not sorted-key JSON. Canonical JSON is the one
//! deliberate wire simplification; the *property* we rely on — a single
//! canonical byte-string per value — is the same one `DAG-CBOR` provides (the
//! in-corpus `serde_ipld_dagcbor` path closes this later).

use serde::Serialize;
use serde_json::Value;

/// Canonicalize any serializable value to deterministic bytes (keys sorted
/// recursively, no whitespace).
///
/// # Panics
///
/// Panics only if the value cannot be represented as JSON (e.g. a non-string
/// map key or a non-finite float). The ledger/receipt/statement types this
/// crate hashes are always representable, so this is an unreachable path.
#[must_use]
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value)
        .expect("canonical: crate ledger/receipt types are always JSON-representable");
    canonical_string(&value).into_bytes()
}

/// Recursively render a JSON value with object keys sorted and no whitespace.
fn canonical_string(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let child = map.get(k).expect("key came from this map's own key set");
                    format!(
                        "{}:{}",
                        encode_scalar(&Value::String(k.clone())),
                        canonical_string(child)
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_string).collect();
            format!("[{}]", parts.join(","))
        }
        scalar => encode_scalar(scalar),
    }
}

/// Encode a scalar (null / bool / number / string) via `serde_json`, which is
/// already canonical for these: integers serialize exactly and strings are
/// JSON-escaped.
fn encode_scalar(value: &Value) -> String {
    serde_json::to_string(value).expect("a scalar JSON value always serializes")
}

#[cfg(test)]
mod tests {
    use super::to_canonical_bytes;
    use serde_json::json;

    #[test]
    fn object_keys_are_sorted_regardless_of_insertion_order() {
        let a = to_canonical_bytes(&json!({"b": 1, "a": 2}));
        let b = to_canonical_bytes(&json!({"a": 2, "b": 1}));
        assert_eq!(a, b);
        assert_eq!(a, br#"{"a":2,"b":1}"#.to_vec());
    }

    #[test]
    fn no_incidental_whitespace() {
        let out = to_canonical_bytes(&json!({"x": [1, 2, 3], "y": "z"}));
        assert_eq!(out, br#"{"x":[1,2,3],"y":"z"}"#.to_vec());
    }

    #[test]
    fn nested_objects_sort_recursively() {
        let out = to_canonical_bytes(&json!({"outer": {"z": 1, "a": 2}}));
        assert_eq!(out, br#"{"outer":{"a":2,"z":1}}"#.to_vec());
    }
}
