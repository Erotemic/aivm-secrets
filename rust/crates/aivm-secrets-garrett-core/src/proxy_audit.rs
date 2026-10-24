//! The proxy audit's rows. The native shell supplies the chain position
//! (sequence number and previous head), the clock and the event's detail
//! fields; the row's fixed fields, key order and bytes are here.
//! Work in progress: not yet called by `garrett-proxy`, not yet proved.

use crate::control::{text, text_units};
use crate::json_wire::Value;

/// Whether key `a` sorts strictly before key `b` (by scalar value).
pub fn key_before(a: &[u32], b: &[u32]) -> bool {
    let mut index = 0;
    while index < a.len() && index < b.len() {
        if a[index] != b[index] {
            return a[index] < b[index];
        }
        index += 1;
    }
    a.len() < b.len()
}

/// A copy of a JSON value (structural recursion; `Value` is not `Clone`).
pub fn clone_value(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        Value::Boolean(b) => Value::Boolean(*b),
        Value::Number(digits) => Value::Number(digits.clone()),
        Value::Text(units) => Value::Text(units.clone()),
        Value::Array(items) => {
            let mut out = Vec::new();
            let mut index = 0;
            while index < items.len() {
                out.push(clone_value(&items[index]));
                index += 1;
            }
            Value::Array(out)
        }
        Value::Object(fields) => {
            let mut out = Vec::new();
            let mut index = 0;
            while index < fields.len() {
                out.push((fields[index].0.clone(), clone_value(&fields[index].1)));
                index += 1;
            }
            Value::Object(out)
        }
    }
}

/// Merge two key-sorted field lists into one key-sorted list.
pub fn merge(left: &[(Vec<u32>, Value)], right: &[(Vec<u32>, Value)]) -> Vec<(Vec<u32>, Value)> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < left.len() || j < right.len() {
        if j >= right.len() || (i < left.len() && key_before(&left[i].0, &right[j].0)) {
            out.push((left[i].0.clone(), clone_value(&left[i].1)));
            i += 1;
        } else {
            out.push((right[j].0.clone(), clone_value(&right[j].1)));
            j += 1;
        }
    }
    out
}

/// `{"event":E,"prev":H,"schema":"proxy-audit-1","seq":N,"timestamp":T}`
/// merged with the event's key-sorted detail fields.
pub fn row(
    event: Value,
    prev: Value,
    seq: Value,
    timestamp: Value,
    detail: Vec<(Vec<u32>, Value)>,
) -> Value {
    let fixed = vec![
        (text_units(b"event"), event),
        (text_units(b"prev"), prev),
        (text_units(b"schema"), text(b"proxy-audit-1")),
        (text_units(b"seq"), seq),
        (text_units(b"timestamp"), timestamp),
    ];
    Value::Object(merge(&fixed, &detail))
}
