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

/// Merge two key-sorted field lists into one key-sorted list.
pub fn merge(left: Vec<(Vec<u32>, Value)>, right: Vec<(Vec<u32>, Value)>) -> Vec<(Vec<u32>, Value)> {
    let mut out = Vec::new();
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    loop {
        let take_left = match (left.peek(), right.peek()) {
            (Some(l), Some(r)) => key_before(&l.0, &r.0),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let next = if take_left { left.next() } else { right.next() };
        if let Some(field) = next {
            out.push(field);
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
    Value::Object(merge(fixed, detail))
}
