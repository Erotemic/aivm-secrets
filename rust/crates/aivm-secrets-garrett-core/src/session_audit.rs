//! The session audit's event records. Native sessions pass the captured
//! strings; the record's shape, key order and fixed values are here, and its
//! bytes come from the extracted JSON encoder.

use crate::control::text_units;
use crate::json_wire::Value;

/// `{"event":E,"grant":G,["operation":O,]"policy":P,["request_digest":D,]"schema":1}`,
/// keys in byte order (the canonical order of the audit file).
pub fn event_record(
    event: Value,
    grant: Value,
    policy: Value,
    operation: Option<Value>,
    request_digest: Option<Value>,
) -> Value {
    let mut fields = vec![(text_units(b"event"), event), (text_units(b"grant"), grant)];
    match operation {
        Some(name) => fields.push((text_units(b"operation"), name)),
        None => {}
    }
    fields.push((text_units(b"policy"), policy));
    match request_digest {
        Some(digest) => fields.push((text_units(b"request_digest"), digest)),
        None => {}
    }
    fields.push((text_units(b"schema"), Value::Number(b"1".to_vec())));
    Value::Object(fields)
}
