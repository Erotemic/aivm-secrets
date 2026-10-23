//! The session audit's event records. Native sessions pass the captured
//! strings; the record's shape, key order and fixed values are here, and its
//! bytes come from the extracted JSON encoder.

use crate::control::{text, text_units};
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

/// The dispatch record written before every provider send of the manifest
/// profile, keys in byte order:
/// `{"event":"dispatch","grant":G,"identity":I,"operation":O,"phase":PH,
/// "policy":P,"request_digest":D,"route":{"host":H,"method":M,"path":T,
/// "port":N},"schema":1}`.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_record(
    phase: Value,
    grant: Value,
    policy: Value,
    identity: Value,
    operation: Value,
    request_digest: Value,
    host: Value,
    port: Value,
    method: Value,
    path: Value,
) -> Value {
    let route = Value::Object(vec![
        (text_units(b"host"), host),
        (text_units(b"method"), method),
        (text_units(b"path"), path),
        (text_units(b"port"), port),
    ]);
    Value::Object(vec![
        (text_units(b"event"), text(b"dispatch")),
        (text_units(b"grant"), grant),
        (text_units(b"identity"), identity),
        (text_units(b"operation"), operation),
        (text_units(b"phase"), phase),
        (text_units(b"policy"), policy),
        (text_units(b"request_digest"), request_digest),
        (text_units(b"route"), route),
        (text_units(b"schema"), Value::Number(b"1".to_vec())),
    ])
}
