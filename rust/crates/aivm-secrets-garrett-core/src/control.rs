//! The guest's control verbs, `describe` and `renounce`, after the session
//! has authorized the capability. The native session supplies the three
//! side effects through [`Control`]; every decision and every reply byte
//! source is here. Neither verb reaches a provider: [`Control`] has no
//! provider callback.

use crate::approval::Mode;
use crate::credential_use::UseGrant;
use crate::json_wire::{append, Value};

/// The native session's side effects for a control verb.
pub trait Control {
    type Error;
    /// Revoke the in-memory control state (no further use of the grant).
    fn revoke(&mut self);
    /// Durably append `record` (canonical JSON, without the newline) to the
    /// session audit.
    fn record(&mut self, record: &[u8]) -> Result<(), Self::Error>;
}

/// The outcome of a control verb.
pub enum Controlled<E> {
    /// The reply for the guest.
    Reply(Value),
    /// The revocation could not be recorded; the control state is already
    /// revoked, the grant is left as it was, and no reply is sent.
    Failed(E),
    /// The revocation record could not be encoded; as for `Failed`, the
    /// control state is already revoked and no reply is sent.
    Unencodable,
    /// Not a control verb.
    Denied,
}

pub fn text(bytes: &[u8]) -> Value {
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        out.push(bytes[index] as u32);
        index += 1;
    }
    Value::Text(out)
}

/// `{"description":DESCRIPTION,"ok":true,"version":1}`, keys in byte order.
pub fn described(description: Value) -> Value {
    Value::Object(vec![
        (text_units(b"description"), description),
        (text_units(b"ok"), Value::Boolean(true)),
        (text_units(b"version"), Value::Number(b"1".to_vec())),
    ])
}

/// `{"ok":true,"renounced":true,"version":1}`.
pub fn renounced() -> Value {
    Value::Object(vec![
        (text_units(b"ok"), Value::Boolean(true)),
        (text_units(b"renounced"), Value::Boolean(true)),
        (text_units(b"version"), Value::Number(b"1".to_vec())),
    ])
}

pub fn text_units(bytes: &[u8]) -> Vec<u32> {
    match text(bytes) {
        Value::Text(units) => units,
        _ => Vec::new(),
    }
}

pub fn mode_name(writes: &Mode) -> Value {
    match writes {
        Mode::Allow => text(b"allow"),
        Mode::Deny => text(b"deny"),
        Mode::Approve => text(b"approve"),
    }
}

fn names(operations: &[Vec<u8>]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < operations.len() {
        out.push(text(&operations[index]));
        index += 1;
    }
    out
}

/// The `manifest-https-v1` description: only the policy's operation names
/// and the session's write mode.
pub fn manifest_description(operations: &[Vec<u8>], writes: &Mode) -> Value {
    Value::Object(vec![
        (text_units(b"operations"), Value::Array(names(operations))),
        (text_units(b"profile"), text(b"manifest-https-v1")),
        (text_units(b"request_limit"), text(b"unbounded")),
        (text_units(b"writes"), mode_name(writes)),
    ])
}

/// The fixed `account-status-v1` description.
pub fn account_description() -> Value {
    Value::Object(vec![
        (
            text_units(b"operations"),
            Value::Array(vec![text(b"profile.read")]),
        ),
        (text_units(b"profile"), text(b"account-status-v1")),
        (
            text_units(b"release"),
            Value::Array(vec![text(b"id"), text(b"active")]),
        ),
    ])
}

/// The audit record of a renounced grant, keys in byte order:
/// `{"event":"revoked","grant":G,["operation":O,]"policy":P,"schema":1}`.
/// `grant`, `policy` and `operation` are the session's captured strings.
pub fn revoked_record(grant: Value, policy: Value, operation: Option<Value>) -> Value {
    let mut fields = vec![
        (text_units(b"event"), text(b"revoked")),
        (text_units(b"grant"), grant),
    ];
    match operation {
        Some(name) => fields.push((text_units(b"operation"), name)),
        None => {}
    }
    fields.push((text_units(b"policy"), policy));
    fields.push((text_units(b"schema"), Value::Number(b"1".to_vec())));
    Value::Object(fields)
}

/// A control verb after authorization. `renounce` revokes, appends exactly
/// the encoding of `revoked` to the audit, then marks `grant` inactive and
/// replies; `describe` replies
/// with `description` and changes nothing; anything else is denied.
pub fn control<C: Control>(
    io: &mut C,
    grant: &mut UseGrant,
    verb: &[u8],
    description: Value,
    revoked: Value,
) -> Controlled<C::Error> {
    let renounce: &[u8] = b"renounce";
    let describe: &[u8] = b"describe";
    if verb == renounce {
        io.revoke();
        let mut bytes = Vec::new();
        if !append(&mut bytes, &revoked) {
            return Controlled::Unencodable;
        }
        match io.record(&bytes) {
            Ok(()) => (),
            Err(error) => return Controlled::Failed(error),
        }
        grant.active = false;
        return Controlled::Reply(renounced());
    }
    if verb == describe {
        return Controlled::Reply(described(description));
    }
    Controlled::Denied
}
