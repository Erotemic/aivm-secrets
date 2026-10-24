//! Exact-write approval consumption. Hashing, the unique keyed store, trusted
//! host issuance and provider I/O are concrete adapter obligations.
#![allow(clippy::ptr_arg)]
#[derive(Clone, Copy)]
pub enum Mode {
    Deny,
    Approve,
    Allow,
}
pub struct Approval {
    pub digest: Vec<u8>,
    pub expires_at: i64,
}
#[derive(Clone, Copy)]
pub enum Decision {
    Allowed,
    Denied,
    Required,
}

pub fn issue(digest: Vec<u8>, now: i64, ttl: i64) -> Option<Approval> {
    if now < 0 || ttl < 1 || ttl > 900 {
        return None;
    }
    if now > i64::MAX - ttl {
        return None;
    }
    Some(Approval {
        digest,
        expires_at: now + ttl,
    })
}

/// A successful approved write returns no reusable approval. Refusal preserves
/// the supplied slot; reads and allow mode do not spend an unrelated approval.
pub fn consume(
    mode: Mode,
    write: bool,
    wanted: &Vec<u8>,
    now: i64,
    prior: Option<Approval>,
) -> (Decision, Option<Approval>) {
    if !write {
        return (Decision::Allowed, prior);
    }
    match mode {
        Mode::Deny => (Decision::Denied, prior),
        Mode::Allow => (Decision::Allowed, prior),
        Mode::Approve => match prior {
            None => (Decision::Required, None),
            Some(slot) => {
                if slot.digest != *wanted || now >= slot.expires_at {
                    return (Decision::Required, Some(slot));
                }
                (Decision::Allowed, None)
            }
        },
    }
}

/// The host's approval store: at most one slot per digest, at most
/// `STORE_LIMIT` live slots. Keys are the slots' own digests.
pub const STORE_LIMIT: usize = 16;

pub struct Taken {
    pub slot: Option<Approval>,
    pub rest: Vec<Approval>,
}

fn copy(slot: &Approval) -> Approval {
    Approval {
        digest: slot.digest.clone(),
        expires_at: slot.expires_at,
    }
}

/// Removes the first slot whose digest is `wanted`; the rest keep their order.
pub fn take(store: &Vec<Approval>, wanted: &Vec<u8>) -> Taken {
    let mut slot = None;
    let mut rest = Vec::new();
    let mut index = 0;
    while index < store.len() {
        let first = match slot {
            None => store[index].digest == *wanted,
            Some(_) => false,
        };
        if first {
            slot = Some(copy(&store[index]));
        } else {
            rest.push(copy(&store[index]));
        }
        index += 1;
    }
    Taken { slot, rest }
}

pub struct Admitted {
    pub decision: Decision,
    pub store: Vec<Approval>,
}

/// Looks up the slot for exactly this request digest and decides with
/// `consume`. An unspent slot goes back into the store.
pub fn admit(
    store: &Vec<Approval>,
    mode: Mode,
    write: bool,
    wanted: &Vec<u8>,
    now: i64,
) -> Admitted {
    let taken = take(store, wanted);
    let mut rest = taken.rest;
    let decided = consume(mode, write, wanted, now, taken.slot);
    match decided.1 {
        Some(kept) => rest.push(kept),
        None => {}
    }
    Admitted {
        decision: decided.0,
        store: rest,
    }
}

/// Installs a newly issued slot: drops any slot with the same digest and any
/// expired slot, then refuses if the store is still full.
pub fn install(store: &Vec<Approval>, slot: Approval, now: i64) -> Option<Vec<Approval>> {
    let mut kept = Vec::new();
    let mut index = 0;
    while index < store.len() {
        if store[index].digest != slot.digest && now < store[index].expires_at {
            kept.push(copy(&store[index]));
        }
        index += 1;
    }
    if kept.len() >= STORE_LIMIT {
        return None;
    }
    kept.push(slot);
    Some(kept)
}

/// `{"arguments":A,"operation":O}`: the request whose canonical encoding the
/// session hashes as the request digest.
pub fn request_value(
    operation: crate::json_wire::Value,
    arguments: crate::json_wire::Value,
) -> crate::json_wire::Value {
    crate::json_wire::Value::Object(vec![
        (crate::control::text_units(b"arguments"), arguments),
        (crate::control::text_units(b"operation"), operation),
    ])
}

/// `{"grant":G,"policy":P,"request":R}`: what an exact-write approval
/// digest is the SHA-256 of (canonical encoding). An approval therefore names
/// one grant, one policy and one request.
pub fn approval_preimage(
    grant: crate::json_wire::Value,
    policy: crate::json_wire::Value,
    request: crate::json_wire::Value,
) -> crate::json_wire::Value {
    crate::json_wire::Value::Object(vec![
        (crate::control::text_units(b"grant"), grant),
        (crate::control::text_units(b"policy"), policy),
        (crate::control::text_units(b"request"), request),
    ])
}
