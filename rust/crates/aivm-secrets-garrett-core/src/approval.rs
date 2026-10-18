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
