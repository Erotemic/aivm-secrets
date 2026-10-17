//! Extracted decisions for declarative provider authority. Search witnesses are
//! untrusted: the core rechecks their bounds and the actual selected value.
#![allow(clippy::ptr_arg)]
use crate::credential_use::{require_use_current, UseClaims, UseDenial, UseGrant};
pub enum Scalar {
    Integer(i64),
    Text(Vec<u8>),
}
pub enum Rule {
    Range(i64, i64),
    Integers(Vec<i64>),
    Texts(Vec<Vec<u8>>),
    Body(usize),
}
pub fn parameter(rule: &Rule, value: &Scalar, witness: usize) -> Result<(), UseDenial> {
    match (rule, value) {
        (Rule::Range(lo, hi), Scalar::Integer(value)) => {
            if *lo < 0 || *hi < *lo || *value < *lo || *value > *hi {
                return Err(UseDenial::Denied);
            }
        }
        (Rule::Integers(allowed), Scalar::Integer(value)) => {
            if witness >= allowed.len() || allowed[witness] != *value {
                return Err(UseDenial::Denied);
            }
        }
        (Rule::Texts(allowed), Scalar::Text(value)) => {
            if witness >= allowed.len() || allowed[witness] != *value {
                return Err(UseDenial::Denied);
            }
        }
        (Rule::Body(maximum), Scalar::Text(value)) => {
            if *maximum < 1 || value.len() > *maximum {
                return Err(UseDenial::Denied);
            }
        }
        _ => return Err(UseDenial::Denied),
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    claims: &UseClaims,
    grant: &UseGrant,
    requested: &Vec<u8>,
    selected: &Vec<u8>,
    write: bool,
    writes_allowed: bool,
    now: i64,
    elapsed: i64,
) -> Result<(), UseDenial> {
    match require_use_current(claims, grant, now, elapsed) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    if *requested != *selected || write && !writes_allowed {
        return Err(UseDenial::Denied);
    }
    Ok(())
}
pub struct ProviderReply {
    pub selected: Vec<u8>,
    pub discarded: Vec<u8>,
}
pub fn release(reply: ProviderReply) -> Vec<u8> {
    reply.selected
}
