//! Privileged identity renewal may carry the SAME opaque broker capability.
//! Verified issuer/certificate facts and stable authority storage are adapters.
#![allow(clippy::ptr_arg)]
use crate::{Claims, Expectation};

pub struct Target {
    pub identity: Expectation,
    pub certificate: Vec<u8>,
    pub key: Vec<u8>,
    pub active: bool,
    pub not_after: i64,
}

pub fn permitted(
    source: &Claims,
    source_key: &Vec<u8>,
    target: &Target,
    expected_epoch: i64,
    expected_certificate: &Vec<u8>,
    now: i64,
) -> bool {
    target.active
        && source.issuer == target.identity.issuer
        && source.audience == target.identity.audience
        && source.subject == target.identity.subject
        && *source_key == target.key
        && source.epoch <= target.identity.epoch
        && target.identity.epoch == expected_epoch
        && target.certificate == *expected_certificate
        && now >= 0
        && now < target.not_after
}

pub trait Rebinder {
    type Secret;
    type Output;
    type Error;
    fn rejected(&self) -> Self::Error;
    fn open(&self) -> Result<Self::Secret, Self::Error>;
    fn issue(&self, secret: &Self::Secret) -> Result<Self::Output, Self::Error>;
}

pub fn rebind<R: Rebinder>(
    ops: &R,
    source: &Claims,
    source_key: &Vec<u8>,
    target: &Target,
    expected_epoch: i64,
    expected_certificate: &Vec<u8>,
    now: i64,
) -> Result<R::Output, R::Error> {
    if !permitted(
        source,
        source_key,
        target,
        expected_epoch,
        expected_certificate,
        now,
    ) {
        return Err(ops.rejected());
    }
    let secret = match ops.open() {
        Ok(secret) => secret,
        Err(error) => return Err(error),
    };
    ops.issue(&secret)
}
