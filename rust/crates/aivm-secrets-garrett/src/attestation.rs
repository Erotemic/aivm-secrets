//! Fresh TPM2 creation evidence under an independently trusted attestation key.
//! An AK supplied by the enrolling client is never a trust anchor. EK activation
//! or supervised provisioning of that pin is an external enrollment obligation.
use crate::{tpm, Error, Outcome};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Authority {
    point: Vec<u8>,
    qualified_name: Vec<u8>,
}
pub struct PendingEnrollment {
    authority: Arc<Authority>,
    challenge: [u8; 32],
    expires: Instant,
}
pub struct Evidence<'a> {
    pub public_area: &'a [u8],
    pub attestation: &'a [u8],
    pub signature: &'a [u8],
}
/// Public data only. Its private constructor records successful evidence checks.
pub struct VerifiedIdentity {
    spki: Vec<u8>,
    name: Vec<u8>,
    area: Vec<u8>,
    expires: Instant,
}
impl VerifiedIdentity {
    pub fn subject_public_key_info(&self) -> &[u8] {
        &self.spki
    }
    pub fn key_name(&self) -> &[u8] {
        &self.name
    }
    pub fn public_area(&self) -> &[u8] {
        &self.area
    }
    pub(crate) fn require_fresh(&self) -> Outcome<()> {
        if Instant::now() >= self.expires {
            return Err(Error::Expired);
        }
        Ok(())
    }
    #[cfg(feature = "conformance")]
    pub(crate) fn fixture_expired(mut self) -> Self {
        self.expires = Instant::now();
        self
    }
}
impl Authority {
    /// Caller asserts this exact restricted AK belongs to an approved TPM.
    /// This is deliberately named as a trust input, not evidence verification.
    pub fn from_trusted_pin(public_area: &[u8], qualified_name: &[u8]) -> Outcome<Arc<Self>> {
        if public_area.len() != 88
            || public_area[4..8] != [0, 5, 0, 0x72]
            || qualified_name.len() != 34
            || qualified_name[..2] != [0, 0x0b]
        {
            return Err(Error::InvalidCapability);
        }
        let mut signing_profile = public_area.to_vec();
        signing_profile[5] = 4; // restricted AK differs by TPMA_OBJECT.restricted
        let (point, _) = tpm::public_key(&signing_profile)?;
        Ok(Arc::new(Self {
            point,
            qualified_name: qualified_name.to_vec(),
        }))
    }
    pub fn begin(self: &Arc<Self>) -> Outcome<PendingEnrollment> {
        let mut challenge = [0u8; 32];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| Error::InternalError)?;
        Ok(PendingEnrollment {
            authority: self.clone(),
            challenge,
            expires: Instant::now() + Duration::from_secs(120),
        })
    }
    #[cfg(feature = "conformance")]
    pub(crate) fn fixture_begin(self: &Arc<Self>, challenge: [u8; 32]) -> PendingEnrollment {
        PendingEnrollment {
            authority: self.clone(),
            challenge,
            expires: Instant::now() + Duration::from_secs(120),
        }
    }
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Outcome<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::InvalidCapability)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidCapability)?;
        self.offset = end;
        Ok(bytes)
    }
    fn sized(&mut self) -> Outcome<&'a [u8]> {
        let n = self.take(2)?;
        self.take(u16::from_be_bytes([n[0], n[1]]) as usize)
    }
}
impl PendingEnrollment {
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
    /// Consuming self makes the fresh challenge single-use within this process.
    /// No restart/persistence or clone of a pending challenge is supported.
    pub fn verify(self, evidence: Evidence<'_>) -> Outcome<VerifiedIdentity> {
        if Instant::now() >= self.expires
            || evidence.attestation.len() > 4096
            || evidence.signature.len() > 80
        {
            return Err(Error::InvalidCapability);
        }
        let (_, spki) = tpm::public_key(evidence.public_area)?;
        signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &self.authority.point,
        )
        .verify(evidence.attestation, evidence.signature)
        .map_err(|_| Error::InvalidCapability)?;
        let mut cursor = Cursor {
            bytes: evidence.attestation,
            offset: 0,
        };
        // TPM_GENERATED_VALUE and TPM_ST_ATTEST_CREATION. No quote/certify or
        // caller-authored blob can be confused with this signed statement.
        if cursor.take(6)? != [0xff, 0x54, 0x43, 0x47, 0x80, 0x1a]
            || cursor.sized()? != self.authority.qualified_name
            || cursor.sized()? != self.challenge
        {
            return Err(Error::InvalidCapability);
        }
        cursor.take(8 + 4 + 4)?; // clock, resetCount, restartCount (not rollback protection)
        if cursor.take(1)? != [1] {
            return Err(Error::InvalidCapability);
        }
        cursor.take(8)?; // firmwareVersion is evidence, not an approved-firmware claim
        let mut name = vec![0, 0x0b];
        name.extend_from_slice(digest::digest(&digest::SHA256, evidence.public_area).as_ref());
        if cursor.sized()? != name
            || cursor.sized()?.len() != 32
            || cursor.offset != evidence.attestation.len()
        {
            return Err(Error::InvalidCapability);
        }
        Ok(VerifiedIdentity {
            spki,
            name,
            area: evidence.public_area.to_vec(),
            expires: self.expires,
        })
    }
}
