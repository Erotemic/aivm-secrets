//! Pure capability freshness decisions. No ambient time, identity, or I/O.
//!
//! These exact functions are extracted by Charon/Aeneas for Lean proofs.
//! JSON validation and authentication of the supplied values belong to callers.
#![forbid(unsafe_code)]

pub enum Denial {
    InvalidCapability,
    Revoked,
}

/// Advance within the operator's bound, without resetting or wrapping epochs.
pub fn advance(current: i64, maximum: i64) -> Result<i64, Denial> {
    if maximum < 0 || current < 0 || current > maximum {
        return Err(Denial::InvalidCapability);
    }
    if current == maximum {
        return Err(Denial::Revoked);
    }
    Ok(current + 1)
}

/// An authenticated claim must name the currently selected nonnegative epoch.
pub fn require_current(actual: i64, expected: i64) -> Result<(), Denial> {
    if actual < 0 || actual != expected {
        return Err(Denial::InvalidCapability);
    }
    Ok(())
}

/// Capability time windows include their start and exclude their expiry.
pub fn require_active(now: i64, not_before: i64, expires_at: i64) -> Result<(), Denial> {
    if not_before < 0 || expires_at < 0 || now < not_before || now >= expires_at {
        return Err(Denial::InvalidCapability);
    }
    Ok(())
}

/// Compose epoch revocation and expiry checks over explicit authenticated facts.
pub fn require_fresh(
    actual: i64,
    expected: i64,
    now: i64,
    not_before: i64,
    expires_at: i64,
) -> Result<(), Denial> {
    match require_current(actual, expected) {
        Err(error) => Err(error),
        Ok(()) => require_active(now, not_before, expires_at),
    }
}
