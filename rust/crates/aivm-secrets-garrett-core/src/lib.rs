//! Extractable Garrett issuance and authenticated presentation decisions.
//! Crypto, TLS, enrollment provenance and text decoding are explicit boundaries.
#![forbid(unsafe_code)]
// Scalar guards keep extraction independent of Range/iterator implementations.
#![allow(clippy::manual_range_contains)]
// Explicit Result matches preserve the small control-flow shape of the proofs.
#![allow(clippy::question_mark)]

pub mod approval;
pub mod audit_record;
pub mod selected_release;
pub mod selected_conversion;
pub mod response_gate;
pub mod authority;
pub mod coordination;
pub mod coordinator_authority;
pub mod credential_use;
pub mod enrollment;
pub mod manifest;
pub mod oauth_login;
pub mod oauth_state;
pub mod protocol;
pub mod provider_exchange;
pub mod read_transition;
pub mod rebinding;
pub mod request_effects;
pub mod trust;

pub enum Denial {
    InvalidCapability,
}

pub struct Claims {
    pub issuer: Vec<u8>,
    pub audience: Vec<u8>,
    pub subject: Vec<u8>,
    pub token_id: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub epoch: i64,
    pub certificate: Vec<u8>,
}

pub struct Expectation {
    pub issuer: Vec<u8>,
    pub audience: Vec<u8>,
    pub subject: Vec<u8>,
    pub epoch: i64,
}

pub struct IssueWindow {
    pub issued_at: i64,
    pub expires_at: i64,
    pub epoch: i64,
}

/// The adapter selects a validated enrollment; this caps its issued authority.
pub fn issue_window(
    active: bool,
    epoch: i64,
    not_after: i64,
    now: i64,
    lifetime: i64,
) -> Result<IssueWindow, Denial> {
    if !active || epoch < 0 || epoch > 2147483647 || not_after < 0 {
        return Err(Denial::InvalidCapability);
    }
    if now < 0 || now > 9223372036854772207 || lifetime < 1 || lifetime > 3600 {
        return Err(Denial::InvalidCapability);
    }
    if now >= not_after {
        return Err(Denial::InvalidCapability);
    }
    let requested = now + lifetime;
    let expires_at = if requested < not_after {
        requested
    } else {
        not_after
    };
    Ok(IssueWindow {
        issued_at: now,
        expires_at,
        epoch,
    })
}

/// Acceptance requires exact bytes for every binding; no hash/interner surrogate.
#[allow(clippy::ptr_arg)] // Use the same modeled byte-vector type for all bindings.
pub fn present(
    claims: &Claims,
    expected: &Expectation,
    peer: &Vec<u8>,
    now: i64,
) -> Result<(), Denial> {
    if claims.issuer != expected.issuer
        || claims.audience != expected.audience
        || claims.subject != expected.subject
        || claims.certificate != *peer
    {
        return Err(Denial::InvalidCapability);
    }
    if claims.epoch < 0 || claims.epoch > 2147483647 || claims.epoch != expected.epoch {
        return Err(Denial::InvalidCapability);
    }
    if claims.issued_at < 0 || claims.issued_at > 9223372036854772207 {
        return Err(Denial::InvalidCapability);
    }
    if claims.expires_at <= claims.issued_at
        || claims.expires_at > claims.issued_at + 3600
        || now < claims.issued_at
        || now >= claims.expires_at
    {
        return Err(Denial::InvalidCapability);
    }
    Ok(())
}

/// Signature verification and authenticated decryption are trusted adapters.
/// The controller below fixes their ordering and the exact claims they share.
pub struct AuthenticatedEnvelope {
    pub claims: Claims,
    pub encrypted: Vec<u8>,
}

pub struct OpenedSurrogate<S> {
    pub claims: Claims,
    pub secret: S,
}

#[allow(clippy::ptr_arg)]
pub trait EnvelopeVerifier {
    type Secret;
    fn verify(&self, token: &Vec<u8>) -> Result<AuthenticatedEnvelope, Denial>;
    fn unseal(&self, envelope: &AuthenticatedEnvelope) -> Result<Self::Secret, Denial>;
}

/// This is the production controller, not a second implementation for proofs.
/// An authenticated envelope cannot be unsealed until actual peer binding holds.
#[allow(clippy::ptr_arg)]
pub fn open_surrogate<V: EnvelopeVerifier>(
    verifier: &V,
    token: &Vec<u8>,
    expected: &Expectation,
    peer: &Vec<u8>,
    now: i64,
) -> Result<OpenedSurrogate<V::Secret>, Denial> {
    let envelope = match verifier.verify(token) {
        Ok(envelope) => envelope,
        Err(error) => return Err(error),
    };
    if let Err(error) = present(&envelope.claims, expected, peer, now) {
        return Err(error);
    }
    let secret = match verifier.unseal(&envelope) {
        Ok(secret) => secret,
        Err(error) => return Err(error),
    };
    Ok(OpenedSurrogate {
        claims: envelope.claims,
        secret,
    })
}

pub struct IssueInputs {
    pub issuer: Vec<u8>,
    pub audience: Vec<u8>,
    pub subject: Vec<u8>,
    pub token_id: Vec<u8>,
    pub certificate: Vec<u8>,
    pub active: bool,
    pub epoch: i64,
    pub not_after: i64,
}

/// Bind the claims to the selected enrollment before cryptographic issuance.
pub fn prepare_issue(input: IssueInputs, now: i64, lifetime: i64) -> Result<Claims, Denial> {
    let window = match issue_window(input.active, input.epoch, input.not_after, now, lifetime) {
        Ok(window) => window,
        Err(error) => return Err(error),
    };
    Ok(Claims {
        issuer: input.issuer,
        audience: input.audience,
        subject: input.subject,
        token_id: input.token_id,
        certificate: input.certificate,
        epoch: window.epoch,
        issued_at: window.issued_at,
        expires_at: window.expires_at,
    })
}

pub struct IssuedSurrogate {
    pub claims: Claims,
    pub token: Vec<u8>,
}

pub trait EnvelopeIssuer {
    type Secret;
    fn seal(&self, claims: &Claims, secret: &Self::Secret) -> Result<Vec<u8>, Denial>;
}

pub fn issue_surrogate<I: EnvelopeIssuer>(
    issuer: &I,
    input: IssueInputs,
    now: i64,
    lifetime: i64,
    secret: &I::Secret,
) -> Result<IssuedSurrogate, Denial> {
    let claims = match prepare_issue(input, now, lifetime) {
        Ok(claims) => claims,
        Err(error) => return Err(error),
    };
    let token = match issuer.seal(&claims, secret) {
        Ok(token) => token,
        Err(error) => return Err(error),
    };
    Ok(IssuedSurrogate { claims, token })
}

pub mod disclosure;

pub mod reflection;

pub mod client_material;
pub mod emission;
pub mod http_auth;
pub mod http_request;
pub mod http_wire;

pub mod line_frame;

pub mod bundle;

pub mod json_reflection;

pub mod guest_frame;

pub mod completion;

pub mod dispatch;

pub mod request_adapter;

pub mod current_admission;

pub mod request_context;

pub mod json_string;
pub mod provider_io;
pub mod provider_wire;

pub mod json_wire;
pub mod public_error;
pub mod channel_work;
pub mod provider_status;
pub mod proxy_http;
pub mod proxy_controller;
pub mod route;
pub mod control;
pub mod route_match;
pub mod proxy_connect;
pub mod write_gate;
pub mod session_audit;
pub mod proxy_audit;
