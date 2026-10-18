//! One production controller from authenticated surrogate to credentialed use.
//! Adapter contracts describe crypto, durable observation and provider I/O;
//! client messages cannot supply successful verification or authorization flags.
#![allow(clippy::ptr_arg)]
use crate::credential_use::{
    authorize_use, finish_use, CredentialExecutor, PublicReply, Route, UseClaims, UseDenial,
    UseGrant,
};
use crate::{issue_surrogate, Denial, EnvelopeIssuer, IssueInputs, IssuedSurrogate};
use crate::{open_surrogate, Claims, EnvelopeVerifier, Expectation};

/// Acknowledges the public identity of the exact token being released. It has
/// no access to either envelope's plaintext or the provider credential.
pub trait IssuanceObserver {
    fn issued(&self, claims: &Claims) -> Result<(), Denial>;
}

pub fn issue_recorded<I: EnvelopeIssuer, A: IssuanceObserver>(
    issuer: &I,
    observer: &A,
    input: IssueInputs,
    now: i64,
    lifetime: i64,
    secret: &I::Secret,
) -> Result<IssuedSurrogate, Denial> {
    let issued = match issue_surrogate(issuer, input, now, lifetime, secret) {
        Ok(issued) => issued,
        Err(error) => return Err(error),
    };
    match observer.issued(&issued.claims) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    Ok(issued)
}

pub struct OpenedCredential<S> {
    pub claims: UseClaims,
    pub credential: S,
}
pub trait CredentialOpener {
    type Capability;
    type Credential;
    fn open(
        &self,
        capability: &Self::Capability,
    ) -> Result<OpenedCredential<Self::Credential>, UseDenial>;
}
/// The trusted adapter must durably associate this identity, inner grant and
/// exact requested effect before acknowledging success. It receives no secret.
pub trait DispatchObserver {
    fn record(
        &self,
        identity: &Claims,
        claims: &UseClaims,
        route: &Route,
        operation: &Vec<u8>,
    ) -> Result<(), UseDenial>;
}
pub struct Presentation {
    pub expected: Expectation,
    pub peer: Vec<u8>,
    pub now: i64,
    pub elapsed: i64,
}

/// Only this module constructs an authorized opening. Its proof holds before
/// observation/execution, including when the provider later returns an error.
pub(crate) struct Prepared<S> {
    identity: Claims,
    claims: UseClaims,
    credential: S,
}

pub(crate) fn prepare<V, O>(
    verifier: &V,
    opener: &O,
    token: &Vec<u8>,
    grant: &UseGrant,
    operation: &Vec<u8>,
    presentation: &Presentation,
) -> Result<Prepared<O::Credential>, UseDenial>
where
    V: EnvelopeVerifier,
    O: CredentialOpener<Capability = V::Secret>,
{
    let outer = match open_surrogate(
        verifier,
        token,
        &presentation.expected,
        &presentation.peer,
        presentation.now,
    ) {
        Ok(outer) => outer,
        Err(_) => return Err(UseDenial::InvalidCapability),
    };
    let inner = match opener.open(&outer.secret) {
        Ok(inner) => inner,
        Err(error) => return Err(error),
    };
    match authorize_use(
        &inner.claims,
        grant,
        operation,
        presentation.now,
        presentation.elapsed,
    ) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    Ok(Prepared {
        identity: outer.claims,
        claims: inner.claims,
        credential: inner.credential,
    })
}

/// Repeat admission after potentially blocking setup, without releasing either
/// opened capability or plaintext credential to the caller.
pub fn recheck<V, O>(
    verifier: &V,
    opener: &O,
    token: &Vec<u8>,
    grant: &UseGrant,
    operation: &Vec<u8>,
    presentation: &Presentation,
) -> Result<(), UseDenial>
where
    V: EnvelopeVerifier,
    O: CredentialOpener<Capability = V::Secret>,
{
    match prepare(verifier, opener, token, grant, operation, presentation) {
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)] // Distinct adapters remain explicit proof boundaries.
pub fn perform<V, O, A, E>(
    verifier: &V,
    opener: &O,
    observer: &A,
    executor: &E,
    token: &Vec<u8>,
    grant: &UseGrant,
    operation: &Vec<u8>,
    presentation: &Presentation,
) -> Result<PublicReply, UseDenial>
where
    V: EnvelopeVerifier,
    O: CredentialOpener<Capability = V::Secret>,
    A: DispatchObserver,
    E: CredentialExecutor<Credential = O::Credential>,
{
    let ready = match prepare(verifier, opener, token, grant, operation, presentation) {
        Ok(ready) => ready,
        Err(error) => return Err(error),
    };
    match observer.record(&ready.identity, &ready.claims, &grant.route, operation) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    finish_use(executor, &ready.credential, &grant.route)
}
