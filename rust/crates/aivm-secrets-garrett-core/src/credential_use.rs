//! Credential-use controller. Only the executor receives the opaque credential;
//! only the declared public projection can leave this controller.
#![allow(clippy::ptr_arg)]

pub enum UseDenial {
    InvalidCapability,
    Denied,
    Upstream,
}
pub enum Authentication {
    Bearer,
    ApiKey,
}
pub struct Route {
    pub host: Vec<u8>,
    pub port: i64,
    pub path: Vec<u8>,
    pub authentication: Authentication,
}
pub struct UseClaims {
    pub binding: Vec<u8>,
    pub policy: Vec<u8>,
    pub grant: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
}
pub struct UseGrant {
    pub claims: UseClaims,
    pub operation: Vec<u8>,
    pub route: Route,
    pub active: bool,
}
/// No request count is part of this profile's authority.
pub fn require_use_current(
    claims: &UseClaims,
    grant: &UseGrant,
    now: i64,
    elapsed: i64,
) -> Result<(), UseDenial> {
    let current = &grant.claims;
    if !grant.active
        || claims.binding != current.binding
        || claims.policy != current.policy
        || claims.grant != current.grant
        || claims.issued_at != current.issued_at
        || claims.expires_at != current.expires_at
    {
        return Err(UseDenial::InvalidCapability);
    }
    if claims.issued_at < 0
        || claims.issued_at > 9223372036854772207
        || claims.expires_at <= claims.issued_at
        || claims.expires_at > claims.issued_at + 3600
        || now < claims.issued_at
        || now >= claims.expires_at
        || elapsed < 0
        || elapsed >= claims.expires_at - claims.issued_at
    {
        return Err(UseDenial::InvalidCapability);
    }
    Ok(())
}

pub fn authorize_use(
    claims: &UseClaims,
    grant: &UseGrant,
    operation: &Vec<u8>,
    now: i64,
    elapsed: i64,
) -> Result<(), UseDenial> {
    match require_use_current(claims, grant, now, elapsed) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    if *operation != grant.operation {
        return Err(UseDenial::Denied);
    }
    Ok(())
}
/// The provider adapter parses the complete response and separates the approved
/// public fields from other data. Neither this type nor its discarded content
/// has a public wire serializer.
pub struct ProviderReply {
    pub account_id: i64,
    pub active: bool,
    pub discarded: Vec<u8>,
}
pub struct PublicReply {
    pub account_id: i64,
    pub active: bool,
}
pub fn release_reply(reply: ProviderReply) -> PublicReply {
    PublicReply {
        account_id: reply.account_id,
        active: reply.active,
    }
}
pub trait CredentialExecutor {
    type Credential;
    fn execute(
        &self,
        route: &Route,
        credential: &Self::Credential,
    ) -> Result<ProviderReply, UseDenial>;
}
pub fn use_credential<E: CredentialExecutor>(
    executor: &E,
    credential: &E::Credential,
    claims: &UseClaims,
    grant: &UseGrant,
    operation: &Vec<u8>,
    now: i64,
    elapsed: i64,
) -> Result<PublicReply, UseDenial> {
    match authorize_use(claims, grant, operation, now, elapsed) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    finish_use(executor, credential, &grant.route)
}

/// Shared emission/release tail. Its callers establish authority first.
pub(crate) fn finish_use<E: CredentialExecutor>(
    executor: &E,
    credential: &E::Credential,
    route: &Route,
) -> Result<PublicReply, UseDenial> {
    let response = match executor.execute(route, credential) {
        Ok(response) => response,
        Err(error) => return Err(error),
    };
    Ok(release_reply(response))
}
