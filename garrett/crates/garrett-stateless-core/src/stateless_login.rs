//! `garrett-stateless-v1` agent-initiated OAuth login
//! (`docs/garrett-stateless-v1.md` section 8).
//!
//! The login state travels sealed through the browser and the provider; the
//! broker keeps only a transient mailbox [`Entry`] per login, so that the
//! agent can collect its surrogate. Sealing the state, PKCE hashing, the
//! token request and the mailbox map are adapters. This module decides:
//! which agent a login belongs to (the mTLS peer that began it), whether a
//! callback may complete it (the existing `oauth_login` lifecycle), which
//! binding the surrogate receives, and to whom it is delivered.

use crate::oauth_login::{self, Callback, IssuerRule, LoginDenial, Pending, Stage};
use crate::stateless::{self, Grant, IssuePolicy, Issued, Rejection, SurrogateSealer, MAX_TIME};

/// Hard cap on a login's lifetime, matching `oauth_login::current`.
pub const MAX_LOGIN: i64 = 600;
/// How long after its login window a completed surrogate may be collected.
pub const DELIVERY_GRACE: i64 = 300;

/// The sealed `state` parameter's content.
pub struct LoginState {
    pub login: Vec<u8>,
    pub provider: Vec<u8>,
    /// Thumbprint of the certificate that began the login.
    pub certificate: Vec<u8>,
    pub subject: Vec<u8>,
    pub certificate_expires: i64,
    pub replica: Vec<u8>,
    pub scope: Vec<u8>,
    pub verifier: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
}

pub struct LoginPolicy {
    pub replica: Vec<u8>,
    pub providers: Vec<Vec<u8>>,
    pub ttl: i64,
}

/// The broker's transient record of one login. Everything the surrogate is
/// bound to comes from here, never from the state the browser carried back.
pub struct Entry {
    pub login: Vec<u8>,
    pub provider: Vec<u8>,
    pub certificate: Vec<u8>,
    pub subject: Vec<u8>,
    pub certificate_expires: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub stage: Stage,
}

/// Start a login for the authenticated `peer`. The binding is the peer's,
/// never a value from the request.
#[allow(clippy::too_many_arguments)]
pub fn begin(
    policy: &LoginPolicy,
    provider: &[u8],
    peer: &[u8],
    subject: &[u8],
    certificate_expires: i64,
    login: &[u8],
    verifier: &[u8],
    scope: &[u8],
    now: i64,
) -> Result<LoginState, Rejection> {
    if policy.ttl < 1 || policy.ttl > MAX_LOGIN || now < 0 || now > MAX_TIME - MAX_LOGIN {
        return Err(Rejection::BadPolicy);
    }
    if !stateless::member(&policy.providers, provider) {
        return Err(Rejection::UnknownProvider);
    }
    if certificate_expires <= now {
        return Err(Rejection::Expired);
    }
    let replica: &[u8] = &policy.replica;
    Ok(LoginState {
        login: login.to_vec(),
        provider: provider.to_vec(),
        certificate: peer.to_vec(),
        subject: subject.to_vec(),
        // Every time this profile writes is at most `2^53 - 1`.
        certificate_expires: stateless::earlier(certificate_expires, MAX_TIME),
        replica: replica.to_vec(),
        scope: scope.to_vec(),
        verifier: verifier.to_vec(),
        issued_at: now,
        expires_at: now + policy.ttl,
    })
}

/// The mailbox entry for a login just begun.
pub fn entry_of(state: &LoginState) -> Entry {
    let login: &[u8] = &state.login;
    let provider: &[u8] = &state.provider;
    let certificate: &[u8] = &state.certificate;
    let subject: &[u8] = &state.subject;
    Entry {
        login: login.to_vec(),
        provider: provider.to_vec(),
        certificate: certificate.to_vec(),
        subject: subject.to_vec(),
        certificate_expires: state.certificate_expires,
        issued_at: state.issued_at,
        expires_at: state.expires_at,
        stage: Stage::Pending,
    }
}

pub fn rule_copy(rule: &IssuerRule) -> IssuerRule {
    match rule {
        IssuerRule::Absent => IssuerRule::Absent,
        IssuerRule::Exact(issuer) => {
            let issuer: &[u8] = issuer;
            IssuerRule::Exact(issuer.to_vec())
        }
    }
}

/// The `oauth_login` view of an entry, under the provider's issuer rule.
pub fn pending_of(entry: &Entry, rule: &IssuerRule) -> Pending {
    let login: &[u8] = &entry.login;
    Pending {
        state: login.to_vec(),
        issuer: rule_copy(rule),
        issued_at: entry.issued_at,
        expires_at: entry.expires_at,
    }
}

/// Whether the opened state belongs to this entry and this replica.
pub fn same_login(policy: &LoginPolicy, entry: &Entry, state: &LoginState) -> bool {
    let replica: &[u8] = &state.replica;
    let own: &[u8] = &policy.replica;
    let login: &[u8] = &entry.login;
    let provider: &[u8] = &entry.provider;
    let certificate: &[u8] = &entry.certificate;
    let state_login: &[u8] = &state.login;
    let state_provider: &[u8] = &state.provider;
    let state_certificate: &[u8] = &state.certificate;
    let subject: &[u8] = &entry.subject;
    let state_subject: &[u8] = &state.subject;
    replica == own
        && login == state_login
        && provider == state_provider
        && certificate == state_certificate
        && subject == state_subject
        && entry.certificate_expires == state.certificate_expires
        && entry.issued_at == state.issued_at
        && entry.expires_at == state.expires_at
}

/// A provider redirect for the login whose sealed state the adapter opened.
/// `iss` is the RFC 9207 parameter (`has_issuer` false when absent);
/// `denied` is true for an `error=` response.
#[allow(clippy::too_many_arguments)]
pub fn accept_callback(
    policy: &LoginPolicy,
    entry: &Entry,
    state: &LoginState,
    rule: &IssuerRule,
    issuer: &[u8],
    has_issuer: bool,
    denied: bool,
    now: i64,
) -> Result<Stage, LoginDenial> {
    if !same_login(policy, entry, state) {
        return Err(LoginDenial::Invalid);
    }
    let pending = pending_of(entry, rule);
    let login: &[u8] = &state.login;
    let callback = Callback {
        state: login.to_vec(),
        issuer: issuer.to_vec(),
        has_issuer,
        denied,
    };
    oauth_login::claim(&entry.stage, &pending, &callback, now)
}

/// Start the one code exchange of an accepted login.
pub fn begin_exchange(entry: &Entry, rule: &IssuerRule, now: i64) -> Result<Stage, LoginDenial> {
    let pending = pending_of(entry, rule);
    oauth_login::begin(&entry.stage, &pending, now)
}

/// The grant for an exchanged login: the provider, certificate, subject and
/// certificate expiry the entry recorded when the peer began the login.
pub fn grant_of(entry: &Entry, credential_expires: i64) -> Grant {
    let provider: &[u8] = &entry.provider;
    let certificate: &[u8] = &entry.certificate;
    let subject: &[u8] = &entry.subject;
    Grant {
        provider: provider.to_vec(),
        subject: subject.to_vec(),
        certificate: certificate.to_vec(),
        certificate_expires: entry.certificate_expires,
        credential_expires,
    }
}

/// Issue the surrogate for an exchanged login. Only an entry that is
/// exchanging can produce a surrogate, and its binding is the entry's.
#[allow(clippy::too_many_arguments)]
pub fn complete<S: SurrogateSealer>(
    sealer: S,
    policy: &IssuePolicy,
    entry: &Entry,
    credential: &[u8],
    credential_expires: i64,
    token_id: &[u8],
    now: i64,
    lifetime: i64,
) -> Result<Issued, Rejection> {
    match entry.stage {
        Stage::Exchanging => (),
        _ => return Err(Rejection::Malformed),
    }
    let grant = grant_of(entry, credential_expires);
    stateless::issue(sealer, policy, grant, credential, token_id, now, lifetime)
}

/// What an agent's poll gets.
pub enum Delivery {
    Pending,
    Deliver,
    WrongCertificate,
    Denied,
    Failed,
    Expired,
}

/// The answer to a poll from `peer`. Only the peer that began the login
/// ever receives its surrogate.
pub fn deliver(entry: &Entry, peer: &[u8], now: i64) -> Delivery {
    let certificate: &[u8] = &entry.certificate;
    if !(certificate == peer) {
        return Delivery::WrongCertificate;
    }
    if entry.expires_at > MAX_TIME - DELIVERY_GRACE || now >= entry.expires_at + DELIVERY_GRACE {
        return Delivery::Expired;
    }
    match entry.stage {
        Stage::Complete => Delivery::Deliver,
        Stage::Denied => Delivery::Denied,
        Stage::Uncertain => Delivery::Failed,
        _ => {
            if now >= entry.expires_at {
                Delivery::Expired
            } else {
                Delivery::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LoginPolicy {
        LoginPolicy {
            replica: b"a".to_vec(),
            providers: vec![b"github".to_vec()],
            ttl: 600,
        }
    }

    fn state() -> LoginState {
        begin(
            &policy(),
            b"github",
            b"PEER",
            b"agent",
            99999,
            b"L1",
            b"V",
            b"",
            100,
        )
        .ok()
        .unwrap()
    }

    #[test]
    fn login_binds_the_beginning_peer() {
        let s = state();
        assert_eq!(s.certificate, b"PEER");
        assert_eq!((s.issued_at, s.expires_at), (100, 700));
        assert!(begin(
            &policy(),
            b"other",
            b"PEER",
            b"a",
            9999,
            b"L",
            b"V",
            b"",
            100
        )
        .is_err());
        assert!(begin(
            &policy(),
            b"github",
            b"PEER",
            b"a",
            100,
            b"L",
            b"V",
            b"",
            100
        )
        .is_err());
    }

    #[test]
    fn callback_lifecycle() {
        let s = state();
        let mut e = entry_of(&s);
        let rule = IssuerRule::Absent;
        let stage = accept_callback(&policy(), &e, &s, &rule, b"", false, false, 200)
            .ok()
            .unwrap();
        assert!(matches!(stage, Stage::Accepted));
        e.stage = stage;
        // A replay finds the entry no longer pending.
        assert!(accept_callback(&policy(), &e, &s, &rule, b"", false, false, 200).is_err());
        e.stage = begin_exchange(&e, &rule, 201).ok().unwrap();
        assert!(matches!(deliver(&e, b"PEER", 202), Delivery::Pending));
        assert!(matches!(
            deliver(&e, b"OTHER", 202),
            Delivery::WrongCertificate
        ));
        e.stage = Stage::Complete;
        assert!(matches!(deliver(&e, b"PEER", 900), Delivery::Deliver));
        assert!(matches!(deliver(&e, b"PEER", 1000), Delivery::Expired));
    }

    #[test]
    fn callback_for_another_login_or_replica_is_refused() {
        let s = state();
        let e = entry_of(&s);
        let mut other = state();
        other.login = b"L2".to_vec();
        let rule = IssuerRule::Absent;
        assert!(accept_callback(&policy(), &e, &other, &rule, b"", false, false, 200).is_err());
        let mut elsewhere = policy();
        elsewhere.replica = b"b".to_vec();
        assert!(accept_callback(&elsewhere, &e, &s, &rule, b"", false, false, 200).is_err());
        assert!(accept_callback(&policy(), &e, &s, &rule, b"", false, false, 700).is_err());
        let exact = IssuerRule::Exact(b"https://idp".to_vec());
        assert!(accept_callback(&policy(), &e, &s, &exact, b"", false, false, 200).is_err());
        assert!(
            accept_callback(&policy(), &e, &s, &exact, b"https://idp", true, false, 200).is_ok()
        );
    }
}
