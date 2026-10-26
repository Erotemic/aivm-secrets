//! The broker's transient login mailbox and every transition the broker
//! makes on it (`docs/garrett-stateless-v1.md` sections 8.1 and 9).
//!
//! The mailbox is the only mutable state of a `garrett-stateless` broker.
//! The native broker holds it behind one lock and changes it only through
//! these functions: its fields are private, so the broker cannot read or
//! change a slot itself. The code exchange runs between two locked
//! transitions, through types the broker cannot build: [`accept`] returns a
//! [`Permit`], [`exchange`] consumes it and returns the provider's answer to
//! the token request made with that login's verifier as an [`Exchanged`],
//! and [`finish`] consumes that. So one accepted callback yields at most one
//! exchange, and its answer can only reach the login it was made for.
// Explicit matches and `mem::replace` keep to what Aeneas models.
#![allow(
    clippy::single_match,
    clippy::match_like_matches_macro,
    clippy::mem_replace_option_with_none,
    clippy::redundant_pattern_matching
)]

use crate::oauth_login::{self, IssuerRule, LoginDenial, Stage};
use crate::stateless::{self, IssuePolicy, Issued, Rejection, SurrogateSealer, MAX_TIME};
use crate::stateless_login::{self, Delivery, Entry, LoginPolicy, LoginState, DELIVERY_GRACE};

/// Hard cap on the logins one broker replica holds.
pub const MAX_PENDING: usize = 1024;
/// The last serial number; a mailbox that reached it refuses new logins.
pub const LAST_SERIAL: u64 = 18446744073709551615;

/// One login in progress and, once issued, its surrogate.
pub struct Slot {
    pub entry: Entry,
    /// Distinct for every login this mailbox ever accepted.
    pub serial: u64,
    /// The finished surrogate (empty until issued).
    pub token: Vec<u8>,
    pub expires_at: i64,
    pub renew_until: i64,
}

pub struct Mailbox {
    slots: Vec<Option<Slot>>,
    next: u64,
}

pub fn empty() -> Mailbox {
    Mailbox {
        slots: Vec::new(),
        next: 0,
    }
}

/// Why the broker refused a login transition.
pub enum MailboxError {
    /// An extracted controller refused (policy, provider, window, issuance).
    Rejected(Rejection),
    /// The `oauth_login` lifecycle refused the callback.
    Refused(LoginDenial),
    TooMany,
    Duplicate,
    Exhausted,
    Unknown,
    Consumed,
    Expired,
    Denied,
}

/// Leave to run the one code exchange of an accepted login. Only [`accept`]
/// makes one, and [`exchange`] consumes it.
pub struct Permit {
    serial: u64,
    login: Vec<u8>,
    provider: Vec<u8>,
    verifier: Vec<u8>,
}

/// What the token endpoint returned, after the native shell validated it.
pub struct Token {
    pub credential: Vec<u8>,
    pub has_expires_in: bool,
    pub expires_in: i64,
}

/// The token request of one login: the provider, the authorization code
/// from the redirect, and the login's PKCE verifier. `None` for any failure.
pub trait CodeExchange {
    fn token(&mut self, provider: &[u8], code: &[u8], verifier: &[u8]) -> Option<Token>;
}

/// The answer to one permitted code exchange. Only [`exchange`] makes one,
/// and [`finish`] consumes it.
pub struct Exchanged {
    permit: Permit,
    token: Option<Token>,
}

/// The token an exchange returned, for the broker's informational claims.
pub fn exchanged_token(exchanged: &Exchanged) -> Option<&Token> {
    match &exchanged.token {
        Some(token) => Some(token),
        None => None,
    }
}

/// Whether pruning keeps a slot: a login lives until `exp`, a finished
/// surrogate until `exp + DELIVERY_GRACE`.
pub fn kept(slot: &Option<Slot>, now: i64) -> bool {
    match slot {
        None => false,
        Some(slot) => {
            slot.entry.expires_at <= MAX_TIME - DELIVERY_GRACE
                && now < slot.entry.expires_at + DELIVERY_GRACE
        }
    }
}

/// Empty every slot that is no longer kept.
pub fn prune(mailbox: &mut Mailbox, now: i64) {
    let mut index = 0;
    while index < mailbox.slots.len() {
        if !kept(&mailbox.slots[index], now) {
            mailbox.slots[index] = None;
        }
        index += 1;
    }
}

/// The number of occupied slots.
pub fn live(slots: &[Option<Slot>]) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < slots.len() {
        match &slots[index] {
            Some(_) => count += 1,
            None => (),
        }
        index += 1;
    }
    count
}

pub fn live_count(mailbox: &Mailbox) -> usize {
    live(&mailbox.slots)
}

pub fn holds(slot: &Option<Slot>, login: &[u8]) -> bool {
    match slot {
        None => false,
        Some(slot) => {
            let own: &[u8] = &slot.entry.login;
            own == login
        }
    }
}

/// Index of the first slot holding `login` (or `slots.len()`).
pub fn find(slots: &[Option<Slot>], login: &[u8]) -> usize {
    let mut index = 0;
    while index < slots.len() && !holds(&slots[index], login) {
        index += 1;
    }
    index
}

pub fn occupied(slot: &Option<Slot>) -> bool {
    match slot {
        None => false,
        Some(_) => true,
    }
}

/// Index of the first empty slot (or `slots.len()`).
pub fn vacancy(slots: &[Option<Slot>]) -> usize {
    let mut index = 0;
    while index < slots.len() && occupied(&slots[index]) {
        index += 1;
    }
    index
}

/// Spec section 8.1 steps 1-2: begin a login for the authenticated `peer`
/// and record its entry. A full mailbox, or one that already holds this
/// login, records nothing.
#[allow(clippy::too_many_arguments)]
pub fn start(
    mailbox: &mut Mailbox,
    policy: &LoginPolicy,
    provider: &[u8],
    peer: &[u8],
    subject: &[u8],
    certificate_expires: i64,
    login: &[u8],
    verifier: &[u8],
    scope: &[u8],
    now: i64,
) -> Result<LoginState, MailboxError> {
    let state = match stateless_login::begin(
        policy,
        provider,
        peer,
        subject,
        certificate_expires,
        login,
        verifier,
        scope,
        now,
    ) {
        Ok(state) => state,
        Err(rejection) => return Err(MailboxError::Rejected(rejection)),
    };
    prune(mailbox, now);
    if live(&mailbox.slots) >= MAX_PENDING {
        return Err(MailboxError::TooMany);
    }
    if find(&mailbox.slots, &state.login) < mailbox.slots.len() {
        return Err(MailboxError::Duplicate);
    }
    if mailbox.next == LAST_SERIAL {
        return Err(MailboxError::Exhausted);
    }
    let slot = Slot {
        entry: stateless_login::entry_of(&state),
        serial: mailbox.next,
        token: Vec::new(),
        expires_at: 0,
        renew_until: 0,
    };
    mailbox.next += 1;
    let index = vacancy(&mailbox.slots);
    if index < mailbox.slots.len() {
        mailbox.slots[index] = Some(slot);
    } else {
        mailbox.slots.push(Some(slot));
    }
    Ok(state)
}

/// Spec section 8.1 step 3: whether `state` is this replica's pending,
/// current login (the interstitial page). Changes nothing.
pub fn pending(
    mailbox: &Mailbox,
    policy: &LoginPolicy,
    state: &LoginState,
    now: i64,
) -> Result<(), MailboxError> {
    let index = find(&mailbox.slots, &state.login);
    if index >= mailbox.slots.len() {
        return Err(MailboxError::Unknown);
    }
    match &mailbox.slots[index] {
        None => Err(MailboxError::Unknown),
        Some(slot) => {
            if !stateless_login::same_login(policy, &slot.entry, state) {
                return Err(MailboxError::Consumed);
            }
            match slot.entry.stage {
                Stage::Pending => (),
                _ => return Err(MailboxError::Consumed),
            }
            if now >= slot.entry.expires_at {
                return Err(MailboxError::Expired);
            }
            Ok(())
        }
    }
}

/// Spec section 8.1 steps 5-6: one provider redirect for the login whose
/// sealed state the adapter opened. An accepted, undenied callback moves the
/// entry to `Exchanging` and returns the permit for its one code exchange.
#[allow(clippy::too_many_arguments)]
pub fn accept(
    mailbox: &mut Mailbox,
    policy: &LoginPolicy,
    state: &LoginState,
    rule: &IssuerRule,
    issuer: &[u8],
    has_issuer: bool,
    denied: bool,
    now: i64,
) -> Result<Permit, MailboxError> {
    let index = find(&mailbox.slots, &state.login);
    if index >= mailbox.slots.len() {
        return Err(MailboxError::Unknown);
    }
    match &mut mailbox.slots[index] {
        None => Err(MailboxError::Unknown),
        Some(slot) => {
            let stage = match stateless_login::accept_callback(
                policy,
                &slot.entry,
                state,
                rule,
                issuer,
                has_issuer,
                denied,
                now,
            ) {
                Ok(stage) => stage,
                Err(denial) => return Err(MailboxError::Refused(denial)),
            };
            slot.entry.stage = stage;
            if denied {
                return Err(MailboxError::Denied);
            }
            let stage = match stateless_login::begin_exchange(&slot.entry, rule, now) {
                Ok(stage) => stage,
                Err(denial) => return Err(MailboxError::Refused(denial)),
            };
            slot.entry.stage = stage;
            let login: &[u8] = &slot.entry.login;
            let provider: &[u8] = &slot.entry.provider;
            let verifier: &[u8] = &state.verifier;
            Ok(Permit {
                serial: slot.serial,
                login: login.to_vec(),
                provider: provider.to_vec(),
                verifier: verifier.to_vec(),
            })
        }
    }
}

/// Spec section 8.1 step 7: the one code exchange a permit allows, with
/// that login's provider and verifier.
pub fn exchange<E: CodeExchange>(exchanger: &mut E, permit: Permit, code: &[u8]) -> Exchanged {
    let token = exchanger.token(&permit.provider, code, &permit.verifier);
    Exchanged { permit, token }
}

/// The surrogate for an exchanged credential: its expiry from `expires_in`,
/// then [`stateless_login::complete`].
#[allow(clippy::too_many_arguments)]
pub fn issued<S: SurrogateSealer>(
    sealer: &S,
    policy: &IssuePolicy,
    entry: &Entry,
    token: &Token,
    token_id: &[u8],
    now: i64,
    lifetime: i64,
) -> Result<Issued, Rejection> {
    let expires = match stateless::credential_expiry(now, token.has_expires_in, token.expires_in) {
        Ok(expires) => expires,
        Err(rejection) => return Err(rejection),
    };
    stateless_login::complete(
        sealer,
        policy,
        entry,
        &token.credential,
        expires,
        token_id,
        now,
        lifetime,
    )
}

/// Spec section 8.1 step 8: the result of a permitted code exchange. A
/// failed exchange, or a failed issuance, ends the login `Uncertain` with no
/// surrogate. Only the slot the permit was made for can change.
#[allow(clippy::too_many_arguments)]
pub fn finish<S: SurrogateSealer>(
    mailbox: &mut Mailbox,
    exchanged: Exchanged,
    sealer: &S,
    policy: &IssuePolicy,
    token_id: &[u8],
    now: i64,
    lifetime: i64,
) -> Result<(), MailboxError> {
    let index = find(&mailbox.slots, &exchanged.permit.login);
    if index >= mailbox.slots.len() {
        return Err(MailboxError::Unknown);
    }
    match &mut mailbox.slots[index] {
        None => Err(MailboxError::Unknown),
        Some(slot) => {
            if slot.serial != exchanged.permit.serial {
                return Err(MailboxError::Unknown);
            }
            match slot.entry.stage {
                Stage::Exchanging => (),
                _ => return Err(MailboxError::Consumed),
            }
            let result = match &exchanged.token {
                Some(token) => issued(sealer, policy, &slot.entry, token, token_id, now, lifetime),
                None => Err(Rejection::InvalidCredential),
            };
            match result {
                Ok(issued) => {
                    slot.entry.stage = match oauth_login::finish(&slot.entry.stage, true) {
                        Ok(stage) => stage,
                        Err(_) => Stage::Uncertain,
                    };
                    slot.token = issued.token;
                    slot.expires_at = issued.claims.expires_at;
                    slot.renew_until = issued.claims.renew_until;
                    Ok(())
                }
                Err(rejection) => {
                    slot.entry.stage = match oauth_login::finish(&slot.entry.stage, false) {
                        Ok(stage) => stage,
                        Err(_) => Stage::Uncertain,
                    };
                    Err(MailboxError::Rejected(rejection))
                }
            }
        }
    }
}

/// What an agent's poll gets.
pub enum Polled {
    Pending,
    Ready {
        token: Vec<u8>,
        expires_at: i64,
        renew_until: i64,
    },
    Unknown,
    WrongCertificate,
    Denied,
    Failed,
    Expired,
}

/// Spec section 8.1 step 9: one poll by the authenticated `peer`. A
/// surrogate is handed over at most once, and only to the login's peer
/// (`stateless_login::deliver`); handing it over empties the slot.
pub fn poll(mailbox: &mut Mailbox, peer: &[u8], login: &[u8], now: i64) -> Polled {
    let index = find(&mailbox.slots, login);
    if index >= mailbox.slots.len() {
        return Polled::Unknown;
    }
    let delivery = match &mailbox.slots[index] {
        None => return Polled::Unknown,
        Some(slot) => stateless_login::deliver(&slot.entry, peer, now),
    };
    match delivery {
        Delivery::Pending => Polled::Pending,
        Delivery::WrongCertificate => Polled::WrongCertificate,
        Delivery::Denied => Polled::Denied,
        Delivery::Failed => Polled::Failed,
        Delivery::Expired => {
            mailbox.slots[index] = None;
            Polled::Expired
        }
        Delivery::Deliver => {
            let taken = core::mem::replace(&mut mailbox.slots[index], None);
            match taken {
                None => Polled::Unknown,
                Some(slot) => Polled::Ready {
                    token: slot.token,
                    expires_at: slot.expires_at,
                    renew_until: slot.renew_until,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateless::{SurrogateClaims, SurrogateSealer};

    struct Seal;
    impl SurrogateSealer for Seal {
        fn seal(&self, claims: &SurrogateClaims, credential: &[u8]) -> Result<Vec<u8>, Rejection> {
            let mut token = claims.certificate.clone();
            token.push(b':');
            token.extend_from_slice(credential);
            Ok(token)
        }
    }

    /// Answers with `CRED-<code>` when the verifier is `V`.
    struct Endpoint {
        calls: usize,
    }
    impl CodeExchange for Endpoint {
        fn token(&mut self, _provider: &[u8], code: &[u8], verifier: &[u8]) -> Option<Token> {
            self.calls += 1;
            if verifier != b"V" {
                return None;
            }
            let mut credential = b"CRED-".to_vec();
            credential.extend_from_slice(code);
            Some(Token {
                credential,
                has_expires_in: false,
                expires_in: 0,
            })
        }
    }

    fn policy() -> LoginPolicy {
        LoginPolicy {
            replica: b"a".to_vec(),
            providers: vec![b"api".to_vec()],
            ttl: 600,
        }
    }

    fn issue_policy() -> IssuePolicy {
        IssuePolicy {
            issuer: b"i".to_vec(),
            audience: b"a".to_vec(),
            providers: vec![b"api".to_vec()],
            max_lifetime: 3600,
            max_renew: 86400,
        }
    }

    fn begun(
        mailbox: &mut Mailbox,
        login: &[u8],
        peer: &[u8],
        verifier: &[u8],
        now: i64,
    ) -> LoginState {
        start(
            mailbox,
            &policy(),
            b"api",
            peer,
            b"agent",
            99999,
            login,
            verifier,
            b"",
            now,
        )
        .ok()
        .unwrap()
    }

    fn accepted(
        mailbox: &mut Mailbox,
        state: &LoginState,
        now: i64,
    ) -> Result<Permit, MailboxError> {
        accept(
            mailbox,
            &policy(),
            state,
            &IssuerRule::Absent,
            b"",
            false,
            false,
            now,
        )
    }

    fn finished(mailbox: &mut Mailbox, exchanged: Exchanged, now: i64) -> Result<(), MailboxError> {
        finish(mailbox, exchanged, &Seal, &issue_policy(), b"j", now, 900)
    }

    #[test]
    fn one_login_end_to_end() {
        let mut mailbox = empty();
        let mut endpoint = Endpoint { calls: 0 };
        let state = begun(&mut mailbox, b"L1", b"PEER", b"V", 100);
        assert!(pending(&mailbox, &policy(), &state, 150).is_ok());
        let permit = accepted(&mut mailbox, &state, 200).ok().unwrap();
        assert!(
            accepted(&mut mailbox, &state, 201).is_err(),
            "a replayed callback"
        );
        assert!(matches!(
            poll(&mut mailbox, b"PEER", b"L1", 202),
            Polled::Pending
        ));
        let exchanged = exchange(&mut endpoint, permit, b"code1");
        finished(&mut mailbox, exchanged, 203).ok().unwrap();
        assert_eq!(endpoint.calls, 1);
        assert!(matches!(
            poll(&mut mailbox, b"OTHER", b"L1", 204),
            Polled::WrongCertificate
        ));
        match poll(&mut mailbox, b"PEER", b"L1", 205) {
            Polled::Ready { token, .. } => assert_eq!(token, b"PEER:CRED-code1"),
            _ => panic!("ready"),
        }
        assert!(matches!(
            poll(&mut mailbox, b"PEER", b"L1", 206),
            Polled::Unknown
        ));
        assert_eq!(live_count(&mailbox), 0);
    }

    #[test]
    fn failed_exchange_never_delivers() {
        let mut mailbox = empty();
        let mut endpoint = Endpoint { calls: 0 };
        let state = begun(&mut mailbox, b"L1", b"PEER", b"wrong", 100);
        let permit = accepted(&mut mailbox, &state, 200).ok().unwrap();
        let exchanged = exchange(&mut endpoint, permit, b"code1");
        assert!(finished(&mut mailbox, exchanged, 203).is_err());
        assert!(matches!(
            poll(&mut mailbox, b"PEER", b"L1", 204),
            Polled::Failed
        ));
        assert!(accepted(&mut mailbox, &state, 205).is_err());
    }

    #[test]
    fn an_exchange_does_not_reach_a_later_login_with_the_same_id() {
        let mut mailbox = empty();
        let mut endpoint = Endpoint { calls: 0 };
        let first = begun(&mut mailbox, b"L1", b"PEER", b"V", 100);
        let permit = accepted(&mut mailbox, &first, 200).ok().unwrap();
        // The first login is pruned; another peer begins one with the same id.
        let second = begun(&mut mailbox, b"L1", b"OTHER", b"V", 2000);
        let _ = accepted(&mut mailbox, &second, 2001).ok().unwrap();
        let exchanged = exchange(&mut endpoint, permit, b"code1");
        assert!(finished(&mut mailbox, exchanged, 2002).is_err());
        assert!(matches!(
            poll(&mut mailbox, b"OTHER", b"L1", 2003),
            Polled::Pending
        ));
    }

    #[test]
    fn duplicate_and_capacity() {
        let mut mailbox = empty();
        let _ = begun(&mut mailbox, b"L1", b"PEER", b"V", 100);
        assert!(matches!(
            start(
                &mut mailbox,
                &policy(),
                b"api",
                b"P",
                b"a",
                99999,
                b"L1",
                b"V",
                b"",
                101
            ),
            Err(MailboxError::Duplicate)
        ));
        for i in 1..MAX_PENDING {
            let login = format!("L{i}x");
            let _ = begun(&mut mailbox, login.as_bytes(), b"PEER", b"V", 100);
        }
        assert!(matches!(
            start(
                &mut mailbox,
                &policy(),
                b"api",
                b"P",
                b"a",
                99999,
                b"full",
                b"V",
                b"",
                101
            ),
            Err(MailboxError::TooMany)
        ));
        // Expired logins are pruned and their slots reused.
        let _ = begun(&mut mailbox, b"late", b"PEER", b"V", 2000);
        assert_eq!(live_count(&mailbox), 1);
        assert_eq!(mailbox.slots.len(), MAX_PENDING);
    }
}
