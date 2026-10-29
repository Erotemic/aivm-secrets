"""The transient login mailbox, the profile's only mutable process state
(Rust ``stateless_mailbox``; spec section 9).

Part of the Python reference: tested against the same vectors as the Rust
crate, not proved. No I/O, clock or randomness."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .stateless import (
    MAX_TIME,
    IssuePolicy,
    Rejection,
    SurrogateSealer,
    credential_expiry,
)
from .stateless_login import (
    DELIVERY_GRACE,
    Entry,
    LoginDenial,
    LoginPolicy,
    LoginState,
    Stage,
    accept_callback,
    begin_exchange,
    begin_login,
    complete,
    deliver,
    entry_of,
    same_login,
    with_stage,
)

MAX_PENDING = 1024
LAST_SERIAL = 2**64 - 1


class MailboxError(Exception):
    """A refused mailbox transition; ``code`` is the public error name."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class Slot:
    entry: Entry
    serial: int
    token: bytes = b''
    expires_at: int = 0
    renew_until: int = 0


class Mailbox:
    """The broker's only mutable state. Change it only through the functions
    below, under one lock."""

    def __init__(self) -> None:
        self.slots: list[Slot | None] = []
        self.next = 0

    def live(self) -> int:
        return sum(slot is not None for slot in self.slots)

    def find(self, login: str) -> int:
        for index, slot in enumerate(self.slots):
            if slot is not None and slot.entry.login == login:
                return index
        return len(self.slots)


@dataclass(frozen=True)
class Permit:
    """Leave for the one code exchange of an accepted login."""
    serial: int
    login: str
    provider: str
    verifier: str


@dataclass(frozen=True)
class Token:
    credential: bytes
    expires_in: int | None


@dataclass(frozen=True)
class Exchanged:
    permit: Permit
    token: Token | None


def _kept(slot: Slot | None, now: int) -> bool:
    return (slot is not None and slot.entry.expires_at <= MAX_TIME - DELIVERY_GRACE
            and now < slot.entry.expires_at + DELIVERY_GRACE)


def mailbox_start(mailbox: Mailbox, policy: LoginPolicy, provider: str, peer: str, subject: str,
                  certificate_expires: int, login: str, verifier: str, scope: str, now: int) -> LoginState:
    state = begin_login(policy, provider, peer, subject, certificate_expires, login, verifier, scope, now)
    mailbox.slots = [slot if _kept(slot, now) else None for slot in mailbox.slots]
    if mailbox.live() >= MAX_PENDING:
        raise MailboxError('too_many_logins')
    if mailbox.find(state.login) < len(mailbox.slots):
        raise MailboxError('internal_error')
    if mailbox.next == LAST_SERIAL:
        raise MailboxError('internal_error')
    slot = Slot(entry_of(state), mailbox.next)
    mailbox.next += 1
    for index, existing in enumerate(mailbox.slots):
        if existing is None:
            mailbox.slots[index] = slot
            break
    else:
        mailbox.slots.append(slot)
    return state


def mailbox_pending(mailbox: Mailbox, policy: LoginPolicy, state: LoginState, now: int) -> None:
    index = mailbox.find(state.login)
    if index >= len(mailbox.slots):
        raise MailboxError('login_unknown')
    slot = mailbox.slots[index]
    if not same_login(policy, slot.entry, state) or slot.entry.stage is not Stage.PENDING:
        raise MailboxError('login_consumed')
    if now >= slot.entry.expires_at:
        raise MailboxError('login_expired')


_DENIALS = {'invalid': 'invalid_callback', 'expired': 'login_expired', 'consumed': 'login_consumed'}


def mailbox_accept(mailbox: Mailbox, policy: LoginPolicy, state: LoginState, issuer_rule: str | None,
                   issuer: str | None, denied: bool, now: int) -> Permit:
    index = mailbox.find(state.login)
    if index >= len(mailbox.slots):
        raise MailboxError('login_unknown')
    slot = mailbox.slots[index]
    try:
        slot.entry = with_stage(slot.entry, accept_callback(policy, slot.entry, state, issuer_rule, issuer,
                                                            denied, now))
        if denied:
            raise MailboxError('login_denied')
        slot.entry = with_stage(slot.entry, begin_exchange(slot.entry, now))
    except LoginDenial as denial:
        raise MailboxError(_DENIALS[denial.code]) from None
    return Permit(slot.serial, slot.entry.login, slot.entry.provider, state.verifier)


def mailbox_exchange(token: Callable[[str, str, str], Token | None], permit: Permit, code: str) -> Exchanged:
    """The one code exchange a permit allows: ``token(provider, code, verifier)``."""
    return Exchanged(permit, token(permit.provider, code, permit.verifier))


def mailbox_finish(mailbox: Mailbox, exchanged: Exchanged, sealer: SurrogateSealer, policy: IssuePolicy,
                   token_id: str, now: int, lifetime: int) -> None:
    index = mailbox.find(exchanged.permit.login)
    if index >= len(mailbox.slots) or mailbox.slots[index].serial != exchanged.permit.serial:
        raise MailboxError('login_unknown')
    slot = mailbox.slots[index]
    if slot.entry.stage is not Stage.EXCHANGING:
        raise MailboxError('login_consumed')
    try:
        if exchanged.token is None:
            raise Rejection('invalid_credential')
        expires = credential_expiry(now, exchanged.token.expires_in)
        issued = complete(sealer, policy, slot.entry, exchanged.token.credential, expires, token_id, now, lifetime)
    except Rejection as rejection:
        slot.entry = with_stage(slot.entry, Stage.UNCERTAIN)
        raise MailboxError(rejection.code) from None
    slot.entry = with_stage(slot.entry, Stage.COMPLETE)
    slot.token, slot.expires_at, slot.renew_until = issued.token, issued.claims.expires_at, issued.claims.renew_until


def mailbox_poll(mailbox: Mailbox, peer: str, login: str, now: int) -> tuple[str, Slot | None]:
    """(outcome, slot): ``ready`` hands over and removes the slot."""
    index = mailbox.find(login)
    if index >= len(mailbox.slots):
        return 'unknown', None
    slot = mailbox.slots[index]
    outcome = deliver(slot.entry, peer, now)
    if outcome in ('expired', 'deliver'):
        mailbox.slots[index] = None
    return ('ready' if outcome == 'deliver' else outcome), slot


