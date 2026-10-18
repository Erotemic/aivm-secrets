"""The trusted interpreter around the kernel.

The broker owns everything the kernel must not: the session key, the clock,
randomness, the audit file and the executor. It makes no authorization
decision of its own. Each guest frame is driven through the same fixed
sequence of kernel transitions, and the only thing ever handed to the
executor is the :class:`AuthorizedEffect` a transition returned::

    note_attempt -> open capability -> admit            (budget reserved)
      audit "authorized"
      emit_preflight -> execute (read-only facts)       [fact-conditioned only]
      audit "dispatch"                                  (intent is durable)
      emit_final -> execute                             (liveness re-sampled)
      audit "completed"
    settle

Two locks keep revocation prompt. ``_requests`` serializes guest requests end
to end, so budgets are never observed concurrently. ``_mutex`` guards only
kernel transitions, so a host ``revoke`` or ``approve`` never waits behind a
slow provider; the next emission simply observes it.
"""

from __future__ import annotations

import secrets
from contextlib import nullcontext
from typing import ContextManager
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..errors import SecretsError
from ..kernel import codec, machine, wire
from ..kernel.model import Binding, Clock, Request
from ..kernel.scope import Narrowing
from ..kernel.service import ServiceSpec, reparse
from .audit import AuditLog
from .egress import HTTPSExecutor
from .envelope import EnvelopeCodec, OpenedCapability
from .files import Roots

MAX_PENDING = 16
DEFAULT_APPROVAL_TTL = 300
CLOSE_GRACE = 5.0


@dataclass
class _Trace:
    """What is known about the request in flight, for its audit records."""

    ticket: machine.Ticket | None = None
    operation: str = ''
    digest: str = ''
    wrote: bool = False


class Broker:
    def __init__(
        self,
        spec: ServiceSpec,
        binding: Binding,
        credential: str,
        audit_path: Path,
        *,
        writes: str = 'deny',
        executor: Any = None,
        untrusted: Roots = (),
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        credential_guard: Callable[[], ContextManager[None]] | None = None,
        credential_context: Callable[[], ContextManager[str]] | None = None,
        coordination: Any = None,
    ):
        self.spec = reparse(spec)
        self.binding = Binding.parse(binding.to_dict())
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        if credential_guard is not None and credential_context is not None:
            raise SecretsError('invalid_policy')
        self._credential_guard = credential_guard
        self._credential_context = credential_context
        self._coordination = coordination
        if credential_context is not None:
            # Never seal a caller-supplied stale bearer if the host supplies
            # a fresh leased credential on every request. The capability is
            # only an authenticated session handle in this mode.
            credential = 'oauth-host-managed-session'
        self._codec: EnvelopeCodec | None = EnvelopeCodec()
        self._state, claims = machine.open_session(
            self.spec,
            self.binding,
            secrets.token_hex(16),
            self._clock(),
            write_mode=writes,
        )
        self.capability = self._codec.seal(claims, credential)
        self.expires_at = claims.expires_at
        self._executor = (
            executor
            if executor is not None
            else HTTPSExecutor(self.spec.egress, untrusted)
        )
        self._requests = threading.Lock()
        self._mutex = threading.Lock()
        self._pending: dict[str, dict[str, Any]] = {}
        self._closed = False
        self._audit = AuditLog(Path(audit_path), self.binding.channel)
        try:
            self._audit.record(
                'session_open',
                timestamp=claims.issued_at,
                grant=claims.grant_id,
                digest=self.spec.digest,
            )
        except SecretsError:
            self._audit.close()
            raise

    # -- kernel access ----------------------------------------------------

    def _clock(self) -> Clock:
        return Clock(int(self._wall_clock()), int(self._monotonic_clock()))

    def _step(
        self, transition: Callable[..., machine.State], *args: Any
    ) -> None:
        with self._mutex:
            self._state = transition(self._state, *args)

    def _emit(self, transition: Callable[..., Any], *args: Any) -> Any:
        with self._mutex:
            self._state, value = transition(self._state, *args)
            return value

    def _kill(self) -> None:
        self._step(machine.revoke)

    def _record(
        self,
        event: str,
        request_id: str = '',
        trace: _Trace | None = None,
        *,
        code: str = '',
        **detail: Any,
    ) -> None:
        if trace is not None:
            if trace.ticket is not None:
                detail.setdefault('grant', trace.ticket.grant_id)
                # Only kernel-validated, allowlisted identifiers: never a
                # body field, and never an argument of a rejected request.
                detail.setdefault('resource', dict(trace.ticket.resource))
                detail.setdefault('digest', trace.ticket.request_digest)
            detail.setdefault('operation', trace.operation)
            if trace.digest:
                detail['digest'] = trace.digest
        self._audit.record(
            event,
            request_id,
            timestamp=int(self._wall_clock()),
            code=code,
            **detail,
        )

    # -- guest plane ------------------------------------------------------

    def handle(self, raw: bytes) -> dict[str, Any]:
        """Serve one guest frame. Never raises; always returns a reply."""
        with self._requests:
            with self._mutex:
                envelope = self._codec
                if self._closed or envelope is None:
                    return wire.failure(SecretsError('revoked'))
                try:
                    self._state = machine.note_attempt(self._state)
                except SecretsError as ex:
                    # Deliberately unaudited: the cap exists to bound audit
                    # growth from hostile traffic.
                    return wire.failure(ex)
            request_id = secrets.token_hex(16)
            trace = _Trace()
            try:
                return self._serve(raw, envelope, request_id, trace)
            except SecretsError as ex:
                error = ex
            except Exception:
                error = SecretsError('internal_error')
            finally:
                self._step(machine.settle)
            return self._fail(error, request_id, trace)

    def _serve(
        self,
        raw: bytes,
        envelope: EnvelopeCodec,
        request_id: str,
        trace: _Trace,
    ) -> dict[str, Any]:
        frame = wire.parse_frame(codec.loads(raw))
        opened = envelope.open(frame.capability)
        claims = opened.claims
        # Global revocation also fences describe/delegate/renounce, not only
        # credentialed provider calls. Do not mint child authority from an
        # already revoked principal when the coordinator is unavailable.
        if self._coordination is not None:
            self._coordination.check()
        if frame.verb == 'request':
            return self._request(frame.payload, opened, request_id, trace)
        if frame.verb == 'describe':
            with self._mutex:
                grant = machine.describe(
                    self._state, claims, self.binding, self._clock()
                )
            # The command tables are operator data for the guest client;
            # they describe how to phrase requests and grant nothing.
            return wire.success(grant=grant, cli=self.spec.cli_tables())
        if frame.verb == 'delegate':
            narrowing = Narrowing.parse(frame.payload)
            child = self._emit(
                machine.delegate,
                claims,
                self.binding,
                narrowing,
                secrets.token_hex(16),
                self._clock(),
            )
            capability = envelope.seal(child, opened.credential)
            self._record('delegated', request_id, grant=child.grant_id)
            with self._mutex:
                grant = machine.describe(
                    self._state, child, self.binding, self._clock()
                )
            return wire.success(capability=capability, grant=grant)
        self._step(machine.renounce, claims, self.binding)
        self._record('renounced', request_id, grant=claims.grant_id)
        return wire.success()

    def _request(
        self,
        payload: Any,
        opened: OpenedCapability,
        request_id: str,
        trace: _Trace,
    ) -> dict[str, Any]:
        # Operator-selected OAuth sources resolve the current token *inside*
        # the vault lock on every request. A refresh changes the generation
        # but not the session's enrolled epoch; revocation still fences it.
        if self._credential_context is not None:
            with self._credential_context() as credential:
                return self._request_under_guard(
                    payload, opened, request_id, trace, credential)
        guard = (self._credential_guard() if self._credential_guard is not None
                 else nullcontext())
        with guard:
            return self._request_under_guard(
                payload, opened, request_id, trace, opened.credential)

    def _request_under_guard(
        self,
        payload: Any,
        opened: OpenedCapability,
        request_id: str,
        trace: _Trace,
        credential: str,
    ) -> dict[str, Any]:
        # The retry key is *not* an effect parameter; it cannot select a URL,
        # request target, operation or authorization scope. The pure kernel
        # receives exactly the original canonical request.
        idempotency_key = None
        if type(payload) is dict and 'idempotency_key' in payload:
            idempotency_key = payload['idempotency_key']
            if (type(idempotency_key) is not str or
                    not 8 <= len(idempotency_key) <= 128 or
                    not all(ch in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for ch in idempotency_key)):
                raise SecretsError('invalid_request')
            payload = {key: value for key, value in payload.items()
                       if key != 'idempotency_key'}
        request = self.spec.parse_request(payload)
        trace.operation = request.operation
        operation = self.spec._operation(request)
        # A key on a read is meaningless. In coordinated sessions ALL writes
        # require a durable key, even when the provider does not support an
        # idempotency header; there is no silent unkeyed retry bypass.
        if idempotency_key is not None and (not operation.write or
                                             self._coordination is None):
            raise SecretsError('invalid_request')
        if operation.write and (self._coordination is not None or
                                operation.idempotency_header) and idempotency_key is None:
            raise SecretsError('invalid_request')
        try:
            self._step(
                machine.admit,
                opened.claims,
                self.binding,
                request,
                self._clock(),
            )
        except SecretsError as ex:
            if ex.code == 'approval_required':
                trace.digest = self._remember(opened.claims.grant_id, request)
            raise
        with self._mutex:
            trace.ticket = self._state.ticket
        self._record('authorized', request_id, trace)
        facts = None
        preflight = self._emit(
            machine.emit_preflight, self.spec, request, self._clock()
        )
        if preflight is not None:
            if self._coordination is not None:
                self._coordination.check()
            facts = self._executor.execute(preflight, credential)
        # Computed here only to learn whether a dispatch follows, so that
        # its intent can be made durable first. The kernel recomputes the
        # effect itself; this value is never sent anywhere.
        if self.spec.final(request, facts) is not None:
            self._record('dispatch', request_id, trace)
        final = self._emit(
            machine.emit_final, self.spec, request, facts, self._clock()
        )
        if final is None:
            result = facts
        else:
            # A remote revocation committed before this check forbids this
            # effect. A revocation racing *after* the check cannot unsend an
            # in-flight effect (see coordination's explicit linearization).
            if self._coordination is not None:
                self._coordination.check()
            provider_key = None
            if idempotency_key is not None:
                # The caller-selected retry name is scoped by the operator's
                # global principal, not by the ephemeral session/grant ID.
                # Thus a broker restart or a different trusted host cannot
                # dispatch a second write with the same key. The separate
                # request fingerprint detects key reuse for another payload.
                provider_key = codec.digest({
                    'schema': 1, 'principal': self._coordination.config.principal,
                    'client_key': idempotency_key,
                })
                request_fingerprint = codec.digest({
                    'policy': self.spec.digest, 'request': request.to_dict(),
                })
                self._coordination.reserve(provider_key, request_fingerprint)
            trace.wrote = final.write
            if provider_key is not None and operation.idempotency_header:
                result = self._executor.execute(final, credential,
                                                idempotency_key=provider_key)
            else:
                result = self._executor.execute(final, credential)
            if provider_key is not None:
                # Failure to record completion is ambiguous, not success.
                self._coordination.finish(provider_key, request_fingerprint)
        reply = wire.success(
            result=result, **(self.spec.reply_meta(request, result) or {})
        )
        encoded = codec.dumps(reply, code='upstream_response')
        # Reflection tripwire, not a general information-flow proof.
        needle = codec.dumps(credential)[1:-1]
        if len(encoded) >= wire.MAX_REPLY or needle in encoded:
            raise SecretsError('upstream_response')
        self._record('completed', request_id, trace)
        return reply

    def _fail(
        self, error: SecretsError, request_id: str, trace: _Trace
    ) -> dict[str, Any]:
        if error.code == 'audit_failed':
            self._kill()
        # Once a write has been handed to the executor, exactly one answer
        # is definite: no connection was made, so nothing was sent. Every
        # other failure -- any HTTP status, transport, parsing, or audit --
        # leaves the outcome open.
        if trace.wrote and error.code != 'unreachable':
            error = SecretsError('outcome_unknown', status=error.status)
        extra: dict[str, Any] = {}
        event = 'rejected_or_failed'
        if error.code == 'approval_required':
            event = 'approval_requested'
            extra['approval'] = {'digest': trace.digest}
        try:
            self._record(
                event,
                request_id,
                trace,
                code=error.code,
                status=error.status or None,
            )
        except SecretsError:
            self._kill()
            error = SecretsError(
                'outcome_unknown' if trace.wrote else 'audit_failed'
            )
            extra = {}
        return wire.failure(error, **extra)

    def _remember(self, grant_id: str, request: Request) -> str:
        """Hold an unapproved write, exactly as sent, for the operator."""
        digest = machine.approval_digest(self.spec.digest, grant_id, request)
        with self._mutex:
            self._pending.pop(digest, None)
            while len(self._pending) >= MAX_PENDING:
                del self._pending[next(iter(self._pending))]
            self._pending[digest] = {
                'digest': digest,
                'grant': grant_id,
                'operation': request.operation,
                'arguments': dict(request.arguments),
                'requested_at': int(self._wall_clock()),
            }
        return digest

    # -- host plane -------------------------------------------------------

    def status(self) -> dict[str, Any]:
        with self._mutex:
            state = self._state
            root = state.grants[0]
            return {
                'channel': self.binding.channel,
                'access_identity': self.binding.access_identity,
                'vm': self.binding.vm,
                'owner_uid': self.binding.owner_uid,
                'service': self.spec.service,
                'policy_digest': self.spec.digest,
                'operations': [item.name for item in root.scope],
                'writes': state.write_mode,
                'active': state.active and root.active and not self._closed,
                'expires_at': root.expires_at,
                'used': root.used,
                'max_requests': root.max_requests,
                'attempts': state.attempts,
                'grants': len(state.grants),
                'pending': len(self._pending),
                'audit': str(self._audit.path),
                'audit_head': self._audit.head,
            }

    def control(self, command: Any) -> dict[str, Any]:
        """Serve one host-operator command. Unreachable from the guest socket."""
        try:
            if type(command) is not dict:
                raise SecretsError('invalid_request')
            verb = command.get('command')
            if verb == 'status':
                return wire.success(session=self.status())
            if verb == 'pending':
                with self._mutex:
                    return wire.success(pending=list(self._pending.values()))
            if verb in ('approve', 'deny'):
                digest = self._pending_digest(command.get('digest'))
                if verb == 'approve':
                    ttl = command.get('ttl', DEFAULT_APPROVAL_TTL)
                    self._step(machine.approve, digest, self._clock(), ttl)
                    self._record('approved', digest=digest)
                with self._mutex:
                    self._pending.pop(digest, None)
                return wire.success(digest=digest)
            if verb == 'revoke':
                grant = command.get('grant', '')
                if type(grant) is not str:
                    raise SecretsError('invalid_request')
                self._step(machine.revoke, grant)
                self._record('revoked', grant=grant)
                return wire.success()
            raise SecretsError('invalid_request')
        except SecretsError as ex:
            if ex.code == 'audit_failed':
                self._kill()
            return wire.failure(ex)
        except Exception:
            return wire.failure(SecretsError('internal_error'))

    def _pending_digest(self, prefix: Any) -> str:
        """An operator may abbreviate, but only to exactly one pending write."""
        if type(prefix) is not str or not 8 <= len(prefix) <= 64:
            raise SecretsError('invalid_request')
        with self._mutex:
            matches = [
                item for item in self._pending if item.startswith(prefix)
            ]
        if len(matches) != 1:
            raise SecretsError('invalid_request')
        return matches[0]

    def revoke(self) -> None:
        """Stop all further authority. Idempotent and never blocks on I/O."""
        self._kill()

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            self._state = machine.revoke(self._state)
            self._codec = None
            self.capability = ''
        # Authority is already gone. Give a request that was mid-dispatch a
        # moment to write its own outcome before the audit file is sealed.
        waited = self._requests.acquire(timeout=CLOSE_GRACE)
        try:
            self._record('session_close')
        finally:
            if waited:
                self._requests.release()
            self._audit.close()
