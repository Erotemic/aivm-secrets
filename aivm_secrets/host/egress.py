"""The one trusted egress path: where a credential leaves the host.

An executor is constructed for exactly one :class:`Egress` and accepts only
an :class:`AuthorizedEffect` from the kernel. It can therefore reach one TLS
identity, with one authentication scheme, on a request the kernel computed.
There is no URL parameter, no redirect following, no retry, no proxy
environment and no fallback origin (ROUTE-01, COMP-01).

Failures are reported as fixed codes that tell the caller what is known
about a write:

``unreachable``        no connection was established; nothing was sent
``outcome_unknown``    a write was sent and did not come back 2xx. Any other
                       status, 4xx included, leaves the outcome open: only
                       the provider's own contract could say otherwise
``upstream_rejected``  a *read* was answered 4xx
``upstream_error`` / ``upstream_response``  a read failed or was unusable
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import threading
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..kernel import codec, grammar
from ..kernel.machine import AuthorizedEffect
from ..kernel.model import Egress, check_effect
from ..kernel.wire import MAX_RESPONSE
from .files import Roots, read_owned

USER_AGENT = 'aivm-secrets/1'
CONNECT_TIMEOUT = 10.0
IO_TIMEOUT = 15.0
# A hard bound on one exchange. A peer that trickles one byte per socket
# timeout cannot hold a request, or the session lock behind it, open.
TOTAL_DEADLINE = 45.0
MAX_CA_BYTES = 1024 * 1024


def tls_context(egress: Egress, untrusted: Roots = ()) -> ssl.SSLContext:
    """Verified TLS 1.2+ to system roots, or to one operator-pinned anchor."""
    # Do not use ``ssl.create_default_context``: it honors SSLKEYLOGFILE,
    # which opens an attacker-selected TLS key log even for the standalone
    # broker. Construct the context explicitly with key logging disabled.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if egress.ca_file:
        try:
            anchors = read_owned(
                Path(egress.ca_file),
                private=False,
                limit=MAX_CA_BYTES,
                untrusted=untrusted,
                what='trust anchor',
            ).decode('ascii')
            context.load_verify_locations(cadata=anchors)
        except (UnicodeError, ssl.SSLError, ValueError):
            raise SecretsError(
                'unsafe_file',
                detail=f'{egress.ca_file}: not a PEM certificate bundle',
            ) from None
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    # Deliberate defense in depth: never export traffic secrets, even if
    # the process was started outside AIVM's scrubbed environment.
    context.keylog_filename = None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class _Connection(http.client.HTTPSConnection):
    """Connect to the pinned address; authenticate the policy's hostname.

    ``abort`` must be able to end the exchange from another thread at any
    point -- mid-handshake, mid-headers or mid-body. Wrapping a socket in
    TLS *detaches* the original object, so the connection keeps its own
    duplicate descriptor of the same kernel socket and shuts that down:
    whichever call is blocked on the connection returns at once.
    """

    def __init__(self, egress: Egress, context: ssl.SSLContext):
        super().__init__(
            egress.host, egress.port, timeout=IO_TIMEOUT, context=context
        )
        self._tls = context
        self._address = egress.address or egress.host
        self._killer: socket.socket | None = None
        self.aborted = False

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._address, self.port), CONNECT_TIMEOUT
        )
        try:
            self._killer = socket.socket(fileno=os.dup(raw.fileno()))
            raw.settimeout(IO_TIMEOUT)
            self.sock = self._tls.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise

    def abort(self) -> None:
        self.aborted = True
        killer = self._killer
        if killer is not None:
            try:
                killer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        super().close()
        killer, self._killer = self._killer, None
        if killer is not None:
            killer.close()


def _check_success_framing(response: http.client.HTTPResponse) -> None:
    """Require one unambiguous, bounded HTTP success-body framing mode.

    ``http.client`` accepts close-delimited bodies, repeated Content-Length,
    and a simultaneous Transfer-Encoding/Content-Length in some cases. Those
    may produce valid JSON despite disagreeing about the authenticated reply
    boundary. This broker accepts only one explicit length or chunked framing.
    The library remains responsible for decoding chunked bytes; the adapter
    checks the declared mode before allowing a result to leave custody.
    """
    # HTTP 206 is a successful *partial representation*, not a complete
    # answer. Provider-controlled Content-Range cannot authorize disclosure.
    if response.status == 206:
        raise SecretsError('upstream_response')
    lengths = response.msg.get_all('Content-Length', [])
    transfers = response.msg.get_all('Transfer-Encoding', [])
    # 204 is terminated by its header section; RFC 9110 forbids both a
    # payload and Content-Length. ``http.client`` intentionally hides any
    # body/framing it might have received for this status.
    if response.status == 204:
        if lengths or transfers:
            raise SecretsError('upstream_response')
        return
    if len(lengths) + len(transfers) != 1:
        raise SecretsError('upstream_response')
    if lengths:
        length = lengths[0]
        # Bound decimal parsing before conversion (Python itself limits very
        # long integer strings, but that must not choose our public error).
        if (not length or len(length) > 20 or not length.isascii()
                or not length.isdecimal() or response.chunked):
            raise SecretsError('upstream_response')
        value = int(length)
        if value > MAX_RESPONSE or response.length != value:
            raise SecretsError('upstream_response')
    elif transfers != ['chunked'] or not response.chunked:
        raise SecretsError('upstream_response')


class HTTPSExecutor:
    def __init__(self, egress: Egress, untrusted: Roots = ()):
        self.egress = egress
        # Built once, so a trust anchor that is unsafe or unreadable stops
        # the session at start rather than at the first request.
        self._context = tls_context(egress, untrusted)

    def _headers(self, authorized: AuthorizedEffect, credential: str) -> dict:
        effect = authorized.effect
        headers = {
            'Accept': effect.accept,
            'Accept-Encoding': 'identity',
            'User-Agent': USER_AGENT,
        }
        headers.update(self.egress.headers)
        if self.egress.authentication == 'bearer':
            headers['Authorization'] = 'Bearer ' + credential
        else:
            headers['X-API-Key'] = credential
        if effect.body is not None:
            headers['Content-Type'] = 'application/json'
        return headers

    def execute(self, authorized: AuthorizedEffect, credential: str, *,
                idempotency_key: str | None = None) -> Any:
        if type(authorized) is not AuthorizedEffect:
            raise SecretsError('denied')
        effect = check_effect(authorized.effect)
        # What a failure means depends on what the operation was *declared*
        # to be, not on its method: a GET may be a declared write.
        write = authorized.write
        if (effect.is_write and not write) or (write and not authorized.final):
            raise SecretsError('denied')
        if idempotency_key is not None:
            # Supplied only by the broker after durable reservation, never
            # by a guest header. An incorrectly typed value fails closed.
            if not write or not authorized.final:
                raise SecretsError('denied')
            grammar.hex_string(idempotency_key, 64, code='denied')
        body = None
        if effect.graphql:
            fields = dict(effect.body or ())
            body = codec.dumps({
                'query': fields['query'],
                'operationName': fields['operation_name'],
                'variables': codec.loads(fields['variables'], code='denied'),
            })
        elif effect.body is not None:
            body = codec.dumps(dict(effect.body))
        headers = self._headers(authorized, credential)
        if idempotency_key is not None:
            headers['Idempotency-Key'] = idempotency_key
        connection = _Connection(self.egress, self._context)
        watchdog = threading.Timer(TOTAL_DEADLINE, connection.abort)
        watchdog.daemon = True
        sent = False
        response = None
        try:
            watchdog.start()
            try:
                connection.connect()
            except Exception:
                raise SecretsError('unreachable') from None
            sent = True
            connection.request(
                effect.method, effect.target, body=body, headers=headers
            )
            response = connection.getresponse()
            status = response.status
            if 400 <= status < 500:
                # The service answered and declined. Its body is provider
                # text and is never read.
                raise SecretsError('upstream_rejected', status=status)
            if not 200 <= status < 300:
                raise SecretsError('upstream_error', status=status)
            _check_success_framing(response)
            if status != 204:
                media = response.msg.get_all('Content-Type', [])
                expected_media = 'text/plain' if effect.response == 'text' else 'application/json'
                if len(media) != 1 or media[0].split(';', 1)[0].strip() != expected_media:
                    raise SecretsError('upstream_response')
            if response.getheader('Content-Encoding', 'identity') != 'identity':
                raise SecretsError('upstream_response')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise SecretsError('upstream_response')
            if connection.aborted or response.length:
                # Cut off by the deadline, or shorter than its own declared
                # length: a transport failure, not an answer to interpret.
                raise SecretsError('upstream_error')
            if effect.response == 'text':
                try:
                    return data.decode('utf-8')
                except UnicodeError:
                    raise SecretsError('upstream_response') from None
            result = codec.loads(
                data, limit=MAX_RESPONSE, code='upstream_response'
            )
            # GraphQL failures often have HTTP 200 and an `errors` object.
            # Never expose provider diagnostic text through the guest.
            if effect.graphql and (type(result) is not dict or result.get('errors')
                                   or type(result.get('data')) is not dict):
                raise SecretsError('upstream_response')
            return result
        except SecretsError as ex:
            # Once a write has been sent, no HTTP status proves it was not
            # applied: a service may act and then answer 409 or 422. The
            # status is kept as a datum; the verdict is "unknown".
            if write and sent:
                raise SecretsError(
                    'outcome_unknown', status=ex.status
                ) from None
            raise
        except Exception:
            code = 'outcome_unknown' if write else 'upstream_error'
            raise SecretsError(code) from None
        finally:
            watchdog.cancel()
            if response is not None:
                response.close()
            connection.close()
