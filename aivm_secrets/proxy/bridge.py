"""Guest-side ``constrained-http`` (HP-6): named operations over the bridge.

The translator in :mod:`.constrained` turns an ordinary HTTPS request into
the one named operation it equals. Here the result is not sent to an
in-process broker but to the guest's native client, ``invoke``, which asks
the host bridge exactly as any other guest tool would. The translator
therefore runs **inside the guest, untrusted, and holds no credential**:

* the host bridge re-checks the operation, its arguments, scope and write
  mode, builds the provider request itself and releases only the
  operation's disclosure, so the native-read theorems apply unchanged;
* the service policy the translator reads is a public copy of the host's
  route templates. A wrong or tampered copy can only make it ask for a
  different named operation, which the bridge authorizes or refuses on its
  own policy. It can never widen authority.

Nothing falls back to credential substitution: an unmatched request is
``unsupported_request``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..kernel import codec
from ..kernel.https import HTTPSpec
from ..kernel.service import parse_policy
from .policy import PolicyError

MAX_ROUTES = 262144
MAX_REPLY = 1 << 22


def load_routes(path: Path) -> HTTPSpec:
    """The public route templates: a schema-2 HTTPS policy, read as data."""
    try:
        with open(path, 'rb') as stream:
            data = stream.read(MAX_ROUTES + 1)
    except OSError as error:
        raise PolicyError('invalid_policy') from error
    if len(data) > MAX_ROUTES:
        raise PolicyError('invalid_policy')
    try:
        spec = parse_policy(codec.loads(data, code='invalid_policy'))
    except SecretsError as error:
        raise PolicyError('invalid_policy') from error
    if not isinstance(spec, HTTPSpec):
        raise PolicyError('invalid_policy')
    return spec


class BridgeDispatcher:
    """Send one translated named request through the guest's ``invoke``.

    Duck-types the part of :class:`~aivm_secrets.host.broker.Broker` the
    proxy session uses (``spec``, ``capability``, ``handle``, ``close``).
    """

    capability = None

    def __init__(self, spec: HTTPSpec, client: list[str], *, timeout: float = 60.0):
        if not client or not all(isinstance(word, str) and word for word in client):
            raise PolicyError('invalid_policy')
        self.spec = spec
        self._client = list(client)
        self._timeout = timeout

    def handle(self, frame: bytes) -> dict[str, Any]:
        request = codec.loads(frame)['request']
        try:
            done = subprocess.run(
                [*self._client, 'invoke', request['operation'], '--arguments-file', '-'],
                input=codec.dumps(request['arguments']), capture_output=True,
                timeout=self._timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return {'version': 1, 'ok': False, 'error': {'code': 'outcome_unknown'}}
        if not done.stdout or len(done.stdout) > MAX_REPLY:
            return {'version': 1, 'ok': False, 'error': {'code': 'outcome_unknown'}}
        try:
            reply = codec.loads(done.stdout)
        except SecretsError:
            return {'version': 1, 'ok': False, 'error': {'code': 'outcome_unknown'}}
        if not isinstance(reply, dict) or not isinstance(reply.get('ok'), bool):
            return {'version': 1, 'ok': False, 'error': {'code': 'outcome_unknown'}}
        return reply

    def close(self) -> None:
        pass
