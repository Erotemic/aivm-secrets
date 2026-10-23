"""``aivm-secrets proxy``: one credential-substitution proxy session.

Process contract v1, mirroring ``native-session``: arguments in, one JSON
announcement line out, and the session lasts until stdin reaches EOF or the
process receives SIGTERM. The announcement carries the listen address, the
session CA certificate (public) and the guest's surrogate proxy token; it
never carries the credential. Failures print ``{"version":1,"ready":false,
"error":CODE}`` and exit 1.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

from ..errors import SecretsError
from ..host.sources import credential_from_file
from .policy import PolicyError, load_policy
from .server import ProxyAudit, ProxyServer, ProxySession

ANNOUNCE_VERSION = 1


def _emit(value: dict) -> None:
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='aivm-secrets proxy')
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--credential-file', required=True, type=Path)
    parser.add_argument('--audit', required=True, type=Path)
    where = parser.add_mutually_exclusive_group()
    where.add_argument('--unix', type=Path)
    where.add_argument('--port', type=int, default=0)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        policy = load_policy(args.policy)
        credential = credential_from_file(args.credential_file).encode('ascii')
        session = ProxySession(policy, credential, audit=ProxyAudit(args.audit))
        with ProxyServer(session, unix_path=args.unix, port=args.port) as server:
            announcement = {
                'version': ANNOUNCE_VERSION, 'ready': True, 'profile': policy.profile,
                'listen': server.address, 'origins': sorted(policy.origins),
                'ca_pem': session.ca.pem.decode('ascii'), 'proxy_token': session.token,
            }
            if credential in json.dumps(announcement).encode():
                raise PolicyError('credential_exposed')
            _emit(announcement)
            try:
                while sys.stdin.buffer.read(4096):
                    pass
            except KeyboardInterrupt:
                pass
    except PolicyError as error:
        _emit({'version': ANNOUNCE_VERSION, 'ready': False, 'error': str(error)})
        return 1
    except SecretsError as error:
        _emit({'version': ANNOUNCE_VERSION, 'ready': False, 'error': error.code})
        return 1
    except (OSError, UnicodeEncodeError):
        _emit({'version': ANNOUNCE_VERSION, 'ready': False, 'error': 'proxy_failed'})
        return 1
    except KeyboardInterrupt:
        return 0
    return 0
