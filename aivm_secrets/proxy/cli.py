"""``aivm-secrets proxy``: one HTTPS proxy profile session.

``credential-substitution`` holds the credential itself. ``constrained-http``
holds an in-process broker built from ``--service-policy`` (a schema-2
HTTPS policy), which holds the credential; the proxy only translates
requests that equal named operations (see :mod:`.constrained`).

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
import os
import secrets
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
    parser.add_argument('--service-policy', type=Path,
                        help='constrained-http: the broker policy whose operations are allowed')
    parser.add_argument('--broker-audit', type=Path)
    parser.add_argument('--writes', choices=('deny', 'allow'), default='deny')
    parser.add_argument('--access-identity', default='')
    parser.add_argument('--vm', default='')
    where = parser.add_mutually_exclusive_group()
    where.add_argument('--unix', type=Path)
    where.add_argument('--port', type=int, default=0)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    broker = None
    try:
        policy = load_policy(args.policy)
        credential = credential_from_file(args.credential_file)
        if policy.profile == 'constrained-http':
            if args.service_policy is None or args.broker_audit is None:
                raise PolicyError('invalid_policy')
            from ..cli import load_policy as load_service
            from ..host.broker import Broker
            from ..kernel.model import Binding

            binding = Binding(os.getuid(), args.access_identity or f'local-uid-{os.getuid()}',
                              args.vm or 'local', secrets.token_hex(16))
            broker = Broker(load_service(args.service_policy), binding, credential,
                            args.broker_audit, writes=args.writes)
            session = ProxySession(policy, None, broker=broker, audit=ProxyAudit(args.audit))
        elif args.service_policy is not None:
            raise PolicyError('invalid_policy')
        else:
            session = ProxySession(policy, credential.encode('ascii'),
                                   audit=ProxyAudit(args.audit))
        secret = credential.encode('ascii')
        del credential
        return _serve(args, policy, session, secret)
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
    finally:
        # The broker owns the credential and its audit; close it on every path.
        if broker is not None:
            broker.close()


def _serve(args, policy, session, secret: bytes) -> int:
    with ProxyServer(session, unix_path=args.unix, port=args.port) as server:
        announcement = {
            'version': ANNOUNCE_VERSION, 'ready': True, 'profile': policy.profile,
            'listen': server.address, 'origins': sorted(policy.origins),
            'ca_pem': session.ca.pem.decode('ascii'), 'proxy_token': session.token,
        }
        if secret in json.dumps(announcement).encode():
            raise PolicyError('credential_exposed')
        _emit(announcement)
        try:
            while sys.stdin.buffer.read(4096):
                pass
        except KeyboardInterrupt:
            pass
    return 0
