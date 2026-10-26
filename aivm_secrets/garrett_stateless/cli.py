"""``garrett-stateless``: the same command-line interface as the Rust crate's
binary (keys, pki, broker, proxy, mint, inspect, agent)."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import encoding as enc
from . import pki
from .agent import Agent, Endpoint
from .broker import Broker
from .config import BrokerConfig
from .files import read_private, read_public, replace_private, write_private
from .keys import BrokerKeys
from .proxy import Proxy
from .token import inspect


def _line(value: dict) -> None:
    sys.stdout.buffer.write(enc.canonical(value) + b'\n')
    sys.stdout.flush()


def _hold(args) -> None:
    if args.until_stdin_eof:
        sys.stdin.buffer.read()
    else:
        while True:
            time.sleep(3600)


def _agent(args) -> Agent:
    if args.tpm is not None or args.key is None:
        raise SystemExit('the Python agent supports --key only; TPM keys need the Rust client '
                         '(garrett-stateless built with --features tpm)')
    return Agent(Path(args.ca), Path(args.cert), Path(args.key))


def _token(args) -> str:
    return read_private(Path(args.token_file), 32768).decode('ascii').strip()


def _deliver(args, issued) -> None:
    if args.out:
        write_private(Path(args.out), issued.token.encode('ascii'))
        _line({'expires_at': issued.expires_at, 'renew_until': issued.renew_until, 'token_file': args.out})
    else:
        _line({'expires_at': issued.expires_at, 'renew_until': issued.renew_until, 'token': issued.token})


def _keys(args) -> None:
    if args.action == 'init':
        keys = BrokerKeys.generate(args.issuer, args.kid or 'k1')
        write_private(Path(args.out), keys.to_json())
        _line({'active': keys.active})
    elif args.action in ('rotate', 'retire'):
        keys = BrokerKeys.load(Path(args.keys))
        if args.action == 'rotate':
            keys.rotate(keys.active_entry().issuer, args.kid)
        else:
            keys.retire(args.kid)
        replace_private(Path(args.keys), keys.to_json())
        _line({'active': keys.active, 'kids': [e.kid for e in keys.entries]})
    else:
        keys = BrokerKeys.load(Path(args.keys))
        write_private(Path(args.out), keys.export_proxy().to_json())
        _line({'kids': [e.kid for e in keys.entries]})


def _pki(args) -> None:
    if args.action == 'ca':
        issued = pki.create_ca(args.name[0], args.days)
    else:
        ca = pki.Issued(read_public(Path(args.ca_cert)), read_private(Path(args.ca_key)))
        if args.action == 'server':
            issued = pki.issue(ca, server_names=args.name, days=args.days)
        else:
            issued = pki.issue(ca, client_name=args.name[0], uri=args.uri, days=args.days)
    Path(args.cert).write_bytes(issued.certificate)
    write_private(Path(args.key), issued.key)


def _run_agent(args) -> int:
    client = _agent(args)
    if args.action == 'login':
        endpoint = Endpoint.parse(args.broker, args.connect)
        started = client.begin_login(endpoint, args.provider, args.scope)
        _line({'authorization_url': started.authorization_url, 'confirmation': started.confirmation,
               'expires_at': started.expires_at, 'login': started.login})
        _deliver(args, client.wait_for_token(endpoint, started.login, args.timeout))
        return 0
    if args.action == 'renew':
        _deliver(args, client.renew(Endpoint.parse(args.broker, args.connect), _token(args)))
        return 0
    if args.data is not None and args.data_file is not None:
        raise SystemExit('--data and --data-file are exclusive')
    body = args.data.encode('utf-8') if args.data is not None else (
        read_public(Path(args.data_file), 16 << 20) if args.data_file else b'')
    headers = []
    for header in args.H or []:
        name, colon, value = header.partition(':')
        if not colon:
            raise SystemExit('bad -H')
        headers.append((name.strip(), value.strip()))
    method = args.X or ('POST' if body else 'GET')
    response = client.request(Endpoint.parse(args.proxy, args.connect), _token(args), method, args.target,
                              headers, body)
    sys.stderr.write(f'{{"status":{response.status}}}\n')
    sys.stdout.buffer.write(response.body)
    sys.stdout.flush()
    return 22 if response.status >= 400 else 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog='garrett-stateless', description='garrett-stateless-v1 broker, proxy and agent')
    commands = top.add_subparsers(dest='command', required=True)

    keys = commands.add_parser('keys')
    keys.add_argument('action', choices=['init', 'rotate', 'retire', 'export'])
    for name in ('--issuer', '--kid', '--out', '--keys'):
        keys.add_argument(name)

    pki_ = commands.add_parser('pki')
    pki_.add_argument('action', choices=['ca', 'server', 'client'])
    pki_.add_argument('--name', action='append', required=True)
    for name in ('--ca-cert', '--ca-key', '--uri'):
        pki_.add_argument(name)
    pki_.add_argument('--cert', required=True)
    pki_.add_argument('--key', required=True)
    pki_.add_argument('--days', type=int, default=30)

    for role in ('broker', 'proxy'):
        server = commands.add_parser(role)
        server.add_argument('--config', required=True)
        server.add_argument('--until-stdin-eof', action='store_true')

    mint = commands.add_parser('mint')
    for name in ('--config', '--provider', '--credential-file', '--certificate'):
        mint.add_argument(name, required=True)
    mint.add_argument('--lifetime', type=int)
    mint.add_argument('--out')

    insp = commands.add_parser('inspect')
    insp.add_argument('token', nargs='?')
    insp.add_argument('--token-file')

    commands.add_parser('agent', add_help=False)
    return top


def agent_parser() -> argparse.ArgumentParser:
    agent = argparse.ArgumentParser(prog='garrett-stateless agent')
    agent.add_argument('action', choices=['login', 'renew', 'request'])
    for name in ('--broker', '--proxy', '--connect', '--provider', '--scope', '--out', '--token-file',
                 '--data', '--data-file', '-X'):
        agent.add_argument(name)
    for name in ('--ca', '--cert'):
        agent.add_argument(name, required=True)
    agent.add_argument('--key')
    agent.add_argument('--tpm')
    agent.add_argument('-H', action='append')
    agent.add_argument('--timeout', type=float, default=600)
    agent.add_argument('target', nargs='?')
    return agent


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['agent']:
        # The target may follow options, as in curl.
        args = agent_parser().parse_intermixed_args(argv[1:])
        args.command = 'agent'
    else:
        args = parser().parse_args(argv)
    try:
        if args.command == 'keys':
            _keys(args)
        elif args.command == 'pki':
            _pki(args)
        elif args.command in ('broker', 'proxy'):
            if args.command == 'broker':
                running = Broker.from_file(Path(args.config)).serve()
                _line({'agent': running.agent_address, 'browser': running.browser_address,
                       'profile': 'garrett-stateless-v1', 'role': 'broker'})
            else:
                running = Proxy.from_file(Path(args.config)).serve()
                _line({'address': running.address, 'profile': 'garrett-stateless-v1', 'role': 'proxy'})
            _hold(args)
            running.stop()
        elif args.command == 'mint':
            broker = Broker(BrokerConfig.load(Path(args.config)), BrokerKeys.load(
                BrokerConfig.load(Path(args.config)).keys))
            credential = read_private(Path(args.credential_file), 8192).strip()
            cert = x509.load_pem_x509_certificate(read_public(Path(args.certificate)))
            _deliver(args, broker.mint(args.provider, credential, cert.public_bytes(serialization.Encoding.DER),
                                       args.lifetime))
        elif args.command == 'inspect':
            token = _token(args) if args.token_file else args.token
            if not token:
                raise SystemExit('TOKEN is required')
            header, payload = inspect(token)
            _line({'header': header, 'payload': payload, 'verified': False})
        else:
            return _run_agent(args)
    except (OSError, ValueError) as error:
        sys.stderr.write(f'garrett-stateless: {type(error).__name__}: {error}\n')
        return 1
    except Exception as error:  # noqa: BLE001 - closed codes only, never secrets
        code = getattr(error, 'code', type(error).__name__)
        sys.stderr.write(f'garrett-stateless: {code}\n')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
