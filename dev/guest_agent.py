#!/usr/bin/env python3
"""A simulated untrusted agent, run inside the guest by the VM acceptance.

An agent is just a program in the guest. This one uses only the standard
library and the session's guest directory (client, config, capability,
forwarded broker socket). It does the useful thing it is allowed to do and
then tries, one by one, to get more than that. It prints one JSON report;
the host decides pass or fail from the report *and* from what the provider
actually saw, so a lying or crashing agent cannot fake a pass.

    python3 guest_agent.py GUEST_DIR REPOSITORY PR
"""
from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys


def client(guest: str, *words: str, timeout: int = 30) -> dict:
    """Run the native client; return its exit status and public JSON."""
    command = [f'{guest}/garrett-client', '--config', f'{guest}/client.json',
               '--capability-file', f'{guest}/capability.jwt', *words]
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'exit': None, 'reply': None}
    try:
        reply = json.loads(result.stdout) if result.stdout.strip() else None
    except ValueError:
        reply = {'unparsed': result.stdout[:200].decode('utf-8', 'replace')}
    return {'exit': result.returncode, 'reply': reply}


def refused(outcome: dict) -> bool:
    """A refusal: nonzero exit and no released result."""
    reply = outcome['reply']
    released = isinstance(reply, dict) and (reply.get('ok') is True or 'result' in reply)
    return outcome['exit'] != 0 and not released


def invoke(guest: str, operation: str, arguments: object) -> dict:
    text = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return client(guest, 'invoke', operation, '--arguments', text)


def raw_socket(path: str, payload: bytes) -> str:
    """Send bytes that are not a TLS client hello; report how it ended."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(path)
        try:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            data = sock.recv(65536)
        except OSError as error:
            return f'closed:{type(error).__name__}'
    return 'closed' if not data else f'answered:{len(data)}'


def tls_without_certificate(path: str, ca: str) -> str:
    """A real TLS client with no client certificate must not get a session."""
    context = ssl.create_default_context(cafile=ca)
    context.check_hostname = False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(path)
        try:
            with context.wrap_socket(sock, server_hostname='localhost') as tls:
                tls.sendall(b'{"version":1,"verb":"describe"}\n')
                data = tls.recv(65536)
        except (ssl.SSLError, OSError) as error:
            return f'refused:{type(error).__name__}'
    return 'refused:empty' if not data else f'answered:{len(data)}'


def main(argv: list[str]) -> int:
    guest, repository, pr = argv[1], argv[2], int(argv[3])
    report: dict = {'attacks': {}}

    view = client(guest, 'gh', 'pr', 'view', str(pr), '--repo', repository,
                  '--json', 'number,title')
    report['useful_read'] = view['exit'] == 0 and view['reply'] == {
        'number': pr, 'title': 'Proof repair'}

    owner, _, name = repository.partition('/')
    attempts = {
        'path_traversal_in_repository': ('pr.view', {'repository': f'{owner}/../../user', 'pr': pr}),
        'encoded_slash_in_repository': ('pr.view', {'repository': f'{owner}%2F..%2F{name}', 'pr': pr}),
        'header_injection_in_repository': ('pr.view', {'repository': f'{repository}\r\nX-Injected: 1', 'pr': pr}),
        'query_in_repository': ('pr.view', {'repository': f'{repository}?per_page=100', 'pr': pr}),
        'other_repository': ('pr.view', {'repository': 'torvalds/linux', 'pr': pr}),
        'other_pull_request': ('pr.view', {'repository': repository, 'pr': pr + 1}),
        'pr_as_path': ('pr.view', {'repository': repository, 'pr': f'{pr}/../../../user'}),
        'pr_negative': ('pr.view', {'repository': repository, 'pr': -pr}),
        'pr_huge': ('pr.view', {'repository': repository, 'pr': 2 ** 70}),
        'pr_float': ('pr.view', {'repository': repository, 'pr': pr + 0.5}),
        'extra_url_argument': ('pr.view', {'repository': repository, 'pr': pr, 'url': 'https://evil.example/'}),
        'missing_argument': ('pr.view', {'repository': repository}),
        'arguments_not_an_object': ('pr.view', [repository, pr]),
        'arguments_not_json': ('pr.view', '{"repository":'),
        'unknown_operation': ('raw.get', {'path': '/user'}),
        'unlisted_write': ('pr.merge', {'repository': repository, 'pr': pr}),
        'denied_write': ('pr.comment', {'repository': repository, 'pr': pr, 'body': 'x'}),
        'oversized_argument': ('pr.view', {'repository': repository + 'a' * 100_000, 'pr': pr}),
    }
    for label, (operation, arguments) in attempts.items():
        outcome = invoke(guest, operation, arguments)
        report['attacks'][label] = 'refused' if refused(outcome) else 'NOT REFUSED'

    broker = f'{guest}/broker.sock'
    report['attacks']['plain_http_on_broker_socket'] = raw_socket(
        broker, b'GET /repos/x/y HTTP/1.1\r\nHost: api.example.org\r\n\r\n')
    report['attacks']['one_megabyte_of_garbage'] = raw_socket(broker, b'A' * (1 << 20))
    report['attacks']['tls_without_client_certificate'] = tls_without_certificate(
        broker, f'{guest}/ca.pem')

    # After all of that, the broker must still do its job.
    again = client(guest, 'gh', 'pr', 'view', str(pr), '--repo', repository, '--json', 'number')
    report['useful_read_after_attacks'] = again['exit'] == 0 and again['reply'] == {'number': pr}
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
