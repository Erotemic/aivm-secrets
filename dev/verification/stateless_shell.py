#!/usr/bin/env python3
"""Privileged call sites of the `garrett-stateless` native shell.

The extracted core (`aivm-secrets-garrett-core/src/stateless*.rs`) makes every
garrett-stateless-v1 decision, and `proofs/GarrettStateless*.lean` prove them.
The shell only performs I/O around those decisions. This guard pins, in the
shell's source, each place where a credential, a signing or sealing key, a
provider connection or an audit record is handled, and checks that each one is
reached only through the extracted interface the proofs quantify over:

* the proxy's one provider write sends `egress_wire` of an `Egress`, which only
  the core's `serve` makes, and only `Origin::exchange` calls it;
* the proxy serves every request for the peer of its TLS handshake;
* the broker seals only through `seal_token`, behind `stateless::issue`,
  `stateless::renew` or the mailbox's `finish`, and drives each mailbox
  transition from exactly one endpoint;
* the OAuth access token becomes a `Token` only inside the permitted exchange,
  and a refresh token is never kept;
* audit records name claims, routes and codes only.

It is a source guard over the shell, not a proof and not a call-graph or
dependency analysis; `docs/verified-garrett-stateless.md` states the trusted
remainder.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SHELL = 'rust/crates/garrett-stateless/src'
CORE = 'rust/crates/aivm-secrets-garrett-core/src'


class ShellError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ShellError(message)


def code_only(source: str) -> str:
    """The source with comments, strings and char literals blanked."""
    out = []
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if source.startswith('//', i):
            j = source.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif source.startswith('/*', i):
            j = source.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', source[i:j]))
            i = j
        elif c == 'b' and source.startswith('b"', i) or c == '"':
            start = i
            i += 2 if c == 'b' else 1
            while i < n and source[i] != '"':
                i += 2 if source[i] == '\\' else 1
            i += 1
            out.append('"' + ' ' * max(0, i - start - 2) + '"')
        elif c == "'" and re.match(r"'(\\.|[^\\'])'", source[i:i + 4]):
            m = re.match(r"'(\\.|[^\\'])'", source[i:i + 4])
            out.append(' ' * len(m.group(0)))
            i += len(m.group(0))
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def body_start(code: str, at: int) -> int:
    """Where the body of the `fn` signature at `at` opens, or -1 for a declaration."""
    depth = 0
    for j in range(at, len(code)):
        c = code[j]
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif depth == 0 and c == ';':
            return -1
        elif depth == 0 and c == '{':
            return j
    return -1


def functions(source: str) -> dict[str, list[str]]:
    """Every `fn` name with the text of each body (in the original source)."""
    code = code_only(source)
    found: dict[str, list[str]] = {}
    for match in re.finditer(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)', code):
        brace = body_start(code, match.end())
        if brace < 0:
            continue
        depth = 0
        for j in range(brace, len(code)):
            if code[j] == '{':
                depth += 1
            elif code[j] == '}':
                depth -= 1
                if depth == 0:
                    found.setdefault(match.group(1), []).append(source[match.start():j + 1])
                    break
    return found


def callers(source: str, call: str) -> list[str]:
    """The innermost named functions whose bodies contain `call` in code."""
    names = []
    for name, bodies in functions(source).items():
        for body in bodies:
            if call in code_only(body):
                names.append(name)
    return names


def owners(source: str, call: str) -> set[str]:
    """The innermost functions containing each occurrence of `call`."""
    code = code_only(source)
    result = set()
    spans = []
    for match in re.finditer(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)', code):
        brace = body_start(code, match.end())
        if brace < 0:
            continue
        depth = 0
        for j in range(brace, len(code)):
            if code[j] == '{':
                depth += 1
            elif code[j] == '}':
                depth -= 1
                if depth == 0:
                    spans.append((match.start(), j, match.group(1)))
                    break
    start = 0
    while True:
        k = code.find(call, start)
        if k < 0:
            break
        inside = [s for s in spans if s[0] <= k <= s[1]]
        require(inside, f'{call!r} outside any function')
        result.add(min(inside, key=lambda s: s[1] - s[0])[2])
        start = k + 1
    return result


def count(source: str, text: str) -> int:
    return code_only(source).count(text)


def check(root: Path = ROOT) -> list[str]:
    shell = {p.name: p.read_text() for p in sorted((root / SHELL).glob('*.rs'))}
    core = {p.name: p.read_text() for p in sorted((root / CORE).glob('stateless*.rs'))}
    every = '\n'.join(shell.values())
    checked = []

    # No escape from the type system anywhere in the shell.
    for name, source in shell.items():
        require(not re.search(r'\bunsafe\b', code_only(source)), f'unsafe code in {name}')
    checked.append('no unsafe code in the shell')

    # The proxy's provider write.
    proxy = shell['proxy.rs']
    require(count(every, 'egress_wire(') == 1, 'egress_wire must be read exactly once in the shell')
    require(owners(proxy, 'egress_wire(') == {'send_upstream'}, 'egress_wire read outside send_upstream')
    require('tls.write_all(egress_wire(&egress))' in proxy, 'the provider write is not the egress bytes')
    require(count(every, 'send_upstream(') == 2, 'send_upstream must be defined once and called once')
    require(owners(proxy, '.send_upstream(') == {'exchange'}, 'send_upstream called outside Origin::exchange')
    exchange = functions(proxy)['exchange'][0]
    require('egress: Egress' in exchange, 'Origin::exchange no longer takes the core Egress')
    require(not re.search(r'\b(loop|while|for)\b', code_only(exchange)), 'Origin::exchange retries')
    send = functions(proxy)['send_upstream'][0]
    require(count(send, 'write_all(') == 1, 'send_upstream writes more than once')
    checked.append('the proxy writes to a provider once per Egress, only in Origin::exchange')

    # The core alone makes an Egress, from an admitted decision.
    core_proxy = core['stateless_proxy.rs']
    struct = re.search(r'pub struct Egress \{(.*?)\}', core_proxy, re.S)
    require(struct is not None, 'Egress struct missing')
    require('pub ' not in struct.group(1), 'Egress fields are public')
    built = re.findall(r'(?<!struct )\bEgress \{', code_only(core_proxy))
    require(len(built) == 1, 'Egress is built more than once in the core')
    require(owners(core_proxy, '(Egress {') == {'serve'}, 'Egress built outside serve')
    for name, source in shell.items():
        require('Egress {' not in code_only(source), f'{name} builds an Egress')
    checked.append('only the core serve makes an Egress; its fields are private')

    # The proxy's peer is the TLS handshake's.
    connection = functions(proxy)['connection'][0]
    require('PeerIdentity::from_connection(&stream.conn)' in connection, 'peer not from the handshake')
    require(re.search(r'stateless_proxy::connection\((?:.|\n)*?peer\.thumbprint\.as_bytes\(\)', connection),
            'connection not served for the handshake peer')
    require(count(every, 'stateless_proxy::connection(') == 1, 'a second connection loop')
    checked.append('every proxied request is decided for the TLS handshake peer')

    # Sealing and the mailbox, from exactly their endpoints.
    broker = shell['broker.rs']
    expect = {
        'stateless::issue(': {'mint_with'},
        'stateless::renew(': {'renew'},
        'stateless_mailbox::start(': {'begin_login'},
        'stateless_mailbox::pending(': {'authorize'},
        'stateless_mailbox::accept(': {'callback'},
        'stateless_mailbox::exchange(': {'callback'},
        'stateless_mailbox::finish(': {'callback'},
        'stateless_mailbox::poll(': {'poll'},
    }
    for call, where in expect.items():
        require(owners(broker, call) == where, f'{call} called from {owners(broker, call)}, not {where}')
        for name, source in shell.items():
            if name != 'broker.rs':
                require(call not in code_only(source), f'{call} called from {name}')
    # The one direct `seal_token` call is the deterministic conformance-vector
    # helper, which no endpoint reaches.
    for name, source in shell.items():
        allowed = {'fixture_seal'} if name == 'token.rs' else set()
        require(owners(source, 'seal_token(') <= allowed if 'seal_token(' in code_only(source) else True,
                f'{name} calls seal_token directly')
        if name != 'token.rs':
            require('fixture_seal(' not in code_only(source) and 'sealer_with_nonce(' not in code_only(source),
                    f'{name} seals with a fixed nonce')
    checked.append('sealing only through issue, renew or the mailbox finish, each from one endpoint')

    # The broker's agent peer is the mTLS handshake's, and each agent decision uses it.
    require(count(broker, 'PeerIdentity::from_connection(&stream.conn)') == 1, 'broker peer not from the handshake')
    require(re.search(r'\(Ok\(request\), Some\(peer\)\) if mutual => broker\.handle_agent\(&request, &peer\)',
                      broker), 'agent requests not served for the mutual-TLS peer')
    agent = functions(broker)['handle_agent'][0]
    for call in ['self.begin_login(peer,', 'self.renew(peer,', 'self.poll(peer,']:
        require(call in agent, f'handle_agent no longer passes its peer to {call}')
    for name, call in [('begin_login', 'peer.thumbprint.as_bytes(),'), ('poll', 'peer.thumbprint.as_bytes(),'),
                       ('renew', 'peer.thumbprint.as_bytes(),')]:
        require(call in functions(broker)[name][0], f'{name} does not decide for the peer thumbprint')
    checked.append('every agent decision of the broker uses the mutual-TLS peer')

    # The OAuth credential.
    require(owners(broker, 'access_token: Zeroizing::new(') == {'token_response'}, 'access token parsed elsewhere')
    require(owners(broker, '.access_token') == {'token'}, 'access token read outside the permitted exchange')
    require('refresh_token' not in code_only(broker).replace('"refresh_token"', ''),
            'a refresh token is kept')
    checked.append('the access token becomes a Token only in the permitted exchange')

    # Audit records name claims, routes and codes, never token or credential bytes.
    for match in re.finditer(r'record\(json::object\(\[(.*?)\]\)\)', proxy, re.S):
        fields = set(re.findall(r'\(\s*"([a-z_]+)",', match.group(1)))
        require(fields <= {'event', 'peer', 'reason', 'jti', 'method', 'provider', 'route', 'sub', 'status', 'code'},
                f'audit record field outside the reviewed set: {sorted(fields)}')
    checked.append('audit records carry claims, routes, statuses and codes only')
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('action', choices=['check'])
    parser.parse_args()
    for line in check():
        print('ok:', line)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
