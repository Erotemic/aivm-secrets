#!/usr/bin/env python3
"""Privileged call sites of the `garrett-stateless` native shell.

The extracted core (`crates/garrett-stateless-core`) makes every
garrett-stateless-v1 decision, and `proofs/GarrettStateless*.lean` prove them.
The shell only performs I/O around those decisions. This guard pins, in the
shell's source, each place where a credential, a signing or sealing key, a
provider connection or an audit record is handled, and checks that each one is
reached only through the extracted interface the proofs quantify over:

* the proxy reaches a provider only through `upstream.rs`, whose private
  types allow one TLS session per `Origin::connect`, authenticated as the
  destination the core passed, and one write on it: `egress_wire` of an
  `Egress` for that destination, which only the core's `serve` makes;
* the proxy never handles a credential: it writes to the agent only the bytes
  the core hands `Channel::send`, and opens nothing with a key;
* the proxy serves every request for the peer of its TLS handshake;
* the broker seals only through `seal_token`, behind `stateless::issue`,
  `stateless::renew` or the mailbox's `finish`, and drives each mailbox
  transition from exactly one endpoint;
* the OAuth access token becomes a `Token` only inside the permitted exchange,
  and a refresh token is never kept;
* audit records name claims, routes and codes only;
* the shell decides nothing itself: it never calls `stateless::open`,
  `stateless_proxy::decide` or `serve` directly;
* its only mutable state beyond keys and configuration is the broker's login
  mailbox (whose policy names the OAuth providers only, so a strict broker's
  stays empty, `GarrettStatelessStrict.lean`), the optional proxy audit file
  handle (refused by a strict configuration), and the stop flags and
  connection counters of the listeners; and the broker and proxy write no
  file except that audit file.

It is a source guard over the shell, not a proof and not a call-graph or
dependency analysis; `docs/verification.md` states the trusted
remainder.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHELL = 'crates/garrett-stateless/src'
CORE = 'crates/garrett-stateless-core/src'


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


def without_tests(source: str) -> str:
    """The source with each `#[cfg(test)]` module blanked: unit tests are not
    part of the running shell."""
    code = code_only(source)
    out = list(source)
    for match in re.finditer(r'#\[cfg\(test\)\]\s*mod\s+\w+\s*\{', code):
        depth = 0
        for j in range(match.end() - 1, len(code)):
            if code[j] == '{':
                depth += 1
            elif code[j] == '}':
                depth -= 1
                if depth == 0:
                    for k in range(match.start(), j + 1):
                        if out[k] != '\n':
                            out[k] = ' '
                    break
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
    shell = {p.name: without_tests(p.read_text()) for p in sorted((root / SHELL).glob('*.rs'))}
    core = {p.name: p.read_text() for p in sorted((root / CORE).glob('stateless*.rs'))}
    every = '\n'.join(shell.values())
    checked = []

    # No escape from the type system anywhere in the shell.
    for name, source in shell.items():
        require(not re.search(r'\bunsafe\b', code_only(source)), f'unsafe code in {name}')
    checked.append('no unsafe code in the shell')

    # The proxy's provider transport is upstream.rs, and only the proxy uses it.
    proxy = shell['proxy.rs']
    upstream = shell['upstream.rs']
    for name, source in shell.items():
        if name not in ('proxy.rs', 'upstream.rs', 'lib.rs'):
            require(not re.search(r'\bupstream::', code_only(source)) and 'Authenticated' not in code_only(source),
                    f'{name} uses the provider transport')
    # Its session types keep their fields private: no other code can reach the
    # socket, and the destination of a session is the one it was opened for.
    for struct in ['Authenticated', 'Answering']:
        body = re.search(r'pub\(crate\) struct ' + struct + r' \{(.*?)\}', code_only(upstream), re.S)
        require(body is not None, f'upstream.rs no longer defines {struct}')
        require('pub' not in body.group(1), f'{struct} exposes a field')
    for struct, builder in [('Authenticated', 'open'), ('Answering', 'transmit')]:
        built = len(re.findall(r'(?<!struct )(?<!impl )\b' + struct + r' \{', code_only(upstream)))
        require(built == 1 and owners(upstream, 'Some(' + struct + ' {') == {builder},
                f'a provider session ({struct}) is built outside {builder}')
    # One write per session: only `transmit`, which consumes the authenticated
    # session, writes, and it writes exactly the egress bytes, once, after
    # checking the egress is for this session's destination.
    require(count(every, 'egress_wire(') == 1, 'egress_wire must be read exactly once in the shell')
    require(owners(upstream, 'egress_wire(') == {'transmit'}, 'egress_wire read outside Authenticated::transmit')
    transmit = functions(upstream)['transmit'][0]
    require('fn transmit(self, egress: Egress) -> Option<Answering>' in transmit,
            'Authenticated::transmit no longer consumes the session and a core Egress')
    require('tls.write_all(egress_wire(&egress))' in transmit, 'the provider write is not the egress bytes')
    for call in ['write_all(', '.write(', 'flush(']:
        require(count(upstream, call) == (0 if call == '.write(' else 1),
                f'the provider session is written other than by one write_all and flush ({call})')
    check_first = 'if &self.destination != egress_destination(&egress) {'
    require(check_first in transmit and transmit.index(check_first) < transmit.index('write_all('),
            'Authenticated::transmit does not check the egress is for its destination before writing')
    require(not re.search(r'\b(loop|while|for)\b', code_only(transmit)), 'Authenticated::transmit retries')
    require('fn transmit(&mut self' not in code_only(upstream) and 'fn write' not in code_only(upstream),
            'a provider session can be written through a borrowed handle')
    # The session is authenticated as the destination the core passed: its
    # address and port, its host as the TLS name, its trust anchors.
    opener = functions(upstream)['open'][0]
    for text, why in [('(address, destination.port)', 'the destination address and port'),
                      ('std::str::from_utf8(&destination.address)', 'the destination address'),
                      ('std::str::from_utf8(&destination.host)', 'the destination host'),
                      ('ServerName::try_from(host.to_string())', 'the destination host as the TLS name'),
                      ('client(&destination.trust)', 'the destination trust anchors'),
                      ('destination: destination.clone()', 'the destination it authenticated')]:
        require(text in opener, f'Authenticated::open does not use {why}')
    client = functions(upstream)['client'][0]
    require('tls::upstream_client(' in client and owners(shell['tls.rs'], '.with_root_certificates(store)') ==
            {'upstream_client'}, 'the provider TLS client does not verify against the destination trust anchors')
    for name, source in shell.items():
        require(not re.search(r'\bdangerous\b|ServerCertVerifier|danger::', code_only(source)),
                f'{name} replaces the TLS certificate verification')
        if name not in ('upstream.rs', 'http.rs'):
            require('ClientConnection::new(' not in code_only(source), f'{name} opens a TLS client connection')
    require(owners(upstream, 'ClientConnection::new(') == {'open'}, 'a provider connection outside open')
    # The proxy opens a session only in Origin::connect, to the destination
    # the core passed, and writes only through it in Origin::transmit.
    require(owners(proxy, 'Authenticated::open(') == {'connect'} and
            'Authenticated::open(destination)' in functions(proxy)['connect'][0],
            'Origin::connect does not open the destination it was given')
    require(owners(proxy, 'session.transmit(egress)') == {'transmit'}, 'the provider write is not Origin::transmit')
    # Its only other outgoing TCP connection wakes its own listener to stop.
    require(owners(proxy, 'TcpStream::connect') == {'stop'} and
            'TcpStream::connect_timeout(&self.address,' in functions(proxy)['stop'][0],
            'the proxy opens a TCP connection other than to its own listener')
    require(not re.search(r'(?<![\w])http::', code_only(proxy)), 'the proxy uses the broker HTTP client')
    require(not re.search(r'\bupstream: Vec<|Vec<Destination>|Vec<Authenticated>', code_only(proxy)),
            'the proxy keeps a destination table')
    checked.append('the proxy reaches a provider only through upstream.rs: one session per connect, authenticated as '
                   'the core\'s destination, written once with that destination\'s Egress')

    # The proxy never handles the credential: it writes to the agent only the
    # bytes the core passes to Channel::send, and opens nothing with a key.
    send = functions(proxy)['send'][0]
    require('self.stream\n            .write_all(bytes)' in send or 'self.stream.write_all(bytes)' in send,
            'Channel::send does not write exactly the core reply')
    require(owners(proxy, 'write_all(') == {'send', 'record'} and count(send, 'write_all(') == 1 and
            '.write(' not in code_only(proxy), 'the proxy writes to the agent outside Channel::send')
    record = functions(proxy)['record'][0]
    require(count(record, 'write_all(&line)') == count(record, 'write_all('),
            'an audit record writes something other than its canonical line')
    for name in ('proxy.rs', 'upstream.rs'):
        code = code_only(shell[name])
        for word in ['credential', 'unseal', 'Opened', 'KeyMaterial', 'reflection_forms', 'sealed']:
            require(not re.search(r'\b' + word + r'\b', code), f'{name} handles a credential ({word})')
    checked.append('the proxy writes to the agent only the core reply and never handles a credential')

    # The core alone makes an Egress, from an admitted decision.
    core_proxy = core['stateless_proxy.rs']
    struct = re.search(r'pub struct Egress \{(.*?)\}', core_proxy, re.S)
    require(struct is not None, 'Egress struct missing')
    require('pub ' not in struct.group(1), 'Egress fields are public')
    built = re.findall(r'(?<!struct )\bEgress \{', code_only(core_proxy))
    require(len(built) == 1, 'Egress is built more than once in the core')
    require(owners(core_proxy, '= Egress {') == {'serve'}, 'Egress built outside serve')
    for name, source in shell.items():
        require('Egress {' not in code_only(source), f'{name} builds an Egress')
    checked.append('only the core serve makes an Egress; its fields are private')

    # The proxy's peer is the TLS handshake's.
    connection = functions(proxy)['connection'][0]
    require('PeerIdentity::from_connection(&stream.conn)' in connection, 'peer not from the handshake')
    # One connection loop per operation policy, each for the handshake peer.
    loops = re.findall(r'stateless_proxy::connection\((.*?)\n\s*\)', connection, re.S)
    require(len(loops) == 2 and all('peer.thumbprint.as_bytes()' in call for call in loops),
            'connection not served for the handshake peer')
    require(count(every, 'stateless_proxy::connection(') == 2, 'a third connection loop')
    checked.append('every proxied request is decided for the TLS handshake peer')

    # The operation policy is one of the core's two extracted policies.
    require(sorted(call.split(',')[1].strip() for call in loops) == ['&Unrestricted', 'read_only'],
            'a connection loop under a policy other than the core Unrestricted or ReadOnly')
    for name, source in shell.items():
        require(not re.search(r'\bimpl\b[^{]*\bOperationPolicy\b', code_only(source)),
                f'{name} implements an operation policy')
    dispatch = re.search(r'pub struct Dispatch \{(.*?)\}', core_proxy, re.S)
    require(dispatch is not None and 'pub ' not in dispatch.group(1), 'Dispatch fields are public')
    checked.append('the operation policy is the core Unrestricted or ReadOnly; dispatch data stays in the core')

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
    # Every production sealer and login-state seal gets a fresh 96-bit nonce
    # from the system random source, drawn in the same function; only the
    # feature-gated conformance fixture passes a nonce in.
    built = {name: owners(source, 'TokenSealer::new(') for name, source in shell.items()
             if 'TokenSealer::new(' in code_only(source)}
    require(built == {'broker.rs': {'renew'}, 'token.rs': {'sealer', 'fixture_seal'}},
            f'a TokenSealer is built outside the reviewed places: {built}')
    for name, function in [('broker.rs', 'renew'), ('token.rs', 'sealer')]:
        body = functions(shell[name])[function][0]
        require(re.search(r'let nonce = (?:crate::encoding::)?random::<12>\(\)', body) and
                re.search(r'TokenSealer::new\([^;]*nonce\.to_vec\(\)', body, re.S),
                f'{function} does not seal with a fresh random nonce')
    fixture = functions(shell['token.rs'])['fixture_seal'][0]
    require(re.search(r'#\[cfg\(feature = "fixtures"\)\]\s*pub fn fixture_seal', shell['token.rs']),
            'the fixed-nonce fixture is compiled without the fixtures feature')
    require(count(shell['login.rs'], 'stateless_token::seal_state(') == 1 and
            'stateless_token::seal_state(&RingStateKey(state_key), state, &random::<12>()?)' in shell['login.rs'],
            'login state is not sealed with a fresh random nonce')
    checked.append('sealing only through issue, renew or the mailbox finish, each from one endpoint, '
                   'each with a fresh random nonce')

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

    # Every decision is the core's.
    for call in ['stateless::open(', 'stateless::authenticate(', 'stateless::decrypt(', 'stateless_proxy::decide(',
                 'stateless_proxy::serve(', 'stateless_proxy::connection_step(', '.permits(', '.unseal(',
                 'Admitted']:
        for name, source in shell.items():
            require(call not in code_only(source), f'{name} calls {call}')
    checked.append('the shell opens no surrogate and decides no request outside the core loop')

    # Mutable process state: the mailbox, the audit handle, stop flags and
    # connection counters, and nothing else.
    for name, source in shell.items():
        code = code_only(source)
        for kind in ['RwLock', 'RefCell', 'Cell<', 'OnceLock', 'OnceCell', 'LazyLock', 'thread_local!',
                     'static mut']:
            require(kind not in code, f'{name} keeps {kind} state')
        allowed = {'broker.rs': {'mailbox: Mutex<Mailbox>'}, 'proxy.rs': {'audit: Option<Mutex<std::fs::File>>'}}
        fields = set(re.findall(r'\b\w+: (?:Option<)?Mutex<[^>]*>>?', code))
        require(fields <= allowed.get(name, set()), f'{name} holds mutable state {sorted(fields)}')
        atomics = set(re.findall(r'\b(\w+)(?::| =) Arc(?:<|::new\()Atomic', code))
        require(atomics <= {'stop', 'active'}, f'{name} holds atomic state {sorted(atomics)}')
    login = functions(broker)['login_policy'][0]
    require('.filter(|p| p.oauth().is_some())' in login, 'the login policy names a provider that is not OAuth')
    checked.append('mutable state is only the OAuth mailbox, the audit handle, stop flags and connection counters')

    # Files: the broker and proxy write only the optional audit file. The
    # agent's optional TPM signer (`tpm.rs`, feature `tpm`) writes private
    # scratch files for tpm2-tools; neither the broker nor the proxy uses it.
    require(all('tpm::' not in code_only(shell[name]) for name in ['broker.rs', 'proxy.rs']),
            'the broker or proxy uses the TPM signer')
    for name, source in shell.items():
        code = code_only(source)
        if name in ('files.rs', 'tpm.rs'):
            continue
        for call in ['write_private(', 'replace_private(', 'File::create(', 'fs::write(', 'create_dir']:
            require(call not in code, f'{name} writes files ({call})')
        opened = owners(source, 'OpenOptions::new()') if 'OpenOptions::new()' in code else set()
        require(opened <= ({'new'} if name == 'proxy.rs' else set()), f'{name} opens files for writing')
    new = functions(proxy)['new'][0]
    require(re.search(r'match &config\.audit \{\s*Some\(path\) => Some\(Mutex::new\(\s*std::fs::OpenOptions::new\(\)'
                      r'\s*\.append\(true\)', new), 'the proxy opens a file other than the configured audit log')
    checked.append('the broker and proxy write no file but the optional (non-strict) audit log')
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
