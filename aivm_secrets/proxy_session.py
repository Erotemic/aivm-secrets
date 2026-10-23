"""Optional host-side lifecycle for one HTTPS proxy profile session (HP-3).

``python -I -m aivm_secrets proxy-session --spec SPEC`` is the versioned
process contract an integrator (such as AIVM) runs to give one guest the
``credential-substitution`` proxy. Like ``native-session`` it is opt-in and
process-only: the integrator imports nothing, reads one JSON announcement
and ends the session by closing stdin (or SIGTERM).

Lifecycle:

1. start the proxy as a child (native ``garrett-proxy`` from ``bin_dir``, or
   the Python reference when ``bin_dir`` is null) and read its announcement;
2. create a fresh guest directory and publish the session CA, a CA bundle
   (the guest's system roots plus the session CA) and an ``env`` file that
   sets ``HTTPS_PROXY`` with the session token and the CA variables common
   tools read;
3. forward one guest loopback TCP port to the proxy (an SSH reverse forward,
   or the same port for a local guest);
4. print one announcement with the guest paths only (no token, no
   credential); the session lasts until stdin closes;
5. teardown ends the proxy's lease, stops the forward and removes the guest
   directory.

The guest gets a surrogate token and a CA, never the credential. Tools that
honour ``HTTPS_PROXY`` send *all* HTTPS through the proxy, which refuses
origins the policy does not list; the proxy is never an open relay. This
mediates only cooperating tools (``PROXY-EGRESS-01``).
"""
from __future__ import annotations

import argparse
import json
import select
import shlex
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from .native_session import LocalGuest, SSHGuest, _environment
from .native_session import SessionError as GuestError

ANNOUNCE_VERSION = 1
SPEC_VERSION = 1
CODES = frozenset({'invalid_spec', 'missing_binary', 'proxy_failed', 'guest_unreachable',
                   'forward_failed', 'credential_exposed'})
SYSTEM_ROOTS = '/etc/ssl/certs/ca-certificates.crt'


class SessionError(Exception):
    def __init__(self, code: str) -> None:
        assert code in CODES
        super().__init__(code)
        self.code = code


def load_spec(path: Path) -> dict[str, Any]:
    try:
        spec = json.loads(path.read_text())
    except (OSError, ValueError):
        raise SessionError('invalid_spec') from None
    required = {'version', 'bin_dir', 'policy_file', 'credential_file', 'audit_file',
                'guest', 'guest_port'}
    if not isinstance(spec, dict) or set(spec) != required or spec['version'] != SPEC_VERSION:
        raise SessionError('invalid_spec')
    port = spec['guest_port']
    if type(port) is not int or not 1024 <= port <= 65535:
        raise SessionError('invalid_spec')
    guest = spec['guest']
    if not isinstance(guest, dict) or guest.get('kind') not in {'local', 'ssh'}:
        raise SessionError('invalid_spec')
    if guest['kind'] == 'ssh' and set(guest) != {'kind', 'ssh_config', 'host'}:
        raise SessionError('invalid_spec')
    if guest['kind'] == 'local' and set(guest) != {'kind'}:
        raise SessionError('invalid_spec')
    if spec['bin_dir'] is not None and not isinstance(spec['bin_dir'], str):
        raise SessionError('invalid_spec')
    return spec


def _proxy_command(spec: dict[str, Any], port: int) -> list[str]:
    arguments = ['--policy', spec['policy_file'], '--credential-file', spec['credential_file'],
                 '--audit', spec['audit_file'], '--port', str(port)]
    if spec['bin_dir'] is None:
        return [sys.executable, '-I', '-m', 'aivm_secrets', 'proxy', *arguments]
    binary = Path(spec['bin_dir']) / 'garrett-proxy'
    if not binary.is_file():
        raise SessionError('missing_binary')
    return [str(binary), *arguments]


def environment_file(proxy_url: str, directory: str) -> bytes:
    ca = f'{directory}/ca.pem'
    bundle = f'{directory}/bundle.pem'
    lines = [
        f'export HTTPS_PROXY={shlex.quote(proxy_url)}',
        'export https_proxy="$HTTPS_PROXY"',
        f'export AIVM_SECRETS_PROXY_CA={shlex.quote(ca)}',
        f'export SSL_CERT_FILE={shlex.quote(bundle)}',
        f'export CURL_CA_BUNDLE={shlex.quote(bundle)}',
        f'export REQUESTS_CA_BUNDLE={shlex.quote(bundle)}',
        f'export NODE_EXTRA_CA_CERTS={shlex.quote(ca)}',
    ]
    return ('\n'.join(lines) + '\n').encode()


class Session:
    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec
        self.proxy: subprocess.Popen | None = None
        self.forward: subprocess.Popen | None = None
        self.guest: Any = None

    def __enter__(self) -> dict[str, Any]:
        try:
            return self._start()
        except SessionError:
            self.__exit__()
            raise
        except GuestError as error:
            self.__exit__()
            code = error.code if error.code in CODES else 'guest_unreachable'
            raise SessionError(code) from None
        except Exception:
            self.__exit__()
            raise SessionError('proxy_failed') from None

    def __exit__(self, *_exc: object) -> None:
        if self.proxy is not None:
            if self.proxy.stdin and not self.proxy.stdin.closed:
                self.proxy.stdin.close()
            try:
                self.proxy.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proxy.kill()
                self.proxy.wait()
            self.proxy = None
        if self.forward is not None:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forward.kill()
            self.forward = None
        if self.guest is not None:
            self.guest.remove()
            self.guest = None

    def _start(self) -> dict[str, Any]:
        spec = self.spec
        kind = spec['guest']['kind']
        # A local guest shares the host loopback, so the proxy listens on the
        # guest port itself; an SSH guest reaches an ephemeral host port.
        host_port = spec['guest_port'] if kind == 'local' else 0
        self.proxy = subprocess.Popen(
            _proxy_command(spec, host_port), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=_environment())
        assert self.proxy.stdout is not None
        ready, _, _ = select.select([self.proxy.stdout], [], [], 30)
        try:
            announced = json.loads(self.proxy.stdout.readline()) if ready else {}
        except ValueError:
            announced = {}
        if announced.get('version') != 1 or announced.get('ready') is not True:
            raise SessionError('proxy_failed')
        listen_port = int(str(announced['listen']).rsplit(':', 1)[1])
        self.guest = LocalGuest(Path(spec['audit_file']).parent) if kind == 'local' else \
            SSHGuest(spec['guest']['ssh_config'], spec['guest']['host'])
        guest = self.guest
        directory = str(guest.dir)
        guest.publish('ca.pem', announced['ca_pem'].encode('ascii'))
        made = guest.run(['sh', '-c', f'if [ -r {SYSTEM_ROOTS} ]; then cat {SYSTEM_ROOTS}; fi; '
                                      'cat ca.pem'])
        if made.returncode:
            raise SessionError('guest_unreachable')
        guest.publish('bundle.pem', made.stdout)
        url = f"http://aivm:{announced['proxy_token']}@127.0.0.1:{spec['guest_port']}"
        guest.publish('env', environment_file(url, directory))
        if kind == 'ssh':
            self.forward = guest.forward_tcp(spec['guest_port'], listen_port)
        announcement = {
            'version': ANNOUNCE_VERSION, 'ready': True, 'profile': announced['profile'],
            'origins': announced['origins'],
            'guest': {'dir': directory, 'env': guest.path('env'), 'ca': guest.path('ca.pem')},
        }
        try:
            secret = Path(spec['credential_file']).read_bytes().strip()
        except OSError:
            secret = b''
        if secret and secret in json.dumps(announcement).encode():
            raise SessionError('credential_exposed')
        return announcement


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='aivm-secrets proxy-session')
    parser.add_argument('--spec', required=True, type=Path)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        spec = load_spec(args.spec)
        with Session(spec) as announcement:
            _emit(announcement)
            try:
                while sys.stdin.buffer.read(4096):
                    pass
            except KeyboardInterrupt:
                pass
    except SessionError as error:
        _emit({'version': ANNOUNCE_VERSION, 'ready': False, 'error': error.code})
        return 1
    except KeyboardInterrupt:
        return 0
    return 0
