"""Optional host-side lifecycle for one native broker session with one guest.

``python -I -m aivm_secrets native-session --spec SPEC`` is the versioned
process contract an integrator (such as AIVM) runs to give a guest the native
Rust broker. It is opt-in and process-only: the integrator imports nothing
from this package, reads one JSON announcement from stdout, and ends the
session by closing this process's stdin (or sending SIGTERM).

Lifecycle, in order:

1. the native client is copied into a fresh guest directory and creates its
   identity key and CSR *inside the guest*; only the public CSR is read back;
2. the host authority enrolls exactly that key, which the spec must approve
   explicitly (``approve_session_key``), and the guest receives the CA and
   its certificate;
3. the native bridge starts with the host-owned policy, disclosure and
   credential; the guest receives the bound capability and client config;
4. the guest's broker socket is connected to the host socket (an SSH
   reverse forward of that one socket, or the same path for a local guest);
5. one announcement line is printed; the session lasts until stdin closes;
6. teardown stops the forward and the bridge and removes the guest directory.

The spec names host-private files (credential, policy, disclosure and the
provider CA, all mode 0600 under a private directory), as the bridge enforces.

Errors print ``{"version":1,"ready":false,"error":CODE}`` with a fixed code
and exit 1; subprocess output is never echoed, so no credential can leak
through diagnostics. The provider credential never enters the guest.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ANNOUNCE_VERSION = 1
SPEC_VERSION = 1
SUBJECT = 'native-session-guest'
CODES = frozenset({
    'invalid_spec', 'missing_binary', 'guest_unreachable', 'guest_key_failed',
    'enrollment_failed', 'broker_failed', 'forward_failed', 'credential_exposed',
})


class SessionError(Exception):
    def __init__(self, code: str) -> None:
        assert code in CODES
        super().__init__(code)
        self.code = code


def _environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in ('SSLKEYLOGFILE', 'RUST_LOG', 'RUST_BACKTRACE', 'PYTHONPATH',
                 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                 'http_proxy', 'https_proxy', 'all_proxy'):
        env.pop(name, None)
    return env


def _private_write(path: Path, data: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    return path


class LocalGuest:
    """A guest that is a directory on this host (tests and the same-UID demo)."""

    def __init__(self, parent: Path) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix='native-guest-', dir=parent))

    def path(self, name: str) -> str:
        return str(self.dir / name)

    def publish(self, name: str, data: bytes, *, executable: bool = False) -> None:
        path = self.dir / name
        _private_write(path, data)
        if executable:
            path.chmod(0o700)

    def read(self, name: str) -> bytes:
        return (self.dir / name).read_bytes()

    def run(self, argv: list[str], *, timeout: float = 75) -> subprocess.CompletedProcess:
        return subprocess.run(argv, cwd=self.dir, capture_output=True, timeout=timeout,
                              env=_environment())

    def connect(self, host_socket: Path) -> subprocess.Popen | None:
        os.symlink(host_socket, self.dir / 'broker.sock')
        return None

    def remove(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


class SSHGuest:
    """A guest reached through a host-selected OpenSSH configuration."""

    def __init__(self, config: str, host: str) -> None:
        self.base = ['ssh', '-F', config, '-o', 'BatchMode=yes', '-o', 'ForwardAgent=no',
                     '-o', 'ClearAllForwardings=yes', host]
        self.forward_base = ['ssh', '-F', config, '-o', 'BatchMode=yes',
                             '-o', 'ForwardAgent=no', '-o', 'ExitOnForwardFailure=yes',
                             '-o', 'StreamLocalBindUnlink=yes', '-N', host]
        made = self._call('umask 077 && mktemp -d /tmp/aivm-native-XXXXXXXX', timeout=20)
        if made.returncode:
            raise SessionError('guest_unreachable')
        self.dir = made.stdout.decode('ascii', 'replace').strip()
        if not self.dir.startswith('/tmp/aivm-native-'):
            raise SessionError('guest_unreachable')

    def _call(self, script: str, *, data: bytes | None = None,
              timeout: float = 75) -> subprocess.CompletedProcess:
        return subprocess.run([*self.base, script], input=data, capture_output=True,
                              timeout=timeout, env=_environment())

    def path(self, name: str) -> str:
        return f'{self.dir}/{name}'

    def publish(self, name: str, data: bytes, *, executable: bool = False) -> None:
        mode = '700' if executable else '600'
        target = shlex.quote(self.path(name))
        done = self._call(f'umask 077 && set -o noclobber && cat > {target} && chmod {mode} {target}',
                          data=data)
        if done.returncode:
            raise SessionError('guest_unreachable')

    def read(self, name: str) -> bytes:
        done = self._call('cat ' + shlex.quote(self.path(name)))
        if done.returncode:
            raise SessionError('guest_unreachable')
        return done.stdout

    def run(self, argv: list[str], *, timeout: float = 75) -> subprocess.CompletedProcess:
        return self._call('cd ' + shlex.quote(self.dir) + ' && exec ' + shlex.join(argv),
                          timeout=timeout)

    def connect(self, host_socket: Path) -> subprocess.Popen:
        remote = self.path('broker.sock')
        process = subprocess.Popen([*self.forward_base, '-R', f'{remote}:{host_socket}'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=_environment())
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise SessionError('forward_failed')
            if self._call('test -S ' + shlex.quote(remote), timeout=10).returncode == 0:
                return process
            time.sleep(0.25)
        process.terminate()
        raise SessionError('forward_failed')

    def remove(self) -> None:
        self._call('rm -rf -- ' + shlex.quote(self.dir), timeout=20)


def load_spec(path: Path) -> dict[str, Any]:
    try:
        spec = json.loads(path.read_text())
    except (OSError, ValueError):
        raise SessionError('invalid_spec') from None
    required = {'version', 'bin_dir', 'workspace', 'policy_file', 'disclosure_file',
                'credential_file', 'provider', 'binding', 'guest', 'approve_session_key'}
    if (not isinstance(spec, dict) or set(spec) != required
            or spec['version'] != SPEC_VERSION or spec['approve_session_key'] is not True):
        raise SessionError('invalid_spec')
    provider = spec['provider']
    if (not isinstance(provider, dict)
            or set(provider) != {'host', 'address', 'port', 'server_ca', 'authentication'}):
        raise SessionError('invalid_spec')
    guest = spec['guest']
    if not isinstance(guest, dict) or guest.get('kind') not in {'local', 'ssh'}:
        raise SessionError('invalid_spec')
    if guest['kind'] == 'ssh' and set(guest) != {'kind', 'ssh_config', 'host'}:
        raise SessionError('invalid_spec')
    if guest['kind'] == 'local' and set(guest) != {'kind'}:
        raise SessionError('invalid_spec')
    binding = spec['binding']
    if not isinstance(binding, dict) or set(binding) != {'access_identity', 'vm'}:
        raise SessionError('invalid_spec')
    return spec


def _binaries(directory: Path) -> dict[str, Path]:
    paths = {role: directory / name for role, name in (
        ('authority', 'garrett-authority'), ('bridge', 'garrett-bridge'),
        ('client', 'garrett-client'))}
    if not all(p.is_file() and os.access(p, os.X_OK) for p in paths.values()):
        raise SessionError('missing_binary')
    return paths


def _authority(binary: Path, host: Path, action: str, **request: Any) -> dict:
    path = _private_write(host / f'operator-{action}.json', json.dumps(request).encode())
    try:
        done = subprocess.run([str(binary), action, '--root', str(host / 'authority'),
                               '--request', str(path)], capture_output=True, timeout=30,
                              env=_environment())
    finally:
        path.unlink()
    try:
        reply = json.loads(done.stdout)
    except ValueError:
        raise SessionError('enrollment_failed') from None
    if done.returncode or reply.get('version') != 1 or reply.get('ok') is not True:
        raise SessionError('enrollment_failed')
    return reply['result']


def _csr_fingerprint(csr: bytes) -> str:
    """The same public-key fingerprint the operator CLI shows for a CSR."""
    from .identity.certificates import inspect_csr

    try:
        return inspect_csr(csr)
    except Exception:
        raise SessionError('guest_key_failed') from None


def _start_bridge(binary: Path, host: Path) -> tuple[subprocess.Popen, dict]:
    process = subprocess.Popen([str(binary), '--config', str(host / 'bridge.json')],
                               cwd=host, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=_environment())
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], 15)
    line = process.stdout.readline() if ready else b''
    try:
        announced = json.loads(line)
    except ValueError:
        announced = None
    if (not isinstance(announced, dict) or announced.get('ready') is not True
            or announced.get('profile') != 'manifest-https-v1'
            or not isinstance(announced.get('capability'), str)):
        _stop(process)
        raise SessionError('broker_failed')
    return process, announced


def _stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class Session:
    """One native broker session bound to one guest; use as a context manager."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec
        self.tools = _binaries(Path(spec['bin_dir']))
        self.host = Path(spec['workspace'])
        self.guest: LocalGuest | SSHGuest | None = None
        self.bridge: subprocess.Popen | None = None
        self.forward: subprocess.Popen | None = None
        self.credential = Path(spec['credential_file']).read_bytes()

    def __enter__(self) -> dict[str, Any]:
        try:
            return self._start()
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_exc: object) -> None:
        _stop(self.forward)
        _stop(self.bridge)
        if self.guest is not None:
            self.guest.remove()

    def _start(self) -> dict[str, Any]:
        spec, host, tools = self.spec, self.host, self.tools
        host.mkdir(mode=0o700, parents=True, exist_ok=False)
        kind = spec['guest']['kind']
        self.guest = (LocalGuest(host.parent) if kind == 'local' else
                      SSHGuest(spec['guest']['ssh_config'], spec['guest']['host']))
        guest = self.guest
        # 1. The identity key is created inside the guest; only the CSR leaves.
        guest.publish('garrett-client', tools['client'].read_bytes(), executable=True)
        made = guest.run([guest.path('garrett-client'), 'request', '--key-mode', 'software',
                          '--key', guest.path('client.key'), '--csr', guest.path('client.csr')])
        try:
            claimed = json.loads(made.stdout)
        except ValueError:
            raise SessionError('guest_key_failed') from None
        csr = guest.read('client.csr')
        fingerprint = _csr_fingerprint(csr)
        if made.returncode or claimed.get('key_fingerprint') != fingerprint:
            raise SessionError('guest_key_failed')
        # 2. Enroll exactly that session key (approved by the spec).
        csr_path = _private_write(host / 'guest.csr', csr)
        _authority(tools['authority'], host, 'init',
                   issuer='aivm-secrets.native-session', audience='aivm-secrets.remote')
        _authority(tools['authority'], host, 'enroll', subject=SUBJECT,
                   csr_file=str(csr_path), approve_fingerprint=fingerprint)
        public = _authority(tools['authority'], host, 'public-client', subject=SUBJECT)
        guest.publish('ca.pem', base64.b64decode(public['ca_pem_b64']))
        guest.publish('client.pem', base64.b64decode(public['certificate_pem_b64']))
        # 3. Start the bridge with host-owned policy, disclosure and credential.
        provider = spec['provider']
        config = {
            'schema': 1, 'authority_root': str(host / 'authority'),
            'client_assurance': 'any-enrolled', 'subject': SUBJECT,
            'listen': str(host / 'identity.sock'), 'lifetime': 300,
            'binding': {'owner_uid': os.getuid(),
                        'access_identity': spec['binding']['access_identity'],
                        'vm': spec['binding']['vm'], 'channel': os.urandom(16).hex()},
            'provider': {
                'profile': 'manifest-https-v1', 'host': provider['host'],
                'address': provider['address'], 'port': provider['port'],
                'authentication': provider['authentication'],
                'server_ca': provider['server_ca'],
                'credential_file': spec['credential_file'],
                'audit_file': str(host / 'provider-audit.jsonl'),
                'policy_file': spec['policy_file'],
                'disclosure_file': spec['disclosure_file'],
                'writes': 'deny', 'request_limit': 'unbounded',
            },
        }
        _private_write(host / 'bridge.json', json.dumps(config).encode())
        self.bridge, ready = _start_bridge(tools['bridge'], host)
        guest.publish('capability.jwt', ready['capability'].encode())
        guest.publish('client.json', json.dumps({
            'schema': 1, 'key_mode': 'software', 'socket': guest.path('broker.sock'),
            'server_name': 'localhost', 'certificate': guest.path('client.pem'),
            'private_key': guest.path('client.key'), 'server_ca': guest.path('ca.pem'),
        }).encode())
        # 4. Connect only the bridge's application socket into the guest.
        self.forward = guest.connect(host / 'identity.sock')
        announcement = {
            'version': ANNOUNCE_VERSION, 'ready': True, 'profile': 'manifest-https-v1',
            'guest': {'dir': guest.dir if isinstance(guest.dir, str) else str(guest.dir),
                      'client': guest.path('garrett-client'),
                      'config': guest.path('client.json'),
                      'capability': guest.path('capability.jwt')},
        }
        if self.credential and self.credential in json.dumps(announcement).encode():
            raise SessionError('credential_exposed')
        return announcement


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='aivm-secrets native-session')
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


if __name__ == '__main__':
    raise SystemExit(main())
