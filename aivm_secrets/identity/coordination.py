"""Durable single-writer coordination for revocation and write retries.

The authority runs on ONE trusted host with a local SQLite database. Other
hosts use mutually authenticated TLS, never a network-mounted SQLite file or
copied ledger. There is no positive-result cache or offline fallback.

Revocation is terminal for a principal name: recovery requires a NEW name
and a deliberate operator registration. This prevents stale hosts from
re-activating a revoked identity. A committed revocation fences subsequent
checks/reservations; effects already authorized before it may still finish.
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
import os
import socket
import sqlite3
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..host.files import private_directory, read_owned
from ..primitives import codec, grammar

MAX_MESSAGE = 4096
MAX_MEMBERS = 32
MAX_BODY = 4096
MAX_PORT = 65535
MAX_ACTIVE_CLIENTS = 32


def principal_name(name: Any) -> str:
    return grammar.token(name, grammar.ALNUM, grammar.ALNUM + '-_.:', 128,
                         code='invalid_policy')


def _hex64(value: Any) -> str:
    return grammar.hex_string(value, 64, code='invalid_request')


def _db_failure(error: Exception) -> SecretsError:
    return SecretsError('audit_failed', detail='coordination storage unavailable')


class _Database:
    """Explicit context manager keeps ledger errors fail-closed and local."""

    def __init__(self, path: Path):
        self.path = path
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(self.path, timeout=4.0, isolation_level=None)
            self.conn = conn
            conn.execute('PRAGMA busy_timeout=4000')
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=FULL')
            return conn
        except sqlite3.Error as error:
            if self.conn is not None:
                self.conn.close()
            raise _db_failure(error) from None

    def __exit__(self, typ, error, tb) -> bool:
        if self.conn is not None:
            self.conn.close()
        if isinstance(error, sqlite3.Error):
            raise _db_failure(error) from None
        return False


class CoordinationLedger:
    """SQLite WAL/FULL local authority. One transaction per decision.

    The protected DB, -wal and -shm files MUST live on durable local storage;
    backups and rollbacks require an external anti-rollback witness. A
    mutation's successful COMMIT is its linearization point. Read decisions
    use their transaction's snapshot; already-admitted effects may complete
    after a later revocation. Never replicate the file.
    """

    def __init__(self, directory: Path):
        self.directory = Path(directory).expanduser().absolute()
        private_directory(self.directory)
        self.path = self.directory / 'coordination.sqlite3'
        if self.path.is_symlink() or not self.path.is_file():
            raise SecretsError('unsafe_file')
        info = self.path.stat()
        if (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise SecretsError('unsafe_file')

    @classmethod
    def initialize(cls, directory: Path) -> 'CoordinationLedger':
        path = Path(directory).expanduser().absolute()
        private_directory(path.parent)
        try:
            path.mkdir(mode=0o700, exist_ok=False)
            fd = os.open(path / 'coordination.sqlite3', os.O_CREAT | os.O_EXCL |
                         os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            os.close(fd)
        except OSError:
            raise SecretsError('unsafe_file') from None
        ledger = cls(path)
        with ledger._database() as conn:
            conn.executescript('''
                CREATE TABLE principals (
                    name TEXT PRIMARY KEY, active INTEGER NOT NULL,
                    members TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    CHECK(active IN (0,1))
                );
                CREATE TABLE writes (
                    name TEXT NOT NULL, key TEXT NOT NULL,
                    digest TEXT NOT NULL, state TEXT NOT NULL,
                    PRIMARY KEY(name, key),
                    CHECK(state IN ('reserved','completed'))
                );
            ''')
        return ledger

    def _database(self) -> _Database:
        # SQLite serializes local transactions; never use a network FS.
        return _Database(self.path)

    def activate(self, name: str, members: list[str]) -> dict[str, Any]:
        name = principal_name(name)
        if type(members) is not list or not 1 <= len(members) <= MAX_MEMBERS:
            raise SecretsError('invalid_request')
        # Validate JSON types before hashing for uniqueness; an object/list
        # member must be a fixed denial rather than an uncaught TypeError.
        members = sorted(_hex64(m) for m in members)
        if len(set(members)) != len(members):
            raise SecretsError('invalid_request')
        with self._database() as conn:
            try:
                conn.execute('BEGIN IMMEDIATE')
                # No UPDATE/UPSERT: even an operator cannot accidentally
                # revive a revoked principal. New principal name required.
                conn.execute('INSERT INTO principals VALUES (?,?,?,?)',
                             (name, 1, codec.dumps(members).decode(), 1))
                conn.execute('COMMIT')
            except sqlite3.IntegrityError:
                conn.execute('ROLLBACK')
                raise SecretsError('revoked') from None
        return {'active': True, 'revision': 1}

    def revoke(self, name: str) -> dict[str, Any]:
        name = principal_name(name)
        with self._database() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT revision FROM principals WHERE name=?',
                               (name,)).fetchone()
            if row is None:
                # A preemptive tombstone stops subsequent registration.
                conn.execute('INSERT INTO principals VALUES (?,?,?,?)',
                             (name, 0, '[]', 1))
                revision = 1
            else:
                revision = row[0] + 1
                conn.execute('UPDATE principals SET active=0, revision=? '
                             'WHERE name=?', (revision, name))
            conn.execute('COMMIT')
        return {'active': False, 'revision': revision}

    @staticmethod
    def _admit(conn: sqlite3.Connection, name: str, peer: str) -> int:
        row = conn.execute('SELECT active, members, revision FROM principals '
                           'WHERE name=?', (name,)).fetchone()
        if (row is None or not row[0] or
                peer not in codec.loads(row[1].encode())):
            raise SecretsError('revoked')
        return row[2]

    def check(self, name: str, peer: str) -> dict[str, Any]:
        name, peer = principal_name(name), _hex64(peer)
        with self._database() as conn:
            conn.execute('BEGIN')
            revision = self._admit(conn, name, peer)
            conn.execute('COMMIT')
            return {'active': True, 'revision': revision}

    def reserve(self, name: str, peer: str, key: str,
                digest: str) -> dict[str, Any]:
        name, peer, key, digest = (principal_name(name), _hex64(peer),
                                   _hex64(key), _hex64(digest))
        with self._database() as conn:
            conn.execute('BEGIN IMMEDIATE')
            self._admit(conn, name, peer)
            try:
                conn.execute('INSERT INTO writes VALUES (?,?,?,?)',
                             (name, key, digest, 'reserved'))
            except sqlite3.IntegrityError:
                conn.execute('ROLLBACK')
                # Never retry a previously reserved request. If the digest
                # differs the key was reused for a different effect; still
                # fail closed without revealing which existing request.
                raise SecretsError('outcome_unknown') from None
            conn.execute('COMMIT')
        return {'reserved': True}

    def finish(self, name: str, peer: str, key: str,
               digest: str) -> dict[str, Any]:
        name, peer, key, digest = (principal_name(name), _hex64(peer),
                                   _hex64(key), _hex64(digest))
        with self._database() as conn:
            conn.execute('BEGIN IMMEDIATE')
            self._admit(conn, name, peer)
            updated = conn.execute('UPDATE writes SET state=? WHERE name=? '
                                   'AND key=? AND digest=?',
                                   ('completed', name, key, digest)).rowcount
            if updated != 1:
                conn.execute('ROLLBACK')
                raise SecretsError('outcome_unknown')
            conn.execute('COMMIT')
        return {'recorded': True}

    def status(self, name: str) -> dict[str, Any]:
        name = principal_name(name)
        with self._database() as conn:
            row = conn.execute('SELECT active, revision FROM principals '
                               'WHERE name=?', (name,)).fetchone()
        return {'active': bool(row and row[0]),
                'revision': None if row is None else row[1]}


class _Handler(http.server.BaseHTTPRequestHandler):
    """Closed one-endpoint mTLS protocol; no token or request-body logging."""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        server = self.server
        assert isinstance(server, CoordinationServer)
        try:
            # One framing interpretation only, including an empty TE field.
            # BaseHTTPRequestHandler otherwise accepts repeated lengths/types.
            headers = list(self.headers.items())
            names = [name.lower() for name, _ in headers]
            if (self.path != '/v1/coordinate' or 'transfer-encoding' in names
                    or len(names) != len(set(names))
                    or sum(len(name) + len(value) + 4 for name, value in headers) > MAX_MESSAGE
                    or any(not name or any(not (char.isascii() and (char.isalnum() or char == '-'))
                                           for char in name)
                           or any(not 32 <= ord(char) <= 126 for char in value)
                           for name, value in headers)):
                raise SecretsError('invalid_request')
            raw_size = self.headers.get('Content-Length', '').strip()
            if (not raw_size.isdecimal() or len(raw_size) > 5 or
                    not 1 <= int(raw_size) <= MAX_MESSAGE):
                raise SecretsError('invalid_request')
            if self.headers.get('Content-Type', '').strip() != 'application/json':
                raise SecretsError('invalid_request')
            size = int(raw_size)
            value = codec.loads(self.rfile.read(size), limit=MAX_MESSAGE)
            data = grammar.exact_keys(value, frozenset({'action', 'name'}),
                                      frozenset({'members', 'key', 'digest'}))
            cert = self.connection.getpeercert(binary_form=True)
            if not cert:
                raise SecretsError('denied')
            peer = hashlib.sha256(cert).hexdigest()
            action = data['action']
            name = data['name']
            if action in ('activate', 'revoke'):
                if peer not in server.operators:
                    raise SecretsError('denied')
                if action == 'activate':
                    grammar.exact_keys(data, frozenset({'action','name','members'}))
                    result = server.ledger.activate(name, data['members'])
                else:
                    grammar.exact_keys(data, frozenset({'action','name'}))
                    result = server.ledger.revoke(name)
            elif action == 'check':
                grammar.exact_keys(data, frozenset({'action','name'}))
                result = server.ledger.check(name, peer)
            elif action in ('reserve', 'finish'):
                grammar.exact_keys(data,
                    frozenset({'action','name','key','digest'}))
                result = getattr(server.ledger, action)(
                    name, peer, data['key'], data['digest'])
            elif action == 'status':
                if peer not in server.operators:
                    raise SecretsError('denied')
                grammar.exact_keys(data, frozenset({'action','name'}))
                result = server.ledger.status(name)
            else:
                raise SecretsError('invalid_request')
            reply = {'ok': True, **result}
        except SecretsError as error:
            reply = {'ok': False, 'code': error.code}
        except Exception:
            reply = {'ok': False, 'code': 'internal_error'}
        body = codec.dumps(reply)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)


class CoordinationServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], *,
                 ledger: CoordinationLedger, server_cert: Path,
                 server_key: Path, client_ca: Path,
                 operator_fingerprints: list[str]):
        self.ledger = ledger
        # A stalled authenticated member must not spawn unbounded threads.
        self._slots = threading.BoundedSemaphore(MAX_ACTIVE_CLIENTS)
        self.operators = frozenset(_hex64(value) for value in operator_fingerprints)
        if not self.operators:
            raise SecretsError('invalid_policy')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.keylog_filename = None
        # Certificate and private key paths are operator-controlled host input,
        # not symlinks or guest-mutable trust material. SSLContext.load_* opens
        # files by pathname: validate first and run in a trusted private tree.
        read_owned(client_ca, private=False, limit=1024 * 1024,
                   what='coordination client CA')
        read_owned(server_cert, private=False, limit=1024 * 1024,
                   what='coordination server certificate')
        read_owned(server_key, private=True, limit=1024 * 1024,
                   what='coordination TLS private key')
        context.load_verify_locations(cafile=str(client_ca))
        context.load_cert_chain(str(server_cert), str(server_key))
        # Do not wrap the LISTEN socket: its accept-side TLS handshake may
        # otherwise block the entire accept loop on a stalling peer. Handshake
        # each accepted client in its bounded worker slot and timeout.
        self._context = context
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            # TLS belongs inside the worker slot. Handshaking in get_request
            # lets one anonymous socket block every authenticated member.
            try:
                tls = self._context.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                self.shutdown_request(request)
                return
            super().process_request_thread(tls, client_address)
        finally:
            self._slots.release()

    def get_request(self) -> tuple[socket.socket, Any]:
        raw, address = super().get_request()
        raw.settimeout(5.0)
        return raw, address


@dataclass(frozen=True)
class CoordinationConfig:
    host: str
    port: int
    ca_file: Path
    certificate_file: Path
    key_file: Path
    principal: str

    @classmethod
    def parse(cls, value: Any) -> 'CoordinationConfig':
        data = grammar.exact_keys(value, frozenset({
            'schema', 'host', 'port', 'ca_file', 'certificate_file',
            'key_file', 'principal'}), code='invalid_policy')
        grammar.integer(data['schema'], 1, 1, code='invalid_policy')
        # Local coordinator deployments use an explicitly authenticated
        # localhost certificate; keep file-loaded and direct clients usable.
        host = ('localhost' if type(data['host']) is str and data['host'] == 'localhost' else
                grammar.hostname(data['host'], code='invalid_policy'))
        port = grammar.integer(data['port'], 1, MAX_PORT, code='invalid_policy')
        principal = principal_name(data['principal'])
        return cls(host, port, *(
            Path(grammar.text(data[key], 4096, code='invalid_policy'))
            .expanduser().absolute() for key in
            ('ca_file', 'certificate_file', 'key_file')),
            principal)

    @classmethod
    def load(cls, path: Path, *, untrusted: tuple[Path, ...] = ()):
        data = read_owned(path, private=True, untrusted=untrusted,
                          limit=MAX_BODY, what='coordination config')
        return cls.parse(codec.loads(data, code='invalid_policy'))


def _acknowledge(action: str, data: Any) -> dict[str, Any]:
    """Accept complete typed receipts; never turn absent state into a tombstone."""
    operator = action in {'activate', 'revoke', 'status'}
    bad = ('outcome_unknown' if action in {'activate', 'revoke'} else
           'upstream_response' if operator else 'revoked')
    if type(data) is not dict or type(data.get('ok')) is not bool:
        raise SecretsError(bad)
    if data['ok'] is False:
        code = data.get('code')
        if not operator:
            raise SecretsError('outcome_unknown' if code == 'outcome_unknown' else 'revoked')
        if set(data) == {'ok', 'code'} and type(code) is str and code in {
                'denied', 'revoked', 'invalid_request', 'outcome_unknown'}:
            raise SecretsError(code)
        raise SecretsError(bad)
    if operator:
        if set(data) != {'ok', 'active', 'revision'} or type(data['active']) is not bool:
            raise SecretsError(bad)
        active, revision = data['active'], data['revision']
        positive = type(revision) is int and 1 <= revision <= 2**63 - 1
        accepted = (
            (action == 'activate' and active and positive and revision == 1) or
            (action == 'revoke' and not active and positive) or
            (action == 'status' and (positive or (revision is None and not active))))
    elif action == 'check':
        accepted = (set(data) == {'ok', 'active', 'revision'} and
                    data['active'] is True and type(data['revision']) is int and
                    1 <= data['revision'] <= 2**63 - 1)
    else:
        flag = {'reserve': 'reserved', 'finish': 'recorded'}.get(action)
        accepted = flag is not None and set(data) == {'ok', flag} and data[flag] is True
    if not accepted:
        raise SecretsError(bad)
    return data


class CoordinationClient:
    """Host-only, fail-closed mTLS; no proxy, redirects, cache or retries."""

    def __init__(self, config: CoordinationConfig):
        self.config = config
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.keylog_filename = None
        read_owned(config.ca_file, private=False, limit=1024 * 1024,
                   what='coordination trust anchor')
        read_owned(config.certificate_file, private=False, limit=1024 * 1024,
                   what='coordination client certificate')
        read_owned(config.key_file, private=True, limit=1024 * 1024,
                   what='coordination TLS private key')
        ctx.load_verify_locations(cafile=str(config.ca_file))
        ctx.load_cert_chain(certfile=str(config.certificate_file),
                            keyfile=str(config.key_file))
        self._context = ctx

    def _call(self, action: str, **extra: Any) -> dict[str, Any]:
        request = codec.dumps({'action': action, 'name': self.config.principal,
                               **extra})
        conn = http.client.HTTPSConnection(self.config.host, self.config.port,
                                          timeout=4, context=self._context)
        operator = action in {'activate', 'revoke', 'status'}
        mutating = action in {'activate', 'revoke'}
        sent = False
        bad_reply = ('outcome_unknown' if mutating else
                     'upstream_response' if operator else 'revoked')
        try:
            # Complete peer authentication before marking possible submission.
            # A partial request write can still commit; never retry it here.
            conn.connect()
            sent = True
            conn.request('POST', '/v1/coordinate', body=request,
                         headers={'Content-Type': 'application/json'})
            response = conn.getresponse()
            if response.status != 200 or response.getheader('Content-Type') != 'application/json':
                raise SecretsError(bad_reply)
            body = response.read(MAX_MESSAGE + 1)
            if len(body) > MAX_MESSAGE:
                raise SecretsError(bad_reply)
            try:
                data = codec.loads(body, limit=MAX_MESSAGE)
            except SecretsError:
                raise SecretsError(bad_reply) from None
            return _acknowledge(action, data)
        except SecretsError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
            code = (bad_reply if sent else 'unreachable') if operator else 'revoked'
            raise SecretsError(code) from None
        finally:
            conn.close()

    def check(self) -> None:
        self._call('check')

    def reserve(self, key: str, digest: str) -> None:
        self._call('reserve', key=key, digest=digest)

    def finish(self, key: str, digest: str) -> None:
        self._call('finish', key=key, digest=digest)

    def activate(self, members: list[str]) -> None:
        self._call('activate', members=members)

    def revoke(self) -> None:
        self._call('revoke')

    def status(self) -> dict[str, Any]:
        return self._call('status')
