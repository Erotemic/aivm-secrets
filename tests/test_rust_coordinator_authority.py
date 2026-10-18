"""Independent Rust coordinator with the existing Python mTLS clients and schema."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import queue
import socket
import sqlite3
import subprocess
import threading

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.coordination import CoordinationLedger
from tests.test_rust_coordination import CoordinatorCase
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import private
from tests.test_secrets_coordination import KEY, DIGEST


class NativeCoordinatorCase(CoordinatorCase):
    """Real native authority process; Python supplies independent clients only."""
    def __enter__(self):
        self.binary = executable('AIVM_SECRETS_RUST_COORDINATOR')
        self.process = None
        self.start()
        return self

    def start(self):
        config = private(self.root / 'server.json', dict(schema=1,
            listen='127.0.0.1:0', directory=str(self.ledger.directory),
            server_certificate_file=str(self.certificate), server_key_file=str(self.key),
            client_ca_file=str(self.ca), operator_fingerprints=[self.operator_material[2]]))
        self.process = subprocess.Popen([self.binary, 'serve', '--config', str(config)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            lines = queue.Queue()
            threading.Thread(target=lambda: lines.put(self.process.stdout.readline()), daemon=True).start()
            ready = json.loads(lines.get(timeout=10))
            assert ready['ok'], ready
            self.port = int(ready['listen'].rsplit(':', 1)[1])
            self.operator = self.client(self.operator_material)
            self.running = True
        except BaseException:
            self.stop()
            raise

    def config(self, material):
        return dict(schema=1, host='localhost', port=self.port,
            ca_file=str(self.ca), certificate_file=str(material[0]),
            key_file=str(material[1]), principal='shared-principal')

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=7)
            assert self.process.stderr.read() == b''
            self.process.stdout.close()
            self.process.stderr.close()
            self.process = None
        self.running = False

    def __exit__(self, typ, error, tb):
        self.stop()
        return False


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_authority_members_operator_roles_and_preemptive_revocation(tmp_path, backend):
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    with case(tmp_path / 'coord') as coord:
        member, other, stranger = [coord.client(m) for m in coord.members]
        assert coord.operator.status() == {'ok': True, 'active': False, 'revision': None}
        for peer in (member, stranger):
            with pytest.raises(SecretsError):
                peer.check()
            for action in [lambda: peer.activate([coord.members[0][2]]), peer.revoke, peer.status]:
                with pytest.raises(SecretsError):
                    action()
        coord.operator.activate([m[2] for m in coord.members[:2]])
        member.check()
        other.check()
        with pytest.raises(SecretsError):
            stranger.check()
        coord.operator.revoke()
        for peer in (member, other):
            with pytest.raises(SecretsError):
                peer.check()
        with pytest.raises(SecretsError):
            coord.operator.activate([coord.members[0][2]])
        assert coord.operator.status() == {'ok': True, 'active': False, 'revision': 2}
        # A tombstone also fences a name that was never registered.
        coord.operator.config = replace(coord.operator.config, principal='never-registered')
        coord.operator.revoke()
        with pytest.raises(SecretsError):
            coord.operator.activate([coord.members[0][2]])


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_authority_racing_members_share_permanent_write_keys(tmp_path, backend):
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    with case(tmp_path / 'coord') as coord:
        coord.operator.activate([m[2] for m in coord.members[:2]])
        def reserve(i):
            try:
                coord.client(coord.members[i % 2]).reserve(KEY, DIGEST)
                return 'reserved'
            except SecretsError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(reserve, range(20)))
        assert outcomes.count('reserved') == 1
        assert outcomes.count('outcome_unknown') == 19
        for digest in [DIGEST, 'f' * 64]:
            with pytest.raises(SecretsError, match='may have completed'):
                coord.client(coord.members[1]).reserve(KEY, digest)
        with pytest.raises(SecretsError):
            coord.client(coord.members[0]).finish(KEY, 'f' * 64)
        coord.client(coord.members[1]).finish(KEY, DIGEST)
        coord.client(coord.members[0]).finish(KEY, DIGEST)
        with sqlite3.connect(coord.root / 'ledger' / 'coordination.sqlite3') as conn:
            assert conn.execute('SELECT name,key,digest,state FROM writes').fetchall() == [
                ('shared-principal', KEY, DIGEST, 'completed')]


def test_native_authority_restart_retains_revocation_and_spent_keys(tmp_path):
    with NativeCoordinatorCase(tmp_path / 'coord') as coord:
        coord.operator.activate([coord.members[0][2]])
        member = coord.client(coord.members[0])
        member.reserve(KEY, DIGEST)
        coord.stop()
        coord.start()
        with pytest.raises(SecretsError):
            coord.client(coord.members[0]).reserve(KEY, DIGEST)
        coord.operator.revoke()
        coord.stop()
        coord.start()
        with pytest.raises(SecretsError):
            coord.client(coord.members[0]).check()
        assert CoordinationLedger(coord.root / 'ledger').status('shared-principal') == {
            'active': False, 'revision': 2}


def test_native_authority_stalled_anonymous_peer_does_not_block_operator(tmp_path):
    with NativeCoordinatorCase(tmp_path / 'coord') as coord:
        with socket.create_connection(('127.0.0.1', coord.port)):
            assert coord.operator.status() == {'ok': True, 'active': False, 'revision': None}


@pytest.mark.parametrize('backend', ['python', 'rust'])
@pytest.mark.parametrize('malformed', ['duplicate-length', 'duplicate-type', 'empty-transfer-encoding'])
def test_authority_rejects_ambiguous_http_framing(tmp_path, backend, malformed):
    import http.client
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    with case(tmp_path / 'coord') as coord:
        port = coord.port if hasattr(coord, 'port') else coord.server.server_address[1]
        conn = http.client.HTTPSConnection('localhost', port, context=coord.operator._context, timeout=4)
        body = b'{"action":"status","name":"shared-principal"}'
        try:
            conn.putrequest('POST', '/v1/coordinate')
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', str(len(body)))
            if malformed == 'duplicate-length':
                conn.putheader('Content-Length', '4096')
            elif malformed == 'duplicate-type':
                conn.putheader('Content-Type', 'application/json')
            else:
                conn.putheader('Transfer-Encoding', '')
            conn.endheaders(body)
            response = conn.getresponse()
            assert json.loads(response.read()) == {'ok': False, 'code': 'invalid_request'}
        finally:
            conn.close()


@pytest.mark.parametrize('backend', ['python', 'rust'])
@pytest.mark.parametrize('payload', [
    b'{"action":"status","action":"check","name":"shared-principal"}',
    b'{"action":{"$serde_json::private::Number":"7"},"name":"shared-principal"}',
    b'{"action":"status","name":"shared-principal","peer":"forged"}',
    b'{"action":"reserve","name":"shared-principal","key":true,"digest":"bad"}',
])
def test_authority_refuses_malformed_typed_protocol(tmp_path, backend, payload):
    import http.client
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    with case(tmp_path / 'coord') as coord:
        port = coord.port if hasattr(coord, 'port') else coord.server.server_address[1]
        conn = http.client.HTTPSConnection('localhost', port, context=coord.operator._context, timeout=4)
        try:
            conn.request('POST', '/v1/coordinate', body=payload, headers={'Content-Type': 'application/json'})
            response = conn.getresponse()
            assert json.loads(response.read()) == {'ok': False, 'code': 'invalid_request'}
        finally:
            conn.close()
        assert coord.operator.status() == {'ok': True, 'active': False, 'revision': None}


def test_native_initializer_is_readable_by_python_and_never_replaces_state(tmp_path):
    binary = executable('AIVM_SECRETS_RUST_COORDINATOR')
    root = tmp_path / 'native-ledger'
    def initialize():
        return subprocess.run([binary, 'init', '--directory', str(root)], capture_output=True, timeout=8)
    result = initialize()
    assert result.returncode == 0 and json.loads(result.stdout)['ok']
    assert result.stderr == b''
    ledger = CoordinationLedger(root)
    ledger.activate('python-member', ['a' * 64])
    ledger.reserve('python-member', 'a' * 64, KEY, DIGEST)
    again = initialize()
    assert again.returncode == 1 and json.loads(again.stdout)['error']['code'] == 'unsafe_file'
    assert ledger.status('python-member') == {'active': True, 'revision': 1}
    with pytest.raises(SecretsError):
        ledger.reserve('python-member', 'a' * 64, KEY, DIGEST)


@pytest.mark.parametrize('replacement', ['symlink', 'hardlink', 'public-mode', 'sidecar-symlink'])
def test_native_authority_refuses_unsafe_database_files(tmp_path, replacement):
    binary = executable('AIVM_SECRETS_RUST_COORDINATOR')
    case = NativeCoordinatorCase(tmp_path / 'coord')
    database = case.root / 'ledger' / 'coordination.sqlite3'
    if replacement == 'symlink':
        moved = case.root / 'actual.sqlite3'
        database.rename(moved)
        database.symlink_to(moved)
    elif replacement == 'hardlink':
        (case.root / 'alias.sqlite3').hardlink_to(database)
    elif replacement == 'public-mode':
        database.chmod(0o644)
    else:
        (database.parent / 'coordination.sqlite3-wal').symlink_to(database)
    with pytest.raises(AssertionError, match='unsafe_file'):
        with case:
            pytest.fail('unsafe database accepted')


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_authority_requires_client_certificate_before_dispatch(tmp_path, backend):
    import http.client
    import ssl
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    with case(tmp_path / 'coord') as coord:
        port = coord.port if hasattr(coord, 'port') else coord.server.server_address[1]
        context = ssl.create_default_context(cafile=str(coord.ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        conn = http.client.HTTPSConnection('localhost', port, context=context, timeout=4)
        try:
            with pytest.raises((OSError, http.client.HTTPException)):
                conn.request('POST', '/v1/coordinate',
                    body=b'{"action":"revoke","name":"shared-principal"}',
                    headers={'Content-Type': 'application/json'})
                conn.getresponse()
        finally:
            conn.close()
        assert coord.operator.status() == {'ok': True, 'active': False, 'revision': None}


@pytest.mark.parametrize('origin', ['python', 'rust'])
def test_database_survives_native_then_reference_server_switch(tmp_path, origin):
    from aivm_secrets.identity.coordination import CoordinationClient, CoordinationConfig, CoordinationServer
    coord = NativeCoordinatorCase(tmp_path / 'coord')
    if origin == 'rust':
        binary = executable('AIVM_SECRETS_RUST_COORDINATOR')
        directory = coord.root / 'native-ledger'
        init = subprocess.run([binary, 'init', '--directory', str(directory)],
                              capture_output=True, timeout=8)
        assert init.returncode == 0, init.stdout
        coord.ledger = CoordinationLedger(directory)
    with coord:
        coord.operator.activate([coord.members[0][2]])
        member = coord.client(coord.members[0])
        member.reserve(KEY, DIGEST)
        member.finish(KEY, DIGEST)
        coord.operator.revoke()
    # The independent Python HTTP authority must retain both decisions too.
    with CoordinationServer(('127.0.0.1', 0), ledger=coord.ledger,
            server_cert=coord.certificate, server_key=coord.key, client_ca=coord.ca,
            operator_fingerprints=[coord.operator_material[2]]) as reference:
        worker = threading.Thread(target=reference.serve_forever, kwargs={'poll_interval': 0.01})
        worker.start()
        try:
            config = dict(coord.config(coord.operator_material), port=reference.server_address[1])
            operator = CoordinationClient(CoordinationConfig.parse(config))
            assert operator.status() == {'ok': True, 'active': False, 'revision': 2}
            with pytest.raises(SecretsError):
                operator.activate([coord.members[0][2]])
            with sqlite3.connect(coord.ledger.path) as db:
                assert db.execute('SELECT digest,state FROM writes').fetchall() == [(DIGEST, 'completed')]
        finally:
            reference.shutdown()
            worker.join(timeout=5)
            assert not worker.is_alive()


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_frozen_authority_protocol_vectors_and_durable_state(tmp_path, backend):
    import http.client
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    rows = [json.loads(line) for line in (Path(__file__).parent /
        'secrets_vectors/coordination/authority-v1.jsonl').read_text().splitlines()]
    with case(tmp_path / 'coord') as coord:
        materials = dict(zip(['member-a', 'member-b', 'stranger'], coord.members))
        materials['operator'] = coord.operator_material
        replacements = {'$' + name: item[2] for name, item in materials.items()}
        replacements.update({'$key': KEY, '$digest': DIGEST, '$other-digest': 'f' * 64})
        def expand(value):
            if isinstance(value, str):
                return replacements.get(value, value)
            if isinstance(value, list):
                return [expand(item) for item in value]
            if isinstance(value, dict):
                return {key: expand(item) for key, item in value.items()}
            return value
        port = coord.port if hasattr(coord, 'port') else coord.server.server_address[1]
        for index, row in enumerate(rows):
            client = coord.client(materials[row['actor']])
            conn = http.client.HTTPSConnection('localhost', port, context=client._context, timeout=4)
            try:
                conn.request('POST', '/v1/coordinate', body=json.dumps(expand(row['request'])),
                             headers={'Content-Type': 'application/json'})
                response = conn.getresponse()
                assert response.status == 200
                assert json.loads(response.read()) == row['reply'], (backend, index, row)
            finally:
                conn.close()
        with sqlite3.connect(coord.ledger.path) as db:
            assert db.execute('SELECT name,active,revision FROM principals ORDER BY name').fetchall() == [
                ('blocked-before-registration', 0, 1), ('other', 1, 1), ('team', 0, 3)]
            assert db.execute('SELECT name,key,digest,state FROM writes ORDER BY name').fetchall() == [
                ('other', KEY, DIGEST, 'reserved'), ('team', KEY, DIGEST, 'completed')]


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_every_authority_action_obeys_role_and_principal_snapshot(tmp_path, backend):
    """Exercise all six actions, including operators lacking member authority.

    Every denied call must leave both durable tables unchanged. Separate names
    keep successful mutations from changing the next row of the role matrix.
    """
    import http.client
    case = CoordinatorCase if backend == 'python' else NativeCoordinatorCase
    actions = ('activate', 'revoke', 'status', 'check', 'reserve', 'finish')
    with case(tmp_path / 'coord') as coord:
        port = coord.port if hasattr(coord, 'port') else coord.server.server_address[1]
        for state in ('absent', 'active', 'revoked'):
            for actor in ('member', 'outsider', 'operator', 'operator-member'):
                for action in actions:
                    name = f'{state}-{actor}-{action}'
                    coord.operator.config = replace(coord.operator.config, principal=name)
                    members = [coord.members[0][2]]
                    if actor == 'operator-member':
                        members.append(coord.operator_material[2])
                    if state != 'absent':
                        coord.operator.activate(members)
                        if action == 'finish':
                            member = coord.client(coord.members[0])
                            member.config = replace(member.config, principal=name)
                            member.reserve(KEY, DIGEST)
                        if state == 'revoked':
                            coord.operator.revoke()
                    material = (coord.operator_material if actor.startswith('operator') else
                                coord.members[0 if actor == 'member' else 1])
                    client = coord.client(material)
                    request = dict(action=action, name=name)
                    if action == 'activate':
                        request['members'] = members
                    elif action in ('reserve', 'finish'):
                        request.update(key=KEY, digest=DIGEST)
                    if action in ('activate', 'revoke', 'status'):
                        denial = (None if actor.startswith('operator') else 'denied')
                        if denial is None and action == 'activate' and state != 'absent':
                            denial = 'revoked'
                    else:
                        denial = (None if state == 'active' and
                                  actor in ('member', 'operator-member') else 'revoked')
                    with sqlite3.connect(coord.ledger.path) as db:
                        before = [db.execute(f'SELECT * FROM {table} ORDER BY name').fetchall()
                                  for table in ('principals', 'writes')]
                    conn = http.client.HTTPSConnection('localhost', port,
                        context=client._context, timeout=4)
                    try:
                        conn.request('POST', '/v1/coordinate', body=json.dumps(request),
                                     headers={'Content-Type': 'application/json'})
                        response = conn.getresponse()
                        assert response.status == 200
                        reply = json.loads(response.read())
                    finally:
                        conn.close()
                    context = (backend, state, actor, action, reply)
                    if denial is None:
                        assert reply['ok'] is True, context
                    else:
                        assert reply == {'ok': False, 'code': denial}, context
                        with sqlite3.connect(coord.ledger.path) as db:
                            after = [db.execute(f'SELECT * FROM {table} ORDER BY name').fetchall()
                                     for table in ('principals', 'writes')]
                        assert after == before, context
