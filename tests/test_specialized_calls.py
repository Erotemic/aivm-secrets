"""Compiler-ledger orchestration and linkage witnesses, not secrecy proofs."""
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from dev.verification.specialized_calls import (
    LedgerError, Limits, capture_process, explain, project_archive, select,
)


def projection():
    def function(i, names, direct=(), kind='Unstructured', unresolved=None):
        return dict(def_id=i, generics=dict(types=0), item_meta=dict(
            name=[*names, '<Instantiated>'], has_errors=False,
            span=dict(Untagged=dict(data=dict(file_id=0, beg=dict(line=i+1, col=0),
                                             end=dict(line=i+1, col=1))))),
            body=dict(kind=kind, blocks=dict(count=1, calls=len(direct), drops=1,
                      direct=list(direct), unresolved=unresolved or {}, sites=[])))
    return dict(projection_schema=1, charon_version='0.1.291', has_errors=False,
                translated=dict(crate_name='garrett_bridge',
                    options=dict(monomorphize=True, ullbc=True),
                    files=[dict(id=0, name={'Local':'src/main.rs'})], fun_decls=[
        function(0, ['aivm_secrets_garrett','tls','<Impl>','answer'], [1,29,41]),
        function(1, ['aivm_secrets_garrett_core','protocol','perform'], [2]),
        function(2, ['aivm_secrets_garrett','custody','<Impl>','execute'], [3]),
        function(3, ['aivm_secrets_garrett','custody','<Impl>','exchange'], [6,8]),
        function(4, ['aivm_secrets_garrett_core','dispatch','dispatch'], [22]),
        function(5, ['aivm_secrets_garrett','custody','manifest_session','<Impl>',
                     'send_manifest_bytes'], [36]),
        function(6, ['std','io','Write','write_all'], kind='Opaque'),
        function(7, ['rustls_pki_types','pem','reader'], unresolved={'Trait':2}),
        function(8, ['aivm_secrets_garrett','custody','account_request_bytes'], [14]),
        function(9, ['aivm_secrets_garrett','custody','manifest_session',
                     'manifest_request_bytes'], [37]),
        function(10, ['aivm_secrets_garrett_core','http_auth','append_header'], [11]),
        function(11, ['aivm_secrets_garrett_core','http_auth','valid_credential']),
        function(12, ['aivm_secrets_garrett_core','http_request','append_line'], [13]),
        function(13, ['aivm_secrets_garrett_core','http_request','valid_target']),
        function(14, ['aivm_secrets_garrett','custody','provider_request_bytes'], [15]),
        function(15, ['aivm_secrets_garrett_core','http_wire','append_request'], [10,12,16]),
        function(16, ['aivm_secrets_garrett_core','http_wire','valid_headers'], [17]),
        function(17, ['aivm_secrets_garrett_core','http_wire','valid_header'], [18]),
        function(18, ['aivm_secrets_garrett_core','http_wire','valid_name'], [19]),
        function(19, ['aivm_secrets_garrett_core','http_wire','reserved_name'], [20]),
        function(20, ['aivm_secrets_garrett_core','http_wire','ascii_equal']),
        function(22, ['aivm_secrets_garrett_core','provider_exchange','exchange'], [5,34,38]),
        function(23, ['aivm_secrets_garrett_core','request_adapter','<Impl>','dispatch'], [4,30]),
        function(24, ['aivm_secrets_garrett_core','request_adapter','<Impl>','complete'], [25]),
        function(25, ['aivm_secrets_garrett_core','completion','complete'], [26]),
        function(26, ['aivm_secrets_garrett','custody','manifest_session','<Impl>','audit'], [27]),
        function(27, ['aivm_secrets_garrett','custody','<Impl>','write_record'], [6]),
        function(29, ['aivm_secrets_garrett_core','read_transition','run_current'], [23,24]),
        function(30, ['aivm_secrets_garrett_core','request_context','<Impl>','dispatch'], [31]),
        function(31, ['aivm_secrets_garrett','custody','manifest_session','<Impl>','checks']),
        function(32, ['aivm_secrets_garrett_core','provider_io','<Impl>','submit'], [33]),
        function(33, ['aivm_secrets_garrett','custody','manifest_session','<Impl>','write_all'], [6]),
        function(34, ['aivm_secrets_garrett','custody','manifest_session','<Impl>','receive'], [35]),
        function(35, ['aivm_secrets_garrett_core','provider_io','<Impl>','into_parts']),
        function(36, ['aivm_secrets_garrett_core','provider_io','<Impl>','submit'], [32]),
        function(37, ['aivm_secrets_garrett_core','provider_wire','append'], [15]),
        function(38, ['aivm_secrets_garrett','custody','manifest_session','<Impl>','setup_route'], [9,39,40]),
        function(39, ['aivm_secrets_garrett_core','provider_wire','<Impl>','host']),
        function(40, ['aivm_secrets_garrett_core','provider_wire','<Impl>','port']),
        function(41, ['aivm_secrets_garrett','json','canonical'], [42]),
        function(42, ['aivm_secrets_garrett','json','string'], [43]),
        function(43, ['aivm_secrets_garrett_core','json_string','append']),
    ]))


def test_compiled_paths_keep_external_and_dynamic_obligations_explicit():
    result = explain(projection())
    assert result['witnesses'] == {'account-controller-executor':[0,1,2,3],
        'coordinated-manifest-executor':[0,29,23,4,22,5],
        'owned-request-completion-audit':[0,29,24,25,26,27],
        'owned-context-check-factory':[0,29,23,30,31],
        'captured-provider-writer':[0,29,23,4,22,5,36,32,33],
        'captured-provider-response-parts':[0,29,23,4,22,34,35],
        'manifest-encoded-endpoint-host':[0,29,23,4,22,38,39],
        'manifest-encoded-endpoint-port':[0,29,23,4,22,38,40],
        'native-json-string-encoder':[0,41,42,43],
        'account-authentication-bytes':[0,1,2,3,8,14,15,10,11],
        'manifest-authentication-bytes':[0,29,23,4,22,38,9,37,15,10,11],
        'account-request-line':[0,1,2,3,8,14,15,12,13],
        'manifest-request-line':[0,29,23,4,22,38,9,37,15,12,13],
        'account-complete-header-admission':[0,1,2,3,8,14,15,16,17,18,19,20],
        'manifest-complete-header-admission':[0,29,23,4,22,38,9,37,15,16,17,18,19,20]}
    assert result['opaque_boundaries'] == [6]
    assert result['unresolved_calls'] == {7:{'Trait':2}}
    assert result['unresolved_in_root'] == {}
    assert result['complete_mediation'] is False
    assert result['witness_details']['account-controller-executor'][-1]['source'][
        'begin']['line'] == 4


@pytest.mark.parametrize('victim', [0,1,2,3,4,8,9,10,12,14,15,16,17,18,19,21,22,23,24,25,27,28,30,32,34,35,36,39,40])
def test_missing_callback_link_cannot_be_rebaselined_as_a_passing_witness(victim):
    data = projection()
    data['translated']['fun_decls'][victim]['body']['blocks']['direct'] = []
    with pytest.raises(LedgerError, match='callback link missing'):
        explain(data)


def test_compiler_generated_helper_is_not_an_extra_method_root():
    data = projection()
    helper = deepcopy(data['translated']['fun_decls'][0])
    helper['def_id'] = 21
    helper['item_meta']['name'].insert(-1, '<Builtin>')
    data['translated']['fun_decls'].append(helper)
    nodes = {f['def_id']:f for f in data['translated']['fun_decls']}
    assert select(nodes, ('aivm_secrets_garrett','tls','answer')) == {0}


@pytest.mark.parametrize('bad', ['header','opaque','generic'])
def test_incomplete_or_unspecialized_declaration_is_refused(bad):
    data = projection()
    if bad == 'header':
        data['has_errors'] = True
    elif bad == 'opaque':
        data['translated']['fun_decls'][1]['body']['kind'] = 'Opaque'
    else:
        data['translated']['fun_decls'][1]['generics']['types'] = 1
    with pytest.raises(LedgerError):
        explain(data)


def writer(out, payload, code=0):
    # Synthetic compiler for stream supervision tests only, not binding evidence.
    return [sys.executable, '-c',
            'import sys; open(sys.argv[1],"wb").write(bytes.fromhex(sys.argv[2])); '
            'raise SystemExit(int(sys.argv[3]))',
            str(out/'garrett_bridge.ullbc'), payload.hex(), str(code)]


def test_capture_roundtrip_hash_and_fifo_cleanup(tmp_path):
    raw = b'fixture compiler output'*200
    result = capture_process(writer(tmp_path,raw),tmp_path,tmp_path,
                             Limits(plain=10000, compressed=10000, compiler_seconds=5))
    assert result['status'] == 'captured'
    assert result['plain_bytes'] == len(raw)
    assert result['plain_sha256'] == hashlib.sha256(raw).hexdigest()
    assert gzip.decompress((tmp_path/'compiler.ullbc.gz').read_bytes()) == raw
    assert not (tmp_path/'garrett_bridge.ullbc').exists()


@pytest.mark.parametrize('failure', ['plain','compressed','exit','empty'])
def test_capture_resource_and_process_failures_cannot_pass(tmp_path, failure):
    raw = b'x'*4096 if failure != 'empty' else b''
    limits = Limits(plain=100 if failure=='plain' else 10000,
                    compressed=16 if failure=='compressed' else 10000,
                    compiler_seconds=5)
    with pytest.raises(LedgerError):
        capture_process(writer(tmp_path,raw,7 if failure=='exit' else 0),
                        tmp_path,tmp_path,limits)
    result = json.loads((tmp_path/'capture.json').read_text())
    assert result['status'] == 'failed'
    assert not (tmp_path/'garrett_bridge.ullbc').exists()
    assert (tmp_path/'compiler.ullbc.gz').stat().st_size <= limits.compressed


def test_capture_deadline_stops_compiler_before_any_output(tmp_path):
    with pytest.raises(LedgerError, match='deadline'):
        capture_process([sys.executable,'-c','import time; time.sleep(30)'],
                        tmp_path,tmp_path,Limits(compiler_seconds=.1))
    result = json.loads((tmp_path/'capture.json').read_text())
    assert result['exit_code'] != 0 and result['status'] == 'failed'


def test_missing_compiler_has_no_dangling_fifo(tmp_path):
    with pytest.raises(LedgerError, match='could not start'):
        capture_process([str(tmp_path/'missing-command')], tmp_path, tmp_path)
    assert json.loads((tmp_path/'capture.json').read_text())['status'] == 'failed'
    assert not (tmp_path/'garrett_bridge.ullbc').exists()


def test_invalid_deadlines_are_refused():
    for value in [float('nan'), float('inf'), -1]:
        with pytest.raises(LedgerError):
            Limits(compiler_seconds=value)


def projector_script(tmp_path, body):
    script = tmp_path/'projector'
    script.write_text('#!'+sys.executable+'\n'+body)
    script.chmod(0o700)
    return script


def test_gzip_crc_failure_is_not_a_valid_projection(tmp_path):
    raw = bytearray(gzip.compress(b'{}'))
    raw[-8] ^= 1
    archive = tmp_path/'input.gz'
    archive.write_bytes(raw)
    child = projector_script(tmp_path, 'import sys; sys.stdin.buffer.read(); '
                             'sys.stdout.write('+repr(json.dumps(projection()))+')\n')
    with pytest.raises(LedgerError, match='corrupt'):
        project_archive(archive, child, tmp_path)
    assert not (tmp_path/'projection.json').exists()


def test_projector_timeout_never_publishes_a_report(tmp_path):
    archive = tmp_path/'input.gz'
    archive.write_bytes(gzip.compress(b'{}'))
    child = projector_script(tmp_path,'import time; time.sleep(30)\n')
    with pytest.raises(subprocess.TimeoutExpired):
        project_archive(archive,child,tmp_path,Limits(projector_seconds=.1))
    assert not (tmp_path/'projection.json').exists()



def authority_projection():
    data = projection()
    data['translated']['crate_name'] = 'garrett_coordinator'
    template = deepcopy(data['translated']['fun_decls'][0])
    def function(i, name, targets=()):
        result = deepcopy(template)
        result['def_id'] = i
        result['item_meta']['name'] = [*name, '<Instantiated>']
        result['body']['blocks']['direct'] = list(targets)
        return result
    native = ['aivm_secrets_garrett', 'coordinator_authority']
    core = ['aivm_secrets_garrett_core', 'coordinator_authority']
    data['translated']['fun_decls'] = [
        function(0, [*native, 'server', 'exchange'], [1]),
        function(1, [*native, 'ledger', '<Impl>', 'handle'], [9,10,4,5,6,7]),
        function(2, [*core, 'require_operator'], [8]),
        function(3, [*core, 'admit'], [8]),
        *[function(i, [*core, name]) for i, name in
          enumerate(['activate', 'revoke', 'reserve', 'finish'], 4)],
        function(8, [*core, 'contains_peer']),
        function(9, [*core, 'require_operator_for'], [2]),
        function(10, [*core, 'authorize'], [9,3]),
    ]
    return data


def test_authority_compiled_handler_paths_keep_mediation_open():
    result = explain(authority_projection(), 'coordinator')
    assert result['witnesses'] == {
        'coordinator-operator-admission': [0,1,9,2,8],
        'coordinator-member-admission': [0,1,10,3,8],
        'coordinator-activate': [0,1,4], 'coordinator-revoke': [0,1,5],
        'coordinator-reserve': [0,1,6], 'coordinator-finish': [0,1,7]}
    assert result['complete_mediation'] is False
    with pytest.raises(LedgerError, match='selected specialized target'):
        explain(authority_projection())


@pytest.mark.parametrize('caller,victim', [(1,10),(9,2),(10,3),
                                               (1,4),(1,5),(1,6),(1,7)])
def test_authority_missing_guard_or_transition_link_fails(caller, victim):
    data = authority_projection()
    data['translated']['fun_decls'][caller]['body']['blocks']['direct'].remove(victim)
    with pytest.raises(LedgerError, match='callback link missing'):
        explain(data, 'coordinator')


def test_authority_final_gate_retains_operator_path_without_early_check():
    data = authority_projection()
    data['translated']['fun_decls'][1]['body']['blocks']['direct'].remove(9)
    result = explain(data, 'coordinator')
    assert result['witnesses']['coordinator-operator-admission'] == [0,1,10,9,2,8]
    assert result['complete_mediation'] is False


def test_capture_uses_the_selected_coordinator_fifo(tmp_path):
    raw = b'coordinator compiler fixture'
    command = [sys.executable, '-c', 'import sys;open(sys.argv[1],"wb").write(bytes.fromhex(sys.argv[2]))',
               str(tmp_path / 'garrett_coordinator.ullbc'), raw.hex()]
    result = capture_process(command, tmp_path, tmp_path,
                             artifact='garrett_coordinator.ullbc')
    assert result['artifact'] == 'garrett_coordinator.ullbc'
    assert gzip.decompress((tmp_path/'compiler.ullbc.gz').read_bytes()) == raw
    assert not (tmp_path/'garrett_coordinator.ullbc').exists()


def test_capture_rejects_unknown_output_name_before_start(tmp_path):
    before = set(tmp_path.iterdir())
    with pytest.raises(LedgerError, match='unknown compiler artifact'):
        capture_process([], tmp_path, tmp_path, artifact='../outside.ullbc')
    assert set(tmp_path.iterdir()) == before
