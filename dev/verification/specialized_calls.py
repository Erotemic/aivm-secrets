#!/usr/bin/env python3
"""Check compiler-specialized callback links, keeping I/O obligations explicit.

No mediation, dominance, data-flow or confidentiality theorem is claimed.
The selected compiled bridge/authority profile is inspected without executing it.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import asdict, dataclass
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
OPAQUE = ['std', 'core', 'alloc', 'rustls', 'ring', 'serde', 'serde_json',
          'x509_parser', 'rcgen', 'rustix', 'zeroize', 'base64', 'time']
LIMITS = [
    'Call paths show selected compiled bindings, not an executable trace or admission dominance.',
    'Opaque dependencies and their callbacks remain contracts, not traversed implementations.',
    'Implicit drops and unwind effects remain unresolved; counts are static compiler sites.',
    'No credential/data-flow or native byte-trace correspondence is proved.',
    'Named compiled target/profile only; other targets and feature combinations need separate evidence.',
]


class LedgerError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LedgerError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class Limits:
    plain: int = 8 * 1024**3
    compressed: int = 512 * 1024**2
    compiler_seconds: float = 300
    projector_seconds: float = 120

    def __post_init__(self):
        require(self.plain >= 0 and self.compressed >= 0, 'negative output limit')
        require(all(math.isfinite(s) and s >= 0 for s in
                    [self.compiler_seconds, self.projector_seconds]), 'invalid deadline')


class LimitedOutput:
    """Gzip may buffer until close; enforce its cap at every actual file write."""
    def __init__(self, stream, limit):
        self.stream, self.limit, self.written = stream, limit, 0

    def write(self, data):
        if self.written + len(data) > self.limit:
            raise LedgerError('compressed output exceeds limit')
        n = self.stream.write(data)
        self.written += n
        return n

    def flush(self):
        self.stream.flush()

    def tell(self):
        return self.written


def stop_group(process):
    # Each compiler invocation owns its process group; never signal other builds.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    # The leader may have exited while one of its descendants ignored TERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def capture_process(command, cwd, out, limits=Limits(), artifact="garrett_bridge.ullbc"):
    """Stream only this fresh directory's compiler FIFO into a bounded gzip."""
    require(artifact in {'garrett_bridge.ullbc', 'garrett_coordinator.ullbc'}, 'unknown compiler artifact')
    fifo = out / artifact
    os.mkfifo(fifo, 0o600)
    state = dict(schema=1, status='running', command=command, artifact=artifact, limits=asdict(limits),
                 plain_bytes=0, error=None)
    digest = hashlib.sha256()
    cancel = threading.Event()
    started = time.monotonic()
    print('+ ' + shlex.join(command), flush=True)
    with (out / 'compiler.log').open('w') as log:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        except OSError as error:
            state.update(status='failed', error=str(error))
            fifo.unlink(missing_ok=True)
            (out/'capture.json').write_text(json.dumps(state, indent=2)+'\n')
            raise LedgerError('compiler process could not start') from error

        def consume():
            fd = None
            seen = False
            try:
                fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                with (out / 'compiler.ullbc.gz').open('wb') as target:
                    bounded = LimitedOutput(target, limits.compressed)
                    with gzip.GzipFile(fileobj=bounded, mode='wb', compresslevel=1, mtime=0) as zipped:
                        while not cancel.is_set():
                            try:
                                chunk = os.read(fd, 65536)
                            except BlockingIOError:
                                chunk = None
                            if chunk:
                                seen = True
                                state['plain_bytes'] += len(chunk)
                                if state['plain_bytes'] > limits.plain:
                                    raise LedgerError('uncompressed output exceeds limit')
                                zipped.write(chunk)
                                digest.update(chunk)
                            elif chunk == b'' and (seen or process.poll() is not None):
                                break
                            else:
                                time.sleep(.01)
            except BaseException as error:
                state['error'] = str(error)
            finally:
                if fd is not None:
                    os.close(fd)

        worker = threading.Thread(target=consume, daemon=True)
        worker.start()
        try:
            while process.poll() is None:
                if state['error'] or time.monotonic() - started > limits.compiler_seconds:
                    state['error'] = state['error'] or 'compiler deadline exceeded'
                    stop_group(process)
                    break
                time.sleep(.05)
            worker.join(timeout=5)
            if worker.is_alive():
                state['error'] = state['error'] or 'compiler output reader did not stop'
            state.update(exit_code=process.wait(), seconds=round(time.monotonic()-started, 3),
                         plain_sha256=digest.hexdigest())
            require(not state['error'], state['error'])
            require(state['exit_code'] == 0, 'compiler failed; see compiler.log')
            require(state['plain_bytes'] > 0, 'compiler emitted no bridge artifact')
            state.update(status='captured', compressed_bytes=(out/'compiler.ullbc.gz').stat().st_size,
                         compressed_sha256=sha(out/'compiler.ullbc.gz'))
        except BaseException as error:
            state.update(status='failed', error=str(error))
            raise
        finally:
            cancel.set()
            stop_group(process)
            worker.join(timeout=3)
            fifo.unlink(missing_ok=True)
            (out/'capture.json').write_text(json.dumps(state, indent=2)+'\n')
    return state


def identifiers(function):
    return tuple(p for p in function['item_meta']['name'] if not p.startswith('<'))


def select(nodes, parts):
    def leaf(f):
        name = f['item_meta']['name']
        # Charon appends this to actual monomorphic instances. A promoted
        # constant/closure/drop helper still ends in a distinct Builtin part.
        return name[-2] if len(name) > 1 and name[-1] == '<Instantiated>' else name[-1]
    return {i for i, f in nodes.items()
            if identifiers(f) == parts and leaf(f) == parts[-1]
            and f['body']['kind'] == 'Unstructured' and f['generics']['types'] == 0}


def reachable(nodes, roots):
    visited, pending = set(), list(roots)
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        require(current in nodes, 'call target has no projected declaration')
        visited.add(current)
        pending.extend(nodes[current]['body']['blocks']['direct'])
    return visited


def path_through(nodes, stages):
    """A graph witness only: control-flow feasibility/dominance is not inferred."""
    require(all(stages), 'required concrete callback declaration missing')
    pending = deque((i, 0) for i in sorted(stages[0]))
    parent = {state: None for state in pending}
    while pending:
        state = pending.popleft()
        node, stage = state
        if stage == len(stages)-1:
            result = []
            while state is not None:
                result.append(state[0])
                state = parent[state]
            return list(reversed(result))
        for target in nodes[node]['body']['blocks']['direct']:
            require(target in nodes, 'unknown callback target')
            next_stage = stage+1 if target in stages[stage+1] else stage
            next_state = (target, next_stage)
            if next_state not in parent:
                parent[next_state] = state
                pending.append(next_state)
    raise LedgerError('required compiled callback link missing')


def explain(projection, profile="bridge"):
    require(projection['projection_schema'] == 1, 'wrong projector schema')
    require(projection['charon_version'] == '0.1.291' and projection['has_errors'] is False,
            'unreviewed or incomplete compiler projection')
    require(profile in {'bridge', 'coordinator'}, 'unknown compiled profile')
    crate = 'garrett_bridge' if profile == 'bridge' else 'garrett_coordinator'
    require(projection['translated']['crate_name'] == crate
            and projection['translated']['options']['monomorphize'] is True
            and projection['translated']['options']['ullbc'] is True,
            'projection is not the selected specialized target')
    declarations = [f for f in projection['translated']['fun_decls'] if f]
    nodes = {f['def_id']: f for f in declarations}
    require(len(nodes) == len(declarations), 'duplicate projected function ID')
    root_name = (('aivm_secrets_garrett', 'tls', 'answer') if profile == 'bridge' else
        ('aivm_secrets_garrett', 'coordinator_authority', 'server', 'exchange'))
    root = select(nodes, root_name)
    witnesses = {}
    required_paths = [
        ('account-controller-executor', [
            ('aivm_secrets_garrett_core','protocol','perform'),
            ('aivm_secrets_garrett','custody','execute'),
            ('aivm_secrets_garrett','custody','exchange')]),
        ('coordinated-manifest-executor', [
            ('aivm_secrets_garrett_core','coordination','dispatch'),
            ('aivm_secrets_garrett','custody','manifest_session','exchange_manifest')]),
        ('account-authentication-bytes', [
            ('aivm_secrets_garrett','custody','exchange'),
            ('aivm_secrets_garrett','custody','account_request_bytes'),
            ('aivm_secrets_garrett','custody','provider_request_bytes'),
            ('aivm_secrets_garrett_core','http_wire','append_request'),
            ('aivm_secrets_garrett_core','http_auth','append_header'),
            ('aivm_secrets_garrett_core','http_auth','valid_credential')]),
        ('manifest-authentication-bytes', [
            ('aivm_secrets_garrett','custody','manifest_session','exchange_manifest'),
            ('aivm_secrets_garrett','custody','manifest_session','manifest_request_bytes'),
            ('aivm_secrets_garrett','custody','provider_request_bytes'),
            ('aivm_secrets_garrett_core','http_wire','append_request'),
            ('aivm_secrets_garrett_core','http_auth','append_header'),
            ('aivm_secrets_garrett_core','http_auth','valid_credential')]),
        ('account-request-line', [
            ('aivm_secrets_garrett','custody','exchange'),
            ('aivm_secrets_garrett','custody','account_request_bytes'),
            ('aivm_secrets_garrett','custody','provider_request_bytes'),
            ('aivm_secrets_garrett_core','http_wire','append_request'),
            ('aivm_secrets_garrett_core','http_request','append_line'),
            ('aivm_secrets_garrett_core','http_request','valid_target')]),
        ('manifest-request-line', [
            ('aivm_secrets_garrett','custody','manifest_session','exchange_manifest'),
            ('aivm_secrets_garrett','custody','manifest_session','manifest_request_bytes'),
            ('aivm_secrets_garrett','custody','provider_request_bytes'),
            ('aivm_secrets_garrett_core','http_wire','append_request'),
            ('aivm_secrets_garrett_core','http_request','append_line'),
            ('aivm_secrets_garrett_core','http_request','valid_target')]),
        *[(label + '-complete-header-admission', [
            ('aivm_secrets_garrett','custody', 'exchange') if label == 'account' else
                ('aivm_secrets_garrett','custody','manifest_session','exchange_manifest'),
            ('aivm_secrets_garrett','custody','provider_request_bytes'),
            ('aivm_secrets_garrett_core','http_wire','append_request'),
            *[('aivm_secrets_garrett_core','http_wire', name) for name in
              ['valid_headers','valid_header','valid_name','reserved_name','ascii_equal']]])
          for label in ['account','manifest']],
    ]
    if profile == 'coordinator':
        handler = ('aivm_secrets_garrett', 'coordinator_authority', 'ledger', 'handle')
        core = ('aivm_secrets_garrett_core', 'coordinator_authority')
        required_paths = [
            ('coordinator-operator-admission', [handler, (*core, 'require_operator_for'), (*core, 'require_operator'), (*core, 'contains_peer')]),
            ('coordinator-member-admission', [handler, (*core, 'authorize'), (*core, 'admit'), (*core, 'contains_peer')]),
            *[('coordinator-' + name, [handler, (*core, name)])
              for name in ['activate', 'revoke', 'reserve', 'finish']],
        ]
    for label, names in required_paths:
        witnesses[label] = path_through(nodes, [root, *(select(nodes, n) for n in names)])
    visited = reachable(nodes, root)
    def open_calls(ids):
        return {i: nodes[i]['body']['blocks']['unresolved'] for i in sorted(ids)
                if nodes[i]['body']['blocks']['unresolved']}
    files = {f['id']: f for f in projection['translated']['files']}
    def describe(i):
        f = nodes[i]
        location = f['item_meta']['span']['Untagged']['data']
        return dict(id=i, name='::'.join(f['item_meta']['name']),
                    source=dict(file=files[location['file_id']]['name'],
                                begin=location['beg'], end=location['end']))
    return dict(schema=1, status='callback-witnesses-present', complete_mediation=False,
                profile=profile, scope='compiled ' + profile + ' handler linkage; not a native trace proof',
                limits=LIMITS, counts=dict(functions=len(nodes),
                    calls=sum(f['body']['blocks']['calls'] for f in declarations),
                    drops=sum(f['body']['blocks']['drops'] for f in declarations),
                    bodies=dict(Counter(f['body']['kind'] for f in declarations))),
                roots=sorted(root), witnesses=witnesses,
                witness_details={k:[describe(i) for i in path] for k,path in witnesses.items()},
                direct_reachable=sorted(visited),
                opaque_boundaries=[i for i in sorted(visited) if nodes[i]['body']['kind']!='Unstructured'],
                unresolved_calls=open_calls(nodes), unresolved_in_root=open_calls(visited))


def rust_inputs(root):
    if __package__:
        from .w3_effect_boundary import rust_sources
    else:
        from w3_effect_boundary import rust_sources
    return rust_sources(root)


def native_inputs(root):
    names = [n for n in rust_inputs(root) if n in {
        'rust/Cargo.toml', 'rust/Cargo.lock', 'rust/rust-toolchain.toml',
    } or n.startswith(('rust/crates/aivm-secrets-garrett/',
                      'rust/crates/aivm-secrets-garrett-core/'))]
    return {n: sha(root/n) for n in sorted(names)}


def project_archive(archive, projector, out, limits=Limits(), profile="bridge"):
    partial = out/'projection.partial.json'
    with partial.open('wb') as output, (out/'projector.log').open('w') as log:
        unzip = subprocess.Popen(['gzip', '-dc', '--', str(archive)], stdout=subprocess.PIPE,
                                 stderr=log)
        process = subprocess.Popen([str(projector),'--max-bytes',str(limits.plain),'--profile',profile],
                                   stdin=unzip.stdout, stdout=output, stderr=log)
        unzip.stdout.close()
        try:
            require(process.wait(timeout=limits.projector_seconds) == 0,
                    'projection failed; see projector.log')
            require(unzip.wait(timeout=5) == 0, 'compressed compiler artifact is corrupt')
        finally:
            for p in [process, unzip]:
                if p.poll() is None:
                    p.kill()
                p.wait()
    require(partial.stat().st_size <= 64*1024**2, 'projection exceeds review size limit')
    projection = json.loads(partial.read_text())
    report = explain(projection, profile)
    partial.replace(out/'projection.json')
    return report


def run(root, charon, limits=Limits(), profile="bridge"):
    (root/'.tools').mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='specialized-calls-', dir=root/'.tools'))
    channel = tomllib.loads((root/'rust/rust-toolchain.toml').read_text())['toolchain']['channel']
    analysis_sources = [Path(__file__), Path(__file__).with_name('w3_effect_boundary.py'),
                        *(root/n for n in sorted(rust_inputs(root))
                          if n in {'rust/Cargo.lock','rust/Cargo.toml','rust/rust-toolchain.toml'}
                          or n.startswith('rust/crates/garrett-call-ledger/'))]
    analysis_before = {str(p): sha(p) for p in analysis_sources}
    compiler_before = {str(p): sha(p) for p in [charon, charon.with_name('charon-driver')]}
    build = ['cargo','+'+channel,'build','--locked','--release','--manifest-path',
             str(root/'rust/Cargo.toml'),'-p','garrett-call-ledger']
    print('+ ' + shlex.join(build), flush=True)
    with (out/'build.log').open('w') as log:
        subprocess.run(build, stdout=log, stderr=subprocess.STDOUT, check=True)
    before = native_inputs(root)
    command = [str(charon),'cargo','--preset=raw-mir','--sysroot','default','--monomorphize',
               '--start-from-if-exists','crate::main','--abort-on-error','--error-on-warnings']
    require(profile in {'bridge', 'coordinator'}, 'unknown compiled profile')
    opaque = OPAQUE + (['rusqlite', 'libsqlite3_sys'] if profile == 'coordinator' else [])
    for name in opaque:
        command += ['--opaque',name]
    binary = 'garrett-bridge' if profile == 'bridge' else 'garrett-coordinator'
    command += ['--dest',str(out),'--','--bin',binary,'--locked']
    if profile == 'coordinator':
        command += ['--features', 'coordinator-server']
    captured = capture_process(command, root/'rust/crates/aivm-secrets-garrett', out, limits,
                               artifact=binary.replace('-', '_') + '.ullbc')
    require(native_inputs(root) == before, 'native Rust input changed during capture')
    projector = root/'rust/target/release/garrett-call-ledger'
    projector_hash = sha(projector)
    report = project_archive(out/'compiler.ullbc.gz', projector, out, limits, profile)
    require(sha(out/'compiler.ullbc.gz') == captured['compressed_sha256'],
            'compiler artifact changed during projection')
    require(native_inputs(root) == before, 'native Rust input changed during projection')
    require({p: sha(Path(p)) for p in compiler_before} == compiler_before,
            'compiler changed during validation')
    require({str(p): sha(p) for p in analysis_sources} == analysis_before,
            'analysis source changed during validation')
    require(sha(projector) == projector_hash, 'projector changed during validation')
    report.update(source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
                  source_dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=root)),
                  native_inputs_sha256=before, capture=captured, projection_sha256=sha(out/'projection.json'),
                  compiler_sha256=compiler_before,
                  projector_sha256=projector_hash, analysis_sources_sha256=analysis_before)
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['counts'],indent=2))
    print('Compiler callback-linkage evidence (not mediation):',out/'report.json')
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--charon',type=Path,default=ROOT/'.tools/aeneas/charon')
    parser.add_argument('--profile', choices=['bridge', 'coordinator'], default='bridge')
    args = parser.parse_args()
    run(args.root.resolve(),args.charon.resolve(),profile=args.profile)


if __name__ == '__main__':
    main()
