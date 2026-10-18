#!/usr/bin/env python3
"""Extract a compiler-derived native call-site ledger, with open edges explicit.

This is a review aid, NOT a sound whole-program call graph, I/O inventory,
mediation check or Lean proof. In particular, generic callbacks and drops are
not resolved. No application code or feature selection is changed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = '0.1.291'
OWNED = {'aivm_secrets_garrett', 'aivm_secrets_garrett_core'}
OPAQUE = ['std', 'core', 'alloc', 'rustls', 'ring', 'serde', 'serde_json',
          'x509_parser', 'rcgen', 'rustix', 'zeroize', 'base64', 'time']
LIMITS = [
    'Direct edges underapproximate reachability; absence of a path proves nothing.',
    'Trait, closure, function-pointer and generic callback dispatch is unresolved.',
    'Drops and unwind paths are counted, not resolved into destructor calls.',
    'Dependency bodies, including higher-order library calls, are not traversed.',
    'Only the default-feature native library is extracted; binary startup is excluded.',
    'No data-flow, temporal admission, concurrency or concrete I/O refinement is proved.',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def crate(meta):
    return meta['name'][0].get('Ident', [''])[0]


def label(meta):
    # IDs and source coordinates disambiguate impls; do not infer receiver types.
    return '::'.join(part['Ident'][0] if 'Ident' in part else '<impl-or-generated>'
                     for part in meta['name'])


def source_location(span, files, spans):
    if set(span) == {'Untagged'}:
        data = span['Untagged']['data']
    elif set(span) == {'Value'}:
        data = span['Value'][1]['data']
    elif set(span) == {'Deduplicated'}:
        data = spans[span['Deduplicated']]['data']
    else:
        raise ValueError('unsupported source span encoding')
    return dict(file=files[data['file_id']]['name'],
                begin=data['beg'], end=data['end'])


def span_definitions(value, spans):
    # Charon deduplicates spans separately from types and other interned values.
    if isinstance(value, dict):
        if (set(value) == {'Value'} and isinstance(value['Value'], list)
                and len(value['Value']) == 2 and isinstance(value['Value'][0], int)):
            index, payload = value['Value']
            if isinstance(payload, dict) and 'data' in payload and 'file_id' in payload['data']:
                require(index not in spans or spans[index] == payload, 'conflicting span IDs')
                spans[index] = payload
        for child in value.values():
            span_definitions(child, spans)
    elif isinstance(value, list):
        for child in value:
            span_definitions(child, spans)


def inventory(document):
    """Read pinned raw ULLBC structure; unknown executable forms fail closed."""
    require(document['charon_version'] == VERSION, 'unreviewed Charon schema')
    require(document['has_errors'] is False, 'Charon reported extraction errors')
    translated = document['translated']
    require(translated['crate_name'] == 'aivm_secrets_garrett', 'wrong crate')
    require(translated['options']['ullbc'] is True, 'expected raw unstructured MIR')
    files = {f['id']: f for f in translated['files']}
    spans = {}
    span_definitions(translated, spans)
    declarations = {f['def_id']: f for f in translated['fun_decls'] if f}
    functions = []
    for fid, f in declarations.items():
        meta = f['item_meta']
        if crate(meta) not in OWNED:
            continue
        require(not meta['has_errors'], 'owned function has translation errors')
        require(isinstance(f['body'], dict) and set(f['body']) == {'Unstructured'},
                'owned function lacks a translated body: ' + label(meta))
        body = f['body']['Unstructured']['body']
        calls, terminators = [], Counter()
        for block, basic in enumerate(body):
            term = basic['terminator']
            kind = term['kind']
            tag = next(iter(kind)) if isinstance(kind, dict) else kind
            require(tag in {'Call', 'Drop', 'Goto', 'Switch', 'Return',
                            'UnwindTerminate', 'UnwindResume', 'UndefinedBehavior',
                            'Assert'}, 'unreviewed MIR terminator: ' + str(tag))
            terminators[tag] += 1
            if tag != 'Call':
                continue
            call = kind['Call']
            func = call['call']['func']
            edge = dict(block=block, source=source_location(term['span'], files, spans),
                        on_unwind=call['on_unwind'], destination=None)
            if set(func) == {'Regular'}:
                target = func['Regular']['kind']
                if set(target) == {'Fun'}:
                    callee = declarations.get(target['Fun'])
                    require(callee is not None, 'missing function declaration')
                    edge['destination'] = callee['def_id']
                    edge['kind'] = ('owned-direct' if crate(callee['item_meta']) in OWNED
                                    else 'dependency-boundary')
                elif set(target) == {'Trait'}:
                    edge['kind'] = 'unresolved-trait'
                else:
                    raise ValueError('unreviewed regular call kind: ' + str(target))
            elif len(func) == 1 and next(iter(func)) in {'Move', 'Copy'}:
                edge['kind'] = 'unresolved-function-pointer'
            else:
                raise ValueError('unreviewed function operand: ' + str(func))
            calls.append(edge)
        functions.append(dict(id=fid, name=label(meta),
                              source=source_location(meta['span'], files, spans),
                              terminators=dict(terminators), calls=calls))
    nodes = {f['id']: f for f in functions}
    roots = [f['def_id'] for f in declarations.values()
             if [p['Ident'][0] for p in f['item_meta']['name'] if 'Ident' in p]
             == ['aivm_secrets_garrett', 'tls', 'answer']
             and f['item_meta']['name'][-1].get('Ident', [''])[0] == 'answer']
    require(len(roots) == 1, 'expected one native Bridge::answer root')
    reached, pending = set(), list(roots)
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        require(current in nodes, 'owned direct edge lacks a body')
        reached.add(current)
        pending.extend(c['destination'] for c in nodes[current]['calls']
                       if c['kind'] == 'owned-direct')
    # Keep ALL owned call sites, even those outside the incomplete root traversal.
    # A closure invisible to this traversal must not disappear from the ledger.
    destinations = sorted({c['destination'] for f in functions for c in f['calls']
                           if c['kind'] == 'dependency-boundary'})
    return dict(schema=1, scope='candidate direct-call ledger, not mediation evidence',
                limits=LIMITS, charon_version=VERSION,
                counts=dict(owned_functions=len(functions),
                            calls=sum(len(f['calls']) for f in functions),
                            call_kinds=dict(Counter(c['kind'] for f in functions
                                                    for c in f['calls'])),
                            drops=sum(f['terminators'].get('Drop', 0) for f in functions)),
                functions=functions,
                dependency_targets=[dict(id=i, name=label(declarations[i]['item_meta']),
                                         body=next(iter(declarations[i]['body']))
                                         if isinstance(declarations[i]['body'], dict)
                                         else declarations[i]['body']) for i in destinations],
                root=dict(id=roots[0], direct_reachable=sorted(reached),
                          incomplete=True))


def extract(root, charon):
    if __package__:
        from .w3_effect_boundary import rust_sources
    else:
        from w3_effect_boundary import rust_sources

    inputs = {name: sha(root / name) for name in sorted(rust_sources(root))}
    tool_hash = sha(Path(__file__))
    (root / '.tools').mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='native-calls-', dir=root / '.tools'))
    ullbc = out / 'native.ullbc'
    command = [str(charon), 'cargo', '--preset=raw-mir', '--sysroot', 'default',
               '--abort-on-error', '--error-on-warnings']
    for name in OPAQUE:
        command.extend(['--opaque', name])
    command.extend(['--dest-file', str(ullbc), '--', '--lib', '--locked'])
    with (out / 'extraction.log').open('w') as log:
        subprocess.run(command, cwd=root / 'rust/crates/aivm-secrets-garrett',
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    document = json.loads(ullbc.read_text())
    # Local source is embedded; dependency-core source is not. Record that gap.
    embedded, unembedded = [], []
    for source in document['translated']['files']:
        if source['crate_name'] in OWNED:
            require(set(source['name']) == {'Local'}, 'unexpected owned source path')
            path = root / 'rust' / source['name']['Local']
            require(path.resolve().is_relative_to((root / 'rust/crates').resolve()),
                    'owned source escapes crate tree')
            if source['contents'] is None:
                require(source['crate_name'] == 'aivm_secrets_garrett_core',
                        'native source unexpectedly omitted')
                unembedded.append(path.relative_to(root).as_posix())
            else:
                require(path.read_text() == source['contents'], 'stale embedded owned source')
                embedded.append(path.relative_to(root).as_posix())
    result = inventory(document)
    require(inputs == {n: sha(root / n) for n in sorted(rust_sources(root))},
            'Rust inputs changed during extraction')
    require(tool_hash == sha(Path(__file__)), 'ledger tool changed during extraction')
    result.update(source_commit=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
        rust_inputs_sha256=inputs, extraction_sha256=sha(ullbc),
        tool_sha256=tool_hash,
        embedded_source_matches=embedded, dependency_sources_not_embedded=unembedded,
        charon_sha256=sha(charon), driver_sha256=sha(charon.with_name('charon-driver')),
        command=command)
    report = out / 'report.json'
    report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['counts'], indent=2))
    print('Incomplete direct-root traversal:', len(result['root']['direct_reachable']))
    print('Review ledger:', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--charon', type=Path, default=ROOT / '.tools/aeneas/charon')
    args = parser.parse_args()
    extract(args.root.resolve(), args.charon.resolve())


if __name__ == '__main__':
    main()
