"""Compiler-ledger omissions must remain visible instead of proving reachability."""
from copy import deepcopy

import pytest

from dev.verification.native_calls import VERSION, inventory


def fixture():
    span = {'Untagged': {'data': {'file_id': 0, 'beg': {'line': 1, 'col': 0},
                                'end': {'line': 1, 'col': 8}}}}

    def function(fid, names, terminators, owner='aivm_secrets_garrett'):
        return dict(def_id=fid, item_meta=dict(
            name=[{'Ident': [s, 0]} for s in [owner, *names]],
            span=deepcopy(span), has_errors=False), body={'Unstructured': {
                'body': [dict(terminator=dict(span=deepcopy(span), kind=t))
                         for t in terminators]}})

    def call(kind):
        return {'Call': dict(call=dict(func={'Regular': dict(kind=kind)}),
                             on_unwind=3)}

    return dict(charon_version=VERSION, has_errors=False, translated=dict(
        crate_name='aivm_secrets_garrett', options=dict(ullbc=True),
        files=[dict(id=0, name={'Local': 'test.rs'})], fun_decls=[
            function(0, ['tls', 'answer'], [call({'Fun': 1})]),
            function(1, ['helper'], [call({'Fun': 4}), call({'Trait': [None, 0]}),
                                    {'Drop': {}}, 'UnwindResume']),
            # A callback can be missing from the direct traversal. Keep its sink.
            function(2, ['callback'], [call({'Fun': 3})]),
            dict(def_id=3, item_meta=dict(name=[{'Ident': ['std', 0]},
                                              {'Ident': ['net', 0]}]), body='Opaque'),
            function(4, ['protocol', 'perform'], [call({'Trait': [None, 1]})],
                     owner='aivm_secrets_garrett_core'),
        ]))


def test_callbacks_drops_and_dependencies_remain_open():
    result = inventory(fixture())
    assert result['root'] == dict(id=0, direct_reachable=[0, 1, 4], incomplete=True)
    assert result['counts']['call_kinds'] == {
        'owned-direct': 2, 'unresolved-trait': 2, 'dependency-boundary': 1}
    assert result['counts']['drops'] == 1
    assert result['dependency_targets'][0]['id'] == 3
    assert result['functions'][2]['calls'][0]['destination'] == 3


@pytest.mark.parametrize('mutation', ['errors', 'schema', 'body', 'missing', 'terminator', 'operand'])
def test_unreviewed_or_incomplete_extraction_is_refused(mutation):
    data = fixture()
    functions = data['translated']['fun_decls']
    if mutation == 'errors':
        data['has_errors'] = True
    elif mutation == 'schema':
        data['charon_version'] = 'future'
    elif mutation == 'body':
        functions[1]['body'] = 'Opaque'
    elif mutation == 'missing':
        functions[0]['body']['Unstructured']['body'][0]['terminator']['kind']['Call'][
            'call']['func']['Regular']['kind'] = {'Fun': 999}
    elif mutation == 'terminator':
        functions[1]['body']['Unstructured']['body'][0]['terminator']['kind'] = 'CoroutineResume'
    else:
        functions[0]['body']['Unstructured']['body'][0]['terminator']['kind']['Call'][
            'call']['func'] = {'Unknown': 0}
    with pytest.raises(ValueError):
        inventory(data)


def test_interned_call_span_is_resolved_to_source():
    data = fixture()
    blocks = data['translated']['fun_decls'][1]['body']['Unstructured']['body']
    payload = dict(data=dict(file_id=0, beg=dict(line=9, col=1), end=dict(line=9, col=5)))
    blocks[0]['terminator']['span'] = {'Value': [7, payload]}
    blocks[1]['terminator']['span'] = {'Deduplicated': 7}
    result = inventory(data)
    assert result['functions'][1]['calls'][1]['source']['begin']['line'] == 9


def test_function_pointer_is_an_unresolved_edge():
    data = fixture()
    data['translated']['fun_decls'][0]['body']['Unstructured']['body'][0][
        'terminator']['kind']['Call']['call']['func'] = {'Move': {'Local': 2}}
    result = inventory(data)
    assert result['root']['direct_reachable'] == [0]
    assert result['counts']['call_kinds']['unresolved-function-pointer'] == 1


def test_promoted_constant_does_not_become_an_extra_request_root():
    data = fixture()
    promoted = deepcopy(data['translated']['fun_decls'][0])
    promoted['def_id'] = 6
    promoted['item_meta']['name'].append({'Builtin': ['PromotedConst', 0]})
    data['translated']['fun_decls'].append(promoted)
    assert inventory(data)['root']['id'] == 0


def test_non_span_value_variant_is_not_treated_as_an_interned_span():
    data = fixture()
    data['translated']['runtime_values'] = [{'Value': [{'Integer': 1}]}]
    assert inventory(data)['root']['id'] == 0
