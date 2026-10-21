"""W6 scoped adapter contract, including deliberate source bypass mutations."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from dev.verification.w6_adapter import CONTRACT, SOURCE, TESTS, CORE_ENCODER, CORE_DISPATCH, CORE_REQUEST, CORE_CURRENT, CORE_CONTEXT, CORE_IO, COMMON_ENCODER, ContractError, check

ROOT = Path(__file__).resolve().parents[1]


def fixture_checkout(tmp_path):
    dst = tmp_path / 'checkout'
    contract = json.loads((ROOT / CONTRACT).read_text())
    names = {CONTRACT, SOURCE, TESTS, CORE_ENCODER, CORE_DISPATCH, CORE_REQUEST, CORE_CURRENT, CORE_CONTEXT, CORE_IO, COMMON_ENCODER,
             'docs/planning/aivm-secrets-w0-boundaries.json',
             'docs/planning/aivm-secrets-assumptions.json'}
    names.update(channel['path'] for channel in contract['channels'])
    names.update(channel.get('evidence_path', TESTS) for channel in contract['channels'])
    for name in names:
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return dst


def test_w6_all_sinks_classified_and_open_premises_named():
    result = check(ROOT)
    assert result['channels'] == 14
    assert result['remaining'] >= 5
    assert 'review guard only' in result['status']


def test_w6_drop_any_channel_is_rejected(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / CONTRACT
    body = json.loads(path.read_text())
    body['channels'] = body['channels'][:-1]
    path.write_text(json.dumps(body))
    with pytest.raises(ContractError, match='sink unclassified'):
        check(checkout)


def test_w6_moving_wire_validation_after_connect_is_rejected(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / SOURCE
    body = path.read_text()
    line = '        let bytes = manifest_request_bytes(route, self.secret, &self.effect, &self.headers)?;\n'
    assert line in body
    body = body.replace(line, '', 1)
    marker = '        let stream = StreamOwned::new(conn, socket);\n'
    assert marker in body
    body = body.replace(marker, marker + line, 1)
    path.write_text(body)
    with pytest.raises(ContractError, match='TCP effect before'):
        check(checkout)


def test_w6_deleted_credential_header_validation_is_rejected(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / CORE_ENCODER
    body = path.read_text()
    assert '!http_auth::valid_credential(secret)' in body
    body = body.replace('!http_auth::valid_credential(secret)',
                        'http_auth::valid_credential(secret)', 1)
    path.write_text(body)
    with pytest.raises(ContractError, match='unvalidated OAuth'):
        check(checkout)


def test_w6_new_provider_send_or_public_raw_return_is_rejected(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / SOURCE
    original = path.read_text()
    marker = '        // Core dispatch owns the composite receipt/current attempt gate.\n        send_manifest_bytes(channel)'
    assert original.count(marker) == 1
    body = original.replace(marker,
                            '        channel.stream.write_all(b"bypass").map_err(|_| Error::UpstreamResponse)?;\n' + marker, 1)
    path.write_text(body)
    with pytest.raises(ContractError, match='another provider send'):
        check(checkout)
    body = original.replace('let result = session\n                    .disclosure\n                    .project(&op.name, &raw, &selection_secret.0)?;',
                                    'let result = raw.clone();', 1)
    path.write_text(body)
    with pytest.raises(ContractError, match='raw provider body'):
        check(checkout)


def test_w6_request_line_bypass_is_rejected(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / CORE_ENCODER
    original = path.read_text()
    assert original.count('http_request::append_line(') == 1
    path.write_text(original.replace('http_request::append_line(', 'unchecked_line(', 1))
    with pytest.raises(ContractError, match='origin-form'):
        check(checkout)


def test_w6_204_cannot_wait_for_transport_eof(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / SOURCE
    original = path.read_text()
    marker = '        (None, None) if status == 204 => {\n'
    assert original.count(marker) == 1
    path.write_text(original.replace(
        marker, marker + '            reader.take(1).read_to_end(&mut body)?;\n', 1))
    with pytest.raises(ContractError, match='waits for EOF after 204'):
        check(checkout)



def test_w6_completion_audit_is_required_before_native_public_success(tmp_path):
    checkout = fixture_checkout(tmp_path)
    path = checkout / SOURCE
    original = path.read_text()
    controller = checkout / CORE_REQUEST
    core_original = controller.read_text()
    marker = 'completion::complete('
    assert marker in core_original
    controller.write_text(core_original.replace(marker, 'unchecked_release(', 1))
    with pytest.raises(ContractError, match='completion audit'):
        check(checkout)
    controller.write_text(core_original)
    path.write_text(original.replace(
        '        self.audit.write_record(&json!({\n            "schema":1,\n            "event":"completed",',
        '        unchecked_record(&json!({\n            "schema":1,\n            "event":"completed",', 1))
    with pytest.raises(ContractError, match='completion audit'):
        check(checkout)
