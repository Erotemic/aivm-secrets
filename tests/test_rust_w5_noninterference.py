"""Native Rust W5 information-release mutation tests.

Requires W2 Rust binaries. The fake HTTPS provider is allowed to return
untrusted bytes, including credential reflections, while the test checks the
actual guest frame and reported error. No live GitHub credentials are used.
"""
from __future__ import annotations

import copy
import json

from tests.secrets_github_scenario import PULL, PULL_PATH, install_github_routes
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
from tests.test_rust_w2_github_workflow import (
    arguments, native_disclosure, native_policy,
)


def test_w5_discarded_fields_and_selected_fields_are_distinguished(tmp_path):
    """Reference fixture checks only; no Rust equivalence inferred here."""
    original = copy.deepcopy(PULL)
    discarded = copy.deepcopy(PULL)
    discarded['opaque_unselected'] = {'secret': TOKEN, 'arbitrary': [1, 2, 3]}
    released = copy.deepcopy(PULL)
    released['title'] = 'an approved different title'
    assert original['title'] == discarded['title']
    assert original['head'] == discarded['head']
    assert original['title'] != released['title']
    assert discarded != original


def test_w5_native_ignored_mutation_preserves_guest_reply_and_reflection_denies(tmp_path):
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        original_route = server.routes[('GET', PULL_PATH)]
        with ManifestCase(tmp_path, server, native_policy(tmp_path, server), native_disclosure()) as case:
            baseline = case.invoke(operation='pr.view', arguments=arguments())
            assert baseline['ok'] is True, baseline

            def with_discarded_secret(seen):
                status, headers, raw = original_route(seen)
                if seen['headers'].get('accept') == 'application/vnd.github+json':
                    payload = json.loads(raw)
                    payload['opaque_unselected'] = {'arbitrary_secret': TOKEN}
                    return status, headers, json.dumps(payload).encode()
                return status, headers, raw

            server.routes[('GET', PULL_PATH)] = with_discarded_secret
            hidden_mutation = case.invoke(operation='pr.view', arguments=arguments())
            assert hidden_mutation == baseline
            assert TOKEN not in json.dumps(hidden_mutation)

            def with_selected_change(seen):
                status, headers, raw = original_route(seen)
                if seen['headers'].get('accept') == 'application/vnd.github+json':
                    payload = json.loads(raw)
                    payload['title'] = 'authorized changed title'
                    return status, headers, json.dumps(payload).encode()
                return status, headers, raw

            server.routes[('GET', PULL_PATH)] = with_selected_change
            allowed_change = case.invoke(operation='pr.view', arguments=arguments())
            assert allowed_change['ok'] is True
            assert allowed_change['result']['title'] == 'authorized changed title'
            assert allowed_change != baseline

            def with_reflected_credential(seen):
                status, headers, raw = original_route(seen)
                if seen['headers'].get('accept') == 'application/vnd.github+json':
                    payload = json.loads(raw)
                    payload['title'] = TOKEN
                    return status, headers, json.dumps(payload).encode()
                return status, headers, raw

            server.routes[('GET', PULL_PATH)] = with_reflected_credential
            reflected = case.invoke(operation='pr.view', arguments=arguments())
            assert reflected['ok'] is False, reflected
            assert TOKEN not in json.dumps(reflected)
            assert reflected != baseline  # observable denial oracle is explicit
