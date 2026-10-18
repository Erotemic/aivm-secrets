"""Structural/traceability check of the W0 security specification.

This validates cross references and source file inventory entries. It cannot
establish that all I/O paths are classified, that a release rule is secure, or
that the Rust executable implements the spec. W3/W6 own those obligations.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / 'docs/planning/aivm-secrets-w0-boundaries.json'
LEDGER = ROOT / 'docs/planning/aivm-secrets-assumptions.json'
COLLECTIONS = (
    'profiles', 'protected_data', 'attacker_inputs', 'sinks',
    'release_rules', 'observations', 'obligations',
)
GUEST_VERBS = {'request', 'describe', 'renounce'}
SCOPES = {'primary', 'extension', 'delegated', 'operator_only', 'guest_owned'}
OBS_TREATMENTS = {'included', 'other_principal', 'excluded'}
AUDIENCES = {
    'guest', 'provider_api', 'oauth_token_provider', 'host_audit',
    'host_operator', 'host_private', 'host_legacy_broker', 'trusted_coordinator',
    'authenticated_coordinator_member',
}


def validate(contract: dict[str, Any], ledger: dict[str, Any], root: Path) -> list[str]:
    """List errors in a W0 inventory; intentionally no theorem/content claims.

    Accepts in-memory dictionaries to let tests attack the specification
    itself. In particular, adding a new guest sink without an observation or
    release rule is detected without asserting user-facing documentation text.
    """
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    def index(key: str) -> dict[str, dict[str, Any]]:
        values = contract.get(key)
        if not isinstance(values, list) or not values:
            errors.append(f'{key}: missing or empty collection')
            return {}
        result: dict[str, dict[str, Any]] = {}
        for n, row in enumerate(values):
            if not isinstance(row, dict):
                errors.append(f'{key}[{n}]: not an object')
                continue
            name = row.get('id')
            if not isinstance(name, str) or not name:
                errors.append(f'{key}[{n}]: missing id')
            elif name in result:
                errors.append(f'{key}: duplicate id {name}')
            else:
                result[name] = row
        return result

    def source_paths(row: dict[str, Any], context: str) -> None:
        paths = row.get('source_paths')
        if not isinstance(paths, list) or not paths:
            errors.append(f'{context}: missing source paths')
            return
        for path in paths:
            if not isinstance(path, str) or not path:
                errors.append(f'{context}: invalid source path')
                continue
            full = (root / path).resolve()
            if not full.is_relative_to(root.resolve()) or not full.is_file():
                errors.append(f'{context}: missing/unsafe source path {path}')

    def links(row: dict[str, Any], field: str, allowed: set[str], context: str) -> None:
        values = row.get(field)
        if not isinstance(values, list) or not values:
            errors.append(f'{context}: no {field}')
            return
        if len(values) != len(set(values)):
            errors.append(f'{context}: duplicate {field}')
        for value in values:
            if value not in allowed:
                errors.append(f'{context}: unknown {field} {value}')

    require(contract.get('schema_version') == 1, 'unsupported W0 schema')
    require(isinstance(contract.get('as_of_commit'), str) and len(contract.get('as_of_commit', '')) == 40,
            'source commit must be pinned')
    require(contract.get('review_status') in {'proposed_W0_baseline_not_a_proof', 'maintainer_approved_scope'},
            'unknown review status')
    for name in ('normative_document', 'assumption_ledger'):
        value = contract.get(name)
        require(isinstance(value, str) and (root / value).is_file(),
                f'{name}: missing document')
    indexed = {key: index(key) for key in COLLECTIONS}
    assumption_rows = ledger.get('assumptions', [])
    assumptions = {e.get('id') for e in assumption_rows if isinstance(e, dict)}
    require(len(assumptions) == len(assumption_rows), 'duplicate ledger assumption id')
    rules = indexed['release_rules']
    sinks = indexed['sinks']
    profiles = indexed['profiles']
    require(contract.get('primary_scope') in profiles, 'primary scope has no profile')
    primary = profiles.get(contract.get('primary_scope'), {})
    require(primary.get('scope') == 'primary', 'primary profile must be primary')

    for id, profile in profiles.items():
        context = f'profile {id}'
        require(profile.get('scope') in SCOPES, f'{context}: unknown scope')
        source_paths(profile, context)
        links(profile, 'assumptions', assumptions, context)
        verbs = profile.get('guest_verbs')
        require(isinstance(verbs, list) and len(verbs) == len(set(verbs)) and set(verbs) <= GUEST_VERBS,
                f'{context}: invalid guest verbs')
        if profile.get('scope') == 'operator_only':
            require(not verbs, f'{context}: privileged profile has guest verbs')

    for id, action in indexed['attacker_inputs'].items():
        source_paths(action, f'action {id}')
        require(action.get('scope') in SCOPES, f'action {id}: invalid scope')
        require(action.get('actor') in {'untrusted_guest', 'untrusted_provider_or_environment',
                                      'environment', 'trusted_operator'},
                f'action {id}: invalid actor')

    for id, rule in rules.items():
        context = f'release {id}'
        links(rule, 'sink_ids', set(sinks), context)
        links(rule, 'assumptions', assumptions, context)
        require(bool(rule.get('permitted')) and bool(rule.get('prohibited')),
                f'{context}: missing positive/negative release contract')
        require(rule.get('operator_review_required') is True,
                f'{context}: authorization policy must be reviewed')

    for id, sink in sinks.items():
        context = f'sink {id}'
        require(sink.get('scope') in SCOPES, f'{context}: invalid scope')
        require(sink.get('audience') in AUDIENCES,
                f'{context}: unclassified audience')
        source_paths(sink, context)
        links(sink, 'release_rules', set(rules), context)
        links(sink, 'assumptions', assumptions, context)
        for rule_id in sink.get('release_rules', []):
            if rule_id in rules and id not in rules[rule_id].get('sink_ids', []):
                errors.append(f'{context}: asymmetric link to {rule_id}')
    for id, rule in rules.items():
        for sink_id in rule.get('sink_ids', []):
            if sink_id in sinks and id not in sinks[sink_id].get('release_rules', []):
                errors.append(f'release {id}: asymmetric sink {sink_id}')

    for id, secret in indexed['protected_data'].items():
        context = f'protected class {id}'
        links(secret, 'permitted_release_rule_ids', set(rules), context)
        require(bool(secret.get('description')), f'{context}: no semantics')

    covered: dict[str, set[str]] = {id: set() for id in sinks}
    for id, observation in indexed['observations'].items():
        context = f'observation {id}'
        treatment = observation.get('treatment')
        require(treatment in OBS_TREATMENTS, f'{context}: unknown treatment')
        targets = observation.get('sink_ids')
        require(isinstance(targets, list), f'{context}: invalid sink_ids')
        if not isinstance(targets, list):
            continue
        if treatment == 'excluded':
            require(not targets, f'{context}: excluded observation names emitted sinks')
        else:
            require(bool(targets), f'{context}: observation has no sinks')
        for sink_id in targets:
            if sink_id not in sinks:
                errors.append(f'{context}: unknown sink {sink_id}')
            else:
                covered[sink_id].add(str(treatment))
                audience = sinks[sink_id].get('audience')
                if audience == 'guest':
                    require(treatment == 'included',
                            f'{context}: guest-readable sink marked {treatment}')
                else:
                    require(treatment == 'other_principal',
                            f'{context}: non-guest sink marked {treatment}')
    for id, sink in sinks.items():
        expected = 'included' if sink.get('audience') == 'guest' else 'other_principal'
        require(expected in covered[id], f'sink {id}: no {expected} observation classification')

    for id, obligation in indexed['obligations'].items():
        require(obligation.get('status') in {'open', 'in_progress', 'conditionally_proved', 'proved'},
                f'obligation {id}: unknown status')
        require(bool(obligation.get('summary')), f'obligation {id}: no summary')
    require({'SINK-01', 'TRACE-01', 'NI-TRACE-01', 'IO-REFINE-01', 'LIVE-01'} <= set(indexed['obligations']),
            'required assurance goals are missing')
    return errors


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != 'check':
        print('Usage: python dev/verification/w0_contract.py check', file=sys.stderr)
        return 2
    with SPEC.open(encoding='utf8') as file:
        contract = json.load(file)
    with LEDGER.open(encoding='utf8') as file:
        ledger = json.load(file)
    errors = validate(contract, ledger, ROOT)
    if errors:
        for error in errors:
            print(f'W0: {error}', file=sys.stderr)
        return 1
    print('W0 boundary references valid: '
          f"{len(contract['profiles'])} profiles; {len(contract['sinks'])} sinks; "
          f"{len(contract['release_rules'])} release rules; "
          f"{len(contract['observations'])} observation classes; "
          f"{len(contract['obligations'])} unproved goals inventoried")
    return 0


if __name__ == '__main__':
    sys.exit(main())
