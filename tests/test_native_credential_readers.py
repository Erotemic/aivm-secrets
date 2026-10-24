"""Pin every place native code reads the provider credential's bytes.

`custody::Credential` keeps its bytes behind a private field, so the
compiler forces every reader through `Credential::expose()`, and
`static_assertions` rejects any `Debug`, `Display`, `Clone`, `Copy`,
`Deref`, `AsRef` or `Serialize` implementation. This test lists the
callers. Adding a reader means changing this list and the
`NATIVE-SINK-01` ledger entry together, on purpose.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / 'rust/crates/aivm-secrets-garrett/src'

# (file, enclosing function) -> why it reads the bytes
EXPECTED = {
    ('custody.rs', 'seal'): 'encrypt into the host-only inner envelope',
    ('custody.rs', 'provider_request_bytes'): 'account-status request, extracted http_wire encoder',
    ('custody.rs', 'exchange'): 'account-status provider writer',
    ('custody.rs', 'open'): 'compare against the OAuth session marker',
    ('custody.rs', 'fixture_envelope'): 'conformance feature only: Python parity export',
    ('custody/manifest_session.rs', 'request'): 'extracted send, reflection and disclosure checks',
    ('custody/manifest_session.rs', 'manifest_request_bytes'): 'cfg(test) byte oracle',
}
FN = re.compile(r'^\s*(?:pub(?:\([a-z]+\))?\s+)?fn\s+([a-z_][a-z0-9_]*)')


def readers() -> dict[tuple[str, str], int]:
    found: dict[tuple[str, str], int] = {}
    for path in sorted(SRC.rglob('*.rs')):
        current = ''
        for line in path.read_text().splitlines():
            match = FN.match(line)
            if match:
                current = match.group(1)
            for _ in re.finditer(r'\.expose\(\)', line):
                key = (str(path.relative_to(SRC)), current)
                found[key] = found.get(key, 0) + 1
    return found


def test_credential_readers_are_exactly_the_reviewed_ones():
    assert set(readers()) == set(EXPECTED)


def test_the_credential_type_is_sealed_at_compile_time():
    custody = (SRC / 'custody.rs').read_text()
    assert 'pub(super) struct Credential(Zeroizing<Vec<u8>>);' in custody
    assert 'static_assertions::assert_not_impl_any!(' in custody
    for name in ('Debug', 'Display', 'Clone', 'Copy', 'Deref', 'AsRef<[u8]>', 'Serialize'):
        assert name in custody.split('assert_not_impl_any!(', 1)[1].split(');', 1)[0]
    # Nothing outside the `secret` module may construct the tuple directly.
    assert custody.count('Credential(Zeroizing::new(') == 1
