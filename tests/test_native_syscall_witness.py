"""Portable checks of the strace parser behind dev/native_syscall_witness.py."""

from __future__ import annotations

from dev import native_syscall_witness as witness


def hexed(data: bytes) -> str:
    return ''.join(f'\\x{b:02x}' for b in data)


def test_a_credential_in_any_written_buffer_is_found():
    token = 'github_pat_SYNTHETIC_0123'
    trace = '\n'.join([
        f'1234  write(5, "{hexed(b"audit record")}", 12) = 12',
        f'1235  writev(7, [{{iov_base="{hexed(b"Authorization: Bearer ")}", iov_len=22}}, '
        f'{{iov_base="{hexed(token.encode())}", iov_len={len(token)}}}], 2) = 47',
        f'[pid  1236] sendto(9, "{hexed(b"x")}", 1, 0, NULL, 0) = 1',
    ])
    parsed = witness.parse(trace)
    assert [name for name, _ in parsed['buffers']] == ['write', 'writev', 'sendto']
    hits = {name for name, data in parsed['buffers']
            for pattern in witness.patterns(token) if pattern in data}
    assert hits == {'writev'}


def test_base64_forms_count_as_the_credential():
    import base64
    token = 'synthetic-token-value-xyz'
    data = base64.b64encode(token.encode())
    parsed = witness.parse(f'1  write(3, "{hexed(data)}", {len(data)}) = {len(data)}')
    assert any(p in parsed['buffers'][0][1] for p in witness.patterns(token))


def test_connect_destinations_are_parsed_for_ipv4_and_ipv6_only():
    trace = '\n'.join([
        '1  connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.112.6")}, 16) = 0',
        '1  connect(6, {sa_family=AF_INET6, sin6_port=htons(8443), sin6_flowinfo=htonl(0), '
        'inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0',
        '1  connect(7, {sa_family=AF_UNIX, sun_path="/tmp/x.sock"}, 110) = 0',
    ])
    parsed = witness.parse(trace)
    assert witness.inet_destinations(parsed['connects']) == [('140.82.112.6', 443), ('::1', 8443)]


def test_escapes_decode_exactly():
    assert witness.decode(r'\x41\n\t\"\\\101z') == b'A\n\t"\\Az'


def test_an_unparseable_inet_connect_is_reported_not_ignored():
    parsed = witness.parse('1  connect(5, {sa_family=AF_INET, garbage}, 16) = 0')
    assert witness.inet_destinations(parsed['connects']) == [('unparsed', 0)]
