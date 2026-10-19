"""Independent, finite W6 read-release oracle for local native-process tests.

This deliberately does not call the Rust disclosure implementation, generated
Lean model, or Python broker projection. It interprets only the host-owned
manifest disclosure grammar exercised by the read profile. This is an oracle
for *particular* observed executions, not a source-to-Lean refinement proof.
"""
from __future__ import annotations

from typing import Any

from aivm_secrets.primitives import codec


class ReleaseMismatch(AssertionError):
    """A provider response cannot be released under the declared policy."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ReleaseMismatch(reason)


def at(value: Any, pointer: list[str]) -> Any:
    """Resolve a reviewed object path; array selection is expressed by items."""
    require(type(pointer) is list and all(type(p) is str for p in pointer),
            'invalid host-selected field pointer')
    for key in pointer:
        require(type(value) is dict and key in value, 'missing selected field')
        value = value[key]
    return value


def project(node: dict[str, Any], provider: Any, *, depth: int = 0) -> Any:
    """Select only explicit typed fields, without raw JSON fallback."""
    require(depth <= 8 and type(node) is dict, 'invalid projection depth/schema')
    value = at(provider, node['at'])
    kind = node['type']
    if kind == 'integer':
        require(type(value) is int and -(2**63) <= value < 2**63,
                'selected value is not a signed 64-bit integer')
        return value
    if kind == 'boolean':
        require(type(value) is bool, 'selected value is not boolean')
        return value
    if kind == 'text':
        require(type(value) is str, 'selected value is not text')
        return value
    if kind == 'null':
        require(value is None, 'selected value is not null')
        return None
    if kind == 'object':
        require(type(value) is dict and type(node.get('fields')) is dict,
                'selected value is not an object')
        return fields(node['fields'], value, depth=depth + 1)
    if kind == 'array':
        limit = node.get('max_items')
        require(type(value) is list and type(limit) is int and
                1 <= limit <= 1000 and len(value) <= limit,
                'selected array exceeds reviewed shape/length')
        return [project(node['items'], row, depth=depth + 1) for row in value]
    raise ReleaseMismatch('unreviewed projection type')


def fields(rules: dict[str, Any], value: Any, *, depth: int = 0) -> dict[str, Any]:
    require(type(rules) is dict and 0 < len(rules) <= 32,
            'empty/oversized host disclosure')
    result = {}
    for field, node in rules.items():
        require(type(field) is str and field and len(field) <= 32 and
                field[0].islower() and field[0].isascii() and
                all(c.isascii() and (c.isalnum() or c == '_') for c in field),
                'invalid public field name')
        result[field] = project(node, value, depth=depth)
    return result


def release(
    policy: dict[str, Any], disclosure: dict[str, Any], operation: str,
    normalized_args: dict[str, Any], provider_response: Any, *, credential: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Calculate the permitted (result, meta) directly from host inputs.

    The provider value must be the independently controlled fixture response,
    not something reconstructed from the guest's observed JSON. Pagination is
    computed on the *raw* provider value, before projection, as in the native
    contract. A reflection veto is expected to become a fixed public denial.
    """
    operations = [op for op in policy['operations'] if op['name'] == operation]
    require(len(operations) == 1, 'operation absent/ambiguous in host policy')
    require(operation in disclosure, 'no host-owned disclosure for operation')
    selected = fields(disclosure[operation], provider_response)
    # The native profile additionally validates decoded JSON text and exact
    # canonical output bytes, so these checks are necessary, not sufficient.
    require(credential.encode() not in codec.dumps(selected),
            'credential reflected in selected fields')
    require(len(codec.dumps(selected)) <= 2 * 1024 * 1024 - 4096,
            'selected output too large')
    page = operations[0].get('page')
    if page is None:
        return selected, None
    require(type(page) is dict, 'invalid pagination declaration')
    rows = at(provider_response, page['at'])
    count = page['size']
    require(type(rows) is list and type(count) is int and 1 <= count <= 1000 and
            len(rows) <= count, 'invalid pagination source')
    pagination = {'per_page': count, 'possibly_more': len(rows) == count}
    if page.get('parameter') is not None:
        name = page['parameter']
        require(name in normalized_args, 'missing normalized page argument')
        pagination['page'] = normalized_args[name]
    return selected, {'pagination': pagination}
