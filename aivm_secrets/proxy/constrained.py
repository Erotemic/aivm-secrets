"""Profile ``constrained-http``: ordinary HTTPS requests as named operations.

The proxy holds no credential in this profile. A guest request is accepted
only if it is *exactly* what the host would itself send for some named
operation of the broker's schema-2 HTTPS policy with some arguments:

1. candidate arguments are read off the request against each operation's
   method, path template and query template (``candidates``);
2. the host's own encoder (``HTTPOperation.normalize`` then ``effect``)
   is run on those arguments, and the request is accepted only when the
   method, the request target and, for a body, the JSON object it carries are
   equal to what the guest sent (``translate``);
3. the accepted ``(operation, arguments)`` goes to the in-process
   :class:`~aivm_secrets.host.broker.Broker` as an ordinary request frame,
   which re-checks scope, builds and sends the provider request itself and
   returns only the operation's disclosure.

Step 2 makes the matcher's correctness irrelevant to authority: any
mistranslation fails the equality and is refused. Nothing falls back to
credential substitution; an unmatched request is ``unsupported_request``.
"""

from __future__ import annotations

from typing import Any

from ..errors import SecretsError
from ..kernel import codec
from ..kernel.https import HTTPOperation, HTTPSpec, _placeholder
from ..kernel.model import Request
from ..kernel.scope import IntRange, IntSet, StrSet
from . import http1
from .http1 import Refused

MAX_SEGMENTS = 64


def _value(spec: Any, text: str) -> Any:
    """The typed argument a path or query text denotes, or ``None``."""
    if isinstance(spec, (IntSet, IntRange)):
        if not text.isdigit() or text != str(int(text)):
            return None
        return int(text)
    if isinstance(spec, StrSet):
        return text
    return None


def _match_path(template: tuple[str, ...], segments: list[str],
                specs: dict[str, Any], bound: dict[str, Any]) -> list[dict[str, Any]]:
    """All bindings of ``template`` to ``segments``; strings may span segments."""
    if not template:
        return [dict(bound)] if not segments else []
    head, rest = template[0], template[1:]
    name = _placeholder(head)
    if name is None:
        if segments and segments[0] == head:
            return _match_path(rest, segments[1:], specs, bound)
        return []
    found = []
    spec = specs.get(name)
    widths = range(1, len(segments) + 1) if isinstance(spec, StrSet) else range(1, 2)
    for width in widths:
        if width > len(segments):
            break
        value = _value(spec, '/'.join(segments[:width]))
        if value is None or (name in bound and bound[name] != value):
            continue
        found += _match_path(rest, segments[width:], specs, {**bound, name: value})
    return found


def _query(target: str) -> list[tuple[str, str]] | None:
    if '?' not in target:
        return []
    text = target.split('?', 1)[1]
    pairs = []
    for item in text.split('&'):
        key, equals, value = item.partition('=')
        if not equals or not key:
            return None
        pairs.append((key, value))
    return pairs


def candidates(operation: HTTPOperation, method: str, target: str) -> list[dict[str, Any]]:
    """Argument sets under which ``operation`` might produce this request."""
    if (operation.returns_check or operation.requires or operation.graphql_document
            or operation.method != method):
        return []
    path = target.split('?', 1)[0]
    segments = path[1:].split('/')
    if len(segments) > MAX_SEGMENTS:
        return []
    specs = dict(operation.parameters)
    query = _query(target)
    if query is None or len(query) != len(operation.query):
        return []
    given = dict(query)
    if len(given) != len(query):
        return []
    results = []
    for bound in _match_path(operation.template, segments, specs, {}):
        ok = True
        for key, item in operation.query:
            if key not in given:
                ok = False
                break
            name = _placeholder(item)
            if name is None:
                ok = given[key] == item
            else:
                value = _value(specs.get(name), given[key])
                ok = value is not None and bound.get(name, value) == value
                bound[name] = value
            if not ok:
                break
        if ok:
            results.append(bound)
    return results


def _body_arguments(operation: HTTPOperation, body: bytes) -> dict[str, Any] | None:
    if not operation.body_fields:
        return {} if not body else None
    try:
        value = codec.loads(body)
    except SecretsError:
        return None
    if type(value) is not dict or any(type(v) is not str for v in value.values()):
        return None
    return value


def translate(spec: HTTPSpec, request: http1.Request) -> Request:
    """The one named request this HTTP request is exactly, or a refusal."""
    method = request.method.decode('ascii')
    target = request.target.decode('ascii')
    path = target.split('?', 1)[0]
    pairs = _query(target)
    if pairs is None or len({key for key, _ in pairs}) != len(pairs):
        raise Refused('unsupported_request')
    query = sorted(pairs)
    accepted: list[Request] = []
    for operation in spec.operations:
        body = _body_arguments(operation, request.body)
        if body is None:
            continue
        for bound in candidates(operation, method, target):
            if set(bound) & set(body):
                continue
            try:
                named = spec.parse_request({'operation': operation.name,
                                            'arguments': {**bound, **body}})
                normalized = operation.normalize(named)
                effect = operation.effect(normalized, {})
            except (SecretsError, KeyError, TypeError, ValueError):
                continue
            sent_body = dict(effect.body) if effect.body is not None else {}
            # Query order is not significant: the host sends its own order.
            if (effect.method == method and effect.path == path
                    and sorted(effect.query) == query and sent_body == body):
                accepted.append(named)
    unique = {(item.operation, item.arguments) for item in accepted}
    if len(unique) != 1:
        # None: unsupported. Several: ambiguous. Both are refused.
        raise Refused('unsupported_request')
    return accepted[0]
