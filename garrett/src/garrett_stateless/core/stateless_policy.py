"""Static operation policies (Rust ``stateless_policy``; spec section 11.1).

Part of the Python reference: tested against the same vectors as the Rust
crate, not proved. No I/O, clock or randomness."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .proxy_http import Request, method_ok, path_matches
from .stateless import SurrogateClaims


@dataclass(frozen=True)
class Operation:
    """What a policy sees of a request: never its credential-bearing fields."""
    method: bytes
    path: bytes
    body: int


def operation_of(request: Request) -> Operation:
    return Operation(request.method, request.target.split(b'?', 1)[0], len(request.body))


class OperationPolicy(Protocol):
    def permits(self, claims: SurrogateClaims, operation: Operation) -> bool: ...


@dataclass(frozen=True)
class Unrestricted:
    """Garrett's proxy: every operation is authorized by the surrogate alone."""

    def permits(self, claims: SurrogateClaims, operation: Operation) -> bool:
        return True


@dataclass(frozen=True)
class Resource:
    provider: str
    method: str  # '' for GET or HEAD
    path: str


@dataclass(frozen=True)
class ReadOnly:
    """The constrained read-only proxy: ``GET`` or ``HEAD`` without a body,
    on an allowed provider and path."""
    resources: tuple[Resource, ...]

    def permits(self, claims: SurrogateClaims, operation: Operation) -> bool:
        if operation.method not in (b'GET', b'HEAD') or operation.body != 0:
            return False
        return any(r.provider == claims.provider and method_ok(r.method.encode(), operation.method)
                   and path_matches(r.path.encode(), operation.path) for r in self.resources)


