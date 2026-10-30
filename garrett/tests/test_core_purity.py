"""``garrett_stateless.core`` is the protocol alone: it imports only the
standard library's pure modules and itself, never the application around it,
a cryptography library, the clock, randomness, files or sockets. The Rust
crate it mirrors, ``garrett-stateless-core``, has no dependencies at all."""
from __future__ import annotations

import ast
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'src' / 'garrett_stateless' / 'core'
PURE = {'__future__', 'base64', 'binascii', 'dataclasses', 'enum', 'json', 'typing', 'urllib.parse'}
# The modules mirroring the Rust crate's modules. Python keeps each as one
# file where Rust splits it into files: ``proxy_http`` is Rust's
# ``proxy_http/{request,upstream,response,refusal}.rs`` plus its small leaves
# (``http_auth``, ``http_wire``, ``proxy_connect``, ``reflection``);
# ``encoding`` is ``stateless_token/{base64,grammar,json}.rs`` and
# ``stateless_token`` the rest of ``stateless_token/``.
MODULES = {'__init__', 'encoding', 'proxy_http', 'stateless', 'stateless_login', 'stateless_mailbox',
           'stateless_policy', 'stateless_proxy', 'stateless_token'}


def imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add('.' * node.level + (node.module or ''))
    return found


def test_core_imports_only_pure_modules():
    assert {p.stem for p in CORE.glob('*.py')} == MODULES
    for path in CORE.glob('*.py'):
        outside = {name for name in imports(path) if not name.startswith('.') and name not in PURE}
        assert not outside, (path.name, outside)
        # Relative imports stay inside the core package.
        assert all(not name.startswith('..') for name in imports(path)), path.name


def test_rust_core_has_no_dependencies():
    manifest = tomllib.loads((ROOT / 'crates' / 'garrett-stateless-core' / 'Cargo.toml').read_text())
    assert not manifest.get('dependencies')
