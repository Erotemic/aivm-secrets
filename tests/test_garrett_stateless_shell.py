"""The garrett-stateless shell reaches credentials and providers only through the extracted core."""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / 'dev/verification/stateless_shell.py'


def load():
    spec = importlib.util.spec_from_file_location('stateless_shell', GUARD)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def copy_sources(tmp_path: Path, guard) -> Path:
    for part in [guard.SHELL, guard.CORE]:
        shutil.copytree(ROOT / part, tmp_path / part)
    return tmp_path


def test_current_shell_passes():
    guard = load()
    assert len(guard.check(ROOT)) == 11


@pytest.mark.parametrize('relative, old, new, message', [
    ('rust/crates/garrett-stateless/src/proxy.rs',
     '        self.proxy.send_upstream(egress)\n',
     '        let _ = self.proxy.send_upstream(egress_again());\n        self.proxy.send_upstream(egress)\n',
     'send_upstream'),
    ('rust/crates/garrett-stateless/src/proxy.rs',
     'peer.thumbprint.as_bytes(),\n            self.config.request_limit,',
     'self.config.authority.as_bytes(),\n            self.config.request_limit,',
     'handshake peer'),
    ('rust/crates/aivm-secrets-garrett-core/src/stateless_proxy.rs',
     'pub struct Egress {\n    route: usize,',
     'pub struct Egress {\n    pub route: usize,',
     'Egress fields'),
    ('rust/crates/garrett-stateless/src/broker.rs',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {\n        let _ = stateless::renew;',
     None),
    ('rust/crates/garrett-stateless/src/proxy.rs',
     '("reason", json::text(rejection_name(rejection))),',
     '("reason", json::text(rejection_name(rejection))),\n            ("token", json::text("")),',
     'audit record'),
    # The shell may not decide a request itself.
    ('rust/crates/garrett-stateless/src/proxy.rs',
     '        self.proxy.send_upstream(egress)\n',
     '        let _ = stateless_proxy::decide(&self.proxy.keys, todo!(), &[], todo!(), b"", 0);\n'
     '        self.proxy.send_upstream(egress)\n',
     'stateless_proxy::decide'),
    # No hidden mutable state, in a struct field or an atomic.
    ('rust/crates/garrett-stateless/src/proxy.rs',
     'pub struct Proxy {\n    config: ProxyConfig,',
     'pub struct Proxy {\n    seen: Mutex<Vec<u8>>,\n    config: ProxyConfig,',
     'mutable state'),
    ('rust/crates/garrett-stateless/src/proxy.rs',
     '        let stop = Arc::new(AtomicBool::new(false));\n',
     '        let stop = Arc::new(AtomicBool::new(false));\n        let served = Arc::new(AtomicUsize::new(0));\n',
     'atomic state'),
    # The mailbox serves OAuth providers only.
    ('rust/crates/garrett-stateless/src/broker.rs',
     '                .filter(|p| p.oauth().is_some())\n',
     '',
     'login policy'),
    # No file writes during credential use.
    ('rust/crates/garrett-stateless/src/broker.rs',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {\n        let _ = std::fs::write("seen", login);',
     'writes files'),
])
def test_bypass_rejected(tmp_path, relative, old, new, message):
    guard = load()
    root = copy_sources(tmp_path, guard)
    path = root / relative
    source = path.read_text()
    assert source.count(old) == 1, old
    path.write_text(source.replace(old, new))
    if message is None:
        # Naming a function without calling it is not a call site.
        guard.check(root)
        return
    with pytest.raises(guard.ShellError, match=message):
        guard.check(root)
