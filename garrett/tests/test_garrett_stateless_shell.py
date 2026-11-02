"""The garrett-stateless shell reaches credentials and providers only through the extracted core."""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / 'verification/shell_guard.py'


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
    assert len(guard.check(ROOT)) == 13


@pytest.mark.parametrize('relative, old, new, message', [
    # A second write on a provider session, or a write of other bytes.
    ('crates/garrett-stateless/src/upstream.rs',
     '        let written = tls.write_all(egress_wire(&egress));\n',
     '        let _ = tls.write_all(egress_wire(&egress));\n'
     '        let written = tls.write_all(b"again");\n',
     'one write_all'),
    ('crates/garrett-stateless/src/upstream.rs',
     '    pub(crate) fn receive(&mut self, chunk: &mut [u8]) -> Received {\n',
     '    pub(crate) fn resend(&mut self, bytes: &[u8]) {\n        let _ = self.tls.flush();\n'
     '        let _ = std::io::Write::write(&mut self.tls, bytes);\n    }\n'
     '    pub(crate) fn receive(&mut self, chunk: &mut [u8]) -> Received {\n',
     'other than by one write_all'),
    # Credential-bearing bytes read out of an Egress anywhere but the one write.
    ('crates/garrett-stateless/src/proxy.rs',
     '        match session.transmit(egress) {\n',
     '        let _copy = garrett_stateless_core::stateless_proxy::egress_wire(&egress).to_vec();\n'
     '        match session.transmit(egress) {\n',
     'egress_wire must be read exactly once'),
    # Writing through a borrowed session, which could then be written again.
    ('crates/garrett-stateless/src/upstream.rs',
     '    pub(crate) fn transmit(self, egress: Egress) -> Option<Answering> {\n',
     '    pub(crate) fn transmit(mut self, egress: Egress) -> Option<Answering> {\n',
     'no longer consumes the session'),
    # A session for one destination used for another destination's egress.
    ('crates/garrett-stateless/src/upstream.rs',
     '        if &self.destination != egress_destination(&egress) {\n            return None;\n        }\n',
     '',
     'does not check the egress is for its destination'),
    # The session must be opened to the destination the core passed, and
    # authenticated as its host under its trust anchors.
    ('crates/garrett-stateless/src/proxy.rs',
     '        self.provider = match Authenticated::open(destination) {\n',
     '        self.provider = match Authenticated::open(&self.proxy.routes[0].destination) {\n',
     'does not open the destination'),
    ('crates/garrett-stateless/src/upstream.rs',
     '        let config = client(&destination.trust).ok()?;\n',
     '        let config = client(&[]).ok()?;\n',
     'trust anchors'),
    ('crates/garrett-stateless/src/upstream.rs',
     '        let name = ServerName::try_from(host.to_string()).ok()?;\n',
     '        let name = ServerName::try_from("provider.example".to_string()).ok()?;\n',
     'TLS name'),
    ('crates/garrett-stateless/src/upstream.rs',
     '            destination: destination.clone(),\n',
     '            destination: Destination { host: Vec::new(), ..destination.clone() },\n',
     'the destination it authenticated'),
    ('crates/garrett-stateless/src/tls.rs',
     '        .with_root_certificates(store)\n',
     '        .dangerous()\n        .with_custom_certificate_verifier(Arc::new(AcceptAll))\n',
     'verif'),
    ('crates/garrett-stateless/src/proxy.rs',
     'fn text(bytes: &[u8]) -> Value {',
     'fn direct(c: Arc<rustls::ClientConfig>) {\n    let _ = rustls::ClientConnection::new(c, "a.test".try_into().unwrap());\n}\n\n'
     'fn text(bytes: &[u8]) -> Value {',
     'opens a TLS client connection'),
    ('crates/garrett-stateless/src/proxy.rs',
     'fn text(bytes: &[u8]) -> Value {',
     'fn direct() {\n    let _ = TcpStream::connect("10.0.0.1:443");\n}\n\nfn text(bytes: &[u8]) -> Value {',
     'TCP connection'),
    # The session types keep the socket private and are built in one place.
    ('crates/garrett-stateless/src/upstream.rs',
     'pub(crate) struct Answering {\n    tls:',
     'pub(crate) struct Answering {\n    pub(crate) tls:',
     'exposes a field'),
    ('crates/garrett-stateless/src/upstream.rs',
     '    pub(crate) fn receive(&mut self, chunk: &mut [u8]) -> Received {\n',
     '    pub(crate) fn reopen(self) -> Option<Authenticated> {\n'
     '        Some(Authenticated { destination: todo!(), tls: self.tls, started: self.started })\n    }\n'
     '    pub(crate) fn receive(&mut self, chunk: &mut [u8]) -> Received {\n',
     'built outside open'),
    ('crates/garrett-stateless/src/broker.rs',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {\n        let _ = crate::upstream::client(&[]);',
     'uses the provider transport'),
    # Only the core makes an Egress.
    ('crates/garrett-stateless/src/proxy.rs',
     '        match session.transmit(egress) {\n',
     '        let egress = Egress { destination: todo!(), wire: Vec::new() };\n'
     '        match session.transmit(egress) {\n',
     'builds an Egress'),
    # The agent receives only the core's reply; the proxy holds no credential.
    ('crates/garrett-stateless/src/proxy.rs',
     '    fn restart(&mut self) {\n',
     '    fn restart(&mut self) {\n        let _ = self.stream.write_all(b"extra");\n',
     'writes to the agent outside Channel::send'),
    ('crates/garrett-stateless/src/proxy.rs',
     '        let received = session.receive(&mut self.chunk);\n',
     '        let received = session.receive(&mut self.chunk);\n'
     '        let _ = garrett_stateless_core::stateless::Opened::credential;\n',
     'handles a credential'),
    ('crates/garrett-stateless/src/proxy.rs',
     '    read_only: Option<ReadOnly>,\n',
     '    read_only: Option<ReadOnly>,\n    upstream: Vec<Destination>,\n',
     'destination table'),
    ('crates/garrett-stateless/src/proxy.rs',
     '                read_only,\n                &mut session,\n                &self.routes,\n'
     '                &self.acceptance,\n                self.config.authority.as_bytes(),\n'
     '                peer.thumbprint.as_bytes(),',
     '                read_only,\n                &mut session,\n                &self.routes,\n'
     '                &self.acceptance,\n                self.config.authority.as_bytes(),\n'
     '                self.config.authority.as_bytes(),',
     'handshake peer'),
    # The read-only proxy may not fall back to Garrett's unrestricted policy,
    # nor run under a policy of the shell's own.
    ('crates/garrett-stateless/src/proxy.rs',
     '                &self.keys,\n                read_only,\n',
     '                &self.keys,\n                &Unrestricted,\n',
     'policy other than'),
    ('crates/garrett-stateless/src/proxy.rs',
     'fn text(bytes: &[u8]) -> Value {',
     'struct Lenient;\nimpl garrett_stateless_core::stateless_policy::OperationPolicy for Lenient {\n'
     '    fn permits(&self, _: &SurrogateClaims, _: &Operation) -> bool { true }\n}\n\nfn text(bytes: &[u8]) -> Value {',
     'implements an operation policy'),
    ('crates/garrett-stateless-core/src/stateless_proxy.rs',
     'pub struct Dispatch {\n    route: usize,',
     'pub struct Dispatch {\n    pub route: usize,',
     'Dispatch fields'),
    ('crates/garrett-stateless-core/src/stateless_proxy.rs',
     'pub struct Egress {\n    destination: Destination,',
     'pub struct Egress {\n    pub destination: Destination,',
     'Egress fields'),
    ('crates/garrett-stateless/src/broker.rs',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {\n        let _ = stateless::renew;',
     None),
    ('crates/garrett-stateless/src/proxy.rs',
     '("reason", json::text(rejection_name(rejection))),',
     '("reason", json::text(rejection_name(rejection))),\n            ("token", json::text("")),',
     'audit record'),
    # The shell may not decide a request itself.
    ('crates/garrett-stateless/src/proxy.rs',
     '        match session.transmit(egress) {\n',
     '        let _ = stateless_proxy::decide(&self.proxy.keys, todo!(), &[], todo!(), b"", 0);\n'
     '        match session.transmit(egress) {\n',
     'stateless_proxy::decide'),
    # The shell may not unseal a surrogate itself, admitted or not.
    ('crates/garrett-stateless/src/broker.rs',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {\n        let _ = self.verification.unseal(todo!());',
     'unseal'),
    # A renewal sealed with a fixed nonce, or a sealer built elsewhere.
    ('crates/garrett-stateless/src/broker.rs',
     '        let nonce = crate::encoding::random::<12>()?;\n',
     '        let nonce = [0u8; 12];\n',
     'fresh random nonce'),
    ('crates/garrett-stateless/src/broker.rs',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {',
     'fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {\n'
     '        let _ = TokenSealer::new(todo!(), todo!(), vec![0; 12]);',
     'outside the reviewed places'),
    # No hidden mutable state, in a struct field or an atomic.
    ('crates/garrett-stateless/src/proxy.rs',
     'pub struct Proxy {\n    config: ProxyConfig,',
     'pub struct Proxy {\n    seen: Mutex<Vec<u8>>,\n    config: ProxyConfig,',
     'mutable state'),
    ('crates/garrett-stateless/src/proxy.rs',
     '        let stop = Arc::new(AtomicBool::new(false));\n',
     '        let stop = Arc::new(AtomicBool::new(false));\n        let served = Arc::new(AtomicUsize::new(0));\n',
     'atomic state'),
    # The mailbox serves OAuth providers only.
    ('crates/garrett-stateless/src/broker.rs',
     '                .filter(|p| p.oauth().is_some())\n',
     '',
     'login policy'),
    # No file writes during credential use.
    ('crates/garrett-stateless/src/broker.rs',
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
