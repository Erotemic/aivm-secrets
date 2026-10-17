"""Normal native issuance: protected output, reference opening and real mTLS."""

from __future__ import annotations

import base64
import select
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from aivm_secrets.host.audit import verify
from aivm_secrets.host.server import LocalServer
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.primitives import codec
from tests.secrets_helpers import REPO, TOKEN, Harness
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import AuthorityCase, private
from tests.test_rust_garrett_provider import ProviderCase


def issue(case, inner, output, **options):
    source = private(case.directory / "inner.capability", inner.encode())
    return case.call(
        "issue",
        subject="vm-test",
        inner_capability_file=str(source),
        output=str(output),
        client_assurance=options.pop("client_assurance", "any-enrolled"),
        **options,
    )


def test_normal_issuer_reference_crypto_and_file_nonreplacement(tmp_path):
    authority = AuthorityCase(tmp_path)
    key, _, enrollment = authority.enroll()
    output = tmp_path / "issued.jwt"
    now = int(time.time())
    result = issue(
        authority, "aivs1.synthetic-host-capability", output, now=now, lifetime=3600
    )
    token = output.read_text()
    assert set(result) == {"subject", "expires_at", "certificate_sha256", "output"}
    assert token not in str(result) and "aivs1." not in str(result)
    assert result["expires_at"] == now + 3600
    assert output.stat().st_mode & 0o777 == 0o600
    certificate = x509.load_pem_x509_certificate(
        Path(enrollment["certificate"]).read_bytes()
    ).public_bytes(serialization.Encoding.DER)
    reference = IdentityAuthority(authority.root)
    expected = reference.expectation_for_peer(certificate, now)
    opened = reference.token_verifier(expected).open(
        token, authenticated_peer_der=certificate, now=now
    )
    assert opened.broker_capability == "aivs1.synthetic-host-capability"
    assert opened.claims.expires_at == result["expires_at"]
    before = set((authority.root / "audit").iterdir())
    issue(authority, "aivs1.other-host-capability", output, error="unsafe_file")
    assert output.read_text() == token and before == set(
        (authority.root / "audit").iterdir()
    )
    for path in before:
        assert verify(path)[0] == 2
        assert (
            b"aivs1." not in path.read_bytes()
            and token.encode() not in path.read_bytes()
        )


def test_native_issued_token_normal_mtls_use_theft_and_live_key_retirement():
    with tempfile.TemporaryDirectory(prefix="agissue-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        key, _, enrolled = authority.enroll()
        certs = authority.certs(key=key, enrollment=enrolled)
        other_key, _, _ = authority.enroll(subject="other")
        other = authority.call("public-client", subject="other")
        other_cert = private(
            p / "other.pem", base64.b64decode(other["certificate_pem_b64"])
        )
        other_private = private(
            p / "other.key",
            other_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        certs["client2"] = (other_cert, other_private, None)
        harness = Harness(p / "broker")
        try:
            result = issue(authority, harness.capability, p / "outer.jwt", lifetime=300)
            token = Path(result["output"]).read_text()
            client = SimpleNamespace(
                directory=p,
                client=executable("AIVM_SECRETS_RUST_GARRETT_CLIENT"),
                token=token,
                certs=certs,
            )
            with LocalServer(harness.broker, p / "broker") as server:
                config = private(
                    p / "bridge.json",
                    dict(
                        schema=1,
                        authority_root=str(authority.root),
                        client_assurance="any-enrolled",
                        subject="vm-test",
                        listen=str(p / "identity.sock"),
                        broker_socket=str(server.socket_path),
                    ),
                )
                process = subprocess.Popen(
                    [
                        executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE"),
                        "--config",
                        str(config),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    ready, _, _ = select.select([process.stdout], [], [], 10)
                    assert ready
                    line = process.stdout.readline()
                    assert line, process.stderr.read()
                    assert codec.loads(line) == dict(version=1, ready=True)

                    def invoke(**options):
                        return ProviderCase.invoke(
                            client,
                            operation="pr.view",
                            arguments=dict(repository=REPO, pr=13861),
                            **options,
                        )

                    reply = invoke()
                    assert reply["ok"] and reply["result"]["number"] == 13861
                    calls = len(harness.executor.calls)
                    assert not invoke(role="client2")["ok"]
                    assert len(harness.executor.calls) == calls
                    authority.call("rotate-issuer")
                    assert invoke()["ok"]
                    authority.call("retire-issuer", kid="local-1")
                    calls = len(harness.executor.calls)
                    assert not invoke()["ok"]
                    assert len(harness.executor.calls) == calls
                    fresh = issue(
                        authority, harness.capability, p / "fresh.jwt", lifetime=300
                    )
                    client.token = Path(fresh["output"]).read_text()
                    assert invoke()["ok"]
                finally:
                    process.terminate()
                    out, err = process.communicate(timeout=5)
                    assert TOKEN.encode() not in out + err
        finally:
            harness.broker.close()


def test_issuance_refuses_wrong_assurance_and_partial_output_is_unpublished(tmp_path):
    authority = AuthorityCase(tmp_path)
    authority.enroll()
    output = tmp_path / "issued.jwt"
    before = len(list((authority.root / "audit").iterdir()))
    issue(
        authority,
        "aivs1.synthetic",
        output,
        client_assurance="attested-tpm",
        error="denied",
    )
    assert (
        not output.exists()
        and len(list((authority.root / "audit").iterdir())) == before
    )
    # A real EFBIG occurs while writing the staged ciphertext, after the intent
    # fits and has been fsynced. The public destination is still absent.
    issue(authority, "aivs1." + "x" * 6000, output, limit=2000, error="internal_error")
    assert not output.exists()
    partial = list(tmp_path.glob(".issued-*"))
    assert len(partial) == 1 and partial[0].stat().st_size == 2000
    assert b"aivs1." not in partial[0].read_bytes()
    audits = list((authority.root / "audit").iterdir())
    assert sorted(verify(path)[0] for path in audits) == [1, 2]
    issue(authority, "aivs1.synthetic", output)
    assert output.exists()
