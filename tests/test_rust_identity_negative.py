"""W8 identity negatives against the running native bridge.

The real-KVM adversarial run covered a foreign subject, a key/certificate
mismatch and a tampered capability. These are the remaining identity cases
it named as outstanding: a subject the registry does not list, an enrollment
past its ``not_after``, a certificate that no longer matches the registered
one, and an expired capability. Each must be refused with no provider call,
and restoring the registry must make the same request succeed again, so the
denial is caused by the change and not by a broken fixture.
"""

import tempfile
import time
from pathlib import Path

import pytest

from aivm_secrets.primitives import codec
from tests.test_rust_garrett import REPO, BoundBridge, executable, run, runner  # noqa: F401


def replace_registry(directory, change):
    path = Path(directory) / "registry.json"
    registry = codec.loads(path.read_bytes())
    original = codec.loads(path.read_bytes())
    change(registry["subjects"])
    staged = Path(directory) / "staged.json"
    staged.write_bytes(codec.dumps(registry))
    staged.chmod(0o600)
    staged.replace(path)
    return original


def restore_registry(directory, registry):
    staged = Path(directory) / "staged.json"
    staged.write_bytes(codec.dumps(registry))
    staged.chmod(0o600)
    staged.replace(Path(directory) / "registry.json")


def unregistered(subjects):
    del subjects["vm-test"]


def expired_enrollment(subjects):
    subjects["vm-test"]["not_after"] = int(time.time()) - 1


def other_certificate(subjects):
    subjects["vm-test"]["certificate_sha256"] = "0" * 64


@pytest.mark.parametrize(
    "change", [unregistered, expired_enrollment, other_certificate],
    ids=["unregistered-subject", "expired-enrollment", "re-enrolled-certificate"],
)
def test_bridge_refuses_identities_the_registry_does_not_currently_back(runner, change):
    bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    with tempfile.TemporaryDirectory(prefix="agid-") as directory:
        with BoundBridge(directory, runner, bridge) as case:
            assert case.exchange()["ok"]
            original = replace_registry(directory, change)
            reply = case.exchange()
            assert not reply["ok"]
            assert reply["error"]["code"] in {"invalid_capability", "expired", "revoked"}
            assert len(case.harness.executor.calls) == 1
            restore_registry(directory, original)
            assert case.exchange()["ok"]
            assert len(case.harness.executor.calls) == 2


def test_bridge_refuses_an_expired_capability(runner):
    bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    with tempfile.TemporaryDirectory(prefix="agex-") as directory:
        with BoundBridge(directory, runner, bridge) as case:
            now = int(time.time())
            (answer,) = run(case.runner, [dict(
                action="issue",
                seed_hex=case.seed.hex(),
                encryption_key_hex=case.key.hex(),
                kid="test-1",
                claims={**case.claims, "iat": now - 120, "exp": now - 60},
                inner_capability=case.harness.capability,
            )], crypto=True)
            assert answer["ok"]
            frame = dict(
                version=1,
                capability=answer["token"],
                request={"operation": "pr.view",
                         "arguments": {"repository": REPO, "pr": 13861}},
            )
            reply = case.exchange(frame)
            assert not reply["ok"]
            assert reply["error"]["code"] in {"invalid_capability", "expired"}
            assert case.harness.executor.calls == []
            # The fresh capability from the same issuer still works.
            assert case.exchange()["ok"]
