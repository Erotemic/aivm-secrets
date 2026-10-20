"""Local TPM emulator tool prerequisites are explicit and fail as requested."""
from __future__ import annotations

import pytest
import subprocess
from pathlib import Path

from tests import test_rust_garrett_tpm as tpm


def test_optional_tpm_tests_skip_with_all_missing_tools_reported(monkeypatch):
    monkeypatch.delenv('AIVM_SECRETS_REQUIRE_TPM_TESTS', raising=False)
    def executable(name):
        return '/usr/bin/swtpm' if name == 'swtpm' else None

    monkeypatch.setattr(tpm.shutil, 'which', executable)
    with pytest.raises(pytest.skip.Exception, match='tpm2_createprimary') as caught:
        tpm.require_software_tpm_tools()
    assert 'tpm2_certifycreation' in str(caught.value)
    assert 'sudo apt install swtpm tpm2-tools' in str(caught.value)


def test_required_tpm_tests_fail_with_actionable_missing_tools(monkeypatch):
    monkeypatch.setenv('AIVM_SECRETS_REQUIRE_TPM_TESTS', '1')
    monkeypatch.setattr(tpm.shutil, 'which', lambda name: None)
    with pytest.raises(
        pytest.fail.Exception, match='local software TPM prerequisites missing'
    ) as caught:
        tpm.require_software_tpm_tools()
    for tool in tpm.SOFTWARE_TPM_TOOLS:
        assert tool in str(caught.value)


def test_tpm_tools_may_resolve_outside_usr_bin(monkeypatch):
    monkeypatch.setenv('AIVM_SECRETS_REQUIRE_TPM_TESTS', '1')
    monkeypatch.setattr(tpm.shutil, 'which', lambda name: '/opt/tpm/bin/' + name)
    tpm.require_software_tpm_tools()


def test_device_prerequisites_do_not_require_an_emulator(monkeypatch):
    monkeypatch.setenv('AIVM_SECRETS_REQUIRE_TPM_TESTS', '1')
    monkeypatch.setattr(tpm.shutil, 'which',
                        lambda name: None if name == 'swtpm' else '/usr/bin/' + name)
    tpm.require_software_tpm_tools(emulator=False)


def test_device_fixture_refuses_occupied_handles_before_provisioning(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'is_char_device', lambda _: True)
    calls = []

    def tool(self, name, *args):
        calls.append((name, args))
        return subprocess.CompletedProcess([], 0, b'- 0x81010011\n', b'')

    monkeypatch.setattr(tpm.SoftwareTPM, 'tool', tool)
    with pytest.raises(RuntimeError, match='occupied'):
        with tpm.DeviceTPM(tmp_path, '/dev/tpmrm0'):
            pytest.fail('occupied device was accepted')
    assert calls == [('getcap', ('handles-persistent',))]


def test_device_fixture_never_evicts_a_replacement_key(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'is_char_device', lambda _: True)
    calls = []

    def tool(self, name, *args):
        calls.append(name)
        assert name == 'readpublic'
        Path(args[-1]).write_bytes(b'a different public key')

    monkeypatch.setattr(tpm.SoftwareTPM, 'tool', tool)
    device = tpm.DeviceTPM(tmp_path, '/dev/tpmrm0')
    device.owned[0x81010011] = b'our public key'
    with pytest.raises(RuntimeError, match='refusing to evict a different key'):
        device.__exit__(None, None, None)
    assert calls == ['readpublic']


def test_device_fixture_rejects_global_flush(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'is_char_device', lambda _: True)
    device = tpm.DeviceTPM(tmp_path, '/dev/tpmrm0')
    with pytest.raises(RuntimeError, match='must not flush'):
        device.tool('flushcontext', '-t')


def test_device_fixture_requires_resource_manager(tmp_path):
    with pytest.raises(ValueError, match='resource manager'):
        tpm.DeviceTPM(tmp_path, '/dev/tpm0')


def test_device_occupied_handle_guard_uses_real_getcap_output(tmp_path, monkeypatch):
    """Catch adapters that accidentally suppress the capability list with -Q."""
    tpm.require_software_tpm_tools()
    state = tmp_path / 'emulator'
    state.mkdir(mode=0o700)
    candidate = tmp_path / 'candidate'
    candidate.mkdir(mode=0o700)
    with tpm.SoftwareTPM(state) as existing:
        saved = (state / 'public.tpmt').read_bytes()
        monkeypatch.setattr(Path, 'is_char_device', lambda _: True)
        device = tpm.DeviceTPM(candidate, '/dev/tpmrm0')
        # Exercise the real tool adapter against an isolated, occupied TPM;
        # ordinary portable runs never provision the machine's device.
        device.tcti = existing.tcti
        with pytest.raises(RuntimeError, match='occupied'):
            with device:
                pytest.fail('occupied TPM was accepted')
        assert not (candidate / 'auth').exists()
        existing.tool('readpublic', '-c', '0x81010011', '-f', 'tpmt',
                      '-o', state / 'after.tpmt')
        assert (state / 'after.tpmt').read_bytes() == saved
