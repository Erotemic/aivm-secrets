"""Local TPM emulator tool prerequisites are explicit and fail as requested."""
from __future__ import annotations

import pytest

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
