# October 19 offline full-suite verification follow-up

After the identity-bundle compatibility overlay, the maintainer's
`python dev/verification/system.py --proofs --full-tests` run reached
`full-python-native`: 2,734 passed, 6 failed, 7 skipped. Earlier stages,
including native build/unit tests, all required workflows and selected Lean
proofs, completed before the failing stage. This follow-up does **not** assert
that the entire gate passed.

This overlay addresses three separate test-boundary problems:

1. **Synthetic HTTP 204 framing:** `TLSService` formerly emitted
   `Content-Length: 0` for every response. RFC 9110 forbids that header on
   204 responses, and the previous security overlay correctly made native
   `manifest_response` reject it. Default fixture 204 responses now contain
   no representation headers and no implicit framing. Explicitly supplied
   invalid headers are still emitted for adversarial tests. A real loopback
   TLS socket test inspects the actual response bytes. The hardened production
   Rust and Python parsers are **not** relaxed.
2. **Standalone distribution test on an AIVM developer machine:** The test
   previously asserted `importlib.util.find_spec('aivm') is None`; this is
   unrelated to `aivm-secrets` packaging correctness if AIVM happens to be
   installed in the active environment. It now uses `python -I` and installs
   an import blocker for `aivm` and its submodules, failing if the installed
   `aivm-secrets` CLI actually tries to load an AIVM module. This verifies
   dependency independence while allowing AIVM to be installed separately.
3. **Incomplete optional TPM prerequisites:** Four tests checked only for
   `swtpm`, then attempted `/usr/bin/tpm2_createprimary` even when
   `tpm2-tools` was absent. The shared emulator now checks the full set of
   required tools before starting tests, and invokes them through `PATH`.
   When absent, optional TPM tests **skip**, not pass. Setting
   `AIVM_SECRETS_REQUIRE_TPM_TESTS=1` makes missing tools an explicit failure.
   Neither a skip nor a local emulator provides hardware TPM assurance.

On Ubuntu, install the development-only emulator CLI packages when you want
actual TPM test coverage (no provider account or real TPM is needed):

```sh
sudo apt install swtpm tpm2-tools
```

Refresh the active source installation if necessary:

```sh
uv pip install --python "$(command -v python)" --no-deps -e .
```

Focused portable tests:

```sh
python -m pytest -q tests/test_distribution.py::test_installed_cli_has_no_vm_manager_dependency tests/test_offline_tpm_prerequisites.py tests/test_secrets_egress.py::test_synthetic_tls_204_is_bodyless_and_has_no_framing_headers
```

With the development tools installed, run the complete gate and explicitly
require TPM coverage:

```sh
AIVM_SECRETS_REQUIRE_TPM_TESTS=1 python dev/verification/system.py --proofs --full-tests
```

A test-only fixture correction and prerequisite check do not add an
implementation-level proof of mediation, credential confinement, or VM
isolation. The first complete run on the maintainer's Rust/Lean environment
remains the acceptance criterion.
