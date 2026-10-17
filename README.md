# aivm-secrets (experimental)

An experimental Python broker for using host-held service credentials through
explicitly authorized operations. **Unaudited: not approved for production
credentials or unattended privileged use.** It is not a TPM or hardware identity
service and it is not a formally verified implementation.

This is the standalone project extracted from AIVM. It installs its own
`aivm-secrets` executable and does not require or bundle the AIVM VM manager.
The package version remains **0.2.0**; extraction does not change the wire
protocol or migrate existing authority, certificate, or OAuth vault state.

From a trusted host checkout that guests cannot modify:

```bash
umask 077
python3 -m venv .venv
.venv/bin/python -m pip install '.[tests]'
.venv/bin/python -m aivm_secrets --help
.venv/bin/python -m pytest -q
.venv/bin/python -m build
```

Tests use synthetic credentials and local test services. Independent Rust
backend tests skip unless their runners are explicitly configured;
those skips are not evidence of Python/Rust parity.

Start with the [operator guide](docs/source/secrets.rst),
[architecture and threat model](docs/planning/aivm-secrets-design.md),
[policy examples](docs/examples/), and
[assumption ledger](docs/planning/aivm-secrets-assumptions.json).
AIVM-specific commands in the operator guide require the separate AIVM checkout
and its existing experimental opt-in adapters.

The [extraction record](docs/extraction.md) explains the preserved authorship,
source commit, commit map, independent checks, and remaining integration work.
Original author and co-author attribution is retained in Git history:

```bash
git shortlog -sne aivm-extraction-base
git log --follow -- aivm_secrets/host/broker.py
```

The first [verified Rust freshness primitive](docs/verified-freshness.md) has
implementation-linked Lean proofs and scoped Python parity tests. It is an
independent development unit; the Python broker remains experimental and
unaudited, and full Rust broker/primitive-runner parity is still pending.

The [Rust Garrett implementation](docs/verified-garrett.md) now has signed and
encrypted surrogates, real TLS client/bridge executables, optional TPM signing
and creation-evidence verification, and independent Python parity tests. Lean
checks extracted issuance/opening controllers and a separate symbolic secrecy
model under explicit crypto, TLS, provider and key-custody conditions. The
[broader assurance campaign](docs/planning/aivm-secrets-garrett-verification.md)
still has open service, hardware and provider obligations; the whole broker
is not formally verified.

An explicit [Rust-owned provider profile](docs/verified-provider.md) now carries
`profile.read` from the authenticated client through credential custody and
pinned HTTPS to a typed public result, without a Python broker in that path.
Its extracted controller and disclosure contract are separate from the general
Python policy interpreter.
